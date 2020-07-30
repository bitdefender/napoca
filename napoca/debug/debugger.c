/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

// DEBUGGER - debugger support
#include "debug/debugger.h"
#include "common/boot/bootdefs.h"
#include "kernel/kernel.h"
#include "kernel/kerneldefs.h"
#include "apic/ipi.h"
#include "memory/cachemap.h"
#include "debug/dumpers.h"
#include "common/debug/memlog.h"
#include "kernel/mtrr.h"
#include "debug/interpreter.h"
#include "base/pe.h"
#include "debug/debug_store.h"
#include "boot/init64.h"
#include "introspection/intromodule.h"
#include "debug/emu_debug.h"
#include "guests/intro.h"

// get the automatically generated status-to-string functions for all components that support this feature
#include "../_external/codex/src/shared/native/cx_status_to_string.c"
#include "../_external/codex/src/shared/native/cx_ntstatus_to_string.c"
#include "../autogen/dacia_status_to_string.c"
CHAR *NtStatusToString(
    _In_ CX_STATUS Status
)
{
    char *str = DaciaStatusToString(Status, CX_TRUE); // call with ReturnNullIfUnknown so we can chain with the next status-to-string function
    if (!str) str = CxStatusToString(Status, CX_TRUE);
    if (!str) str = CxNtStatusToString(Status, CX_TRUE);
    if (str)
        return str;

    // problematic: fill-in and return a single concurrent buffer,
    // its content might change while being printed but its null terminator is written in the same position every time
    static char unknown[100];
    snprintf(unknown, sizeof(unknown) - 1, "(unknown CX_STATUS 0x%08x)", Status);
    return unknown;
}

// A DBG_PARAMS structure instance containing default values for all parameters
extern DBG_PARAMS DbgDefaultParams;

extern HV_FEEDBACK_HEADER *gFeedback;

volatile CX_BOOL gInDebugger = CX_FALSE;

#define MAX_DEBUG_BUFFER                            200
#define DBG_COMMAND_PROCESSING_IN_PROGRESS          1
#define DBG_COMMAND_PROCESSING_IDLE                 0
typedef struct _DEBUGGER_GLOBAL_DATA
{
    CX_BOOL             GotGo;
    CX_BOOL             IsDebuggerReady;                // signal when the debugger is able to run its code
    CHAR                DbgBuffer[MAX_DEBUG_BUFFER];
    CX_UINT32           DbgBuffLen;
    volatile CX_UINT32  CommandProcessingInProgress;   // synchronizes access to DbgGlobalData.DbgBuffer
    volatile CX_UINT32  DbgEnterDebugger;
    CX_BOOL             CpuReceivedNmiFromDebugger[NAPOCA_MAX_PER_GUEST_CPU];
}DEBUGGER_GLOBAL_DATA;
static DEBUGGER_GLOBAL_DATA DbgGlobalData;

/* Static functions */
static CX_VOID                  _DbgResetDebugBuffer(CX_VOID);
static CX_STATUS                _DbgDumpCommandParameters(_In_ DBG_COMMAND *Command, _In_ CX_BOOL IncludeDetails);
static __forceinline CX_BOOL    _IsMemLogReady(CX_VOID);
static CX_STATUS                _PrintGuestRegs(CX_VOID);
static __forceinline CX_VOID    _DbgShowPrompter(CX_VOID);
static __forceinline CX_BOOL    _DbgCheckIfEnterMarkerPresentInBuffer(_In_reads_bytes_(BuffLength) const char *Buffer, _In_ CX_UINT32 BuffLength);
static CX_STATUS                _DbgAnalyzePointer(_In_ CX_UINT64 Hva, __out_opt CX_UINT64 *CallAddress);
static CX_BOOL                  _CheckIfIntroCommandAndExecute(_In_ char *Input, _In_ CX_INT64 Length);

/* Debugging commands */
static CX_STATUS DbgCommandLocks(_In_ CX_UINT64 ParamMask, _In_opt_ CX_UINT64 Flags);
static CX_STATUS DbgCommandHeapTagStats(_In_ CX_UINT64 ParamMask, _In_opt_ CX_UINT64 HeapIndex);
static CX_STATUS DbgCommandGo(CX_VOID);
static CX_STATUS DbgCommandSwCpu(_In_ CX_UINT64 CpuIndex);
static CX_STATUS DbgCommandEptrx(_In_ DBG_PARAM_MEMTARGET* MemTarget, _In_ CX_UINT64 Address);
static CX_STATUS DbgCommandLogOn(CX_VOID);
static CX_STATUS DbgCommandLogOff(CX_VOID);
static CX_STATUS DbgCommandEmulInt(CX_VOID);
static CX_STATUS DbgCommandEmuTrace(CX_VOID);
static CX_STATUS DbgCommandMtrr(CX_VOID);
static CX_STATUS DbgCommandHfpu(CX_VOID);
static CX_STATUS DbgCommandGfpu(_In_ CX_UINT64 UsedParametersMask, _In_ DBG_PARAM_VCPUTARGET *Target);
static CX_STATUS DbgCommandDept(_In_ DBG_PARAM_MEMTARGET* MemTarget, _In_ CX_UINT64 Address);
static CX_STATUS DbgCommandBranches(_In_ CX_UINT64 CpuIndex);
static CX_STATUS DbgCommandReboot(_In_ CX_UINT64 UsedParametersMask, _In_ CX_UINT64 Value);
static CX_STATUS DbgCommandSetInstructionTracing(_In_ CX_UINT64 UsedParametersMask, _In_ DBG_PARAM_VCPUTARGET *Target, _In_ CX_UINT64 Value);
static CX_STATUS DbgCommandTracingAll(_In_ CX_UINT64 UsedParametersMask, _In_ CX_UINT64 Value);
static CX_STATUS DbgCommandDumpDevTree(CX_VOID);
static CX_STATUS DbgTraceDevice(_In_ CX_UINT64 Bus, _In_ CX_UINT64 Device, _In_ CX_UINT64 Function);
static CX_STATUS DbgCommandHelp(_In_ CX_UINT64 UsedParametersMask, _In_ char *CommandName);
static CX_STATUS DbgCommandDumpTargetRange(_In_ CX_UINT64 UsedParametersMask, _In_ char *Options, _In_ DBG_PARAM_TARGETRANGE *Memory);
static CX_STATUS DbgCommandDumpGuestsEptHooks(CX_VOID);
static CX_STATUS DbgCommandDumpGuestsMsrHooks(CX_VOID);
static CX_STATUS DbgCommandDisasmTargetRange(_In_ CX_UINT64 UsedParametersMask, _In_ DBG_PARAM_TARGETRANGE *Memory, _In_ CX_UINT64 Bits);
static CX_STATUS DbgCommandDumpArchRegs(_In_ CX_UINT64 UsedParametersMask, _In_ DBG_PARAM_VCPUTARGET *Target);
static CX_STATUS DbgCommandDbgbreak(CX_VOID);
static CX_STATUS DbgCommandDumpVcpu(_In_ CX_UINT64 UsedParametersMask, _In_ DBG_PARAM_VCPUTARGET *Target);
static CX_STATUS DbgCommandSetDefaultVcpuTarget(_In_ CX_UINT64 UsedParametersMask, _In_ DBG_PARAM_VCPUTARGET *Target);
static CX_STATUS DbgCommandSetDefaultMemTarget(_In_ CX_UINT64 UsedParametersMask, _In_ DBG_PARAM_MEMTARGET *Target);
static CX_STATUS DbgCommandDumpVmcs(_In_ CX_UINT64 UsedParametersMask, _In_ DBG_PARAM_VCPUTARGET *Target);
static CX_STATUS DbgCommandBreakOn(_In_ CX_UINT64 UsedParametersMask, _In_ char *Condition, _In_ DBG_PARAM_VCPUTARGET *Target);
static CX_STATUS DbgCommandTrigger(_In_ CX_UINT64 UsedParametersMask, _In_ char *Condition, _In_ char *Command, _In_ DBG_PARAM_VCPUTARGET *Target);
static CX_STATUS DbgCommandDumpHvaTranslation(_In_ CX_UINT64 UsedParametersMask, _In_ CX_UINT64 Va, _In_ CX_UINT64 Size);
static CX_STATUS DbgCommandDumpGlobalStats(CX_VOID);
static CX_STATUS DbgCommandHostRegs(CX_VOID);
static CX_STATUS DbgCommandTranslateaGuestAddress(_In_ DBG_PARAM_MEMTARGET *MemTarget, _In_ CX_UINT64 Address);
static CX_STATUS DbgCommandInPortDword(_In_ CX_UINT64 Port);
static CX_STATUS DbgCommandOutPortDword(_In_ CX_UINT64 Port, _In_ CX_UINT64 Value);
static CX_STATUS DbgCommandInPortByte(_In_ CX_UINT64 Port);
static CX_STATUS DbgCommandOutPortByte(_In_ CX_UINT64 Port, _In_ CX_UINT64 Value);
static CX_STATUS DbgCommandMMap(_In_ CX_UINT8 GuestIndex, _In_ CX_UINT8 MapType);
static CX_STATUS DbgCommandStackWalkDvtcK(_In_ CX_UINT64 ParamMask, _In_opt_ CX_UINT64 CpuIndex);
static CX_STATUS DbgCommandStackWalkDvtcKV(_In_ CX_UINT64 ParamMask, _In_opt_ CX_UINT64 CpuIndex);
static CX_STATUS DbgCommandStackWalkDvtcKVX(_In_ CX_UINT64 ParamMask, _In_opt_ CX_UINT64 CpuIndex);
static CX_STATUS DbgCommandVaTagStats(_In_ CX_UINT64 ParamMask, _In_opt_ CX_UINT64 VaIndex);
static CX_STATUS DbgCommandHeapWalk(_In_ CHAR *TagToWalkFor);
static CX_STATUS DbgCommandVaWalk(_In_ CHAR *TagToWalkFor);
static CX_STATUS DbgCommandIoHooks(CX_VOID);
static CX_STATUS DbgCommandReadMsr(_In_ CX_UINT64 Msr);
static CX_STATUS DbgCommandWriteMsr(_In_ CX_UINT64 Msr, _In_ CX_UINT64 Value);
static CX_STATUS DbgCommandClearMemoryLog(CX_VOID);
static CX_STATUS DbgCommandStackTrace(_In_ CX_UINT64 RspAddress, _In_ CX_UINT64 Rip, _In_opt_ CX_UINT32 MaxTraces);
static CX_STATUS DbgCommandMapEpt(_In_ CX_UINT64 UsedParametersMask, _In_ CX_UINT64 Gpa, _In_opt_ CX_UINT64 Size);
static CX_STATUS DbgCommandSetIntroVerbosity(_In_ CX_UINT32 VerbosityLevel);
static CX_STATUS DbgCommandStack(_In_ DBG_PARAM_VCPUTARGET *Target);
static CX_STATUS DbgCommandStackAll(CX_VOID);

//
// COMMANDS structure
//
DBG_COMMAND DbgCommands[]=
{
    {
        "help",
            "Generic help or usage details for a given command",
            "use SYMBOL to specify the name of a command",
            DBG_TYPE_OPT_SYMBOL,
            (DBG_INTERPRETER_CALLBACK)DbgCommandHelp
    },
    {
        "go",
            "Leave debugger",
            CX_NULL,
            DBG_TYPE_OPT_SYMBOL,
            (DBG_INTERPRETER_CALLBACK)DbgCommandGo
    },
    {
        "reboot",
            "I guess you know what a reboot is",
            "if a parameter is present an 'emergency' reboot will occur, else a normal reboot",
            DBG_TYPE_OPT_VALUE0,
            (DBG_INTERPRETER_CALLBACK)DbgCommandReboot,
    },
    {
        "trace",
            "Enable or disable single step trace",
            "VALUE0 : 0 => disable, 1 => (default) list each instruction, 2 => list and break after each instruction, 3 => silent (vmexits only)",
            DBG_TYPE_OPT_VCPUTARGET|DBG_TYPE_OPT_VALUE0,
            (DBG_INTERPRETER_CALLBACK)DbgCommandSetInstructionTracing,
    },
    {
        "traceall",
            "Enable or disable single step trace for every cpu of each guest",
            "VALUE0 : 0 => disable, 1 => (default) list each instruction, 2 => list and break after each instruction, 3 => silent (vmexits only)",
            DBG_TYPE_OPT_VALUE0,
            (DBG_INTERPRETER_CALLBACK)DbgCommandTracingAll,
    },
    {
        "breakon",
            "break into debugger each time the given numeric expression is not zero for a vcpu at a vmexit",
            "SYMBOL should be a quoted expression like \"(rip > 0x7c00) && (rip < 0x7e00)\"",
            DBG_TYPE_SYMBOL | DBG_TYPE_OPT_VCPUTARGET,
            (DBG_INTERPRETER_CALLBACK)DbgCommandBreakOn
    },
    {
        "trigger",
            "execute a debugger command each time the specified condition is met by a vcpu at a vmexit",
            "SYMBOL should be a quoted expression like \"(rip > 0x7c00) && (rip < 0x7e00) || (#0.1.rip == 0x7c08)\"\n\
            SYMBOL1 is the command(s) to perform, also quoted (for example \"raw q #0.0.p rsp 0x10\")",
            DBG_TYPE_SYMBOL | DBG_TYPE_SYMBOL1 | DBG_TYPE_OPT_VCPUTARGET,
            (DBG_INTERPRETER_CALLBACK)DbgCommandTrigger
    },
    {
        "raw",
            "Raw memory dump for a memory region",
            "SYMBOL is a combination of the characters mwdqhaclpei:\n\
                m = minimal (includes all the rest),\n\
                w = words\n\
                d = dwords\n\
                q = qwords\n\
                h = no hex values\n\
                a = no address\n\
                c = no characters\n\
                l = no newlines\n\
                p = packed, no spacing\n\
                e = extended (32 bytes/line\n\
                i = ID (apic id) of current processor is used as line prefix\n\
                n = no address alignment",

            DBG_TYPE_OPT_SYMBOL | DBG_TYPE_OPT_TARGETRANGE,
            (DBG_INTERPRETER_CALLBACK)DbgCommandDumpTargetRange,
    },
    {
        "epthooks",
            "Dumps all EPT hooks for each guest",
            CX_NULL,
            DBG_TYPE_VOID,
            (DBG_INTERPRETER_CALLBACK)DbgCommandDumpGuestsEptHooks,
    },
    {
        "msrhooks",
            "Dumps all MSR hooks for each guest",
            CX_NULL,
            DBG_TYPE_VOID,
            (DBG_INTERPRETER_CALLBACK)DbgCommandDumpGuestsMsrHooks,
    },
    {
        "disasm",
            "Disassemble memory",
            "VALUE specifies the architecture: 16, 32 or 64\
            if TARGETRANGE is not specified, dump 0x100 from the current RIP of the current VCPU",
            DBG_TYPE_OPT_VALUE0 | DBG_TYPE_OPT_TARGETRANGE,
            (DBG_INTERPRETER_CALLBACK)DbgCommandDisasmTargetRange
    },
    {
        "regs",
            "Dump the archregs of the current (or a given) VCPU",
            CX_NULL,
            DBG_TYPE_OPT_VCPUTARGET,
            (DBG_INTERPRETER_CALLBACK) DbgCommandDumpArchRegs
    },
    {
        "vcpu",
            "Dump the VCPU fields of the current (or a given) VCPU",
            CX_NULL,
            DBG_TYPE_OPT_VCPUTARGET,
            (DBG_INTERPRETER_CALLBACK) DbgCommandDumpVcpu
    },
    {
        "vmcs",
            "Dump the VMCS fields (vmread) from the current or a given VCPU",
            CX_NULL,
            DBG_TYPE_OPT_VCPUTARGET,
            (DBG_INTERPRETER_CALLBACK) DbgCommandDumpVmcs
    },
    {
        "global-stats",
            "Dump global stats.",
            CX_NULL,
            DBG_TYPE_VOID,
            (DBG_INTERPRETER_CALLBACK) DbgCommandDumpGlobalStats
    },
    {
        "~vcpu",
            "Display (and set if a parameter is given) the default VCPUTARGET",
            CX_NULL,
            DBG_TYPE_OPT_VCPUTARGET,
            (DBG_INTERPRETER_CALLBACK) DbgCommandSetDefaultVcpuTarget
    },
    {
        "~mem",
            "Display (and set if a parameter is given) the default MEMTARGET",
            CX_NULL,
            DBG_TYPE_OPT_MEMTARGET,
            (DBG_INTERPRETER_CALLBACK) DbgCommandSetDefaultMemTarget
    },
    {
        "dbgbreak",
            "Inject a breakpoint exception at current VCPU RIP",
            CX_NULL,
            DBG_TYPE_VOID,
            (DBG_INTERPRETER_CALLBACK) DbgCommandDbgbreak
    },
    {
        "dumpdev",
            "Dump PCI device tree",
            "No parameters",
            DBG_TYPE_VOID,
            (DBG_INTERPRETER_CALLBACK)DbgCommandDumpDevTree
    },
    {
        "tracedev",
            "Traces all of the reads/writes on the given devices PCI config space",
            "<bus> <device> <function> use 0xFFFF for full range",
            DBG_TYPE_VALUE0 | DBG_TYPE_VALUE1 | DBG_TYPE_VALUE2,
            (DBG_INTERPRETER_CALLBACK)DbgTraceDevice
    },
    {
        "hostregs",
            "Dump host registers not found in vmcs",
            CX_NULL,
            DBG_TYPE_VOID,
            (DBG_INTERPRETER_CALLBACK)DbgCommandHostRegs
    },
    {
        "hva",
            "Dump HV virtual address translation info",
            "VALUE0 is the HVA, VALUE1 (optional) is the number of bytes to check",
            DBG_TYPE_VALUE0 | DBG_TYPE_OPT_VALUE1,
            (DBG_INTERPRETER_CALLBACK) DbgCommandDumpHvaTranslation
    },
    {
        "lastlog",
            "Dumps last lines of log from napoca",
            CX_NULL,
            DBG_TYPE_VOID,
            (DBG_INTERPRETER_CALLBACK)DumpersDumpMemoryLog
    },
    {
        "clearlastlog",
            "Clears last lines of log from napoca",
            CX_NULL,
            DBG_TYPE_VOID,
            (DBG_INTERPRETER_CALLBACK)DbgCommandClearMemoryLog
    },
    {
        "gaddr",
            "Dumps translation info for a given guest virtual or physical address",
            "VALUE0 is the target address",
            DBG_TYPE_MEMTARGET | DBG_TYPE_VALUE0,
            (DBG_INTERPRETER_CALLBACK)DbgCommandTranslateaGuestAddress
    },
    {
        "inbyte",
            "Does an IO read on specified port",
            "VALUE0 is the target port",
            DBG_TYPE_VALUE0,
            (DBG_INTERPRETER_CALLBACK)DbgCommandInPortByte
    },
    {
        "outbyte",
            "Does an IO write on specified port",
            "VALUE0 is the target port, VALUE1 is the data to be written",
            DBG_TYPE_VALUE0 | DBG_TYPE_VALUE1,
            (DBG_INTERPRETER_CALLBACK)DbgCommandOutPortByte
    },
    {
        "indword",
            "Does an IO read on specified port",
            "VALUE0 is the target port",
            DBG_TYPE_VALUE0,
            (DBG_INTERPRETER_CALLBACK)DbgCommandInPortDword
    },
    {
        "outdword",
            "Does an IO write on specified port",
            "VALUE0 is the target port, VALUE1 is the data to be written",
            DBG_TYPE_VALUE0 | DBG_TYPE_VALUE1,
            (DBG_INTERPRETER_CALLBACK)DbgCommandOutPortDword
    },
    {
        "mmap",
            "Dump a memory map",
            "First parameter is guest index. Second parameter is map type (0 - phys map, 1 - hyper map, 2 - guest area map, 3 - dev res map 4 - Os map, 5 - MTRR map, 6 - MMIO map, 7 - Ept map).\n For a host memory map use 0xFF as guest index.",
            DBG_TYPE_VALUE0 | DBG_TYPE_VALUE1,
            (DBG_INTERPRETER_CALLBACK)DbgCommandMMap
    },
    {
        "kve",
            "Does a DBGVTC2.DLL based stackwalk attempt, with details and local variables for each function on the selected PCPU (or on current by default)",
            "First optional param represents the PCPU index. If not present, the current PCPU is used",
            DBG_TYPE_OPT_VALUE0,
            (DBG_INTERPRETER_CALLBACK)DbgCommandStackWalkDvtcKVX
    },
    {
        "kv",
            "Does a DBGVTC2.DLL based stackwalk attempt, with details, on the selected PCPU (or on current by default)",
            "First optional param represents the PCPU index. If not present, the current PCPU is used",
            DBG_TYPE_OPT_VALUE0,
            (DBG_INTERPRETER_CALLBACK)DbgCommandStackWalkDvtcKV
    },
    {
        "k",
            "Does a DBGVTC2.DLL based stackwalk attempt on the selected PCPU (or on current by default)",
            "First optional param represents the PCPU index. If not present, the current PCPU is used",
            DBG_TYPE_OPT_VALUE0,
            (DBG_INTERPRETER_CALLBACK)DbgCommandStackWalkDvtcK
    },
    {
        "heaptags",
            "Generates a statistics with all heap blocks, grouped by TAGs",
            "First optional param selects one single given heap allocator. If not present, a global stat is generated, across all heap allocators",
            DBG_TYPE_OPT_VALUE0,
            (DBG_INTERPRETER_CALLBACK)DbgCommandHeapTagStats
    },
    {
        "vatags",
            "Generates a statistics with all **DYNAMIC** VA mappings, grouped by TAGs",
            "First optional param selects one single given VA allocator. If not present, a global stat is generated, across all VA allocators",
            DBG_TYPE_OPT_VALUE0,
            (DBG_INTERPRETER_CALLBACK)DbgCommandVaTagStats
    },
    {
        "heapwalk",
            "Displays all HEAP items currently allocated with the given TAG",
            "First param is a TAG (4 chars, in plain human-readable order)",
            DBG_TYPE_SYMBOL,
            (DBG_INTERPRETER_CALLBACK)DbgCommandHeapWalk
    },
    {
        "vawalk",
            "Displays all **DYNAMIC** VA items currently allocated with the given TAG",
            "First param is a TAG (4 chars, in plain human-readable order)",
            DBG_TYPE_SYMBOL,
            (DBG_INTERPRETER_CALLBACK)DbgCommandVaWalk
    },
    {
        "locks",
            "Displays spinlock / rw-spinlock statistics",
            "VALUE0: 0 = dump, 1 = clear, 2 = reset (probably not what you want)\n",
            DBG_TYPE_OPT_VALUE0,
            (DBG_INTERPRETER_CALLBACK) DbgCommandLocks
    },
    {
        "iohooks",
            "Display information about io port hooks",
            CX_NULL,
            DBG_TYPE_VOID,
            (DBG_INTERPRETER_CALLBACK) DbgCommandIoHooks
    },
    {
        "rdmsr",
            "Read msr value.",
            "Parameter is MSR identifier.",
            DBG_TYPE_VALUE0,
            (DBG_INTERPRETER_CALLBACK) DbgCommandReadMsr
    },
    {
        "wrmsr",
            "Write msr value.",
            "First parameter is MSR identifier; Second parameter is the value.",
            DBG_TYPE_VALUE0|DBG_TYPE_VALUE1,
            (DBG_INTERPRETER_CALLBACK) DbgCommandWriteMsr
    },
    {
        "stacktrace",
            "Executes a stack trace on the given RSP and RIP",
            "First parameter is the RSP address; Second parameter is the RIP; " \
            "Third parameter is how may traces to get. If 0, it parses till the end of stack.",
            DBG_TYPE_VALUE0|DBG_TYPE_VALUE1|DBG_TYPE_VALUE2,
            (DBG_INTERPRETER_CALLBACK) DbgCommandStackTrace
    },
    {
        "mapept",
            "Maps the given GPA range into the ept of the current guest, using EptMapRangeToGuestSpace",
            "first parameter is the start GPA, second one can be the size (4KB default)",
            DBG_TYPE_VALUE0 | DBG_TYPE_OPT_VALUE1,
            (DBG_INTERPRETER_CALLBACK)DbgCommandMapEpt
    },
    {
        "intrologs",
            "Sets introspection verbosity level (0 = LevelDebug, 1 = LevelInfo, 2 = LevelWarning, 3 = LevelError, 4 = LevelCritical)",
            "first parameter the verbosity level",
            DBG_TYPE_VALUE0,
            (DBG_INTERPRETER_CALLBACK)DbgCommandSetIntroVerbosity
    },
    {
        "swcpu",
            "Switching debugger to given CPU index",
            "The parameter is the index of the CPU on which the debugging is to be performed",
            DBG_TYPE_VALUE0,
            (DBG_INTERPRETER_CALLBACK)DbgCommandSwCpu
    },
    {
        "eptrx",
            "Set READ | EXECUTE for EPT 4K page at guest phys-addr",
            "VALUE0 is the target address",
            DBG_TYPE_MEMTARGET | DBG_TYPE_VALUE0,
            (DBG_INTERPRETER_CALLBACK)DbgCommandEptrx
    },
    {
        "logon",
            "Enable logging",
            CX_NULL,
            DBG_TYPE_VOID,
            (DBG_INTERPRETER_CALLBACK)DbgCommandLogOn
    },
    {
        "logoff",
            "Disable logging",
            CX_NULL,
            DBG_TYPE_VOID,
            (DBG_INTERPRETER_CALLBACK)DbgCommandLogOff
    },
    {
        "emulint",
            "Emulate the current software INT (0xCD) instrux, keep TF",
            CX_NULL,
            DBG_TYPE_VOID,
            (DBG_INTERPRETER_CALLBACK)DbgCommandEmulInt
    },
    {
        "emutrace",
            "Display a trace of the last emulated instructions",
            CX_NULL,
            DBG_TYPE_VOID,
            (DBG_INTERPRETER_CALLBACK)DbgCommandEmuTrace
    },
    {
        "mtrr",
            "Dump MTRR state for each guest, for the host at boot phase and for the host as it is at run time",
            CX_NULL,
            DBG_TYPE_VOID,
            (DBG_INTERPRETER_CALLBACK)DbgCommandMtrr
    },
    {
        "hfpu",
            "Dump host fpu registers",
            CX_NULL,
            DBG_TYPE_VOID,
            (DBG_INTERPRETER_CALLBACK)DbgCommandHfpu
    },
    {
        "gfpu",
            "Dump guest fpu registers",
            CX_NULL,
            DBG_TYPE_OPT_VCPUTARGET,
            (DBG_INTERPRETER_CALLBACK)DbgCommandGfpu
    },
    {
        "dept",
            "Dump ept translation for a given GPA",
            "VALUE0 is the GPA",
            DBG_TYPE_MEMTARGET | DBG_TYPE_VALUE0,
            (DBG_INTERPRETER_CALLBACK)DbgCommandDept
    },
    {
        "branches",
            "Print debug store (cpu feature) for given CPU",
            "The parameter is the index of the CPU",
            DBG_TYPE_VALUE0,
            (DBG_INTERPRETER_CALLBACK)DbgCommandBranches
    },
    {
        "stack",
            "Send an NMI to a processor for it to print its stack",
            CX_NULL,
            DBG_TYPE_VCPUTARGET,
            (DBG_INTERPRETER_CALLBACK)DbgCommandStack
    },
    {
        "stackall",
            "Send NMI to all processors for them to print their stack",
            CX_NULL,
            DBG_TYPE_VOID,
            (DBG_INTERPRETER_CALLBACK)DbgCommandStackAll
    },
};
CX_UINT32 DBG_NUMBER_OF_COMMANDS = ARRAYSIZE(DbgCommands);

static DBG_PARAM_HELP DbgTypeDescriptions[]=
{
    // DBG_TYPE_SYMBOL
    {"SYMBOL", "a string matching any C-like symbol name"},

    // DBG_TYPE_SYMBOL1
    {"SYMBOL1", "a string matching any C-like symbol name"},

    // DBG_TYPE_MEMTARGET
    {"MEMTARGET", "describes a target memory space\n\
                - '#h': host memory, use #h.p or #h.v to choose between physical or virtual\n\
                - '#guestOrdinal.vcpuOrdinal': specifies guest memory, add .p or .v for physical vs virtual memory"},

    // DBG_TYPE_MEMRANGE
    {"MEMRANGE", "two numerical expressions, separated by spaces - defines the address and size of a memory block"},

    // DBG_TYPE_TARGETRANGE
    {"TARGETRANGE", "combination of MEMTARGET and MEMRANGE - any generic memory block\n\
                - MEMTARGET: describes a target memory space\n\
                    - '#h': host memory, use #h.p or #h.v to choose between physical or virtual\n\
                    - '#guestOrdinal.vcpuOrdinal.type': specifies guest memory, use .p or .v for type (physical vs virtual memory)\n\
                - MEMRANGE: two numerical expressions, separated by spaces - defines the address and size of a memory block"},

    // DBG_TYPE_VCPUTARGET
    {"VCPUTARGET", "'#guestIndex.vcpuIndex' - specifies a VCPU, where guestIndex and vcpuIndex can be any numerical expressions"},

    // DBG_TYPE_VALUE0
    {"VALUE", "any numerical expression"},

    // DBG_TYPE_VALUE1
    {"VALUE", "any numerical expression"},

    // DBG_TYPE_VALUE2
    {"VALUE", "any numerical expression"},

    // DBG_TYPE_VALUE3
    {"VALUE", "any numerical expression"},

    // DBG_TYPE_VALUE_LIST
    {"VALUELIST", "one or more numerical expressions separated by ',' (comma)"},


    // generic help on syntax for specifying numbers, KEEP THIS AS THE LAST ELEMENT OF THE ARRAY!
    {"specifying numbers",
    "any numerical expression, valid statements:\n\
                decimal or hexadecimal numbers, sizeof(STRUCTURE_NAME),\n\
                BYTE|WORD|DWORD|QWORD|VMX|GATE64|IO'['OPT_MEMTARGET:ADDRESS']',\n\
                [#guestOrdinal.vcpuOrdinal.]rip|rsp|rbx|rax|rbx|rcx|rdx|rsi|rdi|rflags|cr0|cr2|cr3|cr4|cs|csbase|ds|dsbase|ss|ssbase|reason|#cpu|#geust|#vcpu|<varName>,\n\
                KILO|MEGA|GIGA|TERA|gdtbase|idtbase|gdtlimit|idtlimit|VMCS_*|VMCSFLAG_*\n\
                operators: +, -, /, *, ==, !=, <, >, <=, >=, &&, ||, <<, >>, &, |, ^\n\
                altering values: any number-like statement followed by \"=\" and a numeric expression\n\
            "},
    {"command prefixes",
    "\n\
                @<command> will execute the given command on each VCPU of current guest (if available), special symbol i expands to current counter\n\
                *<command> same as @<command> but without switching to vcpu[i]\n\
                *<number>:<command> execute command for number times while making i available as the current counter\n\
                "
    },

    {"specifying statements",
    "\n\
                altering values: any number-like statement followed by \"=\" and a numeric expression\n\
                conditional expression: if <numeric expression>{<statements>}\n\
                loop expression: while <numeric expression>{<statements>}\n\
                block expression: {<statements>}\n\
                logging: print <numeric expression>\n\
                function declaration: <functionName>:={<statements>}\n\
                function call: <functionName>\n\
                defining a variable: <varName> = numeric expression\n\
                undefining a variable: undef <varName>\n\
                "
    },

    {"examples",
    "\n\
                x=1                                // declare a variable x with value 1\n\
                undef x                            // undefine the variable/function x\n\
                cr3=0\n\
                vmx[VMCS_EXCEPTION_BITMAP] = 0x1F\
                @rip                               // list each vcpu's RIP\n\
                @cr3=0                             // make the cr3 of each vcpu zero\n\
                *4: ~vcpu #0.i*2 archregs          // switch to vcpu 0,2,4,6 and list the archregs\n\
                @#0.i.rip = 0x1000 + i*16          // same as @rip = 0x1000 + i*16\n\
                while(x<10){x=x+1;print rax;}\n\
                f:={if(x==3){print rax;}}          // declare a function f which prints rax if x==3\n\
        "}
};
#define DBG_NUMBER_OF_DESCRIPTIONS ARRAYSIZE(DbgTypeDescriptions)

CX_STATUS
DbgInit(
    CX_VOID
)
{
    _DbgResetDebugBuffer();

    DbgGlobalData.IsDebuggerReady = CX_TRUE;

    return CX_STATUS_SUCCESS;
}

CX_BOOL
DbgMatchCommand(
    _In_        CHAR        *Input,
    _In_        CX_INT64    Length,
    __out_opt   CX_INT64    *Consumed,
    _In_        CX_BOOL     Echo,
    __out_opt   CX_BOOL     *PartialMatch
)
{
    if (!InterpreterMatchCommand(Input, Length, Consumed, Echo, PartialMatch))
    {
        // We do not match any of our commands.
        // Check if this is an introspection debugging command.
        if (_CheckIfIntroCommandAndExecute(&Input[*Consumed], Length - *Consumed))
        {
            // If introspection command, send all the command line.
            // We do not know the exact number of parameters.
            *Consumed = Length;
            return CX_TRUE;
        }
        else
        {
            return CX_FALSE;
        }
    }
    else
    {
        return CX_TRUE;
    }
}

CX_VOID
DbgNmiHandler(
    _In_  HV_TRAP_FRAME *TrapFrame
)
{
    CX_UINT32 currentCpuLapicId = HvGetCurrentApicId();

    if (!DbgGlobalData.CpuReceivedNmiFromDebugger[currentCpuLapicId]) return;

    DbgGlobalData.CpuReceivedNmiFromDebugger[currentCpuLapicId] = CX_FALSE;

    if (!TrapFrame)
    {
        LOGN("The NMI caught the processor in the GUEST!\n");

        DumpCurrentVmcs(currentCpuLapicId);

        VCPU *currentVcpu = HvGetCurrentVcpu();
        if (currentVcpu) DumpersDumpArchRegs(&currentVcpu->ArchRegs);

        return;
    }

    DumpersGenerateAndSendStackWalkDumpFromNmiHandler(HvGetCurrentCpu(), TrapFrame, DBG_CUSTOMTYPE_FLAG_KV);

    return;
}

CX_STATUS
DbgScheduleDebugger_(
    _In_ CHAR       *File,
    _In_ CX_UINT32  Line
)
{
    CX_BOOL forcedBreak = CX_FALSE;

    if (!gStageThreeCanProceedOnAps) return CX_STATUS_SUCCESS;

    if (HvGetCurrentCpu()->DebugBreak)
    {
        HvGetCurrentCpu()->DebugBreak = CX_FALSE;

        forcedBreak = CX_TRUE;

        goto __force_break;
    }

    if (0 != HvInterlockedCompareExchangeU32(&DbgGlobalData.DbgEnterDebugger, 0x0, 0x1))
    {
        goto tryEnterDebugger;
    }

__force_break:

    // we can do debugging only if SERIAL is initialized
    if (!(IoSerialIsInited() && IoSerialIsEnabled()))
    {
        return CX_STATUS_OPERATION_NOT_SUPPORTED;
    }

    if (DBG_COMMAND_PROCESSING_IN_PROGRESS == HvInterlockedCompareExchangeU32(&DbgGlobalData.CommandProcessingInProgress,
                                                                           DBG_COMMAND_PROCESSING_IN_PROGRESS,
                                                                           DBG_COMMAND_PROCESSING_IDLE))
    {
        return STATUS_DBG_COMMAND_PROCESSING_IN_PROGRESS;
    }

    // check if there is any input available
    if (IoSerialIsDataReady() || forcedBreak)
    {
        CX_BOOL enterDbg;

        enterDbg = CX_FALSE;

        // reset debugger commands buffer
        _DbgResetDebugBuffer();

        // if this is not a forced break then
        // first char in the buffer must be '\n'
        // if not do not enter in debugger
        if (!forcedBreak)
        {
            CX_UINT16 tmpLen;
            tmpLen = 0;

            if (IoSerialIsDataReady())
            {
                // read all serial input here
                IoSerialRead(DbgGlobalData.DbgBuffer, MAX_DEBUG_BUFFER, &tmpLen);
                DbgGlobalData.DbgBuffLen = tmpLen;

                enterDbg = _DbgCheckIfEnterMarkerPresentInBuffer(DbgGlobalData.DbgBuffer, DbgGlobalData.DbgBuffLen);
            }
        }
        else
        {
            enterDbg = CX_TRUE;
        }

        if (enterDbg)
        {
tryEnterDebugger:
            HvInterlockedExchangeU32(&DbgGlobalData.DbgEnterDebugger, 0x0);
            CfgFeaturesUnloadOnErrorsEnabled = CX_FALSE;    // allow breaking into debugger, otherwise the debugger is disabled
            DbgEnterDebugger3(CX_FALSE, File, Line, 0);

            // reset debugger commands buffer
            _DbgResetDebugBuffer();
        }
    }

    HvInterlockedExchangeU32(&DbgGlobalData.CommandProcessingInProgress, DBG_COMMAND_PROCESSING_IDLE);

    return CX_STATUS_SUCCESS;
}

CX_STATUS
DbgEnterDebugger3(
    _In_ CX_BOOL    AlwaysBreakIgnoreCleanupIKnowWhatImDoing,
    _In_ CHAR       *File,
    _In_ CX_UINT32  Line,
    _In_ CX_UINT32  Options
)
{
    CX_STATUS status;
    VCPU *vcpu;
    CX_UINT32 apicid;
    CX_INT32 cpuPhase;
    CX_VOID *requestId;

    if (!File) return CX_STATUS_INVALID_PARAMETER_3;
    if ((CfgFeaturesUnloadOnErrorsEnabled) && (!AlwaysBreakIgnoreCleanupIKnowWhatImDoing)) return CX_STATUS_SUCCESS;

    // stop if no serial port initialized
    if (!gSerialInited) return CX_STATUS_OPERATION_NOT_SUPPORTED;

    if (!DbgGlobalData.IsDebuggerReady) return CX_STATUS_NOT_INITIALIZED;

    IoEnableSerialOutput(CX_TRUE);

    status = CX_STATUS_UNINITIALIZED_STATUS_VALUE;

    if (HvDoWeHaveValidCpu())
    {
        apicid = HvGetCurrentApicId();
    }
    else
    {
        apicid = HvGetInitialLocalApicIdFromCpuid();
    }

    gInDebugger = CX_TRUE;

    cpuPhase = IoGetPerCpuPhase();

    HvPrint("*******************************************************************************\n");
    if ((Options & 1) == 0)
    {
        HvPrint("    CPU %d is breaking in debugger from file '%s', line %d.\n", HvGetCurrentCpuIndex(), File, Line);
        HvPrint("    Trying to freeze all other CPUs by IPI...\n");
    }

    {
        // Freeze all CPUs excepting the current one
        if ((Options & 1) == 0)
        {
            LOG("IpiFreezeCpus \n");
            status = IpiFreezeCpus(AFFINITY_ALL_EXCLUDING_SELF, IFR_REASON_DEBUGGER, &requestId);
            if (!CX_SUCCESS(status))
            {
                // We continue if the function has failed (most likely only the BSP is active,
                // which is fine) but we must point out that there is no need to resume the other processors!
                requestId = CX_NULL;
                LOG_FUNC_FAIL("IpiFreezeCpus", status);
            }
        }
        else
        {
            status = IpiFreezeCpusSilent(AFFINITY_ALL_EXCLUDING_SELF, IFR_REASON_DEBUGGER, &requestId);
            if (!CX_SUCCESS(status))
            {
                // We continue if the function has failed (most likely only the BSP is active,
                // which is fine) but we must point out that there is no need to resume the other processors!
                requestId = CX_NULL;
                LOG_FUNC_FAIL("IpiFreezeCpusSilent", status);
            }
        }
    }

    if ((Options & 1) == 0)
    {
        HvPrint("    Broke into debugger from file '%s', line %d.\n", File, Line);
        HvPrint("    Global data at address %p\n", &gHypervisorGlobalData);
        HvPrint("    Boot Mode: %d, Wakeup: %d\n", HvGetBootMode(), gHypervisorGlobalData.BootFlags.IsWakeup);
        HvPrint("    Waiting for commands (try 'help' to display available commands).\n");

        HvPrint("    When finished, type 'go' to continue execution.\n");

        HvPrint("*******************************************************************************\n");
    }
    _DbgShowPrompter();

    // prepare default values for debugger commands
    {
        vcpu = HvDoWeHaveValidCpu() ? HvGetCurrentVcpu() : CX_NULL;

        status = InterpreterSetInterpretorSessionDefaults(vcpu);
        if (!CX_SUCCESS(status))
        {
            // warn and then try debugging
            LOG_FUNC_FAIL("InterpreterSetInterpretorSessionDefaults", status);
        }
    }


    // process serial input
    while (CX_TRUE)
    {
        // read data from UART
        if ( IoSerialIsDataReady() )
        {
            CX_UINT16 len = 0;

            status = IoSerialRead(&DbgGlobalData.DbgBuffer[DbgGlobalData.DbgBuffLen], (CX_UINT16)(MAX_DEBUG_BUFFER - DbgGlobalData.DbgBuffLen), &len);
            if (!CX_SUCCESS(status))
            {
                LOG("ERROR: IoSerialRead failed, status=%s\n", NtStatusToString(status));

                if (CX_STATUS_INVALID_PARAMETER_2 == status)
                {
                    LOG("Debug comands buffer is full! MAX_DEBUG_BUFFER %d  DbgGlobalData.DbgBuffLen %d\n",
                        MAX_DEBUG_BUFFER, DbgGlobalData.DbgBuffLen);
                    DbgGlobalData.DbgBuffer[MAX_DEBUG_BUFFER-1] = 0;
                    LOG("BUFFER = '%s'\n", DbgGlobalData.DbgBuffer);
                    DbgGlobalData.DbgBuffLen = 0;
                }

                continue;
            }

            DbgGlobalData.DbgBuffLen = DbgGlobalData.DbgBuffLen + len;
        }

        // process commands, until a 'go'

        CX_UINT32 i, k;

        DbgGlobalData.GotGo = CX_FALSE;

        i = 0;
        while (i < DbgGlobalData.DbgBuffLen)
        {
            if ((10 == DbgGlobalData.DbgBuffer[i]) ||
                (13 == DbgGlobalData.DbgBuffer[i]))
            {
                // append terminating CX_NULL
                DbgGlobalData.DbgBuffer[i] = 0;

                // process any commands (if length > 0)
                if (i > 0)
                {
                    /// debugger interface here!
                    {
                        CX_INT64 consumed = 0, tmp = 0;
                        CX_BOOL success = CX_TRUE;

                        // repeat matching as many commands as possible
                        while ((success) & (consumed < i))
                        {
                            success = InterpreterMatchCommand(DbgGlobalData.DbgBuffer + consumed, i - consumed, &tmp, CX_TRUE, CX_NULL);
                            consumed += tmp;
                            if (!success)
                            {
                                // We do not match any of our commands.
                                // Check if this is an introspection debugging command.
                                _CheckIfIntroCommandAndExecute(DbgGlobalData.DbgBuffer + consumed, i - consumed);
                            }
                        }

                        // commit any consumed bytes
                        if (consumed > 0)
                        {
                            // cut down consumed bytes from buffer
                            for (k = (CX_UINT32)consumed; k < DbgGlobalData.DbgBuffLen-1; k++)
                            {
                                DbgGlobalData.DbgBuffer[k-consumed] = DbgGlobalData.DbgBuffer[k]; // [0] <- [consumed] and so on
                            }
                            DbgGlobalData.DbgBuffLen -= (i+1);
                            // restart processing for any remaining data
                            i = 0;

                            continue;
                        }
                    }
                }

                // cut down command from buffer
                for (k = i; k < DbgGlobalData.DbgBuffLen-1; k++)
                {
                    DbgGlobalData.DbgBuffer[k-i] = DbgGlobalData.DbgBuffer[k+1];
                }
                DbgGlobalData.DbgBuffLen = DbgGlobalData.DbgBuffLen - (i+1);

                // stop processing commands on 'go' / 'g'
                if (DbgGlobalData.GotGo) break;

                // show prompter if there is no more data in the buffer (except maybe a '\n' and there was at least one command )
                if ( (DbgGlobalData.DbgBuffLen <= 1) && (i > 1) )
                {
                    _DbgResetDebugBuffer();

                    _DbgShowPrompter();
                }

                // restart processing
                i = 0;
                continue;
            }

            i++;

        } // while

        if (DbgGlobalData.GotGo) break;
    } // while (CX_TRUE)

    if (CfgFeaturesNmiPerformanceCounterTicksPerSecond)
    {
        CX_UINT32 i = 0;
        // on GO reset the watchdog timer for current PCPU
        for (i = 0; i < gBootInfo->CpuCount; i++)
        {
            gHypervisorGlobalData.CpuData.Cpu[i]->NmiWatchDog.StartingRootModeTsc = HvGetTscTickCount();
        }
    }

    {
        status = IpiResumeCpus(&requestId);
        if (!CX_SUCCESS(status))
        {
            LOG_FUNC_FAIL("IpiResumeCpus", status);
            status = CX_STATUS_SUCCESS;
        }
    }

    gInDebugger = CX_FALSE;

    return CX_STATUS_SUCCESS;
}

/* Static functions */
static
CX_BOOL
_CheckIfIntroCommandAndExecute(
    _In_ char   *Input,
    _In_ CX_INT64  Length
)
{
#define MAX_INTRO_ARGC  50

    CHAR *cmdLine = CX_NULL;
    CX_BOOL functionSucceeded = CX_TRUE;

    if (Input[0] != '!')
    {
        functionSucceeded = CX_FALSE;
        goto cleanup;
    }

    if (!gHypervisorGlobalData.Introspection.GlueIface.DebugProcessCommand)
    {
        ERROR("DebugProcessCommand callback not initialized! Probably no introspection...\n");
        functionSucceeded = CX_FALSE;
        goto cleanup;
    }

    STATUS status = HpAllocWithTag(&cmdLine, Length + 1, TAG_DBG);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("HpAllocWithTag", status);
        functionSucceeded = CX_FALSE; cmdLine = CX_NULL;
        goto cleanup;
    }
    memcpy(cmdLine, Input, Length);

    CX_UINT32 index = 0;
    CX_UINT32 argc = 0;
    CHAR *argv[MAX_INTRO_ARGC] = { CX_NULL };
    while (CX_TRUE)
    {
        // Skip leading spaces
        while ((index < Length) && (cmdLine[index] == ' ')) ++index;

        // All the (remaining) cmdline was just spaces
        // or we reach the end of cmdline.
        // Stop processing if no more chars.
        if (index >= Length) break;

        // Found argv
        argv[argc++] = &(cmdLine[index]);

        if (argc >= MAX_INTRO_ARGC) break;

        // Skip current argv until we got a space or end of cmdline
        while ((index < Length) && (cmdLine[index] != ' ')) ++index;
        cmdLine[index] = 0;
        ++index;
    }

    HvAcquireRwSpinLockShared(&HvGetCurrentGuest()->Intro.IntroCallbacksLock);
    NapIntDebugProcessCommand(HvGetCurrentVcpu()->Guest, HvGetCurrentCpuIndex(), argc, argv);
    HvReleaseRwSpinLockShared(&HvGetCurrentGuest()->Intro.IntroCallbacksLock);

cleanup:
    if (cmdLine) HpFreeAndNullWithTag(&cmdLine, TAG_DBG);

    return functionSucceeded;
}

static
CX_STATUS
_PrintGuestRegs(
    void
)
{
    VCPU *vcpu;
    CX_UINT64 cs = 0, ss = 0, ds = 0, es = 0, gs = 0, tr = 0;
    CX_UINT64 cs_base = 0, ss_base = 0, ds_base = 0, es_base = 0, gs_base = 0, tr_base = 0, rip = 0, rsp = 0;
    CX_UINT64 cs_rights = 0, ss_rights = 0, ds_rights = 0, es_rights = 0, gs_rights = 0, tr_rights = 0;
    CX_UINT64 cr0 = 0, cr3 = 0, cr4 = 0;
    CX_UINT64 gdtr_base = 0, gdtr_limit = 0, idtr_base = 0, idtr_limit = 0;

    vcpu = HvGetCurrentVcpu();

    if (!vcpu)
    {
        HvPrint("ERROR: there is NO current VCPU\n");
        return CX_STATUS_SUCCESS;
    }

    vmx_vmread(VMCS_GUEST_CS, &cs);
    vmx_vmread(VMCS_GUEST_CS_BASE, &cs_base);
    vmx_vmread(VMCS_GUEST_CS_ACCESS_RIGHTS, &cs_rights);
    vmx_vmread(VMCS_GUEST_SS, &ss);
    vmx_vmread(VMCS_GUEST_SS_BASE, &ss_base);
    vmx_vmread(VMCS_GUEST_SS_ACCESS_RIGHTS, &ss_rights);
    vmx_vmread(VMCS_GUEST_DS, &ds);
    vmx_vmread(VMCS_GUEST_DS_BASE, &ds_base);
    vmx_vmread(VMCS_GUEST_DS_ACCESS_RIGHTS, &ds_rights);
    vmx_vmread(VMCS_GUEST_ES, &es);
    vmx_vmread(VMCS_GUEST_ES_BASE, &es_base);
    vmx_vmread(VMCS_GUEST_ES_ACCESS_RIGHTS, &es_rights);
    vmx_vmread(VMCS_GUEST_GS, &gs);
    vmx_vmread(VMCS_GUEST_GS_BASE, &gs_base);
    vmx_vmread(VMCS_GUEST_GS_ACCESS_RIGHTS, &gs_rights);
    vmx_vmread(VMCS_GUEST_TR, &tr);
    vmx_vmread(VMCS_GUEST_TR_BASE, &tr_base);
    vmx_vmread(VMCS_GUEST_TR_ACCESS_RIGHTS, &tr_rights);
    vmx_vmread(VMCS_GUEST_RIP, &rip);
    vmx_vmread(VMCS_GUEST_RSP, &rsp);

    vmx_vmread(VMCS_GUEST_CR0, &cr0);
    vmx_vmread(VMCS_GUEST_CR3, &cr3);
    vmx_vmread(VMCS_GUEST_CR4, &cr4);
    vmx_vmread(VMCS_GUEST_GDTR_BASE, &gdtr_base);
    vmx_vmread(VMCS_GUEST_GDTR_LIMIT, &gdtr_limit);
    vmx_vmread(VMCS_GUEST_IDTR_BASE, &idtr_base);
    vmx_vmread(VMCS_GUEST_IDTR_LIMIT, &idtr_limit);

    HvPrint("[DBG %d] VCPU.VmExitCount = %d   EFLAGS = 0x%08x\n"
            "  CS = 0x%04x / 0x%08jx / R 0x%04x   RIP = 0x%016jx\n"
            "  SS = 0x%04x / 0x%08jx / R 0x%04x   RSP = 0x%016jx\n"
            "  RAX = 0x%016jx   RCX = 0x%016jx\n"
            "  RDX = 0x%016jx   RBX = 0x%016jx\n"
            "  RSP = 0x%016jx   RBP = 0x%016jx\n"
            "  RSI = 0x%016jx   RDI = 0x%016jx\n"
            "   R8 = 0x%016jx    R9 = 0x%016jx\n"
            "  R10 = 0x%016jx   R11 = 0x%016jx\n"
            "  R12 = 0x%016jx   R13 = 0x%016jx\n"
            "  R14 = 0x%016jx   R15 = 0x%016jx\n"
            "  DS = 0x%04x / 0x%08jx / R 0x%04x\n"
            "  ES = 0x%04x / 0x%08jx / R 0x%04x\n"
            "  GS = 0x%04x / 0x%08jx / R 0x%04x\n"
            "  TR = 0x%04x / 0x%08jx / R 0x%04x\n"
            "  CR0 = 0x%08x   CR4 = 0x%08x\n"
            "  CR3 = 0x%016jx\n"
            "  GDTR = 0x%016jx / L 0x%08x\n"
            "  IDTR = 0x%016jx / L 0x%08x\n"
            , HvGetCurrentApicId(),
            vcpu->ExitCount, (CX_UINT32)vcpu->ArchRegs.RFLAGS,
            (CX_UINT32)cs, cs_base, (CX_UINT32)cs_rights, rip,
            (CX_UINT32)ss, ss_base, (CX_UINT32)ss_rights, rsp,
            vcpu->ArchRegs.RAX, vcpu->ArchRegs.RCX,
            vcpu->ArchRegs.RDX, vcpu->ArchRegs.RBX,
            rsp, vcpu->ArchRegs.RBP,
            vcpu->ArchRegs.RSI, vcpu->ArchRegs.RDI,
            vcpu->ArchRegs.R8, vcpu->ArchRegs.R9,
            vcpu->ArchRegs.R10, vcpu->ArchRegs.R11,
            vcpu->ArchRegs.R12, vcpu->ArchRegs.R13,
            vcpu->ArchRegs.R14, vcpu->ArchRegs.R15,
            (CX_UINT32)ds, ds_base, (CX_UINT32)ds_rights,
            (CX_UINT32)es, es_base, (CX_UINT32)es_rights,
            (CX_UINT32)gs, gs_base, (CX_UINT32)gs_rights,
            (CX_UINT32)tr, tr_base, (CX_UINT32)tr_rights,
            (CX_UINT32)cr0, (CX_UINT32)cr4,
            cr3,
            gdtr_base, gdtr_limit,
            idtr_base, idtr_limit
    );

    if (0 != vcpu->DebugContext.SingleStep)
    {
        HvPrint("[DBG %d] LAST VALUES from VCPU\n"
                "  #4 CS = 0x%04x / 0x%08jx   RIP = 0x%016jx\n"
                "  #3 CS = 0x%04x / 0x%08jx   RIP = 0x%016jx\n"
                "  #2 CS = 0x%04x / 0x%08jx   RIP = 0x%016jx\n"
                "  #1 CS = 0x%04x / 0x%08jx   RIP = 0x%016jx\n"
                , HvGetCurrentApicId(),
                (CX_UINT32)vcpu->DebugContext.LastCs[4], vcpu->DebugContext.LastCsBase[4], vcpu->DebugContext.LastRip[4],
                (CX_UINT32)vcpu->DebugContext.LastCs[3], vcpu->DebugContext.LastCsBase[3], vcpu->DebugContext.LastRip[3],
                (CX_UINT32)vcpu->DebugContext.LastCs[2], vcpu->DebugContext.LastCsBase[2], vcpu->DebugContext.LastRip[2],
                (CX_UINT32)vcpu->DebugContext.LastCs[1], vcpu->DebugContext.LastCsBase[1], vcpu->DebugContext.LastRip[1]);
    }

    return CX_STATUS_SUCCESS;
}

static CX_STATUS
_DbgAnalyzePointer(
    _In_ CX_UINT64 Hva,
    __out_opt CX_UINT64 *CallAddress
)
//
// Needed for a more accurate stack trace.
//
{
    CX_STATUS status;
    CX_UINT8 *code;
    INSTRUX instruction = {0};
    CX_UINT64 qwCalledFuncAddr, i;
    CX_BOOL isCall;

    // init
    code = (CX_UINT8 *)(Hva - 7);
    isCall = CX_TRUE;
    qwCalledFuncAddr = 0;
    status = CX_STATUS_INVALID_INTERNAL_STATE;

    if (!MmIsMemReadable(&gHvMm, (CX_VOID *)Hva, 1))
    {
        return STATUS_ACCESS_REQUIREMENTS_NOT_MET;
    }

    //
    // We check from big instructions to small ones. This assures that the instructions will be
    // decoded with prefixes. Also 5-byte instructions (0xe8 calls) are the most frequent ones
    //
    for (i = 0; i <= 5; i++)
    {
        status = NdDecode(&instruction, code + i, ND_CODE_64, ND_DATA_64);
        if (!CX_SUCCESS(status))
        {
            continue;
        }

        if (ND_CAT_CALL != instruction.Category) continue;

        // get the call address if that's possible
        switch (instruction.PrimaryOpCode)
        {
            // A simple call, relative to RIP
        case 0xE8:
        {
            qwCalledFuncAddr = Hva + ND_SIGN_EX(instruction.RelOffsLength, instruction.RelativeOffset);
            break;
        }

        case 0xFF:
        {
            CX_UINT8 reg = (instruction.Rex.b << 3) | instruction.ModRm.rm;

            // call [RIP + disp32]
            if (instruction.ModRm.mod == 0 && (reg == 5 || reg == 13))
            {
                // In protected/compatibility mode, this is just disp32, but in long mode this is
                // [RIP]+disp32 (for 64-bit addresses) or [EIP]+disp32 (for 32-bit addresses)
                CX_UINT64 fetchAddress = Hva + ND_SIGN_EX_32(instruction.Displacement);

                qwCalledFuncAddr = *(CX_UINT64 *)fetchAddress;
            }
            // using SIB
            else if (reg == 4 || reg == 12)
            {
                CX_UINT8 index = (instruction.Rex.x << 3) | instruction.Sib.index;

                // No need to extend base with rex_b
                if (instruction.ModRm.mod == 0 && index == 4 && (instruction.Sib.base == 5))
                {
                    qwCalledFuncAddr = instruction.Displacement;
                }
            }

            break;
        }

        default:
            break;
        }

        // Make sure that instruction length is good (it doesn't override return address & it hasn't slack space)
        if (Hva == Hva - (7 - i) + instruction.Length)
        {
            goto cleanup_and_leave;
        }
    }

    //
    // If we get here and don't find a good instruction then it's no good
    //
    isCall = CX_FALSE;

cleanup_and_leave:
    if (!isCall) status = CX_STATUS_DATA_NOT_FOUND;

    if (CallAddress) *CallAddress = qwCalledFuncAddr;

    return status;
}

static
__forceinline
CX_BOOL
_DbgCheckIfEnterMarkerPresentInBuffer(
    _In_reads_bytes_(BuffLength)
    const char*     Buffer,
    _In_        CX_UINT32           BuffLength
)
{
    assert(Buffer != CX_NULL);

    // check if we have the "enter dbg" marker
    for (CX_UINT32 i = 0; i < BuffLength; i++)
    {
        if ((Buffer[i] == '\r') || (Buffer[i] == '\n'))
        {
            // we have the marker so break in debugger
            return CX_TRUE;
        }
    }

    return CX_FALSE;
}

static
__forceinline
CX_VOID
_DbgShowPrompter(
    CX_VOID
)
{
    if (HvGetCurrentVcpu() != CX_NULL && HvGetCurrentCpu() != CX_NULL )
    {
        HvPrint("[%d] #%d.%d> ",
                HvGetCurrentCpu()->BootInfoIndex,
                HvGetCurrentVcpu()->Guest->Index,
                HvGetCurrentVcpu()->GuestCpuIndex
        );
    }
}

static
__forceinline
CX_BOOL
_IsMemLogReady(
    CX_VOID
)
{
    return ((gSerialInited && gSerialEnabled)) && (gFeedback && gFeedback->Logger.Initialized);
}

static
CX_VOID
_DbgResetDebugBuffer(
    CX_VOID
)
{
    memset(DbgGlobalData.DbgBuffer, 0, MAX_DEBUG_BUFFER);
    DbgGlobalData.DbgBuffLen = 0;
}

static
CX_STATUS
_DbgDumpCommandParameters(
    _In_ DBG_COMMAND *Command,
    _In_ CX_BOOL IncludeDetails
)
//
// helper function, displays generic help for a command's parameter types
//
{
    CX_UINT32 j;
    CX_BOOL hasParams = CX_FALSE;
    if (!Command) return CX_STATUS_INVALID_PARAMETER_1;

    for (j = 0; j < DBG_NUMBER_OF_PARAM_TYPES; j++)
    {
        CX_UINT64 typeMaskValue = ((CX_UINT64)1) << ((CX_UINT64)(2*j));

        CX_BOOL isRequired = (0 != (typeMaskValue & Command->UsedParametersMask));
        CX_BOOL isOptional = (0 != (DBG_TYPE_OPT(typeMaskValue) & Command->UsedParametersMask)); /// there's no defined semantic for both...
        if (isRequired || isOptional) hasParams = CX_TRUE;
        if (isRequired)
        {
            if (DbgTypeDescriptions[j].DisplayedName != CX_NULL)
            {
                LOGN("%s ", DbgTypeDescriptions[j].DisplayedName);
            }
            else
            {
                LOGN("PARAM_%d ", typeMaskValue);
            }
        }
        else if (isOptional)
        {
            if (DbgTypeDescriptions[j].DisplayedName != CX_NULL)
            {
                LOGN("[%s] ", DbgTypeDescriptions[j].DisplayedName);
            }
            else
            {
                LOGN("[PARAM_%d] ", typeMaskValue);
            }
        }
    }
    if (!hasParams) LOGN("no parameters ");
    if (Command->Help) LOGN(" - %s\n", Command->Help);
    if (IncludeDetails)
    {
        LOGN("\n");
        // log parameter descriptions
        for (j = 0; j < DBG_NUMBER_OF_PARAM_TYPES; j++)
        {
            CX_UINT64 typeMaskValue = ((CX_UINT64)1) << ((CX_UINT64)(2*j));

            CX_BOOL isRequired = (0 != (typeMaskValue & Command->UsedParametersMask));
            CX_BOOL isOptional = (0 != (DBG_TYPE_OPT(typeMaskValue) & Command->UsedParametersMask)); /// there's no defined semantic for both...
            if (isRequired || isOptional) LOGN("    %-16s %s\n", DbgTypeDescriptions[j].DisplayedName, DbgTypeDescriptions[j].Description);
        }
    }
    // log command documentation
    if (( Command->Syntax) && (IncludeDetails))
    {
        LOGN("\n");
        LOGN("    Parameter details\n");
        LOGN("        %s\n", Command->Syntax);
    }
    return CX_STATUS_SUCCESS;
}

/* Debugging comands */
static
CX_STATUS
DbgCommandHeapTagStats(
    _In_ CX_UINT64 ParamMask,
    _In_opt_ CX_UINT64 HeapIndex
)
{
    CX_STATUS status;
    INT8 index;
    HTS_VECTOR hts;
    CX_INT32 k;
    CHAR tagText[5];

    status = CX_STATUS_UNINITIALIZED_STATUS_VALUE;

    if (ParamMask & DBG_TYPE_VALUE0)
    {
        index = (INT8)(HeapIndex & 0xFF);
    }
    else
    {
        index = -1;
    }

    // get statistics
    status = HpGenerateHeapTagStats(index, &hts);
    if (!CX_SUCCESS(status))
    {
        HvPrint("ERROR: HpGenerateHeapTagStats failed, status=%s\n", NtStatusToString(status));
        goto cleanup;
    }

    // dump statistics
    HvPrint("dumping HEAP TAG statistics for %d tags   flags 0x%08x\n", hts.TagCount, hts.Flags);
    for (k = 0; k < hts.TagCount; k++)
    {
        // inverse (NT DDK) ordered decoding!
        tagText[3] = (CHAR)((hts.Tag[k].Tag & 0xFF000000) >> 24);
        tagText[2] = (CHAR)((hts.Tag[k].Tag & 0x00FF0000) >> 16);
        tagText[1] = (CHAR)((hts.Tag[k].Tag & 0x0000FF00) >> 8);
        tagText[0] = (CHAR)(hts.Tag[k].Tag & 0x000000FF);
        tagText[4] = 0;

        HvPrint("[%4s] %6d allocs  %10lld bytes   %10lld average / alloc\n",
                tagText, hts.Tag[k].AllocCount, hts.Tag[k].TotalBytes,
                hts.Tag[k].TotalBytes / CX_MAX(hts.Tag[k].AllocCount, 1));
    }

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}

static
CX_STATUS
DbgCommandLocks(
    _In_ CX_UINT64 ParamMask,
    _In_opt_ CX_UINT64 Flags
)
{
    // 0 = dump, 1 = clear, 2 = reset
    if (0 == (ParamMask & DBG_TYPE_OPT_VALUE0)) Flags = 0;

    if (Flags == 0)
    {
        DlDumpAllStats();
    }
    else if (Flags == 1)
    {
        DlReinitLockStats();
    }
    else if (Flags == 2)
    {
        DlResetLockStats();
    }
    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
DbgCommandGo(
    CX_VOID
)
{
    DbgGlobalData.GotGo = CX_TRUE;

    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
DbgCommandSwCpu(
    _In_ CX_UINT64 CpuIndex
)
{
    if (CpuIndex >= gHypervisorGlobalData.CpuData.CpuCount)
    {
        LOG("Invalid cpu index\n");
        return CX_STATUS_SUCCESS;
    }

    gHypervisorGlobalData.CpuData.Cpu[CpuIndex]->DebugBreak = CX_TRUE;

    LOG("Switching debugger to CPU %d\n", CpuIndex);

    return DbgCommandGo();
}

static
CX_STATUS
DbgCommandEptrx(
    _In_ DBG_PARAM_MEMTARGET* MemTarget,
    _In_ CX_UINT64 Address
)
{
    if (MemTarget->IsHostNotGuest)
    {
        LOG("Use a guest address with this command\n");
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    if (!MemTarget->IsPhysicalNotVirtual)
    {
        LOG("Use a guest PHYSICAL address with this command\n");
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    // set EPT attribs
    CX_STATUS status = EptSetRights(GstGetEptOfPhysicalMemory(gHypervisorGlobalData.Guest[MemTarget->VcpuTarget.GuestIndex]),
                            Address,
                            0,
                            EPT_RIGHTS_RX
    );
    if (!CX_SUCCESS(status))
    {
        ERROR("EptSetCacheAndRights failed for gpa 0x%016llx, status = 0x%08x\n", Address, status);
    }
    else
    {
        LOG("EptSetCacheAndRights success for GPA = 0x%016llx\n", Address);
    }

    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
DbgCommandLogOn(
    CX_VOID
)
{
    IoEnableSerialOutput(CX_TRUE);
    HvPrint("will turn on serial logging\n");
    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
DbgCommandLogOff(
    CX_VOID
)
{
    LOG("will turn off serial logging\n");
    IoEnableSerialOutput(CX_FALSE);
    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
DbgCommandEmulInt(
    CX_VOID
)
{
    CX_UINT8 opcode, vector;
    CX_UINT16 cs, ss;
    CX_UINT64 rip = 0, rsp;
    CX_UINT64 stack;
    CX_UINT64 rflags;
    CX_UINT16 csInt;
    CX_UINT64 ripInt;
    CX_UINT64 temp = 0;
    VCPU *vcpu;

    vcpu = HvGetCurrentVcpu();

    // IMPORTANT: we ASSMUE that we are exactly in the context of the interrupted guest / vcpu / vmcs

    // get current instrux CS:RIP
    vmx_vmread(VMCS_GUEST_CS, &temp);
    cs = (CX_UINT16)temp;
    vmx_vmread(VMCS_GUEST_RIP, &rip);

    // check that we have a software INT instrux
    // we now ASSUME 16 bit REAL MODE operation and direct guest mapping !!!!!!!
    opcode = *((CX_UINT8 *)((((CX_UINT64)cs) << 4) + (CX_UINT16)rip));
    vector = *((CX_UINT8 *)((((CX_UINT64)cs) << 4) + (CX_UINT16)rip + 1));

    if (opcode != 0xCD)
    {
        HvPrint("[DBG] ERROR: no software INT (0xCD) found at current CS 0x%04x : IP 0x%04x\n", cs, (CX_UINT32)rip);
        return CX_STATUS_SUCCESS;
    }

    // get other parameters
    vmx_vmread(VMCS_GUEST_SS, &temp);
    ss = (CX_UINT16)temp;
    vmx_vmread(VMCS_GUEST_RSP, &rsp);
    stack = ((((CX_UINT64)ss) << 4) + (CX_UINT16)rsp);
    rflags = vcpu->ArchRegs.RFLAGS;

    csInt = *(CX_UINT16 *)(((CX_UINT64)vector) * 4 + 2);
    ripInt = *(CX_UINT16 *)(((CX_UINT64)vector) * 4);

    HvPrint("[DBG] INTEMUL, CS:IP 0x%04x:0x%04x, SS:SP 0x%04x:0x%04x, EFLAGS 0x%08x, VECTOR 0x%02x, new CS:IP 0x%04x:0x%04x\n",
            cs, (CX_UINT32)rip, ss, (CX_UINT32)rsp, (CX_UINT32)rflags, vector, csInt, (CX_UINT32)ripInt);

    //
    // simulate INT instrux; conform Vol 2A, page 3-516, "INT n/INTO/INT 3-Call to Interrupt Procedure"
    //

    // 1. Push (EFLAGS[15:0]);
    //    SP <- SP - 2;
    //    Memory[SS:SP] <- TEMP; (* Push word *)
    rsp = rsp - 2;
    vcpu->ArchRegs.RSP = rsp;
    stack = stack - 2;
    *((CX_UINT16 *)(stack)) = (CX_UINT16)rflags;               // save return FLAGS

    // 2. IF <- 0; (* Clear interrupt flag *)
    //    TF <- 0; (* Clear trap flag *)            <== this we do NOT clear !!!!!
    //    AC <- 0; (* Clear AC flag *)
    rflags = rflags & (~((CX_UINT64)(RFLAGS_IF | RFLAGS_AC)));      // clear IF and AC
    vcpu->ArchRegs.RFLAGS = rflags;

    // 3. Push(CS);
    //    Push(IP);
    rsp = rsp - 4;
    vcpu->ArchRegs.RSP = rsp;
    stack = stack - 2;
    *((CX_UINT16 *)(stack)) = (CX_UINT16)cs;                   // save return CS:IP
    stack = stack - 2;
    *((CX_UINT16 *)(stack)) = (CX_UINT16)(rip + 2);            // skip "0xCD 0x??" at return !!!

    // 4. CS <- IDT(Descriptor (vector_number << 2), selector));
    //    EIP <- IDT(Descriptor (vector_number << 2), offset)); (* 16 bit offset AND 0000FFFFH *)
    if (0 != vmx_vmwrite(VMCS_GUEST_CS, csInt))
    {
        ERROR("vmx_vmwrite has failed!\n");
        return CX_STATUS_UNEXPECTED_IO_ERROR;
    }

    if (0 != vmx_vmwrite(VMCS_GUEST_CS_BASE, (((CX_UINT64)csInt) << 4)))
    {
        ERROR("vmx_vmwrite has failed!\n");
        return CX_STATUS_UNEXPECTED_IO_ERROR;
    }

    vcpu->ArchRegs.RIP = ripInt;

    HvPrint("[DBG] INTEMUL, guest register state reset, will do 'regs'...\n");

    _PrintGuestRegs();

    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
DbgCommandEmuTrace(
    CX_VOID
)
{
    if (CfgDebugTraceEmulatorEnabled)
    {
        HvPrint("Emulator trace for all CPUs:\n");

        CX_UINT32 backInTimeNumber;
        for (CX_UINT8 cpuIndex = 0; cpuIndex < gBootInfo->CpuCount; cpuIndex++)
        {
            HvPrint("Last instructions for CPU [%d]\n", cpuIndex);

            for (backInTimeNumber = 0; backInTimeNumber < EmuDebugGetTableSize(DBG_TABLE_TRACE); backInTimeNumber++)
            {
                EMU_TRACE_ENTRY emuTraceDebugEntry;
                EmuDebugGetTraceEntry(cpuIndex, backInTimeNumber, &emuTraceDebugEntry, CX_FALSE);

                if (!emuTraceDebugEntry.IsValid) continue;

                HvPrint("CPU-%02x RIP-0x%016llx: ", cpuIndex, emuTraceDebugEntry.EmulatedRip);

                CX_UINT32 instructionIndex;
                for (instructionIndex = 0; instructionIndex < emuTraceDebugEntry.EmulatedBytes.Length; instructionIndex++)
                {
                    HvPrint("%02X ", emuTraceDebugEntry.EmulatedBytes.InstructionBytes[instructionIndex]);
                }

                for (; instructionIndex < 16; instructionIndex++)
                {
                    HvPrint("   ");
                }

                HvPrint(" %s ", emuTraceDebugEntry.EmulatedDis);

                HvPrint("(GVA: %018p, Value load: %018p, Value store: %018p, Size: %d)\n",
                        emuTraceDebugEntry.EmulatedTargetGva,
                        emuTraceDebugEntry.EmulatedTargetValueLoad,
                        emuTraceDebugEntry.EmulatedTargetValueStore,
                        emuTraceDebugEntry.EmulatedTargetSize
                );

                // dump context
                HvPrint("Context before:\n");
                HvPrint("        RAX = 0x%016llx RCX = 0x%016llx RDX = 0x%016llx RBX = 0x%016llx\n"
                        "        RSP = 0x%016llx RBP = 0x%016llx RSI = 0x%016llx RDI = 0x%016llx\n"
                        "        R8  = 0x%016llx R9  = 0x%016llx R10 = 0x%016llx R11 = 0x%016llx\n"
                        "        R12 = 0x%016llx R13 = 0x%016llx R14 = 0x%016llx R15 = 0x%016llx\n"
                        "        RIP = 0x%016llx RFLAGS = 0x%016llx\n",
                        emuTraceDebugEntry.EmulatedContextBefore.RAX, emuTraceDebugEntry.EmulatedContextBefore.RCX,
                        emuTraceDebugEntry.EmulatedContextBefore.RDX, emuTraceDebugEntry.EmulatedContextBefore.RBX,
                        emuTraceDebugEntry.EmulatedContextBefore.RSP, emuTraceDebugEntry.EmulatedContextBefore.RBP,
                        emuTraceDebugEntry.EmulatedContextBefore.RSI, emuTraceDebugEntry.EmulatedContextBefore.RDI,
                        emuTraceDebugEntry.EmulatedContextBefore.R8,  emuTraceDebugEntry.EmulatedContextBefore.R9,
                        emuTraceDebugEntry.EmulatedContextBefore.R10, emuTraceDebugEntry.EmulatedContextBefore.R11,
                        emuTraceDebugEntry.EmulatedContextBefore.R12, emuTraceDebugEntry.EmulatedContextBefore.R13,
                        emuTraceDebugEntry.EmulatedContextBefore.R14, emuTraceDebugEntry.EmulatedContextBefore.R15,
                        emuTraceDebugEntry.EmulatedContextBefore.RIP, emuTraceDebugEntry.EmulatedContextBefore.RFLAGS);

                // dump context
                HvPrint("Context after:\n");
                HvPrint("        RAX = 0x%016llx RCX = 0x%016llx RDX = 0x%016llx RBX = 0x%016llx\n"
                        "        RSP = 0x%016llx RBP = 0x%016llx RSI = 0x%016llx RDI = 0x%016llx\n"
                        "        R8  = 0x%016llx R9  = 0x%016llx R10 = 0x%016llx R11 = 0x%016llx\n"
                        "        R12 = 0x%016llx R13 = 0x%016llx R14 = 0x%016llx R15 = 0x%016llx\n"
                        "        RIP = 0x%016llx RFLAGS = 0x%016llx\n",
                        emuTraceDebugEntry.EmulatedContextAfter.RAX, emuTraceDebugEntry.EmulatedContextAfter.RCX,
                        emuTraceDebugEntry.EmulatedContextAfter.RDX, emuTraceDebugEntry.EmulatedContextAfter.RBX,
                        emuTraceDebugEntry.EmulatedContextAfter.RSP, emuTraceDebugEntry.EmulatedContextAfter.RBP,
                        emuTraceDebugEntry.EmulatedContextAfter.RSI, emuTraceDebugEntry.EmulatedContextAfter.RDI,
                        emuTraceDebugEntry.EmulatedContextAfter.R8,  emuTraceDebugEntry.EmulatedContextAfter.R9,
                        emuTraceDebugEntry.EmulatedContextAfter.R10, emuTraceDebugEntry.EmulatedContextAfter.R11,
                        emuTraceDebugEntry.EmulatedContextAfter.R12, emuTraceDebugEntry.EmulatedContextAfter.R13,
                        emuTraceDebugEntry.EmulatedContextAfter.R14, emuTraceDebugEntry.EmulatedContextAfter.R15,
                        emuTraceDebugEntry.EmulatedContextAfter.RIP, emuTraceDebugEntry.EmulatedContextAfter.RFLAGS);
            }
            HvPrint("\n");
        }

        HvPrint("EMU TLB cache:\n");
        for (backInTimeNumber = 0; backInTimeNumber < EmuDebugGetTableSize(DBG_TABLE_TLB); backInTimeNumber++)
        {
            EMU_TLB_ENTRY emuTlbDebugEntry;
            EmuDebugGetTlbEntry(backInTimeNumber, &emuTlbDebugEntry, CX_FALSE);

            if (!emuTlbDebugEntry.IsValid) continue;

            HvPrint("CPU %d -> GVA: %018p, Flags: 0x%08x, ReqFlags: 0x%08x, Size: %d\n",
                    emuTlbDebugEntry.Cpu,
                    emuTlbDebugEntry.Gva,
                    emuTlbDebugEntry.Flags,
                    emuTlbDebugEntry.RequiredFlags,
                    emuTlbDebugEntry.Size);
        }
    }
    else
    {
        HvPrint("\nEmulator tracing is disabled via CFG_ENABLE_EMULATOR_TRACE.\n");
    }

    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
DbgCommandMtrr(
    CX_VOID
)
{
    CX_INT32 i;
    MTRR_STATE *mtrrState;

    mtrrState = CX_NULL;

    LOGN("MTRR state dump:\n");

    LOGN("MTRR state for host at boot time:\n");
    DumpersDumpMTRRSate(&gHypervisorGlobalData.MemInfo.MtrrState);

    for (i = 0;i<gHypervisorGlobalData.GuestCount;i++)
    {
        if (i == 0) LOGN("MTRR state for Windows guest:\n");

        DumpersDumpMTRRSate(gHypervisorGlobalData.Guest[i]->Mtrr);
    }

    HpAllocWithTagCore(&mtrrState, sizeof(MTRR_STATE), TAG_DBG);
    if (mtrrState != CX_NULL)
    {
        LOGN("MTRR state for host now:\n");
        MtrrBuildState(mtrrState);
        DumpersDumpMTRRSate(mtrrState);
        HpFreeAndNullWithTag(&mtrrState, TAG_DBG);
    }

    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
DbgCommandHfpu(
    CX_VOID
)
{
    return DumpersDumpHostFpuState();
}

static
CX_STATUS
DbgCommandGfpu(
    _In_ CX_UINT64                  UsedParametersMask,
    _In_ DBG_PARAM_VCPUTARGET   *Target
)
{
    VCPU *vcpu;

    if ((UsedParametersMask & DBG_TYPE_OPT_VCPUTARGET))
    {
        CX_STATUS status = InterpreterValidateVcpuTarget(Target);
        if (CX_STATUS_SUCCESS != status)
        {
            LOG("DbgCommandGfpu: failed, invalid vcpu target specified\n");
            return status;
        }

        vcpu = gHypervisorGlobalData.Guest[Target->GuestIndex]->Vcpu[Target->VcpuIndex];
    }
    else
    {
        vcpu = HvGetCurrentVcpu();
    }

    return DumpersDumpGuestFpuState(vcpu);
}

static
CX_STATUS
DbgCommandDept(
    _In_ DBG_PARAM_MEMTARGET *MemTarget,
    _In_ CX_UINT64            Address
)
{
    if (MemTarget->IsHostNotGuest)
    {
        LOG("Use a GUEST address with this command\n");
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    if (!MemTarget->IsPhysicalNotVirtual)
    {
        LOG("Use a host PHYSICAL address with this command\n");
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    for (CX_INT32 i = 0; i < gHypervisorGlobalData.GuestCount; i++)
    {
        LOG("[EPT] page-table walk for %p on guest[%d]\n", Address & 0xFFFFFFFFFFFFF000ULL, i);
        DumpersDumpEptPageTablesWalk(HvGetCurrentVcpu(), Address & 0xFFFFFFFFFFFFF000ULL);
    }

    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
DbgCommandBranches(
    _In_ CX_UINT64 CpuIndex
)
{
    if (CpuIndex < gHypervisorGlobalData.CpuData.CpuCount)
    {
        DbDsDumpBranches(gHypervisorGlobalData.CpuData.Cpu[CpuIndex]);
    }
    else
    {
        LOG("Invalid cpu index!\n");
    }

    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
DbgCommandReboot(
    _In_ CX_UINT64 UsedParametersMask,
    _In_ CX_UINT64 Value
)
{
    UNREFERENCED_PARAMETER(Value);

    HvPrint("Rebooting the target machine...\n");

    PwrReboot(CX_FALSE, (UsedParametersMask & DBG_TYPE_OPT_VALUE0) != 0);

    // If we got here, something is wrong.
    LOG("Couldn't reboot... :(\n");

    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
DbgCommandSetInstructionTracing(
    _In_ CX_UINT64 UsedParametersMask,
    _In_ DBG_PARAM_VCPUTARGET *Target,
    _In_ CX_UINT64 Value
)
{
    if (!Target) return CX_STATUS_INVALID_PARAMETER_2;

    if (!CX_SUCCESS(InterpreterValidateVcpuTarget(Target)))
    {
        LOGN("Invalid VCPU target!\n");
        return CX_STATUS_INVALID_PARAMETER_2;
    }

    VCPU *vcpu = gHypervisorGlobalData.Guest[Target->GuestIndex]->Vcpu[Target->VcpuIndex];

    if (0 == (UsedParametersMask & DBG_TYPE_OPT_VALUE0))
    {
        Value = 1;  // use 1 by default (if not specified)
    }

    DumpersConfigureInstructionTracing(vcpu, Value);

    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
DbgCommandTracingAll(
    _In_ CX_UINT64 UsedParametersMask,
    _In_ CX_UINT64 Value
)
{
    CX_INT32 g;
    CX_UINT32 v;
    VCPU *vcpu;

    if (0 == (UsedParametersMask & DBG_TYPE_OPT_VALUE0))
    {
        Value = 1;  // use 1 by default (if not specified)
    }
    for (g = 0; g < gHypervisorGlobalData.GuestCount; g++)
    {
        for (v = 0; v < gHypervisorGlobalData.Guest[g]->VcpuCount; v++)
        {
            vcpu = gHypervisorGlobalData.Guest[g]->Vcpu[v];
            DumpersConfigureInstructionTracing(vcpu, Value);
        }
    }
    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
DbgCommandDumpDevTree(
    CX_VOID
)
{
    PciDumpDevice3(CX_TRUE);

    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
DbgTraceDevice(
    _In_ CX_UINT64 Bus,
    _In_ CX_UINT64 Device,
    _In_ CX_UINT64 Function
)
{
    return PciTraceDevice(HvGetCurrentGuest(), (PCICFG_ID){.Segment = 0, .Bus = (CX_UINT16)Bus, .Device = (CX_UINT16)Device, .Function = (CX_UINT16)Function});
}

static
CX_STATUS
DbgCommandHelp(
    _In_ CX_UINT64 UsedParametersMask,
    _In_ char *CommandName
)
//
// Provide command list or help for a given command
//
{
    CX_UINT32 i;
    DBG_COMMAND *command = CX_NULL;
    // do we have a command name ?
    LOGN("\n");
    if ((0 != (UsedParametersMask & DBG_TYPE_OPT_SYMBOL)) && ( CommandName))
    {
        // information for the given command
        for (i = 0; i < DBG_NUMBER_OF_COMMANDS; i++)
        {
            if (!strnicmp(DbgCommands[i].Name, CommandName, CX_MIN(strlen(DbgCommands[i].Name), strlen(CommandName))))
            {
                // log command name
                LOGN("%-16s ", DbgCommands[i].Name);

                // log expected parameter types
                command = &(DbgCommands[i]);
                _DbgDumpCommandParameters(command, CX_TRUE);
            }
        }
    }
    else
    {
        // generic help
        for (i = 0; i < DBG_NUMBER_OF_COMMANDS; i++)
        {
            LOGN("%-16s ", DbgCommands[i].Name);
            _DbgDumpCommandParameters(&(DbgCommands[i]), CX_FALSE);
        }
        LOGN("\n\nType syntax info\n");
        for (i = 0; i < DBG_NUMBER_OF_DESCRIPTIONS; i++)
        {
            LOGN("  -%-16s %s\n", DbgTypeDescriptions[i].DisplayedName, DbgTypeDescriptions[i].Description);
        }

        LOGN("Type \"help [command-name]\" to see how to use a command\n");
        LOGN("Type \"!help\" to see introspection debugger commands.\n");
    }

    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
DbgCommandDumpTargetRange(
    _In_ CX_UINT64 UsedParametersMask,
    _In_ char *Options,
    _In_ DBG_PARAM_TARGETRANGE *Memory
)
//
// memory dump for any kind of memory
//
{
    CX_UINT64 flags = 0;
    if (!Memory) return CX_STATUS_INVALID_PARAMETER_3;

    LOGN("Dumping %d bytes from memory at HVA=%p\n", Memory->Size, Memory->Address);

    // check for options
    if (0 != (UsedParametersMask & DBG_TYPE_OPT_SYMBOL))
    {
        if (Options)
        {
            CX_UINT32 i;
            i = 0;
            while (Options[i] != 0)
            {
                if (Options[i] == 'm')  // minimal
                {
                    flags |= DBG_MEMDUMP_MINIMAL;
                }
                else if (Options[i] == 'h') // -address
                {
                    flags |= DBG_MEMDUMP_DISABLE_HEX;
                }
                else if (Options[i] == 'a') // -address
                {
                    flags |= DBG_MEMDUMP_DISABLE_ADDR;
                }
                else if (Options[i] == 'c') // - chars
                {
                    flags |= DBG_MEMDUMP_DISABLE_CHARS;
                }
                else if (Options[i] == 'l') // - lines
                {
                    flags |= DBG_MEMDUMP_DISABLE_NEWLINES;
                }
                else if (Options[i] == 'p') // packed
                {
                    flags |= DBG_MEMDUMP_DISABLE_HEXSPACE;
                }
                else if (Options[i] == 'e') // extended output (32 bytes / line)
                {
                    flags |= DBG_MEMDUMP_WIDE;
                }
                else if (Options[i] == 'w') // extended output (32 bytes / line)
                {
                    flags |= DBG_MEMDUMP_WORDS;
                }
                else if (Options[i] == 'd') // extended output (32 bytes / line)
                {
                    flags |= DBG_MEMDUMP_DWORDS;
                }
                else if (Options[i] == 'q') // extended output (32 bytes / line)
                {
                    flags |= DBG_MEMDUMP_QWORDS;
                }
                else if (Options[i] == 'i') // prefix with the apic id each line
                {
                    flags |= DBG_MEMDUMP_APICID;
                }
                else if (Options[i] == 'n') // prefix with the apic id each line
                {
                    flags |= DBG_MEMDUMP_DISABLE_ALIGN;
                }
                i++;
            }
        }
    }
    return DumpersMemDumpEx(
        0, 0, 0, 0, 0, 0, 0,
        Memory
    );
}

static
CX_STATUS
DbgCommandDumpGuestsEptHooks(
    void
)
{
    CX_INT32 g = 0;
    CX_UINT32 i = 0;

    for (g = 0; g < gHypervisorGlobalData.GuestCount; g++)
    {
        LOGN("G%d Ept hooks:\n", g);
        if (!gHypervisorGlobalData.Guest[g]) continue;

        for (i = 0; i < gHypervisorGlobalData.Guest[g]->EptHooks.Count; i++)
        {
            LOGN("     * %018p - %018p\n", gHypervisorGlobalData.Guest[g]->EptHooks.Hook[i].BaseAddress, gHypervisorGlobalData.Guest[g]->EptHooks.Hook[i].MaxAddress);
        }
    }

    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
DbgCommandDumpGuestsMsrHooks(
    void
)
{
    for (CX_INT32 g = 0; g < gHypervisorGlobalData.GuestCount; g++)
    {
        if (!gHypervisorGlobalData.Guest[g]) continue;

        LOGN("G%d MSR hooks as seen by the hypervisor:\n", g);
        for (CX_UINT32 i = 0; i < gHypervisorGlobalData.Guest[g]->MsrHooks.Count; i++)
        {
            GUEST_MSR_HOOK *msrHook = &gHypervisorGlobalData.Guest[g]->MsrHooks.Hook[i];

            LOGN("     * 0x%08X - 0x%08X (%s)\n", msrHook->Msr, msrHook->MaxMsr,
                ((msrHook->ReadCb != CX_NULL) && (msrHook->WriteCb)) ? "R/W" : (msrHook->ReadCb ? "R" : "W"));
        }
    }

    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
DbgCommandDisasmTargetRange(
    _In_ CX_UINT64 UsedParametersMask,
    _In_ DBG_PARAM_TARGETRANGE *Memory,
    _In_ CX_UINT64 Bits
)
{
    CX_UINT64 options;
    if (!Memory) return CX_STATUS_INVALID_PARAMETER_2;
    options = 0;
    if (0 != (UsedParametersMask & DBG_TYPE_OPT_VALUE0))
    {
        switch(Bits)
        {
        case 16: options = DBG_DISASM_16; break;
        case 32: options = DBG_DISASM_32; break;
        case 64: options = DBG_DISASM_64; break;
        default: LOG("WARNING, defaults applied: %d is not a valid architecture, use 16 32 or 64\n");
        }
    }

    return DumpersMemDisasm(
        0,0,0,0,0,0,0,
        Memory
    );
}

static
CX_STATUS
DbgCommandDumpArchRegs(
    _In_ CX_UINT64 UsedParametersMask,
    _In_ DBG_PARAM_VCPUTARGET *Target
)
{
    VCPU *vcpu;
    ARCH_REGS *ptr;
    CX_STATUS status;
    char *prefix = "";

    if (!Target) return CX_STATUS_INVALID_PARAMETER_2;
    UNREFERENCED_PARAMETER(UsedParametersMask);

    DUMP_BEGIN;

    // validate the given vcpu target
    status = InterpreterValidateVcpuTarget(Target);
    if (CX_STATUS_SUCCESS != status)
    {
        LOG("DbgCommandDumpArchRegs failed, make sure your parameters are correct");
        status = CX_STATUS_INVALID_PARAMETER_2;
        goto cleanup;
    }

    vcpu = gHypervisorGlobalData.Guest[Target->GuestIndex]->Vcpu[Target->VcpuIndex];   // all pointers were already validated via InterpreterValidateVcpuTarget
    ptr = &(vcpu->ArchRegs);
    {
        LOGN("%-10s - %016p: dumping (cached) ARCH_REGS of #%d.%d\n", prefix, ptr, Target->GuestIndex, Target->VcpuIndex);
        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(ptr->RAX), "(CX_UINT64) RAX", ptr->RAX);
        LOGN("%-10s - %016p: %-46s 0x%08X\n", prefix, &(ptr->EAX), "(CX_UINT32) EAX", ptr->EAX);
        LOGN("%-10s - %016p: %-46s 0x%04X\n", prefix, &(ptr->AX), "(CX_UINT16) AX", ptr->AX);
        LOGN("%-10s - %016p: %-46s 0x%02X\n", prefix, &(ptr->AL), "(CX_UINT8) AL", ptr->AL);
        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(ptr->RCX), "(CX_UINT64) RCX", ptr->RCX);
        LOGN("%-10s - %016p: %-46s 0x%08X\n", prefix, &(ptr->ECX), "(CX_UINT32) ECX", ptr->ECX);
        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(ptr->RDX), "(CX_UINT64) RDX", ptr->RDX);
        LOGN("%-10s - %016p: %-46s 0x%08X\n", prefix, &(ptr->EDX), "(CX_UINT32) EDX", ptr->EDX);
        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(ptr->RBX), "(CX_UINT64) RBX", ptr->RBX);
        LOGN("%-10s - %016p: %-46s 0x%08X\n", prefix, &(ptr->EBX), "(CX_UINT32) EBX", ptr->EBX);
        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(ptr->RSP), "(CX_UINT64) RSP", ptr->RSP);
        LOGN("%-10s - %016p: %-46s 0x%08X\n", prefix, &(ptr->ESP), "(CX_UINT32) ESP", ptr->ESP);
        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(ptr->RBP), "(CX_UINT64) RBP", ptr->RBP);
        LOGN("%-10s - %016p: %-46s 0x%08X\n", prefix, &(ptr->EBP), "(CX_UINT32) EBP", ptr->EBP);
        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(ptr->RSI), "(CX_UINT64) RSI", ptr->RSI);
        LOGN("%-10s - %016p: %-46s 0x%08X\n", prefix, &(ptr->ESI), "(CX_UINT32) ESI", ptr->ESI);
        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(ptr->RDI), "(CX_UINT64) RDI", ptr->RDI);
        LOGN("%-10s - %016p: %-46s 0x%08X\n", prefix, &(ptr->EDI), "(CX_UINT32) EDI", ptr->EDI);
        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(ptr->R8), "(CX_UINT64) R8", ptr->R8);
        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(ptr->R9), "(CX_UINT64) R9", ptr->R9);
        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(ptr->R10), "(CX_UINT64) R10", ptr->R10);
        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(ptr->R11), "(CX_UINT64) R11", ptr->R11);
        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(ptr->R12), "(CX_UINT64) R12", ptr->R12);
        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(ptr->R13), "(CX_UINT64) R13", ptr->R13);
        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(ptr->R14), "(CX_UINT64) R14", ptr->R14);
        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(ptr->R15), "(CX_UINT64) R15", ptr->R15);
        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(ptr->DR7), "(CX_UINT64) DR7", ptr->DR7);
        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(ptr->RFLAGS), "(CX_UINT64) RFLAGS", ptr->RFLAGS);
        LOGN("%-10s - %016p: %-46s 0x%08X\n", prefix, &(ptr->EFLAGS), "(CX_UINT32) EFLAGS", ptr->EFLAGS);
        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(ptr->RIP), "(CX_UINT64) RIP", ptr->RIP);
        LOGN("%-10s - %016p: %-46s 0x%08X\n", prefix, &(ptr->EIP), "(CX_UINT32) EIP", ptr->EIP);
        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(ptr->CR0), "(CX_UINT64) CR0", ptr->CR0);
        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(ptr->CR2), "(CX_UINT64) CR2", ptr->CR2);
        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(ptr->CR3), "(CX_UINT64) CR3", ptr->CR3);
        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(ptr->CR4), "(CX_UINT64) CR4", ptr->CR4);
        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(ptr->CR8), "(CX_UINT64) CR8", ptr->CR8);
        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(ptr->XCR0), "(CX_UINT64) XCR0", ptr->XCR0);
        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(ptr->_Reserved6), "(CX_UINT64) _Reserved6", ptr->_Reserved6);
        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(ptr->_Reserved7), "(CX_UINT64) _Reserved7", ptr->_Reserved7);
    }

    status = CX_STATUS_SUCCESS;
cleanup:
    DUMP_END;
    return status;
}

static
CX_STATUS
DbgCommandDbgbreak(
    CX_VOID
)
{
    VirtExcInjectException(CX_NULL, HvGetCurrentVcpu(), EXCEPTION_BREAKPOINT, 0, 0);
    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
DbgCommandDumpVcpu(
    _In_ CX_UINT64 UsedParametersMask,
    _In_ DBG_PARAM_VCPUTARGET *Target
)
{
    UNREFERENCED_PARAMETER(UsedParametersMask);

    VCPU *vcpu;
    CX_STATUS status;
    CX_UINT64 i;
    CHAR *prefix = "";
    CX_UINT32 arrayElements = 16;

    if (!Target) return CX_STATUS_INVALID_PARAMETER_2;
    DUMP_BEGIN;

    // validate the given vcpu target
    status = InterpreterValidateVcpuTarget(Target);
    if (CX_STATUS_SUCCESS != status)
    {
        LOG("DbgCommandDumpVcpu failed, make sure your parameters are correct");
        status = CX_STATUS_INVALID_PARAMETER_2;
        goto cleanup;
    }

    vcpu = gHypervisorGlobalData.Guest[Target->GuestIndex]->Vcpu[Target->VcpuIndex];   // all pointers were already validated via InterpreterValidateVcpuTarget
    {
        LOGN("%-10s - %016p: dumping VCPU #%d.%d\n", prefix, vcpu, Target->GuestIndex, Target->VcpuIndex);
        LOGN("%-10s - %016p: %-46s 0x%04X\n", prefix, &(vcpu->State), "(CX_UINT16) State", vcpu->State);
        LOGN("%-10s - %016p: %-46s 0x%08X\n", prefix, &(vcpu->Schedulable), "(CX_UINT32) Schedulable", vcpu->Schedulable);
        LOGN("%-10s - %016p: %-45s* %016p\n", prefix, &(vcpu->Pcpu), "(CPU) *Pcpu", vcpu->Pcpu);
        LOGN("%-10s - %016p: %-45s* %016p\n", prefix, &(vcpu->Guest), "(GUEST) *Guest", vcpu->Guest);
        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(vcpu->GuestExitRoutine), "(CX_VOID *) GuestExitRoutine", vcpu->GuestExitRoutine);
        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(vcpu->ExitCount), "(CX_INT64) ExitCount", vcpu->ExitCount);
        LOGN("%-10s - %016p: %-46s 0x%04X\n", prefix, &(vcpu->Vpid), "(CX_UINT16) Vpid", vcpu->Vpid);
        LOGN("%-10s - %016p: %-46s 0x%02X\n", prefix, &(vcpu->GuestIndex), "(CX_UINT8) GuestIndex", vcpu->GuestIndex);
        LOGN("%-10s - %016p: %-46s 0x%02X\n", prefix, &(vcpu->GuestCpuIndex), "(CX_UINT8) GuestCpuIndex", vcpu->GuestCpuIndex);
        LOGN("%-10s - %016p: %-46s 0x%08X\n", prefix, &(vcpu->LapicId), "(CX_UINT32) LapicId", vcpu->LapicId);
        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(vcpu->LastExitTsc), "(CX_UINT64) LastExitTsc", vcpu->LastExitTsc);
        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(vcpu->LastEntryTsc), "(CX_UINT64) LastEntryTsc", vcpu->LastEntryTsc);
        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(vcpu->LinearTsc), "(CX_UINT64) LinearTsc", vcpu->LinearTsc);
        LOGN("%-10s - %016p: %-45s* %016p\n", prefix, &(vcpu->ArchRegs), "(ARCH_REGS) ArchRegs", &(vcpu->ArchRegs));
        LOGN("%-10s - %016p: %-46s %d\n", prefix, &(vcpu->RestoreExtState), "(CX_BOOL) RestoreExtState", vcpu->RestoreExtState);
        LOGN("%-10s - %016p: %-45s* %016p\n", prefix, &(vcpu->Mtrr), "(MTRR_STATE) *Mtrr", vcpu->Mtrr);
        LOGN("%-10s - %016p: %-45s* %016p\n", prefix, &(vcpu->BootState), "(CPUSTATE_GUEST_STATE_INFO) *BootState", vcpu->BootState);
        LOGN("%-10s - %016p: %-45s* %016p\n", prefix, &(vcpu->Guest->EmhvIface), "(EMHV_INTERFACE) *EmhvIface", vcpu->Guest->EmhvIface);
        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(vcpu->Vmcs), "(CX_VOID *) Vmcs", vcpu->Vmcs);
        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(vcpu->VmcsPa), "(CX_UINT64) VmcsPa", vcpu->VmcsPa);
        LOGN("%-10s - %016p: %-45s* %016p\n", prefix, &(vcpu->VmcsConfig), "(VMCS_CONFIG) VmcsConfig", &(vcpu->VmcsConfig));

        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(vcpu->VmxTimerQuantum), "(CX_UINT64) VmxTimerQuantum", vcpu->VmxTimerQuantum);
        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(vcpu->ReadShadowCR0), "(CX_UINT64) ReadShadowCR0", vcpu->ReadShadowCR0);
        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(vcpu->GuestHostMaskCR0), "(CX_UINT64) GuestHostMaskCR0", vcpu->GuestHostMaskCR0);
        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(vcpu->ReadShadowCR4), "(CX_UINT64) ReadShadowCR4", vcpu->ReadShadowCR4);
        LOGN("%-10s - %016p: %-46s %016p\n", prefix, &(vcpu->GuestHostMaskCR4), "(CX_UINT64) GuestHostMaskCR4", vcpu->GuestHostMaskCR4);
        LOGN("%-10s - %016p: %-46s %d\n", prefix, &(vcpu->EmulatingEptViolation), "(CX_BOOL) EmulatingEptViolation", vcpu->EmulatingEptViolation);
        LOGN("%-10s - %016p: %-46s %d\n", prefix, &(vcpu->SafeToReExecute), "(CX_BOOL) SafeToReExecute", vcpu->SafeToReExecute);
        LOGN("%-10s - %016p: %-45s* %016p\n", prefix, &(vcpu->CachedTranslations), "(CHM_CACHE) CachedTranslations", &(vcpu->CachedTranslations));
        for (i = 0; (i < arrayElements) && (i < CHM_VA_TRANSLATIONS); i++)
        {
            LOGN("%-10s - %016p: %-42s[%d]* %016p\n", prefix, &(vcpu->TranslationsArray[i]), "(CHM_CACHE_ENTRY) TranslationsArray[]", i, &(vcpu->TranslationsArray[i]));
        }

        for (i = 0; (i < arrayElements) && (i < LAST_EXIT_REASONS_COUNT); i++)
        {
            LOGN("%-10s - %016p: %-43s[%d] 0x%08X\n", prefix, &(vcpu->LastExitReasons[i]), "(CX_UINT32) LastExitReasons[]", i, vcpu->LastExitReasons[i].Reason);
        }
        LOGN("%-10s - %016p: %-46s 0x%08X\n", prefix, &(vcpu->LastExitReasonIndex), "(CX_UINT32) LastExitReasonIndex", vcpu->LastExitReasonIndex);
        LOGN("%-10s - %016p: %-46s 0x%08X\n", prefix, &(vcpu->UsedExitReasonEntries), "(CX_UINT32) UsedExitReasonEntries", vcpu->UsedExitReasonEntries);

        LOGN("%-10s - %016p: %-45s* %016p\n", prefix, &(vcpu->AttachedPcpu), "(CPU) *AttachedPcpu", vcpu->AttachedPcpu);

        LOGN("%-10s - %016p: %-46s %d\n", prefix, &(vcpu->IsBsp), "(CX_BOOL) IsBsp", vcpu->IsBsp);

        LOGN("%-10s - %016p: %-46s 0x%08X\n", prefix, &(vcpu->VcpuException.ExceptionInjectionMask), "(BIT 2) EXCEPTION_NMI", vcpu->VcpuException.ExceptionInjectionMask);

        LOGN("%-10s - %016p: %-46s 0x%02X\n", prefix, &(vcpu->DebugContext.SingleStep), "(CX_UINT8) SingleStep", vcpu->DebugContext.SingleStep);

        for (i = 0; (i < arrayElements) && (i < MAX_CSRIP_TRACE); i++)
        {
            LOGN("%-10s - %016p: %-43s[%d] 0x%04X\n", prefix, &(vcpu->DebugContext.LastCs[i]), "(CX_UINT16) LastCs[]", i, vcpu->DebugContext.LastCs[i]);
        }
        for (i = 0; (i < arrayElements) && (i < MAX_CSRIP_TRACE); i++)
        {
            LOGN("%-10s - %016p: %-43s[%d] %016p\n", prefix, &(vcpu->DebugContext.LastCsBase[i]), "(CX_UINT64) LastCsBase[]", i, vcpu->DebugContext.LastCsBase[i]);
        }
        for (i = 0; (i < arrayElements) && (i < MAX_CSRIP_TRACE); i++)
        {
            LOGN("%-10s - %016p: %-43s[%d] %016p\n", prefix, &(vcpu->DebugContext.LastRip[i]), "(CX_UINT64) LastRip[]", i, vcpu->DebugContext.LastRip[i]);
        }
    }

    status = CX_STATUS_SUCCESS;

cleanup:
    DUMP_END;
    return status;;
}

static
CX_STATUS
DbgCommandSetDefaultVcpuTarget(
    _In_ CX_UINT64 UsedParametersMask,
    _In_ DBG_PARAM_VCPUTARGET *Target
)
//
// set and/or display the current vcpu used as a default value when one is not specified
//
{
    CX_STATUS status;
    if (!Target) return CX_STATUS_INVALID_PARAMETER_2;
    if (0 != (UsedParametersMask & DBG_TYPE_OPT_VCPUTARGET))
    {
        // set a default value
        status = InterpreterValidateVcpuTarget(Target);
        if (CX_STATUS_SUCCESS != status)
        {
            LOG("DbgCommandSetDefaultVcpuTarget: failed, invalid vcpu target specified\n");
            return CX_STATUS_UNINITIALIZED_STATUS_VALUE;
        }
        DbgDefaultParams.VcpuTarget = *Target;
    }

    LOGN("Using VCPU #%d.%d\n", DbgDefaultParams.VcpuTarget.GuestIndex, DbgDefaultParams.VcpuTarget.VcpuIndex);
    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
DbgCommandSetDefaultMemTarget(
    _In_ CX_UINT64 UsedParametersMask,
    _In_ DBG_PARAM_MEMTARGET *Target
)
//
// set and/or display the current memory target used by default when one is not specified
//
{
    CX_STATUS status;

    // set a default value
    if (0 != (UsedParametersMask & DBG_TYPE_OPT_MEMTARGET))
    {
        if (!MmIsMemReadable(&gHvMm, Target, sizeof(DBG_PARAM_MEMTARGET)))
        {
            return CX_STATUS_INVALID_PARAMETER_2;
        }

        if ((!Target->IsHostNotGuest) && (!Target->IsPhysicalNotVirtual))
        {
            status = InterpreterValidateVcpuTarget(&(Target->VcpuTarget));
            if (CX_STATUS_SUCCESS != status)
            {
                LOG("DbgCommandSetDefaultMemTarget: failed, invalid vcpu target specified\n");
                return CX_STATUS_UNINITIALIZED_STATUS_VALUE;
            }
        }
        else if (!Target->IsHostNotGuest)
        {
            // validate guest
            if (Target->VcpuTarget.GuestIndex >= gHypervisorGlobalData.GuestCount)
            {
                LOG("DbgCommandSetDefaultMemTarget: %d is not a valid guest index\n", Target->VcpuTarget.GuestIndex);
                return CX_STATUS_UNINITIALIZED_STATUS_VALUE;
            }
            if (!MmIsMemReadable(&gHvMm, gHypervisorGlobalData.Guest[Target->VcpuTarget.GuestIndex], sizeof(GUEST)))
            {
                LOG("DbgCommandSetDefaultMemTarget: guest[%d] points to an invalid memory region\n", Target->VcpuTarget.GuestIndex);
                return CX_STATUS_UNINITIALIZED_STATUS_VALUE;
            }
        }
        DbgDefaultParams.MemTarget = *Target;
    }

    // display current info
    if (DbgDefaultParams.MemTarget.IsHostNotGuest)
    {
        LOGN("Using memory of #h.%c\n", (DbgDefaultParams.MemTarget.IsPhysicalNotVirtual)? 'p':'v');
    }
    else if (DbgDefaultParams.MemTarget.IsPhysicalNotVirtual)
    {
        LOGN("Using memory of #%d.p\n", DbgDefaultParams.VcpuTarget.GuestIndex);
    }
    else
    {
        LOGN("Using memory of #%d.%d.v\n", DbgDefaultParams.VcpuTarget.GuestIndex, DbgDefaultParams.VcpuTarget.VcpuIndex);
    }
    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
DbgCommandDumpVmcs(
    _In_ CX_UINT64 UsedParametersMask,
    _In_ DBG_PARAM_VCPUTARGET *Target
)
{
    VCPU *vcpu;
    CX_UINT64 currentVmcsPA = 0;
    UCHAR res;
    CX_STATUS status;

    if (!Target) return CX_STATUS_INVALID_PARAMETER_2;
    UNREFERENCED_PARAMETER(UsedParametersMask);

    DUMP_BEGIN;

    status = InterpreterValidateVcpuTarget(Target);
    if (CX_STATUS_SUCCESS != status)
    {
        LOG("DbgCommandDumpVmcs: failed, the vcpu target is invalid\n");
        status = CX_STATUS_INVALID_PARAMETER_2;
        goto cleanup;
    }


    vcpu = gHypervisorGlobalData.Guest[Target->GuestIndex]->Vcpu[Target->VcpuIndex];   // all pointers were validated already

    LOGN("Dumping current VMCS fields of vcpu #%d.%d\n", Target->GuestIndex, Target->VcpuIndex);
    // Save current VMCS
    __vmx_vmptrst(&currentVmcsPA);

    // Load designated VMCS
    res = __vmx_vmptrld(&vcpu->VmcsPa);
    if (res == 0)
    {
        // Dump current VMCS
        DumpCurrentVmcs(vcpu->GuestCpuIndex);

        // Restore VMCS
        res = __vmx_vmptrld(&currentVmcsPA);
        if (res != 0) LOG("DbgCommandDumpVmcs: could not restore original VMCS from PA: %p\n", vcpu->VmcsPa);
    }
    status = CX_STATUS_SUCCESS;

cleanup:
    DUMP_END;
    return status;
}

static
CX_STATUS
DbgCommandBreakOn(
    _In_ CX_UINT64 UsedParametersMask,
    _In_ char *Condition,
    _In_ DBG_PARAM_VCPUTARGET *Target
)
{
    UNREFERENCED_PARAMETER(UsedParametersMask);

    if (!Condition) return CX_STATUS_INVALID_PARAMETER_2;
    if (!Target) return CX_STATUS_INVALID_PARAMETER_3;

    if (!CX_SUCCESS(InterpreterValidateVcpuTarget(Target)))
    {
        LOGN("Invalid VCPU Target!\n");
        return CX_STATUS_INVALID_PARAMETER_3;
    }

    char *input = Condition;
    CX_INT64 len = strlen(input);
    CX_INT64 consumed = 0;
    CX_STATUS status;

    VCPU *vcpu = gHypervisorGlobalData.Guest[Target->GuestIndex]->Vcpu[Target->VcpuIndex];

    // skip "" or other decorators
    InterpreterMatchSymbol(input, len, &consumed, &input, &len);
    if (vcpu->DebugContext.BreakOnCondition) HpFreeAndNullWithTag(&(vcpu->DebugContext.BreakOnCondition), TAG_DBG);

    status = HpAllocWithTagCore(&(vcpu->DebugContext.BreakOnCondition), (CX_UINT32)(1+len), TAG_DBG);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("HpAllocWithTagCore", status);
        LOG("Failed setting condition\n");
        return status;
    }
    memcpy(vcpu->DebugContext.BreakOnCondition, input, len);
    vcpu->DebugContext.BreakOnCondition[len] = 0;

    LOG("WILL BREAK ON <%s>\n", vcpu->DebugContext.BreakOnCondition);
    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
DbgCommandTrigger(
    _In_ CX_UINT64 UsedParametersMask,
    _In_ char *Condition,
    _In_ char *Command,
    _In_ DBG_PARAM_VCPUTARGET *Target
)
{
    UNREFERENCED_PARAMETER(UsedParametersMask);

    if (!Condition) return CX_STATUS_INVALID_PARAMETER_2;
    if (!Command) return CX_STATUS_INVALID_PARAMETER_3;
    if (!Target) return CX_STATUS_INVALID_PARAMETER_4;

    if (!CX_SUCCESS(InterpreterValidateVcpuTarget(Target)))
    {
        LOGN("Invalid VCPU Target!\n");
        return CX_STATUS_INVALID_PARAMETER_3;
    }

    char *input = Condition;
    CX_INT64 len = strlen(input);
    CX_INT64 consumed = 0;
    CX_STATUS status;

    VCPU *vcpu = gHypervisorGlobalData.Guest[Target->GuestIndex]->Vcpu[Target->VcpuIndex];

    // skip "" or other decorators
    InterpreterMatchSymbol(input, len, &consumed, &input, &len);
    if (vcpu->DebugContext.TriggerCondition) HpFreeAndNullWithTag(&(vcpu->DebugContext.TriggerCondition), TAG_DBG);

    status = HpAllocWithTagCore(&(vcpu->DebugContext.TriggerCondition), (CX_UINT32)(1+len), TAG_DBG);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("HpAllocWithTagCore", status);
        LOG("Failed setting condition\n");
        return status;
    }
    memcpy(vcpu->DebugContext.TriggerCondition, input, len);
    vcpu->DebugContext.TriggerCondition[len] = 0;

    // skip "" or other decorators
    input = Command;
    len = strlen(input);
    InterpreterMatchSymbol(input, len, &consumed, &input, &len);
    if (vcpu->DebugContext.TriggerCommand) HpFreeAndNullWithTag(&(vcpu->DebugContext.TriggerCommand), TAG_DBG);

    status = HpAllocWithTagCore(&(vcpu->DebugContext.TriggerCommand), (CX_UINT32)(1+len), TAG_DBG);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("HpAllocWithTagCore", status);
        LOG("Failed setting condition\n");
        return status;
    }
    memcpy(vcpu->DebugContext.TriggerCommand, input, len);
    vcpu->DebugContext.TriggerCommand[len] = 0;

    VCPULOG(vcpu, "WILL EVALUATE COMMAND <%s> EACH TIME <%s>\n", vcpu->DebugContext.TriggerCommand, vcpu->DebugContext.TriggerCondition);
    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
DbgCommandDumpHvaTranslation(
    _In_ CX_UINT64 UsedParametersMask,
    _In_ CX_UINT64 Va,
    _In_ CX_UINT64 Size
)
{
    if (UsedParametersMask & DBG_TYPE_OPT_VALUE1)
    {
        HvaDumpRangeInfo((CX_VOID *)Va, (HVA_PAGE_COUNT)CX_PAGE_COUNT_4K(Va, Size));
    }
    else
    {
        HvaDumpTranslationInfo((CX_VOID *)Va);
    }

    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
DbgCommandDumpGlobalStats(
    CX_VOID
)
{
    DumpersDumpGlobalStats(CX_TRUE);
    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
DbgCommandHostRegs(
    CX_VOID
)
{
    DumpersDumpControlRegisters("Host control registers\n");
    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
DbgCommandTranslateaGuestAddress(
    _In_ DBG_PARAM_MEMTARGET *MemTarget,
    _In_ CX_UINT64 Address
)
{
    CX_STATUS status;
    if (MemTarget->IsHostNotGuest)
    {
        LOG("Use a guest address with this command\n");
        return CX_STATUS_UNINITIALIZED_STATUS_VALUE;
    }

    if (!MemTarget->IsPhysicalNotVirtual)
    {
        CX_UINT64 gpa = 0, hpa = 0;
        status = ChmGvaToGpaAndHpa(gHypervisorGlobalData.Guest[MemTarget->VcpuTarget.GuestIndex]->Vcpu[MemTarget->VcpuTarget.VcpuIndex],
                                   Address, &gpa, &hpa);
        if (!CX_SUCCESS(status))
        {
            LOG("GVA = %p could not be translated, status = %s!\n", Address, NtStatusToString(status));
            return CX_STATUS_SUCCESS;
        }
        LOG("GVA=%p => GPA=%p => HPA=%p\n", Address, gpa, hpa);
    }
    else
    {
        CX_UINT64 hpa = 0;
        status = ChmGpaToHpa(gHypervisorGlobalData.Guest[MemTarget->VcpuTarget.GuestIndex], Address, &hpa);
        if (!CX_SUCCESS(status))
        {
            LOG("GPA = %p could not be translated, status = %s!\n", Address, NtStatusToString(status));
            return CX_STATUS_SUCCESS;
        }
        LOG("GPA=%p => HPA=%p\n", Address, hpa);
    }
    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
DbgCommandInPortDword(
    _In_ CX_UINT64 Port
)
{
    LOG("Port: 0x%04X, Value: 0x%08X\n", (CX_UINT16)Port, __indword((CX_UINT16)Port));

    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
DbgCommandOutPortDword(
    _In_ CX_UINT64 Port,
    _In_ CX_UINT64 Value
)
{
    __outdword((CX_UINT16)Port, (CX_UINT32)Value);

    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
DbgCommandInPortByte(
    _In_ CX_UINT64 Port
)
{
    LOG("InPort: 0x%04X, Value: 0x%02X\n", (CX_UINT16)Port, __inbyte((CX_UINT16)Port));

    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
DbgCommandOutPortByte(
    _In_ CX_UINT64 Port,
    _In_ CX_UINT64 Value
)
{
    LOG("OutPort: 0x%04X, Value: 0x%02X\n", (CX_UINT16)Port, (CX_UINT32)Value);
    __outbyte((CX_UINT16)Port, (UCHAR)Value);

    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
DbgCommandMMap(
    _In_ CX_UINT8 GuestIndex,
    _In_ CX_UINT8 MapType
)
{

    LOG("Dumping memory map of type %d for guest %d\n", MapType, GuestIndex);

    if (GuestIndex == 0xFF)
    {
        switch(MapType)
        {
        case 0: // phys map
            MmapDump(&gHypervisorGlobalData.MemInfo.PhysMap, BOOT_MEM_TYPE_AVAILABLE, "Global PhysMap, ");
            break;
        case 1: // hyper map
            MmapDump(&gHypervisorGlobalData.MemInfo.HyperMap, BOOT_MEM_TYPE_RAM_HYPERVISOR_PROTECTED, "Global MemInfo.HyperMap, ");
            break;
        case 2: // guest area map
            MmapDump(&gHypervisorGlobalData.MemInfo.GuestAreaMap, BOOT_MEM_TYPE_RAM_HYPERVISOR_PROTECTED, "Global MemInfo.GuestAreaMap, ");
            break;
        case 3: // dev res map
            break;
        case 4: // Os map
            break;
        case 5: // Mtrr map
            break;
        case 6:    // MMIO Map
            break;
        case 7: // EPT map
            break;
        case 8:
            MmapDump(&gHypervisorGlobalData.MemInfo.AcpiMap, BOOT_MEM_TYPE_RAM_HYPERVISOR_PROTECTED, "Global ACPI Map, ");
        default:
            break;
        }
    }
    else if (GuestIndex < gHypervisorGlobalData.GuestCount)
    {
        GUEST *guest = gHypervisorGlobalData.Guest[GuestIndex];

        switch(MapType)
        {
        case 0: // phys map
            MmapDump(&guest->PhysMap, BOOT_MEM_TYPE_AVAILABLE,
                     "Guest Physical map");
            break;
        case 1: // hyper map
            break;
        case 2: // guest area map
            MmapDump(&gHypervisorGlobalData.MemInfo.GuestAreaMap, BOOT_MEM_TYPE_RAM_HYPERVISOR_PROTECTED, "Global MemInfo.GuestAreaMap, ");
            break;
        case 3: // dev res map
            break;
        case 5: // Mtrr map
            MmapDump(&guest->Mtrr->Map, BOOT_MEM_TYPE_AVAILABLE,
                     "Guest MTRR map");
            break;
        case 6:    // MMIO Map
            MmapDump(&guest->MmioMap, BOOT_MEM_TYPE_AVAILABLE,
                     "Guest MMIO map");
            break;
        case 7: // EPT map
            MmapDump(&guest->EptMap, BOOT_MEM_TYPE_AVAILABLE,
                     "Guest EPT map");
            break;
        default:
            break;
        }
    }
    else
    {
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
DbgCommandStackWalkDvtcK(
    _In_ CX_UINT64 ParamMask,
    _In_opt_ CX_UINT64 CpuIndex
)
{
    CX_STATUS status;
    PCPU *cpu = HvGetCurrentCpu();
    CX_BOOL isKv;
    HV_TRAP_FRAME trapFrame;

    if (ParamMask & DBG_TYPE_VALUE0)
    {
        if (CpuIndex >= gHypervisorGlobalData.CpuData.CpuCount)
        {
            LOG("ERROR: invalid PCPU index (%d) specified!\n", CpuIndex);
            return CX_STATUS_INVALID_PARAMETER_1;
        }

        cpu = gHypervisorGlobalData.CpuData.Cpu[CpuIndex];
    }
    else
    {
        cpu = HvGetCurrentCpu();
    }

    isKv = (0 != (ParamMask & DBG_CUSTOMTYPE_FLAG_KV));

    trapFrame.Rsp = CpuGetRSP();
    trapFrame.Rip = CpuGetRIP();
    trapFrame.Rdi = CpuGetRDI();

    status = DumpersGenerateAndSendStackWalkDump(cpu, &trapFrame, ((ParamMask & DBG_CUSTOMTYPE_FLAGS)));
    if (!CX_SUCCESS(status))
    {
        LOG("DumpersGenerateAndSendStackWalkDump failed with status: 0x%x\n", status);
        status = CX_STATUS_SUCCESS;
        goto cleanup;
    }

    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}

static
CX_STATUS
DbgCommandStackWalkDvtcKV(
    _In_ CX_UINT64 ParamMask,
    _In_opt_ CX_UINT64 CpuIndex
)
{
    return DbgCommandStackWalkDvtcK(ParamMask | DBG_CUSTOMTYPE_FLAG_KV, CpuIndex);
}

static
CX_STATUS
DbgCommandStackWalkDvtcKVX(
    _In_ CX_UINT64 ParamMask,
    _In_opt_ CX_UINT64 CpuIndex
)
{
    return DbgCommandStackWalkDvtcK(ParamMask | DBG_CUSTOMTYPE_FLAG_KV | DBG_CUSTOMTYPE_FLAG_KVX, CpuIndex);
}

static
CX_STATUS
DbgCommandVaTagStats(
    _In_ CX_UINT64 ParamMask,
    _In_opt_ CX_UINT64 VaIndex
)
{
    CX_STATUS status;
    INT8 index;
    HTS_VECTOR hts; // NOTE: VA tag statistics use the same structs as the HEAP TAG stats
    CX_INT32 k;
    CHAR tagText[5];

    if (ParamMask & DBG_TYPE_VALUE0)
    {
        index = (INT8)(VaIndex & 0xFF);
    }
    else
    {
        index = -1;
    }

    // get statistics
    status = VaMgrGenerateDebugTagStats(index, &hts);
    if (!CX_SUCCESS(status))
    {
        HvPrint("ERROR: VaMgrGenerateDebugTagStats failed, status=%s\n", NtStatusToString(status));
        goto cleanup;
    }

    // dump statistics
    HvPrint("dumping VA TAG statistics for %d tags   flags 0x%08x\n", hts.TagCount, hts.Flags);
    for (k = 0; k < hts.TagCount; k++)
    {
        // inverse (NT DDK) ordered decoding!
        tagText[3] = (CHAR)((hts.Tag[k].Tag & 0xFF000000) >> 24);
        tagText[2] = (CHAR)((hts.Tag[k].Tag & 0x00FF0000) >> 16);
        tagText[1] = (CHAR)((hts.Tag[k].Tag & 0x0000FF00) >> 8);
        tagText[0] = (CHAR)(hts.Tag[k].Tag & 0x000000FF);
        tagText[4] = 0;

        HvPrint("[%4s] %6u allocs  %12llu bytes   %12llu average / alloc\n",
                tagText, hts.Tag[k].AllocCount, hts.Tag[k].TotalBytes,
                hts.Tag[k].TotalBytes / CX_MAX(hts.Tag[k].AllocCount, 1));
    }

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}

static
CX_STATUS
DbgCommandHeapWalk(
    _In_ CHAR *TagToWalkFor
)
{
    CX_STATUS status;
    CX_UINT32 tag;

    if ((!TagToWalkFor) || (4 != strlen(TagToWalkFor)))
    {
        HvPrint("ERROR: specified tag '%s' is invalid\n", TagToWalkFor);
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    tag = *((CX_UINT32 *)TagToWalkFor);

    // walk ALL heap allocators (-1)
    status = HpWalkHeapByTag(-1, tag);
    if (!CX_SUCCESS(status))
    {
        LOG("ERROR: HpWalkHeapByTag failed, status=%s\n", NtStatusToString(status));
        goto cleanup;
    }

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}

static
CX_STATUS
DbgCommandVaWalk(
    _In_ CHAR *TagToWalkFor
)
{
    CX_STATUS status;
    CX_UINT32 tag;

    if ((!TagToWalkFor) || (4 != strlen(TagToWalkFor)))
    {
        HvPrint("ERROR: specified tag '%s' is invalid\n", TagToWalkFor);
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    tag = *((CX_UINT32 *)TagToWalkFor);

    // walk ALL dynamic VA allocators (-1)
    status = VaMgrDumpWalkByTagInfo(-1, tag);
    if (!CX_SUCCESS(status))
    {
        LOG("ERROR: VaMgrDumpWalkByTagInfo failed, status=%s\n", NtStatusToString(status));
        goto cleanup;
    }

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}

static
CX_STATUS
DbgCommandIoHooks(
    CX_VOID
)
{
    CX_UINT64 procBasedCtls1;
    unsigned char ret;
    GUEST *guest = HvGetCurrentGuest();

    // check if unconditional io exit bit is set
    ret = vmx_vmread(VMCS_PROC_BASED_EXEC_CONTROL, &procBasedCtls1);
    if (ret != 0)
    {
        ERROR("Failed reading VMCS_PROC_BASED_EXEC_CONTROL! Error: %d\n", ret);
        return CX_STATUS_UNINITIALIZED_STATUS_VALUE;
    }

    LOGN("Unconditional IO exit is: %s\n", (procBasedCtls1 & VMCSFLAG_PROCEXEC_UNCONDITIONAL_IO_EXIT)?"set":"not set");
    LOGN("Use IO Bitmaps is: %s\n", (procBasedCtls1 & VMCSFLAG_PROCEXEC_USE_IO_BITMAPS)?"set":"not set");

    if ((procBasedCtls1 & VMCSFLAG_PROCEXEC_USE_IO_BITMAPS) && (procBasedCtls1 & VMCSFLAG_PROCEXEC_UNCONDITIONAL_IO_EXIT))
    {
        LOGN("ERROR: Conflicting setting detected! Unconditional IO exist and Use IO Bitmaps set at the same time!\n");
    }

    // dump IO bitmaps information
    if (procBasedCtls1 & VMCSFLAG_PROCEXEC_USE_IO_BITMAPS)
    {
        CX_UINT32 startRange, endRange;
#define MAX_PORT    0xFFFF

        LOGN("Dump io port hooks as seen in IO Bitmaps:\n");
        startRange = 0;
        endRange = 0;

        // walk the entire port range space
        while (endRange < (CX_UINT32)MAX_PORT)
        {
            // find the start of a hooked range
            while ( (startRange < (CX_UINT32)MAX_PORT) &&
                (0 == (guest->IoBitmap[startRange >> 6] & BIT_AT(startRange & 0x3f))))
            {
                startRange++;
            }

            if (startRange >= (CX_UINT32)MAX_PORT)
            {
                break;
            }

            // mark the initial end of hooked range
            endRange = startRange;

            // find the end of a hooked range
            while ( (endRange < (CX_UINT32)MAX_PORT) &&
                (0 != (guest->IoBitmap[endRange >> 6] & BIT_AT(endRange & 0x3f))) )
            {
                endRange++;
            }

            // dump the range
            LOGN("Hooked: 0x%x -> 0x%x\n", startRange, endRange - 1);

            //mark the next potential start of hooked range
            startRange = endRange;
        }

    }

    // dump hypervisor io port hook list
    {
        CX_UINT32 i;

        LOGN("Dump io port hooks as seen in hypervisor IO ports hook list:\n");

        for (i = 0; i < guest->IoHooks.Count;i++)
        {
            LOGN("Hooked: 0x%x -> 0x%x\n", guest->IoHooks.Hook[i].Port, guest->IoHooks.Hook[i].MaxPort);
        }
    }

    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
DbgCommandReadMsr(
    _In_ CX_UINT64 Msr
)
{
    LOG("Msr: 0x%x has value: %p\n", Msr, __readmsr((CX_UINT32)Msr));

    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
DbgCommandWriteMsr(
    _In_ CX_UINT64 Msr,
    _In_ CX_UINT64 Value
)
{
    __writemsr((CX_UINT32)Msr, Value);

    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
DbgCommandClearMemoryLog(
    CX_VOID
)
{
    if (_IsMemLogReady())
    {
        LOG("Clearing lastlog...\n");
        MemLogClear(&gFeedback->Logger);
    }

    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
DbgCommandStackTrace(
    _In_ CX_UINT64 Rsp,
    _In_ CX_UINT64 Rip,
    _In_opt_ CX_UINT32 MaxTraces
)
{
    CX_UINT64 newRip, currentStackFrame, newStackFrame, napocaBase;
    CX_UINT8 *pStack, *pStackCopy;
    CX_STATUS status;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS64 pNth64;
    IMAGE_DATA_DIRECTORY dir = {0};
    CX_UINT32 sizeOfNapoca, traces;

    // preinit
    pStack = pStackCopy = CX_NULL;
    newRip = Rip;
    currentStackFrame = Rsp;
    napocaBase = 0x10000000000;
    traces = 0;

    if (!MmIsMemReadable(&gHvMm, (CX_VOID *)Rsp, 1))
    {
        LOGN("Stack address %018p is not present\n", Rsp);
        return STATUS_ACCESS_REQUIREMENTS_NOT_MET;
    }

    if (!MmIsMemReadable(&gHvMm, (CX_VOID *)Rip, 1))
    {
        LOGN("RIP %018p is not present\n", Rip);
        return STATUS_ACCESS_REQUIREMENTS_NOT_MET;
    }

    // we will parse till we found all
    if (0 == MaxTraces)
    {
        MaxTraces = 20;             // shouldn't have more than this...
    }

    // getting the exception directory
    pDosHeader = (PIMAGE_DOS_HEADER)napocaBase;
    pNth64 = (PIMAGE_NT_HEADERS64) (napocaBase + pDosHeader->e_lfanew);
    sizeOfNapoca = pNth64->OptionalHeader.SizeOfImage;
    dir.Size = pNth64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
    dir.VirtualAddress = pNth64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;

    if (dir.VirtualAddress == 0 || dir.Size == 0
        || dir.Size + dir.VirtualAddress > sizeOfNapoca)
    {
        LOG("Invalid exception directory(VA %x, Size %x, Napoca Size %x)\n",
            dir.VirtualAddress, dir.Size, sizeOfNapoca);
        return CX_STATUS_INVALID_DATA_TYPE;
    }

    LOG("Getting stack trace for RSP %018p RIP %018p\n", Rsp, Rip);
    do
    {
        PRUNTIME_FUNCTION pRuntimeFunction;
        CX_UINT32 i;
        CX_UINT32 dwExtraStackSpace = 0, tries = 0;
        PUNWIND_INFO pUnwindInfoMap = CX_NULL;
        CX_BOOL foundReturnAddress, interruptContext, exceptionContext, found;
        CX_UINT64 unwindInfoAddress;

        foundReturnAddress = interruptContext = exceptionContext = CX_FALSE;

        //
        // The structures are ordered in memory by BeginAddress field so search till we find one bigger than ours or we
        // reach the last page
        //
        found = CX_FALSE;
        pRuntimeFunction = (PRUNTIME_FUNCTION)(napocaBase + dir.VirtualAddress);

        while ((CX_UINT64)pRuntimeFunction < napocaBase + dir.Size + dir.VirtualAddress)
        {
            if (newRip - napocaBase >= pRuntimeFunction->BeginAddress
                && newRip - napocaBase < pRuntimeFunction->EndAddress)
            {
                found = CX_TRUE;
                break;
            }

            pRuntimeFunction = (PRUNTIME_FUNCTION)((CX_UINT64)pRuntimeFunction + sizeof(RUNTIME_FUNCTION));
        }

        if (!found)
        {
            LOG("Cannot found runtime exception structure for RIP %018p. This is probably an ASM function\n", newRip);
            return CX_STATUS_DATA_NOT_FOUND;
        }
        else
        {
            if (pRuntimeFunction->UnwindData % sizeof(CX_UINT32) != 0)
            {
                // align to dword, and that's the new address
                CX_UINT32 newUnwind = pRuntimeFunction->UnwindData & ~0x7;

                if (newUnwind >= dir.VirtualAddress && newUnwind < dir.VirtualAddress + dir.Size)
                {
                    pRuntimeFunction = (PRUNTIME_FUNCTION)(napocaBase + newUnwind);
                }
            }
        }

        //
        // Parse the UNWIND_INFO structures and get the stack frame start. If the runtimeFunction isn't found
        // msdn says that the function doesn't have a prologue, so just analyze the stack without skipping
        //
        if (pRuntimeFunction->BeginAddress != 0)
        {
            unwindInfoAddress = (CX_UINT64)napocaBase + pRuntimeFunction->UnwindData;

            //
            // if UNW_FLAG_CHAININFO is set then we go further. The next three DWORDS are a new
            // RUNTIME_FUNCTION so if we get the 3rd CX_UINT32 we get a new UNWIND_INFO address
            //
            do
            {
                pUnwindInfoMap = (PUNWIND_INFO)unwindInfoAddress;

                //
                // If the FrameRegister is not CX_NULL then another register is used as a stack frame with a FrameOffset
                // But this doesn't change anything for what we want to do since the return address is still on RSP.
                //
                i = 0;  // Sometimes we need to skip the next codes (they're passed as info to this code)
                while (i < pUnwindInfoMap->CountOfCodes)
                {
                    // We check for version (1 on Win7, 2 on Win8) in case we somehow don't skip enough codes
                    if (pUnwindInfoMap->Version != 1 && pUnwindInfoMap->Version != 2)
                    {
                        i++;
                        continue;
                    }

                    //
                    // see http://msdn.microsoft.com/en-US/library/ck9asaa9%28v=vs.80%29.aspx for details
                    //
                    switch(pUnwindInfoMap->UnwindCode[i].UnwindOp)
                    {
                    case 0: // UWOP_PUSH_NONVOL (1)
                        dwExtraStackSpace += 8;
                        i++;
                        break;

                    case 1: // UWOP_ALLOC_LARGE (2 or 3)
                        if (pUnwindInfoMap->UnwindCode[i].OpInfo == 0)
                        {
                            dwExtraStackSpace += *((CX_UINT16 *)&pUnwindInfoMap->UnwindCode[i+1]) * 8;
                            i += 2;
                        }
                        else
                        {
                            dwExtraStackSpace += *((CX_UINT32 *)&pUnwindInfoMap->UnwindCode[i+2]) * 8;
                            i += 3;
                        }
                        break;
                    case 2: // UWOP_ALLOC_SMALL (1)
                        dwExtraStackSpace += pUnwindInfoMap->UnwindCode[i].OpInfo * 8 + 8;
                        i++;
                        break;

                    case 3: // UWOP_SET_FPREG(1)
                        i++;
                        break;

                    case 4: // UWOP_SAVE_NONVOL(1)
                        i += 2;
                        break;

                    case 5: // UWOP_SAVE_NONVOL_FAR
                        i += 3;
                        break;

                    case 6: // UWOP_EPILOG
                            // For what I see so far it just says where the exit points are in a function (if there are multiple exit points)
                        i += 1;
                        break;

                    case 7: // UWOP_SPARE_CODE
                        i += 2;
                        break;

                    case 8: // UWOP_SAVE_XMM128
                        i += 2;
                        break;

                    case 9: // UWOP_SAVE_XMM128_FAR
                        i += 3;
                        break;

                    case 10: // UWOP_PUSH_MACHFRAME
                        if (pUnwindInfoMap->UnwindCode[i].OpInfo == 0)
                        {
                            // We are inside an hardware interrupt
                            dwExtraStackSpace += 5 * 8;  // RIP, CS, EFLAGS, Old RSP, SS
                            interruptContext = CX_TRUE;
                        }
                        else
                        {
                            // We are inside an exceptions
                            dwExtraStackSpace += 6 * 8; // Error Code, RIP, CS, EFLAGS, Old RSP, SS
                            exceptionContext = CX_TRUE;
                        }
                        i++;
                        break;

                    default: // NOT_USED. Shouldn't get here
                        i++;
                        break;
                    }
                }

                //
                // Don't change the unwind info address if we don't need to go further
                //
                if (UNW_FLAG_CHAININFO != pUnwindInfoMap->Flags) // UNW_FLAG_CHAININFO
                {
                    break;
                }

                //
                // Get the new unwind info address so we can map the new one if we need to. Formula:
                // CountOfCode * sizeof(UNWIND_CODE) + 4 (first BYTES in UNWIND_INFO) => RUNTIME_FUNCTION.
                // Add 8 (FIELD_OFFSET(RUNTIME_FUNCTION, UnwindInfo)) to get the new unwind info address.
                //
                unwindInfoAddress = ((CX_UINT64)napocaBase + *(CX_UINT32 *)((CX_UINT8 *)pUnwindInfoMap + pUnwindInfoMap->CountOfCodes * 2 + 12)) & ~0x07;
            }
            while (pUnwindInfoMap->Flags == UNW_FLAG_CHAININFO); // UNW_FLAG_CHAININFO
        }

        // advance the stack pointer
        newStackFrame = currentStackFrame + dwExtraStackSpace;

        if (exceptionContext && interruptContext)
        {
            WARNING("Why do we have both exception and interrupt context ?!\n");
        }
        else if (exceptionContext)
        {
            LOG("..:: exceptionContext ::..\n");
        }
        else if (interruptContext)
        {
            LOG("..:: interruptContext ::..\n");
        }

        //
        // Now for the fun part. Without the .pdb files there is no way to know how many parameters the function
        // has. So analyze all the pointers from here up.
        //
        tries = 0x400; // fair number (0x2000 / 8); the biggest found so far in kernel: 0x2c8

        while (tries > 0)
        {
            CX_UINT64 retAddress, calledAddress;

            pStack = (CX_UINT8 *)newStackFrame;
            if (!MmIsMemReadable(&gHvMm, pStack, 8))
            {
                ERROR("Got to the end of the stack...\n");
                status = STATUS_ACCESS_REQUIREMENTS_NOT_MET;
                break;
            }

            retAddress = *(CX_UINT64 *)pStack;

            //
            // If this isn't a kernel pointer or the address is some pointer on the stack
            //
            if (retAddress < (CX_UINT64)napocaBase || retAddress > napocaBase + sizeOfNapoca)
            {
                goto next_pointer;
            }

            //
            // If the RIP is inside an interrupt we don't need to analyze the pointer, because it won't be a call
            //
            if (!exceptionContext && !interruptContext)
            {
                status = _DbgAnalyzePointer(retAddress, &calledAddress);
                if (!CX_SUCCESS(status))
                {
                    goto next_pointer;
                }
            }
            else
            {
                // The called address is the start of the interrupt routine. This MUST be inside a driver
                calledAddress = napocaBase + pRuntimeFunction->BeginAddress;
            }

            foundReturnAddress = CX_TRUE;
            LOG("%d : from RIP %018p returning to HVA %018p. Called address was %018p %s\n",
                traces, newRip, retAddress,
                calledAddress != 0 ? calledAddress : napocaBase + pRuntimeFunction->BeginAddress,
                calledAddress == 0 ? "(IMPRECISE/GUESS)" : " ");
            newRip = retAddress;     // the new RIP is the address we return

                                     //
                                     // If exists, save the address at the call instruction, not the current function
                                     //
            traces++;

        next_pointer:
            newStackFrame += 8;
            tries--;
            status = CX_STATUS_SUCCESS;

            //
            // Get out if we found what we were looking for or the return address is outside of a driver
            //
            if (foundReturnAddress) break;
        }

        currentStackFrame = newStackFrame; // The stack pointer advance by how many we parsed

        if (!foundReturnAddress)
        {
            //
            // Signal an error only if we found no traces (and no error occurred)
            //
            if (traces == 0 && status == CX_STATUS_SUCCESS)
            {
                ERROR("[ERROR] Didn't found a trace on the stack. RIP at %018p in module %018p\n",
                      newRip, napocaBase);
                status = CX_STATUS_DATA_NOT_FOUND;
            }

            goto leave;
        }
    }
    while (traces < MaxTraces);


leave:

    return status;
}

static
CX_STATUS
DbgCommandMapEpt(
    _In_ CX_UINT64 UsedParametersMask,
    _In_ CX_UINT64 Gpa,
    _In_opt_ CX_UINT64 Size
)
{
    CX_STATUS status;

    if (UsedParametersMask & DBG_TYPE_OPT_VALUE1)
    {
        LOG("Mapping GPA range starting from: %p, with size: 0x%llx\n", Gpa, Size);
        status = EptMapMem(GstGetEptOfPhysicalMemory(HvGetCurrentGuest()), Gpa, Gpa, Size);
        LOG("Ept mapping finished with status: %s\n", NtStatusToString(status));
    }
    else
    {
        LOG("Mapping GPA range starting from: %p, with size: 0x%llx\n", Gpa, (CX_UINT64)(4 * 1024));
        status = EptMapMem(GstGetEptOfPhysicalMemory(HvGetCurrentGuest()), Gpa, Gpa, CX_PAGE_SIZE_4K);
        LOG("Ept mapping finished with status: %s\n", NtStatusToString(status));
    }

    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
DbgCommandSetIntroVerbosity(
    _In_ CX_UINT32 VerbosityLevel
)
{
    return NapIntUpdateIntrospectionVerbosityLogs(HvGetCurrentGuest(), VerbosityLevel);
}

static
CX_STATUS
DbgCommandStack(
    _In_ DBG_PARAM_VCPUTARGET *Target
)
{
    if (!CX_SUCCESS(InterpreterValidateVcpuTarget(Target)))
    {
        LOGN("Invalid VCPU Target!\n");
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    VCPU *vcpu = gHypervisorGlobalData.Guest[Target->GuestIndex]->Vcpu[Target->VcpuIndex];

    if (vcpu == HvGetCurrentVcpu())
    {
        LOGN("Use a different VCPU than current VCPU!\n");
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    LOGN("Warning: is very unlikely but it may happen that the target VCPU is in GUEST (non-root mode) when sending NMI. \n\
         In this case, if we do not have the NMI exit active, we will not see any output (and most likely the GUEST will \"crash\").\n");
    DbgGlobalData.CpuReceivedNmiFromDebugger[vcpu->LapicId] = CX_TRUE;
    IpiSendVector(vcpu->AttachedPcpu->Affinity, NAPOCA_NMI_VECTOR);

    return CX_STATUS_SUCCESS;
}

static
CX_STATUS
DbgCommandStackAll(
    CX_VOID
)
{
    CX_UINT32 vcpuIndex = 0;
    GUEST *currentGuest = HvGetCurrentGuest();

    LOGN("Warning: is very unlikely but it may happen that the target VCPU is in GUEST (non-root mode) when sending NMI. \n\
         In this case, if we do not have the NMI exit active, we will not see any output (and most likely the GUEST will \"crash\").\n");

    while (vcpuIndex < currentGuest->VcpuCount)
    {
        VCPU *vcpu = currentGuest->Vcpu[vcpuIndex];

        if (vcpu == HvGetCurrentVcpu())
        {
            ++vcpuIndex;
            continue;
        }

        DbgGlobalData.CpuReceivedNmiFromDebugger[vcpu->LapicId] = CX_TRUE;
        IpiSendVector(vcpu->AttachedPcpu->Affinity, NAPOCA_NMI_VECTOR);

        // A bit of a pause between sending NMIs
        // because the processors print their stack without lock.
        // Leaving a bit of pause it is possible to avoid "joining" stacks
        HvSpinWait(2000000);
        ++vcpuIndex;
    }

    return CX_STATUS_SUCCESS;
}


BOOLEAN gShowSingleStepTrace = TRUE;

CX_VOID
DbgPreHandlerDebugActions(
    _In_ VCPU* Vcpu
)
{
    Vcpu->DebugContext.BreakOnCondMatched = FALSE;
    Vcpu->DebugContext.TriggerOnCondMatched = FALSE;

    // break into debugger if the specified condition is met (condition set via the 'breakon' command)
    if (Vcpu->DebugContext.BreakOnCondition != NULL)
    {
        QWORD result = 0;
        if (InterpreterMatchNumericExpression(Vcpu->DebugContext.BreakOnCondition, strlen(Vcpu->DebugContext.BreakOnCondition), &result, NULL, FALSE))
        {
            if (result != 0)
            {
                VCPULOG(Vcpu, "Breaking into debugger before handling the exit, condition met: <%s>\n", Vcpu->DebugContext.BreakOnCondition);
                DbgBreakIgnoreCleanupIKnowWhatImDoing();
                Vcpu->DebugContext.BreakOnCondMatched = TRUE;
            }
        }
    }

    // run some debugger commands if the specified condition is met (condition set via the 'trigger' command)
    if ((Vcpu->DebugContext.TriggerCondition != NULL) && (Vcpu->DebugContext.TriggerCommand != NULL))
    {
        QWORD result = 0;
        if (InterpreterMatchNumericExpression(Vcpu->DebugContext.TriggerCondition, strlen(Vcpu->DebugContext.TriggerCondition), &result, NULL, FALSE))
        {
            if (result != 0)
            {
                NTSTATUS status = InterpreterSetInterpretorSessionDefaults(Vcpu);
                if (!SUCCESS(status))
                {
                    // warn and then try debugging
                    LOG_FUNC_FAIL("InterpreterSetInterpretorSessionDefaults", status);
                }
                DbgMatchCommand(Vcpu->DebugContext.TriggerCommand, strlen(Vcpu->DebugContext.TriggerCommand), NULL, FALSE, NULL);
                Vcpu->DebugContext.TriggerOnCondMatched = TRUE;
            }
        }
    }
    return;
}

CX_VOID
DbgPostHandlerDebugActions(
    _In_ VCPU* Vcpu
)
{
    if ((Vcpu->DebugContext.BreakOnCondition != NULL) && (!Vcpu->DebugContext.BreakOnCondMatched))
    {
        QWORD result = 0;
        if (InterpreterMatchNumericExpression(Vcpu->DebugContext.BreakOnCondition, strlen(Vcpu->DebugContext.BreakOnCondition), &result, NULL, FALSE))
        {
            if (result != 0)
            {
                VCPULOG(Vcpu, "Breaking into debugger after handling the exit, condition met: <%s>\n", Vcpu->DebugContext.BreakOnCondition);
                DbgBreakIgnoreCleanupIKnowWhatImDoing();
            }
        }
    }

    if ((Vcpu->DebugContext.TriggerCondition != NULL) && (Vcpu->DebugContext.TriggerCommand != NULL) && (!Vcpu->DebugContext.TriggerOnCondMatched))
    {
        QWORD result = 0;
        if (InterpreterMatchNumericExpression(Vcpu->DebugContext.TriggerCondition, strlen(Vcpu->DebugContext.TriggerCondition), &result, NULL, FALSE))
        {
            if (result != 0)
            {
                LOG("Breaking into debugger after handling the exit, condition met: <%s>\n", Vcpu->DebugContext.BreakOnCondition);
                NTSTATUS status = InterpreterSetInterpretorSessionDefaults(Vcpu);
                if (!SUCCESS(status))
                {
                    // warn and then try debugging
                    LOG_FUNC_FAIL("InterpreterSetInterpretorSessionDefaults", status);
                }
                DbgMatchCommand(Vcpu->DebugContext.TriggerCommand, strlen(Vcpu->DebugContext.TriggerCommand), NULL, FALSE, NULL);
            }
        }
    }

    if (Vcpu->DebugContext.StopTracingAfterExit)
    {
        gShowSingleStepTrace = FALSE;
        Vcpu->DebugContext.SingleStep = 0;
        Vcpu->DebugContext.StopTracingAfterExit = FALSE;
        Vcpu->ArchRegs.RFLAGS &= ~((QWORD)RFLAGS_TF);
    }

    return;
}

CX_VOID
DbgHandleInstructionTracing(
    _In_ VCPU* Vcpu,
    _In_ WORD Cs,
    _In_ QWORD Rip
)
{
    // 0 => disable, 1 => (default) list each instruction, 2 => list and break after each instruction, 3 => silent (vmexits only)
    if (Vcpu->DebugContext.SingleStep != 0)
    {
        INSTRUX instr;
        NTSTATUS status = CX_STATUS_SUCCESS;

        if (gShowSingleStepTrace) DumpersLogInstruction(Vcpu, Cs, Rip);

        // check for STI or other problematic instructions
        status = EmhvDecodeInGuestContext(Vcpu, &instr, 0, 0);
        if (SUCCESS(status))
        {
            if (Vcpu->DebugContext.EnableIfOnTrap)
            {
                // If the instruction which just finished was a PUSHF,
                // i.e. we let the guest push the RFLAGS registers with IF cleared
                VCPULOG(Vcpu, "Setting *delayed* interrupt flag\n");
                Vcpu->ArchRegs.RFLAGS |= RFLAGS_IF;
                Vcpu->DebugContext.EnableIfOnTrap = FALSE;
            }

            if (!Vcpu->DebugContext.StopTracingAfterExit)
            {
                // if here => we haven't received the trace 0 command (=> tracing is still on)
                QWORD intrState;

                vmx_vmread(VMCS_GUEST_INTERRUPTIBILITY_STATE, &intrState);

                if (intrState & VMCSFLAG_IRRSTATE_BLOCKING_BY_STI)
                {
                    // guest interruptibility state is blocking by STI
                    // if this is the case we can't enter the guest with TF set on
                    // => we disable guest IF and remove blocking by STI
                    // if a CLI instruction is not next in the instruction stream we will
                    // enable interrupts after the next exit
                    Vcpu->ArchRegs.RFLAGS &= ~RFLAGS_IF;

                    // check if CLI or POPF is next
                    Vcpu->DebugContext.EnableIfOnTrap = (instr.OpCodeBytes[0] != 0xFA) && (instr.OpCodeBytes[0] != 0x9D);

                    // disable blocking by STI
                    VCPULOG(Vcpu, "Interruptibility state is blocking by STI => disable IF and clear blocking by STI\n");
                    vmx_vmwrite(VMCS_GUEST_INTERRUPTIBILITY_STATE, intrState & ~VMCSFLAG_IRRSTATE_BLOCKING_BY_STI);
                }
            }

        }
        else VCPULOG(Vcpu, "SINGLE-STEP: instruction decoding failed!\n");

        if (Vcpu->DebugContext.SingleStep == 2) DbgBreakIgnoreCleanupIKnowWhatImDoingOp(1); // silently break into debugger after each logged instruction
    }
}
