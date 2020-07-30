/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

// MEMTAGS - memory TAGs for HEAP

#ifndef _MEMTAGS_H_
#define _MEMTAGS_H_

// runtimelib/base tags defs
#define TAG_ANS         'SNA.'
#define TAG_JSN         'NSJ.'
#define TAG_JSF         'FSJ.'
#define TAG_BMP         'PMB.'
#define TAG_AAN         'NAA.'


#define TAG_IVE         'EV#.'  // introspection virtual exception info page
#define TAG_ANS         'SNA.'  // ANSI strings
#define TAG_APM         'MPA.'  // AP trampoline backup
#define TAG_BHK         'KHB.'  // BIOS hook
#define TAG_DBG         'GBD.'
#define TAG_DEV         'VED.'  // device
#define TAG_DEX         'xED.'  // device extension
#define TAG_DIH         'HID.'  // device interrupt handler
#define TAG_EMU         'UME.'
#define TAG_EXT         'TXE.'  // extended FPU state
#define TAG_GST         'TSG.'  // guest
#define TAG_ICACHE      'ACI.'
#define TAG_IFR         'RFI.'  // IPI freeze request context
#define TAG_INV_GPA     'NII.'
#define TAG_IPC         'CPI.'
#define TAG_MDL         'LDM.'  // memory descriptor list
#define TAG_MMP         'PMM.'  // memory map
#define TAG_MODULE      'DOM.'  // loader or other kind of external modules
#define TAG_PCI         'ICP.'  // PCI config space
#define TAG_RMM         'MMR.'  // real-mode memory mappings
#define TAG_RSC         'CSR.'  // device resource
#define TAG_TSW         'WST.'  // mappings for task-switch handling
#define TAG_ACPA        'APCA'  // ACPICA related
#define TAG_ACPI        'IPCA'  // acpi specific
#define TAG_ALIN        'NILA'  // alien mappings from interpreter.c !!!!!! to be fixed !!!!!!
#define TAG_ASTR        'RTSA'
#define TAG_BLOB        'BOLB'  // BLOBs used by DVTC messages
#define TAG_CHMT        'TMHC'  // cache map internal mapping operations
#define TAG_COM         'MMOC'  // communication
#define TAG_DUMP        'PMUD'  // dumpers related
#define TAG_EVENT       'TNVE'
#define TAG_FACS        'SCAF'  // ACPI FACS table
#define TAG_FAST_ALLOC  'tsaf'  // fast (heap)allocator
#define TAG_FREE        'eeRF'  // free heap chunks
#define TAG_HEAP        'PAEH'
#define TAG_FMAP        'PAMF'  // fast map
#define TAG_GENL        'LNEG'  // guest enlightenments
#define TAG_GVAT        'TAVG'  // guest VA mappings tables
#define TAG_HCAL        'LACH'  // hypercall
#define TAG_HRBF        'FBRH'  // host ring buffer
#define TAG_ILCK        'KCLI'  // introspection specific lock
#define TAG_INTD        'DtnI'  // external interrupt descriptor
#define TAG_INTR        'RTNI'  // introspection guest-memory mappings
#define TAG_IOAP        'pAoI'  // I/O APIC
#define TAG_ITPT        'TPTI'  // interpreter mappings
#define TAG_LAPIC       'ipaL'  // local APIC
#define TAG_LXGT        'TGXL'  // LXG temp mapping
#define TAG_MFPS        'SPFM'  // MP structures
#define TAG_MTRR        'RRTM'
#define TAG_INR_UPD     'PUIN'  // intro update
#define TAG_OSSC        'CSSO'  // Guest scanner for identifying the windows version
#define TAG_PIGT        'TGIP'  // per-PCPU IDT, GDT, TSS zone
#define TAG_POWR        'RWOP'  // power management
#define TAG_PSCT        'TCSP'  // before power state change trampoline
#define TAG_UTVA        'AVTU'  // generic unit testcase VA mappings
#define TAG_VCPU        'UPCv'  // VCPU structure
#define TAG_IRT         'TRI.'
#define TAG_IRTE        'ETRI'
#define TAG_X2APIC      'pA2X'  // x2 APIC
#define TAG_X2DEV       'DV2X'  // x2Apic virtual device
#define TAG_LOOKASIDE   'CMV.'
#define TAG_RESET       'TSR.'
#define TAG_LD_MODULE   'dMdL'
#define TAG_CMDLINE     'dmc.'
#define TAG_FIRST_MEGA  '.ts1'
#define TAG_CPU         'upc.'
#define TAG_STACK       'TSxv'
#define TAG_DBF_STACK   'TSfd'
#define TAG_NMI_STACK   'TSin'
#define TAG_MC_STACK    'TScm'
#define TAG_VMXON       'NOxv'
#define TAG_PAGEPOOL    ' PP.'
#define TAG_IDMAP       '1to1'
#define TAG_MSIX_TABLE  'TXSM'
#define TAG_INTRO_MOD   'RTNI'

#define TAG_IOBITMAP    'pmOI'
#define TAG_MSRBITMAP   'pmRM'
#define TAG_EPTP        'PTPE'
#define TAG_EPT_PAGE    'TPE.'  // a EPT paging structure
#define TAG_VMCS        'NOXV'
#define TAG_SINGLESTEP  'BSS.'
#define TAG_GPA_CACHE   'CAPG'

#define TAG_OXFORD      'fxO.'
#define TAG_FPU_DUMP    'pmuD'
#define TAG_OPENSSL     'LSSO'

//  bad, should be replaced
#define TAG_NONE        'ENON'

#endif // _MEMTAGS_H_
