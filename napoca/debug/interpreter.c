/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "debug/interpreter.h"
#include "kernel/kernel.h"
#include "memory/cachemap.h"
#include "wrappers/crt_short/crt.h"

#ifndef DBGTRACE
#define DBGTRACE
#endif

#define DBG_MAX_USER_VARIABLES  8
#define DBG_MAX_USER_FUNCTIONS  8

// Default values for each interpreter parameter type
DBG_PARAMS              DbgDefaultParams = {0};

typedef struct _INTERPRETER_GLOBAL_VARS
{
    DBG_VARS         DbgVars[DBG_MAX_USER_VARIABLES];
    DBG_FUNCTIONS    DbgFunctions[DBG_MAX_USER_FUNCTIONS];
    CHAR             *ReservedKeywords[4];
    CX_UINT32        NumberOfVars;
    CX_UINT32        NumberOfFunctions;
    CX_BOOL          PerformOperation;
    CX_UINT64        RepeatCounter;
    CX_BOOL          Repeating;
}INTERPRETER_GLOBAL_VARS;

//
// Global variables across this entity
// (if there is no explicit initialization, they are initialized 0/FALSE/NULL)
//
static INTERPRETER_GLOBAL_VARS InterpreterGlobals =
{
    .ReservedKeywords = {"while", "if", "print", "undef"},
    .PerformOperation = CX_TRUE,
};

// make visible the actual implemented commands and their number
extern DBG_COMMAND  DbgCommands[];
extern CX_UINT32    DBG_NUMBER_OF_COMMANDS;

/* Static functions */
static CX_BOOL      _MatchMemTarget(_In_ CHAR* Input, _In_ CX_INT64 Length, __out_opt DBG_PARAM_MEMTARGET* Target, __out_opt CX_INT64* Consumed);
static CX_BOOL      _MatchVcpuTarget(_In_ CHAR* Input, _In_ CX_INT64 Length, __out_opt DBG_PARAM_VCPUTARGET* Target, __out_opt CX_INT64* Consumed);
static CX_BOOL      _SwitchVmcs(_In_ CX_UINT64 NewPa, __out_opt CX_UINT64* OldPa);
static CX_STATUS    _UnquoteString(_In_ CHAR* Input, _Out_ CHAR** Output, _In_opt_ CX_SIZE_T MaxCharacterCount);
static CX_BOOL      _FreeUnquotedString(_In_ CHAR** String);
static CX_BOOL      _MatchSimpleSymbol(_In_ CHAR* Input, _In_ CX_INT64 Length, __out_opt CX_INT64* Consumed);
static CX_BOOL      _MatchNumber(_In_ CHAR* Input, _In_ CX_INT64 Length, __out_opt CX_UINT64* ReturnValue, __out_opt CX_INT64* Consumed, _In_ CX_BOOL Secure);
static CX_UINT64    _PerformOperation(_In_ CX_UINT8 Operator, _In_ CX_UINT64 Op0, _In_ CX_UINT64 Op1);
static CX_BOOL      _MatchNumericTerm(_In_ CHAR* Input, _In_ CX_INT64 Length, __out_opt CX_UINT64* Value, __out_opt CX_INT64* Consumed, _In_ CX_BOOL Secure);
static CX_BOOL      _MatchPrefixExpression(_In_ CHAR* Input, _In_ CX_INT64 Length, __out_opt CX_UINT64* Value, __out_opt CX_INT64* Consumed, _In_ CX_BOOL Secure);
static CX_BOOL      _MatchBinaryExpression(_In_ CHAR* Input, _In_ CX_INT64 Length, __out_opt CX_UINT64* Value, __out_opt CX_INT64* Consumed, _In_ CX_BOOL Secure);
static CX_BOOL      _MatchVariableName(_In_ CHAR* Input, _In_ CX_INT64 Length, __out_opt CX_INT64* Consumed);
static CX_BOOL      _MatchCommandName(_In_ CHAR* Input, _In_ CX_INT64 Length, __out_opt CX_UINT64* CommandId, __out_opt CX_INT64* Consumed);
static CX_BOOL      _MatchMemRange(_In_ CHAR* Input, _In_ CX_INT64 Length, __out_opt DBG_PARAM_MEMRANGE* Range, __out_opt CX_INT64* Consumed);
static CX_BOOL      _MatchTargetRange(_In_ CHAR* Input, _In_ CX_INT64 Length, __out_opt DBG_PARAM_MEMTARGET* Target, __out_opt DBG_PARAM_MEMRANGE* Range, __out_opt CX_INT64* Consumed);
static CX_BOOL      _MatchAssignment(_In_ CHAR* Input, _In_ CX_INT64 Length, __out_opt CX_INT64* Consumed, _Out_ CX_UINT64* Value);
static CX_BOOL      _MatchWhile(_In_ CHAR* Input,_In_ CX_INT64 Length,__out_opt CX_INT64* Consumed);
static CX_BOOL      _MatchIf(_In_ CHAR* Input,_In_ CX_INT64 Length,__out_opt CX_INT64* Consumed);
static CX_BOOL      _MatchPrint(_In_ CHAR* Input, _In_ CX_INT64 Length, _In_ CX_UINT64 *Result, __out_opt CX_INT64* Consumed);
static CX_BOOL      _MatchUndef(_In_ CHAR* Input, _In_ CX_INT64 Length, __out_opt CX_INT64* Consumed);
static CX_BOOL      _MatchStatement(_In_ CHAR* Input, _In_ CX_INT64 Length, __out_opt CX_INT64* Consumed);
static CX_BOOL      _MatchVariableAssignment(_In_ CHAR* Input, _In_ CX_INT64 Length, _Out_ CX_UINT64 *Result, __out_opt CX_INT64* Consumed);
static CX_BOOL      _MatchFunction(_In_ CHAR* Input, _In_ CX_INT64 Length, __out_opt CX_INT64* Consumed);
static CX_BOOL      _MatchBlock(_In_ CHAR* Input, _In_ CX_INT64 Length, __out_opt CX_INT64* Consumed);

// lexical and grammar definition of our commands (functions that match/consume various tokens and expressions)

CX_BOOL
InterpreterMatchSpaces(
    _In_        CHAR        *Input,
    _In_        CX_INT64    Length,
    __out_opt   CX_INT64    *Consumed
)
//
// Consumed <= the number of spaces found from Input[0] on
// Returns true if spaces were found
//
{
    CX_INT64 consumed = 0;

    while ((Input) && (Length > 0) && ((*Input == ' ') || (*Input == '\t') || (*Input == '\r') || (*Input == '\n')))
    {
        Length--;
        Input++;
        consumed++;
    }
    if (Consumed) *Consumed = consumed;
    return (consumed != 0);
}

CX_BOOL
InterpreterMatchToken(
    _In_        CHAR        *Input,
    _In_        CX_INT64    Length,
    _In_        CHAR        *Token,
    __out_opt   CX_INT64    *Consumed
)
//
// Return CX_TRUE if the given token follows at Input[0]
//
{
    CX_INT64 consumed = 0;
    CX_INT64 tokenLen;
    if ((Token) && (Input))
    {
        DBGTRACE("trying %s\n", Token);
        tokenLen = (CX_INT64)strlen(Token);
        if ((tokenLen > 0) && (Length >= tokenLen) && (!strnicmp(Input, Token, tokenLen)))
        {
            CX_INT64 pos;
            CX_BOOL hasSpecialChars;

            hasSpecialChars = CX_FALSE;
            for (pos = 0; pos < tokenLen; pos++)
            {
                if (!(((Input[pos] >= 'a') && (Input[pos] <= 'z'))||
                    ((Input[pos] >= 'A') && (Input[pos] <= 'Z'))||
                    ((Input[pos] >= '0') && (Input[pos] <= '9'))||
                    (Input[pos] == '_')))
                {
                    hasSpecialChars = CX_TRUE;
                }
            }

            // if the token doesn't contain special characters make sure it is right-delimited
            if ((Length > tokenLen) && (!hasSpecialChars))
            {
                if (((Input[tokenLen] >= 'a') && (Input[tokenLen] <= 'z'))||
                    ((Input[tokenLen] >= 'A') && (Input[tokenLen] <= 'Z'))||
                    ((Input[tokenLen] >= '0') && (Input[tokenLen] <= '9'))||
                    (Input[tokenLen] == '_'))
                {
                    // part of a larger token, don't match it
                    goto refuse;
                }
            }
            consumed = strlen(Token);
        }
    }

refuse:
    if (Consumed) *Consumed = consumed;

    if (consumed != 0) DBGTRACE("Token matched!\n");
    return consumed != 0;
}

CX_BOOL
InterpreterMatchSymbol(
    _In_        CHAR        *Input,
    _In_        CX_INT64    Length,
    __out_opt   CX_INT64    *Consumed,
    __out_opt   CHAR        **SymbolInPlace,    // return the actual characters ignoring any decorators (like " for example), !NOT NULL-TERMINATED!
    __out_opt   CX_INT64    *SymbolLength       // the actual length without decorators
)
//
// parse [a-zA-Z_][a-zA-Z_0-9]* characters found at the beginning of Input
//
{
    CX_INT64 consumed = 0;
    CX_INT64 symbolLength;
    CHAR *symbolInPlace;

    symbolInPlace = Input;
    symbolLength = 0;

    if ((!Input) || (Length == 0))
    {
        consumed = 0;
        goto cleanup;
    }

    // try a simple literal
    if (_MatchSimpleSymbol(Input, Length, &consumed))
    {
        symbolLength = consumed;
        goto cleanup;
    }

    // try "wh@tever!#$(&"-like strings
    if (InterpreterMatchToken(Input, Length, "\"", &consumed))
    {
        symbolInPlace = Input + consumed;
        symbolLength = 0;
        while ((consumed < Length) && (Input[consumed] != '"'))
        {
            consumed++;
            symbolLength++;
        }
        if ((consumed < Length) && (Input[consumed] == '"'))
        {
            consumed++;
        }
        else
        {
            consumed = 0;
        }
    }

cleanup:
    if (Consumed) *Consumed = consumed;
    if (consumed != 0)
    {
        DBGTRACE("Symbol matched!\n");
        if (SymbolInPlace) *SymbolInPlace = symbolInPlace;
        if (SymbolLength) *SymbolLength = symbolLength;
    }
    else
    {
        if (SymbolInPlace) *SymbolInPlace = CX_NULL;
        if (SymbolLength) *SymbolLength = 0;

    }
    return consumed != 0;
}

#define DBG_MATCH_ARCHREG(Reg)                                                                          \
{                                                                                                   \
    CX_UINT64 val;                                                                                      \
    CX_BOOL writeRequired = CX_FALSE;                                                                  \
    consumed += localTmp;                                                                           \
    if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &localTmp))                             \
    {                                                                                               \
        consumed += localTmp;                                                                       \
    }                                                                                               \
    if (_MatchAssignment(Input + consumed, Length - consumed, &localTmp, &val))                   \
    {                                                                                               \
        consumed += localTmp;                                                                       \
        writeRequired = CX_TRUE && InterpreterGlobals.PerformOperation;                                                  \
    }                                                                                               \
    if (writeRequired)                                                                              \
    {                                                                                               \
        gHypervisorGlobalData.Guest[target.GuestIndex]->Vcpu[target.VcpuIndex]->ArchRegs.Reg = val;\
    }                                                                                               \
    result = gHypervisorGlobalData.Guest[target.GuestIndex]->Vcpu[target.VcpuIndex]->ArchRegs.Reg; \
    isValid = CX_TRUE;                                                                                 \
}

CX_BOOL
InterpreterMatchNumericExpression(
    _In_        CHAR        *Input,
    _In_        CX_INT64    Length,
    __out_opt   CX_UINT64   *Value,
    __out_opt   CX_INT64    *Consumed,
    _In_        CX_BOOL     Secure              // disable advanced features that are unsecure on external input
)
{
    CX_UINT64 v0, v1, v2;
    CX_INT64 tmp, consumed;
    consumed = 0;
    CX_BOOL matched;

    matched = CX_FALSE;
    // get v0
    if (_MatchBinaryExpression(Input, Length, &v0, &tmp, Secure))
    {
        matched = CX_TRUE;

        consumed += tmp;
        InterpreterMatchSpaces(Input + consumed, Length - consumed, &tmp);
        consumed += tmp;

        // ?
        if ((consumed < Length) && Input[consumed] == '?')
        {
            matched = CX_FALSE; // unless we completely match all the operands
            consumed++;
            InterpreterMatchSpaces(Input + consumed, Length - consumed, &tmp);
            consumed += tmp;

            // v1
            if (InterpreterMatchNumericExpression(Input + consumed, Length - consumed, &v1, &tmp, Secure))
            {
                consumed += tmp;

                InterpreterMatchSpaces(Input + consumed, Length - consumed, &tmp);
                consumed += tmp;

                // :
                if ((consumed < Length) && Input[consumed] == ':')
                {
                    consumed++;

                    InterpreterMatchSpaces(Input + consumed, Length - consumed, &tmp);
                    consumed += tmp;

                    // v2
                    if (InterpreterMatchNumericExpression(Input + consumed, Length - consumed, &v2, &tmp, Secure))
                    {
                        v0 = v0 ? v1 : v2;
                        matched = CX_TRUE;
                        consumed += tmp;
                    }
                }
            }
        }
    }
    if (matched && Value) *Value = v0;
    if (Consumed) *Consumed = consumed;
    return matched;
}

CX_BOOL
InterpreterMatchByteArray(
    _In_        CHAR        *Input,
    _In_        CX_INT64    Length,
    __out_opt   CX_UINT8    *Array,         // where to save the 'decoded' data
    _In_        CX_INT64    ArrayLength,    // how much storage space is available
    __out_opt   CX_INT64    *SavedEntries,  // how many entries were matched
    __out_opt   CX_INT64    *Consumed,
    _In_        CX_BOOL     Secure          // avoid advanced features that might be unsecure on external input data
)
//
// Match a list of byte values written as {expr1, expr2, ...} and saves each one (even when it fails in the end) inside the given array
// Will fail matching numbers outside of 0..255 range
// Note: on failure it still returns valid Consumed / SavedEntries
//
{
    CX_INT64 consumed, tmp, i, saved;
    CX_BOOL matched = CX_FALSE;
    CX_BOOL moreValues;

    consumed = 0;
    saved = 0;
    i = 0; // array index

    // skip spaces
    InterpreterMatchSpaces(Input + consumed, Length-consumed, &tmp);
    consumed += tmp;

    // start with a '{'
    if (InterpreterMatchToken(Input + consumed, Length - consumed, "{", &tmp))
    {
        CX_UINT64 val;
        consumed += tmp;

        InterpreterMatchSpaces(Input + consumed, Length-consumed, &tmp);
        consumed += tmp;

        // take a number and repeat while there's a ',' after

        do
        {
            moreValues = CX_FALSE;

            if (InterpreterMatchNumericExpression(Input + consumed, Length - consumed, &val, &tmp, Secure))
            {
                if (val > 255)
                {
                    matched = CX_FALSE;
                    goto cleanup;
                }

                consumed += tmp;
                if (Array)
                {
                    Array[i] = (CX_UINT8)val;
                    i++;
                    saved++;
                }

                InterpreterMatchSpaces(Input + consumed, Length-consumed, &tmp);
                consumed += tmp;

                if (InterpreterMatchToken(Input + consumed, Length - consumed, ",", &tmp))
                {
                    moreValues = CX_TRUE;
                    consumed += tmp;
                }
                InterpreterMatchSpaces(Input + consumed, Length-consumed, &tmp);
                consumed += tmp;
            }
        } while ((i < ArrayLength) && (moreValues));

        // must end with '}'
        if (!InterpreterMatchToken(Input + consumed, Length - consumed, "}", &tmp))
        {
            matched = CX_FALSE;
            goto cleanup;
        }
        consumed += tmp;
    }

    // try matching a string ~ "([^"]+|\\")*"
    else if (InterpreterMatchToken(Input + consumed, Length - consumed, "\"", &tmp))
    {
        CX_UINT8 lastChar = 0;

        while (((consumed + tmp) < Length)
               && (Input[consumed + tmp] != 0)
               && ((i + 1) < ArrayLength)
               && (!((Input[consumed + tmp] == '"') && (lastChar != '\\'))))
        {
            lastChar = Input[consumed + tmp];
            Array[i] = lastChar;
            saved++;
            i++;
            tmp++;
        }

        // set the string terminator
        Array[i] = 0;
        saved++;
        i++;

        consumed += tmp;    // tmp counted both the opening " and the matched characters

        if (!InterpreterMatchToken(Input + consumed, Length - consumed, "\"", &tmp))
        {
            matched = CX_FALSE;
            goto cleanup;
        }
        consumed += tmp;
    }

    // try matching a hexdump ~ \[([0-9A-F]{2})*\]
    else if (InterpreterMatchToken(Input + consumed, Length - consumed, "[", &tmp))
    {
        CHAR d0, d1;

        // we need two characters for each hex digit
        while ( ((consumed + tmp)+1 < Length)
               && (((Input[consumed + tmp] >= '0') && (Input[consumed + tmp] <= '9'))
               || ((Input[consumed + tmp] >= 'a') && (Input[consumed + tmp] <= 'f'))
               || ((Input[consumed + tmp] >= 'A') && (Input[consumed + tmp] <= 'F')))
               && (((Input[consumed + tmp + 1] >= '0') && (Input[consumed + tmp + 1] <= '9'))
               || ((Input[consumed + tmp + 1] >= 'a') && (Input[consumed + tmp + 1] <= 'f'))
               || ((Input[consumed + tmp + 1] >= 'A') && (Input[consumed + tmp + 1] <= 'F'))))
        {
            d0 = Input[consumed + tmp] | 0x20; // lowercase, safe for both 0-9 and a-f
            d1 = Input[consumed + tmp + 1] | 0x20;

            d0 -= (d0 > '9')? ('a' - 10): ('0');
            d1 -= (d1 > '9')? ('a' - 10): ('0');

            Array[i] = 16*d0 + d1;
            tmp += 2;
            saved++;
            i++;
        }

        consumed += tmp;    // tmp counted both the opening " and the matched characters

        if (!InterpreterMatchToken(Input + consumed, Length - consumed, "]", &tmp))
        {
            matched = CX_FALSE;
            goto cleanup;
        }
        consumed += tmp;
    }
    matched = CX_TRUE;

cleanup:
    // save results
    if (Consumed) *Consumed = consumed;
    if (SavedEntries) *SavedEntries = saved;
    return matched;
}

CX_STATUS
InterpreterSetInterpretorSessionDefaults(
    _In_opt_ VCPU *Vcpu
)
{
    if (Vcpu)
    {
        DbgDefaultParams.VcpuTarget.GuestIndex = Vcpu->Guest->Index;
        DbgDefaultParams.VcpuTarget.Vcpu = Vcpu;
        DbgDefaultParams.VcpuTarget.VcpuIndex = Vcpu->GuestCpuIndex;

        DbgDefaultParams.MemRange.Address = Vcpu->PseudoRegs.CsRip;
        DbgDefaultParams.MemRange.Size = 1;
        DbgDefaultParams.MemRange.UnspecifiedSize = CX_TRUE;

        DbgDefaultParams.MemTarget.IsHostNotGuest = CX_FALSE;
        DbgDefaultParams.MemTarget.IsPhysicalNotVirtual = CX_FALSE;
        DbgDefaultParams.MemTarget.VcpuTarget = DbgDefaultParams.VcpuTarget;
    }
    else
    {
        DbgDefaultParams.VcpuTarget.GuestIndex = 0;
        DbgDefaultParams.VcpuTarget.Vcpu = CX_NULL;
        DbgDefaultParams.VcpuTarget.VcpuIndex = 0;

        DbgDefaultParams.MemRange.Address = 0;
        DbgDefaultParams.MemRange.Size = 0;
        DbgDefaultParams.MemRange.UnspecifiedSize = CX_TRUE;

        DbgDefaultParams.MemTarget.IsHostNotGuest = CX_TRUE;
        DbgDefaultParams.MemTarget.IsPhysicalNotVirtual = CX_FALSE;
        DbgDefaultParams.MemTarget.VcpuTarget = DbgDefaultParams.VcpuTarget;
    }

    DbgDefaultParams.Symbol = CX_NULL;
    DbgDefaultParams.Symbol1 = CX_NULL;

    DbgDefaultParams.TargetRange.OriginRange = DbgDefaultParams.MemRange;
    DbgDefaultParams.TargetRange.OriginTarget = DbgDefaultParams.MemTarget;
    DbgDefaultParams.TargetRange.Address = CX_NULL;
    DbgDefaultParams.TargetRange.Size = 0;

    DbgDefaultParams.Value0 = 0;
    DbgDefaultParams.Value1 = 0;
    DbgDefaultParams.Value2 = 0;
    DbgDefaultParams.Value3 = 0;

    DbgDefaultParams.ValueList.NumberOfValues = 0;

    return CX_STATUS_SUCCESS;
}

CX_STATUS
InterpreterValidateVcpuTarget(
    _In_ DBG_PARAM_VCPUTARGET *Target
)
{
    GUEST *guest;
    VCPU *vcpu;

    if (!MmIsMemReadable(&gHvMm, Target, sizeof(DBG_PARAM_VCPUTARGET)))
    {
        return CX_STATUS_INVALID_PARAMETER_1;
    }

    // validate the guest index and structure
    if (Target->GuestIndex >= gHypervisorGlobalData.GuestCount)
    {
        LOG("VCPUTARGET: %d is not a valid guest index!\n", Target->GuestIndex);
        goto cleanup;
    }
    guest = gHypervisorGlobalData.Guest[Target->GuestIndex];

    if (!MmIsMemReadable(&gHvMm, guest, sizeof(GUEST)))
    {
        // faild to access guest fields
        LOG("VCPUTARGET: GUEST structure at %p is not readable!\n", guest);
        goto cleanup;
    }

    // validate the vcpu index and structure
    if (Target->VcpuIndex >= guest->VcpuCount)
    {

        LOG("InterpreterValidateVcpuTarget: %d is an invalid vcpu index for guest[%d]\n", Target->VcpuIndex, Target->GuestIndex);
        goto cleanup;
    }

    vcpu = guest->Vcpu[Target->VcpuIndex];
    if (!MmIsMemReadable(&gHvMm, vcpu, sizeof(VCPU)))
    {
        // faild to access vcpu fields
        LOG("VCPUTARGET: VCPU structure at %p is not readable!\n", vcpu);
        goto cleanup;
    }

    // Vcpu pointer: we can simply make it valid at this point
    Target->Vcpu = vcpu;

    return CX_STATUS_SUCCESS;
cleanup:
    return CX_STATUS_UNINITIALIZED_STATUS_VALUE;
}

CX_BOOL
InterpreterMatchCommand(
    _In_        CHAR        *Input,
    _In_        CX_INT64    Length,
    __out_opt   CX_INT64    *Consumed,
    _In_        CX_BOOL     Echo,
    __out_opt   CX_BOOL     *PartialMatch
)
//
// the main 'production'
//
{
    CX_UINT64 commandIndex = 0;
    CX_INT64 consumed = 0, tmp = 0;
    CX_STATUS status;
    CX_UINT32 i = 0;
    CX_BOOL matched = CX_FALSE;        // command matched
    CX_BOOL valid = CX_FALSE;          // input consumed but no command
    DBG_COMMAND *command = CX_NULL;
    CX_BOOL hasOptionalParams = CX_FALSE;

    // prepare memory placeholders for each possible parameter type
    DBG_PARAMS              params = {0};

    // temp-params for transparent auto-mapped random addresses
    DBG_PARAM_MEMTARGET     targetRange_target = {0};
    DBG_PARAM_MEMRANGE      targetRange_range = {0};

    // dynamic parameters for all possible callback functions
    CX_UINT64                   populatedParametersMask = 0;
    CX_VOID                    *paramPointers[DBG_NUMBER_OF_PARAM_TYPES + 1];  // + 1 for the optional mask which might be inserted here
    CX_UINT32                   paramPointersCount = 0;

    memzero(&params, sizeof(DBG_PARAMS));

    if (Echo) LOGN("<%s>\n", Input);

    do
    {
        CX_BOOL targeted = CX_FALSE;
        CX_BOOL repeat = CX_FALSE;
        matched = CX_FALSE;
        valid = CX_FALSE;
        command = CX_NULL;
        hasOptionalParams = CX_FALSE;
        populatedParametersMask = 0;
        paramPointersCount = 0;

        if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &tmp))
        {
            consumed += tmp;
        }


        // try matching '*number:' or '*' or '@' as a repeat prefix, example: *10: byte[rsp+i] or @rip
        if (InterpreterMatchToken(Input+consumed, Length-consumed, "@", &tmp))
        {
            targeted = CX_TRUE;
            repeat = CX_TRUE;
            consumed += tmp;
        }
        else if (InterpreterMatchToken(Input+consumed, Length-consumed, "*", &tmp))
        {
            targeted = CX_FALSE;
            repeat = CX_TRUE;
            consumed += tmp;
        }

        if (repeat)
        {
            CX_INT64 tmp2 = 0, max, nr;
            CX_UINT64 val = 1, tempI;
            CX_BOOL custom = CX_FALSE;
            CX_BOOL vcpus = CX_FALSE;
            CX_UINT64 oldV;

            if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &tmp2))
            {
                consumed += tmp2;
            }

            // look-ahead for 'number:'
            if (!targeted)
            {
                nr = consumed;
                if (InterpreterMatchNumericExpression(Input + nr, Length - nr, &val, &tmp2, CX_FALSE))
                {
                    nr += tmp2;
                    if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &tmp2))
                    {
                        nr += tmp2;
                    }
                    if (InterpreterMatchToken(Input + nr, Length - nr, ":", &tmp2))
                    {
                        consumed = nr + tmp2;
                        custom = CX_TRUE;
                    }
                }
            }

            if (!custom)
            {
                if (CX_SUCCESS(InterpreterValidateVcpuTarget(&(DbgDefaultParams.VcpuTarget))))
                {
                    val = gHypervisorGlobalData.Guest[DbgDefaultParams.VcpuTarget.GuestIndex]->VcpuCount;
                    vcpus = CX_TRUE;
                }
                else
                {
                    val = gHypervisorGlobalData.CpuData.CpuCount;
                }
            }

            max = 0;
            oldV = DbgDefaultParams.VcpuTarget.VcpuIndex;
            for (tempI = 0; tempI < val; tempI++)
            {
                InterpreterGlobals.RepeatCounter = tempI;
                InterpreterGlobals.Repeating = CX_TRUE;

                if ((targeted) && (vcpus))
                {
                    DbgDefaultParams.VcpuTarget.VcpuIndex = tempI;
                    if (!CX_SUCCESS(InterpreterValidateVcpuTarget(&(DbgDefaultParams.VcpuTarget))))
                    {
                        LOG("Invalid VCPU #%d.%d\n", DbgDefaultParams.VcpuTarget.GuestIndex, DbgDefaultParams.VcpuTarget.VcpuIndex);
                        DbgDefaultParams.VcpuTarget.VcpuIndex = oldV;
                        matched = CX_FALSE;
                        valid = CX_FALSE;
                        goto cleanup;
                    }
                }

                if (!InterpreterMatchCommand(Input + consumed, Length - consumed, &tmp, CX_FALSE, PartialMatch))
                {
                    LOG("Failed matching command %s\n", Input+consumed);
                }
                else if (max < tmp)
                {
                    max = tmp;
                }

                InterpreterGlobals.Repeating = CX_FALSE;

                if ((targeted) && (vcpus))
                {
                    DbgDefaultParams.VcpuTarget.VcpuIndex = oldV;
                    if (!CX_SUCCESS(InterpreterValidateVcpuTarget(&(DbgDefaultParams.VcpuTarget))))
                    {
                        LOG("Invalid VCPU #%d.%d\n", DbgDefaultParams.VcpuTarget.GuestIndex, DbgDefaultParams.VcpuTarget.VcpuIndex);
                    }
                }
            }

            consumed += max;
            if (max != 0)
            {
                matched = CX_TRUE;
                goto cleanup;
            }

            matched = CX_FALSE;
            goto cleanup;
        }

        // take the command name part and select the corresponding command structure
        if (_MatchCommandName(Input + consumed, Length - consumed, &commandIndex, &tmp))
        {
            consumed += tmp;
            command = &(DbgCommands[commandIndex]);
            DBGTRACE("command matched\n");

            // check what parameter types are defined for the given command
            matched = CX_TRUE;
            for (i = 0; i < DBG_NUMBER_OF_PARAM_TYPES; i++)
            {
                CX_UINT64 typeMaskValue = ((CX_UINT64)1) << ((CX_UINT64)(2*i));

                CX_BOOL isRequired = (0 != (typeMaskValue & command->UsedParametersMask));
                CX_BOOL isOptional = (0 != (DBG_TYPE_OPT(typeMaskValue) & command->UsedParametersMask)); /// there's no defined semantic for both...

                if (isOptional) hasOptionalParams = CX_TRUE;

                // skip it if neither
                if ((!isRequired) && (!isOptional))
                {
                    continue;
                }

                // skip spaces
                if (InterpreterMatchSpaces(Input+consumed, Length - consumed, &tmp))
                {
                    consumed += tmp;
                }

                // select a parser and try to match the parameter
                if (0 != ((DBG_TYPE_SYMBOL|DBG_TYPE_OPT_SYMBOL) & (typeMaskValue|DBG_TYPE_OPT(typeMaskValue))))
                {
                    DBGTRACE("DBG_TYPE_SYMBOL\n");
                    if (InterpreterMatchSymbol(Input + consumed, Length - consumed, &tmp, CX_NULL, CX_NULL))
                    {
                        // make a copy of the string
                        CHAR *string = CX_NULL;
                        status = _UnquoteString(Input + consumed, &string, tmp);
                        if (!CX_SUCCESS(status))
                        {
                            LOG_FUNC_FAIL("_UnquoteString", status);
                            break;
                        }
                        memcpy(string, Input+consumed, tmp);
                        string[tmp] = 0;
                        params.Symbol = string;

                        // commit
                        consumed += tmp;
                        populatedParametersMask |= (typeMaskValue<<1 | typeMaskValue);  // both the optional and the required params captured
                        paramPointers[paramPointersCount++] = (CX_VOID *)params.Symbol;
                        DBGTRACE("SYMBOL MATCHED: %s\n", string);
                    }
                    else if (isRequired)
                    {
                        LOG("Command error: invalid SYMBOL parameter at <%s>\n", Input+consumed);
                        matched = CX_FALSE;
                        break;
                    }
                    else
                    {
                        // default value
                        paramPointers[paramPointersCount++] = (CX_VOID *) "";
                    }
                }
                else if (0 != ((DBG_TYPE_SYMBOL1|DBG_TYPE_OPT_SYMBOL1) & (typeMaskValue|DBG_TYPE_OPT(typeMaskValue))))
                {
                    DBGTRACE("DBG_TYPE_SYMBOL1\n");
                    if (InterpreterMatchSymbol(Input + consumed, Length - consumed, &tmp, CX_NULL, CX_NULL))
                    {
                        // make a copy of the string
                        CHAR *string = CX_NULL;
                        status = _UnquoteString(Input + consumed, &string, tmp);
                        if (!CX_SUCCESS(status))
                        {
                            LOG_FUNC_FAIL("_UnquoteString", status);
                            break;
                        }
                        memcpy(string, Input+consumed, tmp);
                        string[tmp] = 0;
                        params.Symbol1 = string;

                        // commit
                        consumed += tmp;
                        populatedParametersMask |= (typeMaskValue<<1 | typeMaskValue);  // both the optional and the required params captured
                        paramPointers[paramPointersCount++] = (CX_VOID *)params.Symbol1;
                        DBGTRACE("SYMBOL MATCHED: %s\n", string);
                    }
                    else if (isRequired)
                    {
                        LOG("Command error: invalid SYMBOL parameter at <%s>\n", Input+consumed);
                        matched = CX_FALSE;
                        break;
                    }
                    else
                    {
                        // default value
                        paramPointers[paramPointersCount++] = (CX_VOID *) "";
                    }
                }
                else if (0 != ((DBG_TYPE_MEMTARGET|DBG_TYPE_OPT_MEMTARGET) & (typeMaskValue|DBG_TYPE_OPT(typeMaskValue))))
                {
                    DBGTRACE("DBG_TYPE_MEMTARGET\n");
                    if (_MatchMemTarget(Input + consumed, Length - consumed, &(params.MemTarget), &tmp))
                    {
                        populatedParametersMask |= (typeMaskValue<<1 | typeMaskValue);  // both the optional and the required params captured
                        consumed += tmp;
                        paramPointers[paramPointersCount++] = (CX_VOID *)&(params.MemTarget);
                    }
                    else if (isRequired)
                    {
                        LOG("Command error: invalid MEMTARGET parameter at <%s>\n", Input+consumed);
                        matched = CX_FALSE;
                        break;
                    }
                    else
                    {
                        paramPointers[paramPointersCount++] = (CX_VOID *)&(params.MemTarget);
                    }
                }
                else if (0 != ((DBG_TYPE_MEMRANGE|DBG_TYPE_OPT_MEMRANGE) & (typeMaskValue|DBG_TYPE_OPT(typeMaskValue))))
                {
                    DBGTRACE("DBG_TYPE_MEMRANGE\n");
                    if (_MatchMemRange(Input + consumed, Length - consumed, &(params.MemRange), &tmp))
                    {
                        populatedParametersMask |= (typeMaskValue<<1 | typeMaskValue);  // both the optional and the required params captured
                        consumed += tmp;
                        paramPointers[paramPointersCount++] = (CX_VOID *)&(params.MemRange);
                    }
                    else if (isRequired)
                    {
                        LOG("Command error: invalid MEMRANGE parameter at <%s>\n", Input+consumed);
                        matched = CX_FALSE;
                        break;
                    }
                    else
                    {
                        paramPointers[paramPointersCount++] = (CX_VOID *)&(params.MemRange);
                    }
                }
                else if (0 != ((DBG_TYPE_VCPUTARGET|DBG_TYPE_OPT_VCPUTARGET) & (typeMaskValue|DBG_TYPE_OPT(typeMaskValue))))
                {
                    DBGTRACE("DBG_TYPE_VCPUTARGET\n");
                    if (_MatchVcpuTarget(Input + consumed, Length - consumed, &params.VcpuTarget, &tmp))
                    {
                        populatedParametersMask |= (typeMaskValue<<1 | typeMaskValue);  // both the optional and the required params captured
                        consumed += tmp;
                        paramPointers[paramPointersCount++] = (CX_VOID *)&params.VcpuTarget;
                    }
                    else if (isRequired)
                    {
                        LOG("Command error: invalid VCPUTARGET parameter at <%s>\n", Input+consumed);
                        matched = CX_FALSE;
                        break;
                    }
                    else
                    {
                        paramPointers[paramPointersCount++] = (CX_VOID *)&params.VcpuTarget;
                    }
                }
                else if (0 != ((DBG_TYPE_TARGETRANGE|DBG_TYPE_OPT_TARGETRANGE) & (typeMaskValue|DBG_TYPE_OPT(typeMaskValue))))
                {
                    DBGTRACE("DBG_TYPE_TARGETRANGE\n");
                    if (_MatchTargetRange(Input + consumed, Length - consumed, &targetRange_target, &targetRange_range, &tmp))
                    {
                        consumed += tmp;
                        populatedParametersMask |= (typeMaskValue << 1 | typeMaskValue);  // both the optional and the required params captured
                    }
                    else
                    {
                        if (isRequired)
                        {
                            LOG("Command error: invalid TARGETRANGE parameter at <%s>\n", Input + consumed);
                            matched = CX_FALSE;
                            break;
                        }
                        targetRange_target = DbgDefaultParams.TargetRange.OriginTarget;
                        targetRange_range = DbgDefaultParams.TargetRange.OriginRange;
                        targetRange_range.UnspecifiedSize = CX_TRUE;
                    }

                    if (!InterpreterMapAlienSpace(&targetRange_target, &targetRange_range, (CX_VOID **)&(params.TargetRange.Address)))
                    {
                        LOG("Command error: the TARGETRANGE specified refers to an inaccessible memory range\n");

                        break;
                    }

                    params.TargetRange.Size = targetRange_range.Size;
                    params.TargetRange.OriginTarget = targetRange_target;
                    params.TargetRange.OriginRange = targetRange_range;
                    paramPointers[paramPointersCount++] = (CX_VOID *)&(params.TargetRange); // convert the value directly to pointer
                }
                else if (0 != ((DBG_TYPE_VALUE0|DBG_TYPE_OPT_VALUE0) & (typeMaskValue|DBG_TYPE_OPT(typeMaskValue))))
                {
                    DBGTRACE("DBG_TYPE_VALUE0\n");
                    if (InterpreterMatchNumericExpression(Input + consumed, Length - consumed, &params.Value0, &tmp, CX_FALSE))
                    {
                        populatedParametersMask |= (typeMaskValue<<1 | typeMaskValue);  // both the optional and the required params captured
                        consumed += tmp;
                        paramPointers[paramPointersCount++] = (CX_VOID *)params.Value0; // convert the value directly to pointer
                    }
                    else if (isRequired)
                    {
                        LOG("Command error: invalid numeric value for parameter at <%s>\n", Input+consumed);
                        matched = CX_FALSE;
                        break;
                    }
                    else
                    {
                        paramPointers[paramPointersCount++] = (CX_VOID *)params.Value0; // convert the value directly to pointer
                    }
                }
                else if (0 != ((DBG_TYPE_VALUE1|DBG_TYPE_OPT_VALUE1) & (typeMaskValue|DBG_TYPE_OPT(typeMaskValue))))
                {
                    DBGTRACE("DBG_TYPE_VALUE1\n");
                    if (InterpreterMatchNumericExpression(Input + consumed, Length - consumed, &params.Value1, &tmp, CX_FALSE))
                    {
                        populatedParametersMask |= (typeMaskValue<<1 | typeMaskValue);  // both the optional and the required params captured
                        consumed += tmp;
                        paramPointers[paramPointersCount++] = (CX_VOID *)params.Value1; // convert the value directly to pointer
                    }
                    else if (isRequired)
                    {
                        LOG("Command error: invalid numeric value for parameter at <%s>\n", Input+consumed);
                        matched = CX_FALSE;
                        break;
                    }
                    else
                    {
                        paramPointers[paramPointersCount++] = (CX_VOID *)params.Value1; // convert the value directly to pointer
                    }
                }
                else if (0 != ((DBG_TYPE_VALUE2|DBG_TYPE_OPT_VALUE2) & (typeMaskValue|DBG_TYPE_OPT(typeMaskValue))))
                {
                    DBGTRACE("DBG_TYPE_VALUE2\n");
                    if (InterpreterMatchNumericExpression(Input + consumed, Length - consumed, &params.Value2, &tmp, CX_FALSE))
                    {
                        populatedParametersMask |= (typeMaskValue<<1 | typeMaskValue);  // both the optional and the required params captured
                        consumed += tmp;
                        paramPointers[paramPointersCount++] = (CX_VOID *)params.Value2; // convert the value directly to pointer
                    }
                    else if (isRequired)
                    {
                        LOG("Command error: invalid numeric value for parameter at <%s>\n", Input+consumed);
                        matched = CX_FALSE;
                        break;
                    }
                    else
                    {
                        paramPointers[paramPointersCount++] = (CX_VOID *)params.Value2; // convert the value directly to pointer
                    }
                }
                else if (0 != ((DBG_TYPE_VALUE3|DBG_TYPE_OPT_VALUE3) & (typeMaskValue|DBG_TYPE_OPT(typeMaskValue))))
                {
                    DBGTRACE("DBG_TYPE_VALUE3\n");
                    if (InterpreterMatchNumericExpression(Input + consumed, Length - consumed, &params.Value3, &tmp, CX_FALSE))
                    {
                        populatedParametersMask |= (typeMaskValue<<1 | typeMaskValue);  // both the optional and the required params captured
                        consumed += tmp;
                        paramPointers[paramPointersCount++] = (CX_VOID *)params.Value3; // convert the value directly to pointer
                    }
                    else if (isRequired)
                    {
                        LOG("Command error: invalid numeric value for parameter at <%s>\n", Input+consumed);
                        matched = CX_FALSE;
                        break;
                    }
                    else
                    {
                        paramPointers[paramPointersCount++] = (CX_VOID *)params.Value3; // convert the value directly to pointer
                    }
                }
                /// TODO: add extraction of more parameter types
                /// else if (0 != ((DBG_TYPE_....
                else
                {
                    // unknown param ?!
                    LOG("Command error: unrecognized parameter type, input = <%s>\n", Input+consumed);
                    matched = CX_FALSE;
                    break;
                }
            }
        }
        else
        {
            // no known command could be recognized
            DBGTRACE("no command matched, trying rule for numeric expression\n");
            if (InterpreterMatchNumericExpression(Input + consumed, Length - consumed, &(params.Value0), &tmp, CX_FALSE))
            {
                consumed += tmp;
                LOGN("[%d] #%d.%d> => %016p (%d)\n",
                    (HvGetCurrentCpu() ? HvGetCurrentCpu()->BootInfoIndex : -1),
                     ((HvGetCurrentVcpu() && HvGetCurrentVcpu()->Guest) ? HvGetCurrentVcpu()->Guest->Index : -1),
                     (HvGetCurrentVcpu() ? HvGetCurrentVcpu()->GuestCpuIndex : -1),
                     params.Value0,
                     params.Value0);
                valid = CX_TRUE;
            }
            else
            {
                DBGTRACE("trying rule for statement\n");
                if (_MatchStatement(Input + consumed, Length - consumed, &tmp))
                {
                    consumed += tmp;
                    valid = CX_TRUE;
                }
            }
        }

        // shift the params to include the optional mask value if needed
        if (hasOptionalParams)
        {
            CX_UINT32 tempI;
            for (tempI = paramPointersCount; tempI > 0; tempI--)
            {
                paramPointers[tempI] = paramPointers[tempI-1];
            }
            paramPointers[0] = (CX_VOID *)populatedParametersMask;
            paramPointersCount++;
        }

        // prepare the corresponding parameters and call the command handler
        if (matched)
        {
            if(InterpreterGlobals.PerformOperation)
            {
                DBGTRACE("calling function for command\n");
                if (paramPointersCount == 0)
                {
                    command->Interpreter(&params);
                }
                else if (paramPointersCount == 1)
                {
                    command->Interpreter(paramPointers[0], &params);
                }
                else if (paramPointersCount == 2)
                {
                    command->Interpreter(paramPointers[0], paramPointers[1], &params);
                }
                else if (paramPointersCount == 3)
                {
                    command->Interpreter(paramPointers[0], paramPointers[1], paramPointers[2], &params);
                }
                else if (paramPointersCount == 4)
                {
                    command->Interpreter(paramPointers[0], paramPointers[1], paramPointers[2], paramPointers[3], &params);
                }
                else if (paramPointersCount == 5)
                {
                    command->Interpreter(paramPointers[0], paramPointers[1], paramPointers[2], paramPointers[3], paramPointers[4], &params);
                }
                else if (paramPointersCount == 6)
                {
                    command->Interpreter(paramPointers[0], paramPointers[1], paramPointers[2], paramPointers[3], paramPointers[4], paramPointers[5], &params);
                }
                else if (paramPointersCount == 7)
                {
                    command->Interpreter(paramPointers[0], paramPointers[1], paramPointers[2], paramPointers[3], paramPointers[4], paramPointers[5], paramPointers[6], &params);
                }
                else if (paramPointersCount == 8)
                {
                    command->Interpreter(paramPointers[0], paramPointers[1], paramPointers[2], paramPointers[3], paramPointers[4], paramPointers[5], paramPointers[6], paramPointers[7], &params);
                }
            }

            //
            // free resources
            //
            if (0 != ((DBG_TYPE_SYMBOL|DBG_TYPE_OPT_SYMBOL) & (populatedParametersMask|DBG_TYPE_OPT(populatedParametersMask))))
            {
                _FreeUnquotedString(&(params.Symbol));
            }
            if (0 != ((DBG_TYPE_SYMBOL1|DBG_TYPE_OPT_SYMBOL1) & (populatedParametersMask|DBG_TYPE_OPT(populatedParametersMask))))
            {
                _FreeUnquotedString(&(params.Symbol1));
            }
            if (0 != ((DBG_TYPE_TARGETRANGE|DBG_TYPE_OPT_TARGETRANGE) & (populatedParametersMask|DBG_TYPE_OPT(populatedParametersMask))))
            {
                if ((params.TargetRange.OriginTarget.IsHostNotGuest) && (!params.TargetRange.OriginTarget.IsPhysicalNotVirtual))
                {
                    InterpreterUnmapAlienSpace(&(params.TargetRange.OriginTarget), (CX_VOID **)&(params.TargetRange.Address));
                }
            }
            /// TODO: free any remaining resources that were allocated for the matched parameters
        }
        //LOG("REMAINING: <%s>\n", Input);
        if((matched||valid) && ( PartialMatch))
        {
            *PartialMatch = CX_TRUE;
        }
    } while ((matched||valid) && ((Length - consumed) > 0));

cleanup:
    if (Consumed) *Consumed = consumed;
    return matched || valid;
}

CX_BOOL
InterpreterMapAlienSpace(
    _In_ DBG_PARAM_MEMTARGET *Target,
    _In_ DBG_PARAM_MEMRANGE  *Range,
    __out_opt CX_VOID        **HvVa
)
{
    CX_VOID *result = CX_NULL;
    CX_BOOL success = CX_FALSE;
    CX_BOOL setUc = CX_TRUE;
    CX_STATUS status;
    CX_UINT64 tmpAddress;
    CX_UINT64 pages;

    pages = CX_PAGE_COUNT_4K(Range->Address, Range->Size);
    tmpAddress = CX_ROUND_DOWN(Range->Address, CX_PAGE_SIZE_4K);
    // case 1: host memory
    if (Target->IsHostNotGuest)
    {
        // host physical mem
        if (Target->IsPhysicalNotVirtual)
        {
            LOG("AUTO-Mapping: HPA\n");
            LOG("MmMapDevMem: <isHost=%d, isPhys=%d, Guest=%d, Vcpu=%d, P=%p, S=%p>\n",
                  Target->IsHostNotGuest, Target->IsPhysicalNotVirtual, Target->VcpuTarget.GuestIndex, Target->VcpuTarget.VcpuIndex,
                  Range->Address, pages);
            status = MmMapDevMem(&gHvMm, tmpAddress, CX_PAGE_SIZE_4K * pages, TAG_ALIN, &result);
            if (CX_SUCCESS(status))
            {
                LOG("AUTO-Mapping: HVA - CX_SUCCESS\n");
                success = CX_TRUE;
                result = (CX_VOID *) ((CX_SIZE_T)result + (Range->Address - tmpAddress));
            }
        }
        else
        {
            // host virtual mem
            setUc = CX_FALSE;
            result = (CX_VOID *)Range->Address; // it'a a HV VA -- check if already mapped
            LOG("AUTO-Mapping: HVA\n");
            if (MmIsMemReadable(&gHvMm, result, Range->Size))
            {
                LOG("AUTO-Mapping: HVA - CX_SUCCESS\n");
                success = CX_TRUE;
            }
        }
    }
    else
        // case 2: guest mem
    {
        LOG("AUTO-Mapping: validate guest\n");
        // validate the guest structure
        if ((Target->VcpuTarget.GuestIndex < gHypervisorGlobalData.GuestCount) && ( gHypervisorGlobalData.Guest[Target->VcpuTarget.GuestIndex]))
        {
            GUEST *guest = gHypervisorGlobalData.Guest[Target->VcpuTarget.GuestIndex];

            if (!MmIsMemReadable(&gHvMm, guest, sizeof(GUEST)))
            {
                // faild to access guest fields
                ERROR("GUEST structure at %p is not readable\n", guest);
            }
            else
            {
                if (Target->IsPhysicalNotVirtual)
                {
                    LOG("AUTO-Mapping: GPA\n");
                    // guest physical address
                    LOG("ChmMapContinuousGuestGpaPagesToHost: <isHost=%d, isPhys=%d, Guest=%d, Vcpu=%d, P=%p, S=%p>\n",
                        Target->IsHostNotGuest, Target->IsPhysicalNotVirtual, Target->VcpuTarget.GuestIndex, Target->VcpuTarget.VcpuIndex,
                        Range->Address, pages);
                    status = ChmMapContinuousGuestGpaPagesToHost(guest,
                        tmpAddress, (CX_UINT32)pages, 0, &result, CX_NULL, TAG_ITPT);
                    if (CX_SUCCESS(status))
                    {
                        LOG("AUTO-Mapping: GPA - CX_SUCCESS\n");
                        success = CX_TRUE;
                        result = (CX_VOID *) ((CX_SIZE_T)result + (Range->Address - tmpAddress));
                    }
                }
                else
                {
                    // guest virtual address
                    if ((Target->VcpuTarget.VcpuIndex < guest->VcpuCount) && ( guest->Vcpu[Target->VcpuTarget.VcpuIndex]))
                    {
                        VCPU *vcpu = guest->Vcpu[Target->VcpuTarget.VcpuIndex];
                        LOG("AUTO-Mapping: validate vcpu\n");
                        if (!MmIsMemReadable(&gHvMm, vcpu, sizeof(VCPU)))
                        {
                            // faild to access vcpu fields
                            LOG("ERROR: VCPU structure at %p is not readable\n", vcpu);
                        }
                        else
                        {
                            LOG("AUTO-Mapping: GVA\n");
                            status = ChmMapGuestGvaPagesToHost(vcpu,
                                tmpAddress, (CX_UINT32)pages, 0, &result, CX_NULL, TAG_ITPT);
                            if (CX_SUCCESS(status))
                            {
                                LOG("AUTO-Mapping: GVA - CX_SUCCESS\n");
                                success = CX_TRUE;
                                result = (CX_VOID *) ((CX_SIZE_T)result + (Range->Address - tmpAddress));
                            }
                        }
                    }
                }
            }
        }
    }

    // disable memory caching for the resulted mapping
    if ((result) && (setUc)) MmAlterCaching(&gHvMm, result, 0, MM_CACHING_UC);

    if (HvVa) *HvVa = result;

    return success;
}

CX_BOOL
InterpreterUnmapAlienSpace(
    _In_ DBG_PARAM_MEMTARGET *Target,
    _Inout_opt_ CX_VOID      **HvVa
)
{
    CX_BOOL success = CX_FALSE;
    CX_VOID *tmpAddress;

    tmpAddress = (CX_VOID *)(CX_ROUND_DOWN((CX_SIZE_T)*HvVa, CX_PAGE_SIZE_4K));

    // case 1: host memory
    if (Target->IsHostNotGuest)
    {
        // host physical mem
        if (Target->IsPhysicalNotVirtual)
        {
            LOG("AUTO-Unmapping: HPA\n");
            MmUnmapDevMem(&gHvMm, CX_TRUE, TAG_ALIN, &tmpAddress);
            *HvVa = tmpAddress;
        }
        else
        {
            LOG("AUTO-Unmapping: HVA\n");
            // host virtual mem -- memory was already mapped, nothing to free
        }
    }
    else
        // case 2: guest mem
    {
        // validate the guest structure
        if (Target->IsPhysicalNotVirtual)
        {
            LOG("AUTO-Unmapping: GPA\n");
            ChmUnmapContinuousGuestGpaPagesFromHost(&tmpAddress, TAG_ITPT);
            *HvVa = tmpAddress;
        }
        else
        {
            LOG("AUTO-Unmapping: GVA\n");
            ChmUnmapGuestGvaPages(&tmpAddress, TAG_ITPT);
            *HvVa = tmpAddress;
        }
    }
    if (HvVa) *HvVa = CX_NULL;
    return success;
}

/* Static functions */
static
CX_BOOL
_MatchSimpleSymbol(
    _In_ CHAR *Input,
    _In_ CX_INT64 Length,
    __out_opt CX_INT64 *Consumed
)
//
// parse [a-zA-Z_:][a-zA-Z_:0-9]* characters found at the beginning of Input
//
{
    CX_INT64 consumed = 0;
    if (( Input) && (Length >= 0))
    {
        if (((Input[0] >= 'a') && (Input[0] <= 'z'))||
            ((Input[0] >= 'A') && (Input[0] <= 'Z'))||
            (Input[0] == '_') || (Input[0] == ':')  ||
            (Input[0] == '.'))
        {
            consumed++;
            while ((CX_INT64)consumed < Length)
            {
                if (((Input[consumed] >= 'a') && (Input[consumed] <= 'z'))||
                    ((Input[consumed] >= 'A') && (Input[consumed] <= 'Z'))||
                    (Input[consumed] == '_') || (Input[consumed] == ':') || (Input[0] == ':') ||
                    ((Input[consumed] >= '0') && (Input[consumed] <= '9')))
                {
                    consumed++;
                }
                else
                {
                    break;
                }
            }
        }
    }
    if (Consumed) *Consumed = consumed;
    if (consumed != 0) DBGTRACE("Symbol matched!\n");
    return consumed != 0;
}

static
CX_BOOL
_MatchNumber(
    _In_ CHAR *Input,
    _In_ CX_INT64 Length,
    __out_opt CX_UINT64 *ReturnValue,
    __out_opt CX_INT64 *Consumed,
    _In_ CX_BOOL Secure                     // avoid giving access to advanced features that might be unsecure on external input
)
//
// Match a number in base 8, 10 or 16
//
{
    CX_INT64 consumed = 0;
    CX_UINT64 result = 0;
    CHAR *current = Input;
    CX_BOOL isHex = CX_FALSE;
    CX_BOOL isValid = CX_FALSE;
    CX_BOOL negative = CX_FALSE;

    if ((!Input) || (Length == 0))
    {
        return CX_FALSE;
    }

    // check (and count) for the 0x case
    if (Length>1)
    {
        if (current[0] == '-')
        {
            current++;
            consumed++;
            negative = CX_TRUE;
        }

        if ((current[0] == '0') && ((current[1] == 'x') || (current[1] == 'X')))
        {
            current += 2;
            consumed = 2;
            isHex = CX_TRUE;
        }
    }

    // check (and count) for 0-9 or a-f digits
    while ((consumed <= Length) &&
        (((current[0] >= '0') && (current[0] <= '9')) ||
           ((isHex) && (((current[0] >='a') && (current[0] <= 'f')) || ((current[0] >='A') && (current[0] <= 'F'))))))
    {
        consumed++;
        current++;
    }

    // check if a number was indeed found
    if (((!isHex) && (consumed > 0))||
        ((isHex) && (consumed > 2)))
    {
        result = strtoull(Input + (negative), CX_NULL, 0);

        isValid = CX_TRUE;
    }

    if ((!isValid) && (InterpreterGlobals.Repeating != CX_FALSE))
    {
        // match /i\b/
        if ((current[0] == 'i') &&
            ((Length<2) ||
            (!(((current[1]>='a')&&(current[1]<='z'))||((current[1]>='A')&&(current[1]<='Z'))||((current[1]>='0')&&(current[1]<='9'))||(current[1] == '_')))
            ))
        {
            consumed++;
            isValid = CX_TRUE;
            result = InterpreterGlobals.RepeatCounter;
        }
    }


    // check for BYTE|WORD|DWORD|QWORD|VMX|GATE[target:address]
    if ((!isValid) && (!Secure))
    {
        CX_INT64 tmp;
        CX_UINT8 size = 0;
        consumed = 0;
        // BYTE|WORD|DWORD|QWORD
        if (InterpreterMatchToken(Input + negative, Length - negative, "byte", &tmp))
        {
            size = 1;
        }
        else if (InterpreterMatchToken(Input + negative, Length - negative, "word", &tmp))
        {
            size = 2;
        }
        else if (InterpreterMatchToken(Input + negative, Length - negative, "dword", &tmp))
        {
            size = 4;
        }
        else if (InterpreterMatchToken(Input + negative, Length - negative, "qword", &tmp))
        {
            size = 8;
        }
        else if (InterpreterMatchToken(Input + negative, Length - negative, "vmx", &tmp))
        {
            size = 255;
        }
        else if (InterpreterMatchToken(Input + negative, Length - negative, "gate64", &tmp))
        {
            size = 254;
        }
        else if (InterpreterMatchToken(Input + negative, Length - negative, "io", &tmp))
        {
            size = 253;
        }
        if (0 != size)
        {
            DBGTRACE("SIZE: %d\n", size);
            consumed += tmp;
            // spaces
            if (InterpreterMatchSpaces(Input+consumed, Length - consumed, &tmp))
            {
                consumed += tmp;
            }
            // [
            if (InterpreterMatchToken(Input+consumed, Length - consumed, "[", &tmp))
            {
                DBG_PARAM_MEMTARGET target;
                CX_BOOL isOk = CX_TRUE;
                target = DbgDefaultParams.MemTarget;

                consumed += tmp;
                // spaces
                if (InterpreterMatchSpaces(Input+consumed, Length - consumed, &tmp))
                {
                    consumed += tmp;
                }
                // memtarget
                DBGTRACE("MEMTARGET..\n");
                if (_MatchMemTarget(Input+consumed, Length-consumed, &target, &tmp))
                {
                    isOk = CX_FALSE;
                    consumed += tmp;
                    // spaces
                    if (InterpreterMatchSpaces(Input+consumed, Length - consumed, &tmp))
                    {
                        consumed += tmp;
                    }
                    DBGTRACE(":..\n");
                    // :
                    if (InterpreterMatchToken(Input + consumed, Length - consumed, ":", &tmp))
                    {
                        consumed += tmp;
                        isOk = CX_TRUE;
                    }
                    if (InterpreterMatchSpaces(Input+consumed, Length - consumed, &tmp))
                    {
                        consumed += tmp;
                    }
                }
                // and/or a numeric expression for the actual address
                if (isOk)
                {
                    DBG_PARAM_MEMRANGE range = {0};
                    CX_VOID *address;
                    CX_BOOL writeRequired = CX_FALSE;
                    CX_UINT64 val;

                    range.Size = size;
                    range.UnspecifiedSize = CX_FALSE;
                    DBGTRACE("ADDRESS..\n");
                    if (InterpreterMatchNumericExpression(Input+consumed, Length - consumed, &(range.Address), &tmp, Secure))
                    {
                        consumed += tmp;
                        if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &tmp))
                        {
                            consumed += tmp;
                        }
                        if (InterpreterMatchToken(Input + consumed, Length-consumed, "]", &tmp))
                        {
                            consumed += tmp;
                        }

                        address = (CX_VOID *)(range.Address);
                        // move the next if inside the prev. block to enforce the ']'...
                        if ((255 == size) || (254 == size) || (253 == size) // for vmx/idt[address] don't map anything
                            || (InterpreterMapAlienSpace(&target, &range, &address)))
                        {
                            isValid = CX_TRUE;

                            if (_MatchAssignment(Input + consumed, Length - consumed, &tmp, &val))
                            {
                                consumed += tmp;
                                writeRequired = CX_TRUE && InterpreterGlobals.PerformOperation;
                            }


                            if (1 == size)
                            {
                                if (writeRequired) *(CX_UINT8 *)(address) = (CX_UINT8)val;
                                result = *(CX_UINT8 *)(address);
                            }
                            else if (2 == size)
                            {
                                if (writeRequired) *(CX_UINT16 *)(address) = (CX_UINT16)val;

                                result = *(CX_UINT16 *)(address);
                            }
                            else if (4 == size)
                            {
                                if (writeRequired) *(CX_UINT32 *)(address) = (CX_UINT32)val;
                                result = *(CX_UINT32 *)(address);
                            }
                            else if (8 == size)
                            {
                                if (writeRequired) *(CX_UINT64 *)(address) = (CX_UINT64)val;
                                result = *(CX_UINT64 *)(address);
                            }
                            else if (255 == size)
                            {
                                // read a vmcs value
                                CX_UINT64 currentVmcsPA;

                                if (_SwitchVmcs(gHypervisorGlobalData.Guest[target.VcpuTarget.GuestIndex]->Vcpu[target.VcpuTarget.VcpuIndex]->VmcsPa, &currentVmcsPA))
                                {
                                    if (writeRequired)
                                    {
                                        if (0 != vmx_vmwrite((CX_SIZE_T)address, val))
                                        {
                                            ERROR("vmx_vmwrite has failed!\n");
                                            isValid = CX_FALSE;
                                        }
                                    }
                                    result = 0;
                                    if (0 != vmx_vmread((CX_SIZE_T)address, &result))
                                    {
                                        ERROR("vmx_vmread has failed!\n");
                                        isValid = CX_FALSE;
                                    }

                                    // Restore VMCS
                                    _SwitchVmcs(currentVmcsPA, CX_NULL);
                                }
                                else
                                {
                                    isValid = CX_FALSE;
                                    LOG_FUNC_FAIL("_SwitchVmcs", CX_STATUS_UNINITIALIZED_STATUS_VALUE);
                                }
                            }
                            else if (254 == size)
                            {
                                // idt gate
                                CPU_IDTR idtr = {0};
                                CX_UINT16 byteIndex;
                                INTERRUPT_GATE *gate;
                                if ((CX_UINT64)address > 256)
                                {
                                    ERROR("Invalid interrupt vector specified\n");
                                    isValid = CX_FALSE;
                                }
                                else
                                {
                                    if (target.IsHostNotGuest)
                                    {
                                        // get the host idt
                                        __sidt(&idtr);
                                    }
                                    else
                                    {
                                        CX_UINT64 currentVmcsPA;
                                        CX_UINT64 limit;

                                        // read VMCS_GUEST_IDTR_BASE
                                        if (_SwitchVmcs(gHypervisorGlobalData.Guest[target.VcpuTarget.GuestIndex]->Vcpu[target.VcpuTarget.VcpuIndex]->VmcsPa, &currentVmcsPA))
                                        {
                                            if (0 != vmx_vmread(VMCS_GUEST_IDTR_BASE, &limit))
                                            {
                                                ERROR("vmx_vmread has failed!\n");
                                                isValid = CX_FALSE;
                                            }
                                            idtr.Base = limit;
                                            if (0 != vmx_vmread(VMCS_GUEST_IDTR_LIMIT, &limit))
                                            {
                                                ERROR("vmx_vmread has failed!\n");
                                                isValid = CX_FALSE;
                                            }
                                            idtr.Limit = (CX_UINT16)(limit & 0xFFFF);
                                            _SwitchVmcs(currentVmcsPA, CX_NULL);
                                        }
                                    }
                                    byteIndex = ((CX_UINT16)(CX_UINT64)address) * 16;
                                    if (byteIndex > idtr.Limit)
                                    {
                                        ERROR("The interrupt vector is beyound the IDT limit!\n");
                                        isValid = CX_FALSE;
                                    }
                                    else
                                    {
                                        target.IsPhysicalNotVirtual = CX_FALSE; // idtr is always specified as VA
                                        range.Address = idtr.Base + byteIndex;
                                        range.Size = sizeof(INTERRUPT_GATE);
                                        if (InterpreterMapAlienSpace(&target, &range, &address))
                                        {
                                            gate = (INTERRUPT_GATE*) address;
                                            if (0 == gate->P)
                                            {
                                                ERROR("Non-present interrupt gate: addr=%p host=%d VA=%d\n",
                                                      range.Address, target.IsHostNotGuest, (!target.IsPhysicalNotVirtual));
                                                isValid = CX_FALSE;
                                            }
                                            else if (0 != gate->S)
                                            {
                                                ERROR("Non-system interrupt descriptor\n");
                                                isValid = CX_FALSE;
                                            }
                                            else
                                            {
                                                ((CX_UINT16*)&result)[0] = (CX_UINT16)gate->Offset_15_0;
                                                ((CX_UINT16*)&result)[1] = (CX_UINT16)gate->Offset_31_16;
                                                ((CX_UINT32*)&result)[1] = (CX_UINT32)gate->Offset_63_32;
                                                if (writeRequired)
                                                {
                                                    /// cli...
                                                    gate->Offset_15_0 = ((CX_UINT16*)&val)[0];
                                                    gate->Offset_31_16 = ((CX_UINT16*)&val)[1];
                                                    gate->Offset_63_32 = ((CX_UINT32*)&val)[1];
                                                }
                                                isValid = CX_TRUE;
                                            }
                                            InterpreterUnmapAlienSpace(&target, &address);
                                        }
                                    }
                                }
                            }
                            else if (253 == size)
                            {
                                if (writeRequired)
                                {
                                    __outbyte((CX_UINT16)(CX_SIZE_T)address, (CX_UINT8)val);
                                    result = (CX_UINT8)val;
                                }
                                else
                                {
                                    result = __inbyte((CX_UINT16)(CX_SIZE_T)address);
                                }
                            }
                            else
                            {
                                isValid = CX_FALSE;
                            }
                            if (isValid) DBGTRACE("RETURN %p..\n", result);

                            if (255 != size && 253 != size) InterpreterUnmapAlienSpace(&target, &address);
                        }
                    }
                }
            }
        }
    }
#define DBG_MATCH_CONST(NAME, VALUE)\
    if (InterpreterMatchToken(Input + consumed, Length - consumed, #NAME, &localTmp))\
    {\
        consumed += localTmp;\
        if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &localTmp)) { consumed += localTmp; }\
        result = VALUE; isValid = CX_TRUE;\
    }

#define DBG_MATCH_HV_CONST(NAME)\
    if (InterpreterMatchToken(Input + consumed, Length - consumed, #NAME, &localTmp))\
    {\
        consumed += localTmp; \
        if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &localTmp)) { consumed += localTmp; } \
            result = NAME; isValid = CX_TRUE; \
    }
    // check for sizeof
    if ((!isValid) && (!Secure))
    {
        consumed = 0;

        CX_INT64 localTmp;
        DBG_PARAM_VCPUTARGET target;
        target = DbgDefaultParams.VcpuTarget;

        // check for [#g.v.]
        if (_MatchVcpuTarget(Input, Length - consumed, &target, &localTmp))
        {
            CX_INT64 startIndex;
            startIndex = consumed;
            consumed += localTmp;

            // take the '.'
            if (InterpreterMatchToken(Input + consumed, Length - consumed, ".", &localTmp))
            {
                consumed += localTmp;
            }
            else
            {
                consumed = startIndex; // rollback
            }
        }
        // check segment registers
        if (InterpreterMatchToken(Input + consumed, Length - consumed, "cs", &localTmp))
        {
            CX_UINT64 currentVmcsPA, val;
            CX_BOOL writeRequired = CX_FALSE;

            consumed += localTmp;
            if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &localTmp))
            {
                consumed += localTmp;
            }
            if (_MatchAssignment(Input + consumed, Length - consumed, &localTmp, &val))
            {
                consumed += localTmp;
                writeRequired = CX_TRUE && InterpreterGlobals.PerformOperation;
            }

            if (_SwitchVmcs(gHypervisorGlobalData.Guest[target.GuestIndex]->Vcpu[target.VcpuIndex]->VmcsPa, &currentVmcsPA))
            {
                CX_UINT64 cs;

                if(writeRequired)
                {
                    if (0 != vmx_vmwrite(VMCS_GUEST_CS, val))
                    {
                        ERROR("vmx_vmwrite has failed!\n");
                    }
                }

                if (0 != vmx_vmread(VMCS_GUEST_CS, &cs))
                {
                    ERROR("vmx_vmread has failed!\n");
                }

                // Restore VMCS
                _SwitchVmcs(currentVmcsPA, CX_NULL);
                result = cs;
            }
            isValid = CX_TRUE;
        }
        else if (InterpreterMatchToken(Input + consumed, Length - consumed, "csbase", &localTmp))
        {
            CX_UINT64 currentVmcsPA, val;
            CX_BOOL writeRequired = CX_FALSE;

            consumed += localTmp;
            if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &localTmp))
            {
                consumed += localTmp;
            }

            if (_MatchAssignment(Input + consumed, Length - consumed, &localTmp, &val))
            {
                consumed += localTmp;
                writeRequired = CX_TRUE && InterpreterGlobals.PerformOperation;
            }

            // Load designated VMCS
            if (_SwitchVmcs(gHypervisorGlobalData.Guest[target.GuestIndex]->Vcpu[target.VcpuIndex]->VmcsPa, &currentVmcsPA))
            {
                CX_UINT64 cs_base;

                if(writeRequired)
                {
                    if (0 != vmx_vmwrite(VMCS_GUEST_CS_BASE, val))
                    {
                        ERROR("vmx_vmwrite has failed!\n");
                    }
                }

                if (0 != vmx_vmread(VMCS_GUEST_CS_BASE, &cs_base))
                {
                    ERROR("vmx_vmread has failed!\n");
                }

                // Restore VMCS
                _SwitchVmcs(currentVmcsPA, CX_NULL);
                result = cs_base;
            }
            isValid = CX_TRUE;
        }
        if (InterpreterMatchToken(Input + consumed, Length - consumed, "ss", &localTmp))
        {
            CX_UINT64 currentVmcsPA, val;
            CX_BOOL writeRequired = CX_FALSE;

            consumed += localTmp;
            if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &localTmp))
            {
                consumed += localTmp;
            }
            if (_MatchAssignment(Input + consumed, Length - consumed, &localTmp, &val))
            {
                consumed += localTmp;
                writeRequired = CX_TRUE && InterpreterGlobals.PerformOperation;
            }

            // Load designated VMCS
            if (_SwitchVmcs(gHypervisorGlobalData.Guest[target.GuestIndex]->Vcpu[target.VcpuIndex]->VmcsPa, &currentVmcsPA))
            {
                CX_UINT64 ss;

                if(writeRequired)
                {
                    if (0 != vmx_vmwrite(VMCS_GUEST_SS, val))
                    {
                        ERROR("vmx_vmwrite has failed!\n");
                    }
                }

                if (0 != vmx_vmread(VMCS_GUEST_SS, &ss))
                {
                    ERROR("vmx_vmread has failed!\n");
                }

                // Restore VMCS
                _SwitchVmcs(currentVmcsPA, CX_NULL);
                result = ss;
            }
            isValid = CX_TRUE;
        }
        else if (InterpreterMatchToken(Input + consumed, Length - consumed, "ssbase", &localTmp))
        {
            CX_UINT64 currentVmcsPA, val;
            CX_BOOL writeRequired = CX_FALSE;

            consumed += localTmp;
            if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &localTmp))
            {
                consumed += localTmp;
            }
            if (_MatchAssignment(Input + consumed, Length - consumed, &localTmp, &val))
            {
                consumed += localTmp;
                writeRequired = CX_TRUE && InterpreterGlobals.PerformOperation;
            }

            // Load designated VMCS
            if (_SwitchVmcs(gHypervisorGlobalData.Guest[target.GuestIndex]->Vcpu[target.VcpuIndex]->VmcsPa, &currentVmcsPA))
            {
                CX_UINT64 ss_base;

                if(writeRequired)
                {
                    if (0 != vmx_vmwrite(VMCS_GUEST_SS_BASE, val))
                    {
                        ERROR("vmx_vmwrite has failed!\n");
                    }
                }

                if (0 != vmx_vmread(VMCS_GUEST_SS_BASE, &ss_base))
                {
                    ERROR("vmx_vmread has failed!\n");
                }

                // Restore VMCS
                _SwitchVmcs(currentVmcsPA, CX_NULL);
                result = ss_base;
            }
            isValid = CX_TRUE;
        }
        if (InterpreterMatchToken(Input + consumed, Length - consumed, "ds", &localTmp))
        {
            CX_UINT64 currentVmcsPA, val;
            CX_BOOL writeRequired = CX_FALSE;

            consumed += localTmp;
            if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &localTmp))
            {
                consumed += localTmp;
            }

            if (_MatchAssignment(Input + consumed, Length - consumed, &localTmp, &val))
            {
                consumed += localTmp;
                writeRequired = CX_TRUE && InterpreterGlobals.PerformOperation;
            }

            // Load designated VMCS
            if (_SwitchVmcs(gHypervisorGlobalData.Guest[target.GuestIndex]->Vcpu[target.VcpuIndex]->VmcsPa, &currentVmcsPA))
            {
                CX_UINT64 ds;

                if(writeRequired)
                {
                    if (0 != vmx_vmwrite(VMCS_GUEST_DS, val))
                    {
                        ERROR("vmx_vmwrite has failed!\n");
                    }
                }

                if (0 != vmx_vmread(VMCS_GUEST_DS, &ds))
                {
                    ERROR("vmx_vmread has failed!\n");
                }

                // Restore VMCS
                _SwitchVmcs(currentVmcsPA, CX_NULL);
                result = ds;
            }
            isValid = CX_TRUE;
        }
        else if (InterpreterMatchToken(Input + consumed, Length - consumed, "dsbase", &localTmp))
        {
            CX_UINT64 currentVmcsPA, val;
            CX_BOOL writeRequired = CX_FALSE;

            consumed += localTmp;
            if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &localTmp))
            {
                consumed += localTmp;
            }

            if (_MatchAssignment(Input + consumed, Length - consumed, &localTmp, &val))
            {
                consumed += localTmp;
                writeRequired = CX_TRUE && InterpreterGlobals.PerformOperation;
            }

            if (_SwitchVmcs(gHypervisorGlobalData.Guest[target.GuestIndex]->Vcpu[target.VcpuIndex]->VmcsPa, &currentVmcsPA))
            {
                CX_UINT64 ds_base;

                if(writeRequired)
                {
                    if (0 != vmx_vmwrite(VMCS_GUEST_DS_BASE, val))
                    {
                        ERROR("vmx_vmwrite has failed!\n");
                    }
                }

                if (0 != vmx_vmread(VMCS_GUEST_DS_BASE, &ds_base))
                {
                    ERROR("vmx_vmread has failed!\n");
                }

                // Restore VMCS
                _SwitchVmcs(currentVmcsPA, CX_NULL);
                result = ds_base;
            }
            isValid = CX_TRUE;
        }
        else
            // check for rip|rsp|....
            if (InterpreterMatchToken(Input + consumed, Length - consumed, "rip", &localTmp))
            {
                CX_UINT64 currentVmcsPA, val;
                CX_BOOL writeRequired = CX_FALSE;

                consumed += localTmp;
                if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &localTmp))
                {
                    consumed += localTmp;
                }

                if (_MatchAssignment(Input + consumed, Length - consumed, &localTmp, &val))
                {
                    consumed += localTmp;
                    writeRequired = CX_TRUE && InterpreterGlobals.PerformOperation;
                }

                // Load designated VMCS
                if (_SwitchVmcs(gHypervisorGlobalData.Guest[target.GuestIndex]->Vcpu[target.VcpuIndex]->VmcsPa, &currentVmcsPA))
                {
                    CX_UINT64 csBase;

                    vmx_vmread(VMCS_GUEST_CS_BASE, &csBase);

                    if(writeRequired)
                    {
                        gHypervisorGlobalData.Guest[target.GuestIndex]->Vcpu[target.VcpuIndex]->ArchRegs.RIP = val - csBase;
                        vmx_vmwrite(VMCS_GUEST_RIP, gHypervisorGlobalData.Guest[target.GuestIndex]->Vcpu[target.VcpuIndex]->ArchRegs.RIP);
                    }

                    // Restore VMCS
                    _SwitchVmcs(currentVmcsPA, CX_NULL);
                    result = gHypervisorGlobalData.Guest[target.GuestIndex]->Vcpu[target.VcpuIndex]->ArchRegs.RIP + csBase;
                }
                isValid = CX_TRUE;
            }
            else if (InterpreterMatchToken(Input + consumed, Length - consumed, "rsp", &localTmp))
            {
                CX_UINT64 currentVmcsPA, val;
                CX_BOOL writeRequired = CX_FALSE;

                consumed += localTmp;
                if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &localTmp))
                {
                    consumed += localTmp;
                }

                if (_MatchAssignment(Input + consumed, Length - consumed, &localTmp, &val))
                {
                    consumed += localTmp;
                    writeRequired = CX_TRUE && InterpreterGlobals.PerformOperation;
                }


                if (_SwitchVmcs(gHypervisorGlobalData.Guest[target.GuestIndex]->Vcpu[target.VcpuIndex]->VmcsPa, &currentVmcsPA))
                {
                    CX_UINT64 ssBase;
                    vmx_vmread(VMCS_GUEST_SS_BASE, &ssBase);

                    if(writeRequired)
                    {
                        gHypervisorGlobalData.Guest[target.GuestIndex]->Vcpu[target.VcpuIndex]->ArchRegs.RSP = val - ssBase;
                        vmx_vmwrite(VMCS_GUEST_RSP, gHypervisorGlobalData.Guest[target.GuestIndex]->Vcpu[target.VcpuIndex]->ArchRegs.RSP);
                    }

                    // Restore VMCS
                    _SwitchVmcs(currentVmcsPA, CX_NULL);
                    result = gHypervisorGlobalData.Guest[target.GuestIndex]->Vcpu[target.VcpuIndex]->ArchRegs.RSP + ssBase;
                }
                isValid = CX_TRUE;
            }

            else if (InterpreterMatchToken(Input + consumed, Length - consumed, "rax", &localTmp))
            {
                DBG_MATCH_ARCHREG(RAX);
            }
            else if (InterpreterMatchToken(Input + consumed, Length - consumed, "rbx", &localTmp))
            {
                DBG_MATCH_ARCHREG(RBX);
            }
            else if (InterpreterMatchToken(Input + consumed, Length - consumed, "rcx", &localTmp))
            {
                DBG_MATCH_ARCHREG(RCX);
            }
            else if (InterpreterMatchToken(Input + consumed, Length - consumed, "rdx", &localTmp))
            {
                DBG_MATCH_ARCHREG(RDX);
            }
            else if (InterpreterMatchToken(Input + consumed, Length - consumed, "r8", &localTmp))
            {
                DBG_MATCH_ARCHREG(R8);
            }
            else if (InterpreterMatchToken(Input + consumed, Length - consumed, "r9", &localTmp))
            {
                DBG_MATCH_ARCHREG(R9);
            }
            else if (InterpreterMatchToken(Input + consumed, Length - consumed, "r10", &localTmp))
            {
                DBG_MATCH_ARCHREG(R10);
            }
            else if (InterpreterMatchToken(Input + consumed, Length - consumed, "r11", &localTmp))
            {
                DBG_MATCH_ARCHREG(R11);
            }
            else if (InterpreterMatchToken(Input + consumed, Length - consumed, "r12", &localTmp))
            {
                DBG_MATCH_ARCHREG(R12);
            }
            else if (InterpreterMatchToken(Input + consumed, Length - consumed, "r13", &localTmp))
            {
                DBG_MATCH_ARCHREG(R13);
            }
            else if (InterpreterMatchToken(Input + consumed, Length - consumed, "r14", &localTmp))
            {
                DBG_MATCH_ARCHREG(R14);
            }
            else if (InterpreterMatchToken(Input + consumed, Length - consumed, "r15", &localTmp))
            {
                DBG_MATCH_ARCHREG(R15);
            }
            else if (InterpreterMatchToken(Input + consumed, Length - consumed, "rsi", &localTmp))
            {
                DBG_MATCH_ARCHREG(RSI);
            }
            else if (InterpreterMatchToken(Input + consumed, Length - consumed, "rdi", &localTmp))
            {
                DBG_MATCH_ARCHREG(RDI);
            }
            else if (InterpreterMatchToken(Input + consumed, Length - consumed, "rbp", &localTmp))
            {
                DBG_MATCH_ARCHREG(RBP);
            }
            else if (InterpreterMatchToken(Input + consumed, Length - consumed, "cr2", &localTmp))
            {
                DBG_MATCH_ARCHREG(CR2);
            }
            else if (InterpreterMatchToken(Input + consumed, Length - consumed, "rflags", &localTmp))
            {
                CX_UINT64 val;
                CX_BOOL writeRequired = CX_FALSE;
                consumed += localTmp;
                if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &localTmp))
                {
                    consumed += localTmp;
                }
                if (_MatchAssignment(Input + consumed, Length - consumed, &localTmp, &val))
                {
                    consumed += localTmp;
                    writeRequired = CX_TRUE && InterpreterGlobals.PerformOperation;
                }
                if(writeRequired)
                {
                    gHypervisorGlobalData.Guest[target.GuestIndex]->Vcpu[target.VcpuIndex]->ArchRegs.RFLAGS = val;
                    vmx_vmwrite(VMCS_GUEST_RFLAGS, val);
                }
                result = gHypervisorGlobalData.Guest[target.GuestIndex]->Vcpu[target.VcpuIndex]->ArchRegs.RFLAGS;
                isValid = CX_TRUE;
            }
            else if (InterpreterMatchToken(Input + consumed, Length - consumed, "cr0", &localTmp))
            {
                CX_UINT64 val;
                CX_BOOL writeRequired = CX_FALSE;
                consumed += localTmp;
                if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &localTmp))
                {
                    consumed += localTmp;
                }
                if (_MatchAssignment(Input + consumed, Length - consumed, &localTmp, &val))
                {
                    consumed += localTmp;
                    writeRequired = CX_TRUE && InterpreterGlobals.PerformOperation;
                }
                if(writeRequired)
                {
                    gHypervisorGlobalData.Guest[target.GuestIndex]->Vcpu[target.VcpuIndex]->ArchRegs.CR0 = val;
                    vmx_vmwrite(VMCS_GUEST_CR0, val);
                }
                result = gHypervisorGlobalData.Guest[target.GuestIndex]->Vcpu[target.VcpuIndex]->ArchRegs.CR0;
                isValid = CX_TRUE;
            }
            else if (InterpreterMatchToken(Input + consumed, Length - consumed, "cr3", &localTmp))
            {
                CX_UINT64 val;
                CX_BOOL writeRequired = CX_FALSE;
                consumed += localTmp;
                if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &localTmp))
                {
                    consumed += localTmp;
                }
                if (_MatchAssignment(Input + consumed, Length - consumed, &localTmp, &val))
                {
                    consumed += localTmp;
                    writeRequired = CX_TRUE && InterpreterGlobals.PerformOperation;
                }
                if(writeRequired)
                {
                    gHypervisorGlobalData.Guest[target.GuestIndex]->Vcpu[target.VcpuIndex]->ArchRegs.CR3 = val;
                    vmx_vmwrite(VMCS_GUEST_CR3, val);
                }
                result = gHypervisorGlobalData.Guest[target.GuestIndex]->Vcpu[target.VcpuIndex]->ArchRegs.CR3;
                isValid = CX_TRUE;
            }
            else if (InterpreterMatchToken(Input + consumed, Length - consumed, "cr4", &localTmp))
            {
                CX_UINT64 val;
                CX_BOOL writeRequired = CX_FALSE;
                consumed += localTmp;
                if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &localTmp))
                {
                    consumed += localTmp;
                }
                if (_MatchAssignment(Input + consumed, Length - consumed, &localTmp, &val))
                {
                    consumed += localTmp;
                    writeRequired = CX_TRUE && InterpreterGlobals.PerformOperation;
                }
                if(writeRequired)
                {
                    gHypervisorGlobalData.Guest[target.GuestIndex]->Vcpu[target.VcpuIndex]->ArchRegs.CR4 = val;
                    vmx_vmwrite(VMCS_GUEST_CR4, val);
                }
                result = gHypervisorGlobalData.Guest[target.GuestIndex]->Vcpu[target.VcpuIndex]->ArchRegs.CR4;
                isValid = CX_TRUE;
            }
            else if (InterpreterMatchToken(Input + consumed, Length - consumed, "rdtsc", &localTmp))
            {
                consumed += localTmp;
                result = __rdtsc();
                isValid = CX_TRUE;
            }
            //
            // continue with symbolic constants
            //
            else DBG_MATCH_CONST(kilo, 1024)
            else DBG_MATCH_CONST(mega, 1024*1024)
            else DBG_MATCH_CONST(giga, 1024*1024*1024)
            else DBG_MATCH_CONST(tera, (CX_UINT64)1024 * 1024 * 1024 * 1024ULL)
            else DBG_MATCH_HV_CONST( VMCSFLAG_IRRSTATE_BLOCKING_BY_MOV_SS)
            else DBG_MATCH_HV_CONST( VMCSFLAG_IRRSTATE_BLOCKING_BY_NMI)
            else DBG_MATCH_HV_CONST( VMCSFLAG_IRRSTATE_BLOCKING_BY_STI)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PENDBGEX_BS)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PINEXEC_EXTERNAL_INTERRUPT)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PINEXEC_NMI)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PINEXEC_PREEMPTION_TIMER)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PINEXEC_PROCESS_POSTED_INTERRUPTS)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PINEXEC_VIRTUAL_NMIS)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PROCEXEC2_ALLOW_RDTSCP)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PROCEXEC2_APIC_REG_VIRTUALIZATION)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PROCEXEC2_DESC_TABLE_EXIT)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PROCEXEC2_ENABLE_EPT)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PROCEXEC2_ENABLE_VPID)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PROCEXEC2_EPT_VE)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PROCEXEC2_INVPCID_ENABLE)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PROCEXEC2_PAUSE_LOOP_EXIT)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PROCEXEC2_RDRAND_EXIT)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PROCEXEC2_UNRESTRICTED_GUEST)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PROCEXEC2_UNUSED_15)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PROCEXEC2_UNUSED_16)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PROCEXEC2_UNUSED_17)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PROCEXEC2_VIRTUALIZE_APIC_ACCESSES)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PROCEXEC2_VIRTUALIZE_X2APIC_MODE)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PROCEXEC2_VIRT_INTR_DELIVERY)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PROCEXEC2_VMCS_SHADOWING)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PROCEXEC2_VMFUNC_ENABLE)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PROCEXEC2_WBINVD_EXIT)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PROCEXEC_CR3_LOAD_EXIT)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PROCEXEC_CR3_STORE_EXIT)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PROCEXEC_ENABLE_PROC_EXEC_CONTROL_2)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PROCEXEC_HLT_EXIT)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PROCEXEC_INTERRUPT_WINDOW_EXIT)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PROCEXEC_INVLPG_EXIT)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PROCEXEC_MONITOR_EXIT)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PROCEXEC_MONITOR_TRAP_FLAG_EXIT)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PROCEXEC_MWAIT_EXIT)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PROCEXEC_NMI_WINDOW_EXIT)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PROCEXEC_PAUSE_EXIT)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PROCEXEC_RDPMC_EXIT)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PROCEXEC_RDTSC_EXIT)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PROCEXEC_UNCONDITIONAL_IO_EXIT)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PROCEXEC_USE_IO_BITMAPS)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PROCEXEC_USE_MSR_BITMAPS)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PROCEXEC_USE_TPR_SHADOW)
            else DBG_MATCH_HV_CONST( VMCSFLAG_PROCEXEC_USE_TSC_OFFSETTING)
            else DBG_MATCH_HV_CONST( VMCSFLAG_VMENTRY_DEACTIVATE_DUAL_MONITOR)
            else DBG_MATCH_HV_CONST( VMCSFLAG_VMENTRY_IA32E_GUEST_EFER_LMA)
            else DBG_MATCH_HV_CONST( VMCSFLAG_VMENTRY_LOAD_DEBUG_CONTROLS)
            else DBG_MATCH_HV_CONST( VMCSFLAG_VMENTRY_LOAD_IA32_EFER_FROM_VMCS)
            else DBG_MATCH_HV_CONST( VMCSFLAG_VMENTRY_LOAD_IA32_PAT_FROM_VMCS)
            else DBG_MATCH_HV_CONST( VMCSFLAG_VMENTRY_SMM)
            else DBG_MATCH_HV_CONST( VMCSFLAG_VMEXIT_64BIT_HOST)
            else DBG_MATCH_HV_CONST( VMCSFLAG_VMEXIT_ACKNOWLEDGE_INTERRUPT_ON_EXIT)
            else DBG_MATCH_HV_CONST( VMCSFLAG_VMEXIT_LOAD_IA32_EFER_FROM_HOST)
            else DBG_MATCH_HV_CONST( VMCSFLAG_VMEXIT_LOAD_IA32_PAT_FROM_HOST)
            else DBG_MATCH_HV_CONST( VMCSFLAG_VMEXIT_SAVE_DEBUG_CONTROLS)
            else DBG_MATCH_HV_CONST( VMCSFLAG_VMEXIT_SAVE_IA32_EFER_TO_VMCS)
            else DBG_MATCH_HV_CONST( VMCSFLAG_VMEXIT_SAVE_IA32_PAT_TO_VMCS)
            else DBG_MATCH_HV_CONST( VMCSFLAG_VMEXIT_SAVE_TIMER)
            else DBG_MATCH_HV_CONST( VMCS_APIC_ACCESS_ADDR)
            else DBG_MATCH_HV_CONST( VMCS_CR3_TARGET_COUNT)
            else DBG_MATCH_HV_CONST( VMCS_CR3_TARGET_VALUE_0)
            else DBG_MATCH_HV_CONST( VMCS_CR3_TARGET_VALUE_1)
            else DBG_MATCH_HV_CONST( VMCS_CR3_TARGET_VALUE_2)
            else DBG_MATCH_HV_CONST( VMCS_CR3_TARGET_VALUE_3)
            else DBG_MATCH_HV_CONST( VMCS_EPTP)
            else DBG_MATCH_HV_CONST( VMCS_ERROR)
            else DBG_MATCH_HV_CONST( VMCS_EXCEPTION_BITMAP)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_ACTIVITY_STATE)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_CR0)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_CR0_MASK)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_CR0_READ_SHADOW)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_CR3)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_CR4)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_CR4_MASK)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_CR4_READ_SHADOW)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_CS)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_CS_ACCESS_RIGHTS)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_CS_BASE)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_CS_LIMIT)
            // break the if else chain before the compiler goes kaboom
            DBG_MATCH_HV_CONST( VMCS_GUEST_DR7)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_DS)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_DS_ACCESS_RIGHTS)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_DS_BASE)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_DS_LIMIT)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_ES)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_ES_ACCESS_RIGHTS)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_ES_BASE)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_ES_LIMIT)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_FS)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_FS_ACCESS_RIGHTS)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_FS_BASE)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_FS_LIMIT)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_GDTR_BASE)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_GDTR_LIMIT)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_GS)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_GS_ACCESS_RIGHTS)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_GS_BASE)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_GS_LIMIT)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_IA32_DEBUGCTL)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_IA32_EFER)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_IA32_PAT)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_IA32_PERF_GLOBAL_CTRL)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_IA32_SYSENTER_CS)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_IA32_SYSENTER_RIP)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_IA32_SYSENTER_RSP)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_IDTR_BASE)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_IDTR_LIMIT)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_INTERRUPTIBILITY_STATE)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_LDTR)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_LDTR_ACCESS_RIGHTS)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_LDTR_BASE)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_LDTR_LIMIT)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_LINEAR)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_LINK_POINTER)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_PDPTE0)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_PDPTE1)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_PDPTE2)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_PDPTE3)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_PHYSICAL)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_RFLAGS)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_RIP)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_RSP)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_SMBASE)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_SS)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_SS_ACCESS_RIGHTS)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_SS_BASE)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_SS_LIMIT)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_TR)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_TR_ACCESS_RIGHTS)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_TR_BASE)
            else DBG_MATCH_HV_CONST( VMCS_GUEST_TR_LIMIT)
            else DBG_MATCH_HV_CONST( VMCS_HOST_CR0)
            else DBG_MATCH_HV_CONST( VMCS_HOST_CR3)
            else DBG_MATCH_HV_CONST( VMCS_HOST_CR4)
            else DBG_MATCH_HV_CONST( VMCS_HOST_CS)
            else DBG_MATCH_HV_CONST( VMCS_HOST_DS)
            else DBG_MATCH_HV_CONST( VMCS_HOST_ES)
            else DBG_MATCH_HV_CONST( VMCS_HOST_FS)
            else DBG_MATCH_HV_CONST( VMCS_HOST_FS_BASE)
            else DBG_MATCH_HV_CONST( VMCS_HOST_GDTR_BASE)
            else DBG_MATCH_HV_CONST( VMCS_HOST_GS)
            else DBG_MATCH_HV_CONST( VMCS_HOST_GS_BASE)
            else DBG_MATCH_HV_CONST( VMCS_HOST_IA32_EFER)
            else DBG_MATCH_HV_CONST( VMCS_HOST_IA32_PAT)
            else DBG_MATCH_HV_CONST( VMCS_HOST_IA32_PERF_GLOBAL_CTRL)
            else DBG_MATCH_HV_CONST( VMCS_HOST_IA32_SYSENTER_CS)
            else DBG_MATCH_HV_CONST( VMCS_HOST_IA32_SYSENTER_RIP)
            else DBG_MATCH_HV_CONST( VMCS_HOST_IA32_SYSENTER_RSP)
            else DBG_MATCH_HV_CONST( VMCS_HOST_IDTR_BASE)
            else DBG_MATCH_HV_CONST( VMCS_HOST_RIP)
            else DBG_MATCH_HV_CONST( VMCS_HOST_RSP)
            else DBG_MATCH_HV_CONST( VMCS_HOST_SS)
            else DBG_MATCH_HV_CONST( VMCS_HOST_TR)
            else DBG_MATCH_HV_CONST( VMCS_HOST_TR_BASE)
            else DBG_MATCH_HV_CONST( VMCS_IDT_VECTORING_ERROR_CODE)
            else DBG_MATCH_HV_CONST( VMCS_IDT_VECTORING_INFORMATTION)
            else DBG_MATCH_HV_CONST( VMCS_IO_BITMAP_A)
            else DBG_MATCH_HV_CONST( VMCS_IO_BITMAP_B)
            else DBG_MATCH_HV_CONST( VMCS_MSR_BITMAP)
            else DBG_MATCH_HV_CONST( VMCS_PAGE_FAULT_ERROR_CODE_MASK)
            else DBG_MATCH_HV_CONST( VMCS_PAGE_FAULT_ERROR_CODE_MATCH)
            else DBG_MATCH_HV_CONST( VMCS_PIN_BASED_EXEC_CONTROL)
            else DBG_MATCH_HV_CONST( VMCS_PROC_BASED_EXEC_CONTROL)
            else DBG_MATCH_HV_CONST( VMCS_PROC_BASED_EXEC_CONTROL_2)
            else DBG_MATCH_HV_CONST( VMCS_TPR_THRESHOLD)
            else DBG_MATCH_HV_CONST( VMCS_TSC_OFFSET)
            else DBG_MATCH_HV_CONST( VMCS_VIRTUAL_APIC_ADDR)
            else DBG_MATCH_HV_CONST( VMCS_VMX_PREEMPTION_TIMER)
            else DBG_MATCH_HV_CONST( VMCS_VM_ENTRY_CONTROL)
            else DBG_MATCH_HV_CONST( VMCS_VM_ENTRY_EVENT_INJECTION)
            else DBG_MATCH_HV_CONST( VMCS_VM_ENTRY_EXCEPTION_ERROR_CODE)
            else DBG_MATCH_HV_CONST( VMCS_VM_ENTRY_INSTRUCTION_LENGTH)
            else DBG_MATCH_HV_CONST( VMCS_VM_ENTRY_MSR_LOAD_ADDRESS)
            else DBG_MATCH_HV_CONST( VMCS_VM_ENTRY_MSR_LOAD_COUNT)
            else DBG_MATCH_HV_CONST( VMCS_VM_EXIT_CONTROL)
            else DBG_MATCH_HV_CONST( VMCS_VM_EXIT_INSTRUCTION_INFORMATION)
            else DBG_MATCH_HV_CONST( VMCS_VM_EXIT_INSTRUCTION_LENGTH)
            else DBG_MATCH_HV_CONST( VMCS_VM_EXIT_INTERRUPTION_ERROR_CODE)
            else DBG_MATCH_HV_CONST( VMCS_VM_EXIT_INTERRUPTION_INFORMATION)
            else DBG_MATCH_HV_CONST( VMCS_VM_EXIT_MSR_LOAD_ADDRESS)
            else DBG_MATCH_HV_CONST( VMCS_VM_EXIT_MSR_LOAD_COUNT)
            else DBG_MATCH_HV_CONST( VMCS_VM_EXIT_MSR_STORE_ADDRESS)
            else DBG_MATCH_HV_CONST( VMCS_VM_EXIT_MSR_STORE_COUNT)
            else DBG_MATCH_HV_CONST( VMCS_VM_EXIT_QUALIFICATION)
            else DBG_MATCH_HV_CONST( VMCS_VM_EXIT_REASON)
            else DBG_MATCH_HV_CONST( VMCS_VPID)
            // break the if else chain before the compiler goes kaboom
            DBG_MATCH_HV_CONST( EXIT_REASON_EXCEPTION_NMI)
            else DBG_MATCH_HV_CONST( EXIT_REASON_EXTERNAL_INTERRUPT)
            else DBG_MATCH_HV_CONST( EXIT_REASON_TRIPLE_FAULT)
            else DBG_MATCH_HV_CONST( EXIT_REASON_INIT)
            else DBG_MATCH_HV_CONST( EXIT_REASON_SIPI)
            else DBG_MATCH_HV_CONST( EXIT_REASON_SMI)
            else DBG_MATCH_HV_CONST( EXIT_REASON_OTHER_SMI)
            else DBG_MATCH_HV_CONST( EXIT_REASON_INTERRUPT_WINDOW)
            else DBG_MATCH_HV_CONST( EXIT_REASON_NMI_WINDOW)
            else DBG_MATCH_HV_CONST( EXIT_REASON_TASK_SWITCH)
            else DBG_MATCH_HV_CONST( EXIT_REASON_CPUID)
            else DBG_MATCH_HV_CONST( EXIT_REASON_GETSEC)
            else DBG_MATCH_HV_CONST( EXIT_REASON_HLT)
            else DBG_MATCH_HV_CONST( EXIT_REASON_INVD)
            else DBG_MATCH_HV_CONST( EXIT_REASON_INVLPG)
            else DBG_MATCH_HV_CONST( EXIT_REASON_RDPMC)
            else DBG_MATCH_HV_CONST( EXIT_REASON_RDTSC)
            else DBG_MATCH_HV_CONST( EXIT_REASON_RSM)
            else DBG_MATCH_HV_CONST( EXIT_REASON_VMCALL)
            else DBG_MATCH_HV_CONST( EXIT_REASON_VMCLEAR)
            else DBG_MATCH_HV_CONST( EXIT_REASON_VMLAUNCH)
            else DBG_MATCH_HV_CONST( EXIT_REASON_VMPTRLD)
            else DBG_MATCH_HV_CONST( EXIT_REASON_VMPTRST)
            else DBG_MATCH_HV_CONST( EXIT_REASON_VMREAD)
            else DBG_MATCH_HV_CONST( EXIT_REASON_VMRESUME)
            else DBG_MATCH_HV_CONST( EXIT_REASON_VMWRITE)
            else DBG_MATCH_HV_CONST( EXIT_REASON_VMOFF)
            else DBG_MATCH_HV_CONST( EXIT_REASON_VMON)
            else DBG_MATCH_HV_CONST( EXIT_REASON_CR_ACCESS)
            else DBG_MATCH_HV_CONST( EXIT_REASON_DR_ACCESS)
            else DBG_MATCH_HV_CONST( EXIT_REASON_IO_INSTRUCTION)
            else DBG_MATCH_HV_CONST( EXIT_REASON_MSR_READ)
            else DBG_MATCH_HV_CONST( EXIT_REASON_MSR_WRITE)
            else DBG_MATCH_HV_CONST( EXIT_REASON_INVALID_GUEST_STATE)
            else DBG_MATCH_HV_CONST( EXIT_REASON_MSR_LOADING)
            else DBG_MATCH_HV_CONST( EXIT_REASON_MWAIT_INSTRUCTION)
            else DBG_MATCH_HV_CONST( EXIT_REASON_MONITOR_TRAP_FLAG)
            else DBG_MATCH_HV_CONST( EXIT_REASON_MONITOR)
            else DBG_MATCH_HV_CONST( EXIT_REASON_PAUSE)
            else DBG_MATCH_HV_CONST( EXIT_REASON_MACHINE_CHECK)
            else DBG_MATCH_HV_CONST( EXIT_REASON_TPR_BELOW_THRESHOLD)
            else DBG_MATCH_HV_CONST( EXIT_REASON_APIC_ACCESS)
            else DBG_MATCH_HV_CONST( EXIT_REASON_VIRTUALIZED_EOI)
            else DBG_MATCH_HV_CONST( EXIT_REASON_GDTR_IDTR_ACCESS)
            else DBG_MATCH_HV_CONST( EXIT_REASON_LDTR_TR_ACCESS)
            else DBG_MATCH_HV_CONST( EXIT_REASON_EPT_VIOLATION)
            else DBG_MATCH_HV_CONST( EXIT_REASON_EPT_MISCONFIGURATION)
            else DBG_MATCH_HV_CONST( EXIT_REASON_INVEPT)
            else DBG_MATCH_HV_CONST( EXIT_REASON_RDTSCP)
            else DBG_MATCH_HV_CONST( EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED)
            else DBG_MATCH_HV_CONST( EXIT_REASON_INVVPID)
            else DBG_MATCH_HV_CONST( EXIT_REASON_WBINVD)
            else DBG_MATCH_HV_CONST( EXIT_REASON_XSETBV)
            else DBG_MATCH_HV_CONST( EXIT_REASON_APIC_WRITE)
            else DBG_MATCH_HV_CONST( EXIT_REASON_RDRAND)
            else DBG_MATCH_HV_CONST( EXIT_REASON_INVPCID)
            else DBG_MATCH_HV_CONST( EXIT_REASON_VMFUNC)
            else DBG_MATCH_HV_CONST( EXIT_REASON_RDSEED)
            else DBG_MATCH_HV_CONST( EXIT_REASON_XSAVES)
            else DBG_MATCH_HV_CONST( EXIT_REASON_XRSTORS)
            else if (InterpreterMatchToken(Input + consumed, Length - consumed, "gdt", &localTmp))
            {
                CPU_GDTR gdtr;
                consumed += localTmp;
            if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &localTmp)) {consumed += localTmp;}
                _sgdt(&gdtr);
                result = gdtr.Base; isValid = CX_TRUE;
            }
            else if (InterpreterMatchToken(Input + consumed, Length - consumed, "gdtbase", &localTmp))
            {
                CPU_GDTR gdtr;
                consumed += localTmp;
            if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &localTmp)) {consumed += localTmp;}
                _sgdt(&gdtr);
                result = gdtr.Base; isValid = CX_TRUE;
            }
            else if (InterpreterMatchToken(Input + consumed, Length - consumed, "gdtlimit", &localTmp))
            {
                CPU_GDTR gdtr;
                consumed += localTmp;
            if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &localTmp)) {consumed += localTmp;}
                _sgdt(&gdtr);
                result = gdtr.Limit; isValid = CX_TRUE;
            }
            else if (InterpreterMatchToken(Input + consumed, Length - consumed, "idt", &localTmp))
            {
            CPU_GDTR idtr;
            consumed += localTmp;
            if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &localTmp)) {consumed += localTmp;}
            __sidt(&idtr);
            result = idtr.Base; isValid = CX_TRUE;
            }
            else if (InterpreterMatchToken(Input + consumed, Length - consumed, "idtbase", &localTmp))
            {
            CPU_GDTR idtr;
            consumed += localTmp;
            if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &localTmp)) {consumed += localTmp;}
            __sidt(&idtr);
            result = idtr.Base; isValid = CX_TRUE;
            }
            else if (InterpreterMatchToken(Input + consumed, Length - consumed, "idtlimit", &localTmp))
            {
            CPU_GDTR idtr;
            consumed += localTmp;
            if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &localTmp)) {consumed += localTmp;}
            __sidt(&idtr);
            result = idtr.Limit; isValid = CX_TRUE;
            }
            else if (InterpreterMatchToken(Input + consumed, Length - consumed, "reason", &localTmp))
            {
            consumed += localTmp;
            if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &localTmp))
            {
                consumed += localTmp;
            }
            result = gHypervisorGlobalData.Guest[target.GuestIndex]->Vcpu[target.VcpuIndex]->CurrentExitReason;
            isValid = CX_TRUE;
            }
            else if (InterpreterMatchToken(Input + consumed, Length - consumed, "#cpu", &localTmp))
            {
            consumed += localTmp;
            if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &localTmp))
            {
                consumed += localTmp;
            }
            if (HvGetCurrentCpu())
            {
                isValid = CX_TRUE;
                result = HvGetCurrentCpu()->BootInfoIndex;
            }
            }
            else if (InterpreterMatchToken(Input + consumed, Length - consumed, "#guest", &localTmp))
            {
            consumed += localTmp;
            if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &localTmp))
            {
                consumed += localTmp;
            }
            if (HvGetCurrentVcpu() && HvGetCurrentVcpu()->Guest)
            {
                isValid = CX_TRUE;
                result = HvGetCurrentVcpu()->Guest->Index;
            }
            }
            else if (InterpreterMatchToken(Input + consumed, Length - consumed, "#vcpu", &localTmp))
            {
            consumed += localTmp;
            if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &localTmp))
            {
                consumed += localTmp;
            }
            if (HvGetCurrentVcpu() && HvGetCurrentVcpu()->Guest)
            {
                isValid = CX_TRUE;
                result = HvGetCurrentVcpu()->Guest->Index;
            }
            }
    }
#undef DBG_MATCH_CONST
#undef DBG_MATCH_HV_CONST

    if ((!isValid)&&(!Secure))
    {
        CX_INT64 tmp = 0;
        CX_UINT64 val = 0;
        if(_MatchVariableAssignment(Input + consumed, Length - consumed, &val, &tmp))
        {
            consumed += tmp;
            result = val;
            isValid = CX_TRUE;
        }
        else if(_MatchPrint(Input + consumed, Length - consumed, &val, &tmp))
        {
            consumed += tmp;
            result = val;
            isValid = CX_TRUE;
        }
    }

    if (!isValid) consumed = 0;

    // prepare the results
    if (ReturnValue)
    {
        if (negative) result = (CX_UINT64)(-((CX_INT64)result));
        *ReturnValue = result;
    }

    if (Consumed) *Consumed = consumed;
    if (isValid) DBGTRACE("Number matched, result=%p!\n", result);
    return isValid;
}

static
CX_UINT64
_PerformOperation(
    _In_ CX_UINT8 Operator,
    _In_ CX_UINT64 Op0,
    _In_ CX_UINT64 Op1
)
{
    CX_UINT64 result = (CX_UINT64)-1;

    switch (Operator)
    {
    case 0: DBGTRACE("INVALID OPERATION!\n"); break;
    case 1: result = Op0 + Op1; break;
    case 2: result = Op0 - Op1; break;
    case 3: result = Op0 * Op1; break;
    case 4: if (Op1 == 0) { DBGTRACE("DIVISION BY ZERO!\n"); }
          else { result = Op0 / Op1; } break;
    case 5: if (Op1 == 0) { DBGTRACE("DIVISION BY ZERO!\n"); }
          else { result = Op0 / Op1; } break;
    case 6: result = (Op0 == Op1); break;
    case 7: result = (Op0 != Op1); break;
    case 8: result = (Op0 < Op1); break;
    case 9: result = (Op0 > Op1); break;
    case 10: result = (Op0 <= Op1); break;
    case 11: result = (Op0 >= Op1); break;
    case 12: result = (Op0 << Op1); break;
    case 13: result = (Op0 >> Op1); break;
    case 14: result = (Op0 & Op1); break;
    case 15: result = (Op0 | Op1); break;
    case 16: result = (Op0 ^ Op1); break;
    case 17: result = (Op0 && Op1); break;
    case 18: result = (Op0 || Op1); break;
    case 19: result = (Op0 ? Op1 : 0); break;
    case 20: result = (Op0 ? Op0 : Op1); break;

    case 200: result = Op0; break;
    case 201: result = (CX_UINT64)(0 - Op0); break;
    case 202: result = (!Op0); break;
    case 203: result = (~Op0); break;
    }
    return result;
};

static
CX_BOOL
_MatchNumericTerm(
    _In_ CHAR *Input,
    _In_ CX_INT64 Length,
    __out_opt CX_UINT64 *Value,
    __out_opt CX_INT64 *Consumed,
    _In_ CX_BOOL Secure         // disable advanced features that are unsecure on external input
)
{
    CX_INT64 consumed, tmp;
    CX_UINT64 v;
    CX_BOOL matched = CX_FALSE;

    consumed = 0;
    // accept (expression)
    if ((Length > 0) && (Input[0] == '('))
    {
        consumed++;

        InterpreterMatchSpaces(Input + consumed, Length - consumed, &tmp);
        consumed += tmp;

        if (InterpreterMatchNumericExpression(Input + consumed, Length - consumed, &v, &tmp, Secure))
        {
            consumed += tmp;

            InterpreterMatchSpaces(Input + consumed, Length - consumed, &tmp);
            consumed += tmp;
            if ((consumed < Length) && (Input[consumed] == ')'))
            {
                consumed++;
                matched = CX_TRUE;
            }
        }
    }
    else
        // accept a simple number or constant or whatever 'terminal' numbers are supported
    {
        matched = _MatchNumber(Input, Length, &v, &consumed, Secure);
        if (matched)
        {
            // check for [num(:num)?] postfix operator
            CX_INT64 postfix = consumed;

            InterpreterMatchSpaces(Input + postfix, Length - postfix, &tmp); postfix += tmp;

            if (postfix < Length && Input[postfix] == '[')
            {
                CX_BOOL hasmsb = CX_FALSE, haslsb = CX_FALSE;
                CX_UINT64 msb = 0, lsb = 0;

                postfix++; // skip [

                InterpreterMatchSpaces(Input + postfix, Length - postfix, &tmp);
                postfix += tmp;

                if (_MatchNumber(Input + postfix, Length - postfix, &msb, &tmp, Secure))
                {
                    postfix += tmp;
                    hasmsb = CX_TRUE;
                    // got a base bit index, check for : number

                    InterpreterMatchSpaces(Input + postfix, Length - postfix, &tmp); postfix += tmp;

                    if (postfix < Length && Input[postfix] == ':')
                    {
                        postfix++; // skip :

                        InterpreterMatchSpaces(Input + postfix, Length - postfix, &tmp); postfix += tmp;

                        if (_MatchNumber(Input + postfix, Length - postfix, &lsb, &tmp, Secure))
                        {
                            postfix += tmp;
                            haslsb = CX_TRUE;
                        }
                    }
                    // check for closing ]
                    InterpreterMatchSpaces(Input + postfix, Length - postfix, &tmp);
                    postfix += tmp;

                    if (postfix < Length && Input[postfix] == ']')
                    {
                        postfix++;

                        lsb = haslsb ? lsb : msb;
                        if (msb < lsb)
                        {
                            // msb <-> lsb
                            msb ^= lsb; lsb ^= msb; msb ^= lsb;
                        }
                        msb %= 64;
                        lsb %= 64;
                        v = (v >> lsb) & ((1 << (msb - lsb + 1)) - 1);
                        consumed = postfix;
                    }
                }
            }
        }
    }

    if (Consumed) *Consumed = consumed;
    if (Value) *Value = v;
    return matched;
}

static
CX_BOOL
_MatchPrefixExpression(
    _In_ CHAR *Input,
    _In_ CX_INT64 Length,
    __out_opt CX_UINT64 *Value,
    __out_opt CX_INT64 *Consumed,
    _In_ CX_BOOL Secure         // disable advanced features that are unsecure on external input
)
{
    // skip spaces
    CX_INT64 consumed, tmp;
    CX_UINT8 op = 0;
    CX_UINT64 value;
    CX_BOOL matched;

    value = 0;
    matched = CX_FALSE;
    consumed = 0;

    if (Length > 0)
    {
        consumed++;
        switch (Input[0])
        {
        case '+': op = 200; break;
        case '-': op = 201; break;
        case '!': op = 202; break;
        case '~': op = 203; break;
        default: consumed--;
        }
        if (consumed)
        {
            InterpreterMatchSpaces(Input + consumed, Length - consumed, &tmp);
            consumed += tmp;
        }
    }

    if (_MatchNumericTerm(Input + consumed, Length - consumed, &value, &tmp, Secure))
    {
        if (op) value = _PerformOperation(op, value, 0);
        consumed += tmp;
        matched = CX_TRUE;
    }

    if (!matched) value = 0;
    if (Consumed) *Consumed = consumed;
    if (Value) *Value = value;
    return matched;
}

// support 64 distinct operators (+64 of their  operands) in a single expression stack
// [actual needed stack size = (2*number of distinct precedence levels) (+ 1 which is not pushed but kept in a variable)]
#define DBG_STK_SIZE 128

static
CX_BOOL
_MatchBinaryExpression(
    _In_ CHAR *Input,
    _In_ CX_INT64 Length,
    __out_opt CX_UINT64 *Value,
    __out_opt CX_INT64 *Consumed,
    _In_ CX_BOOL Secure         // disable advanced features that are unsecure on external input
)
{
    CX_UINT8 OperatorPriority[] =
    {
        255 - 255,  // 0  no operator -- 0
        255 - 1,    // 1  +
        255 - 1,    // 2  -
        255 - 0,    // 3  *
        255 - 0,    // 4  /
        255 - 0,    // 5  %
        255 - 4,    // 6  ==
        255 - 4,    // 7  !=
        255 - 3,    // 8  <
        255 - 3,    // 9  >
        255 - 3,    // 10 <=
        255 - 3,    // 11 >=
        255 - 2,    // 12 <<
        255 - 2,    // 13 >>
        255 - 5,    // 14 &
        255 - 7,    // 15 |
        255 - 6,    // 16 ^
        255 - 8,    // 17 &&
        255 - 9,    // 18 || -- 18
        255 - 10,   // 19 and
        255 - 11,   // 20 or -- 20
    };

    CX_UINT8 operation;
    CX_UINT64 v;
    CX_INT64 tmp, consumed;
    CX_UINT64 stk[DBG_STK_SIZE];
    CX_UINT8 idx = 0;
    CX_BOOL matched, expectOperand;

    consumed = 0;
    matched = CX_FALSE;
    expectOperand = CX_TRUE;
    do
    {
        //
        // SHIFT: get an operand
        //
        if (_MatchPrefixExpression(Input + consumed, Length - consumed, &v, &tmp, Secure))
        {
            matched = CX_TRUE; // if we have at least one numeric operand we've got a match
            consumed += tmp;
            // always insert to stack the values
            if (idx >= DBG_STK_SIZE)
            {
                matched = CX_FALSE;
                ERROR("Evaluation aborted, the expression is too complex (evaluator stack was depleated)\n");
                goto fail;
            }

            stk[idx] = v;
            idx++;
        }
        else
        {
            goto done;
        }

        // skip spaces after the operand
        InterpreterMatchSpaces(Input + consumed, Length - consumed, &tmp);
        consumed += tmp;


        //
        // SHIFT: get the next operation
        //
        expectOperand = CX_FALSE;
        operation = 0;

        // try the 'long' operations first (not to commit to just a part of a longer one)
        if (consumed + 1 < Length)
        {
            CX_UINT16 w = (Input[consumed] << 8) + Input[consumed + 1];
            switch (w)
            {
            case '==': operation = 6; break;
            case '!=': operation = 7; break;
            case '<=': operation = 10; break;
            case '>=': operation = 11; break;
            case '<<': operation = 12; break;
            case '>>': operation = 13; break;
            case '&&': operation = 17; break;
            case '||': operation = 18; break;
            }
            // and consume the operation
            consumed += operation ? 2 : 0;
        }
        // try short operations
        if ((!operation) && (consumed < Length))
        {
            switch (Input[consumed])
            {
            case '+': operation = 1; break;
            case '-': operation = 2; break;
            case '*': operation = 3; break;
            case '/': operation = 4; break;
            case '%': operation = 5; break;
            case '<': operation = 8; break;
            case '>': operation = 9; break;
            case '&': operation = 14; break;
            case '|': operation = 15; break;
            case '^': operation = 16; break;
            }
            // consume the operation
            consumed += operation ? 1 : 0;
        }
        if (!operation)
        {
            if (InterpreterMatchToken(Input + consumed, Length - consumed, "and", &tmp))
            {
                operation = 19;
                consumed += tmp;
            }
            else if (InterpreterMatchToken(Input + consumed, Length - consumed, "or", &tmp))
            {
                operation = 20;
                consumed += tmp;
            }
        }
        if (operation)
        {
            // stack it if it has higher precedence, otherwise we need to reduce some top entries from the stack
            if ((idx < 3) || (OperatorPriority[stk[idx - 2]] < OperatorPriority[operation]))
            {
                if (idx >= DBG_STK_SIZE)
                {
                    matched = CX_FALSE;
                    ERROR("Evaluation aborted, the expression is too complex (evaluator stack was depleated)\n");
                    goto fail;
                }

                stk[idx] = operation;
                idx++;
            }
            else
            {
                // some higher precedence operations were stacked, reduce them
                while ((idx >= 3) && (OperatorPriority[stk[idx - 2]] >= OperatorPriority[operation]))
                {
                    CX_UINT64 left, op, right;
                    left = stk[idx - 3];
                    op = stk[idx - 2];
                    right = stk[idx - 1];
                    stk[idx - 3] = _PerformOperation((CX_UINT8)op, left, right);
                    idx -= 2;
                }

                // now we can add the newly encountered operation (there is room as we freed at least one entry)
                stk[idx] = operation;
                idx++;
            }

            // skip spaces after an operation
            InterpreterMatchSpaces(Input + consumed, Length - consumed, &tmp);
            consumed += tmp;
            expectOperand = CX_TRUE;
        }
    } while (expectOperand);

done:
    if (expectOperand) matched = CX_FALSE;

    //
    // reduce any remaining operations to be performed
    //
    while (idx >= 3)
    {
        CX_UINT64 left, op, right;
        left = stk[idx - 3];
        op = stk[idx - 2];
        right = stk[idx - 1];
        stk[idx - 3] = _PerformOperation((CX_UINT8)op, left, right);
        idx -= 2;
    }
    if (Value) *Value = stk[0];

fail:
    if (Consumed) *Consumed = consumed;
    return matched;
#undef DBG_STK_SIZE
}

static
CX_BOOL
_MatchVariableName(
    _In_ CHAR *Input,
    _In_ CX_INT64 Length,
    __out_opt CX_INT64 *Consumed
)
//
// parse [a-zA-Z_][a-zA-Z_0-9]* characters found at the beginning of Input
//
{
    CX_INT64 consumed = 0, i = 0, reservedKeywordLength = 0, n = 0;
    if (( Input) && (Length >= 0))
    {
        if (((Input[0] >= 'a') && (Input[0] <= 'z'))||
            ((Input[0] >= 'A') && (Input[0] <= 'Z'))||
            (Input[0] == '_')
            )
        {
            consumed++;
            while ((CX_INT64)consumed < Length)
            {
                if (((Input[consumed] >= 'a') && (Input[consumed] <= 'z'))||
                    ((Input[consumed] >= 'A') && (Input[consumed] <= 'Z'))||
                    (Input[consumed] == '_') ||
                    ((Input[consumed] >= '0') && (Input[consumed] <= '9')))
                {
                    consumed++;
                }
                else
                {
                    break;
                }
            }
        }
    }

    if(consumed > 0)
    {
        n = ARRAYSIZE(InterpreterGlobals.ReservedKeywords);
        for(i = 0; i < n; i++)
        {
            reservedKeywordLength = CX_MIN(sizeof(InterpreterGlobals.ReservedKeywords[i]), consumed);
            if(0 == memcmp(InterpreterGlobals.ReservedKeywords[i], Input, reservedKeywordLength))
            {
                consumed = 0;
                break;
            }
        }
    }

    if (Consumed) *Consumed = consumed;
    if (consumed != 0) DBGTRACE("Symbol matched!\n");
    return consumed != 0;
}

static
CX_STATUS
_UnquoteString(
    _In_ CHAR *Input,
    _Out_ CHAR **Output,
    _In_opt_ CX_SIZE_T MaxCharacterCount
)
{
    CX_STATUS status;
    CHAR *string;
    CX_SIZE_T len;

    status = CX_STATUS_UNINITIALIZED_STATUS_VALUE;
    string = CX_NULL;

    if (!Input)
    {
        status = CX_STATUS_INVALID_PARAMETER_1;
        goto cleanup;
    }
    if (!Output)
    {
        status = CX_STATUS_INVALID_PARAMETER_2;
        goto cleanup;
    }

    len = strlen(Input);
    if ((MaxCharacterCount > 0) && (MaxCharacterCount < len))
    {
        len = MaxCharacterCount;
    }

    status = HpAllocWithTagCore((CX_VOID **)&string, (CX_UINT32) len+1, TAG_DBG);
    if (!CX_SUCCESS(status))
    {
        LOG_FUNC_FAIL("HpAllocWithTagCore", status);
        goto cleanup;
    }
    memset(string, 0, len + 1);

    // extract string from "string"
    if (Input[0] == '"')
    {
        memcpy(string, Input + 1, len - 1);

        size_t stringLength = strlen(string);
        if (stringLength > 0 && string[stringLength - 1] == '"') string[stringLength - 1] = 0;
    }
    else
    {
        memcpy(string, Input, len);
    }

    status = CX_STATUS_SUCCESS;

cleanup:
    if (Output) *Output = string;
    return status;
}

static
CX_BOOL
_FreeUnquotedString(
    _In_ CHAR **String
)
{
    return (CX_SUCCESS(HpFreeAndNullWithTag(String, TAG_DBG)));
}

static
CX_BOOL
_SwitchVmcs(
    _In_ CX_UINT64 NewPa,
    __out_opt CX_UINT64 *OldPa
)
{
    CX_UINT64 tmp;
    __vmx_vmptrst(&tmp);
    if (OldPa) *OldPa = tmp;
    tmp = NewPa;
    return (0 == __vmx_vmptrld(&tmp));
}

static
CX_BOOL
_MatchCommandName(
    _In_ CHAR *Input,
    _In_ CX_INT64 Length,
    __out_opt CX_UINT64 *CommandId,
    __out_opt CX_INT64 *Consumed
)
//
// Match a known command name
//
{
    CX_UINT64 commandId = 0xFFFFFFFFFFFFFFFF;
    CX_INT64 consumed = 0;
    CX_UINT32 i;

    DBGTRACE("number of possible commands: %d\n", DBG_NUMBER_OF_COMMANDS);

    for (i = 0; i < DBG_NUMBER_OF_COMMANDS; i++)
    {
        if (InterpreterMatchToken(Input, Length, DbgCommands[i].Name, &consumed))
        {
            commandId = i;
            break;
        }
    }
    if (CommandId) *CommandId = commandId;
    if (Consumed) *Consumed = consumed;
    return (consumed != 0);
}

static
CX_BOOL
_MatchVcpuTarget(
    _In_ CHAR *Input,
    _In_ CX_INT64 Length,
    __out_opt DBG_PARAM_VCPUTARGET *Target,
    __out_opt CX_INT64 *Consumed
)
//
// Match a "#GUEST.VCPU", with no white spaces, where guest and vcpu are numeric expressions
//
{
    CX_INT64 consumed, tmp = 0;
    DBG_PARAM_VCPUTARGET target;
    CX_BOOL matched = CX_FALSE;

    target = DbgDefaultParams.VcpuTarget;

    consumed = 0;

    // "#GUEST.VCPU" with no white spaces, guest and vcpu are numeric expressions
    if (InterpreterMatchToken(Input, Length, "#", &consumed))
    {
        if (InterpreterMatchNumericExpression(Input + consumed, Length - consumed, &(target.GuestIndex), &tmp, CX_FALSE))
        {
            consumed += tmp;
            if (InterpreterMatchToken(Input + consumed, Length - consumed, ".", &tmp))
            {
                consumed += tmp;
                if (InterpreterMatchNumericExpression(Input + consumed, Length - consumed, &(target.VcpuIndex), &tmp, CX_FALSE))
                {
                    consumed += tmp;
                    matched = CX_TRUE;
                }
            }
        }
    }

    // make sure the given vcpu target exists and can be accessed
    if (matched)
    {
        CX_STATUS status;
        status = InterpreterValidateVcpuTarget(&target);    // this will validate and also refresh the .Vcpu pointer
        if (CX_STATUS_SUCCESS != status)
        {
            consumed = 0;
            matched = CX_FALSE;
        }
    }

    // prepare the results
    if (Consumed) *Consumed = consumed;
    if (Target) *Target = target;
    if (matched) DBGTRACE("VCPUTARGET matched!\n");
    return matched;
}

static
CX_BOOL
_MatchMemTarget(
    _In_ CHAR *Input,
    _In_ CX_INT64 Length,
    __out_opt DBG_PARAM_MEMTARGET *Target,
    __out_opt CX_INT64 *Consumed
)
//
// match "#h(.v)|(.p)" or "#guest.vcpu(.v)|(.p)" where guest and vcpu are numeric expressions
//
{
    DBG_PARAM_MEMTARGET target = {{0, 0}, CX_FALSE, CX_FALSE};
    CX_INT64 consumed = 0;
    CX_INT64 tmp = 0;
    CX_BOOL matched = CX_FALSE;
    CX_BOOL cpuMatched = CX_FALSE;

    // first, try to get the cpu specification
    if (_MatchVcpuTarget(Input, Length, &(target.VcpuTarget), &consumed))
    {
        target.IsHostNotGuest = CX_FALSE;
        cpuMatched = CX_TRUE;
    }
    // else check for #h if a host address is being used
    else if (InterpreterMatchToken(Input, Length, "#h", &consumed))
    {
        cpuMatched = CX_TRUE;
        target.IsHostNotGuest = CX_TRUE;
    }


    // and then a .v or .p for virtual/physical
    if (cpuMatched)
    {
        if (InterpreterMatchToken(Input + consumed, Length - consumed, ".v", &tmp))
        {
            consumed += tmp;
            target.IsPhysicalNotVirtual = CX_FALSE;
            matched = CX_TRUE;
        }
        else if (InterpreterMatchToken(Input + consumed, Length - consumed, ".p", &tmp))
        {
            consumed += tmp;
            target.IsPhysicalNotVirtual = CX_TRUE;
            matched = CX_TRUE;
        }
    }

    // return the results
    if (Consumed) *Consumed = consumed;

    if (Target) *Target = target;
    if (matched) DBGTRACE("MEMTARGET matched!\n");
    return matched;
}

static
CX_BOOL
_MatchMemRange(
    _In_ CHAR *Input,
    _In_ CX_INT64 Length,
    __out_opt DBG_PARAM_MEMRANGE *Range,
    __out_opt CX_INT64 *Consumed
)
{
    DBG_PARAM_MEMRANGE range = {0};
    CX_INT64 consumed = 0;
    CX_INT64 tmp = 0;
    CX_BOOL matched = CX_FALSE;

    // get the address
    if (InterpreterMatchNumericExpression(Input, Length, &(range.Address), &consumed, CX_FALSE))
    {
        // skip spaces
        if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &tmp))
        {
            consumed += tmp;
        }
        // get the range part
        if (InterpreterMatchNumericExpression(Input + consumed, Length - consumed, &(range.Size), &tmp, CX_FALSE))
        {
            consumed += tmp;
            matched = CX_TRUE;
        }
        else
        {
            range.Size = CX_PAGE_SIZE_4K;
            matched = CX_TRUE;
            range.UnspecifiedSize = CX_TRUE;
        }
    }

    // return values
    if (!matched) consumed = 0;
    if (Consumed) *Consumed = consumed;
    if (Range) *Range = range;
    if (matched) DBGTRACE("MEMRANGE matched!\n");
    return matched;
};

static
CX_BOOL
_MatchTargetRange(
    _In_ CHAR *Input,
    _In_ CX_INT64 Length,
    __out_opt DBG_PARAM_MEMTARGET *Target,
    __out_opt DBG_PARAM_MEMRANGE *Range,
    __out_opt CX_INT64 *Consumed
)
//
// Optionally match a memory target (use default if not given) followed by a memory range
//
{
    DBG_PARAM_MEMTARGET target = DbgDefaultParams.MemTarget;
    DBG_PARAM_MEMRANGE range = {0};
    CX_INT64 consumed = 0;
    CX_INT64 tmp = 0;
    CX_BOOL matched = CX_FALSE;

    // get the target (optional)
    if (_MatchMemTarget(Input, Length, &target, &tmp))
    {
        // commit
        consumed += tmp;

        // skip spaces
        if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &tmp))
        {
            consumed += tmp;
        }
    }

    if (_MatchMemRange(Input + consumed, Length - consumed, &range, &tmp))
    {
        consumed += tmp;
        matched = CX_TRUE;
    }

    // return values
    if (!matched) consumed = 0;
    if (Consumed) *Consumed = consumed;
    if (Range) *Range = range;
    if (Target) *Target = target;
    if (matched) DBGTRACE("TARGETRANGE matched!\n");
    return matched;
};

static
CX_BOOL
_MatchAssignment(
    _In_ CHAR *Input,
    _In_ CX_INT64 Length,
    __out_opt CX_INT64 *Consumed,
    _Out_ CX_UINT64 *Value
)
//
// Returns true if assignment was found
//
{
    CX_INT64 consumed = 0, tmp = 0;
    CX_BOOL status = CX_FALSE;

    if(!Input)
    {
        status = CX_FALSE;
        goto cleanup;
    }

    if(0 == Length)
    {
        status = CX_FALSE;
        goto cleanup;
    }

    if(!Value)
    {
        status = CX_FALSE;
        goto cleanup;
    }

    if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &tmp)) consumed += tmp;

    if(InterpreterMatchToken(Input + consumed, Length - consumed, "=", &tmp))
    {
        consumed += tmp;
    }
    else
    {
        status = CX_FALSE;
        goto cleanup;
    }

    if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &tmp)) consumed += tmp;

    if(InterpreterMatchNumericExpression(Input + consumed, Length - consumed, Value, &tmp, CX_FALSE))
    {
        consumed += tmp;
    }
    else
    {
        status = CX_FALSE;
        goto cleanup;
    }

    if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &tmp)) consumed += tmp;

    if (InterpreterMatchToken(Input + consumed, Length - consumed, ";", &tmp)) consumed += tmp;

    status = CX_TRUE;
cleanup:
    if (Consumed) *Consumed = consumed;

    return status;
}

static
CX_BOOL
_MatchWhile(
    _In_ CHAR *Input,
    _In_ CX_INT64 Length,
    __out_opt CX_INT64 *Consumed
)
//
// Returns true if statement was found
//
{
    CX_INT64 consumed = 0, tmp = 0, sizeOfExpressionToEvaluate = 0, sizeOfStatementsToIterate = 0;
    CX_UINT64 val = 0;
    CHAR *expressionToEvaluate = CX_NULL, *statementsToIterate = CX_NULL;
    CX_BOOL status = CX_FALSE, performOperation;

    if(!Input)
    {
        status = CX_FALSE;
        goto cleanup;
    }

    if(0 == Length)
    {
        status = CX_FALSE;
        goto cleanup;
    }

    if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &tmp)) consumed += tmp;

    if(InterpreterMatchToken(Input + consumed, Length - consumed, "while", &tmp))
    {
        consumed += tmp;
    }
    else
    {
        status = CX_FALSE;
        goto cleanup;
    }

    if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &tmp)) consumed += tmp;

    if(InterpreterMatchNumericExpression(Input + consumed, Length - consumed, &val, &tmp, CX_FALSE))
    {
        expressionToEvaluate = Input + consumed;
        sizeOfExpressionToEvaluate = tmp;
        consumed += tmp;
    }
    else
    {
        status = CX_FALSE;
        goto cleanup;
    }

    performOperation = InterpreterGlobals.PerformOperation;
    InterpreterGlobals.PerformOperation = CX_FALSE;
    if(_MatchBlock(Input + consumed, Length - consumed, &tmp))
    {
        statementsToIterate = Input + consumed;
        sizeOfStatementsToIterate = tmp;
        consumed += tmp;
    }
    else
    {
        InterpreterGlobals.PerformOperation = performOperation;
        status = CX_FALSE;
        goto cleanup;
    }
    InterpreterGlobals.PerformOperation = performOperation;


    while(0 != val)
    {
        if(!_MatchBlock(statementsToIterate, sizeOfStatementsToIterate, CX_NULL))
        {
            status = CX_FALSE;
            goto cleanup;
        }
        if(!InterpreterMatchNumericExpression(expressionToEvaluate, sizeOfExpressionToEvaluate, &val, CX_NULL, CX_FALSE))
        {
            status = CX_FALSE;
            goto cleanup;
        }
    }

    status = CX_TRUE;
cleanup:
    if (Consumed) *Consumed = consumed;

    return status;
}

static
CX_BOOL
_MatchIf(
    _In_ CHAR *Input,
    _In_ CX_INT64 Length,
    __out_opt CX_INT64 *Consumed
)
//
// Returns true if 'if statement' was found
//
{
    CX_INT64 consumed = 0, tmp = 0, sizeOfExpressionToEvaluate = 0, sizeOfStatementsToIterate = 0;
    CX_UINT64 val = 0;
    CHAR *expressionToEvaluate = CX_NULL, *statementsToIterate = CX_NULL;
    CX_BOOL status = CX_FALSE, performOperation;

    if(!Input)
    {
        status = CX_FALSE;
        goto cleanup;
    }

    if(0 == Length)
    {
        status = CX_FALSE;
        goto cleanup;
    }

    if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &tmp)) consumed += tmp;

    if(InterpreterMatchToken(Input + consumed, Length - consumed, "if", &tmp))
    {
        consumed += tmp;
    }
    else
    {
        status = CX_FALSE;
        goto cleanup;
    }

    if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &tmp)) consumed += tmp;

    if(InterpreterMatchNumericExpression(Input + consumed, Length - consumed, &val, &tmp, CX_FALSE))
    {
        expressionToEvaluate = Input + consumed;
        sizeOfExpressionToEvaluate = tmp;
        consumed += tmp;
    }
    else
    {
        status = CX_FALSE;
        goto cleanup;
    }

    performOperation = InterpreterGlobals.PerformOperation;
    InterpreterGlobals.PerformOperation = CX_FALSE;
    if(_MatchBlock(Input + consumed, Length - consumed, &tmp))
    {
        statementsToIterate = Input + consumed;
        sizeOfStatementsToIterate = tmp;
        consumed += tmp;
    }
    else
    {
        InterpreterGlobals.PerformOperation = performOperation;
        status = CX_FALSE;
        goto cleanup;
    }
    InterpreterGlobals.PerformOperation = performOperation;


    if(0 != val)
    {
        if(!_MatchBlock(statementsToIterate, sizeOfStatementsToIterate, CX_NULL))
        {
            status = CX_FALSE;
            goto cleanup;
        }
    }

    if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &tmp)) consumed += tmp;

    if(InterpreterMatchToken(Input + consumed, Length - consumed, "else", &tmp))
    {
        consumed += tmp;
    }
    else
    {
        status = CX_TRUE;
        goto cleanup;
    }

    if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &tmp)) consumed += tmp;

    performOperation = InterpreterGlobals.PerformOperation;
    InterpreterGlobals.PerformOperation = CX_FALSE;
    if(_MatchBlock(Input + consumed, Length - consumed, &tmp))
    {
        statementsToIterate = Input + consumed;
        sizeOfStatementsToIterate = tmp;
        consumed += tmp;
    }
    else
    {
        InterpreterGlobals.PerformOperation = performOperation;
        status = CX_FALSE;
        goto cleanup;
    }
    InterpreterGlobals.PerformOperation = performOperation;



    if(0 == val)            //we are on the else branch
    {
        if(!_MatchBlock(statementsToIterate, sizeOfStatementsToIterate, CX_NULL))
        {
            status = CX_FALSE;
            goto cleanup;
        }
    }



    status = CX_TRUE;
cleanup:
    if (Consumed) *Consumed = consumed;

    return status;
}

static
CX_BOOL
_MatchPrint(
    _In_ CHAR *Input,
    _In_ CX_INT64 Length,
    _In_ CX_UINT64 *Result,
    __out_opt CX_INT64 *Consumed
)
//
// Returns true if print statement was found
//
{
    CX_INT64 consumed = 0, tmp = 0;
    CX_UINT64 val = 0;
    CX_BOOL status = CX_FALSE;

    if(!Input)
    {
        status = CX_FALSE;
        goto cleanup;
    }

    if(0 == Length)
    {
        status = CX_FALSE;
        goto cleanup;
    }

    if(!Result)
    {
        status  = CX_FALSE;
        goto cleanup;
    }

    if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &tmp)) consumed += tmp;

    if(InterpreterMatchToken(Input + consumed, Length - consumed, "print", &tmp))
    {
        CX_BOOL first, ok;
        consumed += tmp;


        first = 1;
        do
        {
            ok = 0;
            if (InterpreterMatchSpaces(Input+consumed, Length - consumed, &tmp))
            {
                consumed += tmp;
            }
            if ((!first) && (InterpreterMatchToken(Input + consumed, Length - consumed, ",", &tmp)))
            {
                consumed += tmp;
                if (InterpreterMatchSpaces(Input+consumed, Length - consumed, &tmp))
                {
                    consumed += tmp;
                }
            }

            if(InterpreterMatchNumericExpression(Input + consumed, Length - consumed, &val, &tmp, CX_FALSE))
            {
                consumed += tmp;
                *Result = val;
                if(InterpreterGlobals.PerformOperation)
                {
                    if (first)
                    {
                        LOGN("%p(%d)", *Result);
                        first = 0;
                    }
                    else
                    {
                        LOGN(", %p(%d)", *Result);
                    }
                }
                status = CX_TRUE;
                ok = 1;
            }
        } while (ok);
        if (InterpreterMatchToken(Input + consumed, Length - consumed, ";", &tmp))
        {
            consumed += tmp;
        }
        if (!first) LOGN("\n");
    }


cleanup:
    if (Consumed) *Consumed = consumed;

    return status;
}

static
CX_BOOL
_MatchUndef(
    _In_ CHAR *Input,
    _In_ CX_INT64 Length,
    __out_opt CX_INT64 *Consumed
)
//
// Returns true if undef statement was found
//undefines a variable or a function
//
{
    CX_INT64 consumed = 0, tmp = 0, variableNameLength = 0, variableIndex = 0, i = 0;
    CX_BOOL status = CX_FALSE, exists = CX_FALSE;
    CHAR variableName[MAX_LENGTH_FUNCTION_NAME] = {0};
    CX_STATUS ntStatus = CX_STATUS_UNINITIALIZED_STATUS_VALUE;

    if(!Input)
    {
        status = CX_FALSE;
        goto cleanup;
    }

    if(0 == Length)
    {
        status = CX_FALSE;
        goto cleanup;
    }


    if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &tmp)) consumed += tmp;

    if(InterpreterMatchToken(Input + consumed, Length - consumed, "undef", &tmp))
    {
        consumed += tmp;
    }
    else
    {
        status = CX_FALSE;
        goto cleanup;
    }

    if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &tmp)) consumed += tmp;

    if(_MatchVariableName(Input + consumed, Length - consumed, &tmp))
    {
        if(tmp < MAX_LENGTH_VAR_NAME)
        {
            variableNameLength = tmp;
            memcpy(variableName, Input + consumed, variableNameLength);

            consumed += tmp;

            for(variableIndex = 0; variableIndex < InterpreterGlobals.NumberOfVars + 1; variableIndex++)
            {
                if(0 == memcmp(InterpreterGlobals.DbgVars[variableIndex].Name, variableName, variableNameLength))
                {
                    exists = CX_TRUE;
                    if(!InterpreterGlobals.PerformOperation)
                    {
                        status = CX_TRUE;
                        goto cleanup;
                    }
                    break;
                }
            }


            for (i = variableIndex; i < InterpreterGlobals.NumberOfVars; i++)
            {
                InterpreterGlobals.DbgVars[i] = InterpreterGlobals.DbgVars[i + 1];
            }

            if(exists)
            {
                InterpreterGlobals.NumberOfVars--;
                status = CX_TRUE;
            }


            exists = CX_FALSE;
            for(variableIndex = 0; variableIndex < InterpreterGlobals.NumberOfFunctions + 1; variableIndex++)
            {
                if(0 == memcmp(InterpreterGlobals.DbgFunctions[variableIndex].Name, variableName, variableNameLength))
                {
                    exists = CX_TRUE;
                    if(!InterpreterGlobals.PerformOperation)
                    {
                        status = CX_TRUE;
                        goto cleanup;
                    }

                    ntStatus = HpFreeAndNullWithTag((CX_VOID **)&(InterpreterGlobals.DbgFunctions[variableIndex].Command), TAG_DBG);
                    if (!CX_SUCCESS(ntStatus))
                    {
                        LOG_FUNC_FAIL("HpFreeAndNullWithTag", ntStatus);    //we just log that we didn't deallocate the memory
                    }

                    break;
                }
            }

            for (i = variableIndex; i < InterpreterGlobals.NumberOfFunctions; i++)
            {
                InterpreterGlobals.DbgFunctions[i] = InterpreterGlobals.DbgFunctions[i + 1];
            }

            if(exists)
            {
                InterpreterGlobals.NumberOfFunctions--;
                status = CX_TRUE;
            }
        }
        else
        {
            status = CX_FALSE;
            goto cleanup;
        }
    }
    else
    {
        status = CX_FALSE;
        goto cleanup;
    }


cleanup:
    if (status)
    {
        if (InterpreterMatchToken(Input + consumed, Length - consumed, ";", &tmp)) consumed += tmp;
    }
    if (Consumed) *Consumed = consumed;

    return status;
}

static
CX_BOOL
_MatchStatement(
    _In_ CHAR *Input,
    _In_ CX_INT64 Length,
    __out_opt CX_INT64 *Consumed
)
//
// Returns true if statement was found
//
{
    CX_INT64 consumed = 0, tmp = 0;
    CX_BOOL status = CX_FALSE;

    if(!Input)
    {
        status = CX_FALSE;
        goto cleanup;
    }

    if(0 == Length)
    {
        status = CX_FALSE;
        goto cleanup;
    }


    if(_MatchWhile(Input + consumed, Length - consumed, &tmp))
    {
        consumed += tmp;
        status = CX_TRUE;
    }
    else if(_MatchIf(Input + consumed, Length - consumed, &tmp))
    {
        consumed += tmp;
        status = CX_TRUE;
    }
    else if(_MatchBlock(Input + consumed, Length - consumed, &tmp))
    {
        consumed += tmp;
        status = CX_TRUE;
    }
    else if(_MatchFunction(Input + consumed, Length - consumed, &tmp))
    {
        consumed += tmp;
        status = CX_TRUE;
    }
    else if(_MatchUndef(Input + consumed, Length - consumed, &tmp))
    {
        consumed += tmp;
        status = CX_TRUE;
    }

cleanup:
    if (Consumed) *Consumed = consumed;

    return status;
}

static
CX_BOOL
_MatchVariableAssignment(
    _In_ CHAR *Input,
    _In_ CX_INT64 Length,
    _Out_ CX_UINT64 *Result,
    __out_opt CX_INT64 *Consumed
)
{
    CX_INT64 tmp = 0, variableNameLength = 0, consumed = 0;
    CX_UINT32 variableIndex = 0, maxNumberOfVariables = ARRAYSIZE(InterpreterGlobals.DbgVars);
    CX_BOOL variableExists = CX_FALSE, status = CX_FALSE;
    CX_UINT64 val = 0;
    CHAR variableName[MAX_LENGTH_VAR_NAME] = {0};

    if(!Input)
    {
        status = CX_FALSE;
        goto cleanup;
    }
    if(0 == Length)
    {
        status = CX_FALSE;
        goto cleanup;
    }
    if(!Result)
    {
        status = CX_FALSE;
        goto cleanup;
    }

    if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &tmp)) consumed += tmp;

    if(_MatchVariableName(Input + consumed, Length - consumed, &tmp))
    {
        if(tmp < MAX_LENGTH_VAR_NAME)
        {
            variableNameLength = tmp;
            memcpy(variableName, Input + consumed, variableNameLength);
            for(variableIndex = 0; variableIndex < InterpreterGlobals.NumberOfVars + 1; variableIndex++)
            {
                if(0 == memcmp(InterpreterGlobals.DbgVars[variableIndex].Name, variableName, variableNameLength))
                {
                    break;
                }
            }
            if(variableIndex < InterpreterGlobals.NumberOfVars + 1) variableExists = CX_TRUE;

            consumed += tmp;

            if(_MatchAssignment(Input + consumed, Length - consumed, &tmp, &val))
            {
                consumed += tmp;
                if(!InterpreterGlobals.PerformOperation)
                {
                    status = CX_TRUE;     //don't create the variable, but match it as parsed and acknowledged
                }
                else if(variableExists)
                {
                    InterpreterGlobals.DbgVars[variableIndex].Value = val;
                }
                else if(InterpreterGlobals.NumberOfVars < maxNumberOfVariables)
                {
                    memcpy(InterpreterGlobals.DbgVars[InterpreterGlobals.NumberOfVars].Name, variableName, variableNameLength);
                    InterpreterGlobals.DbgVars[InterpreterGlobals.NumberOfVars].Value = val;
                    variableIndex = InterpreterGlobals.NumberOfVars;
                    variableExists = CX_TRUE;
                    InterpreterGlobals.NumberOfVars++;
                }
            }

            if(variableExists)
            {
                *Result = InterpreterGlobals.DbgVars[variableIndex].Value;
                status = CX_TRUE;
            }
        }
    }

cleanup:
    if (Consumed) *Consumed = consumed;

    return status;

}

static
CX_BOOL
_MatchFunction(
    _In_ CHAR *Input,
    _In_ CX_INT64 Length,
    __out_opt CX_INT64 *Consumed
)
//
// Returns true if a function was found
//
{
    CX_INT64 consumed = 0, tmp = 0;
    CX_INT64 functionIndex = 0, functionNameLength = 0, commandLength = 0;
    CX_UINT32 maxNumberOfFunctions = ARRAYSIZE(InterpreterGlobals.DbgFunctions);
    CX_BOOL status = CX_FALSE;
    CHAR functionName[MAX_LENGTH_FUNCTION_NAME] = {0}, *blockPointer = CX_NULL;
    CX_BOOL functionExists = CX_FALSE, performOperation;
    CX_STATUS ntStatus = CX_STATUS_UNINITIALIZED_STATUS_VALUE;

    if(!Input)
    {
        status = CX_FALSE;
        goto cleanup;
    }

    if(0 == Length)
    {
        status = CX_FALSE;
        goto cleanup;
    }

    if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &tmp)) consumed += tmp;

    if(_MatchVariableName(Input + consumed, Length - consumed, &tmp))
    {
        if(tmp < MAX_LENGTH_VAR_NAME)
        {
            functionNameLength = tmp;
            memcpy(functionName, Input + consumed, functionNameLength);
            for(functionIndex = 0; functionIndex < InterpreterGlobals.NumberOfFunctions + 1; functionIndex++)
            {
                if(0 == memcmp(InterpreterGlobals.DbgFunctions[functionIndex].Name, functionName, functionNameLength))
                {
                    break;
                }
            }
            if (functionIndex < InterpreterGlobals.NumberOfFunctions + 1) functionExists = CX_TRUE;
            consumed += tmp;
        }
        else
        {
            status = CX_FALSE;
            goto cleanup;
        }
    }
    else
    {
        status = CX_FALSE;
        goto cleanup;
    }


    if(InterpreterMatchToken(Input + consumed, Length - consumed, ":=", &tmp))
    {
        consumed += tmp;

        if((InterpreterGlobals.NumberOfFunctions < maxNumberOfFunctions) || (functionExists))
        {
            performOperation = InterpreterGlobals.PerformOperation;
            InterpreterGlobals.PerformOperation = CX_FALSE;
            if(_MatchBlock(Input + consumed, Length - consumed, &tmp))
            {
                blockPointer = Input + consumed;
                commandLength = tmp;
                consumed += tmp;
            }
            else
            {
                InterpreterGlobals.PerformOperation = performOperation;
                status = CX_FALSE;
                goto cleanup;
            }
            InterpreterGlobals.PerformOperation = performOperation;

            if(!InterpreterGlobals.PerformOperation)
            {
                status = CX_TRUE;
                goto cleanup;
            }
            if(!functionExists)
            {
                functionIndex = InterpreterGlobals.NumberOfFunctions;
                ntStatus = HpAllocWithTagCore((CX_VOID **)&(InterpreterGlobals.DbgFunctions[functionIndex].Command), (CX_UINT32) commandLength + 1, TAG_DBG);
                if (!CX_SUCCESS(ntStatus))
                {
                    LOG_FUNC_FAIL("HpAllocWithTagCore", ntStatus);
                    status = CX_FALSE;
                    goto cleanup;
                }
            }
            else if(commandLength > InterpreterGlobals.DbgFunctions[functionIndex].Length)
            {
                ntStatus = HpFreeAndNullWithTag((CX_VOID **)&(InterpreterGlobals.DbgFunctions[functionIndex].Command), TAG_DBG);
                if (!CX_SUCCESS(ntStatus))
                {
                    LOG_FUNC_FAIL("HpFreeAndNullWithTag", ntStatus);
                    status = CX_FALSE;
                    goto cleanup;
                }
                ntStatus = HpAllocWithTagCore((CX_VOID **)&(InterpreterGlobals.DbgFunctions[functionIndex].Command), (CX_UINT32) commandLength + 1, TAG_DBG);
                if (!CX_SUCCESS(ntStatus))
                {
                    LOG_FUNC_FAIL("HpAllocWithTagCore", ntStatus);
                    status = CX_FALSE;
                    goto cleanup;
                }
            }


            memcpy(InterpreterGlobals.DbgFunctions[functionIndex].Name, functionName, functionNameLength);
            memcpy(InterpreterGlobals.DbgFunctions[functionIndex].Command, blockPointer, commandLength);
            InterpreterGlobals.DbgFunctions[functionIndex].Command[commandLength] = '\0'; //the string terminator
            InterpreterGlobals.DbgFunctions[functionIndex].Length = commandLength;

            if (!functionExists) InterpreterGlobals.NumberOfFunctions++;


            status = CX_TRUE;
        }
        else
        {
            status = CX_FALSE;
            goto cleanup;
        }
    }
    else if(functionExists)
    {
        if(InterpreterGlobals.PerformOperation)
        {
            CHAR *bufferCopy = CX_NULL;
            CX_INT64 bufferCopyLength;

            bufferCopyLength = InterpreterGlobals.DbgFunctions[functionIndex].Length;

            ntStatus = HpAllocWithTagCore((CX_VOID **)&(bufferCopy), (CX_UINT32) bufferCopyLength + 1, TAG_DBG);
            if (!CX_SUCCESS(ntStatus))
            {
                LOG_FUNC_FAIL("HpAllocWithTagCore", ntStatus);
                status = CX_FALSE;
                goto cleanup;
            }

            memcpy(bufferCopy, InterpreterGlobals.DbgFunctions[functionIndex].Command, bufferCopyLength + 1);
            if(!InterpreterMatchCommand(bufferCopy, bufferCopyLength, &tmp, CX_TRUE, CX_NULL))
            {
                LOGN("The function is invalid!, consumed: %d -->%s\n", tmp, bufferCopy);
            }

            ntStatus = HpFreeAndNullWithTag((CX_VOID **)&(bufferCopy), TAG_DBG);
            if (!CX_SUCCESS(ntStatus))
            {
                LOG_FUNC_FAIL("HpFreeAndNullWithTag", ntStatus);
                status = CX_FALSE;
                goto cleanup;
            }
        }
        if (InterpreterMatchToken(Input + consumed, Length - consumed, ";", &tmp)) consumed += tmp;

        status = CX_TRUE;
        goto cleanup;
    }
    else
    {
        status = CX_FALSE;
        goto cleanup;
    }

cleanup:
    if (Consumed) *Consumed = consumed;

    return status;
}

static
CX_BOOL
_MatchBlock(
    _In_ CHAR *Input,
    _In_ CX_INT64 Length,
    __out_opt CX_INT64 *Consumed
)
//
// Returns true if a block was found
//
{
    CX_INT64 consumed = 0, tmp = 0;
    CX_BOOL status = CX_FALSE, partialMatch = CX_FALSE;
    CX_UINT64 val = 0;

    if (!Input) return CX_FALSE;

    if (0 == Length) return CX_FALSE;

    if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &tmp)) consumed += tmp;

    if(InterpreterMatchToken(Input + consumed, Length - consumed, "{", &tmp))
    {
        consumed += tmp;
    }
    else
    {
        status = CX_FALSE;
        goto cleanup;
    }



    while(CX_TRUE)
    {
        partialMatch = CX_FALSE;
        if (InterpreterMatchSpaces(Input+consumed, Length - consumed, &tmp))
        {
            consumed += tmp;
        }

        if(InterpreterMatchNumericExpression(Input + consumed, Length - consumed, &val, &tmp, CX_FALSE))
        {
            consumed += tmp;
        }
        else if(_MatchStatement(Input + consumed, Length - consumed, &tmp))
        {
            consumed += tmp;
        }
        else
        {
            InterpreterMatchCommand(Input + consumed, Length - consumed, &tmp, CX_FALSE, &partialMatch);
            if(partialMatch)
            {
                consumed += tmp;
            }
            else
            {
                break;
            }
        }

        if (InterpreterMatchSpaces(Input + consumed, Length - consumed, &tmp)) consumed += tmp;

        if (InterpreterMatchToken(Input + consumed, Length - consumed, ";", &tmp)) consumed += tmp;
    }

    if(InterpreterMatchToken(Input + consumed, Length - consumed, "}", &tmp))
    {
        consumed += tmp;
    }
    else
    {
        return CX_FALSE;
    }


    status = CX_TRUE;
cleanup:
    if (Consumed) *Consumed = consumed;

    return status;
}
