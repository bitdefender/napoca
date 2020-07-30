/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _INTERPRETER_H_
#define _INTERPRETER_H_

#include "coredefs.h"
#include "base/cx_sal.h"
#include "base/cx_types.h"
#include "wrappers/cx_wintypes.h"

typedef struct _VCPU VCPU;

//
// Two bits are reserved for each distinct parameter type, encoding:
//   00 - this parameter is NOT ALLOWED in input
//   01 - this parameter is REQUIRED for the given command
//   10 - this parameter is OPTIONAL (can appear but matching continues without it)
//
// To add support for a new parameter type:
//   - write a production for it (parameter matcher function) which can recognize it and captures the corresponding associated data
//   - allocate storage for it in InterpreterMatchCommand
//   - add a new statement ("else if (0 != ...") at "/// TODO: add extraction of more parameter types"
//   - add code to free any allocated resources at "/// TODO: free any remaining resources that were allocated for the matched parameters"
//   - increment DBG_NUMBER_OF_PARAM_TYPES
//   - register the new param in DBG_PARAMS structure
//   - manage its default value (in InterpreterSetInterpretorSessionDefaults) so that any time a command is parsed DbgDefaultParams contains a good value
//   - add documentation to the DbgTypeDescriptions array
//

#define MAX_LENGTH_VAR_NAME         10
#define MAX_LENGTH_FUNCTION_NAME    10

#define DBG_TYPE_OPT(X)         ((X)<<1)                // mark a parameter as being optional

enum
{
    /// !!! MAKE SURE TO KEEP DbgTypeDescriptions in synch with these definitions !!!
    DBG_TYPE_VOID                   = 0,            // placeholder for no parameters

    // a char *, zero terminated parameter
    DBG_TYPE_SYMBOL                 = BIT(0),     // match a symbol name like literal
    DBG_TYPE_OPT_SYMBOL             = BIT(1),     // optionally match a symbol name like literal

    // a char *, zero terminated parameter
    DBG_TYPE_SYMBOL1                = BIT(2),     // match a symbol name like literal
    DBG_TYPE_OPT_SYMBOL1            = BIT(3),     // optionally match a symbol name like literal

    // a DBG_PARAM_MEMTARGET parameter
    DBG_TYPE_MEMTARGET              = BIT(4),     // match a guest+vcpu+pa/va statement
    DBG_TYPE_OPT_MEMTARGET          = BIT(5),     // optionally match a guest+vcpu+pa/va statement

    // a DBG_PARAM_MEMRANGE parameter
    DBG_TYPE_MEMRANGE               = BIT(6),     // match an address + length statement
    DBG_TYPE_OPT_MEMRANGE           = BIT(7),     // optionally match an address + length statement

    // a DBG_PARAM_TARGETRANGE parameter
    DBG_TYPE_TARGETRANGE            = BIT(8),     // match a guest+vcpu + memrange statement & transparently make it available
    DBG_TYPE_OPT_TARGETRANGE        = BIT(9),     // match a guest+vcpu + memrange statement & transparently make it available

    // a DBG_PARAM_VCPUTARGET parameter
    DBG_TYPE_VCPUTARGET             = BIT(10),     // match a guest+vcpu statement
    DBG_TYPE_OPT_VCPUTARGET         = BIT(11),     // optionally match a guest+vcpu statement

    // generic slots for numeric values, each such number uses a different slot
    DBG_TYPE_VALUE0                 = BIT(12),     // match a number
    DBG_TYPE_OPT_VALUE0             = BIT(13),     // optionally match a number
    DBG_TYPE_VALUE1                 = BIT(14),     // match a number,
    DBG_TYPE_OPT_VALUE1             = BIT(15),     // optionally match a number
    DBG_TYPE_VALUE2                 = BIT(16),     // match a number
    DBG_TYPE_OPT_VALUE2             = BIT(17),     // optionally match a number
    DBG_TYPE_VALUE3                 = BIT(18),     // match a number
    DBG_TYPE_OPT_VALUE3             = BIT(19),     // optionally match a number

    // a DBG_PARAM_VALUELIST parameter
    DBG_TYPE_VALUELIST              = BIT(20),     // generic list of numbers, separated by ','
    DBG_TYPE_OPT_VALUELIST          = BIT(21),      // optionally match a generic list of numbers, separated by ','

    //
    // how many parameter types do we have,
    // a max of 32 types are supported (TYPE and TYPE_OPT are considered same parser type)
    //
    DBG_NUMBER_OF_PARAM_TYPES       = ((21 + 1)/2)

};

//
// generic function callback type for command interpreters
//
typedef CX_STATUS (*DBG_INTERPRETER_CALLBACK) (CX_VOID*, ...);

//
// structure definition of a command
//
typedef struct _DBG_COMMAND
{
    CHAR        *Name;                          // command name (the first token which selects what operation is to be perfomed)
    CHAR        *Help;                          // basic help text which is automatically made available to the 'help' command
    CHAR        *Syntax;                        // can be CX_NULL, used for describing the parameters
    CX_UINT64   UsedParametersMask;             // combination of DBG_[OPT_]TYPE_* flags which defines what parameters the command needs
    DBG_INTERPRETER_CALLBACK Interpreter;       // your function that needs to be called
}DBG_COMMAND;

//
// structure definitions for standard parameter types
//
typedef struct _DBG_PARAM_VCPUTARGET
{
    CX_UINT64   GuestIndex;
    CX_UINT64   VcpuIndex;
    VCPU        *Vcpu;
} DBG_PARAM_VCPUTARGET; // ALWAYS use this parameter type when you need guest and vcpu indexes for a command

typedef struct _DBG_PARAM_MEMTARGET
{
    DBG_PARAM_VCPUTARGET    VcpuTarget;
    CX_BOOL                 IsHostNotGuest;
    CX_BOOL                 IsPhysicalNotVirtual;
} DBG_PARAM_MEMTARGET;   // ALWAYS use this type when your command can deal with guest/host and virtual/physical memory spaces

typedef struct _DBG_PARAM_MEMRANGE
{
    CX_UINT64   Address;
    CX_UINT64   Size;
    CX_BOOL     UnspecifiedSize;
} DBG_PARAM_MEMRANGE;     // ALWAYS use it to specify memory ranges so that the parser can perform validations

typedef struct _DBG_PARAM_TARGETRANGE
{
    CX_UINT64           Address;
    CX_UINT64           Size;
    DBG_PARAM_MEMTARGET OriginTarget;           // marks the source of this memory mapped range (mapped from where)
    DBG_PARAM_MEMRANGE  OriginRange;            // marks the source of this memory mapped range (mapped from where)
} DBG_PARAM_TARGETRANGE; // HV-VA for a given generic address

#pragma warning(disable:4200)   // disable zero-sized array in struct/union warning
typedef struct _DBG_PARAM_VALUELIST
{
    CX_UINT64 NumberOfValues;
    CX_UINT64 Values[];
} DBG_PARAM_VALUELIST;   // list of values separated by ','
#pragma warning(default:4200)   // set to default zero-sized array in struct/union warning

//
// Define a structure containing all parameter placeholders
//
typedef struct _DBG_PARAMS
{
    CHAR                    *Symbol;
    CHAR                    *Symbol1;
    DBG_PARAM_VCPUTARGET    VcpuTarget;
    DBG_PARAM_MEMTARGET     MemTarget;
    DBG_PARAM_MEMRANGE      MemRange;
    DBG_PARAM_TARGETRANGE   TargetRange;
    CX_UINT64               Value0;
    CX_UINT64               Value1;
    CX_UINT64               Value2;
    CX_UINT64               Value3;
    DBG_PARAM_VALUELIST     ValueList;
} DBG_PARAMS;

typedef struct _DBG_VARS
{
    CHAR        Name[MAX_LENGTH_VAR_NAME];
    CX_UINT64   Value;

} DBG_VARS;

typedef struct _DBG_FUNCTIONS
{
    CHAR        Name[MAX_LENGTH_FUNCTION_NAME];
    CX_INT64    Length;
    CHAR        *Command;
} DBG_FUNCTIONS;

typedef struct _DBG_PARAM_HELP
{
    CHAR *DisplayedName;
    CHAR *Description;
}DBG_PARAM_HELP;

//
// Basic scanning functions
//
CX_BOOL
InterpreterMatchSpaces(
    _In_        CHAR        *Input,
    _In_        CX_INT64    Length,
    __out_opt   CX_INT64    *Consumed
    );

CX_BOOL
InterpreterMatchToken(
    _In_        CHAR        *Input,
    _In_        CX_INT64    Length,
    _In_        CHAR        *Token,
    __out_opt   CX_INT64    *Consumed
    );

CX_BOOL
InterpreterMatchSymbol(
    _In_        CHAR        *Input,
    _In_        CX_INT64    Length,
    __out_opt   CX_INT64    *Consumed,
    __out_opt   CHAR        **SymbolInPlace,    // return the actual characters ignoring any decorators (like " for example), !NOT NULL-TERMINATED!
    __out_opt   CX_INT64    *SymbolLength       // the actual length without decorators
    );

CX_BOOL
InterpreterMatchNumericExpression(
    _In_        CHAR        *Input,
    _In_        CX_INT64    Length,
    __out_opt   CX_UINT64   *Value,
    __out_opt   CX_INT64    *Consumed,
    _In_        CX_BOOL     Secure              // disable advanced features that are unsecure on external input
    );

CX_BOOL
InterpreterMatchByteArray(
    _In_        CHAR        *Input,
    _In_        CX_INT64    Length,
    __out_opt   CX_UINT8    *Array,         // where to save the 'decoded' data
    _In_        CX_INT64    ArrayLength,    // how much storage space is available
    __out_opt   CX_INT64    *SavedEntries,  // how many entries were matched
    __out_opt   CX_INT64    *Consumed,
    _In_        CX_BOOL     Secure          // avoid advanced features that might be unsecure on external input data
    );

// Init routine for default values provided when optional parameters for commands are not specified
// can be called more than once (as many times as necessary / you like)
CX_STATUS
InterpreterSetInterpretorSessionDefaults(
    _In_opt_ VCPU *Vcpu
);

// Misc utility functions
CX_STATUS
InterpreterValidateVcpuTarget(
    _In_ DBG_PARAM_VCPUTARGET *Target
    );

// The start rule
CX_BOOL
InterpreterMatchCommand(
    _In_        CHAR        *Input,
    _In_        CX_INT64    Length,
    __out_opt   CX_INT64    *Consumed,
    _In_        CX_BOOL     Echo,
    __out_opt   CX_BOOL     *PartialMatch
    );

CX_BOOL
InterpreterMapAlienSpace(
    _In_ DBG_PARAM_MEMTARGET *Target,
    _In_ DBG_PARAM_MEMRANGE  *Range,
    __out_opt CX_VOID        **HvVa
);

CX_BOOL
InterpreterUnmapAlienSpace(
    _In_ DBG_PARAM_MEMTARGET *Target,
    _Inout_opt_ CX_VOID      **HvVa
);

#endif //_INTERPRETER_H_
