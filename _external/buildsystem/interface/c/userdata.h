/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

//
// This file is part of a (ASCII) parser for key=value specified variables used for retrieving configuration options exported by export.pl with "/format txt" option
//
#ifndef _USERDATA_H_
#define _USERDATA_H_

/*
Interfacing:
    - provide definitions for the required types in a H file and add to the compiler
        defines a symbol named USERDATA_TYPES_INCLUDE that expands to your H file
    - or, add compiler defines for the required symbols

required data types (or preprocessor symbols):
    - UD_NUMBER:        type used for counters, lengths etc, recommended unsigned
    - UD_SIZE_T:        native integer (unsigned) of the target platform
    - UD_BOOLEAN:       any integer type, only using zero or non-zero semantics
    - UD_TYPE_QWORD:    highest precision integer type (your option if signed or not)
    - UD_ASCII_STRING:  ascii-string type (char * most likely)
*/


#ifdef UD_TYPES_INCLUDE
#include UD_TYPES_INCLUDE
#endif


// any userdata compatible variable must belong to one of these types
typedef enum
{
    UD_TYPE_NONE,
    UD_TYPE_SIZE_T,
    UD_TYPE_QWORD,
    UD_TYPE_NUMBER,
    UD_TYPE_ASCII_STRING
} UD_TYPE, *PUD_TYPE;


// full description of the variable domain space (when using export.pl to C, you get an array of entries of this type)
typedef struct _UD_VAR_INFO
{
    UD_TYPE VariableType;
    UD_ASCII_STRING VariableName;
    void *VariableAddress;
    UD_NUMBER VariableSizeInBytes;
    UD_NUMBER VariableMetadataFlags;
}UD_VAR_INFO, *PUD_VAR_INFO;


// apply all assignments from a given text to a set of variables
UD_BOOLEAN
UdMatchSpaces(
    /*_In_*/        UD_ASCII_STRING Input,
    /*_In_*/        UD_NUMBER       Length,
    /*__out_opt*/   UD_NUMBER       *Consumed
    );
//
// Returns !=0 if spaces were found with Consumed = number of found whitespace bytes
//


UD_BOOLEAN
UdMatchToken(
    /*_In_*/        UD_ASCII_STRING Token,
    /*_In_*/        UD_ASCII_STRING Input,
    /*_In_*/        UD_NUMBER       Length,
    /*__out_opt*/   UD_NUMBER       *Consumed
    );
//
// Returns !=0 if the given token literal follows at Input with Consumed = number of consumed characters
//


UD_BOOLEAN
UdMatchNumber(
    /*_In_*/        UD_ASCII_STRING Input,
    /*_In_*/        UD_NUMBER       Length,
    /*__out_opt*/   UD_QWORD        *Var,
    /*__out_opt*/   UD_NUMBER       *Consumed
    );
//
// Match [+-]? (0[xX][0-9a-fA-F]+ | [0-9]+)
// Var is only set when a number has beeb successfully matched
//


UD_BOOLEAN
UdMatchString(
    /*_In_*/        UD_ASCII_STRING Input,
    /*_In_*/        UD_NUMBER       Length,
    /*__out_opt*/   UD_ASCII_STRING VarBuffer,
    /*_In_*/        UD_NUMBER       VarBufferSizeInBytes,
    /*_Out_*/       UD_NUMBER       *Consumed
    );
//
// match " ([^\\"]* | \\.)* " and keep the escaped content only (escaped here means the second character after \ -- that is, for \. it will only take the .)
// VarBuffer is filled-in only on a successful match
// a proper match implies VarBufferSizeInBytes is valid, no matter if VarBuffer is missing
//


UD_BOOLEAN
UdMatchNumericExpression(
    /*_In_*/        UD_ASCII_STRING Input,
    /*_In_*/        UD_NUMBER       Length,
    /*__out_opt*/   UD_QWORD        *Var,
    /*__out_opt*/   UD_NUMBER       *Consumed
    );
//
// Placeholder (not fully implemented), currently supports matching plain decimal and hexadecimal numbers only
//


UD_BOOLEAN
UdMatchAsciiStringExpression(
    /*_In_*/        UD_ASCII_STRING Input,
    /*_In_*/        UD_NUMBER       Length,
    /*__out_opt*/   UD_ASCII_STRING VarBuffer,
    /*_In_*/        UD_NUMBER       VarBufferSizeInBytes,
    /*__out_opt*/   UD_NUMBER       *Consumed
    );
//
// Placeholder (not fully implemented), supports only matching a plain "string" literals
//


UD_BOOLEAN
UdMatchAssignementTo(
    /*__in_out*/    UD_VAR_INFO     *Variable,
    /*_In_*/        UD_ASCII_STRING Input,
    /*_In_*/        UD_NUMBER       Length,
    /*__out_opt*/   UD_NUMBER       *Consumed
    );
//
// match Variable->VariableName \s* = \s* (number | string)
//


UD_BOOLEAN
UdMatchVariablesFromTextEx(
    /*__in_out*/    UD_VAR_INFO     *VariableInfo,
    /*_In_*/        UD_NUMBER       NumberOfVariables,
    /*_In_*/        UD_ASCII_STRING Input,
    /*_In_*/        UD_NUMBER       Length,
    /*__out_opt*/   UD_NUMBER       *Consumed,
    /*_In_*/        UD_NUMBER       MetadataFlagsWritableMask,
    /*_In_*/        UD_NUMBER       MetadataFlagsDirtyMask
    );
//
// match ( \s* assignment \s* \,? \s* )*
//


UD_BOOLEAN
UdMatchVariablesFromText(
    /*__in_out*/    UD_VAR_INFO     *VariableInfo,
    /*_In_*/        UD_NUMBER       NumberOfVariables,
    /*_In_*/        UD_ASCII_STRING Input,
    /*_In_*/        UD_NUMBER       Length,
    /*__out_opt*/   UD_NUMBER       *Consumed
);
//
// match ( \s* assignment \s* \,? \s* )*
//


UD_BOOLEAN
UdDumpVariablesToText(
    /*_In_*/        UD_VAR_INFO     *VariableInfo,
    /*_In_*/        UD_NUMBER       NumberOfVariables,
    /*_Out_*/       UD_ASCII_STRING Out,
    /*_In_*/        UD_NUMBER       OutSizeInBytes,
    /*_Out_*/       UD_NUMBER       *OutWrittenBytes
    );
//
// generate a textual representation of the VariableInfo vars
// Out will contain partial data if matching fails or there's not enough room (but will be zero terminated if at least one byte can be written)
// OutWrittenBytes will always tell back the actual number of bytes required for holding the content (even when the function fails)
//


UD_BOOLEAN
UdGetVariableByName(
    /*_In_*/        UD_VAR_INFO     *VariableInfo,
    /*_In_*/        UD_NUMBER       NumberOfVariables,
    /*_In_*/        UD_ASCII_STRING VariableName,
    /*_In_*/        UD_NUMBER       VariableNameLength,
    /*__out_opt*/   void            *OutBuffer,
    /*_In_*/        UD_NUMBER       OutBufferSizeInBytes,
    /*__out_opt*/   UD_NUMBER       *WrittenBytes,
    /*__out_opt*/   UD_VAR_INFO     **Variable
    );
//
// find the specified variable and copy its value to the output buffer (and/or fill-in the UD_VAR_INFO pointer with the found UD_VAR_INFO structure)
//


#endif