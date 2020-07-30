/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

//
// This file implements a (ASCII) parser for key=value specified variables used for retrieving configuration options exported by export.pl with "/format txt" option
//
#include "userdata.h"

#define UD_NULL     ((void *)0)
#define UD_TRUE     (0 == 0)
#define UD_FALSE    (0 != 0)

UD_BOOLEAN
UdMatchSpaces(
    /*_In_*/        UD_ASCII_STRING Input,
    /*_In_*/        UD_NUMBER       Length,
    /*__out_opt*/   UD_NUMBER       *Consumed
    )
//
// Returns !=0 if spaces were found with Consumed = number of found whitespace bytes
//
{
    UD_NUMBER consumed = 0;
    if  (!Input || !Length ) goto cleanup;
    while   ( 
                (Length > 0) && 
                ((*Input == ' ') || (*Input == '\t') || (*Input == '\r') || (*Input == '\n') || (Length == 1 && Input[0] == 0) ) 
            )
    {
        Length--;
        Input++;
        consumed++;
    }

cleanup:
    if (Consumed) *Consumed = consumed;
    return (consumed != 0);
}


UD_BOOLEAN
UdMatchToken(
    /*_In_*/        UD_ASCII_STRING Token,
    /*_In_*/        UD_ASCII_STRING Input,
    /*_In_*/        UD_NUMBER       Length,
    /*__out_opt*/   UD_NUMBER       *Consumed
    )
//
// Returns !=0 if the given token literal follows at Input with Consumed = number of consumed characters
//
{
    UD_NUMBER i = 0;

    if (!Token || !Input || !Length) goto cleanup;

    while ((i < Length) && Token[i] && Input[i] && (Input[i] == Token[i]))
    {
        i++;
    }

    // if we got to last token character then we were successful
    if (!Token[i])
    {
        if (Consumed) *Consumed = i;
        return 1;
    }

cleanup:
    if (Consumed) *Consumed = 0;
    return 0;
}


UD_BOOLEAN
UdMatchNumber(
    /*_In_*/        UD_ASCII_STRING Input,
    /*_In_*/        UD_NUMBER       Length,
    /*__out_opt*/   UD_QWORD        *Var,
    /*__out_opt*/   UD_NUMBER       *Consumed
    )
//
// Match [+-]? (0[xX][0-9a-fA-F]+ | [0-9]+)
// Var is only set when a number has beeb successfully matched
//
{
    UD_QWORD result = 0;
    UD_BOOLEAN isNegative = 0, isHex = 0;
    UD_NUMBER consumed = 0;
    UD_NUMBER digits = 0;

    if (!Input || !Length)
    {
        if (Consumed) *Consumed = 0;
        return 0;
    }

    // consume [+-]?
    if ((Length > 0) && (Input[0] == '-'))
    {
        isNegative = 1;
        consumed++;
    }
    else if ((Length > 0) && (Input[0] == '+')) consumed++;

    // allow a 0x prefix for hex numbers
    if ((Length > consumed + 2) && (Input[consumed] == '0') && ((Input[consumed+1]|32) == 'x'))
    {
        isHex = 1;
        consumed += 2;
    }

    // build the (absolute) value out of the found digits
    if (isHex)
    {
        while   (
                    (consumed < Length) &&
                    (
                        ((Input[consumed] >= '0') && (Input[consumed] <= '9'))||
                        ((Input[consumed] >= 'a') && (Input[consumed] <= 'f'))||
                        ((Input[consumed] >= 'A') && (Input[consumed] <= 'F'))
                    )
                )
        {
            result *= 16;

            // yes, the next line takes into account both 'a' and 'A' cases..
            result += (Input[consumed] < 'A') ? (Input[consumed] - '0') : (10 + ((Input[consumed]|32) - 'a'));
            consumed++;
            digits++;
        }
    }
    else
    {
        while ( (consumed < Length) && (Input[consumed] >= '0') && (Input[consumed] <= '9') )
        {

            result = (result * 10) + (Input[consumed] - '0');
            consumed++;
            digits++;
        }
    }

    if (Consumed)
    {
        *Consumed = consumed;
    }

    // fail if not even a single actual digit was matched
    if (!digits)
    {
        return 0;
    }

    if (Var)
    {
        *Var = isNegative ? (result * (UD_QWORD)-1) : result;
    }
    return 1;
}


UD_BOOLEAN
UdMatchString(
    /*_In_*/        UD_ASCII_STRING Input,
    /*_In_*/        UD_NUMBER       Length,
    /*__out_opt*/   UD_ASCII_STRING VarBuffer,
    /*_In_*/        UD_NUMBER       VarBufferSizeInBytes,
    /*_Out_*/       UD_NUMBER       *Consumed
    )
//
// match " ([^\\"]* | \\.)* " and keep the escaped content only (escaped here means the second character after \ -- that is, for \. it will only take the .)
// VarBuffer is filled-in only on a successful match
// a proper match implies VarBufferSizeInBytes is valid, no matter if VarBuffer is missing
//
{
    UD_NUMBER i,  total;
    if (Input == UD_NULL || !Length || Input[0] != '"')
    {
        goto error;
    }

    // 'lookahead' for valid string and find out its actual size in bytes
    i = 1;
    total = 0;
    while ((i < Length) && (Input[i] != 0) && (Input[i] != '"'))
    {
        if (Input[i] == '\\')
        {
            // skip the escape and continue with consuming the next character instead
            i++;
            // at least one character is required after the escape code
            if (i >= Length) goto error;
        }
        i++;
        total++;
    }

    // check for closing " character
    if ((i >= Length) || (Input[i] != '"'))
    {
        // the string is not properly terminated
        goto error;
    }

    // account for null terminator in the output buffer
    total++;

    // check size
    if (total + 1 >= VarBufferSizeInBytes)
    {
        // an overflow would occur
        goto error;
    }

    // copy the string content now that we know it's all good (and safe)
    if (VarBuffer)
    {
        i = 1;
        total = 0;
        while ((i < Length) && (Input[i] != 0) && (Input[i] != '"'))
        {
            if (Input[i] == '\\')
            {
                // skip the escape and continue with consuming the next character instead
                i++;
                // at least one character is required after the escape code
                if (i >= Length) goto error;
            }

            VarBuffer[total] = Input[i];
            i++;
            total++;
        }

        // skip end "
        i++;

        // add the null terminator
        VarBuffer[total] = 0;
        total++;
    }

    // i is correct whether a VarBuffer was sent or not
    if (Consumed) *Consumed = i;
    return 1;

error:
    if (Consumed) *Consumed = 0;
    return 0;
}


UD_BOOLEAN
UdMatchNumericExpression(
    /*_In_*/        UD_ASCII_STRING Input,
    /*_In_*/        UD_NUMBER       Length,
    /*__out_opt*/   UD_QWORD        *Var,
    /*__out_opt*/   UD_NUMBER       *Consumed
    )
//
// Placeholder (not fully implemented), currently supports matching plain decimal and hexadecimal numbers only
//
{
    return UdMatchNumber(Input, Length, Var, Consumed);
}

UD_BOOLEAN
UdMatchAsciiStringExpression(
    /*_In_*/        UD_ASCII_STRING Input,
    /*_In_*/        UD_NUMBER       Length,
    /*__out_opt*/   UD_ASCII_STRING VarBuffer,
    /*_In_*/        UD_NUMBER       VarBufferSizeInBytes,
    /*__out_opt*/   UD_NUMBER       *Consumed
    )
//
// Placeholder (not fully implemented), supports only matching a plain "string" literals
//
{
    return UdMatchString(Input, Length, VarBuffer, VarBufferSizeInBytes, Consumed);
}

UD_BOOLEAN
UdMatchAssignementTo(
    /*__in_out*/    UD_VAR_INFO     *Variable,
    /*_In_*/        UD_ASCII_STRING Input,
    /*_In_*/        UD_NUMBER       Length,
    /*__out_opt*/   UD_NUMBER       *Consumed
    )
//
// match Variable->VariableName \s* = \s* (number | string)
//
{
    UD_NUMBER consumed = 0, lastMatchLength;
    UD_QWORD number;

    if (!Variable || !Input || !Length)
    {
        if (Consumed) *Consumed = 0;
        return 0;
    }

    if (UdMatchToken(Variable->VariableName, Input, Length, &lastMatchLength))
    {
        consumed += lastMatchLength;
        if (UdMatchSpaces(Input + consumed, Length - consumed, &lastMatchLength))
        {
            consumed += lastMatchLength;
        }

        if (UdMatchToken("=", Input + consumed, Length - consumed, &lastMatchLength))
        {
            consumed += lastMatchLength;
            if (UdMatchSpaces(Input + consumed, Length - consumed, &lastMatchLength))
            {
                consumed += lastMatchLength;
            }

            // match the proper value based on expected type (numeric expression or string expression)
            if (Variable->VariableType == UD_TYPE_NUMBER)
            {
                if (UdMatchNumericExpression(Input + consumed, Length - consumed, &number, &lastMatchLength))
                {
                    *((UD_NUMBER*)Variable->VariableAddress) = (UD_NUMBER)number;

                    if ( (UD_QWORD) (*((UD_NUMBER*)Variable->VariableAddress)) != number )
                    {
                        // make sure we didn't lose any useful bits at the UD_NUMBER conversion
                        goto failed;
                    }
                    consumed += lastMatchLength;
                    goto matched;
                }
            }
            else if (Variable->VariableType == UD_TYPE_ASCII_STRING)
            {
                if (UdMatchAsciiStringExpression(Input + consumed, Length - consumed, Variable->VariableAddress, Variable->VariableSizeInBytes, &lastMatchLength))
                {
                    consumed += lastMatchLength;
                    goto matched;
                }
            }
            else
            {
                // goto failed; -- unnecessary
            }
        }
    }
failed:
    if (Consumed) *Consumed = consumed;
    return 0;

matched:
    if (Consumed) *Consumed = consumed;
    return 1;
}


UD_BOOLEAN
UdMatchVariablesFromTextEx(
    /*__in_out*/    UD_VAR_INFO     *VariableInfo,
    /*_In_*/        UD_NUMBER       NumberOfVariables,
    /*_In_*/        UD_ASCII_STRING Input,
    /*_In_*/        UD_NUMBER       Length,
    /*__out_opt*/   UD_NUMBER       *Consumed,
    /*_In_*/        UD_NUMBER       MetadataFlagsWritableMask,
    /*_In_*/        UD_NUMBER       MetadataFlagsDirtyMask
    )
//
// match ( \s* assignment \s* \,? \s* )*
//
{
    UD_NUMBER assignmentLength = 0, i, lastMatchLength;
    *Consumed = 0;

    if (!VariableInfo || !Input || !Length)
    {
        if (Consumed) *Consumed = 0;
        return 0;
    }

    do
    {
        assignmentLength = 0;

        // skip leading spaces
        if (UdMatchSpaces(Input, Length, &lastMatchLength))
        {
            assignmentLength += lastMatchLength;
        }

        // try each variable
        for (i = 0; i < NumberOfVariables; i++)
        {
            if (MetadataFlagsWritableMask == (VariableInfo[i].VariableMetadataFlags & MetadataFlagsWritableMask))
            {
                if (UdMatchAssignementTo(&(VariableInfo[i]), Input, Length, &lastMatchLength))
                {
                    VariableInfo[i].VariableMetadataFlags |= MetadataFlagsDirtyMask;
                    assignmentLength += lastMatchLength;
                    break;
                }
            }
        }

        if (assignmentLength)
        {
            // skip 'spaces' 'comma' 'spaces' between variable assignments (or at the end)
            if (UdMatchSpaces(Input + assignmentLength, Length - assignmentLength, &lastMatchLength))
            {
                assignmentLength += lastMatchLength;
            }
            if (UdMatchToken(",", Input + assignmentLength, Length - assignmentLength, &lastMatchLength))
            {
                assignmentLength += lastMatchLength;
                if (UdMatchSpaces(Input + assignmentLength, Length - assignmentLength, &lastMatchLength))
                {
                    assignmentLength += lastMatchLength;
                }
            }
            *Consumed += assignmentLength;
            Length -= assignmentLength;
            Input += assignmentLength;
        }
    } while ((assignmentLength) && (Length));

    if (!Length || (Input[Length - 1] == 0))
    {
        // all consumed or got to the null terminator
        return 1;
    }
    return 0;
}


UD_BOOLEAN
UdMatchVariablesFromText(
    /*__in_out*/    UD_VAR_INFO     *VariableInfo,
    /*_In_*/        UD_NUMBER       NumberOfVariables,
    /*_In_*/        UD_ASCII_STRING Input,
    /*_In_*/        UD_NUMBER       Length,
    /*__out_opt*/   UD_NUMBER       *Consumed
)
//
// match ( \s* assignment \s* \,? \s* )*
//
{
    return UdMatchVariablesFromTextEx(VariableInfo, NumberOfVariables, Input, Length, Consumed, 0, 0);
}


static
void
UdWriteOrSkip(
    UD_ASCII_STRING Out,
    UD_NUMBER       OutSizeInBytes,
    UD_NUMBER       *Pos,
    char Character
    )
{
    if (Out && Pos && *Pos < OutSizeInBytes)
        Out[*Pos] = Character;

    (*Pos)++;
}


UD_BOOLEAN
UdDumpVariablesToText(
    /*_In_*/    UD_VAR_INFO     *VariableInfo,
    /*_In_*/    UD_NUMBER       NumberOfVariables,
    /*_Out_*/   UD_ASCII_STRING Out,
    /*_In_*/    UD_NUMBER       OutSizeInBytes,
    /*_Out_*/   UD_NUMBER       *OutWrittenBytes
    )
//
// generate a textual representation of the VariableInfo vars
// Out will contain partial data if matching fails or there's not enough room (but will be zero terminated if at least one byte can be written)
// OutWrittenBytes will always tell back the actual number of bytes required for holding the content (even when the function fails)
//
{
    UD_NUMBER varIndex, i;
    UD_NUMBER outPos;
    UD_VAR_INFO *var;
    char *varData;

    outPos = 0;
    for (var = VariableInfo, varIndex = 0; varIndex < NumberOfVariables; var++, varIndex++)
    {
        // copy the variable name
        i = 0;
        while (var->VariableName[i] != 0)
        {
            UdWriteOrSkip(Out, OutSizeInBytes, &outPos, var->VariableName[i]);
            i++;
        }

        // add '='
        UdWriteOrSkip(Out, OutSizeInBytes, &outPos, '=');


        // and now the actual variable value
        varData = (char *)var->VariableAddress;

        if (var->VariableType == UD_TYPE_ASCII_STRING)
        {
            // add opening '"'
            UdWriteOrSkip(Out, OutSizeInBytes, &outPos, '"');

            // copy the content
            i = 0;
            while (varData[i] != 0)
            {
                if ((varData[i] == '\\') || (varData[i] == '"'))
                {
                    // escape it by writing '\' in front of the character
                    UdWriteOrSkip(Out, OutSizeInBytes, &outPos, '\\');
                }
                UdWriteOrSkip(Out, OutSizeInBytes, &outPos, varData[i]);
                i++;
            }

            // add closing '"'
            UdWriteOrSkip(Out, OutSizeInBytes, &outPos, '"');
        }
        else if ((var->VariableType == UD_TYPE_NUMBER) || (var->VariableType == UD_TYPE_QWORD) || (var->VariableType == UD_TYPE_SIZE_T))
        {
            // get the numerical value and convert to ascii hex representation or leave decimal if <10
            // TODO: make sure signed values are handled properly!!
            UD_QWORD value;
            switch (var->VariableType)
            {
                case UD_TYPE_NUMBER: value = (UD_QWORD)(*(UD_NUMBER*)varData);
                    break;
                case UD_TYPE_QWORD:  value = (UD_QWORD)(*(UD_QWORD*)varData);
                    break;
                case UD_TYPE_SIZE_T: value = (UD_QWORD)(*(UD_SIZE_T*)varData);
                    break;
                default:
                    // when executed it means the if condition was relaxed but without a matching switch case being added / implemented
                    goto error;
            }

            if (value < 10)
            {
                // add a single digit
                UdWriteOrSkip(Out, OutSizeInBytes, &outPos, '0' + (char)value);
            }
            else
            {
                UD_NUMBER digitCount;
                UD_BOOLEAN atLeastOneDigit;
                char digit;

                // remember where the first digit would go to
                // add 0x before the constant
                UdWriteOrSkip(Out, OutSizeInBytes, &outPos, '0');
                UdWriteOrSkip(Out, OutSizeInBytes, &outPos, 'x');

                atLeastOneDigit = Out && (outPos < OutSizeInBytes); // one digit will be written (if the condition holds), even if the number is 0
                digitCount = 0;
                do
                {
                    // add a single digit
                    digit = value % 16;
                    digit = digit < 10 ? '0' + digit : 'A' + (digit - 10);

                    // if we have some digit(s) but we're out of buffer space, left-shift existing digits to make room (by removing the oldest one)
                    if (atLeastOneDigit && (outPos >= OutSizeInBytes))
                    {
                        UD_NUMBER repl;
                        for (repl = OutSizeInBytes - digitCount; repl + 1 < OutSizeInBytes; repl++)
                        {
                            Out[repl] = Out[repl + 1];
                        }

                        Out[OutSizeInBytes - 1] = digit;    // the rightmost character is now free so can overwrite it with the new digit
                        digitCount--;                       // and reflect a missing digit (the one that got out)
                    }

                    // always take into account how many bytes are (or would be) actually needed
                    UdWriteOrSkip(Out, OutSizeInBytes, &outPos, digit);

                    value /= 16;
                    digitCount++;
                } while (value != 0); // we need at least one digit even if it's 0 from the start

                // reverse the digits (atLeastOneDigit implies that digitCount is the number of actually written digits)
                if (atLeastOneDigit)
                {
                    UD_NUMBER rightLimit = outPos < OutSizeInBytes ? outPos : OutSizeInBytes;

                    for (i = 0; i < digitCount / 2; i++)
                    {
                        // bounds: i elements to the left of rightLimit - 1 and i elements to the right of (rightLimit - digitCount)
                        digit = Out[(rightLimit - 1) - i];
                        Out[(rightLimit - 1) - i] = Out[(rightLimit + i) - digitCount];
                        Out[(rightLimit + i) - digitCount] = digit;
                    }
                }
            }
        }
        else // unknown, unsupported or simply unhandled value type
        {
            goto error;
        }

        // add ',' if another variable follows
        if (varIndex + 1 < NumberOfVariables)
        {
            // add a single digit
            UdWriteOrSkip(Out, OutSizeInBytes, &outPos, ',');
        }
    }

    // done, add the NULL terminator
    UdWriteOrSkip(Out, OutSizeInBytes, &outPos, 0);

    // success?
    if (Out && (outPos <= OutSizeInBytes))
    {
        if (OutWrittenBytes)
        {
            *OutWrittenBytes = outPos;
        }

        return UD_TRUE;
    }

error:
    if (Out && OutSizeInBytes)
    {
        // set a null terminator at position: written if it's strictly < OutSizeInBytes or else to OutSizeInBytes - 1
        Out[outPos < OutSizeInBytes ? outPos : OutSizeInBytes - 1] = 0;
        outPos++; // reflect the actual needed number of bytes
    }
    if (OutWrittenBytes)
    {
        *OutWrittenBytes = outPos;
    }
    return UD_FALSE;
}


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
    )
//
// find the specified variable and copy its value to the output buffer (and/or fill-in the UD_VAR_INFO pointer with the found UD_VAR_INFO structure)
//
{
    UD_NUMBER i, j, matchLength;
    char *in, *out;

    // try each variable
    for (i = 0; i < NumberOfVariables; i++)
    {
        // check for matching name
        if (UdMatchToken(VariableInfo[i].VariableName, VariableName, VariableNameLength, &matchLength))
        {
            // make sure it's not only a partial name match
            if (matchLength == VariableNameLength)
            {
                // must have enough space in the output buffer
                if (VariableInfo[i].VariableSizeInBytes <= OutBufferSizeInBytes)
                {
                    in = (char *)VariableInfo[i].VariableAddress;
                    out = (char *)OutBuffer;

                    if (out)
                    {
                        // init out buffer before copying
                        for (j = 0; j < OutBufferSizeInBytes; j++)
                        {
                            out[j] = 0;
                        }

                        for (j = 0; j < VariableInfo[i].VariableSizeInBytes; j++)
                        {
                            out[j] = in[j];
                        }
                    }

                    if (WrittenBytes)
                    {
                        *WrittenBytes = VariableInfo[i].VariableSizeInBytes;
                    }
                    if (Variable)
                    {
                        *Variable = &(VariableInfo[i]);
                    }
                    return 1;
                }
            }
        }
    }
    return 0;
}

