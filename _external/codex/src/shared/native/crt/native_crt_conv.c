/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "crt/crt_crt.h"

//
// helper routines
//

/***
*crt_strtol, crt_strtoul(nptr,endptr,ibase) - Convert ascii string to CX_INT32 un/CX_INT32
*       CX_INT32.
*
*Purpose:
*       Convert an ascii string to a CX_INT32 32-bit value.  The base
*       used for the caculations is supplied by the caller.  The base
*       must be in the range 0, 2-36.  If a base of 0 is supplied, the
*       ascii string must be examined to determine the base of the
*       number:
*               (a) First CX_INT8 = '0', second CX_INT8 = 'x' or 'X',
*                   use base 16.
*               (b) First CX_INT8 = '0', use base 8
*               (c) First CX_INT8 in range '1' - '9', use base 10.
*
*       If the 'endptr' value is non-CX_NULL, then crt_strtol/crt_strtoul places
*       a pointer to the terminating character in this value.
*       See ANSI standard for details
*
*Entry:
*       nptr == NEAR/FAR pointer to the start of string.
*       endptr == NEAR/FAR pointer to the end of the string.
*       ibase == integer base to use for the calculations.
*
*       string format: [whitespace] [sign] [0] [x] [digits/letters]
*
*Exit:
*       Good return:
*               result
*
*       Overflow return:
*               crt_strtol -- CX_INT32_MAX_VALUE or CX_INT32_MIN_VALUE
*               crt_strtoul -- CX_UINT32_MAX_VALUE
*               crt_strtol/crt_strtoul -- errno == ERANGE
*
*       No digits or bad base return:
*               0
*               endptr = nptr*
*
*Exceptions:
*       Input parameters are validated. Refer to the validation section of the function.
*
*******************************************************************************/

/* flag values */
#define FL_UNSIGNED   1       /* crt_strtoul called */
#define FL_NEG        2       /* negative sign found */
#define FL_OVERFLOW   4       /* overflow occured */
#define FL_READDIGIT  8       /* we've read at least one correct digit */

static CX_UINT32 __cdecl
crt_strtoxl(
    const CX_INT8 *nptr,
    const CX_INT8 **endptr,
    CX_INT32 ibase,
    CX_INT32 flags
    )
{
    const CX_INT8 *p;
    CX_INT8 c;
    CX_UINT32 number;
    CX_UINT32 digval;
    CX_UINT32 maxval;

    /* validation section */
    if (endptr != CX_NULL)
    {
        /* store beginning of string in endptr */
        *endptr = (CX_INT8 *)nptr;
    }

    /// TO-DO: reimplement validation
    ///_VALIDATE_RETURN(nptr != CX_NULL, EINVAL, 0L);
    ///_VALIDATE_RETURN(ibase == 0 || (2 <= ibase && ibase <= 36), EINVAL, 0L);

    p = nptr;                       /* p is our scanning pointer */
    number = 0;                     /* start with zero */

    c = *p++;                       /* read CX_INT8 */
    ///while ( _isspace_l((CX_INT32)(CX_UINT8)c, _loc_update.GetLocaleT()) )
    while (' ' == (CX_INT32)(CX_UINT8)c)
        c = *p++;               /* skip whitespace */

    if (c == '-') {
        flags |= FL_NEG;        /* remember minus sign */
        c = *p++;
    }
    else if (c == '+')
        c = *p++;               /* skip sign */

    if (ibase < 0 || ibase == 1 || ibase > 36) {
        /* bad base! */
        if (endptr)
            /* store beginning of string in endptr */
            *endptr = nptr;
        return 0L;              /* return 0 */
    }
    else if (ibase == 0) {
        /* determine base free-lance, based on first two chars of
           string */
        if (c != '0')
            ibase = 10;
        else if (*p == 'x' || *p == 'X')
            ibase = 16;
        else
            ibase = 8;
    }

    if (ibase == 0) {
        /* determine base free-lance, based on first two chars of
           string */
        if (c != '0')
            ibase = 10;
        else if (*p == 'x' || *p == 'X')
            ibase = 16;
        else
            ibase = 8;
    }

    if (ibase == 16) {
        /* we might have 0x in front of number; remove if there */
        if (c == '0' && (*p == 'x' || *p == 'X')) {
            ++p;
            c = *p++;       /* advance past prefix */
        }
    }

    /* if our number exceeds this, we will overflow on multiply */
    maxval = CX_UINT32_MAX_VALUE / ibase;


    for (;;) {      /* exit in middle of loop */
        /* convert c to value */
        ///if ( __ascii_isdigit_l((CX_INT32)(CX_UINT8)c, _loc_update.GetLocaleT()) )
        if (crt_isdigit((CX_INT32)(CX_UINT8)c))
            digval = c - '0';
        ///else if ( __ascii_isalpha_l((CX_INT32)(CX_UINT8)c, _loc_update.GetLocaleT()) )
        else if (crt_isalpha((CX_INT32)(CX_UINT8)c))
            ///digval = __ascii_toupper(c) - 'A' + 10;
            digval = crt_toupper(c) - 'A' + 10;
        else
            break;
        if (digval >= (CX_UINT32)ibase)
            break;          /* exit loop if bad digit found */

        /* record the fact we have read one digit */
        flags |= FL_READDIGIT;

        /* we now need to compute number = number * base + digval,
           but we need to know if overflow occured.  This requires
           a tricky pre-check. */

        if (number < maxval || (number == maxval &&
                    (CX_UINT32)digval <= CX_UINT32_MAX_VALUE % ibase)) {
            /* we won't overflow, go ahead and multiply */
            number = number * ibase + digval;
        }
        else {
            /* we would have overflowed -- set the overflow flag */
            flags |= FL_OVERFLOW;
            if (endptr == CX_NULL) {
                /* no need to keep on parsing if we
                   don't have to return the endptr. */
                break;
            }
        }

        c = *p++;               /* read next digit */
    }

    --p;                            /* point to place that stopped scan */

    if (!(flags & FL_READDIGIT)) {
        /* no number there; return 0 and point to beginning of
           string */
        if (endptr)
            /* store beginning of string in endptr later on */
            p = nptr;
        number = 0L;            /* return 0 */
    }
    else if ( (flags & FL_OVERFLOW) ||
            ( !(flags & FL_UNSIGNED) &&
              ( ( (flags & FL_NEG) && (number > -CX_INT32_MIN_VALUE) ) ||
                ( !(flags & FL_NEG) && (number > CX_INT32_MAX_VALUE) ) ) ) )
    {
        /* overflow or CX_INT32 overflow occurred */
        ///errno = ERANGE;
        if ( flags & FL_UNSIGNED )
            number = CX_UINT32_MAX_VALUE;
        else if ( flags & FL_NEG )
            number = (CX_UINT32)(-CX_INT32_MIN_VALUE);
        else
            number = CX_INT32_MAX_VALUE;
    }

    if (endptr != CX_NULL)
        /* store pointer to CX_INT8 that stopped the scan */
        *endptr = p;

    if (flags & FL_NEG)
        /* negate result if there was a neg sign */
        number = (CX_UINT32)(-(CX_INT32)number);

    return number;                  /* done. */
}

static CX_UINT64 __cdecl
crt_strtoxll(
    const CX_INT8 *nptr,
    const CX_INT8 **endptr,
    CX_INT32 ibase,
    CX_INT32 flags
    )
{
    const CX_INT8 *p;
    CX_INT8 c;
    CX_UINT64 number;
    CX_UINT32 digval;
    CX_UINT64 maxval;

    /* validation section */
    if (endptr != CX_NULL)
    {
        /* store beginning of string in endptr */
        *endptr = (CX_INT8 *)nptr;
    }

    /// TO-DO: reimplement validation
    ///_VALIDATE_RETURN(nptr != CX_NULL, EINVAL, 0L);
    ///_VALIDATE_RETURN(ibase == 0 || (2 <= ibase && ibase <= 36), EINVAL, 0L);

    p = nptr;                       /* p is our scanning pointer */
    number = 0;                     /* start with zero */

    c = *p++;                       /* read CX_INT8 */
    ///while ( _isspace_l((CX_INT32)(CX_UINT8)c, _loc_update.GetLocaleT()) )
    while (' ' == (CX_INT32)(CX_UINT8)c)
        c = *p++;               /* skip whitespace */

    if (c == '-') {
        flags |= FL_NEG;        /* remember minus sign */
        c = *p++;
    }
    else if (c == '+')
        c = *p++;               /* skip sign */

    if (ibase < 0 || ibase == 1 || ibase > 36) {
        /* bad base! */
        if (endptr)
            /* store beginning of string in endptr */
            *endptr = nptr;
        return 0L;              /* return 0 */
    }
    else if (ibase == 0) {
        /* determine base free-lance, based on first two chars of
           string */
        if (c != '0')
            ibase = 10;
        else if (*p == 'x' || *p == 'X')
            ibase = 16;
        else
            ibase = 8;
    }

    if (ibase == 0) {
        /* determine base free-lance, based on first two chars of
           string */
        if (c != '0')
            ibase = 10;
        else if (*p == 'x' || *p == 'X')
            ibase = 16;
        else
            ibase = 8;
    }

    if (ibase == 16) {
        /* we might have 0x in front of number; remove if there */
        if (c == '0' && (*p == 'x' || *p == 'X')) {
            ++p;
            c = *p++;       /* advance past prefix */
        }
    }

    /* if our number exceeds this, we will overflow on multiply */
    maxval = CX_UINT64_MAX_VALUE / ibase;


    for (;;) {      /* exit in middle of loop */
        /* convert c to value */
        ///if ( __ascii_isdigit_l((CX_INT32)(CX_UINT8)c, _loc_update.GetLocaleT()) )
        if (crt_isdigit((CX_INT32)(CX_UINT8)c))
            digval = c - '0';
        ///else if ( __ascii_isalpha_l((CX_INT32)(CX_UINT8)c, _loc_update.GetLocaleT()) )
        else if (crt_isalpha((CX_INT32)(CX_UINT8)c))
            ///digval = __ascii_toupper(c) - 'A' + 10;
            digval = crt_toupper(c) - 'A' + 10;
        else
            break;
        if (digval >= (CX_UINT32)ibase)
            break;          /* exit loop if bad digit found */

        /* record the fact we have read one digit */
        flags |= FL_READDIGIT;

        /* we now need to compute number = number * base + digval,
           but we need to know if overflow occured.  This requires
           a tricky pre-check. */

        if (number < maxval || (number == maxval &&
                    (CX_UINT64)digval <= CX_UINT64_MAX_VALUE % ibase)) {
            /* we won't overflow, go ahead and multiply */
            number = number * ibase + digval;
        }
        else {
            /* we would have overflowed -- set the overflow flag */
            flags |= FL_OVERFLOW;
            if (endptr == CX_NULL) {
                /* no need to keep on parsing if we
                   don't have to return the endptr. */
                break;
            }
        }

        c = *p++;               /* read next digit */
    }

    --p;                            /* point to place that stopped scan */

    if (!(flags & FL_READDIGIT)) {
        /* no number there; return 0 and point to beginning of
           string */
        if (endptr)
            /* store beginning of string in endptr later on */
            p = nptr;
        number = 0L;            /* return 0 */
    }
    else if ( (flags & FL_OVERFLOW) ||
            ( !(flags & FL_UNSIGNED) &&
              ( ( (flags & FL_NEG) && (number > -CX_INT64_MIN_VALUE) ) ||
                ( !(flags & FL_NEG) && (number > CX_INT64_MAX_VALUE) ) ) ) )
    {
        /* overflow or CX_INT32 overflow occurred */
        ///errno = ERANGE;
        if ( flags & FL_UNSIGNED )
            number = CX_UINT64_MAX_VALUE;
        else if ( flags & FL_NEG )
            number = (CX_UINT64)(-CX_INT64_MIN_VALUE);
        else
            number = CX_INT64_MAX_VALUE;
    }

    if (endptr != CX_NULL)
        /* store pointer to CX_INT8 that stopped the scan */
        *endptr = p;

    if (flags & FL_NEG)
        /* negate result if there was a neg sign */
        number = (CX_UINT64)(-(CX_INT64)number);

    return number;                  /* done. */
}


//
// crt_strtol
//
CX_INT32 __cdecl 
crt_strtol(
    _In_z_ const CX_INT8 *nptr,
    __out_opt CX_INT8 **endptr,
    _In_ CX_INT32 ibase
    )
{
    return (CX_INT32)crt_strtoxl(nptr, (const CX_INT8 **)endptr, ibase, 0);
}


//
// crt_strtoul
//
CX_UINT32 __cdecl 
crt_strtoul(
    _In_z_ const CX_INT8 *nptr,
    __out_opt CX_INT8 **endptr,
    _In_ CX_INT32 ibase
    )
{
    return crt_strtoxl(nptr, (const CX_INT8 **)endptr, ibase, FL_UNSIGNED);
}


//
// crt_strtoll
//
CX_INT64 __cdecl 
crt_strtoll(
    _In_z_ const CX_INT8 *nptr,
    __out_opt CX_INT8 **endptr,
    _In_ CX_INT32 ibase
    )
{
    return (CX_INT64)crt_strtoxll(nptr, (const CX_INT8 **)endptr, ibase, 0);
}


//
// crt_strtoull
//
CX_UINT64 __cdecl 
crt_strtoull(
    _In_z_ const CX_INT8 *nptr,
    __out_opt CX_INT8 **endptr,
    _In_ CX_INT32 ibase
    )
{
    return crt_strtoxll(nptr, (const CX_INT8 **)endptr, ibase, FL_UNSIGNED);
}

