/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

//
//  SNPRINTF - crt_snprintf() implementation
//
//  NOTE: minimal modifications marked by ///---
//
#include "crt/crt_crt.h"

/*
 * Copyright (c) 1995 Patrick Powell.
 *
 * This code is based on code written by Patrick Powell <papowell@astart.com>.
 * It may be used for any purpose as long as this notice remains intact on all
 * source code distributions.
 */

/*
 * Copyright (c) 2008 Holger Weiss.
 *
 * This version of the code is maintained by Holger Weiss <holger@jhweiss.de>.
 * My changes to the code may freely be used, modified and/or redistributed for
 * any purpose.  It would be nice if additions and fixes to this file (including
 * trivial code cleanups) would be sent back in order to let me include them in
 * the version available at <http://www.jhweiss.de/software/crt_snprintf.html>.
 * However, this is not a requirement for using or redistributing (possibly
 * modified) versions of this file, nor is leaving this notice intact mandatory.
 */

/*
 * History
 *
 * 2008-01-20 Holger Weiss <holger@jhweiss.de> for C99-crt_snprintf 1.1:
 *
 *  Fixed the detection of infinite floating point values on IRIX (and
 *  possibly other systems) and applied another few minor cleanups.
 *
 * 2008-01-06 Holger Weiss <holger@jhweiss.de> for C99-crt_snprintf 1.0:
 *
 *  Added a lot of new features, fixed many bugs, and incorporated various
 *  improvements done by Andrew Tridgell <tridge@samba.org>, Russ Allbery
 *  <rra@stanford.edu>, Hrvoje Niksic <hniksic@xemacs.org>, Damien Miller
 *  <djm@mindrot.org>, and others for the Samba, INN, Wget, and OpenSSH
 *  projects.  The additions include: support the "e", "E", "g", "G", and
 *  "F" conversion specifiers (and use conversion style "f" or "F" for the
 *  still unsupported "a" and "A" specifiers); support the "hh", "ll", "j",
 *  "t", and "z" length modifiers; support the "#" flag and the (non-C99)
 *  "'" flag; use localeconv(3) (if available) to get both the current
 *  locale's decimal point character and the separator between groups of
 *  digits; fix the handling of various corner cases of field width and
 *  precision specifications; fix various floating point conversion bugs;
 *  handle infinite and NaN floating point values; don't attempt to write to
 *  the output buffer (which may be CX_NULL) if a size of zero was specified;
 *  check for integer overflow of the field width, precision, and return
 *  values and during the floating point conversion; use the CRT_OUTCHAR() macro
 *  instead of a function for better performance; provide crt_asprintf(3) and
 *  crt_vasprintf(3) functions; add new test cases.  The replacement functions
 *  have been renamed to use an "rpl_" prefix, the function calls in the
 *  crt_main project (and in this file) must be redefined accordingly for each
 *  replacement function which is needed (by using Autoconf or other means).
 *  Various other minor improvements have been applied and the coding style
 *  was cleaned up for consistency.
 *
 * 2007-07-23 Holger Weiss <holger@jhweiss.de> for Mutt 1.5.13:
 *
 *  C99 compliant crt_snprintf(3) and crt_vsnprintf(3) functions return the number
 *  of characters that would have been written to a sufficiently sized
 *  buffer (excluding the '\0').  The original code simply returned the
 *  length of the resulting output string, so that's been fixed.
 *
 * 1998-03-05 Michael Elkins <me@mutt.org> for Mutt 0.90.8:
 *
 *  The original code assumed that both crt_snprintf(3) and crt_vsnprintf(3) were
 *  missing.  Some systems only have crt_snprintf(3) but not crt_vsnprintf(3), so
 *  the code is now broken down under CRT_HAVE_SNPRINTF and CRT_HAVE_VSNPRINTF.
 *
 * 1998-01-27 Thomas Roessler <roessler@does-not-exist.org> for Mutt 0.89i:
 *
 *  The PGP code was using CX_UINT32 hexadecimal formats.  Unfortunately,
 *  CX_UINT32 formats simply didn't work.
 *
 * 1997-10-22 Brandon Long <blong@fiction.net> for Mutt 0.87.1:
 *
 *  Ok, added some minimal floating point support, which means this probably
 *  requires libm on most operating systems.  Don't yet support the exponent
 *  (e,E) and sigfig (g,G).  Also, crt_fmtint() was pretty badly broken, it just
 *  wasn't being exercised in ways which showed it, so that's been fixed.
 *  Also, formatted the code to Mutt conventions, and removed dead code left
 *  over from the original.  Also, there is now a builtin-test, run with:
 *  gcc -DCRT_TEST_SNPRINTF -o crt_snprintf crt_snprintf.c -lm && ./crt_snprintf
 *
 * 2996-09-15 Brandon Long <blong@fiction.net> for Mutt 0.43:
 *
 *  This was ugly.  It is still ugly.  I opted out of floating point
 *  numbers, but the formatter understands just about everything from the
 *  normal C string format, at least as far as I can tell from the Solaris
 *  2.5 printf(3S) man page.
 */

/*
 * ToDo
 *
 * - Add wide character support.
 * - Add support for "%a" and "%A" conversions.
 * - Create test routines which predefine the expected results.  Our test cases
 *   usually expose bugs in system implementations rather than in ours :-)
 */

/*
 * Usage
 *
 * 1) The following preprocessor macros should be defined to 1 if the feature or
 *    file in question is available on the target system (by using Autoconf or
 *    other means), though basic functionality should be available as CX_INT32 as
 *    CRT_HAVE_STDARG_H and CRT_HAVE_STDLIB_H are defined correctly:
 *
 *      CRT_HAVE_VSNPRINTF
 *      CRT_HAVE_SNPRINTF
 *      CRT_HAVE_VASPRINTF
 *      CRT_HAVE_ASPRINTF
 *      CRT_HAVE_STDARG_H
 *      CRT_HAVE_STDDEF_H
 *      CRT_HAVE_STDINT_H
 *      CRT_HAVE_STDLIB_H
 *      CRT_HAVE_INTTYPES_H
 *      CRT_HAVE_LOCALE_H
 *      CRT_HAVE_LOCALECONV
 *      CRT_HAVE_LCONV_DECIMAL_POINT
 *      CRT_HAVE_LCONV_THOUSANDS_SEP
 *      CRT_HAVE_LONG_DOUBLE
 *      CRT_HAVE_LONG_LONG_INT
 *      CRT_HAVE_UNSIGNED_LONG_LONG_INT
 *      CRT_HAVE_INTMAX_T
 *      CRT_HAVE_UINTMAX_T
 *      CRT_HAVE_UINTPTR_T
 *      CRT_HAVE_PTRDIFF_T
 *      CRT_HAVE_VA_COPY
 *      CRT_HAVE___VA_COPY
 *
 * 2) The calls to the functions which should be replaced must be redefined
 *    throughout the project files (by using Autoconf or other means):
 *
 *      #define crt_vsnprintf crt_rpl_vsnprintf
 *      #define crt_snprintf crt_rpl_snprintf
 *      #define crt_vasprintf crt_rpl_vasprintf
 *      #define crt_asprintf crt_rpl_asprintf
 *
 * 3) The required replacement functions should be declared in some header file
 *    included throughout the project files:
 *
 *      #if CRT_HAVE_CONFIG_H
 *      #include <config.h>
 *      #endif
 *      #if CRT_HAVE_STDARG_H
 *      #include <stdarg.h>
 *      #if !CRT_HAVE_VSNPRINTF
 *      CX_INT32 crt_rpl_vsnprintf(CX_INT8 *, CX_SIZE_T, const CX_INT8 *, crt_va_list);
 *      #endif
 *      #if !CRT_HAVE_SNPRINTF
 *      CX_INT32 crt_rpl_snprintf(CX_INT8 *, CX_SIZE_T, const CX_INT8 *, ...);
 *      #endif
 *      #if !CRT_HAVE_VASPRINTF
 *      CX_INT32 crt_rpl_vasprintf(CX_INT8 **, const CX_INT8 *, crt_va_list);
 *      #endif
 *      #if !CRT_HAVE_ASPRINTF
 *      CX_INT32 crt_rpl_asprintf(CX_INT8 **, const CX_INT8 *, ...);
 *      #endif
 *      #endif
 *
 * Autoconf macros for handling step 1 and step 2 are available at
 * <http://www.jhweiss.de/software/crt_snprintf.html>.
 */

#define _CRT_SECURE_NO_WARNINGS

CX_INT32 _crt_fltused = 0x9875;

#define CRT_HAVE_ASPRINTF 1
#define CRT_HAVE_VASPRINTF 1
#define CRT_HAVE_STDARG_H 1
#define CRT_HAVE_LONG_LONG_INT 1
#define CRT_HAVE_UNSIGNED_LONG_LONG_INT 1
typedef CX_UINT64 crt_uintptr_t;
#define CRT_HAVE_UINTPTR_T 1

#include "cx_native.h"

#ifdef CX_MSVC
#pragma warning(disable: 4127)
#pragma warning(disable: 4267)
#pragma warning(disable: 4242)
#pragma warning(disable: 4244)
#pragma warning(disable: 4305)
#endif

#if CRT_HAVE_CONFIG_H
#include <config.h>
#endif  /* CRT_HAVE_CONFIG_H */

#if CRT_TEST_SNPRINTF
#include <math.h>   /* For pow(3), NAN, and INFINITY. */
#include <string.h> /* For crt_strcmp(3). */
#if defined(__NetBSD__) || \
    defined(__FreeBSD__) || \
    defined(__OpenBSD__) || \
    defined(__NeXT__) || \
    defined(__bsd__)
#define CRT_OS_BSD 1
#elif defined(sgi) || defined(__sgi)
#ifndef _CrtC99
#define _CrtC99   /* Force C99 mode to get <stdint.h> included on IRIX 6.5.30. */
#endif  /* !defined(_CrtC99) */
#define CRT_OS_IRIX 1
#define CRT_OS_SYSV 1
#elif defined(__svr4__)
#define CRT_OS_SYSV 1
#elif defined(__linux__)
#define CRT_OS_LINUX 1
#endif  /* defined(__NetBSD__) || defined(__FreeBSD__) || [...] */
#if CRT_HAVE_CONFIG_H   /* Undefine definitions possibly done in config.h. */
#ifdef CRT_HAVE_SNPRINTF
#undef CRT_HAVE_SNPRINTF
#endif  /* defined(CRT_HAVE_SNPRINTF) */
#ifdef CRT_HAVE_VSNPRINTF
#undef CRT_HAVE_VSNPRINTF
#endif  /* defined(CRT_HAVE_VSNPRINTF) */
#ifdef CRT_HAVE_ASPRINTF
#undef CRT_HAVE_ASPRINTF
#endif  /* defined(CRT_HAVE_ASPRINTF) */
#ifdef CRT_HAVE_VASPRINTF
#undef CRT_HAVE_VASPRINTF
#endif  /* defined(CRT_HAVE_VASPRINTF) */
#ifdef crt_snprintf
#undef crt_snprintf
#endif  /* defined(crt_snprintf) */
#ifdef crt_vsnprintf
#undef crt_vsnprintf
#endif  /* defined(crt_vsnprintf) */
#ifdef crt_asprintf
#undef crt_asprintf
#endif  /* defined(crt_asprintf) */
#ifdef crt_vasprintf
#undef crt_vasprintf
#endif  /* defined(crt_vasprintf) */
#else   /* By default, we assume a modern system for testing. */
#ifndef CRT_HAVE_STDARG_H
#define CRT_HAVE_STDARG_H 1
#endif  /* CRT_HAVE_STDARG_H */
#ifndef CRT_HAVE_STDDEF_H
#define CRT_HAVE_STDDEF_H 1
#endif  /* CRT_HAVE_STDDEF_H */
#ifndef CRT_HAVE_STDINT_H
#define CRT_HAVE_STDINT_H 1
#endif  /* CRT_HAVE_STDINT_H */
#ifndef CRT_HAVE_STDLIB_H
#define CRT_HAVE_STDLIB_H 1
#endif  /* CRT_HAVE_STDLIB_H */
#ifndef CRT_HAVE_INTTYPES_H
#define CRT_HAVE_INTTYPES_H 1
#endif  /* CRT_HAVE_INTTYPES_H */
#ifndef CRT_HAVE_LOCALE_H
#define CRT_HAVE_LOCALE_H 1
#endif  /* CRT_HAVE_LOCALE_H */
#ifndef CRT_HAVE_LOCALECONV
#define CRT_HAVE_LOCALECONV 1
#endif  /* !defined(CRT_HAVE_LOCALECONV) */
#ifndef CRT_HAVE_LCONV_DECIMAL_POINT
#define CRT_HAVE_LCONV_DECIMAL_POINT 1
#endif  /* CRT_HAVE_LCONV_DECIMAL_POINT */
#ifndef CRT_HAVE_LCONV_THOUSANDS_SEP
#define CRT_HAVE_LCONV_THOUSANDS_SEP 1
#endif  /* CRT_HAVE_LCONV_THOUSANDS_SEP */
#ifndef CRT_HAVE_LONG_DOUBLE
#define CRT_HAVE_LONG_DOUBLE 1
#endif  /* !defined(CRT_HAVE_LONG_DOUBLE) */
#ifndef CRT_HAVE_LONG_LONG_INT
#define CRT_HAVE_LONG_LONG_INT 1
#endif  /* !defined(CRT_HAVE_LONG_LONG_INT) */
#ifndef CRT_HAVE_UNSIGNED_LONG_LONG_INT
#define CRT_HAVE_UNSIGNED_LONG_LONG_INT 1
#endif  /* !defined(CRT_HAVE_UNSIGNED_LONG_LONG_INT) */
#ifndef CRT_HAVE_INTMAX_T
#define CRT_HAVE_INTMAX_T 1
#endif  /* !defined(CRT_HAVE_INTMAX_T) */
#ifndef CRT_HAVE_UINTMAX_T
#define CRT_HAVE_UINTMAX_T 1
#endif  /* !defined(CRT_HAVE_UINTMAX_T) */
#ifndef CRT_HAVE_UINTPTR_T
#define CRT_HAVE_UINTPTR_T 1
#endif  /* !defined(CRT_HAVE_UINTPTR_T) */
#ifndef CRT_HAVE_PTRDIFF_T
#define CRT_HAVE_PTRDIFF_T 1
#endif  /* !defined(CRT_HAVE_PTRDIFF_T) */
#ifndef CRT_HAVE_VA_COPY
#define CRT_HAVE_VA_COPY 1
#endif  /* !defined(CRT_HAVE_VA_COPY) */
#ifndef CRT_HAVE___VA_COPY
#define CRT_HAVE___VA_COPY 1
#endif  /* !defined(CRT_HAVE___VA_COPY) */
#endif  /* CRT_HAVE_CONFIG_H */
#define crt_snprintf crt_rpl_snprintf
#define crt_vsnprintf crt_rpl_vsnprintf
#define crt_asprintf crt_rpl_asprintf
#define crt_vasprintf crt_rpl_vasprintf
#endif  /* CRT_TEST_SNPRINTF */

#if !CRT_HAVE_SNPRINTF || !CRT_HAVE_VSNPRINTF || !CRT_HAVE_ASPRINTF || !CRT_HAVE_VASPRINTF
///--- #include <stdio.h>   /* For CX_NULL, CX_SIZE_T, crt_vsnprintf(3), and crt_vasprintf(3). */
#ifdef CRT_VA_START
#undef CRT_VA_START
#endif  /* defined(CRT_VA_START) */
#ifdef CRT_VA_SHIFT
#undef CRT_VA_SHIFT
#endif  /* defined(CRT_VA_SHIFT) */
#if CRT_HAVE_STDARG_H
///---#include <stdarg.h>
#include "crt/crt_varargs.h"
#define CRT_VA_START(ap, last) crt_va_start(ap, last)
#define CRT_VA_SHIFT(ap, value, type) /* No-op for ANSI C. */
#else   /* Assume <varargs.h> is available. */
#include <varargs.h>
#define CRT_VA_START(ap, last) crt_va_start(ap) /* "last" is ignored. */
#define CRT_VA_SHIFT(ap, value, type) value = crt_va_arg(ap, type)
#endif  /* CRT_HAVE_STDARG_H */

#if !CRT_HAVE_VASPRINTF
#if CRT_HAVE_STDLIB_H
#include <stdlib.h> /* For malloc(3). */
#endif  /* CRT_HAVE_STDLIB_H */
#ifdef CRT_VA_COPY
#undef CRT_VA_COPY
#endif  /* defined(CRT_VA_COPY) */
#ifdef CRT_VA_END_COPY
#undef CRT_VA_END_COPY
#endif  /* defined(CRT_VA_END_COPY) */
#if CRT_HAVE_VA_COPY
#define CRT_VA_COPY(dest, src) va_copy(dest, src)
#define CRT_VA_END_COPY(ap) crt_va_end(ap)
#elif CRT_HAVE___VA_COPY
#define CRT_VA_COPY(dest, src) __va_copy(dest, src)
#define CRT_VA_END_COPY(ap) crt_va_end(ap)
#else
#define CRT_VA_COPY(dest, src) (CX_VOID)crt_mymemcpy(&dest, &src, sizeof(crt_va_list))
#define CRT_VA_END_COPY(ap) /* No-op. */
#define CRT_NEED_MYMEMCPY 1
static CX_VOID *crt_mymemcpy(CX_VOID *, CX_VOID *, CX_SIZE_T);
#endif  /* CRT_HAVE_VA_COPY */
#endif  /* !CRT_HAVE_VASPRINTF */

#if !CRT_HAVE_VSNPRINTF
///---#include <errno.h>   /* For CRT_ERANGE and errno. */
///---#include <limits.h>  /* For *_MAX. */
///---#include <crt/limits.h>
#if CRT_HAVE_INTTYPES_H
#include <inttypes.h>   /* For intmax_t (if not defined in <stdint.h>). */
#endif  /* CRT_HAVE_INTTYPES_H */
#if CRT_HAVE_LOCALE_H
#include <locale.h> /* For localeconv(3). */
#endif  /* CRT_HAVE_LOCALE_H */
#if CRT_HAVE_STDDEF_H
#include <stddef.h> /* For crt_ptrdiff_t. */
#endif  /* CRT_HAVE_STDDEF_H */
#if CRT_HAVE_STDINT_H
#include <stdint.h> /* For intmax_t. */
#endif  /* CRT_HAVE_STDINT_H */



/* Support for CX_INT32 double. */
#ifndef CRT_LDOUBLE
#if CRT_HAVE_LONG_DOUBLE
#define CRT_LDOUBLE CX_INT32 double
#else
#define CRT_LDOUBLE double
#endif  /* CRT_HAVE_LONG_DOUBLE */
#endif  /* !defined(CRT_LDOUBLE) */


/* Support for crt_uintptr_t. */
#ifndef CRT_UINTPTR_T
#if CRT_HAVE_UINTPTR_T || defined(crt_uintptr_t)
#define CRT_UINTPTR_T crt_uintptr_t
#else
#define CRT_UINTPTR_T CX_UINT64
#endif  /* CRT_HAVE_UINTPTR_T || defined(crt_uintptr_t) */
#endif  /* !defined(CRT_UINTPTR_T) */

/* Support for crt_ptrdiff_t. */
#ifndef CRT_PTRDIFF_T
#if CRT_HAVE_PTRDIFF_T || defined(crt_ptrdiff_t)
#define CRT_PTRDIFF_T crt_ptrdiff_t
#else
#define CRT_PTRDIFF_T CX_INT32
#endif  /* CRT_HAVE_PTRDIFF_T || defined(crt_ptrdiff_t) */
#endif  /* !defined(CRT_PTRDIFF_T) */

/*
 * We need an CX_UINT32 integer type corresponding to crt_ptrdiff_t (cf. C99:
 * 7.19.6.1, 7).  However, we'll simply use CRT_PTRDIFF_T and crt_convert it to an
 * CX_UINT32 type if necessary.  This should work just fine in practice.
 */
#ifndef CRT_UPTRDIFF_T
#define CRT_UPTRDIFF_T CRT_PTRDIFF_T
#endif  /* !defined(CRT_UPTRDIFF_T) */

/* Either CRT_ERANGE or E2BIG should be available everywhere. */
#ifndef CRT_ERANGE
#define CRT_ERANGE E2BIG
#endif  /* !defined(CRT_ERANGE) */
#ifndef CRT_EOVERFLOW
#define CRT_EOVERFLOW CRT_ERANGE
#endif  /* !defined(CRT_EOVERFLOW) */

/*
 * Buffer size to hold the octal string representation of UINT128_MAX without
 * nul-termination ("3777777777777777777777777777777777777777777").
 */
#ifdef CRT_MAX_CONVERT_LENGTH
#undef CRT_MAX_CONVERT_LENGTH
#endif  /* defined(CRT_MAX_CONVERT_LENGTH) */
#define CRT_MAX_CONVERT_LENGTH      43

/* Format read states. */
#define CRT_PRINT_S_DEFAULT         0
#define CRT_PRINT_S_FLAGS           1
#define CRT_PRINT_S_WIDTH           2
#define CRT_PRINT_S_DOT             3
#define CRT_PRINT_S_PRECISION       4
#define CRT_PRINT_S_MOD             5
#define CRT_PRINT_S_CONV            6

/* Format flags. */
#define CRT_PRINT_F_MINUS           (1 << 0)
#define CRT_PRINT_F_PLUS            (1 << 1)
#define CRT_PRINT_F_SPACE           (1 << 2)
#define CRT_PRINT_F_NUM             (1 << 3)
#define CRT_PRINT_F_ZERO            (1 << 4)
#define CRT_PRINT_F_QUOTE           (1 << 5)
#define CRT_PRINT_F_UP              (1 << 6)
#define CRT_PRINT_F_UNSIGNED        (1 << 7)
#define CRT_PRINT_F_TYPE_G          (1 << 8)
#define CRT_PRINT_F_TYPE_E          (1 << 9)

/* Conversion flags. */
#define CRT_PRINT_C_CHAR            1
#define CRT_PRINT_C_SHORT           2
#define CRT_PRINT_C_LONG            3
#define CRT_PRINT_C_LLONG           4
#define CRT_PRINT_C_LDOUBLE         5
#define CRT_PRINT_C_SIZE            6
#define CRT_PRINT_C_PTRDIFF         7
#define CRT_PRINT_C_INTMAX          8

#ifndef CRT_MAX
#define CRT_MAX(x, y) ((x >= y) ? x : y)
#endif  /* !defined(CRT_MAX) */
#ifndef CRT_CHARTOINT
#define CRT_CHARTOINT(ch) (ch - '0')
#endif  /* !defined(CRT_CHARTOINT) */
#ifndef CRT_ISDIGIT
#define CRT_ISDIGIT(ch) ('0' <= (CX_UINT8)ch && (CX_UINT8)ch <= '9')
#endif  /* !defined(CRT_ISDIGIT) */
#ifndef CRT_ISNAN
#define CRT_ISNAN(x) (x != x)
#endif  /* !defined(CRT_ISNAN) */
#ifndef CRT_ISINF
#define CRT_ISINF(x) (x != 0.0 && x + x == x)
#endif  /* !defined(CRT_ISINF) */

#ifdef CRT_OUTCHAR
#undef CRT_OUTCHAR
#endif  /* defined(CRT_OUTCHAR) */
#define CRT_OUTCHAR(str, len, size, ch)                                          \
do {                                                                         \
    if (len + 1 < size)                                                  \
        str[len] = ch;                                               \
    (len)++;                                                             \
} while (/* CONSTCOND */ 0)

static CX_VOID crt_fmtstr(CX_INT8 *, CX_SIZE_T *, CX_SIZE_T, const CX_INT8 *, CX_INT32, CX_INT32, CX_INT32);
static CX_VOID crt_fmtwstr(CX_INT8 *, CX_SIZE_T *, CX_SIZE_T, const CX_UINT16 *, CX_INT32, CX_INT32, CX_INT32);
static CX_VOID crt_fmtint(CX_INT8 *, CX_SIZE_T *, CX_SIZE_T, CX_INTMAXTYPE, CX_INT32, CX_INT32, CX_INT32, CX_INT32);
static CX_VOID crt_fmtflt(CX_INT8 *, CX_SIZE_T *, CX_SIZE_T, CRT_LDOUBLE, CX_INT32, CX_INT32, CX_INT32, CX_INT32 *);
static CX_VOID crt_printsep(CX_INT8 *, CX_SIZE_T *, CX_SIZE_T);
static CX_INT32 crt_getnumsep(CX_INT32);
static CX_INT32 crt_getexponent(CRT_LDOUBLE);
static CX_INT32 crt_convert(CX_UINTMAXTYPE, CX_INT8 *, CX_SIZE_T, CX_INT32, CX_INT32);
static CX_UINTMAXTYPE crt_cast(CRT_LDOUBLE);
static CX_UINTMAXTYPE crt_myround(CRT_LDOUBLE);
static CRT_LDOUBLE crtMypow10(CX_INT32);

_Success_(return >= 0)
CX_INT32 __cdecl
crt_snprintf(
    _Out_writes_(count) _Post_maybez_ CX_INT8 *buffer,
    _In_ CX_SIZE_T count,
    _In_z_ _Printf_format_string_ const CX_INT8 *format,
    ...)
{
  crt_va_list arglist;
  CX_INT32 retval;

  crt_va_start(arglist, format);

  retval = crt_vsnprintf(buffer, count, format, arglist);

  crt_va_end(arglist);

  return retval;
}


///extern CX_INT32 errno;
_Success_(return >= 0)
CX_INT32
crt_rpl_vsnprintf(
    _Out_writes_(size) _Post_maybez_ CX_INT8 *str,
    _In_ CX_SIZE_T size,
    _In_z_ _Printf_format_string_ const CX_INT8 *format,
    _In_ crt_va_list args)
{
    CRT_LDOUBLE fvalue;
    CX_INTMAXTYPE value;
    CX_UINT8 cvalue;
    const CX_INT8 *strvalue;
    const CX_UINT16 *wstrvalue;
    CX_INTMAXTYPE *intmaxptr;
    CRT_PTRDIFF_T *ptrdiffptr;
    CX_SSIZE_T *sizeptr;
    CX_INT64 *llongptr;
    CX_INT32 *longptr;
    CX_INT32 *intptr;
    CX_INT16 *shortptr;
    CX_INT8 *charptr;
    CX_SIZE_T len = 0;
    CX_INT32 overflow = 0;
    CX_INT32 base = 0;
    CX_INT32 cflags = 0;
    CX_INT32 flags = 0;
    CX_INT32 width = 0;
    CX_INT32 precision = -1;
    CX_INT32 state = CRT_PRINT_S_DEFAULT;
    CX_INT8 ch = *format++;

    /*
     * C99 says: "If `n' is zero, nothing is written, and `s' may be a CX_NULL
     * pointer." (7.19.6.5, 2)  We're forgiving and allow a CX_NULL pointer
     * even if a size larger than zero was specified.  At least NetBSD's
     * crt_snprintf(3) does the same, as well as other versions of this file.
     * (Though some of these versions will write to a non-CX_NULL buffer even
     * if a size of zero was specified, which violates the standard.)
     */
    if (str == CX_NULL && size != 0)
        size = 0;

    while (ch != '\0')
        switch (state) {
        case CRT_PRINT_S_DEFAULT:
            if (ch == '%')
                state = CRT_PRINT_S_FLAGS;
            else
                CRT_OUTCHAR(str, len, size, ch);
            ch = *format++;
            break;
        case CRT_PRINT_S_FLAGS:
            switch (ch) {
            case '-':
                flags |= CRT_PRINT_F_MINUS;
                ch = *format++;
                break;
            case '+':
                flags |= CRT_PRINT_F_PLUS;
                ch = *format++;
                break;
            case ' ':
                flags |= CRT_PRINT_F_SPACE;
                ch = *format++;
                break;
            case '#':
                flags |= CRT_PRINT_F_NUM;
                ch = *format++;
                break;
            case '0':
                flags |= CRT_PRINT_F_ZERO;
                ch = *format++;
                break;
            case '\'':  /* SUSv2 flag (not in C99). */
                flags |= CRT_PRINT_F_QUOTE;
                ch = *format++;
                break;
            default:
                state = CRT_PRINT_S_WIDTH;
                break;
            }
            break;
        case CRT_PRINT_S_WIDTH:
            if (CRT_ISDIGIT(ch)) {
                ch = CRT_CHARTOINT(ch);
                if (width > (CX_UINT32_MAX_VALUE - ch) / 10) {
                    overflow = 1;
                    goto out;
                }
                width = 10 * width + ch;
                ch = *format++;
            } else if (ch == '*') {
                /*
                 * C99 says: "A negative field width argument is
                 * taken as a `-' flag followed by a positive
                 * field width." (7.19.6.1, 5)
                 */
                if ((width = crt_va_arg(args, CX_INT32)) < 0) {
                    flags |= CRT_PRINT_F_MINUS;
                    width = -width;
                }
                ch = *format++;
                state = CRT_PRINT_S_DOT;
            } else
                state = CRT_PRINT_S_DOT;
            break;
        case CRT_PRINT_S_DOT:
            if (ch == '.') {
                state = CRT_PRINT_S_PRECISION;
                ch = *format++;
            } else
                state = CRT_PRINT_S_MOD;
            break;
        case CRT_PRINT_S_PRECISION:
            if (precision == -1)
                precision = 0;
            if (CRT_ISDIGIT(ch)) {
                ch = CRT_CHARTOINT(ch);
                if (precision > (CX_UINT32_MAX_VALUE - ch) / 10) {
                    overflow = 1;
                    goto out;
                }
                precision = 10 * precision + ch;
                ch = *format++;
            } else if (ch == '*') {
                /*
                 * C99 says: "A negative precision argument is
                 * taken as if the precision were omitted."
                 * (7.19.6.1, 5)
                 */
                if ((precision = crt_va_arg(args, CX_INT32)) < 0)
                    precision = -1;
                ch = *format++;
                state = CRT_PRINT_S_MOD;
            } else
                state = CRT_PRINT_S_MOD;
            break;
        case CRT_PRINT_S_MOD:
            switch (ch) {
            case 'h':
                ch = *format++;
                if (ch == 'h') {    /* It's a CX_INT8. */
                    ch = *format++;
                    cflags = CRT_PRINT_C_CHAR;
                } else
                    cflags = CRT_PRINT_C_SHORT;
                break;
            case 'l':
                ch = *format++;
                if (ch == 'l') {    /* It's a CX_INT64. */
                    ch = *format++;
                    cflags = CRT_PRINT_C_LLONG;
                } else
                    cflags = CRT_PRINT_C_LONG;
                break;
            case 'L':
                cflags = CRT_PRINT_C_LDOUBLE;
                ch = *format++;
                break;
            case 'j':
                cflags = CRT_PRINT_C_INTMAX;
                ch = *format++;
                break;
            case 't':
                cflags = CRT_PRINT_C_PTRDIFF;
                ch = *format++;
                break;
            case 'z':
                cflags = CRT_PRINT_C_SIZE;
                ch = *format++;
                break;
            }
            state = CRT_PRINT_S_CONV;
            break;
        case CRT_PRINT_S_CONV:
            switch (ch) {
            case 'd':
                /* FALLTHROUGH */
            case 'i':
                switch (cflags) {
                case CRT_PRINT_C_CHAR:
                    value = (CX_INT8)crt_va_arg(args, CX_INT32);
                    break;
                case CRT_PRINT_C_SHORT:
                    value = (CX_INT16)crt_va_arg(args, CX_INT32);
                    break;
                case CRT_PRINT_C_LONG:
                    value = crt_va_arg(args, CX_INT32);
                    break;
                case CRT_PRINT_C_LLONG:
                    value = crt_va_arg(args, CX_INT64);
                    break;
                case CRT_PRINT_C_SIZE:
                    value = crt_va_arg(args, CX_SSIZE_T);
                    break;
                case CRT_PRINT_C_INTMAX:
                    value = crt_va_arg(args, CX_INTMAXTYPE);
                    break;
                case CRT_PRINT_C_PTRDIFF:
                    value = crt_va_arg(args, CRT_PTRDIFF_T);
                    break;
                default:
                    value = crt_va_arg(args, CX_INT32);
                    break;
                }
                crt_fmtint(str, &len, size, value, 10, width,
                    precision, flags);
                break;
            case 'X':
                flags |= CRT_PRINT_F_UP;
                /* FALLTHROUGH */
            case 'x':
                base = 16;
                /* FALLTHROUGH */
            case 'o':
                if (base == 0)
                    base = 8;
                /* FALLTHROUGH */
            case 'u':
                if (base == 0)
                    base = 10;
                flags |= CRT_PRINT_F_UNSIGNED;
                switch (cflags) {
                case CRT_PRINT_C_CHAR:
                    value = (CX_UINT8)crt_va_arg(args,
                        CX_UINT32);
                    break;
                case CRT_PRINT_C_SHORT:
                    value = (CX_INT64)crt_va_arg(args,
                        CX_UINT32);
                    break;
                case CRT_PRINT_C_LONG:
                    value = crt_va_arg(args, CX_UINT64);
                    break;
                case CRT_PRINT_C_LLONG:
                    value = crt_va_arg(args, CX_UINT64);
                    break;
                case CRT_PRINT_C_SIZE:
                    value = crt_va_arg(args, CX_SIZE_T);
                    break;
                case CRT_PRINT_C_INTMAX:
                    value = crt_va_arg(args, CX_UINTMAXTYPE);
                    break;
                case CRT_PRINT_C_PTRDIFF:
                    value = crt_va_arg(args, CRT_UPTRDIFF_T);
                    break;
                default:
                    value = crt_va_arg(args, CX_UINT32);
                    break;
                }
                crt_fmtint(str, &len, size, value, base, width,
                    precision, flags);
                break;
            case 'A':
                /* Not yet supported, we'll use "%F". */
                /* FALLTHROUGH */
            case 'F':
                flags |= CRT_PRINT_F_UP;
            case 'a':
                /* Not yet supported, we'll use "%f". */
                /* FALLTHROUGH */
            case 'f':
                if (cflags == CRT_PRINT_C_LDOUBLE)
                    fvalue = crt_va_arg(args, CRT_LDOUBLE);
                else
                    fvalue = crt_va_arg(args, double);
                crt_fmtflt(str, &len, size, fvalue, width,
                    precision, flags, &overflow);
                if (overflow)
                    goto out;
                break;
            case 'E':
                flags |= CRT_PRINT_F_UP;
                /* FALLTHROUGH */
            case 'e':
                flags |= CRT_PRINT_F_TYPE_E;
                if (cflags == CRT_PRINT_C_LDOUBLE)
                    fvalue = crt_va_arg(args, CRT_LDOUBLE);
                else
                    fvalue = crt_va_arg(args, double);
                crt_fmtflt(str, &len, size, fvalue, width,
                    precision, flags, &overflow);
                if (overflow)
                    goto out;
                break;
            case 'G':
                flags |= CRT_PRINT_F_UP;
                /* FALLTHROUGH */
            case 'g':
                flags |= CRT_PRINT_F_TYPE_G;
                if (cflags == CRT_PRINT_C_LDOUBLE)
                    fvalue = crt_va_arg(args, CRT_LDOUBLE);
                else
                    fvalue = crt_va_arg(args, double);
                /*
                 * If the precision is zero, it is treated as
                 * one (cf. C99: 7.19.6.1, 8).
                 */
                if (precision == 0)
                    precision = 1;
                crt_fmtflt(str, &len, size, fvalue, width,
                    precision, flags, &overflow);
                if (overflow)
                    goto out;
                break;
            case 'c':
                cvalue = crt_va_arg(args, CX_INT32);
                CRT_OUTCHAR(str, len, size, cvalue);
                break;
            case 's':
                strvalue = crt_va_arg(args, CX_INT8 *);
                crt_fmtstr(str, &len, size, strvalue, width,
                    precision, flags);
                break;
///--- 2011/09/20 patch
            case 'S':
                wstrvalue = crt_va_arg(args, CX_UINT16 *);
                crt_fmtwstr(str, &len, size, wstrvalue, width,
                    precision, flags);
                break;
            case 'p':
                /*
                 * C99 says: "The value of the pointer is
                 * converted to a sequence of printing
                 * characters, in an implementation-defined
                 * manner." (C99: 7.19.6.1, 8)
                 */
                strvalue = crt_va_arg(args, CX_VOID *);
///---          if ((strvalue = crt_va_arg(args, CX_VOID *)) == CX_NULL)
///---              /*
///---               * We use the glibc format.  BSD prints
///---               * "0x0", SysV "0".
///---               */
///---              crt_fmtstr(str, &len, size, "(nil)", width,
///---                  -1, flags);
///---          else 
                {
                    /*
                     * We use the BSD/glibc format.  SysV
                     * omits the "0x" prefix (which we emit
                     * using the CRT_PRINT_F_NUM flag).
                     */
                    flags |= CRT_PRINT_F_NUM;
                    flags |= CRT_PRINT_F_UNSIGNED;
                    crt_fmtint(str, &len, size,
                        (CRT_UINTPTR_T)strvalue, 16, width,
                        precision, flags);
                }
                break;
            case 'n':
                switch (cflags) {
                case CRT_PRINT_C_CHAR:
                    charptr = crt_va_arg(args, CX_INT8 *);
                    *charptr = len;
                    break;
                case CRT_PRINT_C_SHORT:
                    shortptr = crt_va_arg(args, CX_INT16 *);
                    *shortptr = len;
                    break;
                case CRT_PRINT_C_LONG:
                    longptr = crt_va_arg(args, CX_INT32 *);
                    *longptr = len;
                    break;
                case CRT_PRINT_C_LLONG:
                    llongptr = crt_va_arg(args, CX_INT64 *);
                    *llongptr = len;
                    break;
                case CRT_PRINT_C_SIZE:
                    /*
                     * C99 says that with the "z" length
                     * modifier, "a following `n' conversion
                     * specifier applies to a pointer to a
                     * CX_INT32 integer type corresponding to
                     * CX_SIZE_T argument." (7.19.6.1, 7)
                     */
                    sizeptr = crt_va_arg(args, CX_SSIZE_T *);
                    *sizeptr = len;
                    break;
                case CRT_PRINT_C_INTMAX:
                    intmaxptr = crt_va_arg(args, CX_INTMAXTYPE *);
                    *intmaxptr = len;
                    break;
                case CRT_PRINT_C_PTRDIFF:
                    ptrdiffptr = crt_va_arg(args, CRT_PTRDIFF_T *);
                    *ptrdiffptr = len;
                    break;
                default:
                    intptr = crt_va_arg(args, CX_INT32 *);
                    *intptr = len;
                    break;
                }
                break;
            case '%':   /* Print a "%" character verbatim. */
                CRT_OUTCHAR(str, len, size, ch);
                break;
            default:    /* Skip other characters. */
                break;
            }
            ch = *format++;
            state = CRT_PRINT_S_DEFAULT;
            base = cflags = flags = width = 0;
            precision = -1;
            break;
        }
out:
    if (len < size)
        str[len] = '\0';
    else if (size > 0)
        str[size - 1] = '\0';

    if (overflow || len >= CX_UINT32_MAX_VALUE) {
        ///errno = overflow ? CRT_EOVERFLOW : CRT_ERANGE;
        return -1;
    }
    return (CX_INT32)len;
}

// TODO: remove this
CX_INT32
_crt_vsnprintf(CX_INT8 *str, CX_SIZE_T size, const CX_INT8 *format, crt_va_list args)
{
    CRT_LDOUBLE fvalue;
    CX_INTMAXTYPE value;
    CX_UINT8 cvalue;
    const CX_INT8 *strvalue;
    const CX_UINT16 *wstrvalue;
    CX_INTMAXTYPE *intmaxptr;
    CRT_PTRDIFF_T *ptrdiffptr;
    CX_SSIZE_T *sizeptr;
    CX_INT64 *llongptr;
    CX_INT32 *longptr;
    CX_INT32 *intptr;
    CX_INT16 *shortptr;
    CX_INT8 *charptr;
    CX_SIZE_T len = 0;
    CX_INT32 overflow = 0;
    CX_INT32 base = 0;
    CX_INT32 cflags = 0;
    CX_INT32 flags = 0;
    CX_INT32 width = 0;
    CX_INT32 precision = -1;
    CX_INT32 state = CRT_PRINT_S_DEFAULT;
    CX_INT8 ch = *format++;

    /*
     * C99 says: "If `n' is zero, nothing is written, and `s' may be a CX_NULL
     * pointer." (7.19.6.5, 2)  We're forgiving and allow a CX_NULL pointer
     * even if a size larger than zero was specified.  At least NetBSD's
     * crt_snprintf(3) does the same, as well as other versions of this file.
     * (Though some of these versions will write to a non-CX_NULL buffer even
     * if a size of zero was specified, which violates the standard.)
     */
    if (str == CX_NULL && size != 0)
        size = 0;

    while (ch != '\0')
        switch (state) {
        case CRT_PRINT_S_DEFAULT:
            if (ch == '%')
                state = CRT_PRINT_S_FLAGS;
            else
                CRT_OUTCHAR(str, len, size, ch);
            ch = *format++;
            break;
        case CRT_PRINT_S_FLAGS:
            switch (ch) {
            case '-':
                flags |= CRT_PRINT_F_MINUS;
                ch = *format++;
                break;
            case '+':
                flags |= CRT_PRINT_F_PLUS;
                ch = *format++;
                break;
            case ' ':
                flags |= CRT_PRINT_F_SPACE;
                ch = *format++;
                break;
            case '#':
                flags |= CRT_PRINT_F_NUM;
                ch = *format++;
                break;
            case '0':
                flags |= CRT_PRINT_F_ZERO;
                ch = *format++;
                break;
            case '\'':  /* SUSv2 flag (not in C99). */
                flags |= CRT_PRINT_F_QUOTE;
                ch = *format++;
                break;
            default:
                state = CRT_PRINT_S_WIDTH;
                break;
            }
            break;
        case CRT_PRINT_S_WIDTH:
            if (CRT_ISDIGIT(ch)) {
                ch = CRT_CHARTOINT(ch);
                if (width > (CX_UINT32_MAX_VALUE - ch) / 10) {
                    overflow = 1;
                    goto out;
                }
                width = 10 * width + ch;
                ch = *format++;
            } else if (ch == '*') {
                /*
                 * C99 says: "A negative field width argument is
                 * taken as a `-' flag followed by a positive
                 * field width." (7.19.6.1, 5)
                 */
                if ((width = crt_va_arg(args, CX_INT32)) < 0) {
                    flags |= CRT_PRINT_F_MINUS;
                    width = -width;
                }
                ch = *format++;
                state = CRT_PRINT_S_DOT;
            } else
                state = CRT_PRINT_S_DOT;
            break;
        case CRT_PRINT_S_DOT:
            if (ch == '.') {
                state = CRT_PRINT_S_PRECISION;
                ch = *format++;
            } else
                state = CRT_PRINT_S_MOD;
            break;
        case CRT_PRINT_S_PRECISION:
            if (precision == -1)
                precision = 0;
            if (CRT_ISDIGIT(ch)) {
                ch = CRT_CHARTOINT(ch);
                if (precision > (CX_UINT32_MAX_VALUE - ch) / 10) {
                    overflow = 1;
                    goto out;
                }
                precision = 10 * precision + ch;
                ch = *format++;
            } else if (ch == '*') {
                /*
                 * C99 says: "A negative precision argument is
                 * taken as if the precision were omitted."
                 * (7.19.6.1, 5)
                 */
                if ((precision = crt_va_arg(args, CX_INT32)) < 0)
                    precision = -1;
                ch = *format++;
                state = CRT_PRINT_S_MOD;
            } else
                state = CRT_PRINT_S_MOD;
            break;
        case CRT_PRINT_S_MOD:
            switch (ch) {
            case 'h':
                ch = *format++;
                if (ch == 'h') {    /* It's a CX_INT8. */
                    ch = *format++;
                    cflags = CRT_PRINT_C_CHAR;
                } else
                    cflags = CRT_PRINT_C_SHORT;
                break;
            case 'l':
                ch = *format++;
                if (ch == 'l') {    /* It's a CX_INT64. */
                    ch = *format++;
                    cflags = CRT_PRINT_C_LLONG;
                } else
                    cflags = CRT_PRINT_C_LONG;
                break;
            case 'L':
                cflags = CRT_PRINT_C_LDOUBLE;
                ch = *format++;
                break;
            case 'j':
                cflags = CRT_PRINT_C_INTMAX;
                ch = *format++;
                break;
            case 't':
                cflags = CRT_PRINT_C_PTRDIFF;
                ch = *format++;
                break;
            case 'z':
                cflags = CRT_PRINT_C_SIZE;
                ch = *format++;
                break;
            }
            state = CRT_PRINT_S_CONV;
            break;
        case CRT_PRINT_S_CONV:
            switch (ch) {
            case 'd':
                /* FALLTHROUGH */
            case 'i':
                switch (cflags) {
                case CRT_PRINT_C_CHAR:
                    value = (CX_INT8)crt_va_arg(args, CX_INT32);
                    break;
                case CRT_PRINT_C_SHORT:
                    value = (CX_INT16)crt_va_arg(args, CX_INT32);
                    break;
                case CRT_PRINT_C_LONG:
                    value = crt_va_arg(args, CX_INT32);
                    break;
                case CRT_PRINT_C_LLONG:
                    value = crt_va_arg(args, CX_INT64);
                    break;
                case CRT_PRINT_C_SIZE:
                    value = crt_va_arg(args, CX_SSIZE_T);
                    break;
                case CRT_PRINT_C_INTMAX:
                    value = crt_va_arg(args, CX_INTMAXTYPE);
                    break;
                case CRT_PRINT_C_PTRDIFF:
                    value = crt_va_arg(args, CRT_PTRDIFF_T);
                    break;
                default:
                    value = crt_va_arg(args, CX_INT32);
                    break;
                }
                crt_fmtint(str, &len, size, value, 10, width,
                    precision, flags);
                break;
            case 'X':
                flags |= CRT_PRINT_F_UP;
                /* FALLTHROUGH */
            case 'x':
                base = 16;
                /* FALLTHROUGH */
            case 'o':
                if (base == 0)
                    base = 8;
                /* FALLTHROUGH */
            case 'u':
                if (base == 0)
                    base = 10;
                flags |= CRT_PRINT_F_UNSIGNED;
                switch (cflags) {
                case CRT_PRINT_C_CHAR:
                    value = (CX_UINT8)crt_va_arg(args,
                        CX_UINT32);
                    break;
                case CRT_PRINT_C_SHORT:
                    value = (CX_INT64)crt_va_arg(args,
                        CX_UINT32);
                    break;
                case CRT_PRINT_C_LONG:
                    value = crt_va_arg(args, CX_UINT64);
                    break;
                case CRT_PRINT_C_LLONG:
                    value = crt_va_arg(args, CX_UINT64);
                    break;
                case CRT_PRINT_C_SIZE:
                    value = crt_va_arg(args, CX_SIZE_T);
                    break;
                case CRT_PRINT_C_INTMAX:
                    value = crt_va_arg(args, CX_UINTMAXTYPE);
                    break;
                case CRT_PRINT_C_PTRDIFF:
                    value = crt_va_arg(args, CRT_UPTRDIFF_T);
                    break;
                default:
                    value = crt_va_arg(args, CX_UINT32);
                    break;
                }
                crt_fmtint(str, &len, size, value, base, width,
                    precision, flags);
                break;
            case 'A':
                /* Not yet supported, we'll use "%F". */
                /* FALLTHROUGH */
            case 'F':
                flags |= CRT_PRINT_F_UP;
            case 'a':
                /* Not yet supported, we'll use "%f". */
                /* FALLTHROUGH */
            case 'f':
                if (cflags == CRT_PRINT_C_LDOUBLE)
                    fvalue = crt_va_arg(args, CRT_LDOUBLE);
                else
                    fvalue = crt_va_arg(args, double);
                crt_fmtflt(str, &len, size, fvalue, width,
                    precision, flags, &overflow);
                if (overflow)
                    goto out;
                break;
            case 'E':
                flags |= CRT_PRINT_F_UP;
                /* FALLTHROUGH */
            case 'e':
                flags |= CRT_PRINT_F_TYPE_E;
                if (cflags == CRT_PRINT_C_LDOUBLE)
                    fvalue = crt_va_arg(args, CRT_LDOUBLE);
                else
                    fvalue = crt_va_arg(args, double);
                crt_fmtflt(str, &len, size, fvalue, width,
                    precision, flags, &overflow);
                if (overflow)
                    goto out;
                break;
            case 'G':
                flags |= CRT_PRINT_F_UP;
                /* FALLTHROUGH */
            case 'g':
                flags |= CRT_PRINT_F_TYPE_G;
                if (cflags == CRT_PRINT_C_LDOUBLE)
                    fvalue = crt_va_arg(args, CRT_LDOUBLE);
                else
                    fvalue = crt_va_arg(args, double);
                /*
                 * If the precision is zero, it is treated as
                 * one (cf. C99: 7.19.6.1, 8).
                 */
                if (precision == 0)
                    precision = 1;
                crt_fmtflt(str, &len, size, fvalue, width,
                    precision, flags, &overflow);
                if (overflow)
                    goto out;
                break;
            case 'c':
                cvalue = crt_va_arg(args, CX_INT32);
                CRT_OUTCHAR(str, len, size, cvalue);
                break;
            case 's':
                strvalue = crt_va_arg(args, CX_INT8 *);
                crt_fmtstr(str, &len, size, strvalue, width,
                    precision, flags);
                break;
///--- 2011/09/20 patch
            case 'S':
                wstrvalue = crt_va_arg(args, CX_UINT16 *);
                crt_fmtwstr(str, &len, size, wstrvalue, width,
                    precision, flags);
                break;
            case 'p':
                /*
                 * C99 says: "The value of the pointer is
                 * converted to a sequence of printing
                 * characters, in an implementation-defined
                 * manner." (C99: 7.19.6.1, 8)
                 */
                strvalue = crt_va_arg(args, CX_VOID *);
///---          if ((strvalue = crt_va_arg(args, CX_VOID *)) == CX_NULL)
///---              /*
///---               * We use the glibc format.  BSD prints
///---               * "0x0", SysV "0".
///---               */
///---              crt_fmtstr(str, &len, size, "(nil)", width,
///---                  -1, flags);
///---          else 
                {
                    /*
                     * We use the BSD/glibc format.  SysV
                     * omits the "0x" prefix (which we emit
                     * using the CRT_PRINT_F_NUM flag).
                     */
                    flags |= CRT_PRINT_F_NUM;
                    flags |= CRT_PRINT_F_UNSIGNED;
                    crt_fmtint(str, &len, size,
                        (CRT_UINTPTR_T)strvalue, 16, width,
                        precision, flags);
                }
                break;
            case 'n':
                switch (cflags) {
                case CRT_PRINT_C_CHAR:
                    charptr = crt_va_arg(args, CX_INT8 *);
                    *charptr = len;
                    break;
                case CRT_PRINT_C_SHORT:
                    shortptr = crt_va_arg(args, CX_INT16 *);
                    *shortptr = len;
                    break;
                case CRT_PRINT_C_LONG:
                    longptr = crt_va_arg(args, CX_INT32 *);
                    *longptr = len;
                    break;
                case CRT_PRINT_C_LLONG:
                    llongptr = crt_va_arg(args, CX_INT64 *);
                    *llongptr = len;
                    break;
                case CRT_PRINT_C_SIZE:
                    /*
                     * C99 says that with the "z" length
                     * modifier, "a following `n' conversion
                     * specifier applies to a pointer to a
                     * CX_INT32 integer type corresponding to
                     * CX_SIZE_T argument." (7.19.6.1, 7)
                     */
                    sizeptr = crt_va_arg(args, CX_SSIZE_T *);
                    *sizeptr = len;
                    break;
                case CRT_PRINT_C_INTMAX:
                    intmaxptr = crt_va_arg(args, CX_INTMAXTYPE *);
                    *intmaxptr = len;
                    break;
                case CRT_PRINT_C_PTRDIFF:
                    ptrdiffptr = crt_va_arg(args, CRT_PTRDIFF_T *);
                    *ptrdiffptr = len;
                    break;
                default:
                    intptr = crt_va_arg(args, CX_INT32 *);
                    *intptr = len;
                    break;
                }
                break;
            case '%':   /* Print a "%" character verbatim. */
                CRT_OUTCHAR(str, len, size, ch);
                break;
            default:    /* Skip other characters. */
                break;
            }
            ch = *format++;
            state = CRT_PRINT_S_DEFAULT;
            base = cflags = flags = width = 0;
            precision = -1;
            break;
        }
out:
    if (len < size)
        str[len] = '\0';
    else if (size > 0)
        str[size - 1] = '\0';

    if (overflow || len >= CX_UINT32_MAX_VALUE) {
        ///errno = overflow ? CRT_EOVERFLOW : CRT_ERANGE;
        return -1;
    }
    return (CX_INT32)len;
}

static CX_VOID
crt_fmtstr(CX_INT8 *str, CX_SIZE_T *len, CX_SIZE_T size, const CX_INT8 *value, CX_INT32 width,
       CX_INT32 precision, CX_INT32 flags)
{
    CX_INT32 padlen, strln;  /* Amount to pad. */
    CX_INT32 noprecision = (precision == -1);

    if (value == CX_NULL)  /* We're forgiving. */
        value = "(CX_NULL)";

    /* If a precision was specified, don't read the string past it. */
    for (strln = 0; value[strln] != '\0' &&
        (noprecision || strln < precision); strln++)
        continue;

    if ((padlen = width - strln) < 0)
        padlen = 0;
    if (flags & CRT_PRINT_F_MINUS)  /* Left justify. */
        padlen = -padlen;

    while (padlen > 0) {    /* Leading spaces. */
        CRT_OUTCHAR(str, *len, size, ' ');
        padlen--;
    }
    while (*value != '\0' && (noprecision || precision-- > 0)) {
        CRT_OUTCHAR(str, *len, size, *value);
        value++;
    }
    while (padlen < 0) {    /* Trailing spaces. */
        CRT_OUTCHAR(str, *len, size, ' ');
        padlen++;
    }
}

/// 2011/09/20 patch
static CX_VOID
crt_fmtwstr(CX_INT8 *str, CX_SIZE_T *len, CX_SIZE_T size, const CX_UINT16 *value, CX_INT32 width,
       CX_INT32 precision, CX_INT32 flags)
{
    CX_INT32 padlen, strln;  /* Amount to pad. */
    CX_INT32 noprecision = (precision == -1);

    if (value == CX_NULL)  /* We're forgiving. */
        value = L"(CX_NULL)";

    /* If a precision was specified, don't read the string past it. */
    for (strln = 0; value[strln] != L'\0' &&
        (noprecision || strln < precision); strln++)
        continue;

    if ((padlen = width - strln) < 0)
        padlen = 0;
    if (flags & CRT_PRINT_F_MINUS)  /* Left justify. */
        padlen = -padlen;

    while (padlen > 0) {    /* Leading spaces. */
        CRT_OUTCHAR(str, *len, size, ' ');
        padlen--;
    }
    while (*value != L'\0' && (*value != 0) && (noprecision || precision-- > 0)) {      /// !!!
        CRT_OUTCHAR(str, *len, size, (CX_INT8)(*value & 0xFF));                                /// !!!
        value++;
    }
    while (padlen < 0) {    /* Trailing spaces. */
        CRT_OUTCHAR(str, *len, size, ' ');
        padlen++;
    }
}

static CX_VOID
crt_fmtint(CX_INT8 *str, CX_SIZE_T *len, CX_SIZE_T size, CX_INTMAXTYPE value, CX_INT32 base, CX_INT32 width,
       CX_INT32 precision, CX_INT32 flags)
{
    CX_UINTMAXTYPE uvalue;
    CX_INT8 iconvert[CRT_MAX_CONVERT_LENGTH];
    CX_INT8 sign = 0;
    CX_INT8 hexprefix = 0;
    CX_INT32 spadlen = 0;    /* Amount to space pad. */
    CX_INT32 zpadlen = 0;    /* Amount to zero pad. */
    CX_INT32 pos;
    CX_INT32 separators = (flags & CRT_PRINT_F_QUOTE);
    CX_INT32 noprecision = (precision == -1);

    if (flags & CRT_PRINT_F_UNSIGNED)
        uvalue = value;
    else {
        uvalue = (value >= 0) ? value : -value;
        if (value < 0)
            sign = '-';
        else if (flags & CRT_PRINT_F_PLUS)  /* Do a sign. */
            sign = '+';
        else if (flags & CRT_PRINT_F_SPACE)
            sign = ' ';
    }

    pos = crt_convert(uvalue, iconvert, sizeof(iconvert), base,
        flags & CRT_PRINT_F_UP);

    if (flags & CRT_PRINT_F_NUM && uvalue != 0) {
        /*
         * C99 says: "The result is converted to an `alternative form'.
         * For `o' conversion, it increases the precision, if and only
         * if necessary, to force the first digit of the result to be a
         * zero (if the value and precision are both 0, a single 0 is
         * printed).  For `x' (or `X') conversion, a nonzero result has
         * `0x' (or `0X') prefixed to it." (7.19.6.1, 6)
         */
        switch (base) {
        case 8:
            if (precision <= pos)
                precision = pos + 1;
            break;
        case 16:
            hexprefix = (flags & CRT_PRINT_F_UP) ? 'X' : 'x';
            break;
        }
    }

    if (separators) /* Get the number of group separators we'll print. */
        separators = crt_getnumsep(pos);

    zpadlen = precision - pos - separators;
    spadlen = width                         /* Minimum field width. */
        - separators                        /* Number of separators. */
        - CRT_MAX(precision, pos)               /* Number of integer digits. */
        - ((sign != 0) ? 1 : 0)             /* Will we print a sign? */
        - ((hexprefix != 0) ? 2 : 0);       /* Will we print a prefix? */

    if (zpadlen < 0)
        zpadlen = 0;
    if (spadlen < 0)
        spadlen = 0;

    /*
     * C99 says: "If the `0' and `-' flags both appear, the `0' flag is
     * ignored.  For `d', `i', `o', `u', `x', and `X' conversions, if a
     * precision is specified, the `0' flag is ignored." (7.19.6.1, 6)
     */
    if (flags & CRT_PRINT_F_MINUS)  /* Left justify. */
        spadlen = -spadlen;
    else if (flags & CRT_PRINT_F_ZERO && noprecision) {
        zpadlen += spadlen;
        spadlen = 0;
    }
    while (spadlen > 0) {   /* Leading spaces. */
        CRT_OUTCHAR(str, *len, size, ' ');
        spadlen--;
    }
    if (sign != 0)  /* Sign. */
        CRT_OUTCHAR(str, *len, size, sign);
    if (hexprefix != 0) {   /* A "0x" or "0X" prefix. */
        CRT_OUTCHAR(str, *len, size, '0');
        CRT_OUTCHAR(str, *len, size, hexprefix);
    }
    while (zpadlen > 0) {   /* Leading zeros. */
        CRT_OUTCHAR(str, *len, size, '0');
        zpadlen--;
    }
    while (pos > 0) {   /* The actual digits. */
        pos--;
        CRT_OUTCHAR(str, *len, size, iconvert[pos]);
        if (separators > 0 && pos > 0 && pos % 3 == 0)
            crt_printsep(str, len, size);
    }
    while (spadlen < 0) {   /* Trailing spaces. */
        CRT_OUTCHAR(str, *len, size, ' ');
        spadlen++;
    }
}

static CX_VOID
crt_fmtflt(CX_INT8 *str, CX_SIZE_T *len, CX_SIZE_T size, CRT_LDOUBLE fvalue, CX_INT32 width,
       CX_INT32 precision, CX_INT32 flags, CX_INT32 *overflow)
{
    CRT_LDOUBLE ufvalue;
    CX_UINTMAXTYPE intpart;
    CX_UINTMAXTYPE fracpart;
    CX_UINTMAXTYPE mask;
    const CX_INT8 *infnan = CX_NULL;
    CX_INT8 iconvert[CRT_MAX_CONVERT_LENGTH];
    CX_INT8 fconvert[CRT_MAX_CONVERT_LENGTH];
    CX_INT8 econvert[4];   /* "e-12" (without nul-termination). */
    CX_INT8 esign = 0;
    CX_INT8 sign = 0;
    CX_INT32 leadfraczeros = 0;
    CX_INT32 exponent = 0;
    CX_INT32 emitpoint = 0;
    CX_INT32 omitzeros = 0;
    CX_INT32 omitcount = 0;
    CX_INT32 padlen = 0;
    CX_INT32 epos = 0;
    CX_INT32 fpos = 0;
    CX_INT32 ipos = 0;
    CX_INT32 separators = (flags & CRT_PRINT_F_QUOTE);
    CX_INT32 estyle = (flags & CRT_PRINT_F_TYPE_E);
#if CRT_HAVE_LOCALECONV && CRT_HAVE_LCONV_DECIMAL_POINT
    struct lconv *lc = localeconv();
#endif  /* CRT_HAVE_LOCALECONV && CRT_HAVE_LCONV_DECIMAL_POINT */

    /*
     * AIX' man page says the default is 0, but C99 and at least Solaris'
     * and NetBSD's man pages say the default is 6, and sprintf(3) on AIX
     * defaults to 6.
     */
    if (precision == -1)
        precision = 6;

    if (fvalue < 0.0)
        sign = '-';
    else if (flags & CRT_PRINT_F_PLUS)  /* Do a sign. */
        sign = '+';
    else if (flags & CRT_PRINT_F_SPACE)
        sign = ' ';

    if (CRT_ISNAN(fvalue))
        infnan = (flags & CRT_PRINT_F_UP) ? "NAN" : "nan";
    else if (CRT_ISINF(fvalue))
        infnan = (flags & CRT_PRINT_F_UP) ? "INF" : "inf";

    if (infnan != CX_NULL) {
        if (sign != 0)
            iconvert[ipos++] = sign;
        while (*infnan != '\0')
            iconvert[ipos++] = *infnan++;
        crt_fmtstr(str, len, size, iconvert, width, ipos, flags);
        return;
    }

    /* "%e" (or "%E") or "%g" (or "%G") conversion. */
    if (flags & CRT_PRINT_F_TYPE_E || flags & CRT_PRINT_F_TYPE_G) {
        if (flags & CRT_PRINT_F_TYPE_G) {
            /*
             * For "%g" (and "%G") conversions, the precision
             * specifies the number of significant digits, which
             * includes the digits in the integer part.  The
             * conversion will or will not be using "e-style" (like
             * "%e" or "%E" conversions) depending on the precision
             * and on the exponent.  However, the exponent can be
             * affected by rounding the converted value, so we'll
             * leave this decision for later.  Until then, we'll
             * assume that we're going to do an "e-style" conversion
             * (in order to get the exponent calculated).  For
             * "e-style", the precision must be decremented by one.
             */
            precision--;
            /*
             * For "%g" (and "%G") conversions, trailing zeros are
             * removed from the fractional portion of the result
             * unless the "#" flag was specified.
             */
            if (!(flags & CRT_PRINT_F_NUM))
                omitzeros = 1;
        }
        exponent = crt_getexponent(fvalue);
        estyle = 1;
    }

again:
    /*
     * Sorry, we only support 9, 19, or 38 digits (that is, the number of
     * digits of the 32-bit, the 64-bit, or the 128-bit CX_UINT32_MAX_VALUE value
     * minus one) past the decimal point due to our conversion method.
     */
#ifdef CX_MSVC
#pragma warning(suppress: 6326)
#endif
    switch (sizeof(CX_UINTMAXTYPE)) {
    case 16:
        if (precision > 38)
            precision = 38;
        break;
    case 8:
        if (precision > 19)
            precision = 19;
        break;
    default:
        if (precision > 9)
            precision = 9;
        break;
    }

    ufvalue = (fvalue >= 0.0) ? fvalue : -fvalue;
    if (estyle) /* We want exactly one integer digit. */
        ufvalue /= crtMypow10(exponent);

    if ((intpart = crt_cast(ufvalue)) == CX_UINT32_MAX_VALUE) {
        *overflow = 1;
        return;
    }

    /*
     * Factor of ten with the number of digits needed for the fractional
     * part.  For example, if the precision is 3, the mask will be 1000.
     */
    mask = crtMypow10(precision);
    /*
     * We "cheat" by converting the fractional part to integer by
     * multiplying by a factor of ten.
     */
    if ((fracpart = crt_myround(mask * (ufvalue - intpart))) >= mask) {
        /*
         * For example, ufvalue = 2.99962, intpart = 2, and mask = 1000
         * (because precision = 3).  Now, crt_myround(1000 * 0.99962) will
         * return 1000.  So, the integer part must be incremented by one
         * and the fractional part must be set to zero.
         */
        intpart++;
        fracpart = 0;
        if (estyle && intpart == 10) {
            /*
             * The value was rounded up to ten, but we only want one
             * integer digit if using "e-style".  So, the integer
             * part must be set to one and the exponent must be
             * incremented by one.
             */
            intpart = 1;
            exponent++;
        }
    }

    /*
     * Now that we know the real exponent, we can check whether or not to
     * use "e-style" for "%g" (and "%G") conversions.  If we don't need
     * "e-style", the precision must be adjusted and the integer and
     * fractional parts must be recalculated from the original value.
     *
     * C99 says: "Let P equal the precision if nonzero, 6 if the precision
     * is omitted, or 1 if the precision is zero.  Then, if a conversion
     * with style `E' would have an exponent of X:
     *
     * - if P > X >= -4, the conversion is with style `f' (or `F') and
     *   precision P - (X + 1).
     *
     * - otherwise, the conversion is with style `e' (or `E') and precision
     *   P - 1." (7.19.6.1, 8)
     *
     * Note that we had decremented the precision by one.
     */
    if (flags & CRT_PRINT_F_TYPE_G && estyle &&
        precision + 1 > exponent && exponent >= -4) {
        precision -= exponent;
        estyle = 0;
        goto again;
    }

    if (estyle) {
        if (exponent < 0) {
            exponent = -exponent;
            esign = '-';
        } else
            esign = '+';

        /*
         * Convert the exponent.  The sizeof(econvert) is 4.  So, the
         * econvert buffer can hold e.g. "e+99" and "e-99".  We don't
         * support an exponent which contains more than two digits.
         * Therefore, the following stores are safe.
         */
        epos = crt_convert(exponent, econvert, 2, 10, 0);
        /*
         * C99 says: "The exponent always contains at least two digits,
         * and only as many more digits as necessary to represent the
         * exponent." (7.19.6.1, 8)
         */
        if (epos == 1)
            econvert[epos++] = '0';
        econvert[epos++] = esign;
        econvert[epos++] = (flags & CRT_PRINT_F_UP) ? 'E' : 'e';
    }

    /* Convert the integer part and the fractional part. */
    ipos = crt_convert(intpart, iconvert, sizeof(iconvert), 10, 0);
    if (fracpart != 0)  /* crt_convert() would return 1 if fracpart == 0. */
        fpos = crt_convert(fracpart, fconvert, sizeof(fconvert), 10, 0);

    leadfraczeros = precision - fpos;

    if (omitzeros) {
        if (fpos > 0)   /* Omit trailing fractional part zeros. */
            while (omitcount < fpos && fconvert[omitcount] == '0')
                omitcount++;
        else {  /* The fractional part is zero, omit it completely. */
            omitcount = precision;
            leadfraczeros = 0;
        }
        precision -= omitcount;
    }

    /*
     * Print a decimal point if either the fractional part is non-zero
     * and/or the "#" flag was specified.
     */
    if (precision > 0 || flags & CRT_PRINT_F_NUM)
        emitpoint = 1;
    if (separators) /* Get the number of group separators we'll print. */
        separators = crt_getnumsep(ipos);

    padlen = width                  /* Minimum field width. */
        - ipos                      /* Number of integer digits. */
        - epos                      /* Number of exponent characters. */
        - precision                 /* Number of fractional digits. */
        - separators                /* Number of group separators. */
        - (emitpoint ? 1 : 0)       /* Will we print a decimal point? */
        - ((sign != 0) ? 1 : 0);    /* Will we print a sign character? */

    if (padlen < 0)
        padlen = 0;

    /*
     * C99 says: "If the `0' and `-' flags both appear, the `0' flag is
     * ignored." (7.19.6.1, 6)
     */
    if (flags & CRT_PRINT_F_MINUS)  /* Left justifty. */
        padlen = -padlen;
    else if (flags & CRT_PRINT_F_ZERO && padlen > 0) {
        if (sign != 0) {    /* Sign. */
            CRT_OUTCHAR(str, *len, size, sign);
            sign = 0;
        }
        while (padlen > 0) {    /* Leading zeros. */
            CRT_OUTCHAR(str, *len, size, '0');
            padlen--;
        }
    }
    while (padlen > 0) {    /* Leading spaces. */
        CRT_OUTCHAR(str, *len, size, ' ');
        padlen--;
    }
    if (sign != 0)  /* Sign. */
        CRT_OUTCHAR(str, *len, size, sign);
    while (ipos > 0) {  /* Integer part. */
        ipos--;
        CRT_OUTCHAR(str, *len, size, iconvert[ipos]);
        if (separators > 0 && ipos > 0 && ipos % 3 == 0)
            crt_printsep(str, len, size);
    }
    if (emitpoint) {    /* Decimal point. */
#if CRT_HAVE_LOCALECONV && CRT_HAVE_LCONV_DECIMAL_POINT
        if (lc->decimal_point != CX_NULL && *lc->decimal_point != '\0')
            CRT_OUTCHAR(str, *len, size, *lc->decimal_point);
        else    /* We'll always print some decimal point character. */
#endif  /* CRT_HAVE_LOCALECONV && CRT_HAVE_LCONV_DECIMAL_POINT */
            CRT_OUTCHAR(str, *len, size, '.');
    }
    while (leadfraczeros > 0) { /* Leading fractional part zeros. */
        CRT_OUTCHAR(str, *len, size, '0');
        leadfraczeros--;
    }
    while (fpos > omitcount) {  /* The remaining fractional part. */
        fpos--;
        CRT_OUTCHAR(str, *len, size, fconvert[fpos]);
    }
    while (epos > 0) {  /* Exponent. */
        epos--;
        CRT_OUTCHAR(str, *len, size, econvert[epos]);
    }
    while (padlen < 0) {    /* Trailing spaces. */
        CRT_OUTCHAR(str, *len, size, ' ');
        padlen++;
    }
}

static CX_VOID
crt_printsep(CX_INT8 *str, CX_SIZE_T *len, CX_SIZE_T size)
{
#if CRT_HAVE_LOCALECONV && CRT_HAVE_LCONV_THOUSANDS_SEP
    struct lconv *lc = localeconv();
    CX_INT32 i;

    if (lc->thousands_sep != CX_NULL)
        for (i = 0; lc->thousands_sep[i] != '\0'; i++)
            CRT_OUTCHAR(str, *len, size, lc->thousands_sep[i]);
    else
#endif  /* CRT_HAVE_LOCALECONV && CRT_HAVE_LCONV_THOUSANDS_SEP */
        CRT_OUTCHAR(str, *len, size, ',');
}

static CX_INT32
crt_getnumsep(CX_INT32 digits)
{
    CX_INT32 separators = (digits - ((digits % 3 == 0) ? 1 : 0)) / 3;
#if CRT_HAVE_LOCALECONV && CRT_HAVE_LCONV_THOUSANDS_SEP
    CX_INT32 strln;
    struct lconv *lc = localeconv();

    /* We support an arbitrary separator length (including zero). */
    if (lc->thousands_sep != CX_NULL) {
        for (strln = 0; lc->thousands_sep[strln] != '\0'; strln++)
            continue;
        separators *= strln;
    }
#endif  /* CRT_HAVE_LOCALECONV && CRT_HAVE_LCONV_THOUSANDS_SEP */
    return separators;
}

static CX_INT32
crt_getexponent(CRT_LDOUBLE value)
{
    CRT_LDOUBLE tmp = (value >= 0.0) ? value : -value;
    CX_INT32 exponent = 0;

    /*
     * We check for 99 > exponent > -99 in order to work around possible
     * endless loops which could happen (at least) in the second loop (at
     * least) if we're called with an infinite value.  However, we checked
     * for infinity before calling this function using our CRT_ISINF() macro, so
     * this might be somewhat paranoid.
     */
    while (tmp < 1.0 && tmp > 0.0 && --exponent > -99)
        tmp *= 10;
    while (tmp >= 10.0 && ++exponent < 99)
        tmp /= 10;

    return exponent;
}

static CX_INT32
crt_convert(CX_UINTMAXTYPE value, CX_INT8 *buf, CX_SIZE_T size, CX_INT32 base, CX_INT32 caps)
{
    const CX_INT8 *digits = caps ? "0123456789ABCDEF" : "0123456789abcdef";
    CX_SIZE_T pos = 0;

    /* We return an unterminated buffer with the digits in reverse order. */
    do {
        buf[pos++] = digits[value % base];
        value /= base;
    } while (value != 0 && pos < size);

    return (CX_INT32)pos;
}

static CX_UINTMAXTYPE
crt_cast(CRT_LDOUBLE value)
{
    CX_UINTMAXTYPE result;

    /*
     * We check for ">=" and not for ">" because if CX_UINT32_MAX_VALUE cannot be
     * represented exactly as an CRT_LDOUBLE value (but is less than LDBL_MAX),
     * it may be increased to the nearest higher representable value for the
     * comparison (cf. C99: 6.3.1.4, 2).  It might then equal the CRT_LDOUBLE
     * value although converting the latter to CX_UINTMAXTYPE would overflow.
     */
    if (value >= CX_UINT32_MAX_VALUE)
        return CX_UINT32_MAX_VALUE;

    result = value;
    /*
     * At least on NetBSD/sparc64 3.0.2 and 4.99.30, casting CX_INT32 double to
     * an integer type converts e.g. 1.9 to 2 instead of 1 (which violates
     * the standard).  Sigh.
     */
    return (result <= value) ? result : result - 1;
}

static CX_UINTMAXTYPE
crt_myround(CRT_LDOUBLE value)
{
    CX_UINTMAXTYPE intpart = crt_cast(value);

    return ((value -= intpart) < 0.5) ? intpart : intpart + 1;
}

static CRT_LDOUBLE
crtMypow10(CX_INT32 exponent)
{
    CRT_LDOUBLE result = 1;

    while (exponent > 0) {
        result *= 10;
        exponent--;
    }
    while (exponent < 0) {
        result /= 10;
        exponent++;
    }
    return result;
}
#endif  /* !CRT_HAVE_VSNPRINTF */

#if !CRT_HAVE_VASPRINTF
#if CRT_NEED_MYMEMCPY
CX_VOID *
crt_mymemcpy(CX_VOID *dst, CX_VOID *src, CX_SIZE_T len)
{
    const CX_INT8 *from = src;
    CX_INT8 *to = dst;

    /* No need for optimization, we use this only to replace va_copy(3). */
    while (len-- > 0)
        *to++ = *from++;
    return dst;
}
#endif  /* CRT_NEED_MYMEMCPY */

CX_INT32
crt_rpl_vasprintf(CX_INT8 **ret, const CX_INT8 *format, crt_va_list ap)
{
    CX_SIZE_T size;
    CX_INT32 len;
    crt_va_list aq;

    CRT_VA_COPY(aq, ap);
    len = crt_vsnprintf(CX_NULL, 0, format, aq);
    CRT_VA_END_COPY(aq);
    if (len < 0 || (*ret = malloc(size = len + 1)) == CX_NULL)
        return -1;
    return crt_vsnprintf(*ret, size, format, ap);
}
#endif  /* !CRT_HAVE_VASPRINTF */

#if !CRT_HAVE_SNPRINTF
#if CRT_HAVE_STDARG_H
CX_INT32
crt_rpl_snprintf(CX_INT8 *str, CX_SIZE_T size, const CX_INT8 *format, ...)
#else
CX_INT32
crt_rpl_snprintf(va_alist) va_dcl
#endif  /* CRT_HAVE_STDARG_H */
{
#if !CRT_HAVE_STDARG_H
    CX_INT8 *str;
    CX_SIZE_T size;
    CX_INT8 *format;
#endif  /* CRT_HAVE_STDARG_H */
    crt_va_list ap;
    CX_INT32 len;

    CRT_VA_START(ap, format);
    CRT_VA_SHIFT(ap, str, CX_INT8 *);
    CRT_VA_SHIFT(ap, size, CX_SIZE_T);
    CRT_VA_SHIFT(ap, format, const CX_INT8 *);
    ///len = crt_vsnprintf(str, size, format, ap);
    len = crt_rpl_vsnprintf(str, size, format, ap);
    crt_va_end(ap);
    return len;
}
#endif  /* !CRT_HAVE_SNPRINTF */

#if !CRT_HAVE_ASPRINTF
#if CRT_HAVE_STDARG_H
CX_INT32
crt_rpl_asprintf(CX_INT8 **ret, const CX_INT8 *format, ...)
#else
CX_INT32
crt_rpl_asprintf(va_alist) va_dcl
#endif  /* CRT_HAVE_STDARG_H */
{
#if !CRT_HAVE_STDARG_H
    CX_INT8 **ret;
    CX_INT8 *format;
#endif  /* CRT_HAVE_STDARG_H */
    crt_va_list ap;
    CX_INT32 len;

    CRT_VA_START(ap, format);
    CRT_VA_SHIFT(ap, ret, CX_INT8 **);
    CRT_VA_SHIFT(ap, format, const CX_INT8 *);
    len = crt_vasprintf(ret, format, ap);
    crt_va_end(ap);
    return len;
}
#endif  /* !CRT_HAVE_ASPRINTF */
#else   /* Dummy declaration to avoid empty translation unit warnings. */
CX_INT32 crt_main(CX_VOID);
#endif  /* !CRT_HAVE_SNPRINTF || !CRT_HAVE_VSNPRINTF || !CRT_HAVE_ASPRINTF || [...] */

#if CRT_TEST_SNPRINTF
CX_INT32
crt_main(CX_VOID)
{
    const CX_INT8 *float_fmt[] = {
        /* "%E" and "%e" formats. */
#if CRT_HAVE_LONG_LONG_INT && !CRT_OS_BSD && !CRT_OS_IRIX
        "%.16e",
        "%22.16e",
        "%022.16e",
        "%-22.16e",
        "%#+'022.16e",
#endif  /* CRT_HAVE_LONG_LONG_INT && !CRT_OS_BSD && !CRT_OS_IRIX */
        "foo|%#+0123.9E|bar",
        "%-123.9e",
        "%123.9e",
        "%+23.9e",
        "%+05.8e",
        "%-05.8e",
        "%05.8e",
        "%+5.8e",
        "%-5.8e",
        "% 5.8e",
        "%5.8e",
        "%+4.9e",
#if !CRT_OS_LINUX   /* glibc sometimes gets these wrong. */
        "%+#010.0e",
        "%#10.1e",
        "%10.5e",
        "% 10.5e",
        "%5.0e",
        "%5.e",
        "%#5.0e",
        "%#5.e",
        "%3.2e",
        "%3.1e",
        "%-1.5e",
        "%1.5e",
        "%01.3e",
        "%1.e",
        "%.1e",
        "%#.0e",
        "%+.0e",
        "% .0e",
        "%.0e",
        "%#.e",
        "%+.e",
        "% .e",
        "%.e",
        "%4e",
        "%e",
        "%E",
#endif  /* !CRT_OS_LINUX */
        /* "%F" and "%f" formats. */
#if !CRT_OS_BSD && !CRT_OS_IRIX
        "% '022f",
        "%+'022f",
        "%-'22f",
        "%'22f",
#if CRT_HAVE_LONG_LONG_INT
        "%.16f",
        "%22.16f",
        "%022.16f",
        "%-22.16f",
        "%#+'022.16f",
#endif  /* CRT_HAVE_LONG_LONG_INT */
#endif  /* !CRT_OS_BSD && !CRT_OS_IRIX */
        "foo|%#+0123.9F|bar",
        "%-123.9f",
        "%123.9f",
        "%+23.9f",
        "%+#010.0f",
        "%#10.1f",
        "%10.5f",
        "% 10.5f",
        "%+05.8f",
        "%-05.8f",
        "%05.8f",
        "%+5.8f",
        "%-5.8f",
        "% 5.8f",
        "%5.8f",
        "%5.0f",
        "%5.f",
        "%#5.0f",
        "%#5.f",
        "%+4.9f",
        "%3.2f",
        "%3.1f",
        "%-1.5f",
        "%1.5f",
        "%01.3f",
        "%1.f",
        "%.1f",
        "%#.0f",
        "%+.0f",
        "% .0f",
        "%.0f",
        "%#.f",
        "%+.f",
        "% .f",
        "%.f",
        "%4f",
        "%f",
        "%F",
        /* "%G" and "%g" formats. */
#if !CRT_OS_BSD && !CRT_OS_IRIX && !CRT_OS_LINUX
        "% '022g",
        "%+'022g",
        "%-'22g",
        "%'22g",
#if CRT_HAVE_LONG_LONG_INT
        "%.16g",
        "%22.16g",
        "%022.16g",
        "%-22.16g",
        "%#+'022.16g",
#endif  /* CRT_HAVE_LONG_LONG_INT */
#endif  /* !CRT_OS_BSD && !CRT_OS_IRIX && !CRT_OS_LINUX */
        "foo|%#+0123.9G|bar",
        "%-123.9g",
        "%123.9g",
        "%+23.9g",
        "%+05.8g",
        "%-05.8g",
        "%05.8g",
        "%+5.8g",
        "%-5.8g",
        "% 5.8g",
        "%5.8g",
        "%+4.9g",
#if !CRT_OS_LINUX   /* glibc sometimes gets these wrong. */
        "%+#010.0g",
        "%#10.1g",
        "%10.5g",
        "% 10.5g",
        "%5.0g",
        "%5.g",
        "%#5.0g",
        "%#5.g",
        "%3.2g",
        "%3.1g",
        "%-1.5g",
        "%1.5g",
        "%01.3g",
        "%1.g",
        "%.1g",
        "%#.0g",
        "%+.0g",
        "% .0g",
        "%.0g",
        "%#.g",
        "%+.g",
        "% .g",
        "%.g",
        "%4g",
        "%g",
        "%G",
#endif  /* !CRT_OS_LINUX */
        CX_NULL
    };
    double float_val[] = {
        -4.136,
        -134.52,
        -5.04030201,
        -3410.01234,
        -999999.999999,
        -913450.29876,
        -913450.2,
        -91345.2,
        -9134.2,
        -913.2,
        -91.2,
        -9.2,
        -9.9,
        4.136,
        134.52,
        5.04030201,
        3410.01234,
        999999.999999,
        913450.29876,
        913450.2,
        91345.2,
        9134.2,
        913.2,
        91.2,
        9.2,
        9.9,
        9.96,
        9.996,
        9.9996,
        9.99996,
        9.999996,
        9.9999996,
        9.99999996,
        0.99999996,
        0.99999999,
        0.09999999,
        0.00999999,
        0.00099999,
        0.00009999,
        0.00000999,
        0.00000099,
        0.00000009,
        0.00000001,
        0.0000001,
        0.000001,
        0.00001,
        0.0001,
        0.001,
        0.01,
        0.1,
        1.0,
        1.5,
        -1.5,
        -1.0,
        -0.1,
#if !CRT_OS_BSD /* BSD sometimes gets these wrong. */
#ifdef INFINITY
        INFINITY,
        -INFINITY,
#endif  /* defined(INFINITY) */
#ifdef NAN
        NAN,
#endif  /* defined(NAN) */
#endif  /* !CRT_OS_BSD */
        0
    };
    const CX_INT8 *long_fmt[] = {
        "foo|%0123ld|bar",
#if !CRT_OS_IRIX
        "% '0123ld",
        "%+'0123ld",
        "%-'123ld",
        "%'123ld",
#endif  /* !OS_IRiX */
        "%123.9ld",
        "% 123.9ld",
        "%+123.9ld",
        "%-123.9ld",
        "%0123ld",
        "% 0123ld",
        "%+0123ld",
        "%-0123ld",
        "%10.5ld",
        "% 10.5ld",
        "%+10.5ld",
        "%-10.5ld",
        "%010ld",
        "% 010ld",
        "%+010ld",
        "%-010ld",
        "%4.2ld",
        "% 4.2ld",
        "%+4.2ld",
        "%-4.2ld",
        "%04ld",
        "% 04ld",
        "%+04ld",
        "%-04ld",
        "%5.5ld",
        "%+22.33ld",
        "%01.3ld",
        "%1.5ld",
        "%-1.5ld",
        "%44ld",
        "%4ld",
        "%4.0ld",
        "%4.ld",
        "%.44ld",
        "%.4ld",
        "%.0ld",
        "%.ld",
        "%ld",
        CX_NULL
    };
    CX_INT32 long_val[] = {
#ifdef LONG_MAX
        LONG_MAX,
#endif  /* LONG_MAX */
#ifdef LONG_MIN
        LONG_MIN,
#endif  /* LONG_MIN */
        -91340,
        91340,
        341,
        134,
        0203,
        -1,
        1,
        0
    };
    const CX_INT8 *ulong_fmt[] = {
        /* "%u" formats. */
        "foo|%0123lu|bar",
#if !CRT_OS_IRIX
        "% '0123lu",
        "%+'0123lu",
        "%-'123lu",
        "%'123lu",
#endif  /* !OS_IRiX */
        "%123.9lu",
        "% 123.9lu",
        "%+123.9lu",
        "%-123.9lu",
        "%0123lu",
        "% 0123lu",
        "%+0123lu",
        "%-0123lu",
        "%5.5lu",
        "%+22.33lu",
        "%01.3lu",
        "%1.5lu",
        "%-1.5lu",
        "%44lu",
        "%lu",
        /* "%o" formats. */
        "foo|%#0123lo|bar",
        "%#123.9lo",
        "%# 123.9lo",
        "%#+123.9lo",
        "%#-123.9lo",
        "%#0123lo",
        "%# 0123lo",
        "%#+0123lo",
        "%#-0123lo",
        "%#5.5lo",
        "%#+22.33lo",
        "%#01.3lo",
        "%#1.5lo",
        "%#-1.5lo",
        "%#44lo",
        "%#lo",
        "%123.9lo",
        "% 123.9lo",
        "%+123.9lo",
        "%-123.9lo",
        "%0123lo",
        "% 0123lo",
        "%+0123lo",
        "%-0123lo",
        "%5.5lo",
        "%+22.33lo",
        "%01.3lo",
        "%1.5lo",
        "%-1.5lo",
        "%44lo",
        "%lo",
        /* "%X" and "%x" formats. */
        "foo|%#0123lX|bar",
        "%#123.9lx",
        "%# 123.9lx",
        "%#+123.9lx",
        "%#-123.9lx",
        "%#0123lx",
        "%# 0123lx",
        "%#+0123lx",
        "%#-0123lx",
        "%#5.5lx",
        "%#+22.33lx",
        "%#01.3lx",
        "%#1.5lx",
        "%#-1.5lx",
        "%#44lx",
        "%#lx",
        "%#lX",
        "%123.9lx",
        "% 123.9lx",
        "%+123.9lx",
        "%-123.9lx",
        "%0123lx",
        "% 0123lx",
        "%+0123lx",
        "%-0123lx",
        "%5.5lx",
        "%+22.33lx",
        "%01.3lx",
        "%1.5lx",
        "%-1.5lx",
        "%44lx",
        "%lx",
        "%lX",
        CX_NULL
    };
    CX_UINT64 ulong_val[] = {
#ifdef CX_UINT32_MAX_VALUE
        CX_UINT32_MAX_VALUE,
#endif  /* CX_UINT32_MAX_VALUE */
        91340,
        341,
        134,
        0203,
        1,
        0
    };
    const CX_INT8 *llong_fmt[] = {
        "foo|%0123lld|bar",
        "%123.9lld",
        "% 123.9lld",
        "%+123.9lld",
        "%-123.9lld",
        "%0123lld",
        "% 0123lld",
        "%+0123lld",
        "%-0123lld",
        "%5.5lld",
        "%+22.33lld",
        "%01.3lld",
        "%1.5lld",
        "%-1.5lld",
        "%44lld",
        "%lld",
        CX_NULL
    };
    CX_INT64 llong_val[] = {
#ifdef LLONG_MAX
        LLONG_MAX,
#endif  /* LLONG_MAX */
#ifdef LLONG_MIN
        LLONG_MIN,
#endif  /* LLONG_MIN */
        -91340,
        91340,
        341,
        134,
        0203,
        -1,
        1,
        0
    };
    const CX_INT8 *string_fmt[] = {
        "foo|%10.10s|bar",
        "%-10.10s",
        "%10.10s",
        "%10.5s",
        "%5.10s",
        "%10.1s",
        "%1.10s",
        "%10.0s",
        "%0.10s",
        "%-42.5s",
        "%2.s",
        "%.10s",
        "%.1s",
        "%.0s",
        "%.s",
        "%4s",
        "%s",
        CX_NULL
    };
    const CX_INT8 *string_val[] = {
        "Hello",
        "Hello, world!",
        "Sound check: One, two, three.",
        "This string is a little longer than the other strings.",
        "1",
        "",
        CX_NULL
    };
#if !CRT_OS_SYSV    /* SysV uses a different format than we do. */
    const CX_INT8 *pointer_fmt[] = {
        "foo|%p|bar",
        "%42p",
        "%p",
        CX_NULL
    };
    const CX_INT8 *pointer_val[] = {
        *pointer_fmt,
        *string_fmt,
        *string_val,
        CX_NULL
    };
#endif  /* !CRT_OS_SYSV */
    CX_INT8 buf1[1024], buf2[1024];
    double value, digits = 9.123456789012345678901234567890123456789;
    CX_INT32 i, j, r1, r2, failed = 0, num = 0;

/*
 * Use -DTEST_NILS in order to also test the conversion of nil values.  Might
 * segfault on systems which don't support converting a CX_NULL pointer with "%s"
 * and lets some test cases fail against BSD and glibc due to bugs in their
 * implementations.
 */
#ifndef TEST_NILS
#define TEST_NILS 0
#elif TEST_NILS
#undef TEST_NILS
#define TEST_NILS 1
#endif  /* !defined(TEST_NILS) */
#ifdef TEST
#undef TEST
#endif  /* defined(TEST) */
#define TEST(fmt, val)                                                         \
do {                                                                           \
    for (i = 0; fmt[i] != CX_NULL; i++)                                       \
        for (j = 0; j == 0 || val[j - TEST_NILS] != 0; j++) {          \
            r1 = sprintf(buf1, fmt[i], val[j]);                    \
            r2 = crt_snprintf(buf2, sizeof(buf2), fmt[i], val[j]);     \
            if (crt_strcmp(buf1, buf2) != 0 || r1 != r2) {             \
                (CX_VOID)printf("Results don't match, "           \
                    "format string: %s\n"                      \
                    "\t sprintf(3): [%s] (%d)\n"               \
                    "\tsnprintf(3): [%s] (%d)\n",              \
                    fmt[i], buf1, r1, buf2, r2);               \
                failed++;                                      \
            }                                                      \
            num++;                                                 \
        }                                                              \
} while (/* CONSTCOND */ 0)

#if CRT_HAVE_LOCALE_H
    (CX_VOID)setlocale(LC_ALL, "");
#endif  /* CRT_HAVE_LOCALE_H */

    (CX_VOID)puts("Testing our crt_snprintf(3) against your system's sprintf(3).");
    TEST(float_fmt, float_val);
    TEST(long_fmt, long_val);
    TEST(ulong_fmt, ulong_val);
    TEST(llong_fmt, llong_val);
    TEST(string_fmt, string_val);
#if !CRT_OS_SYSV    /* SysV uses a different format than we do. */
    TEST(pointer_fmt, pointer_val);
#endif  /* !CRT_OS_SYSV */
    (CX_VOID)printf("Result: %d out of %d tests failed.\n", failed, num);

    (CX_VOID)fputs("Checking how many digits we support: ", stdout);
    for (i = 0; i < 100; i++) {
        value = pow(10, i) * digits;
        (CX_VOID)sprintf(buf1, "%.1f", value);
        (CX_VOID)crt_snprintf(buf2, sizeof(buf2), "%.1f", value);
        if (crt_strcmp(buf1, buf2) != 0) {
            (CX_VOID)printf("apparently %d.\n", i);
            break;
        }
    }
    return (failed == 0) ? 0 : 1;
}
#endif  /* CRT_TEST_SNPRINTF */

/* vim: set joinspaces textwidth=80: */
