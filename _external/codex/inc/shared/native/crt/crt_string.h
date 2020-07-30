/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _CRT_STRING_H_
#define _CRT_STRING_H_

#include "base/cx_types.h"
#include "crt_varargs.h"
#include "base/cx_sal.h"
#include "crt_conv.h"

typedef CX_UINT16 CRT_WCHAR, *CRT_PWCHAR;


//
// ANSI character macros
//
#define crt_tolower(c)      ( (((c) >= 'A') && ((c) <= 'Z')) ? ((c) - 'A' + 'a') : (c) )

#define crt_toupper(c)      ( (((c) >= 'a') && ((c) <= 'z')) ? ((c) - 'a' + 'A') : (c) )

#define crt_isalpha(c)      ( ( (((c) >= 'A') && ((c) <= 'Z')) || \
                            (((c) >= 'a') && ((c) <= 'z')) ) ? 1 : 0 )

#define crt_isdigit(c)      ( (((c) >= '0') && ((c) <= '9')) ? 1 : 0 )

#define crt_isxdigit(c)     ( ( (((c) >= 'A') && ((c) <= 'F')) || \
                            (((c) >= 'a') && ((c) <= 'f')) || \
                            (((c) >= '0') && ((c) <= '9')) ) ? 1 : 0 )

#define crt_isprint(c)      (((c) >= ' ' && (c) <= '~') ? 1 : 0)
#define crt_isspace(c)      (((c) == ' ') || ((c) == '\t') || ((c) == '\n') || ((c) == '\v') || ((c) == '\f') || ((c) == '\r') )


//
// ANSI string functions
//
CX_SIZE_T __cdecl
crt_strlen(
    _In_z_ const CX_INT8 *str);

CX_INT8 * __cdecl
crt_strcpy(
    _Out_writes_z_(_String_length_(src) + 1) CX_INT8 *dst,
    _In_z_ const CX_INT8 *src);

CX_INT8 * __cdecl
crt_strncpy (
    __out_z CX_INT8 *dst,
    _In_z_ const CX_INT8 *src,
    CX_SIZE_T               Count);

CX_INT8 * __cdecl
crt_strncat (
    __out_z CX_INT8 *dst,
    _In_z_ const CX_INT8 *src,
    CX_SIZE_T               Count);

CX_INT8 * __cdecl
crt_strcat(
    _Inout_z_ CX_INT8 *dst,
    _In_z_ const CX_INT8 *src);

CX_INT32 __cdecl
crt_strcmp(
    _In_z_ const CX_INT8 *src,
    _In_z_ const CX_INT8 *dst);

CX_INT8 * __cdecl
crt_strstr(
    _In_z_ const CX_INT8 *str1,
    _In_z_ const CX_INT8 *str2);

CX_INT8 * __cdecl
crt_strchr(
    _In_z_ const CX_INT8 *str,
    _In_ CX_INT32 c);

CX_INT8 * __cdecl
crt_strrchr(
    _In_z_ const CX_INT8 *str,
    _In_ CX_INT32 c);

CX_INT32 __cdecl
crt_stricmp(
    _In_z_ const CX_INT8 *str1,
    _In_z_ const CX_INT8 *str2);

CX_INT32 __cdecl
crt_strncmp(
    _In_reads_or_z_(count) const CX_INT8 *str1,
    _In_reads_or_z_(count) const CX_INT8 *str2,
    _In_ CX_SIZE_T count);

CX_INT32 __cdecl
crt_strnicmp(
    _In_reads_or_z_(count) const CX_INT8 *str1,
    _In_reads_or_z_(count) const CX_INT8 *str2,
    _In_ CX_SIZE_T count);

CX_INT8 * __cdecl
crt_strend(
    _In_z_ const CX_INT8 *str,
    _In_ CX_SIZE_T count);


//
// ANSI SAFE string functions
//

// Returns length, or -1 if string doesn't end within given size (size includes null terminator)
CX_SIZE_T __cdecl
crt_strlen_s(
    _In_z_ const CX_INT8 *str,
    _In_ CX_SIZE_T size);

_Check_return_
CX_INT8 * __cdecl
crt_strcpy_s(
    _Out_writes_z_(dst_size) CX_INT8 *dst,
    _In_ CX_SIZE_T dst_size,
    _In_z_ const CX_INT8 *src);

CX_INT8 * __cdecl
crt_strcat_s(
    _Inout_updates_z_(dst_size)CX_INT8 *dst,
    _In_ CX_SIZE_T dst_size,
    _In_z_ const CX_INT8 *src);

CX_INT8 * __cdecl
crt_strstr_s(
    _In_reads_z_(str_size) const CX_INT8 *str,
    _In_ CX_SIZE_T str_size,
    _In_z_ const CX_INT8 *strSearch);

CX_INT8 * __cdecl
crt_strchr_s(
    _In_reads_z_(str_size)  const CX_INT8 *str,
    _In_ CX_SIZE_T str_size,
    _In_ CX_INT32 c);

CX_INT8 * __cdecl
crt_strrchr_s(
    _In_reads_z_(str_size) const CX_INT8 *str,
    _In_ CX_SIZE_T str_size,
    _In_ CX_INT32 c);

CX_INT8 * __cdecl
crt_strend_s(
    _In_reads_z_(str_size) const CX_INT8 *str,
    _In_ CX_SIZE_T str_size,
    _In_ CX_SIZE_T count);

CX_INT8 * __cdecl
crt_strtruncate(
    _Out_writes_bytes_(dst_size) CX_INT8 *dst,
    _In_ CX_SIZE_T dst_size,
    _In_ const CX_INT8 *src);


//
// PRINTF family prototypes
//
_Success_(return >= 0)
CX_INT32 __cdecl
crt_rpl_vsnprintf(
    _Out_writes_(count) _Post_maybez_ CX_INT8 *buffer,
    _In_ CX_SIZE_T count,
    _In_z_ _Printf_format_string_ const CX_INT8 *format,
    _In_ crt_va_list ap);
#define crt_vsnprintf crt_rpl_vsnprintf

_Success_(return >= 0)
CX_INT32 __cdecl
crt_snprintf(
    _Out_writes_(count) _Post_maybez_ CX_INT8 *buffer,
    _In_ CX_SIZE_T count,
    _In_z_ _Printf_format_string_ const CX_INT8 *format,
    ...);


//
// wide strings
//

//
// crt_wstrlen
//
CX_SIZE_T __cdecl
crt_wstrlen(
    _In_z_ const CRT_WCHAR *str
);

CX_SIZE_T __cdecl
crt_wstrlen_s(
    _In_reads_z_(size) const CRT_WCHAR *str,
    _In_ CX_SIZE_T size);

CRT_WCHAR * __cdecl
crt_wstrtruncate(
    _Out_writes_(dst_size) CRT_WCHAR *dst,
    _In_ CX_SIZE_T dst_size,
    _In_ const CRT_WCHAR *src);

CRT_WCHAR * __cdecl
crt_wstrstr_s(
    _In_reads_z_(str_size) const CRT_WCHAR *str,
    _In_ CX_SIZE_T str_size,
    _In_z_ const CRT_WCHAR *strSearch);

#endif // _CRT_STRING_H_

