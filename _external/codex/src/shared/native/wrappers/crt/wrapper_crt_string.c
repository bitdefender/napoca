/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifdef CRT_INC_SETTINGS_WRAPPER_CRT_STRING_C
#include CRT_INC_SETTINGS_WRAPPER_CRT_STRING_C // define it to some .h file name/path if you want to provide settings
#endif


#include "crt/crt_crt.h"
#include "base/cx_env.h"
#include "crt/crt_string.h"
#include "crt/crt_memory.h"

#ifdef CX_MSVC
#ifdef CX_RELEASE_BUILD
#pragma function(strlen, strcpy, strcat, strcmp)
#endif
#endif

#if ( !defined(CRT_SKIP_DEF_STRLEN) && (!defined(CRT_DEFAULT_SKIP_WRAPPER_CRT_STRING_C_DEF) || defined(CRT_WANT_DEF_STRLEN))  )
CX_SIZE_T __cdecl
strlen(
    _In_z_ const CX_INT8 *str
    )
{
    return crt_strlen(str);
}
#endif


#if ( !defined(CRT_SKIP_DEF_STRCPY) && (!defined(CRT_DEFAULT_SKIP_WRAPPER_CRT_STRING_C_DEF) || defined(CRT_WANT_DEF_STRCPY))  )
CX_INT8 * __cdecl
strcpy(
    _Out_writes_z_(_String_length_(src) + 1) CX_INT8 *dst,
    _In_z_ const CX_INT8 *src
)
{
    return crt_strcpy(dst, src);
}
#endif


#if ( !defined(CRT_SKIP_DEF_STRNCPY) && (!defined(CRT_DEFAULT_SKIP_WRAPPER_CRT_STRING_C_DEF) || defined(CRT_WANT_DEF_STRNCPY))  )
CX_INT8 * __cdecl
strncpy(
    __out_z CX_INT8 * dst,
    _In_z_ const CX_INT8 * src,
    CX_SIZE_T               Count
)
{
    return crt_strncpy(dst, src, Count);
}
#endif


#if ( !defined(CRT_SKIP_DEF_STRCAT) && (!defined(CRT_DEFAULT_SKIP_WRAPPER_CRT_STRING_C_DEF) || defined(CRT_WANT_DEF_STRCAT))  )
CX_INT8 * __cdecl
strcat(
    _Inout_z_ CX_INT8 *dst,
    _In_z_ const CX_INT8 *src
       )
{
    return crt_strcat(dst, src);
}
#endif


#if ( !defined(CRT_SKIP_DEF_STRNCAT) && (!defined(CRT_DEFAULT_SKIP_WRAPPER_CRT_STRING_C_DEF) || defined(CRT_WANT_DEF_STRNCAT))  )
CX_INT8 * __cdecl
strncat(
    __out_z CX_INT8 * dst,
    _In_z_ const CX_INT8 * src,
    CX_SIZE_T               Count
)
{
    return crt_strncat(dst, src, Count);
}
#endif


#if ( !defined(CRT_SKIP_DEF_STRCMP) && (!defined(CRT_DEFAULT_SKIP_WRAPPER_CRT_STRING_C_DEF) || defined(CRT_WANT_DEF_STRCMP))  )
CX_INT32 __cdecl
strcmp(
    _In_z_ const CX_INT8 *src,
    _In_z_ const CX_INT8 *dst
    )
{
    return crt_strcmp(src, dst);
}
#endif


#if ( !defined(CRT_SKIP_DEF_WSTRLEN) && (!defined(CRT_DEFAULT_SKIP_WRAPPER_CRT_STRING_C_DEF) || defined(CRT_WANT_DEF_WSTRLEN))  )
CX_SIZE_T __cdecl
wstrlen(
    _In_z_ const CRT_WCHAR *str
       )
{
    return crt_wstrlen(str);
}
#endif


#if ( !defined(CRT_SKIP_DEF_STRSTR) && (!defined(CRT_DEFAULT_SKIP_WRAPPER_CRT_STRING_C_DEF) || defined(CRT_WANT_DEF_STRSTR))  )
CX_INT8 * __cdecl
strstr(
    _In_z_ const CX_INT8 *str1,
    _In_z_ const CX_INT8 *str2
    )
{
    return crt_strstr(str1, str2);
}
#endif


#if ( !defined(CRT_SKIP_DEF_STRCHR) && (!defined(CRT_DEFAULT_SKIP_WRAPPER_CRT_STRING_C_DEF) || defined(CRT_WANT_DEF_STRCHR))  )
CX_INT8 * __cdecl
strchr(
    _In_z_ const CX_INT8 *str,
    _In_ CX_INT32 c
    )
{
    return crt_strchr(str, c);
}
#endif


#if ( !defined(CRT_SKIP_DEF_STRRCHR) && (!defined(CRT_DEFAULT_SKIP_WRAPPER_CRT_STRING_C_DEF) || defined(CRT_WANT_DEF_STRRCHR))  )
CX_INT8 * __cdecl
strrchr(
    _In_z_ const CX_INT8 *str,
    _In_ CX_INT32 c
    )
{
    return crt_strrchr(str, c);
}
#endif


#if ( !defined(CRT_SKIP_DEF_STRICMP) && (!defined(CRT_DEFAULT_SKIP_WRAPPER_CRT_STRING_C_DEF) || defined(CRT_WANT_DEF_STRICMP))  )
CX_INT32 __cdecl
stricmp(
    _In_z_ const CX_INT8 *str1,
    _In_z_ const CX_INT8 *str2
    )
{
    return crt_stricmp(str1, str2);
}
#endif


#if ( !defined(CRT_SKIP_DEF_STRNCMP) && (!defined(CRT_DEFAULT_SKIP_WRAPPER_CRT_STRING_C_DEF) || defined(CRT_WANT_DEF_STRNCMP))  )
CX_INT32 __cdecl
strncmp(
    _In_reads_or_z_(count)  const CX_INT8 *first,
    _In_reads_or_z_(count)  const CX_INT8 *last,
    _In_ CX_SIZE_T count
    )
{
    return crt_strncmp(first, last, count);
}
#endif


#if ( !defined(CRT_SKIP_DEF_STRNICMP) && (!defined(CRT_DEFAULT_SKIP_WRAPPER_CRT_STRING_C_DEF) || defined(CRT_WANT_DEF_STRNICMP))  )
CX_INT32 __cdecl
strnicmp(
    _In_reads_or_z_(count)   const CX_INT8 *str1,
    _In_reads_or_z_(count)   const CX_INT8 *str2,
    _In_ CX_SIZE_T count
    )
{
    return crt_strnicmp(str1, str2, count);
}
#endif


#if ( !defined(CRT_SKIP_DEF_STREND) && (!defined(CRT_DEFAULT_SKIP_WRAPPER_CRT_STRING_C_DEF) || defined(CRT_WANT_DEF_STREND))  )
CX_INT8 * __cdecl
strend(
    _In_z_ const CX_INT8 *str,
    _In_ CX_SIZE_T count
    )
{
    return crt_strend(str, count);
}
#endif


#if ( !defined(CRT_SKIP_DEF_SNPRINTF) && (!defined(CRT_DEFAULT_SKIP_WRAPPER_CRT_STRING_C_DEF) || defined(CRT_WANT_DEF_SNPRINTF))  )
_Success_(return >= 0)
CX_INT32 __cdecl
snprintf(
    _Out_writes_(count) _Post_maybez_ CX_INT8 *buffer,
    _In_ CX_SIZE_T count,
    _In_z_ _Printf_format_string_ const CX_INT8 *format,
    ...
    )
{
    crt_va_list arglist;
    CX_INT32 retval;

    crt_va_start(arglist, format);

    retval = crt_vsnprintf(buffer, count, format, arglist);

    crt_va_end(arglist);

    return retval;
}
#endif

#if ( !defined(CRT_SKIP_DEF_VSNPRINTF) && (!defined(CRT_DEFAULT_SKIP_WRAPPER_CRT_STRING_C_DEF) || defined(CRT_WANT_DEF_VSNPRINTF))  )
_Success_(return >= 0)
CX_INT32 __cdecl
vsnprintf(
    _Out_writes_(count) _Post_maybez_ CX_INT8 *buffer,
    _In_ CX_SIZE_T count,
    _In_z_ _Printf_format_string_ const CX_INT8 *format,
    _In_ crt_va_list ap)
{
    return crt_vsnprintf(buffer, count, format, ap);
}
#endif

#if ( !defined(CRT_SKIP_DEF__VSNPRINTF) && (!defined(CRT_DEFAULT_SKIP_WRAPPER_CRT_STRING_C_DEF) || defined(CRT_WANT_DEF__VSNPRINTF))  )
_Success_(return >= 0)
CX_INT32 __cdecl
_vsnprintf(
    _Out_writes_(count) _Post_maybez_ CX_INT8 *buffer,
    _In_ CX_SIZE_T count,
    _In_z_ _Printf_format_string_ const CX_INT8 *format,
    _In_ crt_va_list ap)
{
    return crt_vsnprintf(buffer, count, format, ap);
}
#endif

#if ( !defined(CRT_SKIP_DEF_STRLEN_S) && (!defined(CRT_DEFAULT_SKIP_WRAPPER_CRT_STRING_C_DEF) || defined(CRT_WANT_DEF_STRLEN_S))  )
CX_SIZE_T __cdecl
strlen_s(
    _In_z_ const CX_INT8 *str,
    _In_ CX_SIZE_T size)
{
    return crt_strlen_s(str, size);
}
#endif


#if ( !defined(CRT_SKIP_DEF_WSTRLEN_S) && (!defined(CRT_DEFAULT_SKIP_WRAPPER_CRT_STRING_C_DEF) || defined(CRT_WANT_DEF_WSTRLEN_S))  )
CX_SIZE_T __cdecl
wstrlen_s(
    _In_reads_z_(size) const CRT_WCHAR *str,
    _In_ CX_SIZE_T size)
{
    return crt_wstrlen_s(str, size);
}
#endif


#if ( !defined(CRT_SKIP_DEF_STRCPY_S) && (!defined(CRT_DEFAULT_SKIP_WRAPPER_CRT_STRING_C_DEF) || defined(CRT_WANT_DEF_STRCPY_S))  )
CX_INT8 * __cdecl
strcpy_s(
    _Out_writes_z_(dst_size) CX_INT8 *dst,
    _In_ CX_SIZE_T dst_size,
    _In_z_ const CX_INT8 *src)
{
    return crt_strcpy_s(dst, dst_size, src);
}
#endif


#if ( !defined(CRT_SKIP_DEF_STRCAT_S) && (!defined(CRT_DEFAULT_SKIP_WRAPPER_CRT_STRING_C_DEF) || defined(CRT_WANT_DEF_STRCAT_S))  )
CX_INT8 * __cdecl
strcat_s(
    _Inout_updates_z_(dst_size)CX_INT8 *dst,
    _In_ CX_SIZE_T dst_size,
    _In_z_ const CX_INT8 *src)
{
    return crt_strcat_s(dst, dst_size, src);
}
#endif


#if ( !defined(CRT_SKIP_DEF_STRSTR_S) && (!defined(CRT_DEFAULT_SKIP_WRAPPER_CRT_STRING_C_DEF) || defined(CRT_WANT_DEF_STRSTR_S))  )
CX_INT8 * __cdecl
strstr_s(
    _In_reads_z_(str_size) const CX_INT8 *str,
    _In_ CX_SIZE_T str_size,
    _In_z_ const CX_INT8 *strSearch)
{
    return crt_strstr_s(str, str_size, strSearch);
}
#endif


#if ( !defined(CRT_SKIP_DEF_STRCHR_S) && (!defined(CRT_DEFAULT_SKIP_WRAPPER_CRT_STRING_C_DEF) || defined(CRT_WANT_DEF_STRCHR_S))  )
CX_INT8 * __cdecl
strchr_s(
    _In_reads_z_(str_size)  const CX_INT8 *str,
    _In_ CX_SIZE_T str_size,
    _In_ CX_INT32 c)
{
    return crt_strchr_s(str, str_size, c);
}
#endif


#if ( !defined(CRT_SKIP_DEF_STRRCHR_S) && (!defined(CRT_DEFAULT_SKIP_WRAPPER_CRT_STRING_C_DEF) || defined(CRT_WANT_DEF_STRRCHR_S))  )
CX_INT8 * __cdecl
strrchr_s(
    _In_reads_z_(str_size) const CX_INT8 *str,
    _In_ CX_SIZE_T str_size,
    _In_ CX_INT32 c)
{
    return crt_strrchr_s(str, str_size, c);
}
#endif


#if ( !defined(CRT_SKIP_DEF_STREND_S) && (!defined(CRT_DEFAULT_SKIP_WRAPPER_CRT_STRING_C_DEF) || defined(CRT_WANT_DEF_STREND_S))  )
CX_INT8 * __cdecl
strend_s(
    _In_reads_z_(str_size) const CX_INT8 *str,
    _In_ CX_SIZE_T str_size,
    _In_ CX_SIZE_T count)
{
    return crt_strend_s(str, str_size, count);
}
#endif


#if ( !defined(CRT_SKIP_DEF_STRTRUNCATE) && (!defined(CRT_DEFAULT_SKIP_WRAPPER_CRT_STRING_C_DEF) || defined(CRT_WANT_DEF_STRTRUNCATE))  )
CX_INT8 * __cdecl
strtruncate(
    _Out_writes_bytes_(dst_size) CX_INT8 *dst,
    _In_ CX_SIZE_T dst_size,
    _In_ const CX_INT8 *src
    )
{
    return crt_strtruncate(dst, dst_size, src);
}
#endif


#if ( !defined(CRT_SKIP_DEF_WSTRTRUNCATE) && (!defined(CRT_DEFAULT_SKIP_WRAPPER_CRT_STRING_C_DEF) || defined(CRT_WANT_DEF_WSTRTRUNCATE))  )
CRT_WCHAR * __cdecl
wstrtruncate(
    _Out_writes_(dst_size) CRT_WCHAR *dst,
    _In_ CX_SIZE_T dst_size,
    _In_ const CRT_WCHAR *src
    )
{
    return crt_wstrtruncate(dst, dst_size, src);
}
#endif

#if ( !defined(CRT_SKIP_DEF_WSTRSTR_S) && (!defined(CRT_DEFAULT_SKIP_WRAPPER_CRT_STRING_C_DEF) || defined(CRT_WANT_DEF_WSTRSTR_S))  )
CRT_WCHAR * __cdecl
wstrstr_s(
    _In_reads_z_(str_size) const CRT_WCHAR *str,
    _In_ CX_SIZE_T str_size,
    _In_z_ const CRT_WCHAR *strSearch
    )
{
    return crt_wstrstr_s(str, str_size, strSearch);
}
#endif


