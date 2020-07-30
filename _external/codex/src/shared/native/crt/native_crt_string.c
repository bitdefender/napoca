/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "crt/crt_crt.h"
#include "base/cx_env.h"
#include "crt/crt_string.h"
#include "crt/crt_memory.h"


CX_SIZE_T __cdecl
crt_strlen(
    _In_z_ const CX_INT8 *str
    )
{
    const CX_INT8 *eos = str;

    crt_assert(CX_NULL != str);

    if (CX_NULL == str)
    {
        return 0;
    }

    while(*eos++);

    return eos - str - 1;
}

CX_INT8 * __cdecl
crt_strcpy(
    _Out_writes_z_(_String_length_(src) + 1) CX_INT8 *dst,
    _In_z_ const CX_INT8 *src
)
{
    CX_INT8 * cp = dst;

#ifdef CX_MSVC
#pragma warning(push)
#pragma warning(suppress:4127)
#endif

    while ((*cp++ = *src++) != '\0')
        ;               /* Copy src over dst */

#ifdef CX_MSVC
#pragma warning(pop)
#endif

    return dst;
}

CX_INT8 * __cdecl
crt_strncpy(
    __out_z CX_INT8 * dst,
    _In_z_ const CX_INT8 * src,
    CX_SIZE_T               Count
)
{
    CX_INT8 *start = dst;

    while (Count && (*dst++ = *src++) != '\0')    /* copy string */
        Count--;

    if (Count)                              /* pad out with zeroes */
        while (--Count)
            *dst++ = '\0';

    return(start);

}

CX_INT8 * __cdecl
crt_strcat(
    _Inout_z_ CX_INT8 *dst,
    _In_z_ const CX_INT8 *src
       )
{
    CX_INT8 * cp = dst;

    crt_assert(CX_NULL != dst);
    crt_assert(CX_NULL != src);
    if (CX_NULL == dst || CX_NULL ==src)
        return CX_NULL;
    while (*cp)
        cp++;                   /* find end of dst */

    while ((*cp++ = *src++) != '\0');       /* Copy src to end of dst */

    return(dst);                  /* return dst */
}

CX_INT8 * __cdecl
crt_strncat(
    __out_z CX_INT8 * dst,
    _In_z_ const CX_INT8 * src,
    CX_SIZE_T               Count
)
{
    CX_INT8 *start = dst;

    while (*dst++)
        ;
    dst--;

    while (Count--)
        if ((*dst++ = *src++) == 0)
            return(start);

    *dst = '\0';
    return(start);
}

CX_INT32 __cdecl
crt_strcmp(
    _In_z_ const CX_INT8 *src,
    _In_z_ const CX_INT8 *dst
    )
{
    CX_INT32 ret = 0;

    while ((ret = *(CX_UINT8 *)src - *(CX_UINT8 *)dst) == 0 && *dst)
        ++src, ++dst;

    if (ret < 0)
        ret = -1;
    else if (ret > 0)
        ret = 1;

    return(ret);
}

CX_SIZE_T __cdecl
crt_wstrlen(
    _In_z_ const CRT_WCHAR *str
       )
{
    CX_SIZE_T i;

    crt_assert(CX_NULL != str);

    if (CX_NULL == str)
    {
        return 0;
    }

    for (i = 0; str[i] != 0; i++);

    return i;
}

CX_INT8 * __cdecl
crt_strstr(
    _In_z_ const CX_INT8 *str1,
    _In_z_ const CX_INT8 *str2
    )
{
    CX_INT8 *cp = (CX_INT8 *) str1;
    CX_INT8 *s1, *s2;

    crt_assert(CX_NULL != str1);
    crt_assert(CX_NULL != str2);

    if (CX_NULL == str1 || CX_NULL == str2)
    {
        return CX_NULL;
    }

    if (!*str2)
    {
        return (CX_INT8 *)str1;
    }

    while (*cp)
    {
        s1 = cp;
        s2 = (CX_INT8 *) str2;

        while (*s1 && *s2 && !(*s1-*s2))
        {
            s1++;
            s2++;
        }

        if (!*s2)
        {
            return cp;
        }

        cp++;
    }

    return CX_NULL;
}

CX_INT8 * __cdecl
crt_strchr(
    _In_z_ const CX_INT8 *str,
    _In_ CX_INT32 c
    )
{
    crt_assert(CX_NULL != str);

    if (CX_NULL == str)
    {
        return CX_NULL;
    }

    while (*str && *str != (CX_INT8)c)
    {
        str++;
    }

    if (*str == (CX_INT8)c)
    {
        return (CX_INT8 *)str;
    }

    return CX_NULL;
}

CX_INT8 * __cdecl
crt_strrchr(
    _In_z_ const CX_INT8 *str,
    _In_ CX_INT32 c
    )
{
    CX_INT8 *start = (CX_INT8 *)str;

    crt_assert(CX_NULL != str);
    if (CX_NULL == str)
    {
        return CX_NULL;
    }

    while (*str++);

    // Search towards front
    while (--str != start && *str != (CX_INT8)c)
    {
        ;
    }

    if (*str == (CX_INT8)c)
    {
        return (CX_INT8 *)str;
    }

    return CX_NULL;
}

CX_INT32 __cdecl
crt_stricmp(
    _In_z_ const CX_INT8 *str1,
    _In_z_ const CX_INT8 *str2
    )
{
    CX_INT32 f;
    CX_INT32 l;

    do
    {
        f = (CX_UINT8)*str1;
        l = (CX_UINT8)*str2;

        if ((f >= 'A') && (f <= 'Z'))
        {
            f |= 0x20;
        }

        if ((l >= 'A') && (l <= 'Z'))
        {
            l |= 0x20;
        }

        str1++;
        str2++;
    }
    while (f && (f == l));

    return f - l;
}

CX_INT32 __cdecl
crt_strncmp(
    _In_reads_or_z_(count)  const CX_INT8 *first,
    _In_reads_or_z_(count)  const CX_INT8 *last,
    _In_ CX_SIZE_T count
    )
{
    CX_SIZE_T x = 0;

    crt_assert(CX_NULL != first);
    crt_assert(CX_NULL != last);

    if (CX_NULL == first || CX_NULL == last)
    {
        return 0;
    }

    if (!count)
    {
        return 0;
    }

    /*
     * This explicit guard needed to deal correctly with boundary
     * cases: strings shorter than 4 bytes and strings longer than
     * UINT_MAX-4 bytes .
     */
    if (count >= 4)
    {
        /* unroll by four */
        for (; x < count - 4; x += 4)
        {
            first += 4;
            last += 4;

            if (*(first-4) == 0 || *(first - 4) != *(last - 4))
            {
                return *(CX_UINT8 *)(first - 4) - *(CX_UINT8 *)(last - 4);
            }

            if (*(first - 3) == 0 || *(first - 3) != *(last - 3))
            {
                return *(CX_UINT8 *)(first - 3) - *(CX_UINT8 *)(last - 3);
            }

            if (*(first - 2) == 0 || *(first - 2) != *(last - 2))
            {
                return *(CX_UINT8 *)(first - 2) - *(CX_UINT8 *)(last - 2);
            }

            if (*(first - 1) == 0 || *(first - 1) != *(last - 1))
            {
                return *(CX_UINT8 *)(first - 1) - *(CX_UINT8 *)(last - 1);
            }
        }
    }

    /* residual loop */
    for (; x < count; x++)
    {
        if (*first == 0 || *first != *last)
        {
            return *(CX_UINT8 *)first - *(CX_UINT8 *)last;
        }

        first++;
        last++;
    }

    return 0;
}

CX_INT32 __cdecl
crt_strnicmp(
    _In_reads_or_z_(count)   const CX_INT8 *str1,
    _In_reads_or_z_(count)   const CX_INT8 *str2,
    _In_ CX_SIZE_T count
    )
{
    CX_INT32 f;
    CX_INT32 l;

    if (0 == count)
    {
        return 0;
    }

    do
    {
        f = (CX_UINT8)*str1;
        l = (CX_UINT8)*str2;

        if ((f >= 'A') && (f <= 'Z'))
        {
            f |= 0x20;
        }

        if ((l >= 'A') && (l <= 'Z'))
        {
            l |= 0x20;
        }

        str1++;
        str2++;
    }
    while (--count && f && (f == l));

    return f - l;
}

CX_INT8 * __cdecl
crt_strend(
    _In_z_ const CX_INT8 *str,
    _In_ CX_SIZE_T count
    )
{
    const CX_INT8 *eos = str;
    CX_SIZE_T len;

    crt_assert(CX_NULL != str);

    if (CX_NULL == str)
    {
        return CX_NULL;
    }

    while( *eos++ ) ;

    len = (eos - str - 1);

    if (count >= len)
    {
        return (CX_INT8*)str;
    }
    else
    {
        return (CX_INT8*)&(str[len - count]);
    }
}

CX_SIZE_T __cdecl
crt_strlen_s(
    _In_z_ const CX_INT8 *str,
    _In_ CX_SIZE_T size)
{
    CX_SIZE_T len = 0;

    crt_assert(CX_NULL != str);

    if (CX_NULL == str)
    {
        return 0;
    }

    for (len = 0; (len < size) && (str[len]); len++);

    if (str[len] == 0)
    {
        return len;
    }
    else
    {
        //
        // See MSDN note:
        // If there is no CX_NULL terminator within the first numberOfElements bytes
        // of the string, then `size` is returned to indicate the error condition;
        // CX_NULL-terminated strings have lengths that are strictly less than `size`.
        //
        return size;
    }
}

CX_SIZE_T __cdecl
crt_wstrlen_s(
    _In_reads_z_(size) const CRT_WCHAR *str,
    _In_ CX_SIZE_T size)
{
    CX_SIZE_T len = 0;

    crt_assert(CX_NULL != str);

    if (size == 0)
    {
        return 0;
    }

    if (CX_NULL == str)
    {
        return 0;
    }

    for (len = 0; (len < size) && (str[len]); len++);
//#TODO: suppress
    if (str[len] == 0)
    {
        return len;
    }
    else
    {
        // see crt_strlen_s for reason why `size`
        return size;
    }
}

_Use_decl_annotations_
CX_INT8 * __cdecl
crt_strcpy_s(
    _Out_writes_z_(dst_size) CX_INT8 *dst,
    _In_ CX_SIZE_T dst_size,
    _In_z_ const CX_INT8 *src)
{
    CX_INT8 * cp = dst;
    CX_SIZE_T s = 0;

    if (dst_size == 0)
    {
        return dst;
    }

    while (s < dst_size)
    {
        *cp = *src;

        if (0 == *cp)
        {
            break;
        }

        cp++;
        src++;
        s++;
    }

    if (s == dst_size && dst[s] != 0)
    {
        crt_memzero(dst, dst_size);
        return CX_NULL;
    }

    return dst;
}

CX_INT8 * __cdecl
crt_strcat_s(
    _Inout_updates_z_(dst_size)CX_INT8 *dst,
    _In_ CX_SIZE_T dst_size,
    _In_z_ const CX_INT8 *src)
{
    CX_INT8 *p = CX_NULL;
    CX_SIZE_T available;

    crt_assert(CX_NULL != dst);
    crt_assert(CX_NULL != src);
    if (CX_NULL == dst)
    {
        return CX_NULL;
    }

    p = dst;
    available = dst_size;
    while (available > 0 && *p != 0)
    {
        p++;
        available--;
    }

    if (available == 0)
    {
        crt_memzero(dst, dst_size);
        return CX_NULL;
    }

    while ((*p++ = *src++) != 0 && --available > 0);

    if (available == 0)
    {
        crt_memzero(dst, dst_size);
        return CX_NULL;
    }

    return dst;
}

CX_INT8 * __cdecl
crt_strstr_s(
    _In_reads_z_(str_size) const CX_INT8 *str,
    _In_ CX_SIZE_T str_size,
    _In_z_ const CX_INT8 *strSearch)
{
    CX_INT8 *cp = (CX_INT8 *) str;
    CX_INT8 *s1, *s2;
    CX_SIZE_T i = 0, j = 0;

    crt_assert(CX_NULL != str);
    crt_assert(CX_NULL != strSearch);

    if (CX_NULL == str || CX_NULL == strSearch)
    {
        return CX_NULL;
    }

    if (!*strSearch)
    {
        return (CX_INT8 *)str;
    }

    while (i < str_size && *cp)
    {
        s1 = cp;
        s2 = (CX_INT8 *)strSearch;
        j = i;

        while (j < str_size && *s1 && *s2 && !(*s1 - *s2))
        {
            s1++;
            s2++;
            j++;
        }

        if (!*s2)
        {
            return cp;
        }

        cp++;
        i++;
    }

    return CX_NULL;
}

CX_INT8 * __cdecl
crt_strchr_s(
    _In_reads_z_(str_size)  const CX_INT8 *str,
    _In_ CX_SIZE_T str_size,
    _In_ CX_INT32 c)
{
    CX_SIZE_T i = 0;

    crt_assert(CX_NULL != str);
    if (CX_NULL == str)
    {
        return CX_NULL;
    }

    while (i < str_size && *str)
    {
        if (*str == (CX_INT8)c)
        {
            return (CX_INT8 *)str;
        }

        str++;
        i++;
    }

    return(CX_NULL);
}

CX_INT8 * __cdecl
crt_strrchr_s(
    _In_reads_z_(str_size) const CX_INT8 *str,
    _In_ CX_SIZE_T str_size,
    _In_ CX_INT32 c)
{
    CX_INT8 *start = (CX_INT8 *)str;
    CX_SIZE_T i = 0;

    crt_assert(CX_NULL != str);
    if (CX_NULL == str)
    {
        return CX_NULL;
    }

    if (0 == str_size)
    {
        return 0;
    }

    while (i < str_size && *str++)
    {
        i++;
    }

    if (i == str_size && start[i-1] != 0)
    {
        return CX_NULL;
    }

    // search towards front
    while (--str != start && *str != (CX_INT8)c);

    if (*str == (CX_INT8)c)
    {
        return (CX_INT8 *)str;
    }

    return CX_NULL;
}

CX_INT8 * __cdecl
crt_strend_s(
    _In_reads_z_(str_size) const CX_INT8 *str,
    _In_ CX_SIZE_T str_size,
    _In_ CX_SIZE_T count)
{
    const CX_INT8 *eos = str;
    CX_SIZE_T len;
    CX_SIZE_T i = 0;

    crt_assert(CX_NULL != str);

    if (CX_NULL == str)
    {
        return CX_NULL;
    }
    if (0 == str_size)
    {
        return 0;
    }

    while(i < str_size && *eos++ )
    {
        i++;
    }

    if (i == str_size && str[i-1] != 0)
    {
        return CX_NULL;
    }

    len = (eos - str - 1);

    if (count >= len)
    {
        return (CX_INT8*)str;
    }
    else
    {
        return (CX_INT8*)&(str[len - count]);
    }
}

CX_INT8 * __cdecl
crt_strtruncate(
    _Out_writes_bytes_(dst_size) CX_INT8 *dst,
    _In_ CX_SIZE_T dst_size,
    _In_ const CX_INT8 *src
    )
{
    CX_INT8 *p = dst;
    const CX_INT8 *s = src;
    CX_SIZE_T copied = 0;

    crt_assert(CX_NULL != dst);
    crt_assert(CX_NULL != src);
    if (!dst || !src || 0 == dst_size)
    {
        return CX_NULL;
    }

    while (copied < dst_size)
    {
        *p = *s;
        if (*p == '\0')
        {
            break;
        }

        p++;
        s++;
        copied++;
    }

    // Put the CX_NULL-terminator if necessary
    if (copied == dst_size)
    {
        dst[copied - 1] = '\0';
    }

    return dst;
}

CRT_WCHAR * __cdecl
crt_wstrtruncate(
    _Out_writes_(dst_size) CRT_WCHAR *dst,
    _In_ CX_SIZE_T dst_size,
    _In_ const CRT_WCHAR *src
    )
{
    CRT_WCHAR *p = dst;
    const CRT_WCHAR *s = src;
    CX_SIZE_T copied = 0;

    crt_assert(CX_NULL != dst);
    crt_assert(CX_NULL != src);
    if (!dst || !src || 0 == dst_size)
    {
        return CX_NULL;
    }

    while (copied < dst_size)
    {
        *p = *s;
        if (*p == 0)
        {
            break;
        }

        p++;
        s++;
        copied++;
    }

    // Put the CX_NULL-terminator if necessary
    if (copied == dst_size)
    {
        dst[copied - 1] = 0;
    }

    return dst;
}

CRT_WCHAR * __cdecl
crt_wstrstr_s(
    _In_reads_z_(str_size) const CRT_WCHAR *str,
    _In_ CX_SIZE_T str_size,
    _In_z_ const CRT_WCHAR *strSearch
    )
{
    crt_assert(CX_NULL != str);
    crt_assert(CX_NULL != strSearch);
    
    CX_SIZE_T i = 0, j = 0;
    CRT_WCHAR *s1, *s2, *str_init = (CRT_WCHAR*)str;

    if (CX_NULL == str || CX_NULL == strSearch)
    {
        return CX_NULL;
    }

    if (!*strSearch)
    {
        return (CRT_WCHAR*)str;
    }

    while (i < str_size && *str_init)
    {
        j = i;
        s2 = (CRT_WCHAR*)strSearch;
        s1 = str_init;
        
        while (j < str_size && *s2 && !(*s2 - *s1))
        {
            j++;
            s2++;
            s1++;
        }

        if (!*s2)
        {
            return str_init;
        }

        i++;
        str_init++;
    }

    return CX_NULL;
}
