/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifdef CRT_INC_SETTINGS_WRAPPER_CRT_CONV_C
#include CRT_INC_SETTINGS_WRAPPER_CRT_CONV_C // define it to some .h file name/path if you want to provide settings
#endif


#include "crt/crt_crt.h"

#if ( !defined(CRT_SKIP_DEF_STRTOL) && (!defined(CRT_DEFAULT_SKIP_WRAPPER_CRT_CONV_C_DEF) || defined(CRT_WANT_DEF_STRTOL))  )
CX_INT32 __cdecl 
strtol(
    _In_z_ const CX_INT8 *nptr,
    __out_opt CX_INT8 **endptr,
    _In_ CX_INT32 ibase
    )
{
    return crt_strtol(nptr, endptr, ibase);
}
#endif


#if ( !defined(CRT_SKIP_DEF_STRTOUL) && (!defined(CRT_DEFAULT_SKIP_WRAPPER_CRT_CONV_C_DEF) || defined(CRT_WANT_DEF_STRTOUL))  )
CX_UINT32 __cdecl 
strtoul(
    _In_z_ const CX_INT8 *nptr,
    __out_opt CX_INT8 **endptr,
    _In_ CX_INT32 ibase
    )
{
    return crt_strtoul(nptr, endptr, ibase);
}
#endif


#if ( !defined(CRT_SKIP_DEF_STRTOLL) && (!defined(CRT_DEFAULT_SKIP_WRAPPER_CRT_CONV_C_DEF) || defined(CRT_WANT_DEF_STRTOLL))  )
CX_INT64 __cdecl 
strtoll(
    _In_z_ const CX_INT8 *nptr,
    __out_opt CX_INT8 **endptr,
    _In_ CX_INT32 ibase
    )
{
    return crt_strtoll(nptr, endptr, ibase);
}
#endif


#if ( !defined(CRT_SKIP_DEF_STRTOULL) && (!defined(CRT_DEFAULT_SKIP_WRAPPER_CRT_CONV_C_DEF) || defined(CRT_WANT_DEF_STRTOULL))  )
CX_UINT64 __cdecl 
strtoull(
    _In_z_ const CX_INT8 *nptr,
    __out_opt CX_INT8 **endptr,
    _In_ CX_INT32 ibase
    )
{
    return crt_strtoull(nptr, endptr, ibase);
}
#endif



