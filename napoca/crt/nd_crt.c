/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "napoca.h"

int
nd_vsnprintf_s(char *str, CX_SIZE_T sizeOfBuffer, CX_SIZE_T count, const char *format, va_list args)
{
    UNREFERENCED_PARAMETER(sizeOfBuffer);

    return crt_rpl_vsnprintf(str, count, format, args);
}

void*
nd_memset(void *s, int c, CX_SIZE_T n)
{
    return crt_memset(s, c, n);
}