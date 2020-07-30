/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _CACHEDEF_H_
#define _CACHEDEF_H_

#include "core.h"

#define CHM_VA_TRANSLATIONS             128
#define CHM_VA_PAGES                    1           // no pages are actually cached, dummy 1-element array
#define CHM_PA_TRANSLATIONS             512
#define CHM_PA_PAGES                    1           // no pages are actually cached, dummy 1-element array

typedef struct _CHM_CACHE_ENTRY
{
    SIZE_T          SrcAddress;
    SIZE_T          DstAddress;
    DWORD           Priority;
}CHM_CACHE_ENTRY;

typedef struct _CHM_CACHE
{
    DWORD           NumberOfEntries;
    DWORD           NumberOfUsedEntries;
    CHM_CACHE_ENTRY *Entries;
}CHM_CACHE;

#endif