/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "autogen/napoca_buildconfig.h"

#include "napoca.h"
#include "kernel/kernel.h"
#include "wrappers/crt_short/crt.h"
#include "memory/heap.h"

typedef size_t time_t;


void
__cdecl
abort(void)
{
    ERROR("%s (not implemented!) was called\n", __FUNCTION__);
    __debugbreak();
}

// helper for realloc implementation
// lame but does the job
// !!! Not thread safe !!!
typedef struct _ALLOC_ITEM_INFO
{
    PVOID Address;
    UINT64 Size;
}ALLOC_ITEM_INFO;

#define MAX_ALLOC_ITEM_INFO 2048
static ALLOC_ITEM_INFO gAllocs[MAX_ALLOC_ITEM_INFO] = { 0 };
UINT64 gTotalOpenSSLBytes = 0;

void*
__cdecl
malloc(size_t Size)
{
    void* buffer;
    NTSTATUS status;

    if (HpInitialized())
    {
        status = HpAllocWithTag(&buffer, Size, TAG_OPENSSL);
        if (!NT_SUCCESS(status))
        {
            LOG_FUNC_FAIL("HpAllocWithTag", status);
            return NULL;
        }

        //LOG("Allocated from heap address: %p size: 0x%x\n", buffer, allocSize);
    }
    else
    {
        status = LdAlloc(gTempMem, Size, PAGE_SIZE, (UINT64*)&buffer, NULL);
        if (!NT_SUCCESS(status))
        {
            LOG_FUNC_FAIL("LdAlloc", status);
            return NULL;
        }

        for (UINT32 i = 0; i < MAX_ALLOC_ITEM_INFO; i++)
        {
            if (gAllocs[i].Address == NULL)
            {
                gAllocs[i].Address = buffer;
                gAllocs[i].Size = Size;
                break;
            }
        }

        //LOG("Allocated from loader provided memory address: %p size: 0x%x\n", buffer, allocSize);
    }

    gTotalOpenSSLBytes += Size;

    return buffer;
}

void
__cdecl
free(void* Ptr)
{
    if (!Ptr)
    {
        //WARNING("free called with NULL pointer\n");
        return;
    }

    if (HpInitialized() && HpIsValidHeapAddress(Ptr))
    {
        //LOG("Free memory allocated from heap address: %p\n", Ptr);
        HpFreeAndNullWithTag(&Ptr, TAG_OPENSSL);
    }
    else
    {
        //LOG("Free (ignore) memory allocated from loader provided memory address: %p.\n", Ptr);

        for (UINT32 i = 0; i < MAX_ALLOC_ITEM_INFO; i++)
        {
            if (gAllocs[i].Address == Ptr)
            {
                gAllocs[i].Address = NULL;
                gAllocs[i].Size = 0;
                return;
            }
        }

        //ERROR("Request to free unrecognized buffer: %p\n", Ptr)
    }
}

void*
__cdecl
realloc(void* Ptr, size_t NewSize)
{
    //PVOID oldBuffer = Ptr;

    if (HpInitialized() && HpIsValidHeapAddress(Ptr))
    {
        NTSTATUS status;
        UINT32 oldSize = 0;

        HpGetAllocationSize(Ptr, &oldSize);

        status = HpReallocWithTag(&Ptr, (UINT32)NewSize, TAG_OPENSSL);
        if (!NT_SUCCESS(status))
        {
            LOG_FUNC_FAIL("HpReallocWithTag", status);
            return NULL;
        }

        gTotalOpenSSLBytes += (NewSize - oldSize);
        //LOG("Reallocated from heap address: %p to address: %p size: 0x%x\n", oldBuffer, Ptr, NewSize);
    }
    else
    {
        PVOID newBuff = NULL;

        newBuff = malloc(NewSize);
        if (newBuff == NULL)
        {
            LOG_FUNC_FAIL("malloc", CX_STATUS_INSUFFICIENT_RESOURCES);
            return  NULL;
        }

        UINT32 i;

        for (i = 0; i < MAX_ALLOC_ITEM_INFO; i++)
        {
            if (gAllocs[i].Address == Ptr)
            {
                memcpy(newBuff, Ptr, CX_MIN(NewSize, gAllocs[i].Size));

                gTotalOpenSSLBytes -= gAllocs[i].Size;

                break;
            }
        }

        if (i == MAX_ALLOC_ITEM_INFO)
        {
            //ERROR("Request to realloc unrecognized buffer: %p\n", Ptr)
        }

        gTotalOpenSSLBytes += NewSize;

        free(Ptr);

        Ptr = newBuff;

        //LOG("Reallocated from loader provided memory address: %p to address: %p size: 0x%x. Index: %d\n", oldBuffer, Ptr, NewSize, i);
    }

    return Ptr;
}

char*
__cdecl
getenv(const char* Name)
{
    UNREFERENCED_PARAMETER(Name);

    ERROR("%s (not implemented!) was called\n", __FUNCTION__);
    __debugbreak();

    return NULL;
}

time_t
__cdecl
time(time_t* Arg)
{
    UNREFERENCED_PARAMETER(Arg);

    ERROR("%s (not implemented!) was called\n", __FUNCTION__);
    __debugbreak();

    return 0;
}

struct tm*
__cdecl
gmtime(const time_t * Time)
{
    UNREFERENCED_PARAMETER(Time);

    ERROR("%s (not implemented!) was called\n", __FUNCTION__);
    __debugbreak();

    return NULL;
}

int
__cdecl
strncasecmp(const char *S1, const char *S2, size_t L)
{
    return strncmp(S1, S2, L);
}

size_t
__cdecl
strspn(const char* str, const char* chars)
{
    size_t i = 0;

    while (str[i] && strchr(chars, str[i])) i++;

    return i;
}

size_t
__cdecl
strcspn(const char* Str, const char* Chars)
{
    size_t i = 0;

    while (Str[i] && !strchr(Chars, Str[i])) i++;

    return i;
}

#undef isspace
int
__cdecl
isspace(
    int Ch)
{
    return crt_isspace(Ch);
}

#undef isdigit
int
__cdecl
isdigit(
    int Ch
)
{
    return crt_isdigit(Ch);
}

#undef isxdigit
int
__cdecl
isxdigit(
    int Ch
)
{
    return crt_isxdigit(Ch);
}

int
__cdecl
isalnum(
    int Ch
)
{
    return (Ch >= '0' && Ch <= '9')
        || (Ch >= 'A' && Ch <= 'Z')
        || (Ch >= 'a' && Ch <= 'z');
}

#undef isalpha
int
__cdecl
isalpha(
    int Ch
)
{
    return crt_isalpha(Ch);
}

#undef isprint
int
__cdecl
isprint(
    int Ch
)
{
    return crt_isprint(Ch);
}

#undef tolower
int
__cdecl
tolower(
    int Ch)
{
    return crt_tolower(Ch);
}

#undef toupper
int
__cdecl
toupper(
    int Ch)
{
    return crt_toupper(Ch);
}

char *
__cdecl
strerror(
    int Errnum
)
{
    UNREFERENCED_PARAMETER(Errnum);

    ERROR("%s (not implemented!) was called\n", __FUNCTION__);
    __debugbreak();

    return NULL;
}

void
__cdecl
qsort(
    void         *_Base,
    size_t        _NumOfElements,
    size_t        _SizeOfElements,
    int (__cdecl *_PtFuncCompare)(const void*, const void*)
)
{
    UNREFERENCED_PARAMETER((_Base, _NumOfElements, _SizeOfElements, _PtFuncCompare));

    ERROR("%s (not implemented!) was called\n", __FUNCTION__);
    __debugbreak();
}

int
__cdecl
sscanf(const char* Buffer, const char* Format, ...)
{
    UNREFERENCED_PARAMETER((Buffer, Format));

    ERROR("%s (not implemented!) was called\n", __FUNCTION__);
    __debugbreak();

    return 0;
}
