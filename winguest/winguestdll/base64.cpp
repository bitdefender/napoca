/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file base64.cpp
*   @brief Convert to/from BASE64
*/

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>

typedef unsigned __int64        QWORD;
typedef _Return_type_success_(return >= 0) long NTSTATUS;

#include "base64.h"

static const CHAR Base64Forward[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const CHAR Base64Reverse[256] = {
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,62, -1,-1,-1,63,
    52,53,54,55, 56,57,58,59, 60,61,-1,-1, -1,-1,-1,-1,
    -1, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,
    15,16,17,18, 19,20,21,22, 23,24,25,-1, -1,-1,-1,-1,
    -1,26,27,28, 29,30,31,32, 33,34,35,36, 37,38,39,40,
    41,42,43,44, 45,46,47,48, 49,50,51,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
};

/**
 * @brief Encode a 3 byte block to Base64
 *
 * @param[out] Out              Output block to store converted result
 * @param[in]  In               Input block that must be encoded
 * @param[in]  Length           Actual number of valid bytes in input block
 */
static
VOID
BlockToBase64(
    __in BYTE Out[4],
    __in const BYTE In[3],
    __in QWORD Length)
{
    Out[0] = Base64Forward[ In[0] >> 2 ];
    Out[1] = Base64Forward[ ((In[0] & 0x03) << 4) | ((In[1] & 0xf0) >> 4) ];
    Out[2] = (BYTE) (Length > 1 ? Base64Forward[ ((In[1] & 0x0f) << 2) | ((In[2] & 0xc0) >> 6) ] : '=');
    Out[3] = (BYTE) (Length > 2 ? Base64Forward[In[2] & 0x3f] : '=');
}

/**
 * @brief Decode 4 byte block from Base64
 *
 * @param[out] Out              Output block to store converted result
 * @param[in]  In               Input block that must be decoded
 *
 * @return Valid bytes after conversion
 */
static
QWORD
BlockFromBase64(
    __out BYTE Out[3],
    __in const BYTE In[4])
{
    INT32 i = 0;
    DWORD numbytes = 3;
    CHAR tmp[4];

    for(i = 3; i >= 0; i--) {
        if(In[i] == '=') {
            tmp[i] = 0;
            numbytes = i - 1;
        } else {
            tmp[i] = Base64Reverse[ (BYTE)In[i] ];
        }

        if(tmp[i] == -1)
            return (QWORD)(-1);
    }

    Out[0] = (BYTE) (  tmp[0] << 2 | tmp[1] >> 4);
    Out[1] = (BYTE) (  tmp[1] << 4 | tmp[2] >> 2);
    Out[2] = (BYTE) (((tmp[2] << 6) & 0xc0) | tmp[3]);

    return numbytes;
}

/**
 * @brief Encode buffer to Base64
 *
 * @param[out] Out              Output Buffer to store converted Base64 result
 * @param[in]  In               Input buffer that must be encoded
 * @param[in]  InLength         Input buffer length
 * @param[in]  OutLength        Output Buffer length
 *
 * @return STATUS_SUCCESS
 * @return OTHER                Other potential internal error
 */
NTSTATUS
Tobase64(
    __out CHAR *Out,
    __in const BYTE *In,
    __in QWORD InLength,
    __in QWORD OutLength
    )
{
    QWORD size;
    QWORD i = 0;

    if (NULL == Out)
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == In)
    {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (OutLength < GetToBase64Size(InLength))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    while(i < InLength)
    {
        size = min(InLength - i, 4);

        BlockToBase64((BYTE *)Out, In, size);

        Out += 4;
        In  += 3;
        i   += 3;
    }

    *Out = '\0';
    return STATUS_SUCCESS;
}


/**
 * @brief Decode buffer from Base64
 *
 * @param[out] Out              Output Buffer to store decoded result
 * @param[in]  In               Input Base64 buffer
 * @param[in]  OutLength        Output Buffer length
 *
 * @return STATUS_SUCCESS
 * @return OTHER                Other potential internal error
 */
NTSTATUS
FromBase64(
    __out BYTE *Out,
    __in const CHAR *In,
    __in QWORD OutLength
    )
{
    QWORD len, i = 0;
    QWORD ret = 0;

    if (NULL == Out)
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == In)
    {
        return STATUS_INVALID_PARAMETER_2;
    }

    len = strlen(In);
    if (OutLength < GetFromBase64Size(len))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    while(i < len)
    {
        ret = BlockFromBase64(Out, (BYTE *)In);
        if((INT64)ret < 0)
        {
            return STATUS_DATA_ERROR;
        }

        Out += 3;
        In  += 4;
        i   += 4;
    }

    return STATUS_SUCCESS;
}

