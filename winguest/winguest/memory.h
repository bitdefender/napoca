/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/


#ifndef _MEMORY_H_
#define _MEMORY_H_

#define ExFreePoolWithTagAndNull(p, tag) \
{  \
    if ((p) && (*p)) \
    { \
        ExFreePoolWithTag((*(p)), tag); \
        (*(p)) = NULL; \
    } \
}

#define TAG_STR         ':RTS'      ///< Tag that identifies string allocations
#define TAG_MSG         ':GSM'      ///< Tag that identifies communication allocations
#define TAG_BUF         ':FUB'      ///< Tag that identifies generic buffer allocations
#define TAG_LOG         ':GOL'      ///< Tag that identifies logging allocations

#endif //_MEMORY_H_
