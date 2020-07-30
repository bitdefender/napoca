/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/


#ifndef _CONSTS_H_
#define _CONSTS_H_

//
// little-endian / big-endian stuff
//
#define GET_WORD_LE(ptr,pos)    (*(( WORD*)(((BYTE*)(ptr)) + (pos))))
#define GET_DWORD_LE(ptr,pos)   (*((DWORD*)(((BYTE*)(ptr)) + (pos))))
#define GET_QWORD_LE(ptr,pos)   (*((QWORD*)(((BYTE*)(ptr)) + (pos))))

#define DEFAULT_BUFFER_SIZE     0x1FF

// memory size
#define ONE_KILOBYTE                        1024
#define ONE_MEGABYTE                        (1024 * ONE_KILOBYTE)
#define ONE_GIGABYTE                        ((QWORD)1024 * (QWORD)ONE_MEGABYTE)
#define ONE_TERABYTE                        ((QWORD)1024 * (QWORD)ONE_GIGABYTE)

#define ROUND_DOWN(v,a)     ((((v) % (a))==0)?(v):((v) - ((v) % (a))))
#define ROUND_UP(v,a)       ((((v) % (a))==0)?(v):((v) + ((a) - ((v) % (a)))))

// delay values for KeDelayExecutionThread()
// NOTE: values are negative to represent relative time
#define DELAY_ONE_MICROSECOND                   (-10ll)
#define DELAY_ONE_MILLISECOND                   (DELAY_ONE_MICROSECOND*1000)
#define DELAY_ONE_SECOND                        (DELAY_ONE_MILLISECOND*1000)

#define HV_COMM_POOLING_INTERVAL    1


#endif //_CONSTS_H_
