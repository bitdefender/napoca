/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/


#ifndef _COMM_MSG_H_
#define _COMM_MSG_H_

// GUEST -> HV
#define RBX_GUEST_MAGIC     0x88611357

typedef enum _MSG_TYPE { //set in EAX/RAX
    cmdTestCommand = 0,
    cmdSetOpt,
    cmdGetOpt,
    cmdInitCommunication,
    cmdUninitCommunication,
    cmdEnableInterrupts,
    cmdDisableInterrupts,
} MSG_TYPE;

//

//HV -> GUEST


#endif //_COMM_MSG_H_