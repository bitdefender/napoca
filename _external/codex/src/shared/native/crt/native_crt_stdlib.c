/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "crt/crt_crt.h"

//
// pseudo-random number generator
//
static volatile CX_UINT64 gCrtRandQ = 1234567890876543;

// check out also the multiply-with-carry method at http://en.wikipedia.org/wiki/Random_number_generation

CX_VOID
crt_srand(
    CX_INT32 seed )
{
    CX_UINT64 oldSeed, newSeed;

    oldSeed = gCrtRandQ;

    // we update only 32 bits from the old seed
    newSeed = 
        ((oldSeed & 0x0000FFFF00000000ULL) << 16) |
        (((CX_UINT64)(seed & 0xFFFF0000)) << 16) |
        ((oldSeed & 0x000000000000FFFFULL) << 16) |
        ((CX_UINT64)(seed & 0xFFFF0000));

    gCrtRandQ = newSeed;
}


CX_INT32
crt_rand(
    CX_VOID )
{
    CX_UINT64 q;
    CX_UINT32 w, z;
    CX_UINT32 nw, nz;

    // get atomically the last Q value and extract W and Z
    q = gCrtRandQ;
    z = (CX_UINT32)(q >> 32);
    w = (CX_UINT32)q;

    // determine NEW W and Z values
    nz = 36969 * (z & 0xffff) + (z >> 16);
    nw = 18000 * (w & 0xffff) + (w >> 16);

    // store atomically Q
    q = (((CX_UINT64)nz) << 32) | nw;
    gCrtRandQ = q;

    // returns random value
    return (CX_INT32)(((nz << 16) + nw) & 0x000000007FFFFFFFULL);
}
