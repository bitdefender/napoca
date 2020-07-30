/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

char* CxStatusToString (int Status, int ReturnNullIfUnknown)
{
    if (Status == 0x00000000) return "CX_STATUS_SUCCESS";
    if (Status == 0x61000000) return "CX_STATUS_NOT_NEEDED_HINT";
    if (Status == 0x61000001) return "CX_STATUS_NOT_INITIALIZED_HINT";
    if (Status == 0x61000002) return "CX_STATUS_ALREADY_INITIALIZED_HINT";
    if (Status == 0x61000003) return "CX_STATUS_REINITIALIZED_HINT";
    if (Status == 0x61000004) return "CX_STATUS_FOUND";
    if (Status == 0xE1000000) return "CX_STATUS_INVALID_PARAMETER";
    if (Status == 0xE1000001) return "CX_STATUS_INVALID_PARAMETER_1";
    if (Status == 0xE1000002) return "CX_STATUS_INVALID_PARAMETER_2";
    if (Status == 0xE1000003) return "CX_STATUS_INVALID_PARAMETER_3";
    if (Status == 0xE1000004) return "CX_STATUS_INVALID_PARAMETER_4";
    if (Status == 0xE1000005) return "CX_STATUS_INVALID_PARAMETER_5";
    if (Status == 0xE1000006) return "CX_STATUS_INVALID_PARAMETER_6";
    if (Status == 0xE1000007) return "CX_STATUS_INVALID_PARAMETER_7";
    if (Status == 0xE1000008) return "CX_STATUS_INVALID_PARAMETER_8";
    if (Status == 0xE1000009) return "CX_STATUS_INVALID_PARAMETER_9";
    if (Status == 0xE100000A) return "CX_STATUS_INVALID_PARAMETER_10";
    if (Status == 0xE100000B) return "CX_STATUS_INVALID_PARAMETER_11";
    if (Status == 0xE100000C) return "CX_STATUS_INVALID_PARAMETER_12";
    if (Status == 0xE100000D) return "CX_STATUS_INVALID_PARAMETER_MIX";
    if (Status == 0xE1000100) return "CX_STATUS_COMPONENT_NOT_INITIALIZED";
    if (Status == 0xE1000101) return "CX_STATUS_COMPONENT_ALREADY_INITIALIZED";
    if (Status == 0xE1000102) return "CX_STATUS_COMPONENT_NOT_READY";
    if (Status == 0xE1000103) return "CX_STATUS_COMPONENT_NOT_FOUND";
    if (Status == 0xE1000104) return "CX_STATUS_COMPONENT_LIFECYCLE_ENDED";
    if (Status == 0xE1000105) return "CX_STATUS_INVALID_COMPONENT_STATE";
    if (Status == 0xE1000106) return "CX_STATUS_OPERATION_NOT_SUPPORTED";
    if (Status == 0xE1000107) return "CX_STATUS_OPERATION_NOT_IMPLEMENTED";
    if (Status == 0xE1000108) return "CX_STATUS_INVALID_OPERATION_STATE";
    if (Status == 0xE1000109) return "CX_STATUS_COMPONENT_BUSY";
    if (Status == 0xE1000200) return "CX_STATUS_INVALID_DATA_VALUE";
    if (Status == 0xE1000201) return "CX_STATUS_INVALID_DATA_TYPE";
    if (Status == 0xE1000202) return "CX_STATUS_INVALID_DATA_SIZE";
    if (Status == 0xE1000203) return "CX_STATUS_INCONSISTENT_DATA_VALUE";
    if (Status == 0xE1000204) return "CX_STATUS_INCONSISTENT_DATA_SIZE";
    if (Status == 0xE1000205) return "CX_STATUS_CORRUPTED_DATA";
    if (Status == 0xE1000206) return "CX_STATUS_DATA_NOT_INITIALIZED";
    if (Status == 0xE1000207) return "CX_STATUS_DATA_IN_USE";
    if (Status == 0xE1000208) return "CX_STATUS_DATA_ALREADY_EXISTS";
    if (Status == 0xE1000209) return "CX_STATUS_DATA_ALREADY_INITIALIZED";
    if (Status == 0xE100020A) return "CX_STATUS_DATA_ALREADY_FREE";
    if (Status == 0xE100020B) return "CX_STATUS_DATA_NOT_FOUND";
    if (Status == 0xE100020C) return "CX_STATUS_DATA_NOT_READY";
    if (Status == 0xE100020D) return "CX_STATUS_DATA_LIFECYCLE_ENDED";
    if (Status == 0xE100020E) return "CX_STATUS_INVALID_DATA_STATE";
    if (Status == 0xE100020F) return "CX_STATUS_DATA_DOMAIN_OVERFLOW";
    if (Status == 0xE1000210) return "CX_STATUS_ALIGNMENT_INCONSISTENCY";
    if (Status == 0xE1000211) return "CX_STATUS_DATA_BUFFER_TOO_SMALL";
    if (Status == 0xE1000212) return "CX_STATUS_BUFFER_UNDERFLOW";
    if (Status == 0xE1000213) return "CX_STATUS_BUFFER_OVERFLOW";
    if (Status == 0xE1000214) return "CX_STATUS_OUT_OF_RESOURCES";
    if (Status == 0xE1000215) return "CX_STATUS_OUT_OF_MEMORY";
    if (Status == 0xE1000216) return "CX_STATUS_INDEX_OUT_OF_RANGE";
    if (Status == 0xE1000217) return "CX_STATUS_NO_MORE_ENTRIES";
    if (Status == 0xE1000218) return "CX_STATUS_ARITHMETIC_UNDERFLOW";
    if (Status == 0xE1000219) return "CX_STATUS_ARITHMETIC_OVERFLOW";
    if (Status == 0xE100021A) return "CX_STATUS_UNSUPPORTED_DATA_VALUE";
    if (Status == 0xE100021B) return "CX_STATUS_UNSUPPORTED_DATA_TYPE";
    if (Status == 0xE100021C) return "CX_STATUS_UNSUPPORTED_DATA_SIZE";
    if (Status == 0xE100021D) return "CX_STATUS_DATA_OUT_OF_RANGE";
    if (Status == 0xE100021E) return "CX_STATUS_KEY_ALREADY_EXISTS";
    if (Status == 0xE100021F) return "CX_STATUS_KEY_NOT_FOUND";
    if (Status == 0xE1000300) return "CX_STATUS_BAD_DEVICE_TYPE";
    if (Status == 0xE1000301) return "CX_STATUS_DEVICE_DATA_ERROR";
    if (Status == 0xE1000302) return "CX_STATUS_DEVICE_IO_ERROR";
    if (Status == 0xE1000303) return "CX_STATUS_DEVICE_NOT_INITIALIZED";
    if (Status == 0xE1000304) return "CX_STATUS_DEVICE_NOT_READY";
    if (Status == 0xE1000305) return "CX_STATUS_DEVICE_NOT_RESPONDING";
    if (Status == 0xE1000306) return "CX_STATUS_DEVICE_POWER_FAILURE";
    if (Status == 0xE1000307) return "CX_STATUS_DEVICE_NOT_FOUND";
    if (Status == 0xE1000308) return "CX_STATUS_INVALID_DEVICE_ID";
    if (Status == 0xE1000309) return "CX_STATUS_INVALID_DEVICE_TYPE";
    if (Status == 0xE100030A) return "CX_STATUS_INVALID_DEVICE_REQUEST";
    if (Status == 0xE100030B) return "CX_STATUS_INVALID_DEVICE_STATE";
    if (Status == 0xE100030C) return "CX_STATUS_DEVICE_CONFIGURATION_ERROR";
    if (Status == 0xE100030D) return "CX_STATUS_DEVICE_BUSY";
    if (Status == 0xE1000401) return "CX_STATUS_ABORTED_ON_TIMEOUT";
    if (Status == 0xE1000402) return "CX_STATUS_ABORTED_ON_CRITICAL_FAULT";
    if (Status == 0xE1000403) return "CX_STATUS_DATA_ALTERED_FROM_OUSIDE";
    if (Status == 0xE1000404) return "CX_STATUS_SYNCHRONIZATION_INCONSISTENCY";
    if (Status == 0xE1000500) return "CX_STATUS_ALREADY_INITIALIZED";
    if (Status == 0xE1000501) return "CX_STATUS_NOT_INITIALIZED";
    if (Status == 0xE1000502) return "CX_STATUS_UNEXPECTED_RACE_CONDITION";
    if (Status == 0xE1000503) return "CX_STATUS_INVALID_INTERNAL_STATE";
    if (Status == 0xE1000504) return "CX_STATUS_OUT_OF_RANGE";
    if (Status == 0xE1000505) return "CX_STATUS_UNINITIALIZED_STATUS_VALUE";
    if (Status == 0xE1000506) return "CX_STATUS_INSUFFICIENT_RESOURCES";
    if (Status == 0xE1000507) return "CX_STATUS_NOT_FOUND";
    if (Status == 0xE1000508) return "CX_STATUS_NOT_SUPPORTED";
    if (Status == 0xE1000509) return "CX_STATUS_ACCESS_DENIED";
    if (Status == 0xE100050A) return "CX_STATUS_UNEXPECTED_IO_ERROR";
    if (Status == 0xE100050B) return "CX_STATUS_ACCESS_VIOLATION";
    if (Status == 0xE100050C) return "CX_STATUS_ABANDONED";
    if (Status == 0xE100050D) return "CX_STATUS_OBJECT_TYPE_MISMATCH";
    if (Status == 0xE100050E) return "CX_STATUS_INVALID_HANDLE";
    if (Status == 0xE100050F) return "CX_STATUS_NOT_READY";
    if (Status == 0xE1000510) return "CX_STATUS_BUSY";
    return ReturnNullIfUnknown? ((char *)0) : "_UNKNOWN_STATUS_";
}