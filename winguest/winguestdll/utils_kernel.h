/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#pragma once

NTSTATUS
EnumEfiPartitions(
    std::vector<std::wstring> &Partitions
    );
