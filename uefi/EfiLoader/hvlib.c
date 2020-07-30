/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "uefi_internal.h"
#include "MemDebugLib/MemDebugLib.c"
#include "FileOperationsLib/FileOperationsLib.c"

EFI_GUID gEfiCertSha384Guid = EFI_CERT_SHA384_GUID;
EFI_GUID gEfiCertX509Sha512Guid = EFI_CERT_X509_SHA512_GUID;
EFI_GUID gEfiCertX509Sha256Guid = EFI_CERT_X509_SHA256_GUID;
EFI_GUID gEfiCertX509Sha384Guid = EFI_CERT_X509_SHA384_GUID;
EFI_GUID gEfiCertSha512Guid = EFI_CERT_SHA512_GUID;