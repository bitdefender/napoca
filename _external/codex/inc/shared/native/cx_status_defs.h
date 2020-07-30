/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _CX_STATUS_FACILITIES_H_
#define _CX_STATUS_FACILITIES_H_

//
// Data format details
//
/*
typedef union _CX_STATUS_BITS
{
    // || Severity:2 | Customer: | Reserved | Facility | Code ||
    CXUINT32    Code:       15 -  0 + 1; // 16
    CXUINT32    Facility:   27 - 16 + 1; // 12
    CXUINT32    _reserved:  28 - 28 + 1; // 1
    CXUINT32    Customer:   29 - 29 + 1; // 1
    CXUINT32    Severity:   31 - 30 + 1; // 2
}CX_STATUS_BITS, *PCX_STATUS_BITS;
*/

//
// Constructing new status values. 
// IMPORTANT: the use of his macro is mandatory when defining any new CX_STATUS values!
//
#ifndef CX_STATUS_TYPECAST
#define CX_STATUS_TYPECAST int
#endif

#define CX_MAKE_STATUS(severity, facility, code) \
(CX_STATUS_TYPECAST)(0uLL + \
    (((severity + 0ull) << 30uLL) | \
     ((1 + 0ull)     << 29uLL) | \
     ((facility + 0ull) << 16uLL) | \
     ((code + 0ull))) \
)

//
// Constructing new status values from win32 errors. 
// IMPORTANT: the use of his macro is mandatory when converting from win32 error codes to status codes.
//
#define CX_MAKE_STATUS_FROM_WIN32_ERROR(error) CX_MAKE_STATUS(CX_STATUS_SEVERITY_ERROR, CX_FACILITY_WIN32_ERRORS, error)

// sample usage:
// #define CX_STATUS_QUEUE_COMM_SUCCESS                     CX_MAKE_STATUS(CX_STATUS_SEVERITY_ERROR, CX_QUEUECOMM_FACILITY, 0x0)


//
// Severity-related definitions
//
#define CX_STATUS_SEVERITY_WARNING                          0x2uLL
#define CX_STATUS_SEVERITY_SUCCESS                          0x0uLL
#define CX_STATUS_SEVERITY_INFORMATIONAL                    0x1uLL
#define CX_STATUS_SEVERITY_ERROR                            0x3uLL

#define CX_SUCCESS(Status)                                  (((int)(Status)) >= 0)
#define CX_INFORMATION(Status)                              ((((int)(Status)) >> 30) == 1)
#define CX_WARNING(Status)                                  ((((int)(Status)) >> 30) == 2)
#define CX_ERROR(Status)                                    ((((int)(Status)) >> 30) == 3)



//
// Allocated facility values
//



/// WINDOWS
#define CX_FACILITY_WIN_DEBUGGER                            0x001
#define CX_FACILITY_WIN_RPC_RUNTIME                         0x002
#define CX_FACILITY_WIN_RPC_STUBS                           0x003
#define CX_FACILITY_WIN_IO_ERROR_CODE                       0x004
#define CX_FACILITY_WIN_CODCLASS_ERROR_CODE                 0x006
#define CX_FACILITY_WIN_NTWIN32                             0x007
#define CX_FACILITY_WIN_NTCERT                              0x008
#define CX_FACILITY_WIN_NTSSPI                              0x009
#define CX_FACILITY_WIN_TERMINAL_SERVER                     0x00A
#define CX_FACILITY_WIN_USB_ERROR_CODE                      0x010
#define CX_FACILITY_WIN_HID_ERROR_CODE                      0x011
#define CX_FACILITY_WIN_FIREWIRE_ERROR_CODE                 0x012
#define CX_FACILITY_WIN_CLUSTER_ERROR_CODE                  0x013
#define CX_FACILITY_WIN_ACPI_ERROR_CODE                     0x014
#define CX_FACILITY_WIN_SXS_ERROR_CODE                      0x015
/// "Facility 0x17 is reserved and used in isolation lib as PIE=0x17:FACILITY_MANIFEST_ERROR_CODE" -- whatever that means...
#define CX_FACILITY_WIN_TRANSACTION                         0x019
#define CX_FACILITY_WIN_COMMONLOG                           0x01A
#define CX_FACILITY_WIN_VIDEO                               0x01B
#define CX_FACILITY_WIN_FILTER_MANAGER                      0x01C
#define CX_FACILITY_WIN_MONITOR                             0x01D
#define CX_FACILITY_WIN_GRAPHICS_KERNEL                     0x01E
#define CX_FACILITY_WIN_DRIVER_FRAMEWORK                    0x020
#define CX_FACILITY_WIN_FVE_ERROR_CODE                      0x021
#define CX_FACILITY_WIN_FWP_ERROR_CODE                      0x022
#define CX_FACILITY_WIN_NDIS_ERROR_CODE                     0x023
#define CX_FACILITY_WIN_TPM                                 0x029
#define CX_FACILITY_WIN_RTPM                                0x02A
#define CX_FACILITY_WIN_HYPERVISOR                          0x035
#define CX_FACILITY_WIN_IPSEC                               0x036
#define CX_FACILITY_WIN_VIRTUALIZATION                      0x037
#define CX_FACILITY_WIN_VOLMGR                              0x038
#define CX_FACILITY_WIN_BCD_ERROR_CODE                      0x039
#define CX_FACILITY_WIN_WIN32K_NTUSER                       0x03E
#define CX_FACILITY_WIN_WIN32K_NTGDI                        0x03F
#define CX_FACILITY_WIN_RESUME_KEY_FILTER                   0x040
#define CX_FACILITY_WIN_RDBSS                               0x041
#define CX_FACILITY_WIN_BTH_ATT                             0x042
#define CX_FACILITY_WIN_SECUREBOOT                          0x043
#define CX_FACILITY_WIN_AUDIO_KERNEL                        0x044
#define CX_FACILITY_WIN_VSM                                 0x045
#define CX_FACILITY_WIN_VOLSNAP                             0x050
#define CX_FACILITY_WIN_SDBUS                               0x051
#define CX_FACILITY_WIN_SHARED_VHDX                         0x05C
#define CX_FACILITY_WIN_SMB                                 0x05D
#define CX_FACILITY_WIN_INTERIX                             0x099
#define CX_FACILITY_WIN_SPACES                              0x0E7
#define CX_FACILITY_WIN_SECURITY_CORE                       0x0E8
#define CX_FACILITY_WIN_SYSTEM_INTEGRITY                    0x0E9
#define CX_FACILITY_WIN_LICENSING                           0x0EA
#define CX_FACILITY_WIN_MAXIMUM_VALUE                       0x0EB

/// BD statuses (relating to CX_FACILITY_WIN_MAXIMUM_VALUE is not necessary as they set the Customer field anyway)

// Win32 error facility, converted win32 errors to status codes.
#define CX_FACILITY_WIN32_ERRORS                            0xF0

// some randomly-assigned facility value (todo: move it to a proper facility-group if we can afford to relocate the related statuses)
#define CX_QUEUECOMM_FACILITY                               0xB0

// Codex statuses
#define CX_FACILITY_CODEX_NATIVE                            0x100
#define CX_FACILITY_CODEX_SHARED                            0x101
#define CX_FACILITY_CODEX_KM                                0x102
#define CX_FACILITY_CODEX_UM                                0x103
// add here any new CODEX facilities
#define CX_FACILITY_CODEX_MAXIMUM_VALUE                     0x1ff   // 0x100 (256) 'components'

// legacy facilities for existing projects
#define CX_AVC_FACILITY                                     0x8E1
#define CX_NAPOCA_FACILITY                                  0x8E2
#define CX_RAW_NTFS_FACILITY                                0x801
#define CX_RAW_REG_FACILITY                                 0x802
#define CX_IGNIS_FACILITY                                   0x803

// Agilis statuses
#define CX_FACILITY_AGILIS                                  0x200
#define CX_FACILITY_AGILIS_MAXIMUM_VALUE                    0x21f   // 0x20 (32) 'components'

// dacia statuses
#define CX_FACILITY_DACIA                                   0x220
#define CX_FACILITY_DACIA_NAPOCA                            (CX_FACILITY_DACIA + 1)
#define CX_FACILITY_DACIA_WINGUEST                          (CX_FACILITY_DACIA + 2)
#define CX_FACILITY_DACIA_MAXIMUM_VALUE                     0x239   // 0x19 (25) 'components'

// BDDCI statuses
#define CX_FACILITY_BDDCI                                   0x23A
#define CX_FACILITY_BDDCI_MAXIMUM_VALUE                     0x23F   // 0x6 (6) 'components'

// hvi
#define CX_FACILITY_HVI                                     0x240
#define CX_FACILITY_HVI_MAXIMUM_VALUE                       0x25F   // 0x20 (32) 'components'

// quARK statuses
#define CX_FACILITY_QUARK                                   0x260
#define CX_FACILITY_QUARK_MAXIMUM_VALUE                     0x269   // 0xA (10) 'components'


#endif // _CX_STATUS_FACILITIES_H_
