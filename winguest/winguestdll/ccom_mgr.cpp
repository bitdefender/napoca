/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file ccom_mgr.cpp
*   @brief COM APIs interaction
*/

#include <atlbase.h>
#include "ccom_mgr.h"

/**
 * @brief Constructor
 */
CComInitMgr::CComInitMgr()
{
    m_ComInitialized = SUCCEEDED(CoInitializeEx(NULL, COINIT_MULTITHREADED));

    if (m_ComInitialized)
    {
        CoInitializeSecurity(
            NULL,
            -1,                          // COM authentication
            NULL,                        // Authentication services
            NULL,                        // Reserved
            RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication
            RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation
            NULL,                        // Authentication info
            EOAC_NONE,                   // Additional capabilities
            NULL                         // Reserved
            );
    }
}

/**
 * @brief Destructor
 */
CComInitMgr::~CComInitMgr()
{
    if (m_ComInitialized)
    {
        CoUninitialize();
        m_ComInitialized = false;
    }
}

/**
 * @brief Getter for m_ComInitialized
 *
 * @return m_ComInitialized
 */
bool CComInitMgr::Initialized() const
{
    return m_ComInitialized;
}
