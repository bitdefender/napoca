/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file ccom_mgr.cpp
*   @brief WMI APIs interaction
*/

#include <string>

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>

typedef _Return_type_success_(return >= 0) long NTSTATUS;

#include <comdef.h>
#include <Wbemidl.h>
#include <atlcomcli.h>

#include "wmi.h"
#include "trace.h"
#include "wmi.tmh"


/**
 * @brief Constructor
 */
WmiBridge::WmiBridge()
{
    m_wbemServices = NULL;
}

/**
 * @brief Connect to WMI server
 *
 * @param[in] Resource      WMI resource
 *
 * @return S_OK
 * @return E_FAIL           Other potential internal error
 */
HRESULT
WmiBridge::Connect(
    std::wstring const& Resource
    )
{
    HRESULT hr = S_OK;
    CComPtr<IWbemLocator> locator;
    CComPtr<IWbemServices> wbemServices;

    if (m_wbemServices)
    {
        return ERROR_ALREADY_INITIALIZED;
    }

    if (!m_ComInitMgr.Initialized())
    {
        return CO_E_NOTINITIALIZED;
    }

    hr = locator.CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "CoCreateInstance");
        return hr;
    }

    hr = locator->ConnectServer(_bstr_t(Resource.c_str()), RPC_C_AUTHZ_NONE, NULL, NULL, WBEM_FLAG_CONNECT_USE_MAX_WAIT, NULL, NULL, &wbemServices);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "ConnectServer");
        return hr;
    }

    hr = CoSetProxyBlanket(wbemServices,
        RPC_C_AUTHN_DEFAULT,
        RPC_C_AUTHZ_DEFAULT,
        COLE_DEFAULT_PRINCIPAL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE
        );
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "CoSetProxyBlanket");
        return hr;
    }

    m_wbemServices = wbemServices;

    return S_OK;
}

/**
 * @brief Getter for m_wbemServices
 *
 * @return m_wbemServices
 */
IWbemServices*
WmiBridge::GetServices()
{
    return m_wbemServices;
}

HRESULT
WmiBridge::GetMethodParamInstances(
    IWbemClassObject* Class,
    std::wstring const& Method,
    CComPtr<IWbemClassObject> &InInst
    )
{
    HRESULT hr;
    CComPtr<IWbemClassObject> pInSign;

    if (NULL == Class)
    {
        return E_INVALIDARG;
    }

    hr = Class->GetMethod(Method.c_str(), 0, &pInSign, NULL);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "GetMethod");
        return hr;
    }

    hr = pInSign->SpawnInstance(0, &InInst);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "SpawnInstance");
        return hr;
    }

    return S_OK;
}

/**
 * @brief Get Input and Output instances for a WMI Method
 *
 * @param[in]  Class        WMI Class
 * @param[in]  Method       WMI Method
 * @param[out] InInst       Input instance for Method
 * @param[out] OutInst      Output instance for Method
 *
 * @return S_OK
 * @return E_FAIL           Other potential internal error
 */
HRESULT
WmiBridge::GetMethodParamInstances(
    IWbemClassObject* Class,
    std::wstring const& Method,
    CComPtr<IWbemClassObject> &InInst,
    CComPtr<IWbemClassObject> &OutInst
    )
{
    HRESULT hr;
    CComPtr<IWbemClassObject> pInSign;
    CComPtr<IWbemClassObject> pOutSign;

    if (NULL == Class)
    {
        return E_INVALIDARG;
    }

    hr = Class->GetMethod(Method.c_str(), 0, &pInSign, &pOutSign);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "GetMethod");
        return hr;
    }

    hr = pInSign->SpawnInstance(0, &InInst);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "SpawnInstance");
        return hr;
    }

    hr = pOutSign->SpawnInstance(0, &OutInst);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "SpawnInstance");
        return hr;
    }

    return S_OK;
}

