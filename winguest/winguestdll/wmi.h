/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#pragma once

#include "ccom_mgr.h"

#define WMI_ROOT_RESOURCE               L"Root\\WMI"
#define WMI_CIMV2_RESOURCE              L"Root\\CIMV2"
#define WMI_VOLUME_ENCRYPTION_RESOURCE  L"\\\\.\\root\\cimv2\\security\\microsoftvolumeencryption"

class WmiBridge
{
public:
    WmiBridge();

    HRESULT Connect(std::wstring const& Resource);

    IWbemServices* GetServices();

    HRESULT GetMethodParamInstances(IWbemClassObject* Class, std::wstring const& Method, CComPtr<IWbemClassObject> &InInst, CComPtr<IWbemClassObject> &OutInst);
    HRESULT GetMethodParamInstances(IWbemClassObject* Class, std::wstring const& Method, CComPtr<IWbemClassObject> &InInst);

protected:

private:
    CComInitMgr                 m_ComInitMgr;
    CComPtr<IWbemServices>      m_wbemServices;
};
