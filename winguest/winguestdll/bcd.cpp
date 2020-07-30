/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/** @file bcd.cpp
*   @brief Interaction with Windows BCD boot variables
*/

#include <string>

#include <ntstatus.h>
#define WIN32_NO_STATUS

#include <comdef.h>
#include <Wbemidl.h>

typedef unsigned __int64        QWORD;
typedef _Return_type_success_(return >= 0) long NTSTATUS;

#include <atlcomcli.h>

#include "wmi.h"
#include "bcd.h"
#include "trace.h"
#include "bcd.tmh"

/**
 * @brief Constructor
 */
BcdStore::BcdStore()
{
    m_wmiBcdStore = NULL;
    m_wmiBcdStoreClass = NULL;

    HRESULT hr = m_wmiBridge.Connect(WMI_ROOT_RESOURCE);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "Connect");
    }
}

/**
 * @brief Open a BCD Store
 *
 * @param[in] StorePath         Path of store. If empty string, will return System BCD Store
 *
 * @return S_OK
 * @return E_FAIL           Other potential internal error
 */
HRESULT
BcdStore::OpenStore(
    std::wstring const& StorePath
    )
{
    HRESULT hr = S_OK;
    CComPtr<IWbemServices> pSvc;

    CComPtr<IWbemClassObject> wmiBcdStore;
    CComPtr<IWbemClassObject> inParam;
    CComPtr<IWbemClassObject> outParam;
    CComVariant objPath;
    CComVariant filePath(StorePath.c_str());
    CComVariant openedStore;

    if (m_wmiBcdStore)
    {
        return ERROR_ALREADY_INITIALIZED;
    }

    pSvc = m_wmiBridge.GetServices();
    if (!pSvc)
    {
        return ERROR_RESOURCE_NOT_AVAILABLE;
    }

    hr = pSvc->GetObject(_bstr_t(L"BcdStore"), WBEM_FLAG_RETURN_WBEM_COMPLETE, NULL, &m_wmiBcdStoreClass, NULL);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "GetObject");
        return hr;
    }

    hr = m_wmiBcdStoreClass->Get(L"__PATH", 0, &objPath, NULL, NULL);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "Get");
        return hr;
    }

    hr = m_wmiBridge.GetMethodParamInstances(m_wmiBcdStoreClass, L"OpenStore", inParam);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "GetMethodParamInstances");
        return hr;
    }

    hr = inParam->Put(L"File", 0, &filePath, CIM_STRING);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "Put");
        return hr;
    }

    hr = pSvc->ExecMethod(V_BSTR(&objPath), L"OpenStore", 0, NULL, inParam, &outParam, NULL);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "ExecMethod");
        return hr;
    }

    hr = outParam->Get(L"Store", 0, &openedStore, NULL, NULL);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "Get");
        return hr;
    }

    if (V_VT(&openedStore) == VT_NULL)
    {
        hr = E_POINTER;
        LogFuncErrorHr(hr, "Get");
        return hr;
    }

    hr = V_UNKNOWN(&openedStore)->QueryInterface(IID_IWbemClassObject, (void**)&wmiBcdStore);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "QueryInterface");
        return hr;
    }

    m_wmiBcdStore = wmiBcdStore;

    return S_OK;
}

/**
 * @brief Close an open BCD Store
 */
VOID
BcdStore::CloseStore(
    )
{
    m_wmiBcdStore = NULL;
}

/**
 * @brief Enumerate objects in store
 *
 * @param[in]  Type         Type of needed objects
 * @param[out] ObjectList   List of Objects that match Type
 *
 * @return S_OK
 * @return E_FAIL           Other potential internal error
 */
HRESULT
BcdStore::EnumerateObjects(
    DWORD Type,
    std::vector<BcdObject*> &ObjectList
    )
{
    HRESULT hr = S_OK;
    CComPtr<IWbemServices> pSvc;

    CComPtr<IWbemClassObject> inParam;
    CComPtr<IWbemClassObject> outParam;
    CComPtr<IWbemClassObject> storeObj;

    SAFEARRAY* objects = NULL;
    LONG upperBound = 0, lowerBound = 0;

    CComVariant relPath;
    CComVariant parameter;
    BcdObject* tmpObj;

    if (!m_wmiBcdStore)
    {
        return E_FAIL; // not initialized
    }

    pSvc = m_wmiBridge.GetServices();
    if (!pSvc)
    {
        return ERROR_RESOURCE_NOT_AVAILABLE;
    }

    ObjectList.clear();

    hr = m_wmiBcdStore->Get(L"__RELPATH", 0, &relPath, NULL, NULL);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "Get");
        goto cleanup;
    }

    hr = m_wmiBridge.GetMethodParamInstances(m_wmiBcdStoreClass, L"EnumerateObjects", inParam);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "GetMethodParamInstances");
        goto cleanup;
    }

    parameter = (INT32)Type;

    hr = inParam->Put(L"Type", 0, &parameter, CIM_UINT32);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "Put");
        goto cleanup;
    }

    hr = pSvc->ExecMethod(V_BSTR(&relPath), L"EnumerateObjects", 0, NULL, inParam, &outParam, NULL);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "ExecMethod");
        goto cleanup;
    }

    parameter.Clear();

    hr = outParam->Get(L"Objects", 0, &parameter, NULL, 0);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "Get");
        goto cleanup;
    }

    objects = V_ARRAY(&parameter);
    parameter.vt = VT_EMPTY;

    if (SafeArrayGetDim(objects) != 1)
    {
        hr = E_UNEXPECTED;
        LogFuncErrorHr(hr, "SafeArrayGetDim");
        goto cleanup;
    }

    hr = SafeArrayGetLBound(objects, 1, &lowerBound);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "SafeArrayGetLBound");
        goto cleanup;
    }

    hr = SafeArrayGetUBound(objects, 1, &upperBound);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "SafeArrayGetUBound");
        goto cleanup;
    }

    for (LONG index = lowerBound; index <= upperBound; index++)
    {
        hr = SafeArrayGetElement(objects, &index, &storeObj);
        if (FAILED(hr))
        {
            LogFuncErrorHr(hr, "SafeArrayGetElement");
            goto cleanup;
        }

        tmpObj = new BcdObject(&m_wmiBridge);

        hr = tmpObj->Init(storeObj);
        if (FAILED(hr))
        {
            LogFuncErrorHr(hr, "Init");
            goto cleanup;
        }

        storeObj.Release();

        ObjectList.push_back(tmpObj);
        tmpObj = NULL;
    }

cleanup:
    if (FAILED(hr))
    {
        this->DisposeOfObject(tmpObj);

        for (DWORD index = 0; index < ObjectList.size(); index++)
        {
            this->DisposeOfObject(ObjectList[index]);
        }

        ObjectList.clear();
    }

    SafeArrayDestroy(objects);

    return hr;
}

/**
 * @brief Open a BCD Object
 *
 * @param[in]  Guid         Guid of Object
 * @param[out] Object       Opened Object
 *
 * @return S_OK
 * @return E_FAIL           Other potential internal error
 */
HRESULT
BcdStore::OpenObject(
    std::wstring const& Guid,
    BcdObject* &Object
    )
{
    HRESULT hr = S_OK;
    CComPtr<IWbemServices> pSvc;

    CComPtr<IWbemClassObject> openedObject;
    CComPtr<IWbemClassObject> inParam;
    CComPtr<IWbemClassObject> outParam;

    CComVariant relPath;
    CComVariant parameter;

    Object = new BcdObject(&m_wmiBridge);

    if (!m_wmiBcdStore)
    {
        return E_FAIL; // not initialized
    }

    pSvc = m_wmiBridge.GetServices();
    if (!pSvc)
    {
        return ERROR_RESOURCE_NOT_AVAILABLE;
    }

    hr = m_wmiBcdStore->Get(L"__RELPATH", 0, &relPath, NULL, NULL);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "Get");
        goto cleanup;
    }

    hr = m_wmiBridge.GetMethodParamInstances(m_wmiBcdStoreClass, L"OpenObject", inParam);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "GetMethodParamInstances");
        goto cleanup;
    }

    parameter = Guid.c_str();

    hr = inParam->Put(L"Id", 0, &parameter, CIM_STRING);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "Put");
        goto cleanup;
    }

    hr = pSvc->ExecMethod(V_BSTR(&relPath), L"OpenObject", 0, NULL, inParam, &outParam, NULL);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "ExecMethod");
        goto cleanup;
    }

    parameter.Clear();

    hr = outParam->Get(L"Object", 0, &parameter, NULL, 0);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "Get");
        goto cleanup;
    }

    if (V_VT(&parameter) == VT_NULL)
    {
        hr = E_POINTER;
        LogFuncErrorHr(hr, "Get");
        goto cleanup;
    }

    hr = V_UNKNOWN(&parameter)->QueryInterface(IID_IWbemClassObject, (void**)&openedObject);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "QueryInterface");
        goto cleanup;
    }

    hr = Object->Init(openedObject);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "Init");
        goto cleanup;
    }

cleanup:
    if (FAILED(hr))
    {
        DisposeOfObject(Object);
    }

    return hr;
}

/**
 * @brief Delete an Object opened with #BcdStore::OpenObject
 *
 * @param[in,out] Object    Opened Object
 *
 * @return S_OK
 * @return E_FAIL           Other potential internal error
 */
void
BcdStore::DisposeOfObject(
    BcdObject* &Object
    )
{
    if (NULL == Object)
    {
        return;
    }

    Object->m_wmiBcdObject.Release();
    Object->m_wmiBcdObjectClass.Release();
    delete Object;
    Object = NULL;
}

/**
 * @brief Copy a BCD Object
 *
 * @param[in]  SourceGuid   Guid of Object
 * @param[out] NewGuid      Guid of copied Object
 *
 * @return S_OK
 * @return E_FAIL           Other potential internal error
 */
HRESULT
BcdStore::CopyObject(
    std::wstring const& SourceGuid,
    std::wstring &NewGuid
    )
{
    HRESULT hr = S_OK;
    CComPtr<IWbemServices> pSvc;

    CComPtr<IWbemClassObject> inParam;
    CComPtr<IWbemClassObject> outParam;
    CComPtr<IWbemClassObject> guidElem;

    CComVariant relPath;
    CComVariant parameter;
    CComVariant output;

    if (!m_wmiBcdStore)
    {
        return E_FAIL; // not initialized
    }

    pSvc = m_wmiBridge.GetServices();
    if (!pSvc)
    {
        return ERROR_RESOURCE_NOT_AVAILABLE;
    }

    hr = m_wmiBcdStore->Get(L"__RELPATH", 0, &relPath, NULL, NULL);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "Get");
        return hr;
    }

    hr = m_wmiBridge.GetMethodParamInstances(m_wmiBcdStoreClass, L"CopyObject", inParam);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "GetMethodParamInstances");
        return hr;
    }

    parameter = L"";

    hr = inParam->Put(L"SourceStoreFile", 0, &parameter, CIM_STRING);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "Put");
        return hr;
    }

    parameter = SourceGuid.c_str();

    hr = inParam->Put(L"SourceId", 0, &parameter, CIM_STRING);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "Put");
        return hr;
    }

    parameter = 0x1; // CreateNewId

    hr = inParam->Put(L"Flags", 0, &parameter, CIM_UINT32);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "Put");
        return hr;
    }

    hr = pSvc->ExecMethod(V_BSTR(&relPath), L"CopyObject", 0, NULL, inParam, &outParam, NULL);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "ExecMethod");
        return hr;
    }

    parameter.Clear();

    hr = outParam->Get(L"Object", 0, &parameter, NULL, 0);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "Get");
        return hr;
    }

    if (V_VT(&parameter) == VT_NULL)
    {
        hr = E_POINTER;
        LogFuncErrorHr(hr, "Get");
        return hr;
    }

    hr = V_UNKNOWN(&parameter)->QueryInterface(IID_IWbemClassObject, (void**)&guidElem);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "QueryInterface");
        return hr;
    }

    hr = guidElem->Get(L"Id", 0, &output, NULL, NULL);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "Get");
        return hr;
    }

    NewGuid = V_BSTR(&output);

    return hr;
}

/**
 * @brief Delete a BCD Object
 *
 * @param[in]  Guid         Guid of Object
 *
 * @return S_OK
 * @return E_FAIL           Other potential internal error
 */
HRESULT
BcdStore::DeleteObject(
    std::wstring const& Guid
    )
{
    HRESULT hr = S_OK;
    CComPtr<IWbemServices> pSvc;

    CComPtr<IWbemClassObject> inParam;
    CComPtr<IWbemClassObject> outParam;

    CComVariant relPath;
    CComVariant guid(Guid.c_str());

    if (!m_wmiBcdStore)
    {
        return E_FAIL; // not initialized
    }

    pSvc = m_wmiBridge.GetServices();
    if (!pSvc)
    {
        return ERROR_RESOURCE_NOT_AVAILABLE;
    }

    hr = m_wmiBcdStore->Get(L"__RELPATH", 0, &relPath, NULL, NULL);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "Get");
        return hr;
    }

    hr = m_wmiBridge.GetMethodParamInstances(m_wmiBcdStoreClass, L"DeleteObject", inParam);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "GetMethodParamInstances");
        return hr;
    }

    hr = inParam->Put(L"Id", 0, &guid, CIM_STRING);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "Put");
        return hr;
    }

    hr = pSvc->ExecMethod(V_BSTR(&relPath), L"DeleteObject", 0, NULL, inParam, &outParam, NULL);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "ExecMethod");
        return hr;
    }

    return hr;
}

/**
 * @brief Constructor
 */
BcdObject::BcdObject(
    WmiBridge* WmiManager
    )
{
    m_wmiBridge = WmiManager;
    m_wmiBcdObject = NULL;
    m_wmiBcdObjectClass = NULL;
}

/**
 * @brief Initialize a BCD Object
 *
 * @param[in]  ObjectInstance       WMI instance of Object
 *
 * @return S_OK
 * @return E_FAIL           Other potential internal error
 */
HRESULT
BcdObject::Init(
    IWbemClassObject* ObjectInstance
    )
{
    HRESULT hr = S_OK;
    CComPtr<IWbemServices> pSvc;

    if (m_wmiBcdObjectClass)
    {
        return ERROR_ALREADY_INITIALIZED;
    }

    pSvc = m_wmiBridge->GetServices();
    if (!pSvc)
    {
        return ERROR_RESOURCE_NOT_AVAILABLE;
    }

    hr = pSvc->GetObject(_bstr_t(L"BcdObject"), WBEM_FLAG_RETURN_WBEM_COMPLETE, NULL, &m_wmiBcdObjectClass, NULL);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "GetObject");
        return hr;
    }

    m_wmiBcdObject = ObjectInstance;

    return hr;
}

/**
 * @brief Get an Object's Integer element
 *
 * @param[in]  Element      Element identifier
 * @param[out] Data         Element Value
 *
 * @return S_OK
 * @return E_FAIL           Other potential internal error
 */
HRESULT
BcdObject::GetIntegerElement(
    DWORD Element,
    std::wstring &Data
    )
{
    HRESULT hr = S_OK;
    CComVariant value;

    hr = GetElementInternal(L"Integer", Element, value);
    if (SUCCEEDED(hr))
    {
        Data = V_BSTR(&value);
    }

    return hr;
}

/**
 * @brief Get an Object's Boolean element
 *
 * @param[in]  Element      Element identifier
 * @param[out] Data         Element Value
 *
 * @return S_OK
 * @return E_FAIL           Other potential internal error
 */
HRESULT
BcdObject::GetBooleanElement(
    DWORD Element,
    BOOLEAN &Data
    )
{
    HRESULT hr = S_OK;
    CComVariant value;

    hr = GetElementInternal(L"Boolean", Element, value);
    if (SUCCEEDED(hr))
    {
        Data = V_BOOL(&value) != FALSE;
    }

    return hr;
}

/**
 * @brief Get an Object's String element
 *
 * @param[in]  Element      Element identifier
 * @param[out] Data         Element Value
 *
 * @return S_OK
 * @return E_FAIL           Other potential internal error
 */
HRESULT
BcdObject::GetStringElement(
    DWORD Element,
    std::wstring &Data
    )
{
    HRESULT hr = S_OK;
    CComVariant value;

    hr = GetElementInternal(L"String", Element, value);
    if (SUCCEEDED(hr))
    {
        Data = V_BSTR(&value);
    }

    return hr;
}

/**
 * @brief Get an Object's List element
 *
 * @param[in]  Element      Element identifier
 * @param[out] Data         Element Value
 *
 * @return S_OK
 * @return E_FAIL           Other potential internal error
 */
HRESULT
BcdObject::GetObjectListElement(
    DWORD Element,
    SAFEARRAY* &Data                    // Must be freed by caller!
    )
{
    HRESULT hr = S_OK;
    VARIANT output;

    VariantInit(&output);

    hr = GetElementInternal(L"Ids", Element, output);
    if (SUCCEEDED(hr))
    {
        Data = V_ARRAY(&output);        // array gets returned, must not be freed here
    }

    return hr;
}

/**
 * @brief Get an Object's generic element
 *
 * @param[in]  ParamName    Type of element
 * @param[in]  Element      Element identifier
 * @param[out] Data         Element Value
 *
 * @return S_OK
 * @return E_FAIL           Other potential internal error
 */
HRESULT
BcdObject::GetElementInternal(
    std::wstring const& ParamName,
    DWORD Element,
    VARIANT &Data
    )
{
    HRESULT hr = S_OK;
    CComPtr<IWbemServices> pSvc;

    CComPtr<IWbemClassObject> inParam;
    CComPtr<IWbemClassObject> outParam;
    CComPtr<IWbemClassObject> bcdElement;

    CComVariant relPath;
    CComVariant parameter;

    if (!m_wmiBcdObject)
    {
        return E_FAIL; // not initialized
    }

    pSvc = m_wmiBridge->GetServices();
    if (!pSvc)
    {
        return ERROR_RESOURCE_NOT_AVAILABLE;
    }

    hr = m_wmiBcdObject->Get(L"__RELPATH", 0, &relPath, NULL, NULL);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "Get");
        return hr;
    }

    hr = m_wmiBridge->GetMethodParamInstances(m_wmiBcdObjectClass, L"GetElement", inParam);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "GetMethodParamInstances");
        return hr;
    }

    parameter = (INT32)Element;

    hr = inParam->Put(L"Type", 0, &parameter, CIM_UINT32);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "Put");
        return hr;
    }

    hr = pSvc->ExecMethod(V_BSTR(&relPath), L"GetElement", 0, NULL, inParam, &outParam, NULL);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "ExecMethod");
        return hr;
    }

    parameter.Clear();

    hr = outParam->Get(L"Element", 0, &parameter, NULL, 0);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "Get");
        return hr;
    }

    if (V_VT(&parameter) == VT_NULL)
    {
        hr = E_POINTER;
        LogFuncErrorHr(hr, "Get");
        return hr;
    }

    hr = V_UNKNOWN(&parameter)->QueryInterface(IID_IWbemClassObject, (void**)&bcdElement);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "QueryInterface");
        return hr;
    }

    hr = bcdElement->Get(ParamName.c_str(), 0, &Data, NULL, NULL);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "Get");
        return hr;
    }

    return hr;
}

/**
 * @brief Set an Object's Integer element
 *
 * @param[in] Element       Element identifier
 * @param[in] Data          Element Value
 *
 * @return S_OK
 * @return E_FAIL           Other potential internal error
 */
HRESULT
BcdObject::SetIntegerElement(
    DWORD Element,
    QWORD Data
    )
{
    CComVariant value((INT32)Data);

    return SetElementInternal(L"SetIntegerElement", L"Integer", Element, value, CIM_UINT64);
}

/**
 * @brief Set an Object's Boolean element
 *
 * @param[in] Element       Element identifier
 * @param[in] Data          Element Value
 *
 * @return S_OK
 * @return E_FAIL           Other potential internal error
 */
HRESULT
BcdObject::SetBooleanElement(
    DWORD Element,
    BOOLEAN Data
    )
{
    CComVariant value(Data);

    return SetElementInternal(L"SetBooleanElement", L"Boolean", Element, value, CIM_BOOLEAN);
}

/**
 * @brief Set an Object's String element
 *
 * @param[in] Element       Element identifier
 * @param[in] Data          Element Value
 *
 * @return S_OK
 * @return E_FAIL           Other potential internal error
 */
HRESULT
BcdObject::SetStringElement(
    DWORD Element,
    std::wstring const& Data
    )
{
    CComVariant value(Data.c_str());

    return SetElementInternal(L"SetStringElement", L"String", Element, value, CIM_STRING);
}

/**
 * @brief Set an Object's List element
 *
 * @param[in] Element       Element identifier
 * @param[in] Data          Element Value
 *
 * @return S_OK
 * @return E_FAIL           Other potential internal error
 */
HRESULT
BcdObject::SetObjectListElement(
    DWORD Element,
    SAFEARRAY* Data
    )
{
    VARIANT value;
    VariantInit(&value);

    V_VT(&value) = VT_ARRAY;    // array was provided from caller, must not be cleared here
    V_ARRAY(&value) = Data;

    return SetElementInternal(L"SetObjectListElement", L"Ids", Element, value, CIM_STRING);
}

/**
 * @brief Set an Object's generic element
 *
 * @param[in] ActualFunc    Function to be used for setting
 * @param[in] ParamName     Type of element
 * @param[in] Element       Element identifier
 * @param[in] Data          Element Value
 *
 * @return S_OK
 * @return E_FAIL           Other potential internal error
 */
HRESULT
BcdObject::SetElementInternal(
    std::wstring const& ActualFunc,
    std::wstring const& ParamName,
    DWORD Element,
    const VARIANT &Data,
    CIMTYPE DataType
    )
{
    HRESULT hr = S_OK;
    CComPtr<IWbemServices> pSvc;

    CComPtr<IWbemClassObject> inParam;
    CComPtr<IWbemClassObject> bcdElement;

    CComVariant relPath;
    CComVariant element((INT32)Element);

    if (!m_wmiBcdObject)
    {
        return E_FAIL; // not initialized
    }

    pSvc = m_wmiBridge->GetServices();
    if (!pSvc)
    {
        return ERROR_RESOURCE_NOT_AVAILABLE;
    }

    hr = m_wmiBcdObject->Get(L"__RELPATH", 0, &relPath, NULL, NULL);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "Get");
        return hr;
    }

    hr = m_wmiBridge->GetMethodParamInstances(m_wmiBcdObjectClass, ActualFunc, inParam);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "GetMethodParamInstances");
        return hr;
    }

    hr = inParam->Put(L"Type", 0, &element, CIM_UINT32);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "Put");
        return hr;
    }

    hr = inParam->Put(ParamName.c_str(), 0, const_cast<VARIANT*>(&Data), DataType);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "Put");
        return hr;
    }

    hr = pSvc->ExecMethod(V_BSTR(&relPath), const_cast<WCHAR*>(ActualFunc.c_str()), 0, NULL, inParam, NULL, NULL);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "ExecMethod");
        return hr;
    }

    return hr;
}

/**
 * @brief Delete an Object's element
 *
 * @param[in] Element       Element identifier
 *
 * @return S_OK
 * @return E_FAIL           Other potential internal error
 */
HRESULT
BcdObject::DeleteElement(
    DWORD Element
    )
{
    HRESULT hr = S_OK;
    CComPtr<IWbemServices> pSvc;

    CComPtr<IWbemClassObject> inParam;
    CComVariant element((INT32)Element);
    CComVariant relPath;

    if (!m_wmiBcdObject)
    {
        return E_FAIL; // not initialized
    }

    pSvc = m_wmiBridge->GetServices();
    if (!pSvc)
    {
        return ERROR_RESOURCE_NOT_AVAILABLE;
    }

    hr = m_wmiBcdObject->Get(L"__RELPATH", 0, &relPath, NULL, NULL);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "Get");
        return hr;
    }

    hr = m_wmiBridge->GetMethodParamInstances(m_wmiBcdObjectClass, L"DeleteElement", inParam);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "GetMethodParamInstances");
        return hr;
    }

    hr = inParam->Put(L"Type", 0, &element, CIM_UINT32);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "Put");
        return hr;
    }

    hr = pSvc->ExecMethod(V_BSTR(&relPath), L"DeleteElement", 0, NULL, inParam, NULL, NULL);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "ExecMethod");
        return hr;
    }

    return hr;
}

/**
 * @brief Get an Object's Type
 *
 * @param[out] Type         Object type
 *
 * @return S_OK
 * @return E_FAIL           Other potential internal error
 */
HRESULT
BcdObject::GetType(
    DWORD &Type
    )
{
    HRESULT hr = S_OK;
    CComVariant type;

    if (!m_wmiBcdObject)
    {
        return E_FAIL; // not initialized
    }

    hr = m_wmiBcdObject->Get(L"Type", 0, &type, NULL, NULL);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "Get");
        return hr;
    }

    Type = V_I4(&type);

    return hr;
}

/**
 * @brief Get an Object's GUID
 *
 * @param[out] Guid         Object GUID
 *
 * @return S_OK
 * @return E_FAIL           Other potential internal error
 */
HRESULT
BcdObject::GetGuid(
    std::wstring &Guid
    )
{
    HRESULT hr = S_OK;
    CComVariant guid;

    if (!m_wmiBcdObject)
    {
        return E_FAIL; // not initialized
    }

    hr = m_wmiBcdObject->Get(L"Id", 0, &guid, NULL, NULL);
    if (FAILED(hr))
    {
        LogFuncErrorHr(hr, "Get");
        return hr;
    }

    Guid = V_BSTR(&guid);

    return hr;
}
