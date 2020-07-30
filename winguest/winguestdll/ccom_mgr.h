/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#pragma once

class CComInitMgr
{
public:
    CComInitMgr();
    ~CComInitMgr();
    bool Initialized() const;

private:
    bool m_ComInitialized;
};
