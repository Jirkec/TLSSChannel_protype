#pragma once

#include <iostream>

#include "NetworkObject.h"

class Client : NetworkObject
{
public:
    Client(std::wstring& hostname, unsigned short port);

    int Start(CertUseType in_CertUseType);
    void Close();

    static void Main();

private:
    std::wstring m_Hostname;
};