#pragma once

#include <iostream>
#include <thread>

#include "NetworkObject.h"

class Server : NetworkObject
{
public:
    Server(unsigned short port, ULONG listenIP = INADDR_ANY);

    int Start();
    void Close();

    static void Main();

private:
    ULONG m_listenIP;
    SOCKET m_ServerSock;
    std::vector<std::thread> m_ClientThreads;

    int HandleClientInbound(SOCKET clientSock, CertUseType in_CertUseType);
};