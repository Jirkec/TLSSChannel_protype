// TLSServer.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "TLSServer.h"

const std::string Server::m_NetObjectTypeName = "Server";
Server::Server(unsigned short port, ULONG listenIP): NetworkObject(port), m_listenIP(listenIP), m_ServerSock(INVALID_SOCKET), m_ClientThreads()
{
}

int Server::Start()
{

    // 1. Initialize Winsock
    WSADATA wsaData; 
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        return -1;
    }

    m_ServerSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in serverAddr = {};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = m_listenIP;
    serverAddr.sin_port = htons(m_Port);
    bind(m_ServerSock, (sockaddr*)&serverAddr, sizeof(serverAddr));
    listen(m_ServerSock, SOMAXCONN);

    PrintMsg(std::string("Listening on port ") + (char)m_Port);

    while (true) {
        int clientSock = accept(m_ServerSock, NULL, NULL);
        if (clientSock < 0) {
            PrintError("Error accepting client connection", clientSock);
            continue;
        }

        PrintMsg("-------------  New Client -----------");
        // Create a new thread for each client
        //m_ClientThreads.emplace_back(std::thread(&Server::HandleClientInbound, this, clientSock, CertUseType::USE_DEFAULT_CERT));
        m_ClientThreads.emplace_back(std::thread(&Server::HandleClientInbound, this, clientSock, CertUseType::GENERATE_CERT));
    }

    return 0;
}

void Server::Close()
{
}

void Server::Main()
{
    Server server(47000);
    server.Start();
}

int Server::HandleClientInbound(SOCKET clientSock, CertUseType in_CertUseType)
{
    SECURITY_STATUS status;
    int result = 0; 
    PrintMsg("New client accepted");

    NetworkObject client;
    client.m_TLSSocket.sock = clientSock;

    // 2. Acquire server certificate (must exist in cert store)
    PCCERT_CONTEXT pCert = nullptr;
    SCHANNEL_CRED cred = {};
    switch (in_CertUseType)
    {
    case CertUseType::USE_DEFAULT_CERT:
        //pCert = FindCertByThumbprint(L"B51CA9086B64BC9F71D8B537BF41194B2FAA41B2");
        //pCert = FindCertByThumbprint(L"35a3d39508d46af3061b19891c537dd3c5379304");
        pCert = FindCertByThumbprint(L"D4192B0864AE03AFE047117A9F2BA12ED756F99C");
        cred.cCreds = 1;
        cred.paCred = &pCert;
        cred.dwFlags =
             SCH_CRED_AUTO_CRED_VALIDATION     // automatically validate server certificate
            ;
        break;
    case CertUseType::GENERATE_CERT:
        pCert = GenerateCert();
        cred.cCreds = 1;
        cred.paCred = &pCert;
        cred.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION     // manualy validate server certificate
            ;
        break;
    case CertUseType::NO_CERT:
        PrintMsg("Error! Server must use a CERTifiacte!");
        return -1;
        break;
    default:
        break;
    }

    // 3. Acquire Schannel credentials
    cred.dwFlags |= SCH_USE_STRONG_CRYPTO;    // use only strong crypto alogorithms
    cred.dwVersion = SCHANNEL_CRED_VERSION;
    cred.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER;

    TimeStamp ts;
    status = AcquireCredentialsHandle(NULL, (WCHAR*)UNISP_NAME, SECPKG_CRED_INBOUND, NULL, &cred, NULL, NULL, &client.m_TLSSocket.handle, &ts);
    //status = AcquireCredentialsHandle(NULL, (WCHAR*)UNISP_NAME, SECPKG_CRED_OUTBOUND, NULL, &cred, NULL, NULL, &client.m_TLSSocket.handle, &ts);
    if (status != SEC_E_OK) {
        closesocket(client.m_TLSSocket.sock);
        PrintError("AcquireCredentialsHandle failed", status);
        return 1;
    }
    PrintError("AcquireCredentialsHandle success", status);


    // 4. TLS handshake - AcceptSecurityContext
    client.m_TLSSocket.received = 0;
    client.m_TLSSocket.used = 0;
    client.m_TLSSocket.available = 0;
    client.m_TLSSocket.decrypted = 0;

    CtxtHandle* context = NULL;
    while (true)
    {

        int r = recv(client.m_TLSSocket.sock, client.m_TLSSocket.incoming + client.m_TLSSocket.received, sizeof(client.m_TLSSocket.incoming) - client.m_TLSSocket.received, 0);
        if (r == 0)
        {
            // server disconnected socket
            return 0;
        }
        else if (r < 0)
        {
            // socket error
            result = -1;
            break;
        }
        client.m_TLSSocket.received += r;

        SecBuffer inbuffers[2] = { 0 };
        inbuffers[0].BufferType = SECBUFFER_TOKEN;
        inbuffers[0].pvBuffer = client.m_TLSSocket.incoming;
        inbuffers[0].cbBuffer = client.m_TLSSocket.received;
        inbuffers[1].BufferType = SECBUFFER_EMPTY;

        SecBuffer outbuffers[1] = { 0 };
        outbuffers[0].BufferType = SECBUFFER_TOKEN;

        SecBufferDesc indesc = { SECBUFFER_VERSION, ARRAYSIZE(inbuffers), inbuffers };
        SecBufferDesc outdesc = { SECBUFFER_VERSION, ARRAYSIZE(outbuffers), outbuffers };

        DWORD flags = ASC_REQ_STREAM | ASC_REQ_CONFIDENTIALITY | ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_REPLAY_DETECT | ASC_REQ_SEQUENCE_DETECT;
        if (in_CertUseType == CertUseType::GENERATE_CERT)
        {
            flags |= ASC_REQ_MUTUAL_AUTH;
        }

        status = AcceptSecurityContext(
            &client.m_TLSSocket.handle,
            context ? &client.m_TLSSocket.context : NULL,
            &indesc,
            flags,
            SECURITY_NATIVE_DREP,
            //context,
            &client.m_TLSSocket.context,
            &outdesc,
            &flags,
            &ts
        );

        // after first call to AcceptSecurityContext context is available and should be reused for next calls
        context = &client.m_TLSSocket.context;
        //client.m_TLSSocket.context = *context;

        if (inbuffers[1].BufferType == SECBUFFER_EXTRA)
        {
            MoveMemory(client.m_TLSSocket.incoming, inbuffers[1].pvBuffer, inbuffers[1].cbBuffer);
            client.m_TLSSocket.received = inbuffers[1].cbBuffer;
        }
        else
        {
            client.m_TLSSocket.received = 0;
        }

        if (status == SEC_E_OK)
        {
            // tls handshake completed
            PrintMsg("TLS handshake complete!");

            // Send server token to client if needed
            if (outbuffers[0].cbBuffer && outbuffers[0].pvBuffer) {
                send(client.m_TLSSocket.sock, (char*)outbuffers[0].pvBuffer, outbuffers[0].cbBuffer, 0);
                FreeContextBuffer(outbuffers[0].pvBuffer);
            }

            //if (in_CertUseType == CertUseType::GENERATE_CERT)
            if (cred.dwFlags & SCH_CRED_MANUAL_CRED_VALIDATION)
            {
                //validate certs manualy
                PCCERT_CONTEXT pServerCert = NULL;
                SECURITY_STATUS queryStatus = QueryContextAttributes(context, SECPKG_ATTR_REMOTE_CERT_CONTEXT, (PVOID)&pServerCert);
                if (queryStatus == SEC_E_OK) {
                   /* std::cout << "Issuer.pbData" << pServerCert->pCertInfo->Issuer.pbData;
                    std::cout << "IssuerUniqueId.pbData" << pServerCert->pCertInfo->IssuerUniqueId.pbData;
                    std::cout << "NotAfter.dwLowDateTime" << pServerCert->pCertInfo->NotAfter.dwLowDateTime;
                    std::cout << "Subject.pbData" << pServerCert->pCertInfo->Subject.pbData;
                    std::cout << "SerialNumber.pbData" << pServerCert->pCertInfo->SerialNumber.pbData;
                    std::cout << "SubjectUniqueId.pbData" << pServerCert->pCertInfo->SubjectUniqueId.pbData;*/
                    CertFreeCertificateContext(pServerCert);
                }
                else {
                    PrintError("QueryContextAttributes failed", queryStatus);
                    //result = -1;
                }

            }
            break;
        }
        else if (status == SEC_I_INCOMPLETE_CREDENTIALS)
        {
            // server asked for client certificate, not supported here
            PrintMsg("SEC_I_INCOMPLETE_CREDENTIALS - not supported here");
            result = -1;
            break;
        }
        else if (status == SEC_I_CONTINUE_NEEDED)
        {
            // need to send data to server
            char* buffer = (char*)outbuffers[0].pvBuffer;
            int size = outbuffers[0].cbBuffer;

            while (size != 0)
            {
                int d = send(client.m_TLSSocket.sock, buffer, size, 0);
                if (d <= 0)
                {
                    break;
                }
                size -= d;
                buffer += d;
            }
            FreeContextBuffer(outbuffers[0].pvBuffer);
            if (size != 0)
            {
                // failed to fully send data to server
                result = -1;
                break;
            }
        }
        else if (status != SEC_E_INCOMPLETE_MESSAGE)
        {
            // SEC_E_CERT_EXPIRED - certificate expired or revoked
            // SEC_E_WRONG_PRINCIPAL - bad hostname
            // SEC_E_UNTRUSTED_ROOT - cannot vertify CA chain
            // SEC_E_ILLEGAL_MESSAGE / SEC_E_ALGORITHM_MISMATCH - cannot negotiate crypto algorithms
            PrintMsg("Error during handshake");
            result = -1;
            break;
        }
    }
    if (result < 0)
    {
        PrintError("error!", status);
        return result;
    }

    PrintMsg("QueryContextAttributes sizes");
    QueryContextAttributes(context, SECPKG_ATTR_STREAM_SIZES, &client.m_TLSSocket.sizes);



    PrintMsg("Start listening");
    while (true)
    {
        const size_t readDataSize = 65536;
        std::vector<char> readData(readDataSize, '\0');
        result = client.TLSread(readData.data(), readDataSize);
        if (result < 0)
        {
            PrintError("TLSread error", result);
            break;
        }
        else
        {
            PrintMsg(std::string("reading decrypted from client: ") + readData.data());
            PrintMsg(std::string("Sending response to client"));

            std::string data = readData.data();
            data += " - responce";
            PrintMsg(std::string("sending: ") + data);
            size_t dataSize = strlen(data.c_str());
            result = client.TLSWrite(data.data(), dataSize);
            if (result < 0)
            {
                PrintError("TLSWrite error", result);
            }

        }
    }

    return 0;
}