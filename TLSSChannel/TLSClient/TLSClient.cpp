// tls_client.cpp

#define SECURITY_WIN32


#include "TLSClient.h"
#include <Shlwapi.h>
#include <cassert>
#include <algorithm>
#include <string.h>
#include <vector>

const std::string Client::m_NetObjectTypeName = "Client";
Client::Client(std::wstring& hostname, unsigned short port): NetworkObject(port), m_Hostname(hostname) 
{
}

void Client::Main()
{
    std::wstring hostname = L"localhost";
    unsigned short port = 47000;

    int result = 0;
    Client client(hostname, port);
    //result = client.Start(CertUseType::USE_DEFAULT_CERT);
    //result = client.Start(CertUseType::NO_CERT);
    result = client.Start(CertUseType::GENERATE_CERT);
    if (result < 0 )
    {
        PrintError("startClient error", result);
        return;
    }

    char data[] = "Hello iam a client";
    PrintMsg(std::string("sending: ") + data);
    size_t dataSize = strlen(data);
    result = client.TLSWrite(data, dataSize);
    if (result < 0)
    {
        PrintError("TLSWrite error", result);
    }

    const size_t readDataSize = 65536;
    std::vector<char> readData(readDataSize, '\0');
    result = client.TLSread(readData.data(), readDataSize);
    if (result < 0)
    {
        PrintError("TLSread error", result);
    }
    else
    {
        PrintMsg(std::string("reading decrypted: ") + readData.data());
    }

    while (true)
    {
        std::string inputLine;
        std::getline(std::cin, inputLine);

        PrintMsg(std::string("Console input: ") + inputLine);
        if (inputLine == "exit")
        {
            PrintMsg("exiting app");
            break;
        }

        size_t dataSize = strlen(inputLine.c_str());
        result = client.TLSWrite(inputLine.data(), dataSize);
        if (result < 0)
        {
            PrintError("TLSWrite error", result);
        }

        const size_t readDataSize = 65536;
        std::vector<char> readData(readDataSize, '\0');
        result = client.TLSread(readData.data(), readDataSize);
        if (result < 0)
        {
            PrintError("TLSread error", result);
        }
        else
        {
            PrintMsg(std::string("reading decrypted: ") + readData.data());
        }
    }
}

int Client::Start(CertUseType in_CertUseType) {
    
    WSADATA wsaData;
    // 1. Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        return -1;
    }

    // create TCP IPv4 socket
    m_TLSSocket.sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_TLSSocket.sock == INVALID_SOCKET)
    {
        WSACleanup();
        return -1;
    }

    WCHAR sport[64];
    swprintf_s(sport, 64, L"%u", m_Port);

    // connect to server
    if (!WSAConnectByName(m_TLSSocket.sock, (WCHAR*)m_Hostname.c_str(), sport, NULL, NULL, NULL, NULL, NULL, NULL))
    {
        closesocket(m_TLSSocket.sock);
        WSACleanup();
        return -1;
    }

    // 2. Acquire client certificate (must exist in cert store)
    //PCCERT_CONTEXT pCert = FindCertByThumbprint(L"D4192B0864AE03AFE047117A9F2BA12ED756F99C");

    SCHANNEL_CRED cred = {};
    PCCERT_CONTEXT pCert = nullptr;
    std::vector<BYTE> out;
    std::string stringThumbprintHex;

    switch (in_CertUseType)
    {
    case CertUseType::USE_DEFAULT_CERT:
    {
        stringThumbprintHex = "B51CA9086B64BC9F71D8B537BF41194B2FAA41B2"; // default cert thumbprint
        size_t len = stringThumbprintHex.length();
        size_t i = 0;
        while (i + 1 < len) {
            while (i < len && (stringThumbprintHex[i] == ' ' || stringThumbprintHex[i] == ':' || stringThumbprintHex[i] == '-')) ++i;
            if (i + 1 >= len) break;
            BYTE b = (BYTE)strtoul(stringThumbprintHex.substr(i, 2).c_str(), nullptr, 16);
            out.push_back(b);
            i += 2;
        }

        pCert = FindCertByThumbprint(out.data(), out.size());
        cred.cCreds = 1;
        cred.paCred = &pCert;
        cred.dwFlags = SCH_CRED_AUTO_CRED_VALIDATION          // automatically validate server certificate
            ;
        break;
    }

    case CertUseType::GENERATE_CERT:
    {
        pCert = GenerateCert();
        //pCert = FindCertByThumbprint(L"B51CA9086B64BC9F71D8B537BF41194B2FAA41B2");
        cred.cCreds = 1;
        cred.paCred = &pCert;
        cred.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION     // manualy validate server certificate
            ;
        break;
    }

    case CertUseType::NO_CERT:
    {
        cred.dwFlags = SCH_CRED_AUTO_CRED_VALIDATION     // automatically validate server certificate
            ;
        break;
    }

    default:
        break;
    }

    cred.dwFlags |= SCH_USE_STRONG_CRYPTO;          // use only strong crypto alogorithms
    cred.dwVersion = SCHANNEL_CRED_VERSION;
    cred.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;

    SECURITY_STATUS status = AcquireCredentialsHandle(NULL, (WCHAR*)UNISP_NAME, SECPKG_CRED_OUTBOUND,NULL, &cred, NULL, NULL, &m_TLSSocket.handle, NULL); //last param time PTimeStamp
    //SECURITY_STATUS status = AcquireCredentialsHandle(NULL, (WCHAR*)UNISP_NAME, SECPKG_CRED_INBOUND,NULL, &cred, NULL, NULL, &m_TLSSocket.handle, NULL); //last param time PTimeStamp
    if (status != SEC_E_OK) {
        closesocket(m_TLSSocket.sock);
        WSACleanup();
        PrintError("AcquireCredentialsHandle failed", status);
        return 1;
    }
    PrintError("AcquireCredentialsHandle success", status);


    // perform tls handshake
    // 1) call InitializeSecurityContext to create/update schannel context
    // 2) when it returns SEC_E_OK - tls handshake completed
    // 3) when it returns SEC_I_INCOMPLETE_CREDENTIALS - server requests client certificate (not supported here)
    // 4) when it returns SEC_I_CONTINUE_NEEDED - send token to server and read data
    // 5) when it returns SEC_E_INCOMPLETE_MESSAGE - need to read more data from server
    // 6) otherwise read data from server and go to step 1

    m_TLSSocket.received = 0;
    m_TLSSocket.used = 0;
    m_TLSSocket.available = 0;
    m_TLSSocket.decrypted = 0;
    //m_TLSSocket.handle = nullptr;

    CtxtHandle* context = NULL;
    int result = 0;

    while (true)
    {
        SecBuffer inbuffers[2] = { 0 };
        inbuffers[0].BufferType = SECBUFFER_TOKEN;
        inbuffers[0].pvBuffer = m_TLSSocket.incoming;
        inbuffers[0].cbBuffer = m_TLSSocket.received;
        inbuffers[1].BufferType = SECBUFFER_EMPTY;

        SecBuffer outbuffers[1] = { 0 };
        outbuffers[0].BufferType = SECBUFFER_TOKEN;

        SecBufferDesc indesc = { SECBUFFER_VERSION, ARRAYSIZE(inbuffers), inbuffers };
        SecBufferDesc outdesc = { SECBUFFER_VERSION, ARRAYSIZE(outbuffers), outbuffers };

        DWORD flags = ISC_REQ_USE_SUPPLIED_CREDS | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM;
        if (in_CertUseType == CertUseType::GENERATE_CERT)
        {
            //flags |= ISC_REQ_MUTUAL_AUTH;
        }

        SECURITY_STATUS sec_status = InitializeSecurityContext(
            &m_TLSSocket.handle,
            context,
            (SEC_WCHAR*)m_Hostname.c_str(),
            flags,
            0,
            0,
            context ? &indesc : NULL,
            0,
            context ? NULL : &m_TLSSocket.context,
            &outdesc,
            &flags,
            NULL);

        // after first call to InitializeSecurityContext context is available and should be reused for next calls
        context = &m_TLSSocket.context;

        if (inbuffers[1].BufferType == SECBUFFER_EXTRA)
        {
            MoveMemory(m_TLSSocket.incoming, inbuffers[1].pvBuffer, inbuffers[1].cbBuffer);
            m_TLSSocket.received = inbuffers[1].cbBuffer;
        }
        else
        {
            m_TLSSocket.received = 0;
        }

        if (sec_status == SEC_E_OK)
        {
            // tls handshake completed
            PrintMsg("TLS handshake complete!");

            // Send server token to client if needed
            if (outbuffers[0].cbBuffer && outbuffers[0].pvBuffer) {
                send(m_TLSSocket.sock, (char*)outbuffers[0].pvBuffer, outbuffers[0].cbBuffer, 0);
                FreeContextBuffer(outbuffers[0].pvBuffer);
            }

            //if (in_CertUseType == CertUseType::GENERATE_CERT)
            if (cred.dwFlags & SCH_CRED_MANUAL_CRED_VALIDATION)
            {
                //validate certs manualy
                PCCERT_CONTEXT pServerCert = NULL;
                SECURITY_STATUS queryStatus = QueryContextAttributes(context, SECPKG_ATTR_REMOTE_CERT_CONTEXT, (PVOID)&pServerCert);
                if (queryStatus == SEC_E_OK) {
                    /*std::cout << "Issuer.pbData" << pServerCert->pCertInfo->Issuer.pbData;
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
        else if (sec_status == SEC_I_INCOMPLETE_CREDENTIALS)
        {
            // server asked for client certificate, not supported here
            PrintError("Error!", sec_status);
            result = -1;
            break;
        }
        else if (sec_status == SEC_I_CONTINUE_NEEDED)
        {
            // need to send data to server
            char* buffer = (char*)outbuffers[0].pvBuffer;
            int size = outbuffers[0].cbBuffer;

            while (size != 0)
            {
                int d = send(m_TLSSocket.sock, buffer, size, 0);
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
        else if (sec_status != SEC_E_INCOMPLETE_MESSAGE)
        {
            // SEC_E_CERT_EXPIRED - certificate expired or revoked
            // SEC_E_WRONG_PRINCIPAL - bad hostname
            // SEC_E_UNTRUSTED_ROOT - cannot vertify CA chain
            // SEC_E_ILLEGAL_MESSAGE / SEC_E_ALGORITHM_MISMATCH - cannot negotiate crypto algorithms
            PrintError("Error!", sec_status);
            result = -1;
            break;
        }

        // read more data from server when possible
        if (m_TLSSocket.received == sizeof(m_TLSSocket.incoming))
        {
            // server is sending too much data instead of proper handshake?
            result = -1;
            break;
        }

        int r = recv(m_TLSSocket.sock, m_TLSSocket.incoming + m_TLSSocket.received, sizeof(m_TLSSocket.incoming) - m_TLSSocket.received, 0);
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
        m_TLSSocket.received += r;
    }

    if (result != 0)
    {
        DeleteSecurityContext(context);
        FreeCredentialsHandle(&m_TLSSocket.handle);
        closesocket(m_TLSSocket.sock);
        WSACleanup();
        return result;
    }

    QueryContextAttributes(context, SECPKG_ATTR_STREAM_SIZES, &m_TLSSocket.sizes);
    return 0;
}

// disconnects socket & releases resources (call this even if tls_write/tls_read function return error)
void Client::Close()
{
    DWORD type = SCHANNEL_SHUTDOWN;

    SecBuffer inbuffers[1];
    inbuffers[0].BufferType = SECBUFFER_TOKEN;
    inbuffers[0].pvBuffer = &type;
    inbuffers[0].cbBuffer = sizeof(type);

    SecBufferDesc indesc = { SECBUFFER_VERSION, ARRAYSIZE(inbuffers), inbuffers };
    ApplyControlToken(&m_TLSSocket.context, &indesc);

    SecBuffer outbuffers[1];
    outbuffers[0].BufferType = SECBUFFER_TOKEN;

    SecBufferDesc outdesc = { SECBUFFER_VERSION, ARRAYSIZE(outbuffers), outbuffers };
    DWORD flags = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM;
    SECURITY_STATUS status = InitializeSecurityContextA(&m_TLSSocket.handle, &m_TLSSocket.context, NULL, flags, 0, 0, &outdesc, 0, NULL, &outdesc, &flags, NULL);
    if (status == SEC_E_OK || status == SEC_I_CONTEXT_EXPIRED)
    {
        char* buffer = (char*)outbuffers[0].pvBuffer;
        int size = outbuffers[0].cbBuffer;
        while (size != 0)
        {
            int d = send(m_TLSSocket.sock, buffer, size, 0);
            if (d <= 0)
            {
                // ignore any failures socket will be closed anyway
                break;
            }
            buffer += d;
            size -= d;
        }
        FreeContextBuffer(outbuffers[0].pvBuffer);
    }
    shutdown(m_TLSSocket.sock, SD_BOTH);

    DeleteSecurityContext(&m_TLSSocket.context);
    FreeCredentialsHandle(&m_TLSSocket.handle);
    closesocket(m_TLSSocket.sock);
    WSACleanup();
}