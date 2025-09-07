#pragma once

#define SECURITY_WIN32

#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")

#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <schannel.h>
#include <security.h>
#include <vector>
#include <string>

#define TLS_MAX_PACKET_SIZE (16384+512) // payload + extra over head for header/mac/padding (probably an overestimate)

typedef struct {
    SOCKET sock;
    CredHandle handle;
    CtxtHandle context;
    SecPkgContext_StreamSizes sizes;
    size_t received;    // byte count in incoming buffer (ciphertext)
    size_t used;        // byte count used from incoming buffer to decrypt current packet
    size_t available;   // byte count available for decrypted bytes
    char* decrypted; // points to incoming buffer where data is decrypted inplace
    char incoming[TLS_MAX_PACKET_SIZE];
} TLSSocket;

enum class CertUseType
{
    USE_DEFAULT_CERT,
    GENERATE_CERT,
    NO_CERT
};

class NetworkObject
{
public:
    NetworkObject(unsigned short m_Port = 0);

    static void PrintMsg(const std::string& msg);
    static void PrintError(const char* msg, SECURITY_STATUS status);

    int TLSread(void* buffer, size_t size);
    int TLSWrite(const void* buffer, size_t size);

    //PCCERT_CONTEXT FindCertByThumbprint(const std::wstring& thumbprint);
    PCCERT_CONTEXT GenerateCert();
    std::vector<BYTE> ConvertThumbprintToByteArray(const std::wstring& thumbprint);

    PCCERT_CONTEXT FindCertByThumbprint(const BYTE* thumbprintByte, DWORD thumbprintSize);

    TLSSocket m_TLSSocket;

protected:
    unsigned short m_Port;
    const static std::string m_NetObjectTypeName;
};