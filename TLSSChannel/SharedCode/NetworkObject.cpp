#include "NetworkObject.h"
#include <iostream>
#include <cassert>

//const std::string NetworkObject::m_NetObjectTypeName = "Base net object";
NetworkObject::NetworkObject(unsigned short m_Port): m_TLSSocket(), m_Port(m_Port)
{
}

void NetworkObject::PrintMsg(const std::string& msg) {
    std::cerr << "[" << m_NetObjectTypeName << "] " << msg << std::endl;
}
void NetworkObject::PrintError(const char* msg, SECURITY_STATUS status) {
    std::cerr << "["<< m_NetObjectTypeName <<"] " << msg << " Error: 0x" << std::hex << status << std::endl;
}

// Function to convert a std::wstring thumbprint to a BYTE array
std::vector<BYTE> NetworkObject::ConvertThumbprintToByteArray(const std::wstring& thumbprint) {
    std::vector<BYTE> byteArray;
    byteArray.reserve(thumbprint.length() / 2);

    for (size_t i = 0; i < thumbprint.length(); i += 2) {
        BYTE byte = 0;
        byte |= (thumbprint[i] >= 'A' ? (thumbprint[i] - 'A' + 0x0A) : (thumbprint[i] - '0')) << 4;
        byte |= (thumbprint[i + 1] >= 'A' ? (thumbprint[i + 1] - 'A' + 0x0A) : (thumbprint[i + 1] - '0'));
        byteArray.push_back(byte);
    }

    return byteArray;
}

PCCERT_CONTEXT NetworkObject::FindCertByThumbprint(const BYTE* thumbprintByte, DWORD thumbprintSize)
{
    //std::vector<BYTE> thumbprintByte = ConvertThumbprintToByteArray(thumbprintHex);
    PCCERT_CONTEXT pCert = nullptr;
    HCERTSTORE hStore = nullptr;

    //look for the certificate in the current user's personal store
    hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, CERT_SYSTEM_STORE_CURRENT_USER, L"MY");
    if (hStore)
    {
        CRYPT_HASH_BLOB hashBlob;
        hashBlob.cbData = thumbprintSize;
        hashBlob.pbData = (BYTE*)thumbprintByte;

        pCert = CertFindCertificateInStore(
            hStore,
            X509_ASN_ENCODING,
            0,
            CERT_FIND_HASH,
            &hashBlob,
            nullptr);

        CertCloseStore(hStore, 0);
    }

    // look for the certificate in the local machine's personal store
    if (!pCert)
    {
        hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, CERT_SYSTEM_STORE_LOCAL_MACHINE, L"MY");
        if (hStore)
        {
            CRYPT_HASH_BLOB hashBlob;
            hashBlob.cbData = thumbprintSize;
            hashBlob.pbData = (BYTE*)thumbprintByte;

            pCert = CertFindCertificateInStore(
                hStore,
                X509_ASN_ENCODING,
                0,
                CERT_FIND_HASH,
                &hashBlob,
                nullptr);

            CertCloseStore(hStore, 0);
        }
    }
    return pCert;
}

PCCERT_CONTEXT NetworkObject::GenerateCert()
{
    // Generate a new RSA key pair
    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContext(
        &hProv,
        L"TemporarySelfSignedCertContainer",  // No persistent key container
        MS_ENHANCED_PROV,
        //MS_DEF_RSA_SCHANNEL_PROV,
        PROV_RSA_FULL,
        CRYPT_NEWKEYSET | CRYPT_MACHINE_KEYSET))  // Use an ephemeral key
    {
        if (GetLastError() == NTE_EXISTS) {
            if (!CryptAcquireContext(&hProv, L"TemporarySelfSignedCertContainer", MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_MACHINE_KEYSET)) {
                PrintError("CryptAcquireContext failed: ", GetLastError());
                return nullptr;
            }
        }
        else
        {
            PrintError("CryptAcquireContext failed: ", GetLastError());
            return nullptr;
        }
    }

    // Generate the key pair
    HCRYPTKEY hKey = 0;
    if (!CryptGenKey(hProv, AT_SIGNATURE, /*RSA1024BIT_KEY*/ 0x08000000 | CRYPT_EXPORTABLE, &hKey))
    {
        PrintError("CryptGenKey failed: ", GetLastError());
        CryptReleaseContext(hProv, 0);
        return nullptr;
    }

    // Prepare the subject name
    CERT_NAME_BLOB subjectName = {};
    LPCWSTR pszSubject = L"CN=TemporaryTLSNAMEPLCSIM";
    BYTE nameEncoded[256] = { 0 };
    DWORD nameSize = sizeof(nameEncoded);
    if (!CertStrToName(
        X509_ASN_ENCODING,
        pszSubject,
        CERT_X500_NAME_STR,
        NULL,
        nameEncoded,
        &nameSize,
        NULL))
    {
        PrintError("CertStrToName failed: ", GetLastError());
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return nullptr;
    }

    subjectName.pbData = nameEncoded;
    subjectName.cbData = nameSize;

    // Set the certificate expiration time (valid for 5 day)
    SYSTEMTIME startTime, endTime;
    GetSystemTime(&startTime);
    endTime = startTime;
    endTime.wDay += 5;


    //// Set the Key Usage (Digital Signature, Key Encipherment)
    //BYTE keyUsage = CERT_DIGITAL_SIGNATURE_KEY_USAGE | CERT_KEY_ENCIPHERMENT_KEY_USAGE;
    //CERT_EXTENSION keyUsageExt = {};
    //keyUsageExt.pszObjId = (char*)szOID_KEY_USAGE;
    //keyUsageExt.fCritical = TRUE;
    //keyUsageExt.Value.pbData = &keyUsage;
    //keyUsageExt.Value.cbData = sizeof(keyUsage);

    //// Set the Enhanced Key Usage (Server Auth, Client Auth)
    //CERT_ENHKEY_USAGE eku = {};
    //LPCSTR usages[] = { szOID_PKIX_KP_SERVER_AUTH, szOID_PKIX_KP_CLIENT_AUTH };
    //eku.cUsageIdentifier = 2;
    //eku.rgpszUsageIdentifier = (LPSTR*)usages;

    //BYTE ekuBuffer[256];
    //DWORD ekuSize = sizeof(ekuBuffer);
    //if (!CryptEncodeObject(
    //    X509_ASN_ENCODING,
    //    szOID_ENHANCED_KEY_USAGE,
    //    &eku,
    //    ekuBuffer,
    //    &ekuSize))
    //{
    //    std::cerr << "CryptEncodeObject (EKU) failed: " << GetLastError() << std::endl;
    //    CryptReleaseContext(hProv, 0);
    //    return nullptr;
    //}

    //CERT_EXTENSION ekuExt = {};
    //ekuExt.pszObjId = (char*)szOID_ENHANCED_KEY_USAGE;
    //ekuExt.fCritical = FALSE;
    //ekuExt.Value.pbData = ekuBuffer;
    //ekuExt.Value.cbData = ekuSize;

    //// Combine extensions
    //CERT_EXTENSION extensions[] = { keyUsageExt, ekuExt };
    //CERT_EXTENSIONS certExtensions = {};
    //certExtensions.cExtension = 2;
    //certExtensions.rgExtension = extensions;

// Setup provider info
    CRYPT_KEY_PROV_INFO keyProvInfo = {};
    keyProvInfo.pwszContainerName = (WCHAR*)L"TemporarySelfSignedCertContainer";
    keyProvInfo.pwszProvName = NULL;
    keyProvInfo.dwProvType = PROV_RSA_FULL;
    keyProvInfo.dwFlags = 0;
    keyProvInfo.cProvParam = 0;
    keyProvInfo.rgProvParam = NULL;
    keyProvInfo.dwKeySpec = AT_KEYEXCHANGE;

    // Create the self-signed certificate
    PCCERT_CONTEXT pCertContext = CertCreateSelfSignCertificate(
        //hProv,
        NULL,
        &subjectName,
        0,
        //&keyProvInfo,
        NULL,
        NULL,
        //NULL,
        //NULL,
        &startTime,
        &endTime,
        //&certExtensions);
        NULL);

    if (!pCertContext)
    {
        PrintError("CertCreateSelfSignCertificate failed: ", GetLastError());
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return nullptr;
    }

    //// Clean up the key pairw
    //CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);

   PrintMsg("Temporary self-signed certificate created successfully");
    return pCertContext;
}

// blocking read, waits & reads up to size bytes, returns amount of bytes received on success (<= size)
// returns 0 on disconnect or negative value on error
int NetworkObject::TLSread(void* buffer, size_t size)
{
    int result = 0;

    while (size != 0)
    {
        if (m_TLSSocket.decrypted)
        {
            // if there is decrypted data available, then use it as much as possible
            size_t use = std::min(size, m_TLSSocket.available);
            result = memcpy_s(buffer, size, m_TLSSocket.decrypted, use);
            if (result < 0)
            {
                // this should not happen, but just in case check it
                PrintError("TLSWrite memcpy_s error", result);
                return -1;
            }
            //CopyMemory(buffer, m_TLSSocket.decrypted, use);

            buffer = (char*)buffer + use;
            size -= use;
            result += use;

            if (use == m_TLSSocket.available)
            {
                // all decrypted data is used, remove ciphertext from incoming buffer so next time it starts from beginning
                MoveMemory(m_TLSSocket.incoming, m_TLSSocket.incoming + m_TLSSocket.used, m_TLSSocket.received - m_TLSSocket.used);
                m_TLSSocket.received -= m_TLSSocket.used;
                m_TLSSocket.used = 0;
                m_TLSSocket.available = 0;
                m_TLSSocket.decrypted = NULL;
            }
            else
            {
                m_TLSSocket.available -= use;
                m_TLSSocket.decrypted += use;
            }
        }
        else
        {
            // if any ciphertext data available then try to decrypt it
            if (m_TLSSocket.received != 0)
            {
                SecBuffer buffers[4];
                assert(m_TLSSocket.sizes.cBuffers == ARRAYSIZE(buffers));

                buffers[0].BufferType = SECBUFFER_DATA;
                buffers[0].pvBuffer = m_TLSSocket.incoming;
                buffers[0].cbBuffer = m_TLSSocket.received;
                buffers[1].BufferType = SECBUFFER_EMPTY;
                buffers[2].BufferType = SECBUFFER_EMPTY;
                buffers[3].BufferType = SECBUFFER_EMPTY;

                SecBufferDesc desc = { SECBUFFER_VERSION, ARRAYSIZE(buffers), buffers };

                SECURITY_STATUS sec = DecryptMessage(&m_TLSSocket.context, &desc, 0, NULL);
                if (sec == SEC_E_OK)
                {
                    assert(buffers[0].BufferType == SECBUFFER_STREAM_HEADER);
                    assert(buffers[1].BufferType == SECBUFFER_DATA);
                    assert(buffers[2].BufferType == SECBUFFER_STREAM_TRAILER);

                    m_TLSSocket.decrypted = (char*)buffers[1].pvBuffer;
                    m_TLSSocket.available = buffers[1].cbBuffer;
                    m_TLSSocket.used = m_TLSSocket.received - (buffers[3].BufferType == SECBUFFER_EXTRA ? buffers[3].cbBuffer : 0);

                    // data is now decrypted, go back to beginning of loop to copy memory to output buffer
                    continue;
                }
                else if (sec == SEC_I_CONTEXT_EXPIRED)
                {
                    // server closed TLS connection (but socket is still open)
                    m_TLSSocket.received = 0;
                    return result;
                }
                else if (sec == SEC_I_RENEGOTIATE)
                {
                    // server wants to renegotiate TLS connection, not implemented here
                    return -1;
                }
                else if (sec != SEC_E_INCOMPLETE_MESSAGE)
                {
                    // some other schannel or TLS protocol error
                    return -1;
                }
                // otherwise sec == SEC_E_INCOMPLETE_MESSAGE which means need to read more data
            }
            // otherwise not enough data received to decrypt

            if (result != 0)
            {
                // some data is already copied to output buffer, so return that before blocking with recv
                break;
            }

            if (m_TLSSocket.received == sizeof(m_TLSSocket.incoming))
            {
                // server is sending too much garbage data instead of proper TLS packet
                return -1;
            }

            // wait for more ciphertext data from server
            int r = recv(m_TLSSocket.sock, m_TLSSocket.incoming + m_TLSSocket.received, sizeof(m_TLSSocket.incoming) - m_TLSSocket.received, 0);
            if (r == 0)
            {
                // server disconnected socket
                return 0;
            }
            else if (r < 0)
            {
                // error receiving data from socket
                result = -1;
                break;
            }
            //PrintError("recv got ", r);
            m_TLSSocket.received += r;
        }
    }

    return result;
}

// returns 0 on success or negative value on error
int NetworkObject::TLSWrite(const void* buffer, size_t size)
{
    int result = 0;
    while (size != 0)
    {
        size_t use = std::min(size, static_cast<size_t>(m_TLSSocket.sizes.cbMaximumMessage));

        char wbuffer[TLS_MAX_PACKET_SIZE];
        //if (m_TLSSocket.sizes.cbHeader + m_TLSSocket.sizes.cbMaximumMessage + m_TLSSocket.sizes.cbTrailer <= sizeof(wbuffer))
        if (m_TLSSocket.sizes.cbHeader + use + m_TLSSocket.sizes.cbTrailer > sizeof(wbuffer))
        {
            PrintError("TLSWrite buffer too small", -1);
            return -1;
        }

        SecBuffer buffers[3];
        buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
        buffers[0].pvBuffer = wbuffer;
        buffers[0].cbBuffer = m_TLSSocket.sizes.cbHeader;
        buffers[1].BufferType = SECBUFFER_DATA;
        buffers[1].pvBuffer = wbuffer + m_TLSSocket.sizes.cbHeader;
        buffers[1].cbBuffer = use;
        buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
        buffers[2].pvBuffer = wbuffer + m_TLSSocket.sizes.cbHeader + use;
        buffers[2].cbBuffer = m_TLSSocket.sizes.cbTrailer;

        //CopyMemory(buffers[1].pvBuffer, buffer, use);
        result = memcpy_s(buffers[1].pvBuffer, buffers[1].cbBuffer, buffer, use);
        if (result < 0)
        {
            // this should not happen, but just in case check it
            PrintError("TLSWrite memcpy_s error", result);
            return -1;
        }

        SecBufferDesc desc = { SECBUFFER_VERSION, ARRAYSIZE(buffers), buffers };
        SECURITY_STATUS sec = EncryptMessage(&m_TLSSocket.context, 0, &desc, 0);
        if (sec != SEC_E_OK)
        {
            // this should not happen, but just in case check it
            PrintError("TLSWrite encryption error", sec);
            return -1;
        }

        int total = buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer;
        int sent = 0;
        while (sent != total)
        {
            int d = send(m_TLSSocket.sock, wbuffer + sent, total - sent, 0);
            if (d <= 0)
            {
                // error sending data to socket, or server disconnected
                PrintError("TLSWrite error sending data to socket, or server disconnected", -1);
                return -1;
            }
            sent += d;
        }

        buffer = (char*)buffer + use;
        size -= use;
    }

    return result;
}
