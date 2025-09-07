#include "TLSClient.h"

#include <iostream>

int main2()
{
    std::cout << "Client to be started\n";
    //NetworkObject test;
    //auto cert = test.GenerateCert();
    Client::Main();

    return 0;
}

int main()
{
    //test find cert by thumbprint

    std::vector<BYTE> out;
    std::string stringThumbprintHex;
    PCCERT_CONTEXT pCert = nullptr;
    NetworkObject netObj;
    size_t i = 0;
    size_t len = 0;

    //find user cert
    stringThumbprintHex = "B51CA9086B64BC9F71D8B537BF41194B2FAA41B2"; // default cert thumbprint
    len = stringThumbprintHex.length();
    i = 0;
    while (i + 1 < len) {
        while (i < len && (stringThumbprintHex[i] == ' ' || stringThumbprintHex[i] == ':' || stringThumbprintHex[i] == '-')) ++i;
        if (i + 1 >= len) break;
        BYTE b = (BYTE)strtoul(stringThumbprintHex.substr(i, 2).c_str(), nullptr, 16);
        out.push_back(b);
        i += 2;
    }
    pCert = netObj.FindCertByThumbprint(out.data(), out.size());

    if (pCert) {
        std::cout << "Found cert with thumbprint: " << stringThumbprintHex << std::endl;
        CertFreeCertificateContext(pCert);
    }
    else {
        std::cout << "Cert not found with thumbprint: " << stringThumbprintHex << std::endl;
    }

    //find machine cert
    out.clear();
    stringThumbprintHex = "c2ccc20ba98e22ac9a107b923d3487ea44f08940"; // default cert thumbprint
    len = stringThumbprintHex.length();
    i = 0;
    while (i + 1 < len) {
        while (i < len && (stringThumbprintHex[i] == ' ' || stringThumbprintHex[i] == ':' || stringThumbprintHex[i] == '-')) ++i;
        if (i + 1 >= len) break;
        BYTE b = (BYTE)strtoul(stringThumbprintHex.substr(i, 2).c_str(), nullptr, 16);
        out.push_back(b);
        i += 2;
    }
    pCert = netObj.FindCertByThumbprint(out.data(), out.size());

    if (pCert) {
        std::cout << "Found cert with thumbprint: " << stringThumbprintHex << std::endl;
        CertFreeCertificateContext(pCert);
    }
    else {
        std::cout << "Cert not found with thumbprint: " << stringThumbprintHex << std::endl;
    }


    return 0;
}