
#---------------------------------------------------------------------------------------
#Internal CA cert - used for signing other certs + must be in the Trust Store
$caCert = New-SelfSignedCertificate `
  -Subject "CN=MyInternalTestCA" `
  -KeyExportPolicy Exportable `
  -KeyUsage CertSign, CRLSign, DigitalSignature `
  -CertStoreLocation "Cert:\CurrentUser\My" `
  -KeyAlgorithm RSA `
  -KeyLength 2048 `
  -NotAfter (Get-Date).AddYears(10) `
  -Type Custom `
  -TextExtension @("2.5.29.19={critical}{text}ca=true")

# Optional: export to a .cer file
Export-Certificate -Cert $caCert -FilePath "D:\Dokumenty\repos\plcsimapitesting\SChannelTLS\MyInternalCA.cer"
# Show thumbprint of the CA cert
$caCert.Thumbprint #36153691A79CBAA20D87DB354D7812195A0C116F

#---------------------------------------------------------------------------------------
# First, create a cert request
$serverCert = New-SelfSignedCertificate `
  -Subject "CN=MyServerTestCN" `
  -KeyExportPolicy Exportable `
  -KeyUsage DigitalSignature, KeyEncipherment `
  -CertStoreLocation "Cert:\CurrentUser\My" `
  -KeyAlgorithm RSA `
  -KeyLength 2048 `
  -Type Custom `
  -DnsName "myserver.local" `
  -Signer $caCert `
  -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1") # Server Auth

# Optional: Export for inspection
Export-Certificate -Cert $serverCert -FilePath "D:\Dokumenty\repos\plcsimapitesting\SChannelTLS\MyServerCert.cer"
# Show thumbprint of the server cert
$serverCert.Thumbprint #D4192B0864AE03AFE047117A9F2BA12ED756F99C

#---------------------------------------------------------------------------------------
#client certificate
$clientCert = New-SelfSignedCertificate `
  -Subject "CN=MyClientTestCN" `
  -KeyExportPolicy Exportable `
  -KeyUsage DigitalSignature, KeyEncipherment `
  -CertStoreLocation "Cert:\CurrentUser\My" `
  -KeyAlgorithm RSA `
  -KeyLength 2048 `
  -Type Custom `
  -DnsName "myclient.local" `
  -Signer $caCert `
  -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2") # Client Authentication

# Optional: Export for inspection
Export-Certificate -Cert $clientCert -FilePath "D:\Dokumenty\repos\plcsimapitesting\SChannelTLS\MyClientCert.cer"
# Show thumbprint of the server cert
$clientCert.Thumbprint #B51CA9086B64BC9F71D8B537BF41194B2FAA41B2