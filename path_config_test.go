package kubeauth

import (
	"crypto/x509"
	"reflect"
	"testing"
)

func TestParseCert(t *testing.T) {
	cert, err := ParsePublicKeyPEM([]byte(testCert))
	if err != nil {
		t.Fatal(err)
	}

	certBytes, err := x509.MarshalPKIXPublicKey(cert)
	if err != nil {
		t.Fatal(err)
	}

	cert2, err := ParsePublicKeyDER(certBytes)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(cert, cert2) {
		t.Fatal("certs did not match")
	}
}

var testCert string = `
-----BEGIN CERTIFICATE-----
MIIDcjCCAlqgAwIBAgIBAjANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDEwptaW5p
a3ViZUNBMB4XDTE3MDgzMDE5MDgzNloXDTE4MDgzMDE5MDgzNlowLDEXMBUGA1UE
ChMOc3lzdGVtOm1hc3RlcnMxETAPBgNVBAMTCG1pbmlrdWJlMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxD3eM3+WNc4phxAeQxNOmcybKlNJWowuC12u
v+cGJWxxpDx/OoEIxKI5wmgHxEwFCZL545sjfLqyBcgxQR2xSCib+bYzjBtfA6uV
6d/35nurzz21okcMffc5xKMyZhEwt98WAvYWD71Bihz7iGBq5Sw9md6pqnkNoScR
Hhi3Vl94a6D6shwb6nXA2hlwYLcnoKtpe3Ptq6MW6CpfBA8C11q5eeW4xdvrwKt3
Vd1TgFeEnnqwzUWGapU2uwwUfbRkLTDvrp6791uq0Vo7mzz00xYhV1PLCeAdpJEK
3Vr74FT7jHIbPlzi/qjRBVFKf9IRXnhbjrCl7S0Ayev1Fao4TQIDAQABo4G1MIGy
MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIw
DAYDVR0TAQH/BAIwADBzBgNVHREEbDBqgiRrdWJlcm5ldGVzLmRlZmF1bHQuc3Zj
LmNsdXN0ZXIubG9jYWyCFmt1YmVybmV0ZXMuZGVmYXVsdC5zdmOCEmt1YmVybmV0
ZXMuZGVmYXVsdIIKa3ViZXJuZXRlc4cEwKhjZIcECgAAATANBgkqhkiG9w0BAQsF
AAOCAQEAIw8rKuryhhl527wf9q/VrWixzZ1jCLvyc/60z9rWpXxKFxT8AyCsHirM
F4fHXW4Brcoh/Dc2ci36cUbuywIyxHjgVUG45D4jPPWskY1++ZSfJfSXAuA8eFew
c+No3WPkmZB6ZOZ6q5iPY+FOgDZC7ddWmGuZrle51gBL347cU7H1BrTm6Lm6kXRs
fHRZJX2+B8lnsXsS3QF2BTU0ymuCxCCQxub/GhPZVz3nNNtro1z7/szLUVP1c1/8
p7HP3k7caxfp346TZ/HgbV9sJEkHP7Ym7n9E7LSyUTSxXwBRPraH1WQzEgFNPSUV
V0n6FBLiejOTPKapJ2F0tIqAyJHFug==
-----END CERTIFICATE-----`
