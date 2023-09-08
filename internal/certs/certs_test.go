package certs

import "testing"

func TestLoadCertificates(t *testing.T) {
	goodTestCert := "data/testclient.crt"
	goodTestkey := "data/testclientkey.pem"
	goodPassphrase := "security123"
//	missingTestCert := "data/testclient_missing.crt"
	missingTestkey := "data/testclientkey_missing.pem"
//	missingPassphrase := ""

	if certificate, err := LoadCertificate(&goodTestCert, &goodTestkey, nil); certificate == nil || err != nil {
		t.Errorf("Failure: Couldn't load supposedly valid certificate.")
	}
	if certificate, err := LoadCertificate(nil, &goodTestkey, nil); certificate != nil || err == nil {
		t.Errorf("Failure: No error despite missing certificate")
	}
	if certificate, err := LoadCertificate(&goodTestCert, &missingTestkey, nil); certificate != nil || err == nil {
		t.Errorf("Failure: No Failure while loading certificate using missing key.")
	}
	if certificate, err := LoadCertificate(&goodTestCert, &goodTestkey, &goodPassphrase); certificate == nil || err != nil {
		t.Errorf("Failure: Couldn't load supposedly valid certificate with passphrase.")
	}
	if certificate, err := LoadCertificate(&goodTestCert, &missingTestkey, &goodPassphrase); certificate != nil || err == nil {
		t.Errorf("Failure:  No Failure while loading certificate using missing key with passphrase.")
	}
}
