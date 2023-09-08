package certs

import "testing"

func TestLoadCertificates(t *testing.T) {
	TestCert := "data/testclient.crt"
	Testkey := "data/testclientkey.pem"
	Passphrase := "security123"
	missingTestkey := "data/testclientkey_missing.pem"

	if certificate, err := LoadCertificate(&TestCert, &Testkey, nil); certificate == nil || err != nil {
		t.Errorf("Failure: Couldn't load supposedly valid certificate.")
	}
	if certificate, err := LoadCertificate(nil, &Testkey, nil); certificate != nil || err == nil {
		t.Errorf("Failure: No error despite missing certificate")
	}
	if certificate, err := LoadCertificate(&TestCert, &missingTestkey, nil); certificate != nil || err == nil {
		t.Errorf("Failure: No Failure while loading certificate using missing key.")
	}
	if certificate, err := LoadCertificate(&TestCert, &Testkey, &Passphrase); certificate == nil || err != nil {
		t.Errorf("Failure: Couldn't load supposedly valid certificate with passphrase.")
	}
	if certificate, err := LoadCertificate(&TestCert, &missingTestkey, &Passphrase); certificate != nil || err == nil {
		t.Errorf("Failure:  No Failure while loading certificate using missing key with passphrase.")
	}
}
