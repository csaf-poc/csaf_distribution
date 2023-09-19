package certs

import "testing"

func TestLoadCertificates(t *testing.T) {
	testCert := "data/testclient.crt"
	testKey := "data/testclientkey.pem"
	passphrase := "qwer"
	missingCert := "data/testclientcert_missing.crt"
	missingTestkey := "data/testclientkey_missing.pem"
	privateKey := "data/privated.pem"
	privateCert := "data/cert.crt"

	// Try to load certificate that is not protected, expect success.
	if certificate, err := LoadCertificate(&testCert, &testKey, nil); certificate == nil || err != nil {
		t.Errorf("Failure: Couldn't load supposedly valid certificate.")
	}
	// Try to load no certificate, expect error.
	if certificate, err := LoadCertificate(nil, &testKey, nil); certificate != nil || err == nil {
		t.Errorf("Failure: No error despite missing certificate")
	}
	// Try to load certificate using a nonexistent key, expect error.
	if certificate, err := LoadCertificate(&testCert, &missingTestkey, nil); certificate != nil || err == nil {
		t.Errorf("Failure: No Failure while loading certificate using missing key.")
	}
	// Try to decrypt not encrypted certificate, expect error
	if certificate, err := LoadCertificate(&testCert, &testKey, &passphrase); certificate != nil || err == nil {
		t.Errorf("Failure: Could load unprotected valid certificate with passphrase.")
	}
	// Try to load encrypted certificate using a nonexistent key, but valid passphrase. Expect error.
	if certificate, err := LoadCertificate(&testCert, &missingTestkey, &passphrase); certificate != nil || err == nil {
		t.Errorf("Failure:  No Failure while loading certificate using missing key with passphrase.")
	}
	// Try to load encrypted certificate, expecting success.
	if certificate, err := LoadCertificate(&privateCert, &privateKey, &passphrase); certificate == nil || err != nil {
		t.Errorf("Failure: Couldn't load supposedly valid encrypted certificate.")
	}
	// Try to load wrong encrypted certificate, expecting error.
	if certificate, err := LoadCertificate(&testKey, &privateKey, &passphrase); certificate != nil || err == nil {
		t.Errorf("Failure:  No Failure while loading certificate using wrong encrypted key.")
	}
	// Try to load nonexistent encrypted certificate, expecting error.
	if certificate, err := LoadCertificate(&missingCert, &privateKey, &passphrase); certificate != nil || err == nil {
		t.Errorf("Failure:  No Failure while loading nonexistens certificate.")
	}
	// Try to load nonexistent encrypted certificate, expecting error.
	if certificate, err := LoadCertificate(nil, nil, nil); certificate != nil || err != nil {
		t.Errorf("Failure:  Expected nil return.")
	}
}
