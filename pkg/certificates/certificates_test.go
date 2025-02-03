package certificates_test

import (
	"crypto/x509"
	"encoding/pem"
	"homelab-pki/pkg/certificates"
	"testing"
)

// TODO(william) Implement parameterized test

// func TestGenerateCSRSANs(t *testing.T) {
// 	test := []struct {
// 		name string
// 		dnsSANs []string
// 		ipSANs []string
// 		validate func(*testing.T, *x509.CertificateRequest)
// 	}
// } ... unimplemented parameterized test

func TestGenerateCSR(t *testing.T) {
	t.Parallel()

	commonName := "examplecsr.example.com"
	sans := []string{"examplecsr.example.com", "examplecsr2.example.com", "10.10.10.10", "10.10.10.11"}

	csrDER, _, err := certificates.GenerateCSRFromConfig(commonName, sans, getSigningConfig())
	if err != nil {
		t.Fatalf("Failed to generate CSR: %v", err)
	}

	csr := decodeAndParseCSR(t, csrDER)

	// Verify Common Name
	verifyCommonName(t, csr, commonName)
	// Verify SANs
	verifyDNSSAN(t, csr, sans)
	// Verify SANIPs
	verifyIPSAN(t, csr, sans)
}

func TestPrivateKeyConversion(t *testing.T) {
	t.Parallel()

	commonName := "examplecsr.example.com"
	sans := []string{"examplecsr.example.com", "examplecsr2.example.com", "10.10.10.10", "10.10.10.11"}

	_, keyDER, err := certificates.GenerateCSRFromConfig(commonName, sans, getSigningConfig())
	if err != nil {
		t.Fatalf("Failed to generate CSR: %v", err)
	}

	_, err = certificates.ConvertPrivateKeyToPEM(keyDER)
	if err != nil {
		t.Fatalf("keyDER conversion to pem failed: %v", err)
	}
}

func TestConvertX509Cert2PEM(t *testing.T) {
	t.Parallel()

	// Mock Raw Data
	exampleCert := &x509.Certificate{
		Raw: []byte{0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00},
	}

	want := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: exampleCert.Raw,
	}))

	got := certificates.ConvertX509Cert2PEM(exampleCert)

	if got != want {
		t.Errorf("error conversion cert to pem; got: %v, want %v", got, want)
	}
}

func TestConvertX509CSR2PEM(t *testing.T) {
	t.Parallel()

	// Mock Raw Data
	csr := &x509.CertificateRequest{
		Raw: []byte{0x33, 0x12, 0x02, 0x0a, 0x02, 0x52, 0x01, 0x01, 0x00},
	}

	want := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr.Raw,
	}))

	got := certificates.ConvertX509CSR2PEM(csr)

	if got != want {
		t.Errorf("error conversion csr to pem; got: %v, want %v", got, want)
	}
}

func verifyCommonName(t *testing.T, csr *x509.CertificateRequest, expectedcn string) {
	t.Helper()

	if csr.Subject.CommonName != expectedcn {
		t.Errorf("Expected common name: %s, got %s", expectedcn, csr.Subject.CommonName)
	}
}

func verifyDNSSAN(t *testing.T, csr *x509.CertificateRequest, sans []string) {
	t.Helper()

	expectedSans := map[string]bool{sans[0]: true, sans[1]: true}

	for _, dnsName := range csr.DNSNames {
		if !expectedSans[dnsName] {
			t.Errorf("unexpected san value found: %s", dnsName)
		}

		delete(expectedSans, dnsName) // deletes found sounds to compare if we miss something
	}

	if len(expectedSans) > 0 {
		t.Errorf("not all expected sans found in csr, missing %v", expectedSans)
	}
}

func verifyIPSAN(t *testing.T, csr *x509.CertificateRequest, sans []string) {
	t.Helper()

	expectedIPs := map[string]bool{sans[2]: true, sans[3]: true} // Update on loopBase

	for _, ipAddress := range csr.IPAddresses {
		ipString := ipAddress.String()
		if !expectedIPs[ipAddress.String()] {
			t.Errorf("unexpected ip san found: %s", ipString)
		}

		delete(expectedIPs, ipString)
	}

	if len(expectedIPs) > 0 {
		t.Errorf("not all expected ip sans are found within the csr. Missing: %v", expectedIPs)
	}
}

func decodeAndParseCSR(t *testing.T, csrDER []byte) *x509.CertificateRequest {
	t.Helper() // Mark as test helper

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("Failed to parse CSR: %v", err)
	}

	return csr
}

func getSigningConfig() *certificates.SigningConfig {
	return &certificates.SigningConfig{
		CountryName:        "NL",
		State:              "NH",
		Locality:           "Amsterdam",
		Organization:       "MyOrg",
		OrganizationalUnit: "Unit",
		BitSize:            4096,
	}
}
