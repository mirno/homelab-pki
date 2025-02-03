package test

import (
	"context"
	"crypto/x509"
	"homelab-pki/internal/usecases"
	"homelab-pki/pkg/certificates"
	"homelab-pki/pkg/errorhandling"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	commonName = "demo.example.com"
	sans       = []string{"verify01"}
)

func ValidatePKIProvider(t *testing.T, provider usecases.PKIProvider) {
	t.Helper()

	ctx := context.Background()

	signingConf := certificates.GetDefaultSigningConfig()

	csrDER, _, err := certificates.GenerateCSRFromConfig(commonName, sans, signingConf)
	require.NoError(t, err)

	csr := DecodeAndParseCSR(t, csrDER)

	cert, err := provider.CreateCertificate(ctx, csr)
	require.NoError(t, err)

	validateCert, err := provider.GetCertificate(ctx, cert.ID)
	require.NoError(t, err)

	assert.Equal(t, validateCert.Certificate.Subject.CommonName, cert.Certificate.Subject.CommonName)

	_, err = provider.RevokeCertificate(ctx, cert.ID)
	require.ErrorIs(t, err, errorhandling.ErrHostnameValidation)

	_, err = provider.RevokeCertificate(ctx, cert.ID, usecases.WithCommonName(commonName))
	require.NoError(t, err)
}

func DecodeAndParseCSR(t *testing.T, csrDER []byte) *x509.CertificateRequest {
	t.Helper()

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("failed to parse csr: %v", err)
	}

	return csr
}
