package localpki //nolint:testpackage // testing private function

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"homelab-pki/pkg/certificates"
)

// ErrIOReader is a helper error mocking IO Reader error.
var ErrIOReader = errors.New("mocked error")

type mockReaderDirectOverwrite struct{}

func (*mockReaderDirectOverwrite) Read(_ []byte) (int, error) {
	return 0, ErrIOReader
}

// TestSerialGeneration tests the private function 'generateSerial'. Since
// 'rsa.GenerateKey' used before the private function it's difficult to reach
// the generateSerial because the ioReader errors are caught before reaching
// this private function.
// Ideally we should avoid testing private functions.
func TestSerialGeneration(t *testing.T) {
	t.Parallel()

	mockReader := &mockReaderDirectOverwrite{}

	_, err := generateSerial(mockReader)
	require.ErrorIs(t, err, ErrSerialGeneration)
}

// TestCertGenerationErrors overrides the 'random' ioReader variable after the
// new struct is defined. This is required for the CA steps to complete without
// errors.
func TestCertGenerationErrors(t *testing.T) {
	t.Parallel()

	provider, err := NewInMemoryCertificatesProvider(rand.Reader, RootCACommonName)
	require.NoError(t, err)

	mockReader := &mockReaderDirectOverwrite{}

	provider.random = mockReader // overwrite reader.

	_, err = provider.CreateCertificate(context.Background(), generatex509CSR(t, "example.example.com", nil))
	require.ErrorIs(t, err, ErrCertGeneration, ErrIOReader)
}

// TestGenerateX509Certificate_ErrorCases does test the generatex509Certificate
// function. Which currently has it's error handled upfron in the following
// chained functions:
//   - CreateCertificate()
//   - create()
//   - generatex509Certificate()
func TestGenerateX509Certificate_ErrorCases(t *testing.T) {
	t.Parallel()

	// Test cases
	tests := []struct {
		setup     func() *x509.CertificateRequest
		wantError error
		name      string
	}{
		{
			name: "certificate generation error",
			setup: func() *x509.CertificateRequest {
				return &x509.CertificateRequest{
					Subject: pkix.Name{CommonName: "invalid"},
				}
			},
			wantError: ErrCertGeneration,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			provider, err := NewInMemoryCertificatesProvider(rand.Reader, RootCACommonName)
			require.NoError(t, err)

			_, err = provider.generatex509Certificate(tt.setup())
			require.ErrorIs(t, err, tt.wantError)
		})
	}
}

func generatex509CSR(t *testing.T, commonName string, sans []string) *x509.CertificateRequest {
	t.Helper()

	signingConf := certificates.GetDefaultSigningConfig()

	csrDER, _, err := certificates.GenerateCSRFromConfig(commonName, sans, signingConf)
	require.NoError(t, err)

	csrPEM, err := certificates.DecodeAndParseCSR(csrDER)
	require.NoError(t, err)

	return csrPEM
}
