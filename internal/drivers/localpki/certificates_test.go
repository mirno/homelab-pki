package localpki_test

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"homelab-pki/internal/drivers/localpki"
	"homelab-pki/internal/test"
	"homelab-pki/internal/usecases"
	"homelab-pki/pkg/certificates"
)

var domain = ".yourdomain.local"

type IOverwrite struct{}

func (*IOverwrite) Read(_ []byte) (int, error) {
	return 0, errors.New("always error")
}

func TestMemory_CertificatesProvider(t *testing.T) {
	t.Parallel()

	provider, err := localpki.NewInMemoryCertificatesProvider(rand.Reader, localpki.RootCACommonName)
	require.NoError(t, err)

	test.ValidatePKIProvider(t, provider)
}

func TestListing(t *testing.T) {
	ctx := context.TODO()

	t.Parallel()

	if testing.Short() {
		t.Skip(">20s")
	}

	const loopCount = 10

	var provider usecases.PKIProvider

	provider, err := localpki.NewInMemoryCertificatesProvider(rand.Reader, localpki.RootCACommonName)
	require.NoError(t, err)

	for range loopCount {
		var sans []string

		commonName := generateCommonName(t, domain)

		csr := generatex509CSR(t, commonName, sans)
		cert, err := provider.CreateCertificate(ctx, csr)
		require.NoError(t, err)
		assert.EqualValues(t, commonName, cert.Certificate.Subject.CommonName)
	}

	list, err := provider.ListCertificates(ctx)
	require.NoError(t, err)
	assert.Len(t, list, loopCount)
}

func TestBrokenIOReader(t *testing.T) {
	t.Parallel()

	reader := &IOverwrite{}

	_, err := localpki.NewInMemoryCertificatesProvider(reader, localpki.RootCACommonName)
	assert.Error(t, err)
}

func TestValidateCSR(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	tests := []struct {
		setupFunc  func(t *testing.T) *x509.CertificateRequest
		csr        *x509.CertificateRequest
		name       string
		wantErrors []error
	}{
		{
			name:       "IsNil",
			csr:        nil,
			wantErrors: []error{localpki.ErrInvalidCSR, localpki.ErrIsNil},
		},
		{
			name:       "Fail to parse",
			wantErrors: []error{localpki.ErrInvalidCSR, localpki.ErrCSRParse},
			setupFunc: func(t *testing.T) *x509.CertificateRequest {
				t.Helper()

				emptyCSR := x509.CertificateRequest{}
				emptyCSR.Raw = []byte("invalid data")

				return &emptyCSR
			},
		},
		{
			name:       "Invalid signature",
			wantErrors: []error{localpki.ErrInvalidCSR, localpki.ErrSigValidation},
			setupFunc: func(t *testing.T) *x509.CertificateRequest {
				t.Helper()

				csr := generatex509CSR(t, "signaturetest.example.com", nil)

				csr.Signature = append(csr.Signature, byte(0))

				return csr
			},
		},
		{
			name:       "Missing CommonName",
			wantErrors: []error{localpki.ErrInvalidCSR, localpki.ErrCommonNameValidation, localpki.ErrIsNil},
			setupFunc: func(t *testing.T) *x509.CertificateRequest {
				t.Helper()

				return generatex509CSR(t, "", nil)
			},
		},
		{
			name:       "Empty DNS SAN",
			wantErrors: []error{localpki.ErrInvalidCSR, localpki.ErrDNSValidation, localpki.ErrIsNil},
			setupFunc: func(t *testing.T) *x509.CertificateRequest {
				t.Helper()

				return generatex509CSR(t, "emptydnssan.example.com", []string{""})
			},
		},
		{
			name:       "Valid",
			wantErrors: nil,
			setupFunc: func(t *testing.T) *x509.CertificateRequest {
				t.Helper()

				return generatex509CSR(t, "valid.example.com", nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var csr *x509.CertificateRequest

			if tt.setupFunc != nil {
				csr = tt.setupFunc(t)
			} else {
				csr = tt.csr
			}

			provider, err := localpki.NewInMemoryCertificatesProvider(rand.Reader, localpki.RootCACommonName)
			require.NoError(t, err)

			_, err = provider.CreateCertificate(ctx, csr)

			for _, expectedError := range tt.wantErrors {
				require.ErrorIs(t, err, expectedError)
			}
		})
	}
}

func TestInvalidCATemplate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		template    *x509.Certificate
		expectedErr string
	}{
		{
			name: "invalid basic constraints",
			template: &x509.Certificate{
				SerialNumber:          big.NewInt(1),
				Subject:               pkix.Name{CommonName: "Invalid Constraints"},
				BasicConstraintsValid: true,
				IsCA:                  false,
				MaxPathLen:            1,
			},
			expectedErr: "x509: only CAs are allowed to specify MaxPathLen",
		},
		{
			name: "unsupported SignatureAlgorithm",
			template: &x509.Certificate{
				SerialNumber:       big.NewInt(1),
				Subject:            pkix.Name{CommonName: "Unsupported Key"},
				SignatureAlgorithm: x509.ECDSAWithSHA1,
				IsCA:               true,
			},
			expectedErr: "x509: requested SignatureAlgorithm does not match private key type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := localpki.NewInMemoryCertificatesProvider(rand.Reader, localpki.RootCACommonName, localpki.WithOverRideCATemplate(tt.template))
			require.Error(t, err)
			require.ErrorContains(t, err, tt.expectedErr)
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

func generateCommonName(t *testing.T, domain string) string {
	t.Helper()

	randomName, err := generateName(t, "pki", 5)
	require.NoError(t, err)

	return randomName + domain
}

func generateName(t *testing.T, prefix string, length int) (string, error) {
	t.Helper()

	const ascii = "0123456789qwertyuiopasdfghjklzxcvbnm"

	result := make([]byte, 0, length)

	for range length {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(ascii))))
		if err != nil {
			return "", fmt.Errorf("error generating random int: %w", err)
		}

		result = append(result, ascii[num.Int64()])
	}

	return prefix + string(result), nil
}
