package localpki_test

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"homelab-pki/internal/drivers/localpki"
	"homelab-pki/internal/entities"
	"homelab-pki/internal/usecases"
)

func TestInMemoryCertificatesProvider_GetCertificate(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	provider, err := localpki.NewInMemoryCertificatesProvider(rand.Reader, localpki.RootCACommonName)
	require.NoError(t, err)

	// Create a certificate to use in tests
	certStore, err := provider.CreateCertificate(ctx, generatex509CSR(t, generateCommonName(t, domain), []string{}))
	require.NoError(t, err)

	cert, err := provider.GetCertificate(ctx, certStore.ID)
	require.NoError(t, err)
	assert.Equal(t, certStore, cert)

	// Non existed ID
	_, err = provider.GetCertificate(ctx, "nonexistent-id")
	assert.ErrorIs(t, err, localpki.ErrIDNotFound)
}

func TestInMemoryCertificatesProvider_ListCertificates(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	provider, err := localpki.NewInMemoryCertificatesProvider(rand.Reader, localpki.RootCACommonName)
	require.NoError(t, err)

	var waitGroup sync.WaitGroup

	waitGroup.Add(3)

	results := make(map[string]*entities.CertificateStore)

	var muty sync.Mutex

	createCert := func(commonName, resultKey string) {
		defer waitGroup.Done()

		certStore, err := provider.CreateCertificate(ctx, generatex509CSR(t, commonName, []string{}))
		require.NoError(t, err)

		muty.Lock()
		results[resultKey] = certStore
		muty.Unlock()
	}

	go createCert("cert1.example.com", "cert1")
	go createCert("cert2.example.com", "cert2")
	go createCert("cert3.example.com", "cert3")

	waitGroup.Wait()

	// Assume ListCertificates returns a map of CertificateStore by ID
	certs, err := provider.ListCertificates(ctx)
	require.NoError(t, err)
	assert.Len(t, certs, 3)

	// Verify that all certificates are present using the results from the map
	assert.Equal(t, certs[results["cert1"].ID], results["cert1"])
	assert.Equal(t, certs[results["cert2"].ID], results["cert2"])
	assert.Equal(t, certs[results["cert3"].ID], results["cert3"])
}

func TestInMemoryCertificatesProvider_CreateCertificate(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	tests := []struct {
		csr       *x509.CertificateRequest
		wantError error
		name      string
	}{
		{
			name:      "Successfully create certificate",
			csr:       generatex509CSR(t, generateCommonName(t, domain), []string{}),
			wantError: nil,
		},
		{
			name:      "Create certificate with invalid CSR",
			csr:       &x509.CertificateRequest{}, // Invalid CSR
			wantError: localpki.ErrInvalidCSR,
		},
		{
			name:      "Create certificate with invalid nil CSR",
			csr:       nil, // Invalid CSR
			wantError: localpki.ErrInvalidCSR,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			provider, err := localpki.NewInMemoryCertificatesProvider(rand.Reader, localpki.RootCACommonName)
			require.NoError(t, err)

			cert, err := provider.CreateCertificate(ctx, tt.csr)
			if tt.wantError != nil {
				assert.ErrorIs(t, err, tt.wantError)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, cert)
				assert.Equal(t, tt.csr.Subject.CommonName, cert.CommonName)
			}
		})
	}
}

func TestInMemoryCertificatesProvider_RenewCertificate(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	provider, err := localpki.NewInMemoryCertificatesProvider(rand.Reader, localpki.RootCACommonName)
	require.NoError(t, err)

	commonName := generateCommonName(t, domain)

	csr := generatex509CSR(t, commonName, []string{})

	// Create a certificate to use in tests
	origCert, err := provider.CreateCertificate(ctx, csr)
	require.NoError(t, err)

	// verify commonName mismatch
	_, err = provider.RenewCertificate(ctx, origCert.ID, csr, usecases.WithCommonName("mismatch"+domain))
	require.ErrorIs(t, err, localpki.ErrFilterMissMatch)

	// verify ID mismatch
	_, err = provider.RenewCertificate(ctx, "non-existing", csr)
	require.ErrorIs(t, err, localpki.ErrIDNotFound)

	// renew using the same csr...
	renewedCert, err := provider.RenewCertificate(ctx, origCert.ID, csr, usecases.WithCommonName(commonName))
	require.NoError(t, err)
	assert.Equal(t, origCert.CommonName, renewedCert.CommonName)
	assert.Equal(t, entities.Renewed, renewedCert.Status)

	// verify if old cert is revoked.
	verifyGetOrig, err := provider.GetCertificate(ctx, origCert.ID)
	require.NoError(t, err)
	assert.Equal(t, entities.Revoked, verifyGetOrig.Status)

	_, err = provider.RenewCertificate(ctx, origCert.ID, csr, usecases.WithCommonName(commonName))
	require.ErrorIs(t, err, localpki.ErrAlreadyRevoked)
}

func TestInMemoryCertificatesProvider_RenewCertificate_FaultyRevoke(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	provider, err := localpki.NewInMemoryCertificatesProvider(rand.Reader, localpki.RootCACommonName)
	require.NoError(t, err)

	commonName := generateCommonName(t, domain)

	csr := generatex509CSR(t, commonName, []string{})

	// Create a certificate to use in tests
	origCert, err := provider.CreateCertificate(ctx, csr)
	require.NoError(t, err)

	_, err = provider.RenewCertificate(ctx, origCert.ID, csr, usecases.WithCommonName(commonName), usecases.WithCommonName("faulty"))
	require.ErrorIs(t, err, localpki.ErrFilterMissMatch)
}

func TestInMemoryCertificatesProvider_RenewCertificate_InvalidCSR(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	tests := []struct {
		csr       *x509.CertificateRequest
		wantError error
		name      string
	}{
		{
			name:      "Create certificate with invalid CSR",
			csr:       &x509.CertificateRequest{}, // Invalid CSR
			wantError: localpki.ErrInvalidCSR,
		},
		{
			name:      "Create certificate with invalid nil CSR",
			csr:       nil, // Invalid CSR
			wantError: localpki.ErrInvalidCSR,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			provider, err := localpki.NewInMemoryCertificatesProvider(rand.Reader, localpki.RootCACommonName)
			require.NoError(t, err)

			commonName := generateCommonName(t, domain)

			validCSR := generatex509CSR(t, commonName, []string{})

			// Create a valid certificate to use in test
			origCert, err := provider.CreateCertificate(ctx, validCSR)
			require.NoError(t, err)

			// renew using the same csr...
			_, err = provider.RenewCertificate(ctx, origCert.ID, tt.csr, usecases.WithCommonName(commonName))
			require.ErrorIs(t, err, tt.wantError)
		})
	}
}

func TestInMemoryCertificatesProvider_RevokeCertificate(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	provider, err := localpki.NewInMemoryCertificatesProvider(rand.Reader, localpki.RootCACommonName)
	require.NoError(t, err)

	commonName := generateCommonName(t, domain)
	// Create a certificate to use in tests
	certStore, err := provider.CreateCertificate(ctx, generatex509CSR(t, commonName, []string{}))
	require.NoError(t, err)

	// WithOut commonName verification
	_, err = provider.RevokeCertificate(ctx, certStore.ID)
	require.ErrorIs(t, err, localpki.ErrCommonNameValidation)

	// faulty commonName
	_, err = provider.RevokeCertificate(ctx, certStore.ID, usecases.WithCommonName("faulty"))
	require.ErrorIs(t, err, localpki.ErrFilterMissMatch)

	// non-existing ID // CommonName verification is higher in order
	_, err = provider.RevokeCertificate(ctx, "nonexistent-id", usecases.WithCommonName(commonName))
	require.ErrorIs(t, err, localpki.ErrIDNotFound)

	// Empty ID //
	_, err = provider.RevokeCertificate(ctx, "", usecases.WithCommonName(commonName))
	require.ErrorIs(t, err, localpki.ErrIDEmpty)

	// Successfully revoke.
	_, err = provider.RevokeCertificate(ctx, certStore.ID, usecases.WithCommonName(commonName))
	require.NoError(t, err)

	// Verify that the certificate is revoked
	get, err := provider.GetCertificate(ctx, certStore.ID)
	require.NoError(t, err)
	assert.Equal(t, entities.Revoked, get.Status)

	// Already revoked.
	_, err = provider.RevokeCertificate(ctx, certStore.ID, usecases.WithCommonName(commonName))
	require.ErrorIs(t, err, localpki.ErrAlreadyRevoked)

	crlBytes, err := provider.GenerateCRL(ctx)
	require.NoError(t, err)

	parsed, err := x509.ParseRevocationList(crlBytes)
	require.NoError(t, err)

	assert.Equal(t, parsed.RevokedCertificateEntries[0].SerialNumber, get.Certificate.SerialNumber)
}

func TestCSRValidationInCertificateFunctions(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	if testing.Short() {
		t.Skip("long test")
	}

	tests := []struct {
		csr       *x509.CertificateRequest
		wantError error
		name      string
	}{
		{
			name:      "Valid CSR",
			csr:       generatex509CSR(t, generateCommonName(t, domain), []string{}),
			wantError: nil,
		},
		{
			name:      "Create with nil CSR",
			csr:       nil,
			wantError: localpki.ErrInvalidCSR,
		},
		{
			name:      "Create with empty CN",
			csr:       generatex509CSR(t, "", []string{"example.com"}),
			wantError: localpki.ErrInvalidCSR,
		},
		{
			name:      "Renew with nil CSR",
			csr:       nil,
			wantError: localpki.ErrInvalidCSR,
		},
		{
			name:      "Renew with empty CN",
			csr:       generatex509CSR(t, "", []string{"example.com"}),
			wantError: localpki.ErrInvalidCSR,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			provider, err := localpki.NewInMemoryCertificatesProvider(rand.Reader, localpki.RootCACommonName)
			require.NoError(t, err)

			// Create a valid certificate to use for renewal tests
			validCSR := generatex509CSR(t, generateCommonName(t, domain), []string{}) // same CSR parallel runs
			baseCert, err := provider.CreateCertificate(ctx, validCSR)
			require.NoError(t, err)

			_, err = provider.CreateCertificate(ctx, tt.csr)
			require.ErrorIs(t, err, tt.wantError)

			_, err = provider.RenewCertificate(ctx, baseCert.ID, tt.csr) // Try to renew with same CSR ?
			require.ErrorIs(t, err, tt.wantError)
		})
	}
}

func TestInMemoryCertificatesProvider_GenerateCRL(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	template := &x509.Certificate{
		// SerialNumber: serial, // serial will be generated using the io.Reader
		Subject: pkix.Name{
			Organization: []string{"MyOrg"},
			CommonName:   string("CRL"),
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // expire after 1 year.
		KeyUsage:              x509.KeyUsageCertSign,                // exclude x509.KeyUsageCRLSign to cause error.
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	provider, err := localpki.NewInMemoryCertificatesProvider(rand.Reader, localpki.RootCACommonName, localpki.WithOverRideCATemplate(template))
	require.NoError(t, err)

	_, err = provider.GenerateCRL(ctx)
	require.Error(t, err)
}
