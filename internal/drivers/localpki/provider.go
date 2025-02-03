package localpki

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"time"

	"homelab-pki/internal/entities"
	"homelab-pki/internal/usecases"
	"homelab-pki/pkg/certificates"
)

// GetCertificate retrieves a certificate by its id
func (inMemoryCertStore *InMemoryCertificatesProvider) GetCertificate(_ context.Context, id string) (*entities.CertificateStore, error) {
	funcErr := errors.New("(localpki: GetCertificate)")

	inMemoryCertStore.mu.RLock()
	defer inMemoryCertStore.mu.RUnlock()

	err := inMemoryCertStore.validateID(id)
	if err != nil {
		return nil, errors.Join(funcErr, err)
	}

	cert := inMemoryCertStore.certificates[id]

	return cert, nil
}

// ListCertificates lists certificates based on filters.
func (inMemoryCertStore *InMemoryCertificatesProvider) ListCertificates(_ context.Context, options ...usecases.CertificateOption) (map[string]*entities.CertificateStore, error) {
	inMemoryCertStore.mu.RLock()
	defer inMemoryCertStore.mu.RUnlock()

	conf := usecases.NewCertificateOptions(options...)

	out := make(map[string]*entities.CertificateStore)

	for id, cert := range inMemoryCertStore.certificates {
		if matchesFilter(cert, conf) {
			out[id] = cert
		}
	}

	return out, nil
}

// CreateCertificate generates and stores a new certificate.
func (inMemoryCertStore *InMemoryCertificatesProvider) CreateCertificate(_ context.Context, csr *x509.CertificateRequest, options ...usecases.CertificateOption) (*entities.CertificateStore, error) {
	funcErr := errors.New("(localpki: CreateCertificate)")

	inMemoryCertStore.mu.Lock()
	defer inMemoryCertStore.mu.Unlock()

	if err := validateCSR(csr); err != nil {
		return nil, errors.Join(funcErr, err)
	}

	conf := usecases.NewCertificateOptions(options...)

	id, err := inMemoryCertStore.create(csr, conf)
	if err != nil {
		return nil, errors.Join(funcErr, err)
	}

	return inMemoryCertStore.certificates[id], nil
}

// RenewCertificate renews an existing certificate. It verifies the existence of
// the certificate based on the ID. Generated a new one with `Renewed` state.
// Revokes the previous found certificate based in the input ID.
func (inMemoryCertStore *InMemoryCertificatesProvider) RenewCertificate(_ context.Context, id string, csr *x509.CertificateRequest, options ...usecases.CertificateOption) (*entities.CertificateStore, error) {
	funcErr := errors.New("(localpki: RenewCertificate)")

	inMemoryCertStore.mu.Lock()
	defer inMemoryCertStore.mu.Unlock()

	err := inMemoryCertStore.validateID(id)
	if err != nil {
		return nil, errors.Join(funcErr, err)
	}

	if err := validateCSR(csr); err != nil {
		return nil, errors.Join(funcErr, err)
	}

	certStore := inMemoryCertStore.certificates[id]

	if certStore.Status == entities.Revoked {
		return nil, ErrAlreadyRevoked
	}

	conf := usecases.NewCertificateOptions(options...)

	// validation of WithOptions
	// We can append enforcement of the certificate options to put configuration, but we did not define those requirements clearly.
	if !matchesFilter(certStore, conf) {
		return nil, fmt.Errorf("%w: %w: filtering optional certificate functions does not match the found certificate: \n%v", funcErr, ErrFilterMissMatch, certStore)
	}

	// Override old BusinessValues to Renewed Certificate.
	conf.Subject.CommonName = certStore.CommonName

	newID, err := inMemoryCertStore.create(csr, conf)
	if err != nil {
		return nil, errors.Join(funcErr, err)
	}

	// Update with Renewed state
	inMemoryCertStore.certificates[newID].Status = entities.Renewed

	certOut := inMemoryCertStore.certificates[newID] // Define certificate output before unlocking | using the new generated ID.

	_, err = inMemoryCertStore.revoke(id, conf) // Revokes the certificate (old ID) after creation of the new certificate.
	if err != nil {
		return nil, errors.Join(funcErr, err) // difficult to test since similar validations are done upfront since we want insurance to revoke only when a creation completes.
	}

	return certOut, nil
}

// RevokeCertificate revokes a certificate. Reason is left empty since the
// struct does not contain a revoke information
// serialNumber must be in hex format.
func (inMemoryCertStore *InMemoryCertificatesProvider) RevokeCertificate(_ context.Context, id string, options ...usecases.CertificateOption) (*entities.CertificateStore, error) {
	funcErr := errors.New("(localpki: RevokeCertificate)")

	inMemoryCertStore.mu.Lock()
	defer inMemoryCertStore.mu.Unlock()

	conf := usecases.NewCertificateOptions(options...)

	// if hostname verification
	if conf.Subject.CommonName == "" {
		return nil, errors.Join(funcErr, errors.New("hostname verification triggered from subject content"), ErrCommonNameValidation, certificates.ErrInvalidInput)
	}

	certStore, err := inMemoryCertStore.revoke(id, conf)
	if err != nil {
		return nil, errors.Join(funcErr, err)
	}

	return certStore, nil
}

// GenerateCRL creates a standards-compliant CRL using the RevocationList
// template. Consider making this a private function after we update the
// interface to list CRL's.
func (inMemoryCertStore *InMemoryCertificatesProvider) GenerateCRL(_ context.Context) ([]byte, error) {
	inMemoryCertStore.mu.RLock()
	defer inMemoryCertStore.mu.RUnlock()

	crlTemplate := x509.RevocationList{
		Number:              big.NewInt(1), // Increment with each new CRL
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().Add(7 * 24 * time.Hour), // CRL valid for 7 days
		RevokedCertificates: inMemoryCertStore.crlEntries,
	}

	crlBytes, err := x509.CreateRevocationList(inMemoryCertStore.random, &crlTemplate, inMemoryCertStore.caCert, inMemoryCertStore.caKey)
	if err != nil {
		return nil, fmt.Errorf("error creating revocationlist: %w", err)
	}

	return crlBytes, nil
}
