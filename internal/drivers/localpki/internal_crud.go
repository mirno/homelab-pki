package localpki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"time"

	"homelab-pki/internal/entities"
	"homelab-pki/internal/usecases"
)

// create is an internal create function to support the Public functions,
// wrapping simpler functionality and separating mutex locks to the public
// levels.
func (inMemoryCertStore *InMemoryCertificatesProvider) create(csr *x509.CertificateRequest, _ *usecases.CertificateOptions) (string, error) {
	cert, err := inMemoryCertStore.generatex509Certificate(csr)
	if err != nil {
		return "", errors.Join(ErrCertGeneration, err)
	}

	id, err := inMemoryCertStore.addNewCert2Store(cert)
	if err != nil {
		return "", fmt.Errorf("error adding generated certificate to certstore: %w", err)
	}

	return id, nil
}

// revoke is an internal revoke function to support the Public functions,
// wrapping simpler functionality and separating mutex locks to the public
// levels.
func (inMemoryCertStore *InMemoryCertificatesProvider) revoke(id string, conf *usecases.CertificateOptions) (*entities.CertificateStore, error) {
	err := inMemoryCertStore.validateID(id)
	if err != nil {
		return nil, errors.Join(errors.New("unable revoke due to id validation issue"), err)
	}

	certStore := inMemoryCertStore.certificates[id]

	// validation of WithOptions
	// We can append enforcement of the certificate options to put configuration, but we did not define those requirements clearly.
	if !matchesFilter(certStore, conf) {
		return nil, fmt.Errorf("%w: filtering optional certificate functions does not match the found certificate: \n%v", ErrFilterMissMatch, certStore)
	}

	if certStore.Status == entities.Revoked {
		return nil, ErrAlreadyRevoked
	}

	certStore.Status = entities.Revoked // Instead of modifying the certStore pointer (*entities.CertificateStore) we use the certificates directly so we can use the mutex lock.

	// Add the certificate to the CRL entries
	revokedCert := pkix.RevokedCertificate{
		SerialNumber:   certStore.Certificate.SerialNumber,
		RevocationTime: time.Now(),
	}
	inMemoryCertStore.crlEntries = append(inMemoryCertStore.crlEntries, revokedCert)

	return certStore, nil
}
