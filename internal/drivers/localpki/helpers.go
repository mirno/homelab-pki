package localpki

import (
	"crypto/x509"
	"errors"
	"homelab-pki/internal/entities"
	"homelab-pki/internal/usecases"
	"time"

	"github.com/google/uuid"
)

func matchesFilter(cert *entities.CertificateStore, conf *usecases.CertificateOptions) bool {
	commonNameMatches := (conf.Subject.CommonName == "" || cert.CommonName == conf.Subject.CommonName)

	return commonNameMatches
}

func (inMemoryCertStore *InMemoryCertificatesProvider) generatex509Certificate(csr *x509.CertificateRequest) (*x509.Certificate, error) {
	serial, err := generateSerial(inMemoryCertStore.random)
	if err != nil {
		return nil, errors.Join(ErrSerialGeneration, err)
	}

	certTemplate := &x509.Certificate{
		SerialNumber: serial,
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature, // https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3
	}

	certBytes, err := x509.CreateCertificate(inMemoryCertStore.random, certTemplate, inMemoryCertStore.caCert, csr.PublicKey, inMemoryCertStore.caKey)
	if err != nil {
		return nil, errors.Join(ErrCertGeneration, err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, errors.Join(ErrCertParse, err) // Difficult to test this section. It does not make sense to mock the x509.CreateCertificate() and alter the bytes to make those invalid. It's expected that the above function always returns a proper set of bytes.
	}

	return cert, nil
}

func (inMemoryCertStore *InMemoryCertificatesProvider) validateID(id string) error {
	if id == "" || id == uuid.Nil.String() {
		return ErrIDEmpty
	}

	if _, exists := inMemoryCertStore.certificates[id]; !exists {
		return ErrIDNotFound
	}

	return nil
}
