// Package localpki is a local implementation to request certificates locally
package localpki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"

	"github.com/google/uuid"

	"homelab-pki/internal/entities"
	"homelab-pki/pkg/errorhandling"
)

const (
	// RootCACommonName is the replacement of the root CA G3 commonname
	RootCACommonName                 entities.RootCAIssuerCN = "GMem"
	pemBlockCertificateType          string                  = "CERTIFICATE"
	pemBlockCertificateRequestType   string                  = "CERTIFICATE REQUEST"
	pemBlockCertificateRSAPKEYType   string                  = "RSA PRIVATE KEY"
	pemBlockCertificateECDSAPKEYType string                  = "EC PRIVATE KEY"
	keySize                          int                     = 4096

	// RSA defines a constant of the type EncryptionAlgo
	RSA EncryptionAlgo = "RSA"
	// ECDSA defines a constant of the type EncryptionAlgo
	ECDSA EncryptionAlgo = "ECDSA"

	// BitSize is used to generate a serial number up to 20 octets (160 bits) //https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.2 | We use 64-bit serial to get 19 decimal digits.
	BitSize uint = 64
)

var (
	// ErrCertGeneration is a specific error for certificate generation failures.
	ErrCertGeneration = errors.New("failed to generate certificate")
	// ErrCertParse is a error when the certificate in byte format could not be parsed properly.
	ErrCertParse = errors.New("failed parsing certificate")
	// ErrCSRParse is a error when the certificateRequest in byte format could not be parsed properly.
	ErrCSRParse = errors.New("failed parsing certificate")
	// ErrKeyGeneration is a specific error for key generation failures.
	ErrKeyGeneration = errors.New("failed to generate private key")
	// ErrSerialGeneration is a specific error for serial generation failures.
	ErrSerialGeneration = errors.New("failed to generate serialNumber")
	// ErrInvalidInput handles input failures // TODO: should be replaced by existing usecaseerrors.
	ErrInvalidInput = errors.New("invalid input or missing configuration")
	// ErrHostnameValidation verifies if the hostname of the certificates matches with the input.
	ErrHostnameValidation = errors.New("hostname validation failed")
	// ErrDNSValidation verifies if the DNS of the certificates.
	ErrDNSValidation = errors.New("dsn validation failed")
	// ErrIDNotFound verifies if the id is found is the map of the certificate store.
	ErrIDNotFound = errors.New("no certificate found in the certificate store")
	// ErrIDEmpty does not allow to search on the map with an empty string as ID.
	ErrIDEmpty = errors.New("not allowed to enter empty id to search in the certificate store")
	// ErrIDTaken ID is not available since it's already taken.
	ErrIDTaken = errors.New("id is already taken")
	// ErrAlreadyRevoked mean that the certificate found has already the revoked status.
	ErrAlreadyRevoked = errors.New("certificate is already revoked")
	// ErrFilterMissMatch returns an error when the filtering on commonname fails
	ErrFilterMissMatch = errors.New("filtering on [commonname] did not match")
	// ErrInvalidCSR used the validateCSR func to define the csr in the localPKI driver
	ErrInvalidCSR = errors.New("error validating csr")
	// ErrIsNil returns the error code when a state equals nil or ""
	ErrIsNil = errors.New("is nil")
	// ErrSigValidation displays that a signature validation for x509 has failed.
	ErrSigValidation = errors.New("validating signature failed")

	// moved to usecases error package

	// ErrCommonNameValidation verifies if the hostname of the certificates matches with the input.
	ErrCommonNameValidation = errorhandling.ErrHostnameValidation
)

// EncryptionAlgo defines types of encryption keys.
type EncryptionAlgo string

// InMemoryCertificatesProvider builds a CA and stores certificates in-memory.
// authorization information
// + revoke struct (reason information)
type InMemoryCertificatesProvider struct { //nolint:govet // No idea to resolve this error
	certificates map[string]*entities.CertificateStore
	caCert       *x509.Certificate
	caKey        *rsa.PrivateKey
	mu           sync.RWMutex
	random       io.Reader
	crlEntries   []pkix.RevokedCertificate // List of revoked certificates
	idGenerator  IDGenerator
}

// NewInMemoryCertificatesProvider initializes a new InMemoryCertificatesProvider with a CA.
func NewInMemoryCertificatesProvider(random io.Reader, issuerCN entities.RootCAIssuerCN, options ...Option) (*InMemoryCertificatesProvider, error) {
	config := &ProviderConfig{
		random:      random,                      // can be moved out of the inputs if required, which needs some refactoring.
		idGenerator: IDGeneratorFN(uuid.NewUUID), // default uuid generator.
		caCertTemplate: &x509.Certificate{
			// SerialNumber: serial, // serial will be generated using the io.Reader
			Subject: pkix.Name{
				Organization: []string{"MyOrg"},
				CommonName:   string(issuerCN),
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour), // expire after 1 year.
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		},
	}

	// options override the default config
	for _, option := range options {
		option(config)
	}

	caKey, err := rsa.GenerateKey(config.random, keySize)
	if err != nil {
		return nil, errors.Join(ErrKeyGeneration, err)
	}

	serial, err := generateSerial(config.random)
	if err != nil {
		return nil, errors.Join(ErrSerialGeneration, err) // Difficult to test since rsa.GenerateKey will break if we use the IO reader to return a error state.
	}

	config.caCertTemplate.SerialNumber = serial

	caCertBytes, err := x509.CreateCertificate(config.random, config.caCertTemplate, config.caCertTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, errors.Join(ErrCertGeneration, err)
	}

	caCert, err := x509.ParseCertificate(caCertBytes) // Difficult to test this section. It does not make sense to mock the x509.CreateCertificate() and alter the bytes to make those invalid. It's expected that the above function always returns a proper set of bytes.
	if err != nil {
		return nil, errors.Join(ErrCertParse, err)
	}

	providerConfig := &InMemoryCertificatesProvider{
		certificates: make(map[string]*entities.CertificateStore),
		caCert:       caCert,
		caKey:        caKey,
		random:       config.random,
		idGenerator:  config.idGenerator,
	}

	return providerConfig, nil
}

// generateSerial should comply with RFC5280
// https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.2
func generateSerial(random io.Reader) (*big.Int, error) {
	serial, err := rand.Int(random, new(big.Int).Lsh(big.NewInt(1), BitSize)) // Generate a serial number up to 20 octets (160 bits)
	if err != nil {
		return nil, errors.Join(ErrSerialGeneration, err)
	}

	return serial, nil
}

// addNewCert2Store adds the certificate to the local store. Avoid the mix of
// deterministic and non-deterministic code.
// When adding a new Certificate it returns a New ID for the certificate.
func (inMemoryCertStore *InMemoryCertificatesProvider) addNewCert2Store(cert *x509.Certificate) (string, error) {
	id, err := inMemoryCertStore.idGenerator.NewUUID()
	if err != nil {
		return "", fmt.Errorf("id generation failed: %w", err)
	}

	if id.String() == "" || id.String() == uuid.Nil.String() {
		return "", ErrIDEmpty
	}

	if _, exists := inMemoryCertStore.certificates[id.String()]; exists {
		return "", fmt.Errorf("error using the generated ID, since it's already taken: %w", ErrIDTaken)
	}

	serialHex := hex.EncodeToString(cert.SerialNumber.Bytes()) // preserving leading zeros

	state := entities.Active

	inMemoryCertStore.certificates[id.String()] = &entities.CertificateStore{
		ID:          id.String(),
		Certificate: cert,
		SerialHex:   serialHex,
		CommonName:  cert.Subject.CommonName,
		StartDate:   &cert.NotBefore,
		EndDate:     &cert.NotAfter,
		Status:      state,
		// TokenType: typeless,
	}

	return id.String(), nil
}

// validateCSR validates a Certificate Signing Request to ensure it meets specific criteria.
func validateCSR(csr *x509.CertificateRequest) error {
	funcErr := ErrInvalidCSR
	// Check if the CSR is nil
	if csr == nil {
		return errors.Join(funcErr, ErrIsNil)
	}

	// Parse the CSR to check its contents
	if _, err := x509.ParseCertificateRequest(csr.Raw); err != nil {
		return errors.Join(funcErr, ErrCSRParse)
	}

	// Check the signature on the CSR
	if err := csr.CheckSignature(); err != nil {
		return errors.Join(funcErr, ErrSigValidation)
	}

	// Validate Common Name (CN)
	if csr.Subject.CommonName == "" {
		return errors.Join(funcErr, ErrCommonNameValidation, ErrIsNil)
	}

	// Validate DNSNames in SAN extension
	for _, dnsName := range csr.DNSNames {
		if dnsName == "" {
			return errors.Join(funcErr, ErrDNSValidation, ErrIsNil)
		} // Add more DNS checks if required.
	}

	return nil
}
