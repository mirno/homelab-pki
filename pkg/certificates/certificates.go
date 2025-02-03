// Package certificates provides utilities to handle X.509 certificates.
package certificates

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

const (
	pemBlockCertificateType          string = "CERTIFICATE"
	pemBlockCertificateRequestType   string = "CERTIFICATE REQUEST"
	pemBlockCertificateRSAPKEYType   string = "RSA PRIVATE KEY"
	pemBlockCertificateECDSAPKEYType string = "EC PRIVATE KEY"
	keySize                          int    = 4096

	// BitSize is used to generate a serial number up to 20 octets (160 bits)
	// https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.2
	// We use 64-bit serial to get 19 decimal digits.
	BitSize uint = 64
)

var (
	// ErrCertGeneration is a specific error for certificate generation failures.
	ErrCertGeneration = errors.New("failed to generate certificate")
	// ErrKeyGeneration is a specific error for key generation failures.
	ErrKeyGeneration = errors.New("failed to generate private key")
	// ErrSerialGeneration is a specific error for serial generation failures.
	ErrSerialGeneration = errors.New("failed to generate serialNumber")
	// ErrInvalidInput handles input failures // TODO: should be replaced by existing usecaseerrors.
	ErrInvalidInput = errors.New("invalid input or missing configuration")
)

// GenerateCSRFromConfig creates a DER-encoded certificate signing request (CSR)
func GenerateCSRFromConfig(commonName string, sans []string, conf *SigningConfig) ([]byte, *rsa.PrivateKey, error) {
	// TODO(mirno) Build option to provide  ecdsa as well
	privateKey, err := rsa.GenerateKey(rand.Reader, conf.BitSize)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating x509 private key: %w", err)
	}

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         commonName,
			Organization:       []string{conf.Organization},       // types read from files are not slices
			OrganizationalUnit: []string{conf.OrganizationalUnit}, // types read from files are not slices
		},
		DNSNames:    extractDNSNames(sans),
		IPAddresses: extractIPs(sans),
		// Directly specify sans // ExtraExtensions could have been an option as well.
		// Need to figure our how to insert sans based on an existing CSR (I believe the API handles some of this already)
		// using the asn1.RawValues (See outcommented below)
		// ExtraExtensions: []pkix.Extension{
		// 	pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Critical: false, Value: []byte{san}},
		// },
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create certificate request: %w", err)
	}

	return csrBytes, privateKey, nil
}

// Bad implementation of functions, requires improvements
// Required to run double checks, which causes a bad/slow implementation according to BigO

// extractDNSNames is a helper function
// to extract the DNS names from the SAN
// information within the certificate
// separate DNSSAN and IPSAN
func extractDNSNames(sans []string) []string {
	var dnsNames []string

	for _, san := range sans {
		// not ideal to simply not-match IP since SAN mail could be an option as well.
		if ip := net.ParseIP(san); ip == nil {
			// append to string slice
			dnsNames = append(dnsNames, san)
		}
	}

	return (dnsNames)
}

// extractIPs is a helper function
// to extract the IP's  from the SAN
// information within the certificate
// separate DNSSAN and IPSAN
func extractIPs(sans []string) []net.IP {
	var ipSAN []net.IP

	for _, san := range sans {
		if ip := net.ParseIP(san); ip != nil {
			// append to string slice
			ipSAN = append(ipSAN, ip)
		}
	}

	return (ipSAN)
}

// GetDefaultSigningConfig returns the company-specific, default signing
// configuration
func GetDefaultSigningConfig() *SigningConfig {
	return &SigningConfig{
		CommonName:         "signexample.example.com",
		CountryName:        "NL",
		State:              "NH",
		Locality:           "Amstelveen",
		Organization:       "MyOrg",
		OrganizationalUnit: "Unit",
		BitSize:            keySize,
	}
}

// ConvertToPEM transforms the input into a PEM block then returns its string
// representation.
//
// it supports byte slice or *x509.Certificate values
//
// Deprecated: input any should be replace to avoid type errors.
// Use:
//   - ConvertX509Cert2PEM
//   - ConvertX509CSR2PEM
func ConvertToPEM(input any) (string, error) {
	switch certData := input.(type) {
	case []byte:
		// DER encoded byte x509.Certificate.Raw()
		pemBlock := pem.Block{
			Type:  pemBlockCertificateType,
			Bytes: certData,
		}

		return string(pem.EncodeToMemory(&pemBlock)), nil
	case *x509.Certificate:
		pemBlock := pem.Block{
			Type:  pemBlockCertificateType,
			Bytes: certData.Raw,
		}

		return string(pem.EncodeToMemory(&pemBlock)), nil
	default:
		return "", fmt.Errorf("unsupported type in pem conversion: %T", certData)
	}
}

// ConvertX509Cert2PEM uses direct types. Since the type validation is there it
// does not return an error. Errors can be handled using the CSR validation.
func ConvertX509Cert2PEM(cert *x509.Certificate) string {
	pemBlock := pem.Block{
		Type:  pemBlockCertificateType,
		Bytes: cert.Raw,
	}

	return string(pem.EncodeToMemory(&pemBlock))
}

// ConvertX509CSR2PEM uses direct types. Since the type validation is there it
// does not return an error. Errors can be handled using the CSR validation.
func ConvertX509CSR2PEM(cert *x509.CertificateRequest) string {
	pemBlock := pem.Block{
		Type:  pemBlockCertificateRequestType,
		Bytes: cert.Raw,
	}

	return string(pem.EncodeToMemory(&pemBlock))
}

// DecodeAndParseCSRfromBytes transforms the csr in PEM format
// to the x509 certificate type from the x509 package.
func DecodeAndParseCSRfromBytes(csrPEM []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != pemBlockCertificateRequestType {
		return nil, errors.New("failed decoding csr")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse csr: %w", err)
	}

	return csr, nil
}

// ConvertPrivateKeyToPEM investigates the (valid) type
// and transforms the output to a PEMstring
//
// Deprecated: input any should be replace to avoid type errors.
func ConvertPrivateKeyToPEM(input any) (string, error) {
	var pemBlock *pem.Block
	// TODO(mirno) improve intelligence of function and use tests/benchmarks to improve
	switch key := input.(type) {
	case *rsa.PrivateKey:
		derEncodedKey := x509.MarshalPKCS1PrivateKey(key)
		pemBlock = &pem.Block{
			Type:  pemBlockCertificateRSAPKEYType,
			Bytes: derEncodedKey,
		}
	case *ecdsa.PrivateKey:
		derEncodedKey, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return "", fmt.Errorf("unable to marshal ecdsa key: %w", err)
		}

		pemBlock = &pem.Block{
			Type:  pemBlockCertificateECDSAPKEYType,
			Bytes: derEncodedKey,
		}
	case []byte:
		if pKey, err := x509.ParsePKCS1PrivateKey(key); err == nil {
			pemBlock = &pem.Block{
				Type:  pemBlockCertificateRSAPKEYType,
				Bytes: x509.MarshalPKCS1PrivateKey(pKey),
			}
		} else if pKey, err := x509.ParseECPrivateKey(key); err == nil {
			marshelledKey, err := x509.MarshalECPrivateKey(pKey)
			if err != nil {
				return "", fmt.Errorf("unable to unmarshall ecdsa key: %w", err)
			}

			pemBlock = &pem.Block{
				Type:  pemBlockCertificateECDSAPKEYType,
				Bytes: marshelledKey,
			}
		} else {
			return "", errors.New("unable to parse any of the ByteTypes")
		}
	default:
		return "", fmt.Errorf("unsopported private key type for conversion: %T", key)
	}

	pemPrivateKey := pem.EncodeToMemory(pemBlock)

	return string(pemPrivateKey), nil
}

// ConvertPemCSR2x509Request converts the PEM CSR
// to the x509 CertificateRequest type from the x509 package.
func ConvertPemCSR2x509Request(pemData string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("failed to decode csr pem data")
	}

	x509Request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse csr: %w", err)
	}

	return x509Request, nil
}

// ConvertPemCER2x509Cert converts the PEM certificate
// to the x509 Certificate type from the x509 package.
func ConvertPemCER2x509Cert(pemData string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("failed to decode csr pem data")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse csr: %w", err)
	}

	return cert, nil
}

// ConvertDERCSR2PEMCSR converts the CSRDER output
// (x509.CreateCertificateRequest) to PEMstring format.
func ConvertDERCSR2PEMCSR(csrDER []byte) (string, error) {
	// Convert DER to PEM
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  pemBlockCertificateRequestType,
		Bytes: csrDER,
	})

	if csrPEM == nil {
		return "", errors.New("failed to encode csr to pem")
	}

	// Convert to string if needed
	csrPEMString := string(csrPEM)

	return csrPEMString, nil
}

// DecodeAndParseCSR decoded CSR in byte format to the x509.CertificateRequest
// format
func DecodeAndParseCSR(csrDER []byte) (*x509.CertificateRequest, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("unable to parse CSR: %w", err)
	}

	return csr, nil
}

// GenerateRSACertificate is a supportive function to generate a RSA certificate
// pem + key without ca.
func (conf *SigningConfig) GenerateRSACertificate() (pemCertificateString, pemPrivateKeyString string, err error) { //nolint:nonamedreturns // linter loop requesting named returns, inflicting with the nonamedreturns linter
	priv, err := rsa.GenerateKey(rand.Reader, conf.BitSize)
	if err != nil {
		return "", "", errors.Join(ErrKeyGeneration, err)
	}

	// Define time stamps
	noteBefore := time.Now()
	noteAfter := noteBefore.Add(time.Duration(time.Now().Year())) // Add a year from now.

	// Generate serialNumber
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), BitSize)) // generate serial
	if err != nil {
		return "", "", errors.Join(ErrSerialGeneration, err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         conf.CommonName,
			Country:            []string{conf.CountryName},
			Locality:           []string{conf.Locality},
			Organization:       []string{conf.Organization},
			OrganizationalUnit: []string{conf.OrganizationalUnit},
		},
		NotBefore: noteBefore,
		NotAfter:  noteAfter,

		// KeyUsage: ,
		// ExtKeyUsage: ,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	if err != nil {
		return "", "", errors.Join(ErrCertGeneration, err)
	}

	pemBlock := pem.Block{
		Type:  pemBlockCertificateType,
		Bytes: derBytes,
	}
	pemCertificateString = string(pem.EncodeToMemory(&pemBlock))

	derEncodedKey := x509.MarshalPKCS1PrivateKey(priv)
	pemBlock = pem.Block{
		Type:  pemBlockCertificateRSAPKEYType,
		Bytes: derEncodedKey,
	}
	pemPrivateKeyString = string(pem.EncodeToMemory(&pemBlock))

	return pemCertificateString, pemPrivateKeyString, nil
}
