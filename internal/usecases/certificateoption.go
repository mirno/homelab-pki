package usecases

import "crypto/x509/pkix"

type CertificateOption func(*CertificateOptions)

type CertificateOptions struct {
	Reason      string
	Environment string
	Subject     pkix.Name
	Status      string
	Sans        []string
}

func NewCertificateOptions(options ...CertificateOption) *CertificateOptions {
	certConfig := &CertificateOptions{}

	for _, option := range options {
		option(certConfig)
	}

	return certConfig
}

func WithCommonName(commonName string) CertificateOption {
	return func(option *CertificateOptions) {
		option.Subject.CommonName = commonName
	}

}
