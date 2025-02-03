package localpki

import (
	"crypto/x509"
	"io"
)

// Option defines with options for the InMemoryCertificatesProvider
type Option func(*ProviderConfig)

// ProviderConfig holds the configuration for InMemoryCertificatesProvider.
type ProviderConfig struct {
	random         io.Reader
	idGenerator    IDGeneratorFN
	caCertTemplate *x509.Certificate
}

// WithIDGenerator allows a more scalable version to generate ID's.
func WithIDGenerator(idGenerator IDGenerator) Option {
	return func(config *ProviderConfig) {
		config.idGenerator = idGenerator.NewUUID
	}
}

// WithOverRideCATemplate overrides the default CA template for custom ca
// config. It's not recommended to use this optional functions to tamper with the default config since it changes
// the behavior of the cert authority. Which requires certain properties
// to function as expected.
func WithOverRideCATemplate(template *x509.Certificate) Option {
	return func(config *ProviderConfig) {
		config.caCertTemplate = template
	}
}
