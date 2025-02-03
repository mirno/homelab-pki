package entities

import (
	"crypto/x509"
	"time"
)

const (
	EnvironmentDevelopment Environment = "D"
	EnvironmentTest        Environment = "T"
	EnvironmentAcceptance  Environment = "A"
	EnvironmentProduction  Environment = "P"

	Active  Status = "Active"
	Expired Status = "Expired"
	Renewed Status = "Renewed"
	Revoked Status = "Revoked"
)

// RootCAIssuerCN defines the issuer common name
type RootCAIssuerCN string

type Status string

type Environment string

type CertificateStore struct {
	ID         string `json:"id"`
	CommonName string `json:"commonName,omitempty"`
	SerialHex  string `json:"serialHex,omitempty"`

	Status      Status      `json:"status,omitempty"`
	Environment Environment `json:"environment,omitempty"`

	StartDate *time.Time `json:"startDate,omitempty"`
	EndDate   *time.Time `json:"endDate,omitempty"`

	Certificate *x509.Certificate `json:"certificate,omitempty"`
}
