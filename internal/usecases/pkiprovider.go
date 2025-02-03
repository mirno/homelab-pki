package usecases

import (
	"context"
	"crypto/x509"
	"homelab-pki/internal/entities"
)

type PKIProvider interface {
	GetCertificate(ctx context.Context, id string) (*entities.CertificateStore, error)
	ListCertificates(ctx context.Context, options ...CertificateOption) (map[string]*entities.CertificateStore, error)
	CreateCertificate(ctx context.Context, csr *x509.CertificateRequest, options ...CertificateOption) (*entities.CertificateStore, error)
	RenewCertificate(ctx context.Context, id string, csr *x509.CertificateRequest, options ...CertificateOption) (*entities.CertificateStore, error)
	RevokeCertificate(ctx context.Context, id string, options ...CertificateOption) (*entities.CertificateStore, error)
}
