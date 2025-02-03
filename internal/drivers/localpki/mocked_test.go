package localpki_test

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"homelab-pki/internal/drivers/localpki"
	"homelab-pki/internal/testdata"
)

var ErrIOReader = errors.New("mocked error")

type mockReaderDirectOverwrite struct{}

func (*mockReaderDirectOverwrite) Read(_ []byte) (int, error) {
	return 0, ErrIOReader
}

func TestMockedGeneratorWithNil(t *testing.T) {
	t.Parallel()

	mockedGenerator := new(testdata.MockedIDGenerator)
	mockedGenerator.On("NewUUID").Return(uuid.Nil, nil)

	provider, err := localpki.NewInMemoryCertificatesProvider(rand.Reader, localpki.RootCACommonName, localpki.WithIDGenerator(mockedGenerator))
	require.NoError(t, err)

	_, err = provider.CreateCertificate(context.Background(), generatex509CSR(t, "example.example.com", nil))
	require.ErrorIs(t, err, localpki.ErrIDEmpty)
}

func TestMockedGeneratorWithStaticID(t *testing.T) {
	t.Parallel()

	mockedGenerator := new(testdata.MockedIDGenerator)
	mockedGenerator.On("NewUUID").Return(uuid.NewMD5(uuid.NameSpaceDNS, []byte("example.com")), nil)

	provider, err := localpki.NewInMemoryCertificatesProvider(rand.Reader, localpki.RootCACommonName, localpki.WithIDGenerator(mockedGenerator))
	require.NoError(t, err)

	cert, err := provider.CreateCertificate(context.Background(), generatex509CSR(t, "example.example.com", nil))
	require.NoError(t, err)
	_, err = provider.CreateCertificate(context.Background(), generatex509CSR(t, "example.example.com", nil))
	require.ErrorIs(t, err, localpki.ErrIDTaken)

	_, err = provider.RenewCertificate(context.Background(), cert.ID, generatex509CSR(t, "example.example.com", nil))
	require.ErrorIs(t, err, localpki.ErrIDTaken)
}

func TestUUIDError(t *testing.T) {
	t.Parallel()

	errGeneration := errors.New("uuid generation error")

	mockedGenerator := new(testdata.MockedIDGenerator)
	mockedGenerator.On("NewUUID").Return(uuid.Nil, errGeneration)

	provider, err := localpki.NewInMemoryCertificatesProvider(rand.Reader, localpki.RootCACommonName, localpki.WithIDGenerator(mockedGenerator))
	require.NoError(t, err)

	_, err = provider.CreateCertificate(context.Background(), generatex509CSR(t, "example.example.com", nil))
	require.ErrorIs(t, err, errGeneration)
}

func TestBrokenIOReader2(t *testing.T) {
	t.Parallel()

	mockReader := &mockReaderDirectOverwrite{}

	_, err := localpki.NewInMemoryCertificatesProvider(mockReader, localpki.RootCACommonName)
	require.ErrorIs(t, err, localpki.ErrKeyGeneration)
}
