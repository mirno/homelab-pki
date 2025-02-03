package certificates

const (
	// RSA defines a constant of the type EncryptionAlgo
	RSA EncryptionAlgo = "RSA"
	// ECDSA defines a constant of the type EncryptionAlgo
	ECDSA EncryptionAlgo = "ECDSA"
)

// EncryptionAlgo defines values for encryptionType
type EncryptionAlgo string

// CSRGenerator is an interface
// supporting generation of CSR based on the SigningConfig entity
// returning both csr and privatekey
type CSRGenerator interface {
	GenerateCSR(conf SigningConfig) (csr, privateKey []byte, err error)
}

// CSRVerifier is an interface
// supporting the verification of CSR's based
// on the VerificationConfig
type CSRVerifier interface {
	VerifyCSR(csr []byte, conf VerificationConfig) (bool, error)
}

// SigningConfig is an entity which allows json unmarshalling
// into the struct.
// Containing the properties of a Certificate Signing Request (CSR)
type SigningConfig struct {
	CommonName          string         `json:"commonName"`
	CountryName         string         `json:"countryName"`
	State               string         `json:"state"`
	Locality            string         `json:"locality"`
	Organization        string         `json:"organization"`
	OrganizationalUnit  string         `json:"organizationalUnit"`
	EncryptionAlgorithm EncryptionAlgo `json:"encryptionAlgorithm"`
	BitSize             int            `json:"bitSize"`
}

// VerificationConfig defines the properties
// to verify if the original signing config complies
// with the VerificationConfig struct
type VerificationConfig struct {
	BitSize int `json:"bitSize"`
}
