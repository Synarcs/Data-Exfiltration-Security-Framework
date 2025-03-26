package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/initca"
)

const (
	KEY_DIR       = "keys"
	PRIVATE_KEY   = KEY_DIR + "/private.key"
	CERT_FILE     = KEY_DIR + "/cert.pem"
	CERT_DER_FILE = KEY_DIR + "/cert.der"
	VALIDITY_DAYS = 365
	KEY_SIZE      = 1 << 8
	CERT_SUBJECT  = "BPF Program Signing Key"
	CUSTOM_OID    = "1.3.6.1.4.1.2312.19.1"
)

/*
Clean older crypto dir if any exists and ensure the keys are always ephemeral
*/
func CleanOlderCrypoDir() error {
	if err := os.RemoveAll(KEY_DIR); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	return nil
}

func createKeyDir() error {
	return os.MkdirAll(KEY_DIR, 0700)
}

// Generate a self-signed certificate for signing eBPF programs
func generateSelfSignedCert() ([]byte, []byte, []byte, error) {

	// for 256 key anway the curve is P256 which kerne keyring suport and also defualt in ECDSA for tls 1.2
	key := &csr.KeyRequest{
		A: "ecdsa",
		S: KEY_SIZE,
	}

	// Define CSR template
	req := &csr.CertificateRequest{
		CN:         CERT_SUBJECT,
		KeyRequest: key,
		Names: []csr.Name{
			{O: "BPF Security"},
		},
		CA: &csr.CAConfig{
			Expiry: fmt.Sprintf("%dh", VALIDITY_DAYS*24),
		},
	}

	certPEM, _, privateKey, err := initca.New(req)
	if err != nil {
		return nil, nil, nil, err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, nil, fmt.Errorf("failed to decode PEM certificate")
	}

	certDER, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, nil, err
	}

	return certPEM, certDER.Raw, privateKey, nil
}

// Save the private key in PEM format
func savePrivateKeyToPEM(privateKey []byte, outputFile string) error {
	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKey,
	}

	pemData := pem.EncodeToMemory(pemBlock)
	return os.WriteFile(outputFile, pemData, 0600)
}

func savePEMCert(filename string, certPEM []byte) error {
	return os.WriteFile(filename, certPEM, 0644)
}

func saveDerCert(filename string, certDER []byte) error {
	return os.WriteFile(filename, certDER, 0644)
}

func GenerateBPFCert() error {
	// Ensure key directory exists
	if err := createKeyDir(); err != nil {
		return err
	}

	// Generate certificate and key
	certPEM, certDER, key, err := generateSelfSignedCert()
	if err != nil {
		return err
	}

	// Save private key
	if err := savePrivateKeyToPEM(key, PRIVATE_KEY); err != nil {
		log.Println("Error saving private key:", err)
		return err
	}

	// Save certificate in PEM format
	if err := savePEMCert(CERT_FILE, certPEM); err != nil {
		log.Println("Error saving certificate:", err)
		return err
	}

	// Save certificate in DER format
	if err := saveDerCert(CERT_DER_FILE, certDER); err != nil {
		log.Println("Error saving DER certificate:", err)
		return err
	}

	log.Println("Generated BPF Signing Certificate and stored in", KEY_DIR)
	return nil
}
