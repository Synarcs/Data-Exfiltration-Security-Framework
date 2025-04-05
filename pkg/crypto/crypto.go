package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"path"

	"github.com/cilium/ebpf/asm"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/initca"
	"go.mozilla.org/pkcs7"
)

const (
	KEY_DIR       = "keys"
	PRIVATE_KEY   = KEY_DIR + "/private.key"
	CERT_FILE     = KEY_DIR + "/cert.pem"
	CERT_DER_FILE = KEY_DIR + "/cert.der"
	VALIDITY_DAYS = 365
	KEY_SIZE      = 256
	CERT_SUBJECT  = "DNSObelisk Security Framework"
	CUSTOM_OID    = "1.3.6.1.4.1.2312.19.1"
)

const (
	MAX_DATA_SIZE = 1024 * 1024
	DUMP_CA_LSM   = true
)

type NodeAgentCryptoConfig struct {
	Cert    *x509.Certificate
	Key     *ecdsa.PrivateKey
	KeySize int
}

type CompiledProgInfo struct {
	Data    [MAX_DATA_SIZE]byte
	DataLen int
	Sig     [4096]byte
	SigLen  int
}

type ModifiedJitProgInfo struct {
	Data    [MAX_DATA_SIZE]byte
	DataLen int
	Sig     [4096]byte
	SigLen  int
	Prog    asm.Instruction
}

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
func generateSelfSignedCert() (*x509.Certificate, *ecdsa.PrivateKey, error) {

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

	cert, _, privateKey, err := initca.New(req)
	if err != nil {
		return nil, nil, err
	}

	if DUMP_CA_LSM {
		if err := savePrivateKeyToPEM(privateKey, PRIVATE_KEY); err != nil {
			log.Println("Error saving private key:", err)
		}
		if err := savePEMCert(cert, CERT_FILE); err != nil {
			log.Println("Error saving certificate:", err)
		}
	}

	block, _ := pem.Decode(cert)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, err
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	pblock, _ := pem.Decode(privateKey)
	if privateKey == nil || pblock.Type != "EC PRIVATE KEY" {
		log.Fatal("failed to decode key PEM", block)
	}

	pKey, err := x509.ParseECPrivateKey(pblock.Bytes)
	if err != nil {
		log.Fatalf("failed to parse key: %v", err)
	}

	return certificate, pKey, nil
}

// Save the private key in PEM format
func savePrivateKeyToPEM(privateKey []byte, outputFile string) error {
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKey,
	}

	// encode in memory for safety and speed
	pemData := pem.EncodeToMemory(pemBlock)
	return os.WriteFile(outputFile, pemData, 0600)
}

func savePEMCert(certPEM []byte, filename string) error {
	return os.WriteFile(filename, certPEM, 0644)
}

func GenerateBPFCert() (*NodeAgentCryptoConfig, error) {
	// Ensure key directory exists
	if err := createKeyDir(); err != nil {
		return nil, err
	}

	// Generate certificate and key
	cert, pKey, err := generateSelfSignedCert()
	if err != nil {
		return nil, err
	}

	log.Println("Generated BPF Signing Certificate and stored in", KEY_DIR)
	return &NodeAgentCryptoConfig{
		Cert:    cert,
		Key:     pKey,
		KeySize: KEY_SIZE,
	}, nil
}

func verifyPkcs7Signature(signPayload []byte, data []byte) error {
	var pemBuff bytes.Buffer
	pem.Encode(&pemBuff, &pem.Block{Type: "PKCS7", Bytes: signPayload})
	p7, err := pkcs7.Parse(signPayload)
	if err != nil {
		return fmt.Errorf("Cannot parse our signed data: %s", err)
	}

	// since the signature was detached, reattach the content here
	p7.Content = data

	if !bytes.Equal(data, p7.Content) {
		return fmt.Errorf("Our content was not in the parsed data:\n\t Expected: %s\n\tActual: %s", data, p7.Content)
	}

	if err = p7.Verify(); err != nil {
		err = fmt.Errorf("Cannot verify our signed data: %s", err)
		return err
	}

	return nil
}

func computeOriginalSignature(data []byte, cryptoConfig *NodeAgentCryptoConfig, org *CompiledProgInfo) error {

	signedData, err := pkcs7.NewSignedData(data)
	if err != nil {
		log.Fatalf("NewSignedData failed: %v", err)
	}

	err = signedData.AddSigner(cryptoConfig.Cert, cryptoConfig.Key, pkcs7.SignerInfoConfig{})
	if err != nil {
		log.Fatalf("AddSigner failed: %v", err)
	}
	signedData.Detach()

	p7Bytes, err := signedData.Finish()
	if err != nil {
		log.Fatalf("Finish failed: %v", err)
	}

	if len(p7Bytes) > len(org.Sig) {
		return fmt.Errorf("signature too large for buffer (size: %d, max: %d)", len(p7Bytes), len(org.Sig))
	}

	copy(org.Sig[:], p7Bytes)
	org.SigLen = len(p7Bytes)

	if err := verifyPkcs7Signature(p7Bytes, data); err != nil {
		log.Println("Signature verification failed")
		return err
	}

	return nil
}

func ComputeRawBpfByteOriginalSig(basePath, progPath string, cryptoConfig *NodeAgentCryptoConfig) error {
	progData, err := os.ReadFile(path.Join(basePath, progPath))
	if err != nil {
		return err
	}

	if len(progData) == 0 {
		return fmt.Errorf("empty program data")
	}

	var org CompiledProgInfo

	copy(org.Data[:], progData)
	org.DataLen = len(progData)

	if err := computeOriginalSignature(org.Data[:org.DataLen], cryptoConfig, &org); err != nil {
		log.Println("Error computing original signature or sig verification failed for prog :", progPath, err)
		return err
	}

	log.Println("Original signature computed successfully for prog:", progPath, hex.EncodeToString(cryptoConfig.Cert.Signature))
	return nil
}

func computeModifiedSignature(instructions []asm.Instructions,
	origSig []byte, privateKeyPath, certPath string, modSig *ModifiedJitProgInfo) error {
	return nil
}
