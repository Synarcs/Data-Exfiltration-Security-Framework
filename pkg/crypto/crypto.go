package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/a5i/pkcs7"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/initca"
)

const (
	KERNEL_BPF_CRYPTO_PATH = "keys" // used for kernel crypto security over keyrings ensuring security over injected kernel programs
	keySize                = 1 << 12
	privateKey             = KERNEL_BPF_CRYPTO_PATH + "/private.pem"
	certFile               = KERNEL_BPF_CRYPTO_PATH + "/cert.pem"
	certDERFile            = KERNEL_BPF_CRYPTO_PATH + "/cert.der"
	certPkcs7File          = KERNEL_BPF_CRYPTO_PATH + "/cert.p7b"
	validityDays           = 365
)

// savePEMKey saves an RSA private key in PEM format
func savePEMKey(filename string, key *rsa.PrivateKey) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	return pem.Encode(file, pemBlock)
}

func bigInt() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	return n
}

// save the self sign cert for the agent
func savePEMCert(filename string, certDER []byte) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}

	return pem.Encode(file, pemBlock)
}

// generateSelfSignedCert creates a self-signed X.509 certificate using CFSSL
func generateSelfSignedCert(privKey *rsa.PrivateKey) ([]byte, []byte, error) {
	req := &csr.CertificateRequest{
		CN: "dnsSecurity.bleed.io",
		KeyRequest: &csr.KeyRequest{
			A: "rsa",
			S: keySize,
		},
	}

	_, _, err := csr.ParseRequest(req)
	if err != nil {
		return nil, nil, err
	}

	certPEM, _, _, err := initca.New(req)
	if err != nil {
		return nil, nil, err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode PEM certificate")
	}

	certDER, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return certPEM, certDER.Raw, nil
}

// convertToPKCS7 converts a DER-encoded certificate to PKCS#7 format
// kernel uses pkcs7 as keyring for LSM from over every kernel module to be injected in kernel to bpf load lsm security hooks to verify the security of the BPF-Loader kernel code
func convertToPKCS7(certDER []byte, outputFile string) error {
	// Parse the certificate from DER format
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %v", err)
	}

	degenerateCert, err := pkcs7.DegenerateCertificate(cert.Raw)
	if err != nil {
		fmt.Println("Error creating degenerate certificate:", err)
		return err
	}

	degenerateCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PKCS7",
		Bytes: degenerateCert,
	})

	// Store the pkcs7 cert on disk
	if err := os.WriteFile(outputFile, degenerateCertPEM, 0644); err != nil {
		return err
	}
	return nil
}

func GenerateCryptoDir() error {
	if err := os.MkdirAll(KERNEL_BPF_CRYPTO_PATH, 0777); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil
		}
		return err
	}

	// generate the private key
	privKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		fmt.Println("Error generating private key:", err)
		return err
	}

	if err := savePEMKey(privateKey, privKey); err != nil {
		fmt.Println("Error saving private key:", err)
		return err
	}

	certPEM, certDER, err := generateSelfSignedCert(privKey)
	if err != nil {
		fmt.Println("Error generating certificate:", err)
		return err
	}

	// Save certificate in PEM format
	if err := savePEMCert(certFile, certPEM); err != nil {
		fmt.Println("Error saving certificate:", err)
		return err
	}

	// Convert to PKCS#7 for kernel keyring verifier
	if err := convertToPKCS7(certDER, certPkcs7File); err != nil {
		log.Println("Error converting to PKCS#7:", err.Error())
		return err
	}

	log.Println("Generate the eBPF Node Agent Inject Security Private Key stored at ", privateKey)
	log.Println("Generate the eBPF Node Agent Inject Security Cert stored at ", certFile)
	log.Println("Generate the eBPF Node Agent Inject Security Cert stored at ", certFile)

	return nil
}

func CleanCryptoDir() error {
	return os.RemoveAll(KERNEL_BPF_CRYPTO_PATH)
}
