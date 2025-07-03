/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package crypto

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events"
	controllerrpc "github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/rpc/controller"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
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
	Data    [1024 * 1024]byte
	DataLen uint32
	Sig     [4096]byte
	SigLen  uint32
}

type ModifiedJitProgInfo struct {
	Data    [MAX_DATA_SIZE]byte
	DataLen uint32
	Sig     [4096]byte
	SigLen  uint32
	Prog    asm.Instruction
}

type ModifiedSig struct {
	Sig    [4096]byte
	SigLen uint32
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
			utils.Log("Error saving private key:", err)
		}
		if err := savePEMCert(cert, CERT_FILE); err != nil {
			utils.Log("Error saving certificate:", err)
		}
	}

	block, _ := pem.Decode(cert)
	if block == nil || block.Type != "CERTIFICATE" {
		utils.Log("Error decoding certificate: the pem is malformed", err)
		if utils.DEBUG {
			for hName, val := range block.Headers {
				utils.Log("Header:", hName, val)
			}
		}
		return nil, nil, err
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		utils.Log("Error parsing certificate:", err)
		return nil, nil, err
	}

	pblock, _ := pem.Decode(privateKey)
	if privateKey == nil || pblock.Type != "EC PRIVATE KEY" {
		utils.Logger.Fatal("failed to decode key PEM", block)
	}

	pKey, err := x509.ParseECPrivateKey(pblock.Bytes)
	if err != nil {
		utils.Logger.Fatalf("failed to parse key: %v", err)
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

	utils.Log("Generated BPF Signing Certificate and stored in", KEY_DIR)
	utils.Log("Generate global cert for node agent with injected in kernel keyring use to sign ebpf programs with signature", hex.EncodeToString(cert.Signature))

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

func pkcs7Sign(data []byte, cryptoConfig *NodeAgentCryptoConfig) ([]byte, error) {

	signedData, err := pkcs7.NewSignedData(data)
	if err != nil {
		return nil, err
	}

	err = signedData.AddSigner(cryptoConfig.Cert, cryptoConfig.Key, pkcs7.SignerInfoConfig{})
	if err != nil {
		return nil, err
	}
	signedData.Detach()

	p7Bytes, err := signedData.Finish()
	if err != nil {
		return nil, err
	}

	return p7Bytes, nil
}

func (lsm *CryptoBpfLsm) computeOriginalSignature(data []byte, org *CompiledProgInfo) error {

	p7Bytes, err := pkcs7Sign(data, lsm.AgentCryptoConfig)

	if err != nil {
		return err
	}

	if len(p7Bytes) > len(org.Sig) {
		return fmt.Errorf("signature too large for buffer (size: %d, max: %d)", len(p7Bytes), len(org.Sig))
	}

	copy(org.Sig[:], p7Bytes)
	org.SigLen = uint32(len(p7Bytes))

	if err := verifyPkcs7Signature(p7Bytes, data); err != nil {
		utils.Log("Signature verification failed")
		return err
	}

	return nil
}

func (lsm *CryptoBpfLsm) computeModifiedSignature(instructions asm.Instructions,
	origSig []byte, modSig *ModifiedJitProgInfo) error {

	var buff bytes.Buffer
	instructions.Marshal(&buff, binary.LittleEndian)
	p7Bytes, err := pkcs7Sign(buff.Bytes(), lsm.AgentCryptoConfig)

	if err != nil {
		return err
	}

	if len(p7Bytes) > len(modSig.Sig) {
		return fmt.Errorf("signature too large for buffer (size: %d, max: %d)", len(p7Bytes), len(modSig.Sig))
	}

	copy(modSig.Sig[:], p7Bytes)
	modSig.SigLen = uint32(len(p7Bytes))

	if err := verifyPkcs7Signature(p7Bytes, buff.Bytes()); err != nil {
		utils.Log("Signature verification failed")
		return err
	}

	return nil
}

type CryptoBpfLsm struct {
	PinnedMaps                []string
	LsmProgCollection         *ebpf.Collection
	AgentCryptoConfig         *NodeAgentCryptoConfig
	Program                   *ebpf.Program
	Link                      link.Link
	ControllerEnabledZtEnfoce bool
	AgentRpcClient            *controllerrpc.AgentControllerRpcServices
}

var cryptoMaps []string = []string{
	events.EXFIL_SECURITY_KEYRING_MAP,
	events.EXFIL_SECURITY_MODIFIED_SIGNATURE,
	events.EXFIL_SECURITY_KEYRING_MAP,
	events.EXFIL_SECURITY_COMBINED_DATA_MAP,
}

func New(options ...func(*CryptoBpfLsm)) *CryptoBpfLsm {
	cryptoLsm := &CryptoBpfLsm{
		PinnedMaps: cryptoMaps,
	}
	for _, funcOpt := range options {
		funcOpt(cryptoLsm)
	}
	return cryptoLsm
}

func NewCryptoBpfLsmWithLocalCAConfig(ctx context.Context, agentCryptoConfig *NodeAgentCryptoConfig) func(*CryptoBpfLsm) {
	return func(cbl *CryptoBpfLsm) {
		cbl.AgentCryptoConfig = agentCryptoConfig
	}
}

func NewCryptoBpfLsmWithLocalControllerRpcConfig(ctx context.Context,
	controllerEnabledZtEnfoce bool, rpcClient *controllerrpc.AgentControllerRpcServices) func(*CryptoBpfLsm) {
	return func(cbl *CryptoBpfLsm) {
		cbl.AgentRpcClient = rpcClient
		cbl.ControllerEnabledZtEnfoce = controllerEnabledZtEnfoce
	}
}

// this is the global layered bpf prog enforcement for the agent in datapalne request controller to sign the raw bytecode before inject in LSM
func (lsm *CryptoBpfLsm) RequestControllerForBpfProgSign(ebpfProgRaw []byte,
	progInfo *ebpf.ProgramInfo) error {
	// TODO: Ask the controller to sign the required eBPF progs raw bytecode establish first chain of trust
	return nil
}

func (lsm *CryptoBpfLsm) InjectLSMProgsPostSignatureGenerate(ebpfProgRaw []byte,
	ebpfProg *ebpf.ProgramInfo, keyringconfigInfo *KernelCryptoKeyRingIds) error {

	if lsm.ControllerEnabledZtEnfoce {
		return lsm.RequestControllerForBpfProgSign(ebpfProgRaw, ebpfProg)
	}

	var org CompiledProgInfo

	copy(org.Data[:], ebpfProgRaw)
	org.DataLen = uint32(len(ebpfProgRaw))

	if err := lsm.computeOriginalSignature(org.Data[:org.DataLen], &org); err != nil {
		utils.Log("Error computing original signature or sig verification failed for prog :", ebpfProg.Name, err)
		return err
	}

	utils.Log("Populating keyring map with sign key ring id")
	var crypto_kernel_const uint32 = 0

	if err := lsm.LsmProgCollection.Maps[events.EXFIL_SECURITY_KEYRING_MAP].Put(&crypto_kernel_const, &keyringconfigInfo.EbpfSignKeyringId); err != nil {
		utils.Log("Error writing to keyring map", err)
		return err
	}

	insn, err := ebpfProg.Instructions()
	if err != nil {
		return err
	}

	var mod ModifiedJitProgInfo
	if err := lsm.computeModifiedSignature(insn, org.Sig[:org.SigLen], &mod); err != nil {
		utils.Log("Error computing modified signature or sig verification failed for prog :", ebpfProg.Name, err)
		return err
	}

	_ = uint32(lsm.LsmProgCollection.Maps[events.EXFIL_SECURITY_ORIGINAL_PROGRAM].FD())
	_ = uint32(lsm.LsmProgCollection.Maps[events.EXFIL_SECURITY_MODIFIED_SIGNATURE].FD())

	if err := lsm.LsmProgCollection.Maps[events.EXFIL_SECURITY_ORIGINAL_PROGRAM].
		Put(&crypto_kernel_const, &org); err != nil {
		utils.Log("Error writing original program info to map", err)
		return err
	}

	var modSignPayload *ModifiedSig = &ModifiedSig{
		Sig:    mod.Sig,
		SigLen: mod.SigLen,
	}

	if err := lsm.LsmProgCollection.Maps[events.EXFIL_SECURITY_MODIFIED_SIGNATURE].
		Put(&crypto_kernel_const, modSignPayload); err != nil {
		utils.Log("Error writing modified program info to map", err)
		return err
	}

	return nil
}
