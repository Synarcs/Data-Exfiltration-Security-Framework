/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package crypto

import (
	"errors"
	"fmt"
	"os"
	"path"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"golang.org/x/sys/unix"
)

type KernelCryptoKeyRingIds struct {
	SessionId         uint32
	RootKeyringId     uint32
	EbpfSignKeyringId uint32
}

func VerifyKeyRinggenerated() (string, error) {
	file := path.Join(CERT_FILE)
	_, err := os.Stat(file)

	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			utils.Log("File does not exist")
		} else {
			utils.Log("Runtime permission error please check the file stats and permission", err)
		}
		return "", err
	}

	return file, err
}

func AddKernelKeyRing(config *NodeAgentCryptoConfig) error {
	utils.Log("Configuring the kernel keyring for all prog verification in kernel ")

	if DUMP_CA_LSM {
		VerifyKeyRinggenerated()
	}

	// create a new session keyring ID in the kernel, the keyring should be ephemeral and lived only until the node agent is alive in kernel
	sessionID, err := unix.KeyctlInt(unix.KEYCTL_JOIN_SESSION_KEYRING, 0, 0, 0, 0)
	if err != nil {
		utils.Logger.Fatalf("Failed to create new session keyring: %v", err)
	}

	utils.Log(fmt.Sprintf("Created session keyring with ID: %d", sessionID))

	if err != nil {
		return err
	}

	val := config.Cert.Raw

	utils.Log("the size of the keyring Der file for encrypt x509 cert is ", val[:1], len(val))

	keyDesc := ".ebpf:signing:x509"

	// Add the asymmetric key to the session keyring
	keyID, err := unix.AddKey("asymmetric", keyDesc, val, unix.KEY_SPEC_PROCESS_KEYRING)

	if err != nil {
		utils.Logger.Fatalf("Failed to add key: %v", err)
	}
	utils.Log(fmt.Sprintf("Root key added with ID: %d", keyID))

	// Create a new keyring in the session keyring
	keyringID, err := unix.AddKey("keyring", "_ebpf", nil, unix.KEY_SPEC_SESSION_KEYRING)
	if err != nil {
		utils.Logger.Fatalf("Failed to create keyring: %v", err)
	}
	utils.Log(fmt.Sprintf("Created eBPF prog signer keyring with ID: %d\n", keyringID))

	// Link the key to the keyring one used by the userspace laoder, and second via the kernel BPF LSM hooks before all the kernel eBPF hooks are injected inside kernell network stack, raw tracepoint and kprobes
	ret, err := unix.KeyctlInt(unix.KEYCTL_LINK, keyID, keyringID, 0, 0)
	if err != nil {
		utils.Logger.Fatalf("Failed to link key: %v", err)
	}
	if ret < 0 {
		utils.Logger.Fatalf("Failed to link key: %v", err)
	}
	utils.Log(fmt.Sprintf("Linked key %d to keyring %d\n", keyID, keyringID))
	return nil
}

func CleanupKernelKeyRing() error {
	// Get the session keyring ID
	sessionID, err := unix.KeyctlInt(unix.KEYCTL_GET_KEYRING_ID, unix.KEY_SPEC_SESSION_KEYRING, 0, 0, 0)
	if err != nil {
		return fmt.Errorf("failed to get session keyring ID: %v", err)
	}

	// First, find and clear the _ebpf keyring (leaf)
	ebpfKeyringID, err := unix.KeyctlSearch(sessionID, "keyring", "_ebpf", 0)
	if err == nil {
		// Found the keyring, clear it first (removes all keys inside)
		_, err = unix.KeyctlInt(unix.KEYCTL_CLEAR, ebpfKeyringID, 0, 0, 0)
		if err != nil {
			utils.Logger.Printf("Warning: failed to clear _ebpf keyring: %v", err)
		}

		// Unlink the keyring from session
		_, err = unix.KeyctlInt(unix.KEYCTL_UNLINK, ebpfKeyringID, sessionID, 0, 0)
		if err != nil {
			utils.Logger.Printf("Warning: failed to unlink _ebpf keyring: %v", err)
		}

		utils.Log("Successfully cleaned up ebpfKeyringID session keyring", ebpfKeyringID)
	} else {
		utils.Log("keyring not found for ebpf session keyring")
	}

	// Find and revoke the asymmetric key
	rootKeyId, err := unix.KeyctlSearch(sessionID, "asymmetric", ".ebpf:signing:x509", 0)
	if err == nil {
		// Revoke the key for the parent sign
		_, err = unix.KeyctlInt(unix.KEYCTL_REVOKE, rootKeyId, 0, 0, 0)
		if err != nil {
			utils.Log(fmt.Sprintf("Warning: failed to revoke key: %v", err))
		}

		// Unlink the key from session
		_, err = unix.KeyctlInt(unix.KEYCTL_UNLINK, rootKeyId, sessionID, 0, 0)
		if err != nil {
			utils.Log(fmt.Sprintf("Warning: failed to unlink key: %v", err))
		}
		utils.Log("Successfully cleaned up root session keyring", rootKeyId)
	} else {
		utils.Log("key not found for root session keyring")
	}

	// Finally, clear the session keyring (removes any remaining items)
	_, err = unix.KeyctlInt(unix.KEYCTL_CLEAR, sessionID, 0, 0, 0)
	if err != nil {
		return fmt.Errorf("failed to clear session keyring: %v", err)
	}

	utils.Log("Successfully cleaned up kernel session keyring", sessionID)
	return nil
}

func GetKeyRingSessionId() (int, error) {

	sessionID, err := unix.KeyctlInt(unix.KEYCTL_GET_KEYRING_ID, unix.KEY_SPEC_SESSION_KEYRING, 0, 0, 0)
	if err != nil {
		return -1, fmt.Errorf("failed to get session keyring ID: %v", err)
	}

	return sessionID, nil
}

func GetEbpFProgSignKeyringId() (uint32, error) {

	sessionID, err := GetKeyRingSessionId()
	if err != nil {
		return 0, fmt.Errorf("failed to get session keyring ID: %v", err)
	}

	ebpfKeyringID, err := unix.KeyctlSearch(sessionID, "keyring", "_ebpf", 0)
	if err != nil {
		return 0, fmt.Errorf("failed to get ebpf keyring ID: %v", err)
	}

	return uint32(ebpfKeyringID), nil
}

func GetRootKeyRingId() (uint32, error) {

	sessionID, err := GetKeyRingSessionId()
	if err != nil {
		return 0, fmt.Errorf("failed to get session keyring ID: %v", err)
	}

	keyID, err := unix.KeyctlSearch(sessionID, "asymmetric", ".ebpf:signing:x509", 0)

	if err != nil {
		return 0, fmt.Errorf("failed to get ebpf keyring ID: %v", err)
	}

	return uint32(keyID), nil
}
