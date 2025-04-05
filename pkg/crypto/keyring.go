package crypto

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path"

	"golang.org/x/sys/unix"
)

func VerifyKeyRinggenerated() (string, error) {
	file := path.Join(CERT_DER_FILE)
	_, err := os.Stat(file)

	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Println("File does not exist")
		} else {
			log.Println("Runtime permission error please check the file stats and permission", err)
		}
		return "", err
	}

	return file, err
}

const (
	KEYCTL_JOIN_SESSION_KEYRING = 1
	KEYCTL_LINK                 = 8
)

func AddKernelKeyRing(config *NodeAgentCryptoConfig) error {

	if DUMP_CA_LSM {
		VerifyKeyRinggenerated()
	}

	// create a new session keyring ID in the kernel, the keyring should be ephemeral and lived only until the node agent is alive in kernel
	sessionID, err := unix.KeyctlInt(KEYCTL_JOIN_SESSION_KEYRING, 0, 0, 0, 0)
	if err != nil {
		log.Fatalf("Failed to create new session keyring: %v", err)
	}

	log.Printf("Created session keyring with ID: %d", sessionID)

	if err != nil {
		return err
	}

	if err != nil {
		log.Fatalf("Failed to generate ECDH key: %v", err)
	}

	val := config.Cert.Raw

	log.Println("the size of the keyring Der file for encrypt x509 cert is ", val[:1], len(val))

	keyDesc := ".ebpf:signing:x509"

	// Add the asymmetric key to the session keyring
	keyID, err := unix.AddKey("asymmetric", keyDesc, val, unix.KEY_SPEC_SESSION_KEYRING)
	if err != nil {
		log.Fatalf("Failed to add key: %v", err)
	}
	log.Printf("Key added with ID: %d", keyID)

	// Create a new keyring in the session keyring
	keyringID, err := unix.AddKey("keyring", "_ebpf", nil, unix.KEY_SPEC_SESSION_KEYRING)
	if err != nil {
		log.Fatalf("Failed to create keyring: %v", err)
	}
	fmt.Printf("Created keyring with ID: %d\n", keyringID)

	// Link the key to the keyring one used by the userspace laoder, and second via the kernel BPF LSM hooks before all the kernel eBPF hooks are injected inside kernell network stack, raw tracepoint and kprobes
	ret, err := unix.KeyctlInt(unix.KEYCTL_LINK, keyID, keyringID, 0, 0)
	if err != nil {
		log.Fatalf("Failed to link key: %v", err)
	}
	if ret < 0 {
		log.Fatalf("Failed to link key: %v", err)
	}
	fmt.Printf("Linked key %d to keyring %d\n", keyID, keyringID)
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
			log.Printf("Warning: failed to clear _ebpf keyring: %v", err)
		}

		// Unlink the keyring from session
		_, err = unix.KeyctlInt(unix.KEYCTL_UNLINK, ebpfKeyringID, sessionID, 0, 0)
		if err != nil {
			log.Printf("Warning: failed to unlink _ebpf keyring: %v", err)
		}
	}

	// Find and revoke the asymmetric key
	keyID, err := unix.KeyctlSearch(sessionID, "asymmetric", ".ebpf:signing:x509", 0)
	if err == nil {
		// Revoke the key for the parent sign
		_, err = unix.KeyctlInt(unix.KEYCTL_REVOKE, keyID, 0, 0, 0)
		if err != nil {
			log.Printf("Warning: failed to revoke key: %v", err)
		}

		// Unlink the key from session
		_, err = unix.KeyctlInt(unix.KEYCTL_UNLINK, keyID, sessionID, 0, 0)
		if err != nil {
			log.Printf("Warning: failed to unlink key: %v", err)
		}
	}

	// Finally, clear the session keyring (removes any remaining items)
	_, err = unix.KeyctlInt(unix.KEYCTL_CLEAR, sessionID, 0, 0, 0)
	if err != nil {
		return fmt.Errorf("failed to clear session keyring: %v", err)
	}

	log.Println("Successfully cleaned up kernel session keyring", sessionID)
	return nil
}
