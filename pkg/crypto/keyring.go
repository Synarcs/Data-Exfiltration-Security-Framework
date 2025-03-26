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

func GetSignKeySize() ([]byte, int64, error) {
	_, err := VerifyKeyRinggenerated()
	if err != nil {
		log.Println("the required keyring not found to sign loaded progs in kernel space")
		return nil, -1, err
	}

	fd, err := os.Open(CERT_DER_FILE)

	if err != nil {
		return nil, -1, err // perfmission or other errors
	}

	defer fd.Close()
	fileInfo, _ := fd.Stat()

	fileSize := fileInfo.Size()

	if fileSize > (1 << 12) {
		// kernel usually dont allow the keyrings to have more than 4096 bytes
		return nil, -1, fmt.Errorf("the size of the file is too large to be loaded in kernel keyring")
	}

	var keyBuff []byte = make([]byte, fileSize)
	_, err = fd.Read(keyBuff)

	if err != nil {
		return nil, -1, err
	}

	return keyBuff, fileSize, nil
}

const (
	KEYCTL_JOIN_SESSION_KEYRING = 1
	KEYCTL_LINK                 = 8
)

func AddKernelKeyRing() error {
	// create a new session keyring ID in the kernel
	sessionID, err := unix.KeyctlInt(KEYCTL_JOIN_SESSION_KEYRING, 0, 0, 0, 0)
	if err != nil {
		log.Fatalf("Failed to create new session keyring: %v", err)
	}

	log.Printf("Created session keyring with ID: %d", sessionID)
	keyBuff, keySize, err := GetSignKeySize()
	if err != nil {
		return err
	}
	log.Println("the size of the keyring Der file for encrypt x509 cert is ", keyBuff[:1], keySize)

	keyDesc := ".ebpf:signing:x509"

	// Add the asymmetric key to the session keyring
	keyID, err := unix.AddKey("asymmetric", keyDesc, keyBuff, unix.KEY_SPEC_SESSION_KEYRING)
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

	// Link the key to the keyring one used by the userspace laoder, and second via the kernel BPF LSM hooks before all the kernel eBPF hooks are injected inside kernell network stack
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

	log.Printf("Successfully cleaned up kernel keyring")
	return nil
}
