package auth

import (
	"fmt"
	"os"

	ssh "golang.org/x/crypto/ssh"
)

// LoadHostKey loads the SSH host private key from the specified path.
func LoadHostKey(path string) (ssh.Signer, error) {
	privateBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load SSH private key: %w", err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH private key: %w", err)
	}
	return private, nil
}
