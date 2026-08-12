package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// GenerateHostKeyPEM returns a fresh ed25519 host key in OpenSSH PEM form, for
// callers that persist the key themselves (shared custody, Phase 42).
func GenerateHostKeyPEM() ([]byte, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(block), nil
}

// HostKeyFromPEM parses a host key that a custodian handed back.
func HostKeyFromPEM(pem []byte) (ssh.Signer, error) {
	signer, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		return nil, fmt.Errorf("parse host key: %w", err)
	}
	return signer, nil
}
