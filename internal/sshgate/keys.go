package sshgate

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	gossh "golang.org/x/crypto/ssh"
)

func EnsureKeypair(privatePath string) (publicAuthorizedKey string, err error) {
	if data, readErr := os.ReadFile(privatePath); readErr == nil {
		signer, err := gossh.ParsePrivateKey(data)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(gossh.MarshalAuthorizedKey(signer.PublicKey()))), nil
	}
	if err := os.MkdirAll(filepath.Dir(privatePath), 0700); err != nil {
		return "", err
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	pemBlock, err := gossh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(privatePath, pem.EncodeToMemory(pemBlock), 0600); err != nil {
		return "", err
	}
	signer, err := gossh.NewSignerFromKey(privateKey)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(gossh.MarshalAuthorizedKey(signer.PublicKey()))), nil
}

func LoadSigner(privatePath string) (gossh.Signer, error) {
	data, err := os.ReadFile(privatePath)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	return gossh.ParsePrivateKey(data)
}
