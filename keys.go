package main

import (
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func defaultIdentityPaths() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return []string{
		filepath.Join(home, ".ssh", "id_ed25519"),
		filepath.Join(home, ".ssh", "id_rsa"),
	}
}

func resolveIdentityPath(override string) (string, error) {
	if override != "" {
		if _, err := os.Stat(override); err != nil {
			return "", fmt.Errorf("identity %q: %w", override, err)
		}
		return override, nil
	}
	for _, p := range defaultIdentityPaths() {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", errors.New("no SSH key found at ~/.ssh/id_ed25519 or ~/.ssh/id_rsa; pass -i to specify one")
}

func pubkeyPathFor(privatePath string) string {
	return privatePath + ".pub"
}

func readSelfRecipient(identityPath string) (recipientInfo, error) {
	pubPath := pubkeyPathFor(identityPath)
	data, err := os.ReadFile(pubPath)
	if err != nil {
		return recipientInfo{}, fmt.Errorf("read public key %q: %w", pubPath, err)
	}
	return parseSSHRecipient(string(data))
}

func loadIdentity(path string) (age.Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read identity %q: %w", path, err)
	}

	key, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		var pmErr *ssh.PassphraseMissingError
		if !errors.As(err, &pmErr) {
			return nil, fmt.Errorf("parse identity %q: %w", path, err)
		}
		pub, err := loadAuthorizedKey(pubkeyPathFor(path))
		if err != nil {
			return nil, fmt.Errorf("load public key for encrypted identity (need %s): %w", pubkeyPathFor(path), err)
		}
		prompt := fmt.Sprintf("Passphrase for %s: ", path)
		return agessh.NewEncryptedSSHIdentity(pub, data, func() ([]byte, error) {
			return promptPassphrase(prompt)
		})
	}

	switch k := key.(type) {
	case *ed25519.PrivateKey:
		return agessh.NewEd25519Identity(*k)
	case ed25519.PrivateKey:
		return agessh.NewEd25519Identity(k)
	case *rsa.PrivateKey:
		return agessh.NewRSAIdentity(k)
	default:
		return nil, fmt.Errorf("unsupported SSH key type %T (only ed25519 and RSA are supported by age)", key)
	}
}

func loadAuthorizedKey(path string) (ssh.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse %q: %w", path, err)
	}
	return pub, nil
}

func promptPassphrase(prompt string) ([]byte, error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, errors.New("SSH key is passphrase-protected and no terminal is available")
	}
	defer f.Close()

	if _, err := io.WriteString(f, prompt); err != nil {
		return nil, err
	}
	pw, err := term.ReadPassword(int(f.Fd()))
	io.WriteString(f, "\n")
	return pw, err
}
