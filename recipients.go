package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"golang.org/x/crypto/ssh"
)

// recipientInfo bundles an age recipient with a human-friendly label
// (the SSH key comment, or a fallback) and a fingerprint for dedup.
type recipientInfo struct {
	R           age.Recipient
	Label       string
	Fingerprint string
	IsSelf      bool
}

func parseRecipientArg(arg string) (recipientInfo, error) {
	if isSSHKeyPrefix(arg) {
		return parseSSHRecipient(arg)
	}
	// Try the address book before treating the arg as a path. An arg
	// containing a path separator is unambiguously a path and skips this.
	hasSep := strings.ContainsRune(arg, os.PathSeparator)
	if !hasSep {
		keyLine, found, err := resolveAddressBookKeyLine(arg)
		if err != nil {
			return recipientInfo{}, err
		}
		if found {
			r, err := parseSSHRecipient(keyLine)
			if err != nil {
				return recipientInfo{}, fmt.Errorf("recipient %q: %w", arg, err)
			}
			// Prefer the registered name over the key comment for clarity.
			r.Label = arg
			return r, nil
		}
	}
	data, err := os.ReadFile(arg)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !hasSep {
			return recipientInfo{}, fmt.Errorf("no recipient named %q (try `padlock recipients list`)", arg)
		}
		return recipientInfo{}, fmt.Errorf("read recipient %q: %w", arg, err)
	}
	return parseSSHRecipient(string(data))
}

func parseSSHRecipient(s string) (recipientInfo, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return recipientInfo{}, errors.New("empty recipient")
	}

	// Surface friendly errors for unsupported key types before attempting to
	// parse the rest of the line — ssh.ParseAuthorizedKey would otherwise
	// reject malformed bodies with a confusing base64 error.
	fields := strings.Fields(s)
	if len(fields) > 0 {
		switch fields[0] {
		case "ssh-ed25519", "ssh-rsa":
			// supported; continue
		case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
			return recipientInfo{}, fmt.Errorf("ECDSA SSH keys aren't supported by age. Ask the recipient for an ed25519 key:\n  ssh-keygen -t ed25519")
		case "ssh-dss":
			return recipientInfo{}, fmt.Errorf("DSA SSH keys aren't supported by age. Ask the recipient for an ed25519 key:\n  ssh-keygen -t ed25519")
		default:
			if strings.HasPrefix(fields[0], "sk-") {
				return recipientInfo{}, fmt.Errorf("hardware-backed SSH keys (sk-*) aren't supported by age. Ask the recipient for an ed25519 key:\n  ssh-keygen -t ed25519")
			}
		}
	}

	pub, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(s))
	if err != nil {
		return recipientInfo{}, fmt.Errorf("parse SSH public key: %w", err)
	}

	fp := ssh.FingerprintSHA256(pub)
	switch t := pub.Type(); t {
	case "ssh-ed25519":
		r, err := agessh.NewEd25519Recipient(pub)
		if err != nil {
			return recipientInfo{}, err
		}
		return recipientInfo{R: r, Label: labelFor(comment, t), Fingerprint: fp}, nil
	case "ssh-rsa":
		r, err := agessh.NewRSARecipient(pub)
		if err != nil {
			return recipientInfo{}, err
		}
		return recipientInfo{R: r, Label: labelFor(comment, t), Fingerprint: fp}, nil
	default:
		return recipientInfo{}, fmt.Errorf("unsupported SSH key type %q (supported: ed25519, RSA)", t)
	}
}

func labelFor(comment, keyType string) string {
	if comment != "" {
		return comment
	}
	return "(unnamed " + keyType + ")"
}
