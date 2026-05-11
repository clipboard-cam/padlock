package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestParseRecipientArg_StringEd25519(t *testing.T) {
	pubLine := generateEd25519PubLine(t, "alice@laptop")
	r, err := parseRecipientArg(pubLine)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if r.Label != "alice@laptop" {
		t.Errorf("label = %q, want alice@laptop", r.Label)
	}
	if r.Fingerprint == "" {
		t.Errorf("fingerprint should be set")
	}
}

func TestParseRecipientArg_FilePath(t *testing.T) {
	dir := t.TempDir()
	pubLine := generateEd25519PubLine(t, "bob@desktop")
	path := filepath.Join(dir, "bob.pub")
	if err := os.WriteFile(path, []byte(pubLine), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := parseRecipientArg(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if r.Label != "bob@desktop" {
		t.Errorf("label = %q, want bob@desktop", r.Label)
	}
}

func TestParseRecipientArg_RejectsECDSA(t *testing.T) {
	// Fake-but-prefix-valid ECDSA line; the type-check should reject it
	// before the body is parsed.
	line := "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN/exam ecdsa@host"
	_, err := parseRecipientArg(line)
	if err == nil || !strings.Contains(err.Error(), "ECDSA") {
		t.Errorf("expected ECDSA error, got %v", err)
	}
}

func TestParseRecipientArg_RejectsDSA(t *testing.T) {
	line := "ssh-dss AAAAB3NzaC1kc3MAA dsa@host"
	_, err := parseRecipientArg(line)
	if err == nil || !strings.Contains(err.Error(), "DSA") {
		t.Errorf("expected DSA error, got %v", err)
	}
}

func TestParseRecipientArg_RejectsHardwareKey(t *testing.T) {
	line := "sk-ssh-ed25519@openssh.com AAAA hw@yubikey"
	_, err := parseRecipientArg(line)
	if err == nil || !strings.Contains(err.Error(), "hardware") {
		t.Errorf("expected hardware-key error, got %v", err)
	}
}

func TestParseRecipientArg_UnnamedKey(t *testing.T) {
	// Strip the comment.
	pubLine := generateEd25519PubLine(t, "")
	r, err := parseRecipientArg(pubLine)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !strings.HasPrefix(r.Label, "(unnamed") {
		t.Errorf("label = %q, want (unnamed ...)", r.Label)
	}
}

func TestParseRecipientArg_Empty(t *testing.T) {
	if _, err := parseSSHRecipient(""); err == nil {
		t.Error("expected error for empty input")
	}
}

// generateEd25519PubLine returns a single-line authorized_keys-format
// ed25519 public key with the given comment.
func generateEd25519PubLine(t *testing.T, comment string) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimRight(string(ssh.MarshalAuthorizedKey(sshPub)), "\n")
	if comment != "" {
		line += " " + comment
	}
	return line
}
