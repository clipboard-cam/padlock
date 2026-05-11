package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveIdentityPathOverride(t *testing.T) {
	dir := t.TempDir()
	priv, _ := generateSSHKeypair(t, dir, "alice")
	got, err := resolveIdentityPath(priv)
	if err != nil {
		t.Fatal(err)
	}
	if got != priv {
		t.Errorf("got %s, want %s", got, priv)
	}
}

func TestResolveIdentityPathOverrideMissing(t *testing.T) {
	_, err := resolveIdentityPath("/no/such/file/anywhere")
	if err == nil || !strings.Contains(err.Error(), "/no/such/file/anywhere") {
		t.Errorf("expected error mentioning path, got %v", err)
	}
}

func TestResolveIdentityPathDefaultEd25519(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatal(err)
	}
	generateSSHKeypair(t, sshDir, "alice")
	t.Setenv("HOME", home)

	got, err := resolveIdentityPath("")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(sshDir, "id_ed25519")
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestResolveIdentityPathDefaultRSAFallback(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	os.MkdirAll(sshDir, 0700)
	// Place an RSA key only — no id_ed25519.
	rsaPriv, _ := generateRSASSHKeypair(t, sshDir, "alice@rsa")
	t.Setenv("HOME", home)

	got, err := resolveIdentityPath("")
	if err != nil {
		t.Fatal(err)
	}
	if got != rsaPriv {
		t.Errorf("got %s, want %s", got, rsaPriv)
	}
}

func TestResolveIdentityPathNoneFound(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	_, err := resolveIdentityPath("")
	if err == nil || !strings.Contains(err.Error(), "no SSH key found") {
		t.Errorf("expected no-key error, got %v", err)
	}
}
