package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setupAddressBook isolates the test from any real ~/.config/padlock by
// pointing XDG_CONFIG_HOME at a fresh tempdir. It returns the path the
// recipients file would live at.
func setupAddressBook(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	return filepath.Join(dir, "padlock", "recipients")
}

func TestAddressBookAddAndLoad(t *testing.T) {
	setupAddressBook(t)
	pubLine := generateEd25519PubLine(t, "alice@laptop")

	if err := addAddressBookEntry("alice", pubLine, false); err != nil {
		t.Fatalf("add: %v", err)
	}
	entries, err := loadAddressBook()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if entries[0].Name != "alice" {
		t.Errorf("name = %q, want alice", entries[0].Name)
	}
	if !strings.HasPrefix(entries[0].KeyLine, "ssh-ed25519 ") {
		t.Errorf("keyline = %q, want ssh-ed25519 prefix", entries[0].KeyLine)
	}
}

func TestAddressBookRefusesDuplicateWithoutForce(t *testing.T) {
	setupAddressBook(t)
	pubLine := generateEd25519PubLine(t, "alice")

	if err := addAddressBookEntry("alice", pubLine, false); err != nil {
		t.Fatal(err)
	}
	err := addAddressBookEntry("alice", pubLine, false)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected duplicate error, got %v", err)
	}
	if err := addAddressBookEntry("alice", pubLine, true); err != nil {
		t.Errorf("force should succeed: %v", err)
	}
}

func TestAddressBookRejectsInvalidName(t *testing.T) {
	setupAddressBook(t)
	pubLine := generateEd25519PubLine(t, "x")
	for _, bad := range []string{"alice bob", "alice/bob", "alice;rm", ""} {
		if err := addAddressBookEntry(bad, pubLine, false); err == nil {
			t.Errorf("expected error for name %q", bad)
		}
	}
}

func TestAddressBookRejectsUnsupportedKey(t *testing.T) {
	setupAddressBook(t)
	err := addAddressBookEntry("alice", "ecdsa-sha2-nistp256 AAAA fake@host", false)
	if err == nil || !strings.Contains(err.Error(), "ECDSA") {
		t.Errorf("expected ECDSA rejection, got %v", err)
	}
}

func TestAddressBookRemove(t *testing.T) {
	setupAddressBook(t)
	pubLine := generateEd25519PubLine(t, "alice")
	if err := addAddressBookEntry("alice", pubLine, false); err != nil {
		t.Fatal(err)
	}
	if err := removeAddressBookEntry("alice"); err != nil {
		t.Fatal(err)
	}
	entries, _ := loadAddressBook()
	if len(entries) != 0 {
		t.Errorf("entries = %d, want 0", len(entries))
	}
	err := removeAddressBookEntry("alice")
	if err == nil || !strings.Contains(err.Error(), "no recipient") {
		t.Errorf("expected no-such-recipient error, got %v", err)
	}
}

func TestAddressBookFileIsPrivateMode(t *testing.T) {
	path := setupAddressBook(t)
	pubLine := generateEd25519PubLine(t, "alice")
	if err := addAddressBookEntry("alice", pubLine, false); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := fi.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("recipients file mode = %o, want no group/world bits", mode)
	}
}

func TestAddressBookSkipsCommentsAndBlanks(t *testing.T) {
	path := setupAddressBook(t)
	pubLine := generateEd25519PubLine(t, "alice")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	content := "# heading\n\nalice " + pubLine + "\n# trailing\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	entries, err := loadAddressBook()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name != "alice" {
		t.Errorf("got %+v, want one entry named alice", entries)
	}
}

func TestAddressBookMalformedLineErrors(t *testing.T) {
	path := setupAddressBook(t)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("solo-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAddressBook(); err == nil {
		t.Error("expected malformed-line error")
	}
}

func TestAddressBookMissingFileIsNotAnError(t *testing.T) {
	setupAddressBook(t)
	entries, err := loadAddressBook()
	if err != nil {
		t.Fatalf("missing file should not error, got %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("entries = %d, want 0", len(entries))
	}
}

func TestParseRecipientArg_UsesAddressBook(t *testing.T) {
	setupAddressBook(t)
	pubLine := generateEd25519PubLine(t, "alice@laptop")
	if err := addAddressBookEntry("alice", pubLine, false); err != nil {
		t.Fatal(err)
	}
	r, err := parseRecipientArg("alice")
	if err != nil {
		t.Fatalf("resolve by name: %v", err)
	}
	if r.Label != "alice" {
		t.Errorf("label = %q, want alice (registered name should win over key comment)", r.Label)
	}
}

func TestParseRecipientArg_UnknownNameHintsAtList(t *testing.T) {
	setupAddressBook(t)
	_, err := parseRecipientArg("nobody")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "recipients list") {
		t.Errorf("error should hint at `recipients list`, got %v", err)
	}
}

func TestParseRecipientArg_PathWithSlashSkipsAddressBook(t *testing.T) {
	setupAddressBook(t)
	// Register a name that collides with a basename — but pass a path
	// containing a slash, which should bypass the address book entirely.
	registered := generateEd25519PubLine(t, "registered-alice")
	if err := addAddressBookEntry("alice.pub", registered, false); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	fileLine := generateEd25519PubLine(t, "from-disk")
	pubPath := filepath.Join(dir, "alice.pub")
	if err := os.WriteFile(pubPath, []byte(fileLine), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := parseRecipientArg(pubPath)
	if err != nil {
		t.Fatalf("file path: %v", err)
	}
	if r.Label != "from-disk" {
		t.Errorf("label = %q, want from-disk (path with slash should win)", r.Label)
	}
}
