package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureStdout redirects os.Stdout for the duration of fn and returns
// everything fn wrote.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	done := make(chan string)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		done <- buf.String()
	}()

	fn()
	w.Close()
	os.Stdout = old
	return <-done
}

func TestRunPubkeyReadsDefaultKey(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatal(err)
	}
	generateSSHKeypair(t, sshDir, "test@host")
	t.Setenv("HOME", home)

	out := captureStdout(t, func() {
		if err := run([]string{"pubkey"}); err != nil {
			t.Fatalf("run pubkey: %v", err)
		}
	})

	if !strings.Contains(out, "ssh-ed25519") {
		t.Errorf("expected ed25519 prefix, got %q", out)
	}
	if !strings.Contains(out, "test@host") {
		t.Errorf("expected comment in output, got %q", out)
	}
}

func TestRunPubkeyRejectsArguments(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	os.MkdirAll(sshDir, 0700)
	generateSSHKeypair(t, sshDir, "x")
	t.Setenv("HOME", home)

	err := run([]string{"pubkey", "extra"})
	if err == nil || !strings.Contains(err.Error(), "no arguments") {
		t.Errorf("expected 'no arguments' error, got %v", err)
	}
}

func TestRunNoArgsPrintsHelp(t *testing.T) {
	out := captureStdout(t, func() {
		if err := run(nil); err != nil {
			t.Fatalf("run: %v", err)
		}
	})
	if !strings.Contains(out, "padlock — share files safely") {
		t.Errorf("expected help text, got %q", out)
	}
}

func TestRunHelpFlag(t *testing.T) {
	for _, arg := range []string{"-h", "--help", "help"} {
		t.Run(arg, func(t *testing.T) {
			out := captureStdout(t, func() {
				if err := run([]string{arg}); err != nil {
					t.Fatalf("run %s: %v", arg, err)
				}
			})
			if !strings.Contains(out, "padlock — share files safely") {
				t.Errorf("expected help text for %s, got %q", arg, out)
			}
		})
	}
}

func TestDispatchEncryptedFileWithRecipientsErrors(t *testing.T) {
	dir := t.TempDir()
	alicePriv, _ := generateSSHKeypair(t, dir, "alice")
	_, bobPub := generateSSHKeypair(t, t.TempDir(), "bob")

	src := filepath.Join(dir, "x.txt")
	os.WriteFile(src, []byte("x"), 0600)
	enc := filepath.Join(dir, "x.txt.padlock")

	if err := runEncrypt(encryptOptions{
		input: src, recipients: []string{bobPub}, identityPath: alicePriv, outputPath: enc,
	}); err != nil {
		t.Fatal(err)
	}

	err := run([]string{"-i", alicePriv, enc, bobPub})
	if err == nil || !strings.Contains(err.Error(), "already encrypted") {
		t.Errorf("expected 'already encrypted' error, got %v", err)
	}
}

func TestDispatchRecursiveOnFileErrors(t *testing.T) {
	dir := t.TempDir()
	alicePriv, _ := generateSSHKeypair(t, dir, "alice")
	_, bobPub := generateSSHKeypair(t, t.TempDir(), "bob")

	src := filepath.Join(dir, "x.txt")
	os.WriteFile(src, []byte("x"), 0600)

	err := run([]string{"-r", "-i", alicePriv, src, bobPub})
	if err == nil || !strings.Contains(err.Error(), "is a file") {
		t.Errorf("expected 'is a file' error, got %v", err)
	}
}
