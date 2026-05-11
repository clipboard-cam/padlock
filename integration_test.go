package main

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// generateRSASSHKeypair writes an RSA SSH keypair into dir as id_rsa
// and id_rsa.pub, returning the private and public key paths.
func generateRSASSHKeypair(t *testing.T, dir, comment string) (priv, pub string) {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemBlock, err := ssh.MarshalPrivateKey(privKey, comment)
	if err != nil {
		t.Fatal(err)
	}
	priv = filepath.Join(dir, "id_rsa")
	if err := os.WriteFile(priv, pem.EncodeToMemory(pemBlock), 0600); err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(&privKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubLine := strings.TrimRight(string(ssh.MarshalAuthorizedKey(sshPub)), "\n")
	if comment != "" {
		pubLine += " " + comment
	}
	pub = priv + ".pub"
	if err := os.WriteFile(pub, []byte(pubLine+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

// generateSSHKeypair writes an ed25519 SSH keypair into dir as id_ed25519
// and id_ed25519.pub, returning the private and public key paths.
func generateSSHKeypair(t *testing.T, dir, comment string) (priv, pub string) {
	t.Helper()
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pemBlock, err := ssh.MarshalPrivateKey(privKey, comment)
	if err != nil {
		t.Fatal(err)
	}
	priv = filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(priv, pem.EncodeToMemory(pemBlock), 0600); err != nil {
		t.Fatal(err)
	}

	sshPub, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		t.Fatal(err)
	}
	pubLine := strings.TrimRight(string(ssh.MarshalAuthorizedKey(sshPub)), "\n")
	if comment != "" {
		pubLine += " " + comment
	}
	pub = priv + ".pub"
	if err := os.WriteFile(pub, []byte(pubLine+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func TestRoundTripFile(t *testing.T) {
	dir := t.TempDir()
	alicePriv, alicePub := generateSSHKeypair(t, dir, "alice@laptop")
	bobPriv, bobPub := generateSSHKeypair(t, t.TempDir(), "bob@laptop")

	plaintext := "the prod db password is hunter2"
	src := filepath.Join(dir, "secrets.txt")
	if err := os.WriteFile(src, []byte(plaintext), 0600); err != nil {
		t.Fatal(err)
	}
	encOut := filepath.Join(dir, "secrets.txt.padlock")

	// Alice encrypts to Bob.
	if err := runEncrypt(encryptOptions{
		input:        src,
		recipients:   []string{bobPub},
		identityPath: alicePriv,
		outputPath:   encOut,
	}); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Bob decrypts.
	bobOutDir := t.TempDir()
	bobOut := filepath.Join(bobOutDir, "secrets.txt")
	if err := runDecrypt(decryptOptions{
		input:        encOut,
		identityPath: bobPriv,
		outputPath:   bobOut,
	}); err != nil {
		t.Fatalf("bob decrypt: %v", err)
	}
	got, err := os.ReadFile(bobOut)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != plaintext {
		t.Errorf("plaintext mismatch: got %q, want %q", string(got), plaintext)
	}

	// Alice can also decrypt (encrypt-to-self).
	aliceOutDir := t.TempDir()
	aliceOut := filepath.Join(aliceOutDir, "secrets.txt")
	if err := runDecrypt(decryptOptions{
		input:        encOut,
		identityPath: alicePriv,
		outputPath:   aliceOut,
	}); err != nil {
		t.Fatalf("alice self-decrypt: %v", err)
	}
	got, err = os.ReadFile(aliceOut)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != plaintext {
		t.Errorf("self-decrypt mismatch: got %q, want %q", string(got), plaintext)
	}

	_ = alicePub // not used; kept for symmetry/clarity
}

func TestRoundTripDirectory(t *testing.T) {
	srcRoot := t.TempDir()
	alicePriv, _ := generateSSHKeypair(t, srcRoot, "alice@laptop")
	bobPriv, bobPub := generateSSHKeypair(t, t.TempDir(), "bob@laptop")

	srcDir := filepath.Join(srcRoot, "secrets")
	mustWrite(t, filepath.Join(srcDir, "top.txt"), "top contents")
	mustWrite(t, filepath.Join(srcDir, "sub", "nested.txt"), "nested contents")

	encOut := filepath.Join(srcRoot, "secrets.padlock")
	if err := runEncrypt(encryptOptions{
		input:        srcDir,
		recipients:   []string{bobPub},
		recursive:    true,
		identityPath: alicePriv,
		outputPath:   encOut,
	}); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	bobRoot := t.TempDir()
	dst := filepath.Join(bobRoot, "secrets")
	if err := runDecrypt(decryptOptions{
		input:        encOut,
		identityPath: bobPriv,
		outputPath:   dst,
	}); err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	got := walkSorted(t, dst)
	want := []string{
		"sub/nested.txt:nested contents",
		"top.txt:top contents",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("contents mismatch\n got: %v\nwant: %v", got, want)
	}
}

func TestRoundTripMultipleRecipients(t *testing.T) {
	dir := t.TempDir()
	alicePriv, _ := generateSSHKeypair(t, dir, "alice")
	bobPriv, bobPub := generateSSHKeypair(t, t.TempDir(), "bob")
	carolPriv, carolPub := generateSSHKeypair(t, t.TempDir(), "carol")

	plaintext := "shared secret"
	src := filepath.Join(dir, "shared.txt")
	if err := os.WriteFile(src, []byte(plaintext), 0600); err != nil {
		t.Fatal(err)
	}
	encOut := filepath.Join(dir, "shared.txt.padlock")

	if err := runEncrypt(encryptOptions{
		input:        src,
		recipients:   []string{bobPub, carolPub},
		identityPath: alicePriv,
		outputPath:   encOut,
	}); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	for who, key := range map[string]string{"alice": alicePriv, "bob": bobPriv, "carol": carolPriv} {
		out := filepath.Join(t.TempDir(), "out")
		if err := runDecrypt(decryptOptions{
			input:        encOut,
			identityPath: key,
			outputPath:   out,
		}); err != nil {
			t.Fatalf("%s decrypt: %v", who, err)
		}
		got, _ := os.ReadFile(out)
		if string(got) != plaintext {
			t.Errorf("%s got %q, want %q", who, got, plaintext)
		}
	}
}

func TestRefuseOverwrite(t *testing.T) {
	dir := t.TempDir()
	alicePriv, _ := generateSSHKeypair(t, dir, "alice")
	_, bobPub := generateSSHKeypair(t, t.TempDir(), "bob")

	src := filepath.Join(dir, "x.txt")
	if err := os.WriteFile(src, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "x.txt.padlock")
	if err := os.WriteFile(out, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}

	err := runEncrypt(encryptOptions{
		input:        src,
		recipients:   []string{bobPub},
		identityPath: alicePriv,
		outputPath:   out,
	})
	if err == nil || !strings.Contains(err.Error(), "use -f") {
		t.Errorf("expected refuse-overwrite error, got %v", err)
	}

	if err := runEncrypt(encryptOptions{
		input:        src,
		recipients:   []string{bobPub},
		identityPath: alicePriv,
		outputPath:   out,
		force:        true,
	}); err != nil {
		t.Errorf("force=true should succeed: %v", err)
	}
}

func TestEncryptDirectoryWithoutRecursiveErrors(t *testing.T) {
	dir := t.TempDir()
	alicePriv, _ := generateSSHKeypair(t, dir, "alice")
	_, bobPub := generateSSHKeypair(t, t.TempDir(), "bob")

	srcDir := filepath.Join(dir, "things")
	if err := os.Mkdir(srcDir, 0755); err != nil {
		t.Fatal(err)
	}

	err := runEncrypt(encryptOptions{
		input:        srcDir,
		recipients:   []string{bobPub},
		identityPath: alicePriv,
	})
	if err == nil || !strings.Contains(err.Error(), "directory") || !strings.Contains(err.Error(), "-r") {
		t.Errorf("expected directory/-r hint, got %v", err)
	}
}

func TestSelfRecipientDeduplicated(t *testing.T) {
	dir := t.TempDir()
	alicePriv, alicePub := generateSSHKeypair(t, dir, "alice@laptop")

	src := filepath.Join(dir, "s.txt")
	os.WriteFile(src, []byte("x"), 0600)
	out := filepath.Join(dir, "s.txt.padlock")

	// Pass alice's own pubkey as the "recipient" — should not double up.
	if err := runEncrypt(encryptOptions{
		input:        src,
		recipients:   []string{alicePub},
		identityPath: alicePriv,
		outputPath:   out,
	}); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// Should still be decryptable by alice.
	bobOut := filepath.Join(t.TempDir(), "out")
	if err := runDecrypt(decryptOptions{
		input:        out,
		identityPath: alicePriv,
		outputPath:   bobOut,
	}); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
}

// Repro of the gzip-collision bug: a plaintext file that happens to start
// with the gzip magic bytes used to be misdetected as a tar+gzip dir
// archive on decrypt. The PADLOCK-DIR-1 framing header now disambiguates.
func TestEncryptingGzipFileDoesNotExtract(t *testing.T) {
	dir := t.TempDir()
	alicePriv, _ := generateSSHKeypair(t, dir, "alice")
	bobPriv, bobPub := generateSSHKeypair(t, t.TempDir(), "bob")

	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	if _, err := gw.Write([]byte("not a tarball, just gzip")); err != nil {
		t.Fatal(err)
	}
	gw.Close()
	raw := gzBuf.Bytes()
	if raw[0] != 0x1f || raw[1] != 0x8b {
		t.Fatal("bad test setup: expected gzip magic")
	}

	src := filepath.Join(dir, "blob.gz")
	if err := os.WriteFile(src, raw, 0600); err != nil {
		t.Fatal(err)
	}
	encOut := filepath.Join(dir, "blob.gz.padlock")
	if err := runEncrypt(encryptOptions{
		input:        src,
		recipients:   []string{bobPub},
		identityPath: alicePriv,
		outputPath:   encOut,
	}); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	decOut := filepath.Join(t.TempDir(), "blob.gz")
	if err := runDecrypt(decryptOptions{
		input:        encOut,
		identityPath: bobPriv,
		outputPath:   decOut,
	}); err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	fi, err := os.Stat(decOut)
	if err != nil {
		t.Fatalf("stat decrypted output: %v", err)
	}
	if fi.IsDir() {
		t.Fatal("gzip-shaped plaintext was wrongly treated as a dir archive")
	}
	got, _ := os.ReadFile(decOut)
	if !bytes.Equal(got, raw) {
		t.Errorf("round-trip changed contents:\n got %x\nwant %x", got, raw)
	}
}

func TestRoundTripRSA(t *testing.T) {
	dir := t.TempDir()
	alicePriv, _ := generateRSASSHKeypair(t, dir, "alice@rsa")
	bobPriv, bobPub := generateRSASSHKeypair(t, t.TempDir(), "bob@rsa")

	plaintext := "rsa works too"
	src := filepath.Join(dir, "msg.txt")
	if err := os.WriteFile(src, []byte(plaintext), 0600); err != nil {
		t.Fatal(err)
	}
	encOut := filepath.Join(dir, "msg.txt.padlock")

	if err := runEncrypt(encryptOptions{
		input:        src,
		recipients:   []string{bobPub},
		identityPath: alicePriv,
		outputPath:   encOut,
	}); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	decOut := filepath.Join(t.TempDir(), "msg.txt")
	if err := runDecrypt(decryptOptions{
		input:        encOut,
		identityPath: bobPriv,
		outputPath:   decOut,
	}); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	got, _ := os.ReadFile(decOut)
	if string(got) != plaintext {
		t.Errorf("got %q, want %q", got, plaintext)
	}
}

func TestDecryptWithWrongIdentity(t *testing.T) {
	dir := t.TempDir()
	alicePriv, _ := generateSSHKeypair(t, dir, "alice")
	_, bobPub := generateSSHKeypair(t, t.TempDir(), "bob")
	carolPriv, _ := generateSSHKeypair(t, t.TempDir(), "carol")

	src := filepath.Join(dir, "x.txt")
	if err := os.WriteFile(src, []byte("nope"), 0600); err != nil {
		t.Fatal(err)
	}
	encOut := filepath.Join(dir, "x.txt.padlock")
	if err := runEncrypt(encryptOptions{
		input:        src,
		recipients:   []string{bobPub},
		identityPath: alicePriv,
		outputPath:   encOut,
	}); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	err := runDecrypt(decryptOptions{
		input:        encOut,
		identityPath: carolPriv,
		outputPath:   filepath.Join(t.TempDir(), "x.txt"),
	})
	if err == nil {
		t.Fatal("expected decrypt to fail for non-recipient")
	}
	if !strings.Contains(err.Error(), "encrypted for you?") {
		t.Errorf("error should hint at recipient mismatch, got %v", err)
	}
}

func TestEncryptedFileIsPrivateMode(t *testing.T) {
	dir := t.TempDir()
	alicePriv, _ := generateSSHKeypair(t, dir, "alice")
	_, bobPub := generateSSHKeypair(t, t.TempDir(), "bob")

	src := filepath.Join(dir, "x.txt")
	if err := os.WriteFile(src, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	encOut := filepath.Join(dir, "x.txt.padlock")
	if err := runEncrypt(encryptOptions{
		input:        src,
		recipients:   []string{bobPub},
		identityPath: alicePriv,
		outputPath:   encOut,
	}); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	fi, err := os.Stat(encOut)
	if err != nil {
		t.Fatal(err)
	}
	if mode := fi.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("encrypted file mode = %o, expected no group/world bits", mode)
	}
}

func TestDecryptOfFileProducesFile(t *testing.T) {
	dir := t.TempDir()
	alicePriv, _ := generateSSHKeypair(t, dir, "alice")
	_, bobPub := generateSSHKeypair(t, t.TempDir(), "bob")

	src := filepath.Join(dir, "x.txt")
	if err := os.WriteFile(src, []byte("hi"), 0600); err != nil {
		t.Fatal(err)
	}
	encOut := filepath.Join(dir, "x.txt.padlock")
	if err := runEncrypt(encryptOptions{
		input:        src,
		recipients:   []string{bobPub},
		identityPath: alicePriv,
		outputPath:   encOut,
	}); err != nil {
		t.Fatal(err)
	}

	decOut := filepath.Join(t.TempDir(), "x.txt")
	if err := runDecrypt(decryptOptions{
		input:        encOut,
		identityPath: alicePriv,
		outputPath:   decOut,
	}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(decOut)
	if err != nil {
		t.Fatal(err)
	}
	if fi.IsDir() {
		t.Errorf("expected regular file, got directory")
	}
}

// When -i is explicit and the matching .pub file is missing, encrypt
// must error rather than silently dropping the self-recipient — otherwise
// the user could lock themselves out of their own ciphertext.
func TestEncryptSelfRecipientPubMissing(t *testing.T) {
	dir := t.TempDir()
	alicePriv, alicePub := generateSSHKeypair(t, dir, "alice")
	if err := os.Remove(alicePub); err != nil {
		t.Fatal(err)
	}
	_, bobPub := generateSSHKeypair(t, t.TempDir(), "bob")

	src := filepath.Join(dir, "x.txt")
	os.WriteFile(src, []byte("x"), 0600)

	err := runEncrypt(encryptOptions{
		input:        src,
		recipients:   []string{bobPub},
		identityPath: alicePriv,
		outputPath:   filepath.Join(dir, "x.txt.padlock"),
	})
	if err == nil || !strings.Contains(err.Error(), "self recipient") {
		t.Errorf("expected self-recipient error, got %v", err)
	}
}

