package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLooksEncrypted(t *testing.T) {
	dir := t.TempDir()

	encrypted := filepath.Join(dir, "enc")
	if err := os.WriteFile(encrypted, append([]byte("age-encryption.org/v1\n"), []byte("rest")...), 0600); err != nil {
		t.Fatal(err)
	}
	plain := filepath.Join(dir, "plain")
	if err := os.WriteFile(plain, []byte("hello world"), 0600); err != nil {
		t.Fatal(err)
	}
	short := filepath.Join(dir, "short")
	if err := os.WriteFile(short, []byte("hi"), 0600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		path string
		want bool
	}{
		{encrypted, true},
		{plain, false},
		{short, false},
	}
	for _, tc := range cases {
		got, err := looksEncrypted(tc.path)
		if err != nil {
			t.Fatalf("%s: %v", tc.path, err)
		}
		if got != tc.want {
			t.Errorf("looksEncrypted(%s) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestDefaultEncryptOutput(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "mydir")
	if err := os.Mkdir(subdir, 0755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "secrets.txt")
	if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}

	if got, want := defaultEncryptOutput(file), file+".padlock"; got != want {
		t.Errorf("file: got %s, want %s", got, want)
	}
	if got, want := defaultEncryptOutput(subdir), "mydir.padlock"; got != want {
		t.Errorf("dir: got %s, want %s", got, want)
	}
	// Trailing slash on a directory.
	if got, want := defaultEncryptOutput(subdir+"/"), "mydir.padlock"; got != want {
		t.Errorf("dir/: got %s, want %s", got, want)
	}
}

func TestDefaultDecryptOutput(t *testing.T) {
	cases := []struct{ in, want string }{
		{"foo.txt.padlock", "foo.txt"},
		{"bar.padlock", "bar"},
		{"path/to/baz.padlock", "baz"},
		{"weird", "weird.out"},
	}
	for _, tc := range cases {
		if got := defaultDecryptOutput(tc.in); got != tc.want {
			t.Errorf("defaultDecryptOutput(%s) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestOpenOutputRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out")
	if err := os.WriteFile(path, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := openOutput(path, false); err == nil {
		t.Fatal("expected error when overwriting without force")
	}
	f, err := openOutput(path, true)
	if err != nil {
		t.Fatalf("force=true should succeed: %v", err)
	}
	f.Close()
}

func TestHumanSize(t *testing.T) {
	cases := []struct {
		n    int64
		want string
	}{
		{0, "0 B"},
		{500, "500 B"},
		{1024, "1.0 KB"},
		{1500, "1.5 KB"},
		{2 * 1024 * 1024, "2.0 MB"},
	}
	for _, tc := range cases {
		if got := humanSize(tc.n); got != tc.want {
			t.Errorf("humanSize(%d) = %s, want %s", tc.n, got, tc.want)
		}
	}
}
