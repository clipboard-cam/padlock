package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func TestTarGzipRoundTrip(t *testing.T) {
	src := t.TempDir()
	mustWrite(t, filepath.Join(src, "top.txt"), "hello top")
	mustWrite(t, filepath.Join(src, "sub", "nested.txt"), "hello nested")
	mustWrite(t, filepath.Join(src, "sub", "deep", "leaf.txt"), "leaf")

	// Tar+gzip into a buffer.
	var buf bytes.Buffer
	if err := tarGzipDir(&buf, src); err != nil {
		t.Fatalf("tarGzipDir: %v", err)
	}
	if buf.Len() < 2 || buf.Bytes()[0] != 0x1f || buf.Bytes()[1] != 0x8b {
		t.Fatal("output should start with gzip magic")
	}

	// Untar to a new dir.
	dst := filepath.Join(t.TempDir(), "out")
	n, err := untarGzip(&buf, dst)
	if err != nil {
		t.Fatalf("untarGzip: %v", err)
	}
	if n != 3 {
		t.Errorf("file count = %d, want 3", n)
	}

	got := walkSorted(t, dst)
	want := []string{
		"sub/deep/leaf.txt:leaf",
		"sub/nested.txt:hello nested",
		"top.txt:hello top",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("contents mismatch\n got: %v\nwant: %v", got, want)
	}
}

func TestUntarGzipRejectsTraversalEntry(t *testing.T) {
	// Build a malicious tar+gzip whose second entry tries to escape the root.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	if err := tw.WriteHeader(&tar.Header{
		Name: "root/", Mode: 0755, Typeflag: tar.TypeDir,
	}); err != nil {
		t.Fatal(err)
	}
	body := []byte("pwned")
	if err := tw.WriteHeader(&tar.Header{
		Name: "root/../escape.txt", Mode: 0644, Typeflag: tar.TypeReg, Size: int64(len(body)),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	gz.Close()

	dst := filepath.Join(t.TempDir(), "out")
	_, err := untarGzip(&buf, dst)
	if err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Errorf("expected unsafe-path error, got %v", err)
	}
	// Belt and braces: confirm nothing escaped to the parent dir.
	parent := filepath.Dir(dst)
	if _, err := os.Stat(filepath.Join(parent, "escape.txt")); err == nil {
		t.Error("traversal succeeded; escape.txt was created outside dst")
	}
}

func TestTarGzipSkipsSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks unreliable on Windows test runners")
	}
	src := t.TempDir()
	mustWrite(t, filepath.Join(src, "real.txt"), "real")
	if err := os.Symlink("real.txt", filepath.Join(src, "link.txt")); err != nil {
		t.Skipf("symlink create failed: %v", err)
	}

	var buf bytes.Buffer
	if err := tarGzipDir(&buf, src); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "out")
	n, err := untarGzip(&buf, dst)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("file count = %d, want 1 (real.txt only)", n)
	}
	if _, err := os.Stat(filepath.Join(dst, "real.txt")); err != nil {
		t.Errorf("real.txt missing: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dst, "link.txt")); err == nil {
		t.Error("link.txt should have been skipped")
	}
}

func TestTarGzipPreservesEmptyDirectories(t *testing.T) {
	src := t.TempDir()
	mustWrite(t, filepath.Join(src, "real.txt"), "x")
	if err := os.MkdirAll(filepath.Join(src, "empty", "nested-empty"), 0755); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := tarGzipDir(&buf, src); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "out")
	if _, err := untarGzip(&buf, dst); err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{"empty", "empty/nested-empty"} {
		fi, err := os.Stat(filepath.Join(dst, p))
		if err != nil {
			t.Errorf("%s missing after round-trip: %v", p, err)
			continue
		}
		if !fi.IsDir() {
			t.Errorf("%s should be a directory", p)
		}
	}
}

func TestDirArchiveHeaderRoundTrip(t *testing.T) {
	src := t.TempDir()
	mustWrite(t, filepath.Join(src, "a.txt"), "alpha")

	var buf bytes.Buffer
	if err := writeDirArchive(&buf, src); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(buf.Bytes(), dirArchiveHeader) {
		t.Fatal("archive should start with dirArchiveHeader")
	}

	br := bufio.NewReader(&buf)
	isDir, err := detectAndConsumeDirHeader(br)
	if err != nil {
		t.Fatal(err)
	}
	if !isDir {
		t.Fatal("expected detect to return true")
	}

	dst := filepath.Join(t.TempDir(), "out")
	n, err := untarGzip(br, dst)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("file count = %d, want 1", n)
	}
}

func TestDetectAndConsumeDirHeaderAbsent(t *testing.T) {
	br := bufio.NewReader(bytes.NewReader([]byte("hello world")))
	isDir, err := detectAndConsumeDirHeader(br)
	if err != nil {
		t.Fatal(err)
	}
	if isDir {
		t.Error("expected false for plaintext that is not a dir archive")
	}
	// Reader should be unchanged: still positioned at "hello world".
	rest, _ := br.Peek(11)
	if string(rest) != "hello world" {
		t.Errorf("reader was advanced unexpectedly; saw %q", rest)
	}
}

func TestSafePath(t *testing.T) {
	// Build a malicious tarball with a path containing ..
	// We do this by tarring a real dir, then surgically replacing a header name
	// would be complex — instead test the safePath helper directly.
	cases := []struct {
		path string
		safe bool
	}{
		{"foo/bar", true},
		{"foo/bar.txt", true},
		{"foo/.bar", true},
		{"foo..bar/baz", true},
		{"../etc/passwd", false},
		{"foo/../etc/passwd", false},
		{"/etc/passwd", false},
	}
	for _, tc := range cases {
		if got := safePath(tc.path); got != tc.safe {
			t.Errorf("safePath(%q) = %v, want %v", tc.path, got, tc.safe)
		}
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func walkSorted(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.Walk(root, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out = append(out, filepath.ToSlash(rel)+":"+string(data))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}
