package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// dirArchiveHeader is prepended to the tar+gzip stream when encrypting a
// directory, so decrypt can unambiguously distinguish "user encrypted a
// directory" from "user encrypted a file that happens to be gzip-shaped"
// (e.g. db-backup.sql.gz). The trailing newline keeps it line-readable.
var dirArchiveHeader = []byte("PADLOCK-DIR-1\n")

// writeDirArchive prepends dirArchiveHeader to w and then streams a
// tar+gzip of root.
func writeDirArchive(w io.Writer, root string) error {
	if _, err := w.Write(dirArchiveHeader); err != nil {
		return err
	}
	return tarGzipDir(w, root)
}

// detectAndConsumeDirHeader reports whether r begins with dirArchiveHeader.
// If yes, the header bytes are consumed from r so the next read starts with
// the gzip stream; if no, r is left unchanged.
func detectAndConsumeDirHeader(r *bufio.Reader) (bool, error) {
	peek, err := r.Peek(len(dirArchiveHeader))
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return false, err
	}
	if len(peek) >= len(dirArchiveHeader) && bytes.Equal(peek, dirArchiveHeader) {
		if _, err := r.Discard(len(dirArchiveHeader)); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

// tarGzipDir streams a tar+gzip archive of the directory at root into w.
// Archive entries are rooted at the basename of root (so a file at root/foo
// becomes <basename>/foo in the archive).
func tarGzipDir(w io.Writer, root string) error {
	root = filepath.Clean(root)
	info, err := os.Stat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s: not a directory", root)
	}
	parent := filepath.Dir(root)

	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)

	walkErr := filepath.Walk(root, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Skip symlinks — we don't want to silently encrypt arbitrary symlink targets.
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil
		}

		rel, err := filepath.Rel(parent, path)
		if err != nil {
			return err
		}

		hdr, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if fi.IsDir() {
			hdr.Name += "/"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if !fi.Mode().IsRegular() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	})

	if cerr := tw.Close(); walkErr == nil {
		walkErr = cerr
	}
	if cerr := gz.Close(); walkErr == nil {
		walkErr = cerr
	}
	return walkErr
}

// untarGzip reads a gzipped tar from r and writes its contents to dst.
// The single top-level directory in the archive is stripped so contents
// land directly under dst. Returns the number of regular files extracted.
func untarGzip(r io.Reader, dst string) (int, error) {
	if err := os.MkdirAll(dst, 0755); err != nil {
		return 0, err
	}
	gz, err := gzip.NewReader(r)
	if err != nil {
		return 0, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	var rootPrefix string
	rootDetermined := false
	fileCount := 0

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fileCount, err
		}

		name := filepath.ToSlash(hdr.Name)
		if !rootDetermined {
			parts := strings.SplitN(name, "/", 2)
			rootPrefix = parts[0] + "/"
			rootDetermined = true
		}
		rel := strings.TrimPrefix(name, rootPrefix)
		if rel == "" {
			continue // archive root directory entry
		}

		if !safePath(rel) {
			return fileCount, fmt.Errorf("archive contains unsafe path %q", hdr.Name)
		}

		target := filepath.Join(dst, filepath.FromSlash(rel))
		mode := os.FileMode(hdr.Mode).Perm()

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, mode|0700); err != nil {
				return fileCount, err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fileCount, err
			}
			f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode|0600)
			if err != nil {
				return fileCount, err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return fileCount, err
			}
			if err := f.Close(); err != nil {
				return fileCount, err
			}
			fileCount++
		default:
			// Skip unknown entry types (symlinks, devices, etc).
		}
	}
	return fileCount, nil
}

// safePath rejects archive entries that would escape the destination via
// absolute paths or `..` components.
func safePath(p string) bool {
	if filepath.IsAbs(p) {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if part == ".." {
			return false
		}
	}
	return true
}
