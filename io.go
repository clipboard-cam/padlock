package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const padlockExt = ".padlock"

var ageMagic = []byte("age-encryption.org/v1\n")

// looksEncrypted reports whether the file at path begins with the age v1
// magic header. Returns false (without error) for short files.
func looksEncrypted(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	buf := make([]byte, len(ageMagic))
	n, err := io.ReadFull(f, buf)
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return n == len(ageMagic) && string(buf) == string(ageMagic), nil
}

// defaultEncryptOutput returns the default output path for encrypting input.
//
//	foo.txt -> foo.txt.padlock
//	bar/    -> bar.padlock
func defaultEncryptOutput(input string) string {
	cleaned := filepath.Clean(input)
	info, err := os.Stat(cleaned)
	if err == nil && info.IsDir() {
		return filepath.Base(cleaned) + padlockExt
	}
	return cleaned + padlockExt
}

// defaultDecryptOutput returns the default output path for decrypting input.
//
//	foo.txt.padlock -> foo.txt
//	bar.padlock     -> bar
//	other           -> other.out
func defaultDecryptOutput(input string) string {
	base := filepath.Base(input)
	if strings.HasSuffix(base, padlockExt) {
		return strings.TrimSuffix(base, padlockExt)
	}
	return base + ".out"
}

// openOutput opens path for writing. If path exists and force is false,
// returns an error pointing the user at -f.
func openOutput(path string, force bool) (*os.File, error) {
	if _, err := os.Stat(path); err == nil && !force {
		return nil, fmt.Errorf("%s exists; use -f to overwrite", path)
	}
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
}

// ensureDirAvailable returns an error if path exists and force is false,
// otherwise removes the existing path so it can be re-created.
func ensureDirAvailable(path string, force bool) error {
	if _, err := os.Stat(path); err == nil {
		if !force {
			return fmt.Errorf("%s exists; use -f to overwrite", path)
		}
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("remove existing %s: %w", path, err)
		}
	}
	return nil
}

func fileSize(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fi.Size()
}

func humanSize(n int64) string {
	const (
		kb = 1024
		mb = 1024 * 1024
		gb = 1024 * 1024 * 1024
	)
	switch {
	case n < kb:
		return fmt.Sprintf("%d B", n)
	case n < mb:
		return fmt.Sprintf("%.1f KB", float64(n)/kb)
	case n < gb:
		return fmt.Sprintf("%.1f MB", float64(n)/mb)
	default:
		return fmt.Sprintf("%.2f GB", float64(n)/gb)
	}
}
