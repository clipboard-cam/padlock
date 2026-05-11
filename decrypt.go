package main

import (
	"bufio"
	"fmt"
	"io"
	"os"

	"filippo.io/age"
)

type decryptOptions struct {
	input        string
	identityPath string
	outputPath   string
	force        bool
}

func runDecrypt(opts decryptOptions) (err error) {
	idPath, err := resolveIdentityPath(opts.identityPath)
	if err != nil {
		return err
	}
	identity, err := loadIdentity(idPath)
	if err != nil {
		return err
	}

	in, err := os.Open(opts.input)
	if err != nil {
		return fmt.Errorf("input: %w", err)
	}
	defer in.Close()

	decReader, err := age.Decrypt(in, identity)
	if err != nil {
		return fmt.Errorf("decrypt %s: %w (was this file encrypted for you?)", opts.input, err)
	}

	bufReader := bufio.NewReader(decReader)
	isArchive, err := detectAndConsumeDirHeader(bufReader)
	if err != nil {
		return fmt.Errorf("read decrypted stream: %w", err)
	}

	outPath := opts.outputPath
	if outPath == "" {
		outPath = defaultDecryptOutput(opts.input)
	}

	if isArchive {
		if err := ensureDirAvailable(outPath, opts.force); err != nil {
			return err
		}
		n, err := untarGzip(bufReader, outPath)
		if err != nil {
			return fmt.Errorf("extract: %w", err)
		}
		plural := "files"
		if n == 1 {
			plural = "file"
		}
		fmt.Printf("Decrypted to %s/  (%d %s)\n", outPath, n, plural)
		return nil
	}

	out, err := openOutput(outPath, opts.force)
	if err != nil {
		return err
	}
	success := false
	defer func() {
		out.Close()
		if !success {
			os.Remove(outPath)
		}
	}()

	if _, err := io.Copy(out, bufReader); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close output: %w", err)
	}
	success = true

	fmt.Printf("Decrypted to %s\n", outPath)
	return nil
}
