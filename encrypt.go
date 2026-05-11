package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"
)

type encryptOptions struct {
	input        string
	recipients   []string
	recursive    bool
	identityPath string
	outputPath   string
	force        bool
}

func runEncrypt(opts encryptOptions) (err error) {
	info, err := os.Stat(opts.input)
	if err != nil {
		return fmt.Errorf("input: %w", err)
	}

	example := exampleRecipient(opts.recipients)
	if info.IsDir() && !opts.recursive {
		return fmt.Errorf("'%s' is a directory.\n  To encrypt it:  padlock -r %s %s",
			opts.input, opts.input, example)
	}
	if !info.IsDir() && opts.recursive {
		return fmt.Errorf("'%s' is a file; -r is only for directories", opts.input)
	}
	if len(opts.recipients) == 0 {
		return fmt.Errorf("no recipient — who should be able to open this?\n  Try:  padlock %s alice.pub\n        padlock %s 'ssh-ed25519 AAAA…'",
			opts.input, opts.input)
	}

	recipients := make([]recipientInfo, 0, len(opts.recipients)+1)
	for _, arg := range opts.recipients {
		r, err := parseRecipientArg(arg)
		if err != nil {
			return err
		}
		recipients = append(recipients, r)
	}

	idPath, err := resolveIdentityPath(opts.identityPath)
	if err != nil {
		return err
	}
	selfRecipient, selfErr := readSelfRecipient(idPath)
	if selfErr != nil && opts.identityPath != "" {
		return fmt.Errorf("read self recipient: %w", selfErr)
	}
	if selfErr == nil {
		selfRecipient.IsSelf = true
		matched := false
		for i := range recipients {
			if recipients[i].Fingerprint == selfRecipient.Fingerprint {
				recipients[i].IsSelf = true
				matched = true
				break
			}
		}
		if !matched {
			recipients = append(recipients, selfRecipient)
		}
	}

	ageRecipients := make([]age.Recipient, len(recipients))
	for i, r := range recipients {
		ageRecipients[i] = r.R
	}

	outPath := opts.outputPath
	if outPath == "" {
		outPath = defaultEncryptOutput(opts.input)
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

	encWriter, err := age.Encrypt(out, ageRecipients...)
	if err != nil {
		return fmt.Errorf("init encryption: %w", err)
	}

	if info.IsDir() {
		if err := writeDirArchive(encWriter, opts.input); err != nil {
			return fmt.Errorf("archive %s: %w", opts.input, err)
		}
	} else {
		f, err := os.Open(opts.input)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(encWriter, f)
		f.Close()
		if copyErr != nil {
			return fmt.Errorf("encrypt %s: %w", opts.input, copyErr)
		}
	}
	if err := encWriter.Close(); err != nil {
		return fmt.Errorf("finalize encryption: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close output: %w", err)
	}

	success = true

	fmt.Printf("Encrypted to %s (%s)\n", outPath, humanSize(fileSize(outPath)))
	fmt.Printf("Recipients: %s\n", recipientList(recipients))
	return nil
}

func exampleRecipient(args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	return "<recipient>"
}

func recipientList(recipients []recipientInfo) string {
	labels := make([]string, len(recipients))
	for i, r := range recipients {
		if r.IsSelf {
			labels[i] = "you (" + r.Label + ")"
		} else {
			labels[i] = r.Label
		}
	}
	return strings.Join(labels, ", ")
}
