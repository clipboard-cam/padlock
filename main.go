package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "padlock: %s\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Print(helpText)
		return nil
	}

	switch args[0] {
	case "-h", "--help", "help":
		fmt.Print(helpText)
		return nil
	case "pubkey":
		return runPubkey(args[1:])
	}

	return runDefault(args)
}

func runPubkey(args []string) error {
	fs := flag.NewFlagSet("pubkey", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("pubkey takes no arguments")
	}
	idPath, err := resolveIdentityPath("")
	if err != nil {
		return err
	}
	data, err := os.ReadFile(pubkeyPathFor(idPath))
	if err != nil {
		return fmt.Errorf("read public key: %w", err)
	}
	fmt.Print(string(data))
	return nil
}

func runDefault(args []string) error {
	fs := flag.NewFlagSet("padlock", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		recursive bool
		identity  string
		output    string
		force     bool
	)
	fs.BoolVar(&recursive, "r", false, "recursive — required for directory input")
	fs.StringVar(&identity, "i", "", "override identity path")
	fs.StringVar(&output, "o", "", "override output path")
	fs.BoolVar(&force, "f", false, "overwrite existing output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Print(helpText)
		return nil
	}

	input := rest[0]
	recipientArgs := rest[1:]

	info, err := os.Stat(input)
	if err != nil {
		return fmt.Errorf("input: %w", err)
	}

	encrypted := false
	if !info.IsDir() {
		encrypted, err = looksEncrypted(input)
		if err != nil {
			return fmt.Errorf("input: %w", err)
		}
	}

	if encrypted {
		if len(recipientArgs) > 0 {
			return fmt.Errorf("'%s' looks already encrypted.\n  To decrypt:        padlock %s\n  To re-encrypt:     decrypt first, then encrypt to the new recipient",
				input, input)
		}
		if recursive {
			return fmt.Errorf("-r is only valid when encrypting a directory")
		}
		return runDecrypt(decryptOptions{
			input:        input,
			identityPath: identity,
			outputPath:   output,
			force:        force,
		})
	}

	return runEncrypt(encryptOptions{
		input:        input,
		recipients:   recipientArgs,
		recursive:    recursive,
		identityPath: identity,
		outputPath:   output,
		force:        force,
	})
}
