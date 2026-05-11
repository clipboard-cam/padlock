package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// nameRegexp enforces sensible names on `recipients add`. Lookups accept
// any string (so a typo gets a friendly error instead of silent fallback).
var nameRegexp = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

type addressEntry struct {
	Name    string
	KeyLine string // an authorized_keys line, no leading name
}

func addressBookPath() (string, error) {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "padlock", "recipients"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "padlock", "recipients"), nil
}

// loadAddressBook returns the address book entries. A missing file is not
// an error — returns (nil, nil).
func loadAddressBook() ([]addressEntry, error) {
	path, err := addressBookPath()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var entries []addressEntry
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, rest, ok := splitNameAndKey(line)
		if !ok {
			return nil, fmt.Errorf("%s:%d: malformed entry", path, lineNo)
		}
		entries = append(entries, addressEntry{Name: name, KeyLine: rest})
	}
	return entries, sc.Err()
}

func splitNameAndKey(line string) (name, rest string, ok bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", "", false
	}
	name = fields[0]
	rest = strings.TrimSpace(strings.TrimPrefix(line, name))
	return name, rest, true
}

func saveAddressBook(entries []addressEntry) error {
	path, err := addressBookPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })

	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	for _, e := range entries {
		if _, err := fmt.Fprintf(w, "%s %s\n", e.Name, e.KeyLine); err != nil {
			f.Close()
			os.Remove(tmp)
			return err
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

func addAddressBookEntry(name, keyLine string, force bool) error {
	if !nameRegexp.MatchString(name) {
		return fmt.Errorf("recipient name %q must match [A-Za-z0-9._-]+", name)
	}
	// Parse the key now so we never persist garbage and so unsupported
	// key types get the same friendly rejection as inline recipients.
	if _, err := parseSSHRecipient(keyLine); err != nil {
		return fmt.Errorf("invalid key for %q: %w", name, err)
	}
	entries, err := loadAddressBook()
	if err != nil {
		return err
	}
	for i, e := range entries {
		if e.Name == name {
			if !force {
				return fmt.Errorf("recipient %q already exists; use -f to overwrite", name)
			}
			entries[i].KeyLine = keyLine
			return saveAddressBook(entries)
		}
	}
	entries = append(entries, addressEntry{Name: name, KeyLine: keyLine})
	return saveAddressBook(entries)
}

func removeAddressBookEntry(name string) error {
	entries, err := loadAddressBook()
	if err != nil {
		return err
	}
	for i, e := range entries {
		if e.Name == name {
			entries = append(entries[:i], entries[i+1:]...)
			return saveAddressBook(entries)
		}
	}
	return fmt.Errorf("no recipient named %q", name)
}

// resolveAddressBookKeyLine returns the authorized_keys line for the named
// recipient, or (zero, false, nil) if there is no match.
func resolveAddressBookKeyLine(name string) (string, bool, error) {
	entries, err := loadAddressBook()
	if err != nil {
		return "", false, err
	}
	for _, e := range entries {
		if e.Name == name {
			return e.KeyLine, true, nil
		}
	}
	return "", false, nil
}

func runRecipients(args []string) error {
	if len(args) == 0 {
		return listRecipients()
	}
	switch args[0] {
	case "list", "ls":
		if len(args) != 1 {
			return fmt.Errorf("recipients list takes no arguments")
		}
		return listRecipients()
	case "add":
		return runRecipientsAdd(args[1:])
	case "rm", "remove":
		if len(args) != 2 {
			return fmt.Errorf("usage: padlock recipients rm <name>")
		}
		return removeAddressBookEntry(args[1])
	default:
		return fmt.Errorf("unknown subcommand %q\n  Try:  padlock recipients add <name> <key-or-pubpath>\n        padlock recipients list\n        padlock recipients rm <name>", args[0])
	}
}

func listRecipients() error {
	entries, err := loadAddressBook()
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		fmt.Println("No recipients registered. Add one with:")
		fmt.Println("  padlock recipients add alice alice.pub")
		return nil
	}
	for _, e := range entries {
		fields := strings.Fields(e.KeyLine)
		if len(fields) >= 3 {
			fmt.Printf("%s  (%s)\n", e.Name, strings.Join(fields[2:], " "))
		} else {
			fmt.Println(e.Name)
		}
	}
	return nil
}

func runRecipientsAdd(args []string) error {
	fs := flag.NewFlagSet("recipients add", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var force bool
	fs.BoolVar(&force, "f", false, "overwrite existing entry")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 2 {
		return fmt.Errorf("usage: padlock recipients add [-f] <name> <key-or-pubpath>")
	}
	keyLine, err := readRecipientSource(rest[1])
	if err != nil {
		return err
	}
	if err := addAddressBookEntry(rest[0], keyLine, force); err != nil {
		return err
	}
	fmt.Printf("Added %s\n", rest[0])
	return nil
}

// readRecipientSource accepts either a raw SSH key string or a path to a
// .pub file, and returns the trimmed authorized_keys line.
func readRecipientSource(src string) (string, error) {
	if isSSHKeyPrefix(src) {
		return strings.TrimSpace(src), nil
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return "", fmt.Errorf("read %q: %w", src, err)
	}
	return strings.TrimSpace(string(data)), nil
}

func isSSHKeyPrefix(s string) bool {
	return strings.HasPrefix(s, "ssh-") || strings.HasPrefix(s, "ecdsa-") || strings.HasPrefix(s, "sk-")
}
