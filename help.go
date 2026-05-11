package main

const helpText = `padlock — share files safely

  Get your public key:    padlock pubkey
  Register a recipient:   padlock recipients add alice alice.pub
  List recipients:        padlock recipients list
  Remove a recipient:     padlock recipients rm alice

  Encrypt a file:         padlock report.pdf alice
  Encrypt a directory:    padlock -r my-secrets/ alice
  Decrypt:                padlock report.pdf.padlock

  <recipient> is a registered name, a public-key string, or a path to a .pub file.
  Multiple recipients allowed: padlock file.pdf alice bob

Flags:
  -r              recursive — required when input is a directory
  -i <path>       override identity (default ~/.ssh/id_ed25519, then id_rsa)
  -o <path>       override output path
  -f              overwrite existing output (also: ` + "`padlock recipients add -f`" + `)
  -h, --help      this help

padlock uses your existing SSH key. Encrypted files are valid age files
(https://age-encryption.org/) and can be decrypted with the standard age tool.
`
