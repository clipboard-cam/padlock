# padlock

Share files safely using SSH keys you already have.

`padlock` is a small CLI that wraps [age](https://age-encryption.org/) encryption with SSH-key ergonomics, so engineers can send sensitive files over Slack/email/wherever without learning PKI vocabulary.

```
$ padlock pubkey
ssh-ed25519 AAAA… cam@laptop

$ padlock secret.txt alice.pub
Encrypted to secret.txt.padlock (337 B)
Recipients: alice@laptop, you (cam@laptop)

$ padlock secret.txt.padlock
Decrypted to secret.txt
```

Encryption and decryption use the same SSH key already sitting in `~/.ssh/`. No new key types, no key servers, nothing to install on the recipient's side beyond `padlock` itself.

## Install

```sh
go install github.com/clipboard-cam/padlock@latest
```

Or build from source:

```sh
git clone https://github.com/clipboard-cam/padlock
cd padlock && go build -o padlock .
```

The result is a single static binary; drop it anywhere on `$PATH`.

## Quick start

**1. Share your public key.**

```sh
padlock pubkey
# Paste the line into Slack/email so others can encrypt to you.
```

**2. Encrypt something for a teammate.**

```sh
padlock secret.txt 'ssh-ed25519 AAAA… alice@laptop'
# or, given their .pub file:
padlock secret.txt alice.pub
```

The recipient runs `padlock secret.txt.padlock` to decrypt. You can decrypt the same file too — padlock always adds you as a recipient so you don't lock yourself out.

**3. Encrypt a directory.**

```sh
padlock -r my-secrets/ alice.pub
# Produces my-secrets.padlock. The recipient decrypts into a directory.
```

## Address book

Register frequently-used recipients once and reference them by name:

```sh
padlock recipients add alice alice.pub
padlock recipients add bob 'ssh-ed25519 AAAA… bob@desktop'
padlock recipients list

padlock secret.txt alice            # alice resolves from the address book
padlock secret.txt alice bob        # multiple recipients in one file
padlock recipients rm alice
```

Stored at `~/.config/padlock/recipients` (or `$XDG_CONFIG_HOME/padlock/recipients`), mode 0600, in an authorized_keys-style format with a leading name — hand-editable and greppable.

## CLI reference

```
padlock pubkey                          Print your public key
padlock recipients add <name> <key>     Register a recipient (key or .pub path)
padlock recipients list                 Show registered recipients
padlock recipients rm <name>            Remove a recipient

padlock <file> <recipient>...           Encrypt to one or more recipients
padlock -r <dir> <recipient>...         Encrypt a directory
padlock <encrypted-file>                Decrypt (auto-detected from input)
```

A `<recipient>` is one of:

- a registered name from the address book
- a raw public-key string (`ssh-ed25519 AAAA…`)
- a path to a `.pub` file

Flags:

```
-r            recursive — required when the input is a directory
-i <path>     override identity (default: ~/.ssh/id_ed25519, then id_rsa)
-o <path>     override output path
-f            overwrite existing output (also: padlock recipients add -f)
```

## Supported key types

| Key type      | Supported | Notes              |
|---------------|-----------|--------------------|
| ed25519       | yes       | recommended        |
| RSA           | yes       |                    |
| ECDSA         | no        | age limitation     |
| DSA           | no        | age limitation     |
| Hardware sk-* | no        | age limitation     |

If a recipient has an unsupported key, ask them to generate an ed25519 one:

```sh
ssh-keygen -t ed25519
```

## Under the hood

- Recipients and identities are real SSH keys parsed via `golang.org/x/crypto/ssh`.
- Encryption is [age](https://github.com/FiloSottile/age). The output is a standard age file and can be decrypted with the regular `age` CLI given the same SSH key (`age -d -i ~/.ssh/id_ed25519 secret.txt.padlock`).
- Directories are streamed as `tar+gzip` inside the encrypted blob, with a `PADLOCK-DIR-1` framing header so plaintext files that happen to start with gzip's magic bytes aren't misread as archives on decrypt.
- Encrypt never reads your private key — only the `.pub` next to it — so it never prompts for an SSH passphrase. Decrypt does need the private key, and prompts on `/dev/tty` if it's passphrase-protected.

## Limitations

- No stdin/stdout streaming — input must be a file path.
- One flat recipient list per file; no groups or aliases yet.
- Symlinks are skipped on encrypt (encrypting arbitrary symlink targets is a footgun).
- Linux/macOS only in practice; Windows behaviour around symlinks and permissions is untested.
