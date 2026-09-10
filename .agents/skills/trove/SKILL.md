---
name: trove
description: "Manage shared encrypted secrets in this repo with the trove Makefile: create, read, update, rotate, grant, and revoke secrets backed by AES-256-CBC + HMAC-SHA256 with per-user GPG key wrapping. USE FOR: secret, password, API key, credential, encrypt, decrypt, create-secret, read-secret, update-secret, grant-access, revoke-access, rotate-secret, list-secrets, list-users, delete-secret, new-user, add-user, generate-key, import-key, export-key, import-secret-key, GPG, AES. DO NOT USE FOR: general-purpose encryption tooling, non-secret git operations, password managers like 1Password/Bitwarden."
---

# Trove

Trove is the shared secret manager for **this repository**. It is a single `Makefile` that encrypts secrets with AES-256-CBC (random key + IV, HMAC-SHA256 integrity tag) and wraps the symmetric key per-user with GPG asymmetric encryption. Access control is the filesystem: a user can decrypt a secret if and only if their `<user>.key.enc` file exists in that secret's directory.

All commands are run via `make <target>` from the repo root. Run `make help` to see the live target list.

## Requirements

- GPG (GnuPG 2.x) — `gpg` or `gpg2`
- OpenSSL
- Bash >= 4
- xxd

Verify with:

```bash
make check-deps
```

## Layout

```
secrets/
  <secret-name>/
    secret.enc          # IV (hex) line 1, HMAC (hex) line 2, binary ciphertext after
    <user>.key.enc      # AES key wrapped for <user> via GPG (one per authorized user)
users/
  <user>.pub           # <user>'s GPG public key
.gnupg/                 # Isolated keyring holding ONLY public keys (gitignored)
```

- The isolated `.gnupg/` keyring stores public keys for wrapping. It never holds private keys.
- Decryption uses the **personal** GPG keyring at `~/.gnupg` (or `$PERSONAL_GNUPGHOME`).
- `.gitignore` excludes `.gnupg/`, `*.tmp`, and `*.secret.key` files.
- Input names are validated against `[a-zA-Z0-9._/-]` (secrets) / `[a-zA-Z0-9._@-]` (users) and reject path traversal (`..`, leading `/`).

## Identity Resolution

The current user is resolved in this order (override any time with `PM_USER=`):

1. `PM_USER` environment variable
2. `$USER@$(hostname -s)` if a matching `.pub` exists in `users/`
3. `$USER`

```bash
PM_USER=bob make read-secret NAME=dbpass
```

## Core Workflow

### First-time setup

```bash
make init                       # Create users/, secrets/, .gnupg/
make check-deps                 # Verify tools
```

### Users

```bash
# Generate a new GPG keypair and register it (keys have NO passphrase — see Security Notes)
make new-user NAME=alice

# Or register an existing public key file
make add-user NAME=alice KEY=alice.pub

# Move keys between machines
make export-key NAME=alice          # → alice.pub + alice.secret.key
make import-secret-key NAME=alice KEY=alice.secret.key
rm alice.secret.key                 # delete the exported secret immediately

# Inspect
make list-users
```

### Secrets

```bash
# Create (auto-grants access to the current user)
echo "s3cret" > /tmp/dbpass.txt
make create-secret NAME=dbpass FILE=/tmp/dbpass.txt

# Read (decrypts to stdout)
make read-secret NAME=dbpass

# Update content (re-encrypts with the SAME key — existing access is preserved)
echo "new-password" > /tmp/dbpass.txt
make update-secret NAME=dbpass FILE=/tmp/dbpass.txt

# Share / revoke
make grant-access  NAME=dbpass USER=bob
make revoke-access NAME=dbpass USER=bob

# True revocation (revoke + rotate so the revoked user's old clone can't decrypt new ciphertext)
make revoke-access NAME=dbpass USER=bob
make rotate-secret  NAME=dbpass

# Housekeeping
make list-secrets
make delete-secret NAME=dbpass
```

## Command Reference

| Target | Required Vars | Description |
|--------|---------------|-------------|
| `help` | — | Show all targets and usage |
| `check-deps` | — | Verify gpg, openssl, bash>=4, xxd |
| `init` | — | Create `users/`, `secrets/`, `.gnupg/` |
| `test` | — | Run `tests/test_trove.sh` (isolated temp GPG keys) |
| `test-crypto` | — | Crypto round-trip smoke test |
| `new-user` | `NAME=` | Generate GPG keypair + register the user |
| `generate-key` | `NAME=` (opt `EMAIL=`) | Generate a GPG keypair only |
| `import-key` | `NAME=` | Import an existing key from your personal keyring |
| `export-key` | `NAME=` (opt `DIR=`) | Export keypair to files for transfer |
| `import-secret-key` | `NAME= KEY=` | Import a GPG secret key onto this machine |
| `add-user` | `NAME= KEY=` | Register a user's GPG public key file |
| `create-secret` | `NAME= FILE=` | Encrypt a file as a named secret |
| `read-secret` | `NAME=` | Decrypt a secret to stdout |
| `update-secret` | `NAME= FILE=` | Replace content, keep existing access |
| `grant-access` | `NAME= USER=` | Give a user access to a secret |
| `revoke-access` | `NAME= USER=` | Remove a user's access (soft) |
| `rotate-secret` | `NAME=` | Re-key a secret, re-grant all current users |
| `list-secrets` | — | List secrets with access counts |
| `list-users` | — | List registered users |
| `delete-secret` | `NAME=` | Permanently delete a secret directory |

All targets validate `NAME`/`USER` against a strict charset and reject path traversal.

## Git Workflow

Trove does **not** touch git — you commit and push yourself.

```bash
# After any change to users/ or secrets/:
git add users/ secrets/
git commit -m "add dbpass secret, grant bob access"
git push
```

`.gitignore` excludes `.gnupg/`, `*.tmp`, and `*.secret.key`.

## Security Notes (read before relying on this)

- **Encrypt-then-MAC.** `secret.enc` = `IV_HEX\nHMAC_HEX\n<ciphertext>`. HMAC is verified **before** any decryption; tampered files are rejected.
- **Per-user key wrapping** uses GPG asymmetric encryption to the recipient's public key in `users/`.
- **Plaintext cleanup.** Crypto targets use `trap` to scrub temp files holding plaintext key material.
- **Soft revocation.** `make revoke-access` only deletes the user's `.key.enc`. Anyone who already cloned the repo still has the old ciphertext **and** their old wrapped key — they can decrypt indefinitely from their local clone. For real revocation, **revoke then rotate**:
  ```bash
  make revoke-access NAME=api-key USER=bob
  make rotate-secret  NAME=api-key
  git add secrets/api-key && git commit -m "revoke bob, rotate api-key"
  ```
  `rotate-secret` re-encrypts with fresh key material and re-wraps the key only for users who still have a `.key.enc`, excluding the revoked user.
- **AES key in the process table.** `openssl enc -K` requires the raw hex key on the command line, so the key briefly appears in `/proc/<pid>/cmdline` / `ps aux` during encrypt/decrypt. Fine on single-user workstations; **do not run trove on shared multi-user servers** if this is a concern.
- **Passphraseless GPG keys.** `make new-user` and `make generate-key` create keys with `--passphrase ""`. The private key in `~/.gnupg` is unprotected at rest. Intended for CI/scripts. For interactive human use on shared machines, generate keys manually with `gpg --full-generate-key` and register the pubkey with `make add-user`.
- **Secrets committed to this template repo are visible to anyone with access.** Fork/copy this repo into a private repo before storing real secrets.

## Testing

```bash
make test         # full test suite (creates isolated temp GPG keypairs)
make test-crypto  # AES + HMAC round-trip smoke test
```

The test suite never touches your real GPG keys — it uses temporary keyrings in isolation.

## Troubleshooting

- **"Current user '...' is not registered"** — run `make new-user NAME=<you>` (or `make add-user`), then retry.
- **"Access denied — user '...' does not have access"** — your `<user>.key.enc` is missing from the secret. Ask an authorized user to run `make grant-access NAME=<secret> USER=<you>`.
- **"Failed to decrypt key — check your GPG private key"** — the matching private key must be in your personal keyring (`~/.gnupg`). Import it with `make import-secret-key` or generate it on this machine with `make new-user`.
- **Wrong identity selected?** — set `PM_USER=<name>` explicitly, or ensure `users/<USER>@<host>.pub` exists for auto-detection.
- **GPG can't find the public key for wrapping** — the repo keyring is isolated at `.gnupg/`. `add-user`/`new-user` import public keys into it automatically; if a key was added by hand, re-register it.
