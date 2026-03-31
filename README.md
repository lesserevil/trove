# Trove

> **DO NOT store secrets in this repository directly.** This repo is a template. Fork it (or copy it) into your own private repo, then use that as your team's trove. Secrets committed here are visible to everyone with access to the original repo.

A shared secret manager built on Make, GPG, and AES-256 — backed by git.

Each secret is a directory containing the AES-encrypted content and per-user GPG-encrypted copies of the symmetric key. Access control is the filesystem: if `secrets/myapp/alice.key.enc` exists, Alice can decrypt `myapp`.

## How It Works

```
secrets/
  api-key/
    secret.enc          # AES-256-CBC encrypted content (IV on first line)
    alice.key.enc       # Symmetric key encrypted with Alice's GPG public key
    bob.key.enc         # Same symmetric key encrypted with Bob's GPG public key
users/
  alice.pub             # Alice's GPG public key
  bob.pub               # Bob's GPG public key
```

- Content is encrypted with a random AES-256 key + IV
- The AES key is wrapped per-user with GPG (asymmetric)
- Decryption uses the user's personal GPG private key (`~/.gnupg`)
- An isolated GPG keyring (`.gnupg/`) stores public keys only — your personal keyring is never touched for imports

## Requirements

- GPG (GnuPG 2.x)
- OpenSSL
- Bash >= 4
- xxd

```
make check-deps
```

## Quick Start

```bash
# Initialize the directory structure
make init

# Set up yourself as a user (generates a GPG keypair if needed)
make new-user NAME=alice

# Or register an existing GPG public key
make add-user NAME=alice KEY=alice.pub

# Create a secret (auto-grants access to you)
echo "s3cret" > /tmp/dbpass.txt
make create-secret NAME=dbpass FILE=/tmp/dbpass.txt

# Read it back
make read-secret NAME=dbpass

# Share with a teammate
make grant-access NAME=dbpass USER=bob

# Revoke access
make revoke-access NAME=dbpass USER=bob

# Housekeeping
make list-secrets
make list-users
make delete-secret NAME=dbpass
```

## Updating a Secret

To replace a secret's content, use `update-secret`. This re-encrypts with the same symmetric key (only the IV changes), so all existing user access remains valid — no need to re-grant.

```bash
echo "new-password-456" > /tmp/dbpass.txt
make update-secret NAME=dbpass FILE=/tmp/dbpass.txt
```

## Moving Keys Between Machines

Export a keypair from one machine and import it on another — no manual GPG commands needed.

```bash
# On the old machine: export the keypair to files
make export-key NAME=alice
# → alice.pub + alice.secret.key

# Copy both files to the new machine, then:
make import-secret-key NAME=alice KEY=alice.secret.key

# Delete the secret key file immediately after import
rm alice.secret.key
```

The `.gitignore` blocks `*.secret.key` files, but don't rely on that — delete them after transfer.

## User Identity

Trove resolves the current user in this order:

1. `PM_USER` environment variable (if set)
2. `$USER@$(hostname -s)` (if a matching `.pub` exists in `users/`)
3. `$USER`

Override for any command: `PM_USER=bob make read-secret NAME=dbpass`

## Commands

| Command | Description |
|---------|-------------|
| `make help` | Show all targets and usage examples |
| `make check-deps` | Verify required tools are installed |
| `make init` | Create directory structure (`.gnupg/`, `users/`, `secrets/`) |
| `make new-user NAME=` | Generate GPG keypair and register the user |
| `make generate-key NAME=` | Generate a GPG keypair (optional `EMAIL=`) |
| `make import-key NAME=` | Import an existing key from your GPG keyring |
| `make export-key NAME=` | Export a user's keypair to files for transfer (optional `DIR=`) |
| `make import-secret-key NAME= KEY=` | Import a GPG secret key onto this machine |
| `make add-user NAME= KEY=` | Register a user's GPG public key file |
| `make create-secret NAME= FILE=` | Encrypt a file as a named secret |
| `make read-secret NAME=` | Decrypt a secret to stdout |
| `make update-secret NAME= FILE=` | Update a secret's content (keeps existing access) |
| `make grant-access NAME= USER=` | Give a user access to a secret |
| `make revoke-access NAME= USER=` | Remove a user's access to a secret |
| `make rotate-secret NAME=` | Re-key a secret and re-grant all current users |
| `make list-secrets` | List all secrets with access counts |
| `make list-users` | List all registered users |
| `make delete-secret NAME=` | Permanently delete a secret |

## Git Workflow

Trove doesn't touch git — you manage commits yourself.

```bash
# After adding a user or creating/sharing a secret:
git add users/ secrets/
git commit -m "add dbpass secret, grant bob access"
git push
```

The `.gitignore` excludes `.gnupg/` (isolated keyring), `*.tmp` files, and `*.secret.key` files.

## Tests

```bash
make test
# or directly:
bash tests/test_trove.sh
```

The test suite creates temporary GPG keypairs in isolation — your real keys are never used.

## Security Notes

- Symmetric keys are AES-256-CBC with random IV (prepended to ciphertext)
- Per-user key wrapping uses GPG asymmetric encryption
- All operations use `trap` cleanup to remove plaintext key material from temp files
- Input names are validated against `[a-zA-Z0-9._@-]` to prevent path traversal
- `*.secret.key` files are gitignored, but you should still delete them after transfer
- Revocation is **soft**: deleting a user's `.key.enc` prevents future decryption but does not invalidate copies they already cloned. See below.

### Revoking access — rotate the key too

`make revoke-access` only removes the user's copy of the encrypted key. Anyone who cloned the repo before revocation still has their copy and can still decrypt `secret.enc` from their local clone indefinitely.

For true revocation, rotate the secret immediately after revoking:

```bash
make revoke-access NAME=api-key USER=bob
make rotate-secret NAME=api-key
git add secrets/api-key && git commit -m "revoke bob, rotate api-key"
```

`make rotate-secret` decrypts the current content, generates fresh key material, re-encrypts, and re-wraps the key for every user who still has a `.key.enc` file — excluding the just-revoked user. Bob's old clone can still decrypt the old ciphertext, but the new ciphertext in the repo is protected by a key Bob has never seen.

### AES key visible in process table during encrypt/decrypt

`openssl enc` requires the raw AES key to be passed via the `-K` flag, which means the key hex value appears in `/proc/<pid>/cmdline` for the duration of the openssl process. On Linux, any local user can read this with `ps aux` or directly from `/proc`.

- **Single-user workstation:** Non-issue — you are the only local user.
- **Shared server:** Any co-located user can briefly observe the key. **Do not use trove on a shared multi-user server** if this is a concern, or accept the risk given the short exposure window.

This is an inherent limitation of `openssl enc -K`. Passing the key via an environment variable or a file descriptor is not supported for the `-K` (raw hex key) interface — it only accepts a command-line argument.

### GPG keys are generated without a passphrase

`make new-user` and `make generate-key` both use `--passphrase ""` to create GPG keys with **no passphrase**. This means:

- The private key in `~/.gnupg` is **unprotected at rest** — anyone with filesystem access to that directory can use it to decrypt secrets without any further authentication.
- This is intentional for non-interactive use cases (CI, scripts), but is a poor choice for interactive human users on shared or multi-user machines.

If you want passphrase-protected keys, generate the keypair manually with `gpg --full-generate-key`, then register it with `make add-user NAME=alice KEY=alice.pub`. The rest of the workflow is unchanged; GPG will prompt for your passphrase at decrypt time.
