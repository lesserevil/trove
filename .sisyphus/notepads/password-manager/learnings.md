# Password Manager - Learnings

## Task 1: Makefile & Init Structure

### Boilerplate Pattern
- `SHELL := /bin/bash` with `.SHELLFLAGS := -eu -o pipefail -c` ensures proper error handling and pipefail
- Variables like `STORE_DIR`, `USERS_DIR`, `SECRETS_DIR`, `GNUPGHOME` enable path configuration
- `export GNUPGHOME` makes the variable available to subprocess environments (critical for GPG tools)
- TROVE_USER cascade uses `$(or ...)` for fallback logic with file existence checks

### .PHONY Declaration
- `.PHONY: check-deps init` tells Make these are not files, enabling re-runs without caching
- Essential for targets that are idempotent or don't produce files

### Idempotent Targets
- `make init` uses `mkdir -p` (creates if missing, succeeds if exists)
- `chmod 700` is safe to run repeatedly (idempotent)
- No pre-conditions mean targets can run in any order

### Dependency Checking
- `check-deps` uses `command -v` to test tool availability
- Bash version check: `[[ ${BASH_VERSINFO[0]} -lt 4 ]]` (note: must use bash -c, sh lacks this)
- Each check exits on failure via `|| (echo ... && exit 1)`

### Directory Permissions
- `.gnupg/` requires `chmod 700` (read-write-execute for owner only)
- Verified with `stat -f '%Lp'` on macOS (returns octal: 700)

### .gitignore Best Practice
- `.gnupg/` (directory with trailing slash) - ignore entire directory
- `*.tmp` (pattern) - ignore temporary files
- Both entries critical for credential store safety

## Task 2: Crypto Primitives

### OpenSSL Flags
- `-K` and `-iv`: Raw key mode (hex strings, no passphrase derivation) — critical distinction from `-pass` mode
- `-nosalt`: No salt needed with raw key mode (salt is for password-based key derivation)
- `-aes-256-cbc`: AES-256 in CBC mode — the specific cipher suite
- IV must be stored separately (first line of .enc file) so decryptor knows it

### GPG Flags
- `--batch --yes --trust-model always`: Non-interactive mode, auto-trust keys (essential for CI/automation)
- `--homedir "$(GNUPGHOME)"`: Isolated keyring for encrypt operations (public keys only)
- `--recipient-file`: Encrypt directly to a key file without importing to keyring first (convenient)
- `--pinentry-mode loopback --passphrase ""`: For test keypairs with no passphrase
- `--armor`: ASCII-armored output for key.enc files (safe for git)
- **Critical**: `_decrypt-key` does NOT use `--homedir` — it uses the user's personal GPG keyring

### Makefile Shell Patterns
- Cleanup via `trap _cleanup EXIT` inside a single `@` shell block (must be in same recipe line via `\` continuation)
- `$$` in Makefile escapes to single `$` in shell — critical for variable references
- All crypto operations within test-crypto are in a single shell block (one `@` line with `\` continuations) so variables persist
- `_PARTIAL_OUT` pattern: set before operation, clean up on failure via trap

### Test Design
- Test GPG keypair generated in `mktemp -d` with `--quick-generate-key` (fast, no user interaction)
- Export pubkey → import into repo keyring → encrypt for user → decrypt with test keyring
- SHA-256 via `shasum -a 256` for binary round-trip verification (cross-platform on macOS)
- Cleanup trap recreates clean store dirs (GNUPGHOME, USERS_DIR, SECRETS_DIR) after test

### Gotchas
- GPG may not be installed by default on macOS — `brew install gnupg` required
- `gpg` vs `gpg2` naming: modern brew installs as `gpg` (GnuPG 2.4.x)
- Binary files with newlines: `head -1` / `tail -n +2` pattern works because IV line is pure hex (no binary)
- The test-crypto target must handle both text and binary in the same run to prove content-agnostic encryption

## Task 3: Core Trio (add-user, create-secret, read-secret)

### CRITICAL: GNUPGHOME Export Gotcha
- The Makefile has `export GNUPGHOME` (line 9) which makes ALL child processes use the isolated keyring
- `read-secret` must decrypt the symmetric key using the user's PERSONAL GPG keyring (not the isolated one)
- **Fix**: Use `unset GNUPGHOME;` before the GPG decrypt command in the recipe shell block
- Same fix applied to `_decrypt-key` primitive: `GNUPGHOME= gpg ...` (set to empty = use default ~/.gnupg)
- This was the #1 bug — encryption worked fine, but decryption silently failed with "No secret key"

### Input Validation Patterns
- User names: `^[a-zA-Z0-9._@-]+$` (allows @ for user@host identities)
- Secret names: `^[a-zA-Z0-9._-]+$` (NO @ or / — stricter than user names)
- In Makefile: `echo "$(NAME)" | grep -qE '^[a-zA-Z0-9._-]+$$'` (note `$$` → shell `$`)
- Validation runs as separate `@` lines BEFORE the main shell block — fails fast

### Error Handling Pattern
- Each validation as a separate `@` recipe line: `@test -n "$(VAR)" || { echo "Error: ..." >&2; exit 1; }`
- Main crypto logic in a single `@` shell block with `\` continuations
- `trap _cleanup EXIT` for temp directory cleanup
- On crypto failure, `rm -rf "$$SECRET_DIR"` to avoid leaving partial state

### Target Structure Pattern
```
target:
    @<validation 1>
    @<validation 2>
    @<validation N>
    @<main shell block with trap, crypto ops, success message>
```

### create-secret Flow
1. Validate NAME, FILE params
2. Check secret doesn't already exist (reject duplicates)
3. Check current user is registered
4. Generate AES key + IV (openssl rand)
5. Encrypt content (IV first line + ciphertext)
6. Encrypt symmetric key for creator (GPG with --recipient-file)
7. Print success message

### read-secret Flow
1. Validate NAME
2. Check secret exists
3. Check user has access (*.key.enc file exists)
4. Decrypt symmetric key (personal GPG, GNUPGHOME unset)
5. Decrypt content (IV from first line, openssl)
6. Output raw bytes to stdout

### Gotchas
- `gpg --show-keys` validates a GPG public key file — good for add-user
- `test ! -d` to check directory does NOT exist (for duplicate prevention)
- `test -r` to check file readability (separate from existence check)
- The `echo "success message"` at end of create-secret goes to stdout, but read-secret must NOT echo anything extra — only raw decrypted content
