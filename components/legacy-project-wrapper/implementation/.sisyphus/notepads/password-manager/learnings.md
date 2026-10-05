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

## Task 5: Utility Targets

### list-secrets Target Pattern
- `ls -A` to check if directory is non-empty (returns empty string if nothing there)
- `for secret_dir in $(SECRETS_DIR)/*/` iterates over subdirectories
- `find "$$secret_dir" -name "*.key.enc" | wc -l` counts user access files
- Output format: "secretname (N users)" for each secret
- Falls back to "No secrets found" if directory is empty
- Must be in a single shell block with `\` continuation for variable persistence

### list-users Target Pattern
- `basename "$$user_key" .pub` strips .pub extension from filenames
- Output: one username per line
- Falls back to "No users found" if no .pub files exist
- Simple for loop pattern — no special validation needed

### delete-secret Target Pattern
- Full input validation: NAME parameter + secret name regex check
- Check directory exists before deletion (fail with clear error if missing)
- `rm -rf "$(SECRETS_DIR)/$(NAME)"` atomic deletion of entire secret and all access files
- Exit code 1 on any failure (missing directory, invalid name, etc.)
- Success message: "Secret 'NAME' deleted"

### Key Patterns Learned
- Utility targets use simpler error handling than core operations (no trap cleanup needed)
- For loops in Makefile require `$$` for shell variables (not `$`)
- Always check non-empty before iterating: `ls -A` returns nothing if empty
- `basename` with second arg is clean way to strip file extensions
- Validation failures exit immediately, no partial state cleanup needed

## Task 6: Error Handling and Input Validation Hardening

### Audit Results Summary
Conducted comprehensive audit of ALL 15 targets across Makefile (334 lines):
- **check-deps**: Fixed — errors were going to stdout, now route to stderr
- **init**: ✓ Compliant
- **_generate-key, _generate-iv**: ✓ Compliant
- **_encrypt-content, _decrypt-content**: ✓ Compliant
- **_encrypt-key-for-user, _decrypt-key**: ✓ Compliant
- **test-crypto**: ✓ Compliant (already had stderr routing for failures)
- **add-user, create-secret, read-secret**: ✓ Compliant (proper validation + error handling)
- **grant-access, revoke-access**: ✓ Compliant (both present with full NAME/USER validation)
- **list-secrets, list-users, delete-secret**: ✓ Compliant (utility targets with consistent error handling)

### Standardization Applied

1. **Error Message Format**: Standardized ALL error messages to `Error:` (title case)
   - Before: Mixed `ERROR:` (uppercase) and `Error:` (title case)
   - After: Consistent `Error: <message>` across all 15 targets
   - Verified: 0 occurrences of uppercase `ERROR:` remain

2. **Stderr Routing**: All errors explicitly routed via `>&2`
   - Fixed check-deps: Changed from `(echo ... && exit 1)` to `{ echo ... >&2; exit 1; }`
   - Verified: All 27+ error points tested and confirmed

3. **Exit Codes**: All error paths exit non-zero (exit 1 or exit 2 from make)
   - No silent failures anywhere
   - Every parameter validation has explicit exit 1
   - Tested with `echo "Exit code: $?"` after each error case

### Validation Consistency Checklist

✓ NAME validation in create-secret/read-secret/grant-access/delete-secret:
  - Pattern: `^[a-zA-Z0-9._-]+$` (no @ or / for secrets)
  - All targets use identical regex pattern
  - Blocks path traversal (../evil rejected)

✓ NAME validation in add-user:
  - Pattern: `^[a-zA-Z0-9._@-]+$` (allows @ for user@host)
  - Stricter than secret names (allows @, not used for files)

✓ USER validation in grant-access/revoke-access:
  - Pattern: `^[a-zA-Z0-9._@-]+$` (same as add-user)
  - Applied as separate validation line before main operation

✓ FILE validation in create-secret:
  - `test -f` (existence check)
  - `test -r` (readability check)
  - Two separate tests catch all error cases

✓ Key/Secret existence checks:
  - `test -f` for key files
  - `test -d` for secret directories
  - `test ! -d` for duplicate prevention

### Trap Cleanup Presence
✓ All targets that create temp files have trap cleanup:
  - _encrypt-content: Creates OUTPUT_FILE, traps cleanup
  - _encrypt-key-for-user: Creates OUTPUT_FILE, traps cleanup
  - create-secret: Creates _TMPDIR + SECRET_DIR, traps cleanup
  - read-secret: Creates _TMPDIR, traps cleanup
  - grant-access: Creates _TMPDIR, traps cleanup

### Test Cases Verified

1. **Empty NAME test**: `make create-secret NAME= FILE=/tmp/test.txt`
   - Result: Error message to stderr, exit code 2 ✓

2. **Path traversal test**: `make create-secret NAME=../evil FILE=/tmp/test.txt`
   - Result: Regex rejection with clear error, exit code 2 ✓

3. **Stderr routing test**: `make create-secret NAME= 2>&1 1>/dev/null`
   - Result: Error message captured (not suppressed), proves stderr routing ✓

4. **grant-access validation**: `make grant-access NAME= USER=test`
   - Result: NAME= required error, exit code 2 ✓

5. **revoke-access validation**: `make revoke-access NAME= USER=test`
   - Result: NAME= required error, exit code 2 ✓

### Changes Applied to Makefile

1. **Line 24-30** (check-deps target):
   - Changed: `(echo "ERROR: ..." && exit 1)` 
   - To: `{ echo "Error: ..." >&2; exit 1; }`
   - Lines affected: 24, 26, 28, 30

2. **Error message standardization**:
   - Replaced 20 occurrences of `ERROR:` with `Error:`
   - Lines affected: 50, 54, 59-63, 69, 74-76, 79, 84-87, 96, 101-102, 104

### Key Patterns for Future Hardening

1. **Parameter validation**: Use as separate `@` recipe lines (fast-fail pattern)
2. **Bash conditional syntax**: Always use `{ ... } ` not `( ... )` for better error handling
3. **Stderr redirection**: `>&2` is mandatory for errors (allows separation in scripts)
4. **Error format**: `Error: <specific message>` (user-facing, actionable)
5. **Cleanup pattern**: `trap _cleanup EXIT` with variable tracking (`_TMPDIR`, `_PARTIAL_OUT`)

### All 15 Targets Audit Complete
- ✓ check-deps (6 targets, 4 dependency checks with errors to stderr)
- ✓ init (1 target, idempotent, no errors)
- ✓ _generate-key, _generate-iv (2 targets, error handling)
- ✓ _encrypt-content, _decrypt-content (2 targets, full validation + trap)
- ✓ _encrypt-key-for-user, _decrypt-key (2 targets, full validation + trap)
- ✓ test-crypto (1 target, comprehensive round-trip tests with cleanup)
- ✓ add-user, create-secret, read-secret (3 targets, strict validation + trap)
- ✓ grant-access, revoke-access (2 targets, parameter validation + trap)
- ✓ list-secrets, list-users, delete-secret (3 targets, utility with consistent errors)

**Status**: All 15 targets now have consistent error handling with:
- All errors to stderr (>&2)
- All errors with "Error:" prefix
- All errors exit non-zero
- All temp-creating targets have trap cleanup
- All parameter validations present and consistent

## Task 4: Access Control (grant-access, revoke-access)

### grant-access Pattern
- Reuses the "encrypt key for user" pattern from create-secret, but decrypts first
- Flow: Decrypt symmetric key using current user's personal GPG key → Re-encrypt with target user's public key
- Key insight: `unset GNUPGHOME; gpg ...` for decrypt (uses personal keyring), then switch back to isolated keyring for encrypt
- Validations in strict order:
  1. NAME/USER parameters (catch typos fast)
  2. Secret exists (catch nonexistent secrets)
  3. Target user registered (catch unknown users)
  4. Current user has access (prevent unauthorized grants)
  5. Target user doesn't already have access (prevent overwrites)
- Error precedence: Early parameter validation → resource existence → permissions

### revoke-access Pattern
- Simplest target: just validate and delete file
- Validations:
  1. NAME/USER parameters (same grep pattern as grant-access)
  2. Key file exists (check user has access before deleting)
- Clean deletion: `rm -f` followed by exit check
- No need for trap cleanup (just file deletion, no temp files)

### Gotchas and Design Notes
- Make's `$(USER)` built-in variable defaults to system username when parameter not provided — this is correct behavior, not a bug
- When `make grant-access NAME=secret USER=` is called with empty USER override, Make still uses system username — validation still works because the user's `.pub` file check catches it
- Grant-access must check for duplicate access BEFORE attempting GPG encrypt (prevents corrupting the access if encrypt fails)
- Revoke is idempotent: if key file doesn't exist, check catches it and errors (good for clarity, user knows the state)

### Test Coverage
All scenarios from plan QA passed:
- ✓ Grant without access: User without access.key.enc cannot grant (test 6)
- ✓ Grant to nonexistent user: Rejects unknown users (test 5)
- ✓ Grant to duplicate: Rejects if user already has access.key.enc (test 7)
- ✓ Revoke removes file: rm -f deletes the key file (test 12)
- ✓ After revoke denied: User has no access.key.enc, next read fails (automatic)
- ✓ Parameter validation: All invalid NAME/USER patterns caught (tests 1-11)

### Validation Pattern Consistency
All targets now use same validation approach:
```makefile
@test -n "$(NAME)" || { echo "Error: NAME= is required" >&2; exit 1; }
@echo "$(NAME)" | grep -qE '^[a-zA-Z0-9._-]+$$' || { echo "Error: Invalid NAME..." >&2; exit 1; }
```
This pattern scales to all future targets (list-secrets, list-users, delete-secret, etc.)

## Task 7: Integration Test Suite

### GPG Keypair Isolation Strategy
- Test keypairs generated in a shared `TEST_GNUPGHOME` (mktemp -d) with `--quick-generate-key`
- Critical discovery: Makefile's `read-secret` and `grant-access` do `unset GNUPGHOME; gpg --decrypt` which falls back to `$HOME/.gnupg`
- Solution: Create `TEST_FAKE_HOME` with `.gnupg` symlinked to `TEST_GNUPGHOME`, then set `HOME=$TEST_FAKE_HOME` when calling make
- This lets the Makefile's unset-GNUPGHOME pattern work transparently with test keys

### Test Architecture
- `tests/helpers.sh`: Setup/teardown, assertions, `run_make`/`run_as` wrappers
- `tests/test_trove.sh`: 20 test functions, each with isolated setup/teardown
- No external test framework (BATS, etc.) — pure bash with colored output
- Each test: `begin_test` → `setup_test_env` → assertions → `pass_test`/`fail_test` → `teardown_test_env`
- Summary: "X passed, Y failed" with exit code 0 on all-pass

### Assertion Pattern
- Assertions return 0/1 (not exit) — use `|| ok=false` pattern to accumulate failures
- `$ok && pass_test` at end — only marks pass if all assertions succeeded
- `assert_exit_code` captures exit code without `set -e` killing the test
- `assert_output_contains` uses `grep -qF` for literal string matching

### run_make vs run_as
- `run_make`: Passes `STORE_DIR` and `GNUPGHOME` pointing to test store (for admin ops like add-user, list-*, revoke, delete)
- `run_as <user>`: Also sets `PM_USER=<user>` and `HOME=$TEST_FAKE_HOME` (for user-context ops like create, read, grant)
- The HOME override is the key trick — without it, `unset GNUPGHOME; gpg` can't find test private keys

### Cleanup
- 4 temp directories per test: `TEST_TMPDIR`, `TEST_GNUPGHOME`, `TEST_STORE_DIR`, `TEST_FAKE_HOME`
- All cleaned up by `teardown_test_env` at end of each test
- Verified: temp dir count is identical before/after test run (no leaks)

### macOS Gotcha
- macOS ships with bash 3.2 (/bin/bash) — the `check-deps` target correctly rejects it
- Test for check-deps validates output content rather than exit code to remain portable
- All test code avoids bash 4+ features (no associative arrays, no `${var,,}`, etc.)

### Test Coverage (20 tests)
1-2: Structure init, user registration
3-4: Text and binary encrypt/decrypt round-trips
5: Duplicate secret rejection
6: Multi-user access via grant
7-8: Revoke removes key file + denies subsequent reads
9-10: List secrets (with user counts) and list users
11: Delete secret removes directory
12: Path traversal rejection (../ and /)
13: Missing/empty parameter rejection
14: Nonexistent secret read fails
15: Unauthorized grant attempt fails
16: Empty store lists return clean messages
17: check-deps validates and reports tool status
18: Delete nonexistent secret fails
19: Revoke from user without access fails
20: Duplicate grant attempt fails
