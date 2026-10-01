# Trove — Shared Secret Manager (Makefile + GPG)

## TL;DR

> **Quick Summary**: Build "Trove", a shared CLI secret manager using a Makefile + GPG + AES-256, backed by a git repo. Each secret gets a directory containing the encrypted content and per-user encrypted symmetric keys, enabling fine-grained access control via GPG public keys.
> 
> **Deliverables**:
> - `~/src/trove/Makefile` — all crypto operations as Make targets
> - `~/src/trove/.gitignore` — excludes temp files, isolated keyring
> - `~/src/trove/tests/` — shell-based integration test suite
> - Working targets: `init`, `check-deps`, `add-user`, `create-secret`, `read-secret`, `grant-access`, `revoke-access`, `list-secrets`, `list-users`, `delete-secret`
> 
> **Estimated Effort**: Medium
> **Parallel Execution**: YES — 2 waves (foundation sequential, then targets parallel)
> **Critical Path**: Task 1 → Task 2 → Task 3 → Task 4 → Task 5 (crypto core must be proven before targets)

---

## Context

### Original Request
Build a shared password/secret manager. All encrypted secrets stored in a git repo. Each secret gets a directory with the secret encrypted using a random symmetric key, plus per-user files containing the symmetric key encrypted with that user's public GPG key. Users and their public keys listed elsewhere in the repo.

### Interview Summary
**Key Discussions**:
- **Application type**: CLI tool, Makefile + GPG — Unix philosophy
- **Storage model**: One directory per secret in `secrets/`, one `.pub` per user in `users/`
- **Crypto**: AES-256 symmetric for content, GPG asymmetric for per-user key wrapping
- **Secret content**: Arbitrary bytes — text, images, JSON, binary. Content-agnostic.
- **Identity**: Cascading resolution: `$PM_USER` env → `$USER@$(hostname -s)` → `$USER`
- **Git**: Manual — Makefile only handles crypto, user handles git
- **Revocation**: MVP uses simple delete of `.key.enc`; full re-key is future work
- **Tests**: Shell-based integration tests with temporary GPG keys
- **Working directory**: `~/src/trove`

### Metis Review
**Identified Gaps** (all addressed below):
- GPG not currently installed on system — need `check-deps` target
- BATS not installed — need test framework setup
- macOS/BSD tool differences (`base64 -D` vs `-d`, `mktemp`, `sed -i ''`) — use `openssl base64` and `xxd`
- AES mode and IV handling not specified — pinned to CBC with prepended IV
- GPG keyring isolation needed — use `GNUPGHOME` per-repo
- Input validation for path traversal attacks — validate all params
- `create-secret` must auto-grant creator access
- `create-secret` on existing name must error
- Temp file cleanup for plaintext key material — use `trap`
- Error handling in Makefile recipes — use `bash -euo pipefail`
- Binary round-trip testing required — not just text
- `gpg --trust-model always --batch --yes` required for non-interactive use

---

## Work Objectives

### Core Objective
Build a working shared secret manager where multiple users/services can securely share secrets via a git repo, with per-secret access control enforced by public-key cryptography.

### Concrete Deliverables
- `~/src/trove/Makefile` — complete with all targets
- `~/src/trove/.gitignore` — excludes `.gnupg/`, `*.tmp`
- `~/src/trove/tests/test_trove.sh` — integration test suite
- `~/src/trove/tests/helpers.sh` — test helper functions (GPG key generation, setup/teardown)

### Definition of Done
- [ ] `make check-deps` reports all dependencies present
- [ ] Full round-trip: `create-secret` → `read-secret` produces identical bytes (text AND binary)
- [ ] Multi-user flow: create → grant-access → second user reads successfully
- [ ] Revoke flow: revoke-access → second user's key file removed
- [ ] All error cases: missing params, bad names, nonexistent secrets → non-zero exit + stderr message
- [ ] All tests pass: `bash tests/test_trove.sh` → 0 failures

### Must Have
- Isolated GPG keyring (`GNUPGHOME=$(CURDIR)/.gnupg`) — never touch user's personal keyring
- Input validation on all parameters (`NAME`, `USER`, `FILE`) — reject path traversal
- `trap`-based cleanup for temp files containing plaintext key material
- `SHELL := /bin/bash` and `.SHELLFLAGS := -eu -o pipefail -c` for safe recipes
- All targets declared `.PHONY`
- `create-secret` auto-grants access to the creator
- `create-secret` errors on existing secret name (no silent overwrite)
- Binary-safe encrypt/decrypt (arbitrary file content)

### Must NOT Have (Guardrails)
- **No metadata files** — `ls secrets/` is your metadata, `ls secrets/name/*.key.enc` is your ACL
- **No secret versioning** — git history is versioning
- **No stdin/pipe input** — `FILE=path` only
- **No output formatting** — raw decrypted content to stdout only
- **No auto-commit** — Makefile does crypto, user does git
- **No multi-file secrets** — one file per secret
- **No symlinks in users/** — one file per identity
- **No key rotation logic** — MVP: re-add + re-grant manually
- **No passphrase-mode OpenSSL** — raw key mode only (`-K` and `-iv` flags)
- **No system `base64`** — use `openssl base64` or `xxd` for cross-platform safety
- **No importing keys into user's default keyring** — isolated `GNUPGHOME` always

---

## Crypto Reference (EXACT COMMANDS — copy verbatim)

### Generate AES-256 Symmetric Key (hex-encoded)
```bash
openssl rand -hex 32
# Output: 64 hex characters = 256-bit key
```

### Generate IV (hex-encoded)
```bash
openssl rand -hex 16
# Output: 32 hex characters = 128-bit IV
```

### Encrypt Content (AES-256-CBC, raw key mode)
```bash
# $KEY_HEX = 64 hex chars, $IV_HEX = 32 hex chars
# Prepend IV to ciphertext so decrypt knows the IV
echo "$IV_HEX" > "$SECRET_DIR/secret.enc"
openssl enc -aes-256-cbc -nosalt -K "$KEY_HEX" -iv "$IV_HEX" -in "$PLAINTEXT_FILE" >> "$SECRET_DIR/secret.enc"
```

### Decrypt Content (AES-256-CBC, raw key mode)
```bash
# First line of secret.enc is the IV (hex), rest is ciphertext
IV_HEX=$(head -1 "$SECRET_DIR/secret.enc")
tail -n +2 "$SECRET_DIR/secret.enc" | openssl enc -aes-256-cbc -d -nosalt -K "$KEY_HEX" -iv "$IV_HEX"
```

### Encrypt Symmetric Key for a User (GPG)
```bash
# Encrypt the hex key string with user's public key
echo "$KEY_HEX" | gpg --batch --yes --trust-model always \
  --homedir "$GNUPGHOME" \
  --recipient-file "$USERS_DIR/$USERNAME.pub" \
  --encrypt --armor \
  --output "$SECRET_DIR/$USERNAME.key.enc"
```

### Decrypt Symmetric Key (GPG, current user)
```bash
# User decrypts with their private key (from their own GPG keyring, NOT the repo's)
gpg --batch --yes --quiet --decrypt "$SECRET_DIR/$TROVE_USER.key.enc"
# Output: the hex key string
```

### Import User Public Key to Isolated Keyring
```bash
gpg --batch --yes --homedir "$GNUPGHOME" --import "$KEY_FILE"
```

**NOTE on decrypt**: When *decrypting* the symmetric key, the user uses their **own** GPG private key (their personal `~/.gnupg`), NOT the repo's isolated `GNUPGHOME`. The isolated keyring is only for operations that use public keys (encrypt-for-user, import). This is a critical distinction.

---

## Verification Strategy (MANDATORY)

> **UNIVERSAL RULE: ZERO HUMAN INTERVENTION**
>
> ALL tasks in this plan MUST be verifiable WITHOUT any human action.
> Every criterion is verified by running a command or using a tool.

### Test Decision
- **Infrastructure exists**: NO (new project)
- **Automated tests**: YES — shell-based integration tests (tests after implementation)
- **Framework**: Plain bash test script (no BATS dependency needed for MVP)

### Test Infrastructure
- `tests/test_trove.sh` — main test runner
- `tests/helpers.sh` — functions for: creating temp GPG keypairs, setup/teardown of test environment
- Tests create temporary GPG identities (alice, bob) in temp dirs, exercise all targets, verify round-trips
- All tests run in an isolated temp directory — no side effects

### Agent-Executed QA Scenarios (MANDATORY — ALL tasks)

> Whether tests exist or not, EVERY task includes Agent-Executed QA Scenarios.
> The executing agent DIRECTLY verifies each deliverable by running it.

---

## Execution Strategy

### Parallel Execution Waves

```
Wave 1 (Sequential Foundation):
├── Task 1: Project setup + check-deps + init targets
├── Task 2: Crypto primitives (generate key, encrypt/decrypt content, encrypt/decrypt key-for-user)
└── Task 3: add-user + create-secret + read-secret (core trio, round-trip proven)

Wave 2 (Parallel — after Wave 1):
├── Task 4: grant-access + revoke-access
├── Task 5: list-secrets + list-users + delete-secret
└── Task 6: Error handling + input validation hardening

Wave 3 (Final):
└── Task 7: Integration test suite (exercises ALL targets end-to-end)
```

### Dependency Matrix

| Task | Depends On | Blocks | Can Parallelize With |
|------|------------|--------|---------------------|
| 1 | None | 2, 3, 4, 5, 6, 7 | None |
| 2 | 1 | 3, 4, 5, 6, 7 | None |
| 3 | 2 | 4, 5, 7 | None |
| 4 | 3 | 7 | 5, 6 |
| 5 | 3 | 7 | 4, 6 |
| 6 | 3 | 7 | 4, 5 |
| 7 | 4, 5, 6 | None | None (final) |

### Agent Dispatch Summary

| Wave | Tasks | Recommended Agents |
|------|-------|-------------------|
| 1 | 1, 2, 3 | Sequential: `task(category="unspecified-high", ...)` |
| 2 | 4, 5, 6 | Parallel: three `task(category="quick", ...)` |
| 3 | 7 | Final: `task(category="unspecified-high", ...)` |

---

## TODOs

- [x] 1. Project Setup: `check-deps` and `init` Targets

  **What to do**:
  - Create `~/src/trove/` directory
  - Create `Makefile` with boilerplate:
    ```makefile
    SHELL := /bin/bash
    .SHELLFLAGS := -eu -o pipefail -c

    STORE_DIR := $(CURDIR)
    USERS_DIR := $(STORE_DIR)/users
    SECRETS_DIR := $(STORE_DIR)/secrets
    GNUPGHOME := $(STORE_DIR)/.gnupg

    export GNUPGHOME

    # Identity resolution cascade
    TROVE_USER := $(or $(PM_USER),$(shell \
      if [ -f "$(USERS_DIR)/$$USER@$$(hostname -s).pub" ]; then \
        echo "$$USER@$$(hostname -s)"; \
      else \
        echo "$$USER"; \
      fi \
    ))
    ```
  - Implement `make check-deps` target:
    - Verify `gpg` (or `gpg2`) is available: `command -v gpg >/dev/null 2>&1`
    - Verify `openssl` is available and supports `enc -aes-256-cbc`
    - Verify `bash` version >= 4 (for associative arrays if needed, and robust `pipefail`)
    - Verify `xxd` is available
    - Print clear error messages listing missing deps and install instructions (`brew install gnupg`, etc.)
  - Implement `make init` target:
    - Create `users/` directory
    - Create `secrets/` directory
    - Create `.gnupg/` directory with `chmod 700`
    - Create `.gitignore` containing `.gnupg/` and `*.tmp`
    - Idempotent — safe to run multiple times
  - All targets declared `.PHONY`

  **Must NOT do**:
  - Do NOT run `git init` (user manages git)
  - Do NOT install dependencies automatically
  - Do NOT create any example users or secrets

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: Straightforward file creation and shell command wrapping, no complex logic
  - **Skills**: []
    - No specialized skills needed — pure Makefile and shell
  - **Skills Evaluated but Omitted**:
    - `playwright`: No browser involvement
    - `frontend-ui-ux`: No UI

  **Parallelization**:
  - **Can Run In Parallel**: NO
  - **Parallel Group**: Wave 1 — Sequential (first task)
  - **Blocks**: Tasks 2, 3, 4, 5, 6, 7
  - **Blocked By**: None (starting task)

  **References**:

  **Pattern References**:
  - None (greenfield project)

  **Documentation References**:
  - Crypto Reference section in this plan — Makefile boilerplate and variable definitions

  **External References**:
  - GNU Make manual: https://www.gnu.org/software/make/manual/make.html — `.SHELLFLAGS`, `.PHONY`, variable assignment
  - GPG manual: `man gpg` — `--homedir` flag documentation

  **WHY Each Reference Matters**:
  - The Makefile boilerplate (SHELL, SHELLFLAGS, variable defs) is the foundation every other task builds on
  - Getting GNUPGHOME and identity resolution right here prevents debugging in every downstream target

  **Acceptance Criteria**:

  > **AGENT-EXECUTABLE VERIFICATION ONLY**

  - [ ] `~/src/trove/Makefile` exists and is valid (`make -n check-deps` does not error)
  - [ ] `make check-deps -C ~/src/trove` exits 0 and prints dependency status (or non-zero with clear error if dep missing)
  - [ ] `make init -C ~/src/trove` exits 0
  - [ ] `test -d ~/src/trove/users && test -d ~/src/trove/secrets && test -d ~/src/trove/.gnupg` — all dirs exist
  - [ ] `stat -f '%Lp' ~/src/trove/.gnupg` outputs `700` (macOS) — correct permissions
  - [ ] `cat ~/src/trove/.gitignore` contains `.gnupg/` and `*.tmp`
  - [ ] Running `make init -C ~/src/trove` a second time exits 0 (idempotent)
  - [ ] `make -p -C ~/src/trove | grep '.PHONY'` includes `check-deps` and `init`

  **Agent-Executed QA Scenarios:**

  ```
  Scenario: Fresh init creates directory structure
    Tool: Bash
    Preconditions: ~/src/trove exists with only the Makefile
    Steps:
      1. Run: make init -C ~/src/trove
      2. Assert: exit code 0
      3. Run: ls -la ~/src/trove/
      4. Assert: users/, secrets/, .gnupg/, .gitignore all exist
      5. Run: stat -f '%Lp' ~/src/trove/.gnupg
      6. Assert: output is "700"
      7. Run: cat ~/src/trove/.gitignore
      8. Assert: contains ".gnupg/" and "*.tmp"
    Expected Result: All directories created with correct permissions
    Evidence: Terminal output captured

  Scenario: Init is idempotent
    Tool: Bash
    Preconditions: make init already ran once
    Steps:
      1. Run: make init -C ~/src/trove
      2. Assert: exit code 0
      3. Assert: no errors on stderr
    Expected Result: Second init succeeds silently
    Evidence: Terminal output captured

  Scenario: check-deps reports missing tools clearly
    Tool: Bash
    Preconditions: Makefile exists
    Steps:
      1. Run: make check-deps -C ~/src/trove
      2. Assert: exit code 0 (if gpg and openssl installed)
      3. Assert: stdout lists each dependency with OK/MISSING status
    Expected Result: Clear dependency status report
    Evidence: Terminal output captured
  ```

  **Commit**: YES
  - Message: `feat(init): add Makefile with check-deps and init targets`
  - Files: `Makefile`, `.gitignore`
  - Pre-commit: `make check-deps -C ~/src/trove && make init -C ~/src/trove`

---

- [x] 2. Crypto Primitives: Helper Targets/Functions

  **What to do**:
  - Add internal helper targets or shell functions within the Makefile for the core crypto operations. These are the building blocks every user-facing target calls. Implement them following the **Crypto Reference** section EXACTLY:
    - **`_generate-key`**: `openssl rand -hex 32` → outputs 64 hex char AES key
    - **`_generate-iv`**: `openssl rand -hex 16` → outputs 32 hex char IV
    - **`_encrypt-content`**: Takes `KEY_HEX`, `IV_HEX`, `PLAINTEXT_FILE`, `OUTPUT_FILE`. Writes IV as first line, appends ciphertext.
    - **`_decrypt-content`**: Takes `KEY_HEX`, `SECRET_ENC_FILE`. Reads IV from first line, decrypts rest.
    - **`_encrypt-key-for-user`**: Takes `KEY_HEX`, `USERNAME`, `OUTPUT_FILE`. Encrypts hex key string with user's `.pub` via GPG using isolated `GNUPGHOME`.
    - **`_decrypt-key`**: Takes `KEY_ENC_FILE`. Decrypts with user's personal GPG private key (NOT isolated keyring). Outputs hex key string.
  - Each primitive must handle errors (non-zero exit, stderr message)
  - Each primitive must clean up temp files via `trap`
  - Add a `make test-crypto` smoke target that:
    1. Generates a test GPG keypair in `.gnupg/`
    2. Creates a temp file with known content
    3. Runs full round-trip: generate key → encrypt content → encrypt key for test user → decrypt key → decrypt content
    4. Compares output to original
    5. Cleans up test artifacts

  **Must NOT do**:
  - Do NOT use passphrase-mode OpenSSL (`-pass`, `-salt`)
  - Do NOT use system `base64` — use `openssl base64` or `xxd -p`
  - Do NOT import keys into user's default keyring — isolated `GNUPGHOME` only
  - Do NOT skip the IV — every encryption must generate and store an IV

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
    - Reason: Crypto operations are the highest-risk code in the project. Getting OpenSSL and GPG flags wrong causes silent corruption. Requires careful, methodical implementation.
  - **Skills**: []
    - No specialized skills needed — shell + openssl + gpg
  - **Skills Evaluated but Omitted**:
    - `playwright`: No browser
    - `git-master`: No git operations

  **Parallelization**:
  - **Can Run In Parallel**: NO
  - **Parallel Group**: Wave 1 — Sequential (second task)
  - **Blocks**: Tasks 3, 4, 5, 6, 7
  - **Blocked By**: Task 1

  **References**:

  **Pattern References**:
  - `~/src/trove/Makefile` (from Task 1) — Makefile boilerplate, GNUPGHOME, SHELL settings

  **Documentation References**:
  - **Crypto Reference section in this plan** — the EXACT commands to use, verbatim. This is the most important reference. Do not deviate.

  **External References**:
  - `man openssl-enc` — `-K`, `-iv`, `-nosalt` flags, AES-256-CBC mode
  - `man gpg` — `--recipient-file`, `--encrypt`, `--armor`, `--batch`, `--trust-model always`, `--homedir`
  - `man xxd` — `-p` flag for plain hex dump

  **WHY Each Reference Matters**:
  - The Crypto Reference section contains the EXACT commands to copy. Any deviation risks silent data corruption.
  - OpenSSL and GPG have dozens of modes — the wrong flag combination produces output that looks valid but won't decrypt.

  **Acceptance Criteria**:

  > **AGENT-EXECUTABLE VERIFICATION ONLY**

  - [ ] `make test-crypto -C ~/src/trove` exits 0
  - [ ] Text round-trip: encrypt "hello world" → decrypt → output matches exactly
  - [ ] Binary round-trip: encrypt 10KB random binary → decrypt → SHA-256 matches original
  - [ ] Key encryption round-trip: generate key → encrypt for test user → decrypt as test user → key matches
  - [ ] Temp files cleaned up: no `*.tmp` or plaintext key material left after operations
  - [ ] All crypto helper targets/functions use `trap` for cleanup

  **Agent-Executed QA Scenarios:**

  ```
  Scenario: Text round-trip encrypt/decrypt preserves content
    Tool: Bash
    Preconditions: Task 1 complete, make init ran, GPG installed
    Steps:
      1. Run: echo "test secret content 12345" > /tmp/trove-test-plain.txt
      2. Run: make test-crypto -C ~/src/trove
      3. Assert: exit code 0
      4. Assert: stdout or test output confirms "PASS" / content matches
    Expected Result: Decrypted content is byte-identical to original
    Evidence: Terminal output captured

  Scenario: Binary round-trip preserves content
    Tool: Bash
    Preconditions: test-crypto target exists
    Steps:
      1. Run: dd if=/dev/urandom of=/tmp/trove-test-binary bs=1024 count=10 2>/dev/null
      2. Run: shasum -a 256 /tmp/trove-test-binary | awk '{print $1}'
      3. Capture hash as EXPECTED_HASH
      4. Run the binary round-trip portion of make test-crypto
      5. Run: shasum -a 256 on decrypted output
      6. Assert: hashes match
    Expected Result: Binary file survives encrypt/decrypt with identical SHA-256
    Evidence: Hash comparison output captured

  Scenario: No plaintext key material left on disk after operations
    Tool: Bash
    Preconditions: make test-crypto completed
    Steps:
      1. Run: find ~/src/trove -name "*.tmp" -o -name "tmp.*" 2>/dev/null
      2. Assert: no results (empty output)
      3. Run: find /tmp -name "trove-*" -newer ~/src/trove/Makefile 2>/dev/null
      4. Assert: no leftover temp files
    Expected Result: All temporary plaintext cleaned up
    Evidence: Find output captured
  ```

  **Commit**: YES
  - Message: `feat(crypto): add core crypto primitives with round-trip smoke test`
  - Files: `Makefile`
  - Pre-commit: `make test-crypto -C ~/src/trove`

---

- [x] 3. Core Trio: `add-user`, `create-secret`, `read-secret`

  **What to do**:
  - Implement `make add-user NAME=<username> KEY=<path/to/pubkey>`:
    - Validate `NAME` matches `^[a-zA-Z0-9._@-]+$` (note: `@` allowed for `user@host` identities)
    - Validate `KEY` file exists and is a valid GPG public key (`gpg --show-keys "$KEY"`)
    - Copy public key to `users/$NAME.pub`
    - Import key into isolated `GNUPGHOME` keyring: `gpg --batch --yes --homedir .gnupg --import users/$NAME.pub`
  - Implement `make create-secret NAME=<name> FILE=<path>`:
    - Validate `NAME` matches `^[a-zA-Z0-9._-]+$` (NO `@` or `/` in secret names)
    - Validate `FILE` exists and is readable
    - Check `secrets/$NAME/` does NOT already exist — error if it does
    - Resolve current user identity via cascade (`TROVE_USER`)
    - Verify `users/$TROVE_USER.pub` exists — error if creator isn't a registered user
    - Generate random AES-256 key (hex) and IV (hex)
    - Encrypt content: IV as first line + ciphertext in `secrets/$NAME/secret.enc`
    - Encrypt symmetric key for creator: `secrets/$NAME/$TROVE_USER.key.enc`
    - Clean up all temp files via `trap`
  - Implement `make read-secret NAME=<name>`:
    - Validate `NAME`
    - Verify `secrets/$NAME/` exists
    - Resolve current user identity via cascade (`TROVE_USER`)
    - Verify `secrets/$NAME/$TROVE_USER.key.enc` exists — error "access denied" if not
    - Decrypt symmetric key using user's PERSONAL GPG key (NOT isolated keyring)
    - Decrypt content using symmetric key and IV from `secret.enc`
    - Output raw decrypted content to stdout
    - Clean up temp files via `trap`

  **Must NOT do**:
  - Do NOT allow `create-secret` to overwrite an existing secret
  - Do NOT format or transform the decrypted output — raw bytes to stdout
  - Do NOT allow `@` or `/` in secret names (only in user names for `user@host`)
  - Do NOT import keys into user's personal keyring — isolated `GNUPGHOME` only

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
    - Reason: These three targets form the critical path. The create→read round-trip is the fundamental proof that the crypto model works. Errors here cascade to everything downstream.
  - **Skills**: []
  - **Skills Evaluated but Omitted**:
    - `playwright`: No browser
    - `git-master`: No git operations

  **Parallelization**:
  - **Can Run In Parallel**: NO
  - **Parallel Group**: Wave 1 — Sequential (third task)
  - **Blocks**: Tasks 4, 5, 7
  - **Blocked By**: Task 2

  **References**:

  **Pattern References**:
  - `~/src/trove/Makefile` (from Tasks 1-2) — crypto primitives, GNUPGHOME setup, identity resolution variable

  **Documentation References**:
  - **Crypto Reference section in this plan** — exact encrypt/decrypt commands for content and key wrapping
  - Input validation pattern: `echo "$(NAME)" | grep -qE '^[a-zA-Z0-9._-]+$$' || (echo "Error: Invalid name" >&2 && exit 1)`
  - Note the `$$` in Makefile (escapes `$` for shell)

  **External References**:
  - `man gpg` — `--show-keys` for validating public key files, `--recipient-file` for encrypting to a key file

  **WHY Each Reference Matters**:
  - The crypto primitives from Task 2 are called here — understanding how they work is essential
  - Input validation pattern must be consistent across all targets — establish it here, reuse in Tasks 4-6
  - The identity cascade variable `TROVE_USER` is used here for the first time in a real operation

  **Acceptance Criteria**:

  > **AGENT-EXECUTABLE VERIFICATION ONLY**

  - [ ] `make add-user NAME=testuser KEY=/path/to/test.pub -C ~/src/trove` exits 0
  - [ ] `test -f ~/src/trove/users/testuser.pub` — public key file copied
  - [ ] Text round-trip: `echo "hunter2" > /tmp/s.txt && make create-secret NAME=dbpass FILE=/tmp/s.txt && make read-secret NAME=dbpass > /tmp/out.txt && diff /tmp/s.txt /tmp/out.txt` — exit 0
  - [ ] Binary round-trip: same with 10KB random binary, SHA-256 match
  - [ ] `secrets/dbpass/` directory exists with `secret.enc` and `$TROVE_USER.key.enc`
  - [ ] `make create-secret NAME=dbpass FILE=/tmp/s.txt` (duplicate) exits non-zero with error message
  - [ ] `make create-secret NAME=../etc/passwd FILE=/tmp/s.txt` exits non-zero (path traversal rejected)
  - [ ] `make create-secret NAME=test` (no FILE=) exits non-zero with error message
  - [ ] `make read-secret NAME=nonexistent` exits non-zero with error message
  - [ ] `make add-user NAME="../../bad" KEY=/tmp/k.pub` exits non-zero (path traversal rejected)

  **Agent-Executed QA Scenarios:**

  ```
  Scenario: Full text round-trip (create → read)
    Tool: Bash
    Preconditions: Tasks 1-2 complete, test GPG keypair created, test user added
    Steps:
      1. echo "my-secret-password-12345" > /tmp/trove-test-secret.txt
      2. make create-secret NAME=test-text FILE=/tmp/trove-test-secret.txt -C ~/src/trove
      3. Assert: exit code 0
      4. Assert: test -d ~/src/trove/secrets/test-text
      5. Assert: test -f ~/src/trove/secrets/test-text/secret.enc
      6. Assert: test -f ~/src/trove/secrets/test-text/${TROVE_USER}.key.enc
      7. make read-secret NAME=test-text -C ~/src/trove > /tmp/trove-test-out.txt
      8. diff /tmp/trove-test-secret.txt /tmp/trove-test-out.txt
      9. Assert: exit code 0 (files identical)
    Expected Result: Decrypted output matches original input byte-for-byte
    Evidence: diff output captured

  Scenario: Full binary round-trip (create → read)
    Tool: Bash
    Preconditions: Tasks 1-2 complete, test user exists
    Steps:
      1. dd if=/dev/urandom of=/tmp/trove-test-bin bs=1024 count=10 2>/dev/null
      2. shasum -a 256 /tmp/trove-test-bin > /tmp/trove-expected-hash
      3. make create-secret NAME=test-binary FILE=/tmp/trove-test-bin -C ~/src/trove
      4. Assert: exit code 0
      5. make read-secret NAME=test-binary -C ~/src/trove > /tmp/trove-test-bin-out
      6. shasum -a 256 /tmp/trove-test-bin-out > /tmp/trove-actual-hash
      7. diff /tmp/trove-expected-hash /tmp/trove-actual-hash
      8. Assert: exit code 0 (hashes match)
    Expected Result: Binary file survives encrypt/decrypt with identical SHA-256
    Evidence: Hash comparison captured

  Scenario: Duplicate secret name rejected
    Tool: Bash
    Preconditions: Secret "test-text" already created
    Steps:
      1. echo "new content" > /tmp/trove-dup.txt
      2. make create-secret NAME=test-text FILE=/tmp/trove-dup.txt -C ~/src/trove 2>/tmp/trove-err.txt; EC=$?
      3. Assert: EC is non-zero
      4. Assert: /tmp/trove-err.txt contains "already exists" or "Error"
    Expected Result: Non-zero exit, meaningful error on stderr
    Evidence: Error output captured

  Scenario: Path traversal in NAME rejected
    Tool: Bash
    Preconditions: Makefile exists
    Steps:
      1. echo "x" > /tmp/trove-x.txt
      2. make create-secret NAME=../../etc/passwd FILE=/tmp/trove-x.txt -C ~/src/trove 2>/tmp/trove-err.txt; EC=$?
      3. Assert: EC is non-zero
      4. Assert: stderr contains "Invalid" or "Error"
      5. Assert: test ! -d ~/src/trove/secrets/../../etc
    Expected Result: Path traversal blocked, non-zero exit
    Evidence: Error output captured

  Scenario: Missing FILE parameter rejected
    Tool: Bash
    Preconditions: Makefile exists
    Steps:
      1. make create-secret NAME=nope -C ~/src/trove 2>/tmp/trove-err.txt; EC=$?
      2. Assert: EC is non-zero
      3. Assert: stderr mentions "FILE" or "required"
    Expected Result: Clear error about missing parameter
    Evidence: Error output captured
  ```

  **Commit**: YES
  - Message: `feat(core): add add-user, create-secret, read-secret targets`
  - Files: `Makefile`
  - Pre-commit: `make read-secret NAME=test-text -C ~/src/trove | diff /tmp/trove-test-secret.txt -`

---

- [x] 4. Access Control: `grant-access` and `revoke-access`

  **What to do**:
  - Implement `make grant-access NAME=<secret> USER=<username>`:
    - Validate `NAME` and `USER` parameters
    - Verify `secrets/$NAME/` exists
    - Verify `users/$USER.pub` exists — error "unknown user" if not
    - Verify current user (`TROVE_USER`) has access: `secrets/$NAME/$TROVE_USER.key.enc` exists
    - Verify target user does NOT already have access (error if `$USER.key.enc` exists)
    - Decrypt symmetric key using current user's personal GPG key
    - Encrypt symmetric key with target user's public key (from isolated keyring)
    - Write `secrets/$NAME/$USER.key.enc`
    - Clean up temp files via `trap`
  - Implement `make revoke-access NAME=<secret> USER=<username>`:
    - Validate `NAME` and `USER` parameters
    - Verify `secrets/$NAME/$USER.key.enc` exists — error if not
    - Prevent self-revocation if user is the LAST person with access (warn/error)
    - Delete `secrets/$NAME/$USER.key.enc`

  **Must NOT do**:
  - Do NOT implement full re-key (future work)
  - Do NOT allow granting access if the granting user doesn't have access themselves
  - Do NOT silently overwrite an existing `$USER.key.enc` on grant

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: Builds directly on Task 3 patterns. The crypto is already proven — this is wiring it for a second user.
  - **Skills**: []
  - **Skills Evaluated but Omitted**:
    - `playwright`: No browser

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 2 (with Tasks 5, 6)
  - **Blocks**: Task 7
  - **Blocked By**: Task 3

  **References**:

  **Pattern References**:
  - `~/src/trove/Makefile` — `create-secret` target (from Task 3) — follows same pattern: decrypt key → re-encrypt for another user
  - `~/src/trove/Makefile` — input validation pattern from Task 3

  **Documentation References**:
  - **Crypto Reference section** — "Encrypt Symmetric Key for a User" and "Decrypt Symmetric Key" commands

  **WHY Each Reference Matters**:
  - `grant-access` is essentially the "encrypt key for user" primitive applied to an existing secret — Task 3's create-secret already does this for the creator, so the pattern is established
  - Input validation must be consistent — copy from Task 3

  **Acceptance Criteria**:

  > **AGENT-EXECUTABLE VERIFICATION ONLY**

  - [ ] Grant: Second test user (bob) can read a secret after grant — `make grant-access NAME=test-text USER=bob && PM_USER=bob make read-secret NAME=test-text` produces correct content
  - [ ] Grant without access: `PM_USER=eve make grant-access NAME=test-text USER=carol` fails (eve has no access)
  - [ ] Grant to nonexistent user: `make grant-access NAME=test-text USER=nobody` fails with error
  - [ ] Revoke: `make revoke-access NAME=test-text USER=bob` removes `bob.key.enc`
  - [ ] After revoke: `PM_USER=bob make read-secret NAME=test-text` fails (access denied)
  - [ ] Revoke nonexistent: `make revoke-access NAME=test-text USER=nobody` fails with error

  **Agent-Executed QA Scenarios:**

  ```
  Scenario: Grant access enables second user to read
    Tool: Bash
    Preconditions: Secret "test-text" exists, user "bob" added, bob does NOT have access yet
    Steps:
      1. make grant-access NAME=test-text USER=bob -C ~/src/trove
      2. Assert: exit code 0
      3. Assert: test -f ~/src/trove/secrets/test-text/bob.key.enc
      4. PM_USER=bob make read-secret NAME=test-text -C ~/src/trove > /tmp/trove-bob-out.txt
      5. diff /tmp/trove-test-secret.txt /tmp/trove-bob-out.txt
      6. Assert: exit code 0 (content matches)
    Expected Result: Bob can decrypt the secret after being granted access
    Evidence: diff output captured

  Scenario: Revoke removes access
    Tool: Bash
    Preconditions: bob has access to test-text
    Steps:
      1. make revoke-access NAME=test-text USER=bob -C ~/src/trove
      2. Assert: exit code 0
      3. Assert: test ! -f ~/src/trove/secrets/test-text/bob.key.enc
      4. PM_USER=bob make read-secret NAME=test-text -C ~/src/trove 2>/dev/null; EC=$?
      5. Assert: EC is non-zero
    Expected Result: bob.key.enc deleted, bob can no longer read
    Evidence: Terminal output captured

  Scenario: Cannot grant without own access
    Tool: Bash
    Preconditions: User "eve" exists but has no access to test-text
    Steps:
      1. PM_USER=eve make grant-access NAME=test-text USER=bob -C ~/src/trove 2>/tmp/trove-err.txt; EC=$?
      2. Assert: EC is non-zero
      3. Assert: stderr contains "access" or "denied" or "Error"
    Expected Result: Cannot grant what you don't have
    Evidence: Error output captured
  ```

  **Commit**: YES
  - Message: `feat(acl): add grant-access and revoke-access targets`
  - Files: `Makefile`
  - Pre-commit: `make grant-access NAME=test-text USER=bob -C ~/src/trove && PM_USER=bob make read-secret NAME=test-text -C ~/src/trove > /dev/null`

---

- [x] 5. Utility Targets: `list-secrets`, `list-users`, `delete-secret`

  **What to do**:
  - Implement `make list-secrets`:
    - List directory names under `secrets/`
    - For each, show how many users have access (count `*.key.enc` files)
    - Output format: one secret per line, e.g., `dbpass (2 users)`
    - Exit 0 even if no secrets exist (empty output)
  - Implement `make list-users`:
    - List usernames from `users/` (strip `.pub` extension)
    - Output format: one username per line
    - Exit 0 even if no users exist
  - Implement `make delete-secret NAME=<name>`:
    - Validate `NAME`
    - Verify `secrets/$NAME/` exists — error if not
    - Remove entire `secrets/$NAME/` directory (`rm -rf`)
    - No confirmation prompt (this is a CLI tool; git provides undo via history)

  **Must NOT do**:
  - Do NOT add verbose/quiet flags
  - Do NOT add JSON or structured output format
  - Do NOT add recursive listing or tree views
  - Do NOT add confirmation prompts

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: Simple directory listing and deletion. Minimal logic, mostly `ls` and `rm`.
  - **Skills**: []
  - **Skills Evaluated but Omitted**:
    - `playwright`: No browser

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 2 (with Tasks 4, 6)
  - **Blocks**: Task 7
  - **Blocked By**: Task 3

  **References**:

  **Pattern References**:
  - `~/src/trove/Makefile` — input validation pattern from Task 3
  - `~/src/trove/Makefile` — `.PHONY` declarations pattern from Task 1

  **WHY Each Reference Matters**:
  - Input validation for `delete-secret` NAME param — reuse the same grep pattern
  - These are the simplest targets but still need `.PHONY` and param validation

  **Acceptance Criteria**:

  > **AGENT-EXECUTABLE VERIFICATION ONLY**

  - [ ] `make list-secrets -C ~/src/trove` includes previously created secrets
  - [ ] `make list-users -C ~/src/trove` includes previously added users
  - [ ] `make delete-secret NAME=test-text -C ~/src/trove` exits 0 and `test ! -d ~/src/trove/secrets/test-text`
  - [ ] `make delete-secret NAME=nonexistent -C ~/src/trove` exits non-zero with error
  - [ ] `make list-secrets -C ~/src/trove` after delete no longer shows deleted secret

  **Agent-Executed QA Scenarios:**

  ```
  Scenario: list-secrets shows existing secrets with user counts
    Tool: Bash
    Preconditions: At least one secret created
    Steps:
      1. make list-secrets -C ~/src/trove
      2. Assert: output contains secret name(s)
      3. Assert: output shows user count per secret
    Expected Result: Each secret listed with access count
    Evidence: Terminal output captured

  Scenario: list-users shows registered users
    Tool: Bash
    Preconditions: At least one user added
    Steps:
      1. make list-users -C ~/src/trove
      2. Assert: output contains added username(s)
    Expected Result: Each registered user listed
    Evidence: Terminal output captured

  Scenario: delete-secret removes entire directory
    Tool: Bash
    Preconditions: Secret exists
    Steps:
      1. make delete-secret NAME=test-binary -C ~/src/trove
      2. Assert: exit code 0
      3. test ! -d ~/src/trove/secrets/test-binary
      4. Assert: exit code 0 (directory gone)
      5. make list-secrets -C ~/src/trove
      6. Assert: "test-binary" not in output
    Expected Result: Secret completely removed
    Evidence: Terminal output captured
  ```

  **Commit**: YES
  - Message: `feat(util): add list-secrets, list-users, delete-secret targets`
  - Files: `Makefile`
  - Pre-commit: `make list-secrets -C ~/src/trove && make list-users -C ~/src/trove`

---

- [x] 6. Error Handling and Input Validation Hardening

  **What to do**:
  - Audit ALL existing targets and ensure consistent error handling:
    - Every target that accepts `NAME=` validates against `^[a-zA-Z0-9._-]+$` (secrets) or `^[a-zA-Z0-9._@-]+$` (users)
    - Every target that accepts `FILE=` validates file exists and is readable
    - Every target that requires a parameter errors clearly if parameter is empty/missing
    - Every error outputs to stderr (not stdout) and exits non-zero
  - Add parameter presence checks at the top of each recipe:
    ```makefile
    create-secret:
    	@test -n "$(NAME)" || (echo "Error: NAME= is required" >&2 && exit 1)
    	@test -n "$(FILE)" || (echo "Error: FILE= is required" >&2 && exit 1)
    ```
  - Ensure all error messages follow a consistent format: `Error: <description>` to stderr
  - Verify `trap` cleanup is present in ALL recipes that create temp files
  - Test that `FILE=/dev/stdin` and `FILE=-` are rejected (or handled gracefully)
  - Test empty secret name, whitespace in names, very long names

  **Must NOT do**:
  - Do NOT add verbose/debug modes
  - Do NOT add color to error output
  - Do NOT add error codes (just non-zero exit)

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: Hardening pass over existing code. Pattern is repetitive (validate → error). Low creativity, high diligence.
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 2 (with Tasks 4, 5)
  - **Blocks**: Task 7
  - **Blocked By**: Task 3

  **References**:

  **Pattern References**:
  - `~/src/trove/Makefile` — all existing targets from Tasks 1-3 (audit each one)

  **Documentation References**:
  - Metis review guardrail G2 (No Shell Injection): `echo "$(NAME)" | grep -qE '^[a-zA-Z0-9._-]+$$' || (echo "Invalid name" >&2 && exit 1)`

  **WHY Each Reference Matters**:
  - Every target is being audited — need to read each one and verify validation is present and consistent
  - The grep pattern from Metis is the canonical validation — ensure it's used everywhere

  **Acceptance Criteria**:

  > **AGENT-EXECUTABLE VERIFICATION ONLY**

  - [ ] Every target with `NAME=` rejects `../`, `./`, `/`, spaces, empty string — verify with test commands
  - [ ] Every target with `FILE=` rejects missing file — verify with `make create-secret NAME=x FILE=/nonexistent`
  - [ ] Every target with `USER=` rejects invalid characters — verify with test commands
  - [ ] All errors go to stderr: `make create-secret NAME= -C ~/src/trove 2>&1 1>/dev/null | grep -q "Error"`
  - [ ] All errors exit non-zero: `make create-secret NAME= -C ~/src/trove 2>/dev/null; test $? -ne 0`
  - [ ] No temp files left after any error scenario

  **Agent-Executed QA Scenarios:**

  ```
  Scenario: Empty NAME rejected for all targets
    Tool: Bash
    Preconditions: Makefile complete from Tasks 1-5
    Steps:
      1. for target in create-secret read-secret delete-secret grant-access revoke-access; do
           make $target NAME= -C ~/src/trove 2>/dev/null; echo "$target: exit $?";
         done
      2. Assert: all exit codes are non-zero
    Expected Result: Every target rejects empty NAME
    Evidence: Exit codes captured

  Scenario: Path traversal rejected for all targets
    Tool: Bash
    Preconditions: Makefile complete
    Steps:
      1. echo "x" > /tmp/trove-x.txt
      2. make create-secret NAME=../evil FILE=/tmp/trove-x.txt -C ~/src/trove 2>/dev/null; EC=$?
      3. Assert: EC is non-zero
      4. make read-secret NAME=../evil -C ~/src/trove 2>/dev/null; EC=$?
      5. Assert: EC is non-zero
    Expected Result: All path traversal attempts rejected
    Evidence: Exit codes captured

  Scenario: Error output goes to stderr, not stdout
    Tool: Bash
    Preconditions: Makefile complete
    Steps:
      1. STDOUT=$(make create-secret NAME= -C ~/src/trove 2>/dev/null); echo "stdout: '$STDOUT'"
      2. Assert: STDOUT is empty
      3. STDERR=$(make create-secret NAME= -C ~/src/trove 2>&1 1>/dev/null); echo "stderr: '$STDERR'"
      4. Assert: STDERR contains "Error"
    Expected Result: Errors to stderr only, nothing on stdout
    Evidence: Output comparison captured
  ```

  **Commit**: YES
  - Message: `fix(validation): harden input validation and error handling across all targets`
  - Files: `Makefile`
  - Pre-commit: `make create-secret NAME=../evil FILE=/dev/null -C ~/src/trove 2>/dev/null; test $? -ne 0`

---

- [x] 7. Integration Test Suite

  **What to do**:
  - Create `tests/helpers.sh` with:
    - `setup_test_env()`: Creates temp directory, initializes Trove repo, generates 2-3 test GPG keypairs (alice, bob, carol) in isolated temp GNUPGHOME
    - `teardown_test_env()`: Removes all temp directories and keypairs
    - `assert_eq()`, `assert_ne()`, `assert_file_exists()`, `assert_file_not_exists()`, `assert_exit_code()`: Simple assertion helpers
    - `run_as()`: Helper to run a make target as a specific user (sets `PM_USER`)
  - Create `tests/test_trove.sh` with test cases covering ALL flows:
    - **Test: Init creates directory structure**
    - **Test: Add user registers public key**
    - **Test: Create + read round-trip (text)**
    - **Test: Create + read round-trip (binary)**
    - **Test: Create duplicate secret fails**
    - **Test: Grant access enables second user**
    - **Test: Revoke access removes key file**
    - **Test: After revoke, user cannot read**
    - **Test: List secrets shows entries with counts**
    - **Test: List users shows registered users**
    - **Test: Delete secret removes directory**
    - **Test: Path traversal in NAME rejected**
    - **Test: Missing parameters rejected**
    - **Test: Read nonexistent secret fails**
    - **Test: Grant from user without access fails**
    - **Test: Empty store — list returns empty, no errors**
  - Add `make test` target to Makefile that runs `bash tests/test_trove.sh`
  - Test output format: `PASS: <test name>` or `FAIL: <test name> — <reason>`
  - Summary at end: `X passed, Y failed`

  **Must NOT do**:
  - Do NOT require BATS or any external test framework
  - Do NOT use the developer's real GPG keys — always generate temp test keys
  - Do NOT leave test artifacts after completion (full cleanup)
  - Do NOT skip error-case tests

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
    - Reason: Comprehensive test suite touching ALL targets. Requires setting up GPG keypair infrastructure for testing, which is fiddly. Must cover happy paths AND error paths.
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: NO
  - **Parallel Group**: Wave 3 — Final (after all implementation)
  - **Blocks**: None (final task)
  - **Blocked By**: Tasks 4, 5, 6

  **References**:

  **Pattern References**:
  - `~/src/trove/Makefile` — all targets (this test suite exercises every single one)

  **Documentation References**:
  - Acceptance criteria from Tasks 1-6 — each task's QA scenarios become formal test cases here
  - **Crypto Reference section** — test setup needs to generate GPG keypairs; reference the `gpg --batch --gen-key` approach

  **External References**:
  - GPG batch key generation: `gpg --batch --gen-key <<EOF` with `Key-Type`, `Key-Length`, `Name-Real`, `%no-protection`, `%commit`

  **WHY Each Reference Matters**:
  - Every Makefile target is exercised — need to understand params, expected behavior, and error conditions for each
  - GPG batch key generation is non-obvious and easy to get wrong — reference the exact format

  **Acceptance Criteria**:

  > **AGENT-EXECUTABLE VERIFICATION ONLY**

  - [ ] `make test -C ~/src/trove` exits 0
  - [ ] Output shows all tests passing: `X passed, 0 failed`
  - [ ] At least 16 test cases (covering all targets + error cases)
  - [ ] No leftover temp directories/files after test run: `ls /tmp/trove-test-*` returns nothing
  - [ ] Tests use exclusively generated temp GPG keys (not developer's real keys)
  - [ ] `bash tests/test_trove.sh` works standalone (doesn't require make)

  **Agent-Executed QA Scenarios:**

  ```
  Scenario: Full test suite passes
    Tool: Bash
    Preconditions: All tasks 1-6 complete
    Steps:
      1. make test -C ~/src/trove
      2. Assert: exit code 0
      3. Assert: stdout contains "0 failed"
      4. Assert: stdout shows at least 16 "PASS" lines
    Expected Result: All integration tests pass
    Evidence: Full test output captured to .sisyphus/evidence/task-7-test-suite.txt

  Scenario: Test cleanup leaves no artifacts
    Tool: Bash
    Preconditions: Test suite just completed
    Steps:
      1. ls /tmp/trove-test-* 2>/dev/null; EC=$?
      2. Assert: no files found (EC non-zero or empty output)
      3. find ~/src/trove -name "*.tmp" 2>/dev/null
      4. Assert: no temp files
    Expected Result: Complete cleanup after tests
    Evidence: Find output captured

  Scenario: Tests work standalone
    Tool: Bash
    Preconditions: All tasks complete
    Steps:
      1. bash ~/src/trove/tests/test_trove.sh
      2. Assert: exit code 0
      3. Assert: output matches make test output
    Expected Result: Tests runnable without make wrapper
    Evidence: Terminal output captured
  ```

  **Commit**: YES
  - Message: `test(integration): add comprehensive shell-based integration test suite`
  - Files: `tests/helpers.sh`, `tests/test_trove.sh`, `Makefile` (add `test` target)
  - Pre-commit: `make test -C ~/src/trove`

---

## Commit Strategy

| After Task | Message | Files | Verification |
|------------|---------|-------|--------------|
| 1 | `feat(init): add Makefile with check-deps and init targets` | `Makefile`, `.gitignore` | `make check-deps && make init` |
| 2 | `feat(crypto): add core crypto primitives with round-trip smoke test` | `Makefile` | `make test-crypto` |
| 3 | `feat(core): add add-user, create-secret, read-secret targets` | `Makefile` | text + binary round-trip |
| 4 | `feat(acl): add grant-access and revoke-access targets` | `Makefile` | grant → read chain |
| 5 | `feat(util): add list-secrets, list-users, delete-secret targets` | `Makefile` | list + delete verification |
| 6 | `fix(validation): harden input validation and error handling` | `Makefile` | path traversal + empty param tests |
| 7 | `test(integration): add comprehensive integration test suite` | `tests/*`, `Makefile` | `make test` |

---

## Success Criteria

### Verification Commands
```bash
# Full test suite
make test -C ~/src/trove
# Expected: X passed, 0 failed

# Manual smoke test: complete multi-user flow
make init -C ~/src/trove
make add-user NAME=alice KEY=alice.pub -C ~/src/trove
make add-user NAME=bob KEY=bob.pub -C ~/src/trove
echo "supersecret" > /tmp/s.txt
make create-secret NAME=myapp FILE=/tmp/s.txt -C ~/src/trove
make grant-access NAME=myapp USER=bob -C ~/src/trove
PM_USER=bob make read-secret NAME=myapp -C ~/src/trove
# Expected: "supersecret"
make revoke-access NAME=myapp USER=bob -C ~/src/trove
make list-secrets -C ~/src/trove
# Expected: myapp (1 users)
make delete-secret NAME=myapp -C ~/src/trove
make list-secrets -C ~/src/trove
# Expected: (empty)
```

### Final Checklist
- [ ] All "Must Have" present (isolated keyring, input validation, trap cleanup, PHONY, binary-safe)
- [ ] All "Must NOT Have" absent (no metadata, no stdin, no auto-commit, no formatting flags)
- [ ] All tests pass (`make test` → 0 failures)
- [ ] Crypto commands match Crypto Reference section exactly
- [ ] Clean repo: no temp files, no plaintext key material
