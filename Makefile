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

# Validate TROVE_USER at load time — prevents path traversal or shell injection via PM_USER
_VALID_TROVE_USER := $(shell [[ "$(TROVE_USER)" =~ ^[a-zA-Z0-9._@-]+$$ ]] && echo ok)
$(if $(_VALID_TROVE_USER),,$(error Invalid TROVE_USER '$(TROVE_USER)' — must match [a-zA-Z0-9._@-]+))

.PHONY: help check-deps init _generate-key _generate-iv _encrypt-content _decrypt-content _encrypt-key-for-user _decrypt-key test-crypto add-user generate-key import-key export-key import-secret-key new-user create-secret read-secret update-secret grant-access revoke-access rotate-secret list-secrets list-users delete-secret test

## help: Show this help message
help:
	@echo "Usage: make <target> [VARS]"
	@echo ""
	@echo "Targets:"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
	@echo ""
	@echo "Variables:"
	@echo "  NAME=<name>       Secret or user name"
	@echo "  FILE=<path>       Path to file to encrypt"
	@echo "  KEY=<path>        Path to GPG public key file"
	@echo "  USER=<username>   Target user for grant/revoke"
	@echo "  DIR=<path>        Output directory for export-key (default: .)"
	@echo ""
	@echo "Examples:"
	@echo "  make check-deps"
	@echo "  make init"
	@echo "  make add-user NAME=alice KEY=alice.pub"
	@echo "  make create-secret NAME=api-key FILE=secret.txt"
	@echo "  make read-secret NAME=api-key"
	@echo "  make update-secret NAME=api-key FILE=new-secret.txt"
	@echo "  make grant-access NAME=api-key USER=bob"
	@echo "  make revoke-access NAME=api-key USER=bob"
	@echo "  make list-secrets"
	@echo "  make list-users"
	@echo "  make delete-secret NAME=api-key"
	@echo "  make export-key NAME=ci-deploy"
	@echo "  make import-secret-key NAME=ci-deploy KEY=ci-deploy.secret.key"

## test: Run the test suite
test:
	@bash tests/test_trove.sh

## check-deps: Verify required tools (gpg, openssl, bash ≥ 4, xxd)
check-deps:
	@echo "Checking dependencies..."
	@command -v gpg2 >/dev/null 2>&1 || command -v gpg >/dev/null 2>&1 || { echo "Error: gpg or gpg2 not found" >&2; exit 1; }
	@echo "✓ GPG found"
	@command -v openssl >/dev/null 2>&1 || { echo "Error: openssl not found" >&2; exit 1; }
	@echo "✓ OpenSSL found"
	@bash -c 'if [[ $${BASH_VERSINFO[0]} -lt 4 ]]; then echo "Error: bash >= 4 required" >&2; exit 1; fi'
	@echo "✓ Bash >= 4 found"
	@command -v xxd >/dev/null 2>&1 || { echo "Error: xxd not found" >&2; exit 1; }
	@echo "✓ xxd found"
	@echo "All dependencies OK"

## init: Create directory structure and initialize trove
init:
	@echo "Initializing trove structure..."
	@mkdir -p $(USERS_DIR)
	@mkdir -p $(SECRETS_DIR)
	@mkdir -p $(GNUPGHOME)
	@chmod 700 $(GNUPGHOME)
	@echo "✓ Directories created with proper permissions"
	@echo "✓ GNUPGHOME=$(GNUPGHOME)"
	@echo "Trove initialized successfully"

# ---------------------------------------------------------------------------
# Crypto Primitives (internal helpers)
# ---------------------------------------------------------------------------

# _generate-key: Output a 64 hex-char AES-256 key to stdout
_generate-key:
	@openssl rand -hex 32 || { echo "Error: failed to generate AES key" >&2; exit 1; }

# _generate-iv: Output a 32 hex-char IV to stdout
_generate-iv:
	@openssl rand -hex 16 || { echo "Error: failed to generate IV" >&2; exit 1; }

# _encrypt-content: Encrypt PLAINTEXT_FILE → OUTPUT_FILE using KEY_HEX and IV_HEX
#   Required vars: KEY_HEX, IV_HEX, PLAINTEXT_FILE, OUTPUT_FILE
#   Security note: KEY_HEX is passed via openssl's -K flag, which appears in
#   /proc/<pid>/cmdline. This is inherent to openssl enc — there is no file/fd
#   interface for raw hex keys. Safe on single-user machines; avoid on shared servers.
_encrypt-content:
	@test -n "$(KEY_HEX)" || { echo "Error: KEY_HEX is required" >&2; exit 1; }
	@test -n "$(IV_HEX)" || { echo "Error: IV_HEX is required" >&2; exit 1; }
	@test -n "$(PLAINTEXT_FILE)" || { echo "Error: PLAINTEXT_FILE is required" >&2; exit 1; }
	@test -n "$(OUTPUT_FILE)" || { echo "Error: OUTPUT_FILE is required" >&2; exit 1; }
	@test -f "$(PLAINTEXT_FILE)" || { echo "Error: PLAINTEXT_FILE not found: $(PLAINTEXT_FILE)" >&2; exit 1; }
	@_CIPHER_TMP="$(OUTPUT_FILE).tmp"; \
	_cleanup() { rm -f "$${_CIPHER_TMP}" "$(OUTPUT_FILE)"; }; \
	trap _cleanup EXIT; \
	openssl enc -aes-256-cbc -nosalt -K "$(KEY_HEX)" -iv "$(IV_HEX)" -in "$(PLAINTEXT_FILE)" > "$${_CIPHER_TMP}" || \
	{ echo "Error: encryption failed" >&2; exit 1; }; \
	HMAC_HEX=$$(printf '%s' "$(IV_HEX)" | cat - "$${_CIPHER_TMP}" | \
	  openssl dgst -sha256 -mac hmac -macopt hexkey:"$(KEY_HEX)" -binary | xxd -p -c 256) || \
	{ echo "Error: HMAC computation failed" >&2; exit 1; }; \
	{ printf '%s\n' "$(IV_HEX)" "$$HMAC_HEX"; cat "$${_CIPHER_TMP}"; } > "$(OUTPUT_FILE)" || \
	{ echo "Error: failed to write output file" >&2; exit 1; }; \
	rm -f "$${_CIPHER_TMP}"; \
	trap - EXIT

# _decrypt-content: Decrypt SECRET_ENC_FILE to stdout using KEY_HEX
#   Required vars: KEY_HEX, SECRET_ENC_FILE
_decrypt-content:
	@test -n "$(KEY_HEX)" || { echo "Error: KEY_HEX is required" >&2; exit 1; }
	@test -n "$(SECRET_ENC_FILE)" || { echo "Error: SECRET_ENC_FILE is required" >&2; exit 1; }
	@test -f "$(SECRET_ENC_FILE)" || { echo "Error: SECRET_ENC_FILE not found: $(SECRET_ENC_FILE)" >&2; exit 1; }
	@_TMPDIR=$$(mktemp -d); \
	_cleanup() { rm -rf "$${_TMPDIR}"; }; \
	trap _cleanup EXIT; \
	IV_HEX=$$(head -1 "$(SECRET_ENC_FILE)"); \
	STORED_HMAC=$$(sed -n '2p' "$(SECRET_ENC_FILE)"); \
	tail -n +3 "$(SECRET_ENC_FILE)" > "$${_TMPDIR}/cipher.bin"; \
	COMPUTED_HMAC=$$(printf '%s' "$$IV_HEX" | cat - "$${_TMPDIR}/cipher.bin" | \
	  openssl dgst -sha256 -mac hmac -macopt hexkey:"$(KEY_HEX)" -binary | xxd -p -c 256) || \
	{ echo "Error: HMAC computation failed" >&2; exit 1; }; \
	[ "$$COMPUTED_HMAC" = "$$STORED_HMAC" ] || \
	{ echo "Error: HMAC verification failed — ciphertext may be corrupt or tampered" >&2; exit 1; }; \
	openssl enc -aes-256-cbc -d -nosalt -K "$(KEY_HEX)" -iv "$$IV_HEX" -in "$${_TMPDIR}/cipher.bin" || \
	{ echo "Error: decryption failed" >&2; exit 1; }

# _encrypt-key-for-user: Encrypt KEY_HEX for USERNAME → OUTPUT_FILE (GPG)
#   Required vars: KEY_HEX, USERNAME, OUTPUT_FILE
_encrypt-key-for-user:
	@test -n "$(KEY_HEX)" || { echo "Error: KEY_HEX is required" >&2; exit 1; }
	@test -n "$(USERNAME)" || { echo "Error: USERNAME is required" >&2; exit 1; }
	@test -n "$(OUTPUT_FILE)" || { echo "Error: OUTPUT_FILE is required" >&2; exit 1; }
	@test -f "$(USERS_DIR)/$(USERNAME).pub" || { echo "Error: public key not found: $(USERS_DIR)/$(USERNAME).pub" >&2; exit 1; }
	@_cleanup() { if [ -n "$${_PARTIAL_OUT:-}" ] && [ -f "$${_PARTIAL_OUT}" ]; then rm -f "$${_PARTIAL_OUT}"; fi; }; \
	trap _cleanup EXIT; \
	_PARTIAL_OUT="$(OUTPUT_FILE)"; \
	echo "$(KEY_HEX)" | gpg --batch --yes --trust-model always \
	  --homedir "$(GNUPGHOME)" \
	  --recipient-file "$(USERS_DIR)/$(USERNAME).pub" \
	  --encrypt --armor \
	  --output "$(OUTPUT_FILE)" || \
	{ echo "Error: GPG encryption failed for user $(USERNAME)" >&2; rm -f "$(OUTPUT_FILE)"; exit 1; }

# _decrypt-key: Decrypt KEY_ENC_FILE to stdout (uses user's personal GPG keyring)
#   Required vars: KEY_ENC_FILE
_decrypt-key:
	@test -n "$(KEY_ENC_FILE)" || { echo "Error: KEY_ENC_FILE is required" >&2; exit 1; }
	@test -f "$(KEY_ENC_FILE)" || { echo "Error: KEY_ENC_FILE not found: $(KEY_ENC_FILE)" >&2; exit 1; }
	@GNUPGHOME= gpg --batch --yes --quiet --decrypt "$(KEY_ENC_FILE)" || \
	{ echo "Error: GPG decryption failed for $(KEY_ENC_FILE)" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Smoke Test: full round-trip encrypt → decrypt
# ---------------------------------------------------------------------------

## test-crypto: Run full encrypt/decrypt round-trip smoke test
test-crypto:
	@echo "=== Trove Crypto Smoke Test ==="
	@echo ""
	@# --- Setup: isolated test GPG keypair ---
	@TEST_GNUPGHOME=$$(mktemp -d); \
	TEST_TMPDIR=$$(mktemp -d); \
	_cleanup() { \
	  rm -rf "$$TEST_GNUPGHOME" "$$TEST_TMPDIR"; \
	  rm -rf "$(GNUPGHOME)" "$(USERS_DIR)" "$(SECRETS_DIR)"; \
	  mkdir -p "$(GNUPGHOME)" "$(USERS_DIR)" "$(SECRETS_DIR)"; \
	  chmod 700 "$(GNUPGHOME)"; \
	}; \
	trap _cleanup EXIT; \
	chmod 700 "$$TEST_GNUPGHOME"; \
	\
	echo "[1/8] Generating test GPG keypair..."; \
	gpg --batch --yes --homedir "$$TEST_GNUPGHOME" --pinentry-mode loopback --passphrase "" \
	  --quick-generate-key "trove-test@test.local" default default never 2>/dev/null; \
	\
	echo "[2/8] Exporting test public key..."; \
	gpg --batch --yes --homedir "$$TEST_GNUPGHOME" --armor \
	  --export "trove-test@test.local" > "$(USERS_DIR)/testuser.pub"; \
	\
	echo "[3/8] Importing test public key into repo keyring..."; \
	gpg --batch --yes --homedir "$(GNUPGHOME)" --import "$(USERS_DIR)/testuser.pub" 2>/dev/null; \
	\
	echo "[4/8] Generating AES key and IV..."; \
	KEY_HEX=$$(openssl rand -hex 32); \
	IV_HEX=$$(openssl rand -hex 16); \
	\
	echo "--- Text Round-Trip Test ---"; \
	echo "[5/8] Encrypting text content..."; \
	echo "test secret content 12345" > "$$TEST_TMPDIR/plaintext.txt"; \
	openssl enc -aes-256-cbc -nosalt -K "$$KEY_HEX" -iv "$$IV_HEX" \
	  -in "$$TEST_TMPDIR/plaintext.txt" > "$$TEST_TMPDIR/cipher_text.bin"; \
	HMAC_HEX=$$(printf '%s' "$$IV_HEX" | cat - "$$TEST_TMPDIR/cipher_text.bin" | \
	  openssl dgst -sha256 -mac hmac -macopt hexkey:"$$KEY_HEX" -binary | xxd -p -c 256); \
	{ printf '%s\n' "$$IV_HEX" "$$HMAC_HEX"; cat "$$TEST_TMPDIR/cipher_text.bin"; } > "$(SECRETS_DIR)/secret.enc"; \
	\
	echo "[6/8] Encrypting key for test user..."; \
	echo "$$KEY_HEX" | gpg --batch --yes --trust-model always \
	  --homedir "$(GNUPGHOME)" \
	  --recipient-file "$(USERS_DIR)/testuser.pub" \
	  --encrypt --armor \
	  --output "$(SECRETS_DIR)/testuser.key.enc"; \
	\
	echo "[7/8] Decrypting key and content (text)..."; \
	RECOVERED_KEY=$$(gpg --batch --yes --quiet --homedir "$$TEST_GNUPGHOME" \
	  --pinentry-mode loopback --passphrase "" \
	  --decrypt "$(SECRETS_DIR)/testuser.key.enc"); \
	RECOVERED_IV=$$(head -1 "$(SECRETS_DIR)/secret.enc"); \
	STORED_HMAC=$$(sed -n '2p' "$(SECRETS_DIR)/secret.enc"); \
	tail -n +3 "$(SECRETS_DIR)/secret.enc" > "$$TEST_TMPDIR/cipher_text_rec.bin"; \
	COMPUTED_HMAC=$$(printf '%s' "$$RECOVERED_IV" | cat - "$$TEST_TMPDIR/cipher_text_rec.bin" | \
	  openssl dgst -sha256 -mac hmac -macopt hexkey:"$$RECOVERED_KEY" -binary | xxd -p -c 256); \
	[ "$$COMPUTED_HMAC" = "$$STORED_HMAC" ] || { echo "  ✗ FAIL: HMAC verification failed" >&2; exit 1; }; \
	RECOVERED_TEXT=$$(openssl enc -aes-256-cbc -d -nosalt -K "$$RECOVERED_KEY" -iv "$$RECOVERED_IV" \
	  -in "$$TEST_TMPDIR/cipher_text_rec.bin"); \
	ORIGINAL_TEXT=$$(cat "$$TEST_TMPDIR/plaintext.txt"); \
	if [ "$$RECOVERED_TEXT" = "$$ORIGINAL_TEXT" ]; then \
	  echo "  ✓ PASS: Text round-trip matches"; \
	else \
	  echo "  ✗ FAIL: Text round-trip mismatch" >&2; \
	  echo "  Expected: $$ORIGINAL_TEXT" >&2; \
	  echo "  Got:      $$RECOVERED_TEXT" >&2; \
	  exit 1; \
	fi; \
	\
	echo ""; \
	echo "--- Binary Round-Trip Test ---"; \
	echo "[8/8] Testing 10KB binary round-trip..."; \
	dd if=/dev/urandom of="$$TEST_TMPDIR/binary.dat" bs=1024 count=10 2>/dev/null; \
	ORIG_SHA=$$(shasum -a 256 "$$TEST_TMPDIR/binary.dat" | awk '{print $$1}'); \
	BIN_KEY=$$(openssl rand -hex 32); \
	BIN_IV=$$(openssl rand -hex 16); \
	openssl enc -aes-256-cbc -nosalt -K "$$BIN_KEY" -iv "$$BIN_IV" \
	  -in "$$TEST_TMPDIR/binary.dat" > "$$TEST_TMPDIR/binary_cipher.bin"; \
	BIN_HMAC=$$(printf '%s' "$$BIN_IV" | cat - "$$TEST_TMPDIR/binary_cipher.bin" | \
	  openssl dgst -sha256 -mac hmac -macopt hexkey:"$$BIN_KEY" -binary | xxd -p -c 256); \
	{ printf '%s\n' "$$BIN_IV" "$$BIN_HMAC"; cat "$$TEST_TMPDIR/binary_cipher.bin"; } > "$(SECRETS_DIR)/binary.enc"; \
	DEC_IV=$$(head -1 "$(SECRETS_DIR)/binary.enc"); \
	DEC_STORED_HMAC=$$(sed -n '2p' "$(SECRETS_DIR)/binary.enc"); \
	tail -n +3 "$(SECRETS_DIR)/binary.enc" > "$$TEST_TMPDIR/binary_dec_cipher.bin"; \
	DEC_COMPUTED_HMAC=$$(printf '%s' "$$DEC_IV" | cat - "$$TEST_TMPDIR/binary_dec_cipher.bin" | \
	  openssl dgst -sha256 -mac hmac -macopt hexkey:"$$BIN_KEY" -binary | xxd -p -c 256); \
	[ "$$DEC_COMPUTED_HMAC" = "$$DEC_STORED_HMAC" ] || { echo "  ✗ FAIL: HMAC verification failed" >&2; exit 1; }; \
	openssl enc -aes-256-cbc -d -nosalt -K "$$BIN_KEY" -iv "$$DEC_IV" \
	  -in "$$TEST_TMPDIR/binary_dec_cipher.bin" > "$$TEST_TMPDIR/binary_recovered.dat"; \
	RECV_SHA=$$(shasum -a 256 "$$TEST_TMPDIR/binary_recovered.dat" | awk '{print $$1}'); \
	if [ "$$ORIG_SHA" = "$$RECV_SHA" ]; then \
	  echo "  ✓ PASS: Binary round-trip SHA-256 matches"; \
	  echo "  SHA-256: $$ORIG_SHA"; \
	else \
	  echo "  ✗ FAIL: Binary round-trip SHA-256 mismatch" >&2; \
	  echo "  Original: $$ORIG_SHA" >&2; \
	  echo "  Recovered: $$RECV_SHA" >&2; \
	  exit 1; \
	fi; \
	\
	echo ""; \
	echo "=== All crypto smoke tests PASSED ==="

# ---------------------------------------------------------------------------
# Core Operations
# ---------------------------------------------------------------------------

# add-user: Register a user's public GPG key
#   Required vars: NAME, KEY
## add-user: Register a user's GPG public key (NAME= KEY=)
add-user:
	@test -n "$(NAME)" || { echo "Error: NAME= is required" >&2; exit 1; }
	@echo "$(NAME)" | grep -qE '^[a-zA-Z0-9._@-]+$$' || { echo "Error: Invalid NAME '$(NAME)' — must match [a-zA-Z0-9._@-]+" >&2; exit 1; }
	@test -n "$(KEY)" || { echo "Error: KEY= is required" >&2; exit 1; }
	@test -f "$(KEY)" || { echo "Error: KEY file not found: $(KEY)" >&2; exit 1; }
	@gpg --show-keys "$(KEY)" >/dev/null 2>&1 || { echo "Error: KEY is not a valid GPG public key: $(KEY)" >&2; exit 1; }
	@cp "$(KEY)" "$(USERS_DIR)/$(NAME).pub" || { echo "Error: Failed to copy key to $(USERS_DIR)/$(NAME).pub" >&2; exit 1; }
	@gpg --batch --yes --homedir "$(GNUPGHOME)" --import "$(USERS_DIR)/$(NAME).pub" 2>/dev/null || { echo "Error: Failed to import key into isolated keyring" >&2; exit 1; }
	@echo "User '$(NAME)' added successfully"

# generate-key: Generate a new GPG keypair for a user
#   Required vars: NAME (optional: EMAIL, output defaults to users/NAME.pub)
## generate-key: Generate a new GPG keypair (NAME= [EMAIL=])
generate-key:
	@test -n "$(NAME)" || { echo "Error: NAME= is required" >&2; exit 1; }
	@echo "$(NAME)" | grep -qE '^[a-zA-Z0-9._@-]+$$' || { echo "Error: Invalid NAME '$(NAME)' — must match [a-zA-Z0-9._@-]+" >&2; exit 1; }
	@USER_EMAIL="$(if $(EMAIL),$(EMAIL),$(NAME)@trove.local)"; \
	echo "Generating GPG keypair for $$USER_EMAIL..."; \
	# Note: --passphrase "" generates a key with no passphrase — private key is unprotected at rest.
	# For passphrase-protected keys, generate manually and register with: make add-user NAME=... KEY=...
	gpg --batch --yes --pinentry-mode loopback --passphrase "" \
	  --quick-generate-key "$$USER_EMAIL" default default never 2>&1 | grep -v "^gpg:" || true; \
	echo "Exporting public key to $(USERS_DIR)/$(NAME).pub..."; \
	gpg --armor --export "$$USER_EMAIL" > "$(USERS_DIR)/$(NAME).pub" || \
	{ echo "Error: Failed to export public key" >&2; exit 1; }; \
	gpg --batch --yes --homedir "$(GNUPGHOME)" --import "$(USERS_DIR)/$(NAME).pub" 2>/dev/null || \
	{ echo "Error: Failed to import key into isolated keyring" >&2; exit 1; }; \
	echo "✓ Keypair generated and public key registered"; \
	echo "  User ID: $$USER_EMAIL"; \
	echo "  Public key: $(USERS_DIR)/$(NAME).pub"; \
	echo "  Note: Private key stored in your personal GPG keyring (~/.gnupg)"

# import-key: Import an existing public key from your GPG keyring
#   Required vars: NAME (optional: EMAIL)
## import-key: Import existing public key from your GPG keyring (NAME= [EMAIL=])
import-key:
	@test -n "$(NAME)" || { echo "Error: NAME= is required" >&2; exit 1; }
	@echo "$(NAME)" | grep -qE '^[a-zA-Z0-9._@-]+$$' || { echo "Error: Invalid NAME '$(NAME)' — must match [a-zA-Z0-9._@-]+" >&2; exit 1; }
	@USER_EMAIL="$(if $(EMAIL),$(EMAIL),$(NAME)@trove.local)"; \
	echo "Searching for key with UID containing '$$USER_EMAIL'..."; \
	gpg --list-keys "$$USER_EMAIL" >/dev/null 2>&1 || \
	{ echo "Error: No key found for '$$USER_EMAIL' in your GPG keyring" >&2; \
	  echo "Available keys:" >&2; \
	  gpg --list-keys --with-colons | grep "^uid" | cut -d: -f10 | head -10 >&2; \
	  exit 1; }; \
	echo "Exporting public key to $(USERS_DIR)/$(NAME).pub..."; \
	gpg --armor --export "$$USER_EMAIL" > "$(USERS_DIR)/$(NAME).pub" || \
	{ echo "Error: Failed to export public key" >&2; exit 1; }; \
	gpg --batch --yes --homedir "$(GNUPGHOME)" --import "$(USERS_DIR)/$(NAME).pub" 2>/dev/null || \
	{ echo "Error: Failed to import key into isolated keyring" >&2; exit 1; }; \
	echo "✓ Public key imported and registered"; \
	echo "  User ID: $$USER_EMAIL"; \
	echo "  Public key: $(USERS_DIR)/$(NAME).pub"

# export-key: Export a user's GPG keypair (public + secret) to files for transfer
#   Required vars: NAME (optional: EMAIL, DIR — defaults to current directory)
## export-key: Export a user's GPG keypair to files for transfer (NAME= [EMAIL=] [DIR=.])
export-key:
	@test -n "$(NAME)" || { echo "Error: NAME= is required" >&2; exit 1; }
	@echo "$(NAME)" | grep -qE '^[a-zA-Z0-9._@-]+$$' || { echo "Error: Invalid NAME '$(NAME)' — must match [a-zA-Z0-9._@-]+" >&2; exit 1; }
	@USER_EMAIL="$(if $(EMAIL),$(EMAIL),$(NAME)@trove.local)"; \
	EXPORT_DIR="$(if $(DIR),$(DIR),.)"; \
	echo "Exporting keypair for '$$USER_EMAIL'..."; \
	(unset GNUPGHOME; gpg --list-keys "$$USER_EMAIL") >/dev/null 2>&1 || \
	{ echo "Error: No key found for '$$USER_EMAIL' in your GPG keyring" >&2; \
	  echo "Available keys:" >&2; \
	  (unset GNUPGHOME; gpg --list-keys --with-colons) | grep "^uid" | cut -d: -f10 | head -10 >&2; \
	  exit 1; }; \
	echo "[1/2] Exporting public key to $$EXPORT_DIR/$(NAME).pub..."; \
	(unset GNUPGHOME; gpg --armor --export "$$USER_EMAIL") > "$$EXPORT_DIR/$(NAME).pub" || \
	{ echo "Error: Failed to export public key" >&2; exit 1; }; \
	echo "[2/2] Exporting secret key to $$EXPORT_DIR/$(NAME).secret.key..."; \
	(unset GNUPGHOME; gpg --armor --export-secret-keys "$$USER_EMAIL") > "$$EXPORT_DIR/$(NAME).secret.key" || \
	{ echo "Error: Failed to export secret key" >&2; rm -f "$$EXPORT_DIR/$(NAME).pub"; exit 1; }; \
	echo ""; \
	echo "✓ Keypair exported"; \
	echo "  Public key:  $$EXPORT_DIR/$(NAME).pub"; \
	echo "  Secret key:  $$EXPORT_DIR/$(NAME).secret.key"; \
	echo ""; \
	echo "  Transfer both files to the new machine, then run:"; \
	echo "    make import-secret-key NAME=$(NAME) KEY=$$EXPORT_DIR/$(NAME).secret.key"; \
	echo ""; \
	echo "  ⚠  Delete $(NAME).secret.key after transfer — do not commit it to git"

# import-secret-key: Import a GPG secret key (and its public key) onto this machine and register the user
#   Required vars: NAME, KEY (path to the .secret.key file)
## import-secret-key: Import a GPG secret key onto this machine (NAME= KEY=)
import-secret-key:
	@test -n "$(NAME)" || { echo "Error: NAME= is required" >&2; exit 1; }
	@echo "$(NAME)" | grep -qE '^[a-zA-Z0-9._@-]+$$' || { echo "Error: Invalid NAME '$(NAME)' — must match [a-zA-Z0-9._@-]+" >&2; exit 1; }
	@test -n "$(KEY)" || { echo "Error: KEY= is required (path to .secret.key file)" >&2; exit 1; }
	@test -f "$(KEY)" || { echo "Error: KEY file not found: $(KEY)" >&2; exit 1; }
	@echo "Importing secret key from $(KEY)..."; \
	echo "[1/3] Importing secret key into personal GPG keyring (~/.gnupg)..."; \
	(unset GNUPGHOME; gpg --batch --yes --import "$(KEY)") 2>&1 | grep -v "^gpg:" || true; \
	echo "[2/3] Exporting public key to $(USERS_DIR)/$(NAME).pub..."; \
	USER_EMAIL=$$(unset GNUPGHOME; gpg --with-colons --import-options show-only --import "$(KEY)" 2>/dev/null | grep "^uid" | head -1 | cut -d: -f10); \
	(unset GNUPGHOME; gpg --armor --export "$$USER_EMAIL") > "$(USERS_DIR)/$(NAME).pub" || \
	{ echo "Error: Failed to export public key after import" >&2; exit 1; }; \
	echo "[3/3] Importing public key into repo keyring (.gnupg/)..."; \
	gpg --batch --yes --homedir "$(GNUPGHOME)" --import "$(USERS_DIR)/$(NAME).pub" 2>/dev/null || \
	{ echo "Error: Failed to import key into isolated keyring" >&2; exit 1; }; \
	echo ""; \
	echo "✓ Secret key imported and user registered"; \
	echo "  User ID: $$USER_EMAIL"; \
	echo "  Trove Name: $(NAME)"; \
	echo "  Public key: $(USERS_DIR)/$(NAME).pub"; \
	echo ""; \
	echo "  ⚠  Delete the .secret.key file now — it's no longer needed:"; \
	echo "    rm $(KEY)"

# new-user: Interactive setup for new Trove user (walks through keypair generation, export, and registration)
#   Required vars: NAME (optional: EMAIL, defaults to NAME@trove.local)
## new-user: Interactive setup for new Trove user (NAME= [EMAIL=])
new-user:
	@test -n "$(NAME)" || { echo "Error: NAME= is required" >&2; exit 1; }
	@echo "$(NAME)" | grep -qE '^[a-zA-Z0-9._@-]+$$' || { echo "Error: Invalid NAME '$(NAME)' — must match [a-zA-Z0-9._@-]+" >&2; exit 1; }
	@NAME="$(NAME)" EMAIL="$(EMAIL)" USERS_DIR="$(USERS_DIR)" GNUPGHOME="$(GNUPGHOME)" bash -c '\
		USER_EMAIL="$${EMAIL:-$$NAME@trove.local}"; \
		echo "=== Setting up new Trove user ==="; \
		echo ""; \
		echo "[1/3] Generating GPG keypair in your personal keyring (~/.gnupg)..."; \
		(unset GNUPGHOME; gpg --batch --yes --pinentry-mode loopback --passphrase "" \
		  --quick-generate-key "$$USER_EMAIL" default default never 2>&1 | grep -v "^gpg:" || true); \
		(unset GNUPGHOME; gpg --list-keys "$$USER_EMAIL" >/dev/null 2>&1) || \
		{ echo "Error: Keypair generation failed for $$USER_EMAIL" >&2; exit 1; }; \
		echo "✓ Keypair generated"; \
		echo ""; \
		echo "[2/3] Exporting public key to $(USERS_DIR)/$(NAME).pub..."; \
		(unset GNUPGHOME; gpg --armor --export "$$USER_EMAIL") > "$(USERS_DIR)/$(NAME).pub" || \
		{ echo "Error: Failed to export public key" >&2; exit 1; }; \
		test -f "$(USERS_DIR)/$(NAME).pub" || \
		{ echo "Error: Public key file not created" >&2; exit 1; }; \
		echo "✓ Public key exported"; \
		echo ""; \
		echo "[3/3] Importing public key to repo keyring (.gnupg/)..."; \
		gpg --batch --yes --homedir "$(GNUPGHOME)" --import "$(USERS_DIR)/$(NAME).pub" 2>/dev/null || \
		{ echo "Error: Failed to import key into isolated keyring" >&2; exit 1; }; \
		echo "✓ Public key registered in repo keyring"; \
		echo ""; \
		echo "=== Setup Complete ==="; \
		echo ""; \
		echo "✓ New user setup complete!"; \
		echo ""; \
		echo "  User ID: $$USER_EMAIL"; \
		echo "  Trove Name: $(NAME)"; \
		echo ""; \
		echo "  Public key registered:"; \
		echo "    - File: $(USERS_DIR)/$(NAME).pub"; \
		echo "    - Imported to repo keyring (.gnupg/)"; \
		echo ""; \
		echo "  Private key location:"; \
		echo "    - Stored in: ~/.gnupg (your personal GPG keyring)"; \
		echo "    - Trove accesses it when you decrypt secrets"; \
		echo ""; \
		echo "  How to use:"; \
		echo "    1. Create secrets: make create-secret NAME=mysecret FILE=secret.txt"; \
		echo "       (Uses PM_USER=$(NAME) automatically)"; \
		echo ""; \
		echo "    2. Read secrets: make read-secret NAME=mysecret"; \
		echo "       (GPG uses your private key from ~/.gnupg)"; \
		echo ""; \
		echo "    3. Grant access: make grant-access NAME=mysecret USER=bob"; \
		echo ""; \
		echo "  Next steps:"; \
		echo "    - Commit users/$(NAME).pub to git"; \
		echo "    - Share the repo with your team"; \
	'

# create-secret: Encrypt a file and store it as a named secret
#   Required vars: NAME, FILE
## create-secret: Encrypt a file and store it as a secret (NAME= FILE=)
create-secret:
	@test -n "$(NAME)" || { echo "Error: NAME= is required" >&2; exit 1; }
	@echo "$(NAME)" | grep -qE '^[a-zA-Z0-9._/-]+$$' || { echo "Error: Invalid NAME '$(NAME)' — must match [a-zA-Z0-9._/-]+" >&2; exit 1; }
	@echo "$(NAME)" | grep -qE '\.\./|^\.\.|^/' && { echo "Error: Invalid NAME '$(NAME)' — path traversal not allowed" >&2; exit 1; } || true
	@test -n "$(FILE)" || { echo "Error: FILE= is required" >&2; exit 1; }
	@test -f "$(FILE)" || { echo "Error: FILE not found: $(FILE)" >&2; exit 1; }
	@test -r "$(FILE)" || { echo "Error: FILE not readable: $(FILE)" >&2; exit 1; }
	@test ! -d "$(SECRETS_DIR)/$(NAME)" || { echo "Error: Secret '$(NAME)' already exists" >&2; exit 1; }
	@test -f "$(USERS_DIR)/$(TROVE_USER).pub" || { echo "Error: Current user '$(TROVE_USER)' is not registered — run add-user first" >&2; exit 1; }
	@SECRET_DIR="$(SECRETS_DIR)/$(NAME)"; \
	_cleanup() { \
	  if [ -n "$${_TMPDIR:-}" ] && [ -d "$${_TMPDIR}" ]; then rm -rf "$${_TMPDIR}"; fi; \
	}; \
	trap _cleanup EXIT; \
	_TMPDIR=$$(mktemp -d); \
	KEY_HEX=$$(openssl rand -hex 32) || { echo "Error: Failed to generate AES key" >&2; exit 1; }; \
	IV_HEX=$$(openssl rand -hex 16) || { echo "Error: Failed to generate IV" >&2; exit 1; }; \
	mkdir -p "$$(dirname "$$SECRET_DIR")" || { echo "Error: Failed to create parent directories" >&2; exit 1; }; \
	mkdir -p "$$SECRET_DIR" || { echo "Error: Failed to create secret directory" >&2; exit 1; }; \
	openssl enc -aes-256-cbc -nosalt -K "$$KEY_HEX" -iv "$$IV_HEX" -in "$(FILE)" > "$${_TMPDIR}/cipher.bin" || \
	{ echo "Error: Encryption failed" >&2; rm -rf "$$SECRET_DIR"; exit 1; }; \
	HMAC_HEX=$$(printf '%s' "$$IV_HEX" | cat - "$${_TMPDIR}/cipher.bin" | \
	  openssl dgst -sha256 -mac hmac -macopt hexkey:"$$KEY_HEX" -binary | xxd -p -c 256) || \
	{ echo "Error: HMAC computation failed" >&2; rm -rf "$$SECRET_DIR"; exit 1; }; \
	{ printf '%s\n' "$$IV_HEX" "$$HMAC_HEX"; cat "$${_TMPDIR}/cipher.bin"; } > "$$SECRET_DIR/secret.enc" || \
	{ echo "Error: Failed to write secret" >&2; rm -rf "$$SECRET_DIR"; exit 1; }; \
	echo "$$KEY_HEX" | gpg --batch --yes --trust-model always \
	  --homedir "$(GNUPGHOME)" \
	  --recipient-file "$(USERS_DIR)/$(TROVE_USER).pub" \
	  --encrypt --armor \
	  --output "$$SECRET_DIR/$(TROVE_USER).key.enc" || \
	{ echo "Error: Failed to encrypt key for user '$(TROVE_USER)'" >&2; rm -rf "$$SECRET_DIR"; exit 1; }; \
	echo "Secret '$(NAME)' created (access granted to $(TROVE_USER))"

# read-secret: Decrypt and output a secret's content to stdout
#   Required vars: NAME
## read-secret: Decrypt and print a secret to stdout (NAME=)
read-secret:
	@test -n "$(NAME)" || { echo "Error: NAME= is required" >&2; exit 1; }
	@echo "$(NAME)" | grep -qE '^[a-zA-Z0-9._/-]+$$' || { echo "Error: Invalid NAME '$(NAME)' — must match [a-zA-Z0-9._/-]+" >&2; exit 1; }
	@echo "$(NAME)" | grep -qE '\.\./|^\.\.|^/' && { echo "Error: Invalid NAME '$(NAME)' — path traversal not allowed" >&2; exit 1; } || true
	@test -d "$(SECRETS_DIR)/$(NAME)" || { echo "Error: Secret '$(NAME)' does not exist" >&2; exit 1; }
	@test -f "$(SECRETS_DIR)/$(NAME)/$(TROVE_USER).key.enc" || { echo "Error: Access denied — user '$(TROVE_USER)' does not have access to secret '$(NAME)'" >&2; exit 1; }
	@_cleanup() { \
	  if [ -n "$${_TMPDIR:-}" ] && [ -d "$${_TMPDIR}" ]; then rm -rf "$${_TMPDIR}"; fi; \
	}; \
	trap _cleanup EXIT; \
	_TMPDIR=$$(mktemp -d); \
	KEY_HEX=$$(unset GNUPGHOME; gpg --batch --yes --quiet --decrypt "$(SECRETS_DIR)/$(NAME)/$(TROVE_USER).key.enc") || \
	{ echo "Error: Failed to decrypt key — check your GPG private key" >&2; exit 1; }; \
	IV_HEX=$$(head -1 "$(SECRETS_DIR)/$(NAME)/secret.enc"); \
	STORED_HMAC=$$(sed -n '2p' "$(SECRETS_DIR)/$(NAME)/secret.enc"); \
	tail -n +3 "$(SECRETS_DIR)/$(NAME)/secret.enc" > "$${_TMPDIR}/cipher.bin"; \
	COMPUTED_HMAC=$$(printf '%s' "$$IV_HEX" | cat - "$${_TMPDIR}/cipher.bin" | \
	  openssl dgst -sha256 -mac hmac -macopt hexkey:"$$KEY_HEX" -binary | xxd -p -c 256) || \
	{ echo "Error: HMAC computation failed" >&2; exit 1; }; \
	[ "$$COMPUTED_HMAC" = "$$STORED_HMAC" ] || \
	{ echo "Error: HMAC verification failed — ciphertext may be corrupt or tampered" >&2; exit 1; }; \
	openssl enc -aes-256-cbc -d -nosalt -K "$$KEY_HEX" -iv "$$IV_HEX" -in "$${_TMPDIR}/cipher.bin" || \
	{ echo "Error: Failed to decrypt secret content" >&2; exit 1; }

# update-secret: Re-encrypt a secret with new content, keeping the same symmetric key
#   Required vars: NAME, FILE
## update-secret: Update a secret's content (NAME= FILE=)
update-secret:
	@test -n "$(NAME)" || { echo "Error: NAME= is required" >&2; exit 1; }
	@echo "$(NAME)" | grep -qE '^[a-zA-Z0-9._/-]+$$' || { echo "Error: Invalid NAME '$(NAME)' — must match [a-zA-Z0-9._/-]+" >&2; exit 1; }
	@echo "$(NAME)" | grep -qE '\.\./|^\.\.|^/' && { echo "Error: Invalid NAME '$(NAME)' — path traversal not allowed" >&2; exit 1; } || true
	@test -n "$(FILE)" || { echo "Error: FILE= is required" >&2; exit 1; }
	@test -f "$(FILE)" || { echo "Error: FILE not found: $(FILE)" >&2; exit 1; }
	@test -r "$(FILE)" || { echo "Error: FILE not readable: $(FILE)" >&2; exit 1; }
	@test -d "$(SECRETS_DIR)/$(NAME)" || { echo "Error: Secret '$(NAME)' does not exist" >&2; exit 1; }
	@test -f "$(SECRETS_DIR)/$(NAME)/$(TROVE_USER).key.enc" || { echo "Error: Access denied — user '$(TROVE_USER)' does not have access to secret '$(NAME)'" >&2; exit 1; }
	@_cleanup() { \
	  if [ -n "$${_TMPDIR:-}" ] && [ -d "$${_TMPDIR}" ]; then rm -rf "$${_TMPDIR}"; fi; \
	}; \
	trap _cleanup EXIT; \
	_TMPDIR=$$(mktemp -d); \
	KEY_HEX=$$(unset GNUPGHOME; gpg --batch --yes --quiet --decrypt "$(SECRETS_DIR)/$(NAME)/$(TROVE_USER).key.enc") || \
	{ echo "Error: Failed to decrypt key — check your GPG private key" >&2; exit 1; }; \
	IV_HEX=$$(openssl rand -hex 16) || { echo "Error: Failed to generate IV" >&2; exit 1; }; \
	openssl enc -aes-256-cbc -nosalt -K "$$KEY_HEX" -iv "$$IV_HEX" -in "$(FILE)" > "$${_TMPDIR}/cipher.bin" || \
	{ echo "Error: Encryption failed" >&2; exit 1; }; \
	HMAC_HEX=$$(printf '%s' "$$IV_HEX" | cat - "$${_TMPDIR}/cipher.bin" | \
	  openssl dgst -sha256 -mac hmac -macopt hexkey:"$$KEY_HEX" -binary | xxd -p -c 256) || \
	{ echo "Error: HMAC computation failed" >&2; exit 1; }; \
	{ printf '%s\n' "$$IV_HEX" "$$HMAC_HEX"; cat "$${_TMPDIR}/cipher.bin"; } > "$${_TMPDIR}/secret.enc" || \
	{ echo "Error: Failed to write encrypted content" >&2; exit 1; }; \
	mv "$${_TMPDIR}/secret.enc" "$(SECRETS_DIR)/$(NAME)/secret.enc" || \
	{ echo "Error: Failed to update secret" >&2; exit 1; }; \
	echo "Secret '$(NAME)' updated"

# grant-access: Share a secret's symmetric key with another user
#   Required vars: NAME, USER
## grant-access: Give a user access to a secret (NAME= USER=)
grant-access:
	@test -n "$(NAME)" || { echo "Error: NAME= is required" >&2; exit 1; }
	@echo "$(NAME)" | grep -qE '^[a-zA-Z0-9._/-]+$$' || { echo "Error: Invalid NAME '$(NAME)' — must match [a-zA-Z0-9._/-]+" >&2; exit 1; }
	@echo "$(NAME)" | grep -qE '\.\./|^\.\.|^/' && { echo "Error: Invalid NAME '$(NAME)' — path traversal not allowed" >&2; exit 1; } || true
	@test -n "$(USER)" || { echo "Error: USER= is required" >&2; exit 1; }
	@echo "$(USER)" | grep -qE '^[a-zA-Z0-9._@-]+$$' || { echo "Error: Invalid USER '$(USER)' — must match [a-zA-Z0-9._@-]+" >&2; exit 1; }
	@test -d "$(SECRETS_DIR)/$(NAME)" || { echo "Error: Secret '$(NAME)' does not exist" >&2; exit 1; }
	@test -f "$(USERS_DIR)/$(USER).pub" || { echo "Error: User '$(USER)' is not registered — unknown user" >&2; exit 1; }
	@test -f "$(SECRETS_DIR)/$(NAME)/$(TROVE_USER).key.enc" || { echo "Error: Access denied — user '$(TROVE_USER)' does not have access to secret '$(NAME)'" >&2; exit 1; }
	@test ! -f "$(SECRETS_DIR)/$(NAME)/$(USER).key.enc" || { echo "Error: User '$(USER)' already has access to secret '$(NAME)'" >&2; exit 1; }
	@_cleanup() { \
	  if [ -n "$${_TMPDIR:-}" ] && [ -d "$${_TMPDIR}" ]; then rm -rf "$${_TMPDIR}"; fi; \
	}; \
	trap _cleanup EXIT; \
	_TMPDIR=$$(mktemp -d); \
	KEY_HEX=$$(unset GNUPGHOME; gpg --batch --yes --quiet --decrypt "$(SECRETS_DIR)/$(NAME)/$(TROVE_USER).key.enc") || \
	{ echo "Error: Failed to decrypt key — check your GPG private key" >&2; exit 1; }; \
	echo "$$KEY_HEX" | gpg --batch --yes --trust-model always \
	  --homedir "$(GNUPGHOME)" \
	  --recipient-file "$(USERS_DIR)/$(USER).pub" \
	  --encrypt --armor \
	  --output "$(SECRETS_DIR)/$(NAME)/$(USER).key.enc" || \
	{ echo "Error: GPG encryption failed for user $(USER)" >&2; exit 1; }; \
	echo "Access to secret '$(NAME)' granted to user '$(USER)'"

# revoke-access: Remove a user's access to a secret
#   Required vars: NAME, USER
## revoke-access: Remove a user's access to a secret (NAME= USER=)
revoke-access:
	@test -n "$(NAME)" || { echo "Error: NAME= is required" >&2; exit 1; }
	@echo "$(NAME)" | grep -qE '^[a-zA-Z0-9._/-]+$$' || { echo "Error: Invalid NAME '$(NAME)' — must match [a-zA-Z0-9._/-]+" >&2; exit 1; }
	@echo "$(NAME)" | grep -qE '\.\./|^\.\.|^/' && { echo "Error: Invalid NAME '$(NAME)' — path traversal not allowed" >&2; exit 1; } || true
	@test -n "$(USER)" || { echo "Error: USER= is required" >&2; exit 1; }
	@echo "$(USER)" | grep -qE '^[a-zA-Z0-9._@-]+$$' || { echo "Error: Invalid USER '$(USER)' — must match [a-zA-Z0-9._@-]+" >&2; exit 1; }
	@test -f "$(SECRETS_DIR)/$(NAME)/$(USER).key.enc" || { echo "Error: User '$(USER)' does not have access to secret '$(NAME)'" >&2; exit 1; }
	@rm -f "$(SECRETS_DIR)/$(NAME)/$(USER).key.enc" || { echo "Error: Failed to revoke access" >&2; exit 1; }
	@echo "Access to secret '$(NAME)' revoked for user '$(USER)'"

# rotate-secret: Re-encrypt a secret with new key material, re-granting all current users
#   Required vars: NAME
#   Use after revoking a user to ensure the revoked user's copy of the key can no longer
#   decrypt the new ciphertext.
## rotate-secret: Re-key a secret and re-grant all current users (NAME=)
rotate-secret:
	@test -n "$(NAME)" || { echo "Error: NAME= is required" >&2; exit 1; }
	@echo "$(NAME)" | grep -qE '^[a-zA-Z0-9._/-]+$$' || { echo "Error: Invalid NAME '$(NAME)' — must match [a-zA-Z0-9._/-]+" >&2; exit 1; }
	@echo "$(NAME)" | grep -qE '\.\./|^\.\.|^/' && { echo "Error: Invalid NAME '$(NAME)' — path traversal not allowed" >&2; exit 1; } || true
	@test -d "$(SECRETS_DIR)/$(NAME)" || { echo "Error: Secret '$(NAME)' does not exist" >&2; exit 1; }
	@test -f "$(SECRETS_DIR)/$(NAME)/$(TROVE_USER).key.enc" || { echo "Error: Access denied — user '$(TROVE_USER)' does not have access to secret '$(NAME)'" >&2; exit 1; }
	@_cleanup() { \
	  if [ -n "$${_TMPDIR:-}" ] && [ -d "$${_TMPDIR}" ]; then rm -rf "$${_TMPDIR}"; fi; \
	}; \
	trap _cleanup EXIT; \
	_TMPDIR=$$(mktemp -d); \
	echo "Rotating secret '$(NAME)'..."; \
	echo "[1/3] Decrypting current content with existing key..."; \
	OLD_KEY_HEX=$$(unset GNUPGHOME; gpg --batch --yes --quiet --decrypt "$(SECRETS_DIR)/$(NAME)/$(TROVE_USER).key.enc") || \
	{ echo "Error: Failed to decrypt key — check your GPG private key" >&2; exit 1; }; \
	OLD_IV_HEX=$$(head -1 "$(SECRETS_DIR)/$(NAME)/secret.enc"); \
	OLD_STORED_HMAC=$$(sed -n '2p' "$(SECRETS_DIR)/$(NAME)/secret.enc"); \
	tail -n +3 "$(SECRETS_DIR)/$(NAME)/secret.enc" > "$${_TMPDIR}/old_cipher.bin"; \
	OLD_COMPUTED_HMAC=$$(printf '%s' "$$OLD_IV_HEX" | cat - "$${_TMPDIR}/old_cipher.bin" | \
	  openssl dgst -sha256 -mac hmac -macopt hexkey:"$$OLD_KEY_HEX" -binary | xxd -p -c 256) || \
	{ echo "Error: HMAC computation failed" >&2; exit 1; }; \
	[ "$$OLD_COMPUTED_HMAC" = "$$OLD_STORED_HMAC" ] || \
	{ echo "Error: HMAC verification failed — ciphertext may be corrupt or tampered" >&2; exit 1; }; \
	openssl enc -aes-256-cbc -d -nosalt -K "$$OLD_KEY_HEX" -iv "$$OLD_IV_HEX" \
	  -in "$${_TMPDIR}/old_cipher.bin" > "$${_TMPDIR}/plaintext" || \
	{ echo "Error: Failed to decrypt secret content" >&2; exit 1; }; \
	echo "[2/3] Re-encrypting with new key material..."; \
	NEW_KEY_HEX=$$(openssl rand -hex 32) || { echo "Error: Failed to generate new AES key" >&2; exit 1; }; \
	NEW_IV_HEX=$$(openssl rand -hex 16) || { echo "Error: Failed to generate new IV" >&2; exit 1; }; \
	openssl enc -aes-256-cbc -nosalt -K "$$NEW_KEY_HEX" -iv "$$NEW_IV_HEX" \
	  -in "$${_TMPDIR}/plaintext" > "$${_TMPDIR}/new_cipher.bin" || \
	{ echo "Error: Re-encryption failed" >&2; exit 1; }; \
	NEW_HMAC_HEX=$$(printf '%s' "$$NEW_IV_HEX" | cat - "$${_TMPDIR}/new_cipher.bin" | \
	  openssl dgst -sha256 -mac hmac -macopt hexkey:"$$NEW_KEY_HEX" -binary | xxd -p -c 256) || \
	{ echo "Error: HMAC computation failed" >&2; exit 1; }; \
	{ printf '%s\n' "$$NEW_IV_HEX" "$$NEW_HMAC_HEX"; cat "$${_TMPDIR}/new_cipher.bin"; } > "$${_TMPDIR}/secret.enc" || \
	{ echo "Error: Failed to write rotated secret" >&2; exit 1; }; \
	echo "[3/3] Re-wrapping key for all current users..."; \
	for key_enc in "$(SECRETS_DIR)/$(NAME)"/*.key.enc; do \
	  user=$$(basename "$$key_enc" .key.enc); \
	  if [ -f "$(USERS_DIR)/$$user.pub" ]; then \
	    echo "$$NEW_KEY_HEX" | gpg --batch --yes --trust-model always \
	      --homedir "$(GNUPGHOME)" \
	      --recipient-file "$(USERS_DIR)/$$user.pub" \
	      --encrypt --armor \
	      --output "$${_TMPDIR}/$$user.key.enc" || \
	    { echo "Error: Failed to re-encrypt key for user '$$user'" >&2; exit 1; }; \
	    echo "  ✓ $$user"; \
	  else \
	    echo "  ⚠  Skipping $$user — no public key found in $(USERS_DIR)" >&2; \
	  fi; \
	done; \
	cp "$${_TMPDIR}/secret.enc" "$(SECRETS_DIR)/$(NAME)/secret.enc" || \
	{ echo "Error: Failed to write rotated secret" >&2; exit 1; }; \
	for new_key_enc in "$${_TMPDIR}"/*.key.enc; do \
	  [ -f "$$new_key_enc" ] || continue; \
	  user=$$(basename "$$new_key_enc" .key.enc); \
	  cp "$$new_key_enc" "$(SECRETS_DIR)/$(NAME)/$$user.key.enc" || \
	  { echo "Error: Failed to write rotated key for user '$$user'" >&2; exit 1; }; \
	done; \
	echo "Secret '$(NAME)' rotated — all current users re-granted"

# ---------------------------------------------------------------------------
# Utility Operations
# ---------------------------------------------------------------------------

# list-secrets: List all secrets with user access counts
## list-secrets: List all secrets and their access counts
list-secrets:
	@if [ -d "$(SECRETS_DIR)" ] && [ -n "$$(find $(SECRETS_DIR) -name 'secret.enc' 2>/dev/null)" ]; then \
	  find $(SECRETS_DIR) -name 'secret.enc' | while read secret_file; do \
	    secret_dir=$$(dirname "$$secret_file"); \
	    secret_name=$$(echo "$$secret_dir" | sed "s|^$(SECRETS_DIR)/||"); \
	    user_count=$$(find "$$secret_dir" -name "*.key.enc" | wc -l | tr -d ' '); \
	    echo "$$secret_name ($$user_count users)"; \
	  done | sort; \
	else \
	  echo "No secrets found"; \
	fi

# list-users: List all registered users (strip .pub extension)
## list-users: List all registered users
list-users:
	@if [ -d "$(USERS_DIR)" ] && [ -n "$$(ls -A $(USERS_DIR) 2>/dev/null)" ]; then \
	  for user_key in $(USERS_DIR)/*.pub; do \
	    basename "$$user_key" .pub; \
	  done; \
	else \
	  echo "No users found"; \
	fi

# delete-secret: Remove entire secret directory (requires NAME= parameter)
#   Required vars: NAME
## delete-secret: Permanently delete a secret (NAME=)
delete-secret:
	@test -n "$(NAME)" || { echo "Error: NAME= is required" >&2; exit 1; }
	@echo "$(NAME)" | grep -qE '^[a-zA-Z0-9._/-]+$$' || { echo "Error: Invalid NAME '$(NAME)' — must match [a-zA-Z0-9._/-]+" >&2; exit 1; }
	@echo "$(NAME)" | grep -qE '\.\./|^\.\.|^/' && { echo "Error: Invalid NAME '$(NAME)' — path traversal not allowed" >&2; exit 1; } || true
	@test -d "$(SECRETS_DIR)/$(NAME)" || { echo "Error: Secret '$(NAME)' does not exist" >&2; exit 1; }
	@rm -rf "$(SECRETS_DIR)/$(NAME)" || { echo "Error: Failed to delete secret '$(NAME)'" >&2; exit 1; }
	@echo "Secret '$(NAME)' deleted"
