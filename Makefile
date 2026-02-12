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

.PHONY: check-deps init _generate-key _generate-iv _encrypt-content _decrypt-content _encrypt-key-for-user _decrypt-key test-crypto

check-deps:
	@echo "Checking dependencies..."
	@command -v gpg2 >/dev/null 2>&1 || command -v gpg >/dev/null 2>&1 || (echo "ERROR: gpg or gpg2 not found" && exit 1)
	@echo "✓ GPG found"
	@command -v openssl >/dev/null 2>&1 || (echo "ERROR: openssl not found" && exit 1)
	@echo "✓ OpenSSL found"
	@bash -c 'if [[ $${BASH_VERSINFO[0]} -lt 4 ]]; then echo "ERROR: bash >= 4 required"; exit 1; fi'
	@echo "✓ Bash >= 4 found"
	@command -v xxd >/dev/null 2>&1 || (echo "ERROR: xxd not found" && exit 1)
	@echo "✓ xxd found"
	@echo "All dependencies OK"

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
	@openssl rand -hex 32 || { echo "ERROR: failed to generate AES key" >&2; exit 1; }

# _generate-iv: Output a 32 hex-char IV to stdout
_generate-iv:
	@openssl rand -hex 16 || { echo "ERROR: failed to generate IV" >&2; exit 1; }

# _encrypt-content: Encrypt PLAINTEXT_FILE → OUTPUT_FILE using KEY_HEX and IV_HEX
#   Required vars: KEY_HEX, IV_HEX, PLAINTEXT_FILE, OUTPUT_FILE
_encrypt-content:
	@test -n "$(KEY_HEX)" || { echo "ERROR: KEY_HEX is required" >&2; exit 1; }
	@test -n "$(IV_HEX)" || { echo "ERROR: IV_HEX is required" >&2; exit 1; }
	@test -n "$(PLAINTEXT_FILE)" || { echo "ERROR: PLAINTEXT_FILE is required" >&2; exit 1; }
	@test -n "$(OUTPUT_FILE)" || { echo "ERROR: OUTPUT_FILE is required" >&2; exit 1; }
	@test -f "$(PLAINTEXT_FILE)" || { echo "ERROR: PLAINTEXT_FILE not found: $(PLAINTEXT_FILE)" >&2; exit 1; }
	@_cleanup() { if [ -n "$${_PARTIAL_OUT:-}" ] && [ -f "$${_PARTIAL_OUT}" ]; then rm -f "$${_PARTIAL_OUT}"; fi; }; \
	trap _cleanup EXIT; \
	_PARTIAL_OUT="$(OUTPUT_FILE)"; \
	echo "$(IV_HEX)" > "$(OUTPUT_FILE)" && \
	openssl enc -aes-256-cbc -nosalt -K "$(KEY_HEX)" -iv "$(IV_HEX)" -in "$(PLAINTEXT_FILE)" >> "$(OUTPUT_FILE)" || \
	{ echo "ERROR: encryption failed" >&2; rm -f "$(OUTPUT_FILE)"; exit 1; }

# _decrypt-content: Decrypt SECRET_ENC_FILE to stdout using KEY_HEX
#   Required vars: KEY_HEX, SECRET_ENC_FILE
_decrypt-content:
	@test -n "$(KEY_HEX)" || { echo "ERROR: KEY_HEX is required" >&2; exit 1; }
	@test -n "$(SECRET_ENC_FILE)" || { echo "ERROR: SECRET_ENC_FILE is required" >&2; exit 1; }
	@test -f "$(SECRET_ENC_FILE)" || { echo "ERROR: SECRET_ENC_FILE not found: $(SECRET_ENC_FILE)" >&2; exit 1; }
	@IV_HEX=$$(head -1 "$(SECRET_ENC_FILE)"); \
	tail -n +2 "$(SECRET_ENC_FILE)" | openssl enc -aes-256-cbc -d -nosalt -K "$(KEY_HEX)" -iv "$$IV_HEX" || \
	{ echo "ERROR: decryption failed" >&2; exit 1; }

# _encrypt-key-for-user: Encrypt KEY_HEX for USERNAME → OUTPUT_FILE (GPG)
#   Required vars: KEY_HEX, USERNAME, OUTPUT_FILE
_encrypt-key-for-user:
	@test -n "$(KEY_HEX)" || { echo "ERROR: KEY_HEX is required" >&2; exit 1; }
	@test -n "$(USERNAME)" || { echo "ERROR: USERNAME is required" >&2; exit 1; }
	@test -n "$(OUTPUT_FILE)" || { echo "ERROR: OUTPUT_FILE is required" >&2; exit 1; }
	@test -f "$(USERS_DIR)/$(USERNAME).pub" || { echo "ERROR: public key not found: $(USERS_DIR)/$(USERNAME).pub" >&2; exit 1; }
	@_cleanup() { if [ -n "$${_PARTIAL_OUT:-}" ] && [ -f "$${_PARTIAL_OUT}" ]; then rm -f "$${_PARTIAL_OUT}"; fi; }; \
	trap _cleanup EXIT; \
	_PARTIAL_OUT="$(OUTPUT_FILE)"; \
	echo "$(KEY_HEX)" | gpg --batch --yes --trust-model always \
	  --homedir "$(GNUPGHOME)" \
	  --recipient-file "$(USERS_DIR)/$(USERNAME).pub" \
	  --encrypt --armor \
	  --output "$(OUTPUT_FILE)" || \
	{ echo "ERROR: GPG encryption failed for user $(USERNAME)" >&2; rm -f "$(OUTPUT_FILE)"; exit 1; }

# _decrypt-key: Decrypt KEY_ENC_FILE to stdout (uses user's personal GPG keyring)
#   Required vars: KEY_ENC_FILE
_decrypt-key:
	@test -n "$(KEY_ENC_FILE)" || { echo "ERROR: KEY_ENC_FILE is required" >&2; exit 1; }
	@test -f "$(KEY_ENC_FILE)" || { echo "ERROR: KEY_ENC_FILE not found: $(KEY_ENC_FILE)" >&2; exit 1; }
	@gpg --batch --yes --quiet --decrypt "$(KEY_ENC_FILE)" || \
	{ echo "ERROR: GPG decryption failed for $(KEY_ENC_FILE)" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Smoke Test: full round-trip encrypt → decrypt
# ---------------------------------------------------------------------------

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
	echo "$$IV_HEX" > "$(SECRETS_DIR)/secret.enc"; \
	openssl enc -aes-256-cbc -nosalt -K "$$KEY_HEX" -iv "$$IV_HEX" \
	  -in "$$TEST_TMPDIR/plaintext.txt" >> "$(SECRETS_DIR)/secret.enc"; \
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
	RECOVERED_TEXT=$$(tail -n +2 "$(SECRETS_DIR)/secret.enc" | \
	  openssl enc -aes-256-cbc -d -nosalt -K "$$RECOVERED_KEY" -iv "$$RECOVERED_IV"); \
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
	echo "$$BIN_IV" > "$(SECRETS_DIR)/binary.enc"; \
	openssl enc -aes-256-cbc -nosalt -K "$$BIN_KEY" -iv "$$BIN_IV" \
	  -in "$$TEST_TMPDIR/binary.dat" >> "$(SECRETS_DIR)/binary.enc"; \
	DEC_IV=$$(head -1 "$(SECRETS_DIR)/binary.enc"); \
	tail -n +2 "$(SECRETS_DIR)/binary.enc" | \
	  openssl enc -aes-256-cbc -d -nosalt -K "$$BIN_KEY" -iv "$$DEC_IV" \
	  > "$$TEST_TMPDIR/binary_recovered.dat"; \
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
