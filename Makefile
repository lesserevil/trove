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

.PHONY: check-deps init

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
