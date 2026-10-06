# Contributor-only native build entry point. Secret operations are Go CLI commands.
NATIVE_SOURCE ?= generated/trove/source
NATIVE_OBJECTS := $(abspath _build/native)
.PHONY: all build deps test test-core interop package clean retained-test
all: build
build:
	$(MAKE) -C "$(NATIVE_SOURCE)" all OBJECT_ROOT="$(NATIVE_OBJECTS)"
deps:
	$(MAKE) -C "$(NATIVE_SOURCE)" deps OBJECT_ROOT="$(NATIVE_OBJECTS)"
test:
	$(MAKE) -C "$(NATIVE_SOURCE)" test OBJECT_ROOT="$(NATIVE_OBJECTS)"
test-core:
	$(MAKE) -C "$(NATIVE_SOURCE)" test-core OBJECT_ROOT="$(NATIVE_OBJECTS)"
interop:
	$(MAKE) -C "$(NATIVE_SOURCE)" interop OBJECT_ROOT="$(NATIVE_OBJECTS)"
package:
	$(MAKE) -C "$(NATIVE_SOURCE)" package OBJECT_ROOT="$(NATIVE_OBJECTS)"
clean:
	$(MAKE) -C "$(NATIVE_SOURCE)" clean OBJECT_ROOT="$(NATIVE_OBJECTS)"
retained-test:
	$(MAKE) -f litai.harness.mk test

# Local release gates; GitHub tag CI supplies the other four native runtimes.
.PHONY: release-check release-check-candidate release-tooling-test
release-check:
	python3 scripts/release.py check
release-check-candidate:
	python3 scripts/release.py check --candidate
release-tooling-test:
	python3 scripts/release.py test
