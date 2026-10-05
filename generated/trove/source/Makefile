# Contributor-only build convenience. User data is never expanded into recipes.
LITAI_LANGUAGE_TOOL ?= go
OBJECT_ROOT ?= ../../../_build/native
OUT ?= $(OBJECT_ROOT)/out
EXPORT_PATH ?= $(OUT)/trove
GOCACHE ?= $(abspath $(OBJECT_ROOT)/go-cache)
GOMODCACHE ?= $(abspath $(OBJECT_ROOT)/go-mod)
export GOCACHE GOMODCACHE
export CGO_ENABLED := 0
export GOTOOLCHAIN := go1.26.8

.PHONY: all deps test test-core interop package clean
all:
	"$(LITAI_LANGUAGE_TOOL)" run ./tools/builddirs "$(GOCACHE)" "$(GOMODCACHE)" "$(OUT)"
	"$(LITAI_LANGUAGE_TOOL)" build -mod=readonly -trimpath -buildvcs=false -o "$(EXPORT_PATH)" ./cmd/trove
deps:
	"$(LITAI_LANGUAGE_TOOL)" run ./tools/builddirs "$(GOCACHE)" "$(GOMODCACHE)"
	"$(LITAI_LANGUAGE_TOOL)" mod tidy
test-core:
	"$(LITAI_LANGUAGE_TOOL)" test -count=1 ./internal/app ./internal/format ./internal/safefs ./tools/release
test: all
	"$(LITAI_LANGUAGE_TOOL)" test -count=1 ./...
interop:
	"$(LITAI_LANGUAGE_TOOL)" test -tags interoperability -count=1 ./internal/pgp
package:
	"$(LITAI_LANGUAGE_TOOL)" run ./tools/release
clean:
	"$(LITAI_LANGUAGE_TOOL)" run ./tools/builddirs --clean "$(OUT)"
