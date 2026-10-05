---
schema: urn:literate-ai:schema:v1:specification-to-source-skill
skill_id: trove-go
version: 1.0.0
title: Trove Go module application
stages:
  - plan
  - generate
dependencies: []
limitations:
  - Do not replace embedded OpenPGP with external programs or deprecated x/crypto/openpgp.
  - Do not use mocked crypto to qualify the application or publish test receipts.
  - Keep generated product source in the admitted source workspace.
trust: repository-reviewed
---
# Trove Go module application

Generate a Go module with cmd/trove, internal/app, internal/format, internal/fs,
internal/pgp and tools/release. Ordinary CLI arguments and raw byte streams are
the product interface. The starter's JSON invocation protocol does not apply.
Keep OpenPGP behind a narrow adapter so standard-library store/format tests can run
independently when module downloads are unavailable. Such tests qualify only those
boundaries, never cryptographic interoperability or whole-application acceptance.
Use Go 1.26 directory handles; pin GopenPGP and platform modules from the selected
Flavor. Generate contributor-only Make rules with build/test/package/clean targets,
honoring OUT, EXPORT_PATH, OBJECT_ROOT and LITAI_LANGUAGE_TOOL. No operational
secret command belongs in Make. The release helper is Go, not Python or shell;
cross-compile CGO-free archives from one matrix and record runtime gates separately.
No tests access original ciphertext or real keyrings. Never invent go.sum entries,
admission identities or passing test receipts when downloads/builds are blocked.
