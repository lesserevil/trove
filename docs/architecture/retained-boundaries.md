# Retained application boundaries

This inventory implements the first two steps of
[ADOPT-002](../roadmap/active-work.md#adopt-002). Paths below are relative to
`components/legacy-project-wrapper/implementation/` unless stated otherwise.
The retained application remains source authority while replacements qualify under
[ADR 0002](../decisions/0002-native-literate-ai-rewrite.md).

| Boundary | Evidence | Classification and owner | Replacement / disposition |
| --- | --- | --- | --- |
| Operational interface | `Makefile` targets; `README.md` usage | Component intent: Trove CLI | One executable; preserve intended operations with literal arguments and raw byte output. Remove operational Make recipes after acceptance. |
| Public registrations | `Makefile` `add-user`, `import-key`, `generate-key`, `new-user`, `import-secret-key`; `users/alice.pub` | Component intent: public-key registration | Exactly one usable public identity, full fingerprint, public-only normalization; reject secret-bearing inputs. |
| Personal identities | `Makefile` identity cascade, generation, import/export and decrypt targets | Component intent: identity lifecycle | Protected personal identity directory outside the store; portable OpenPGP import/export. Keep existing GPG directories for explicit recovery. |
| Store traversal and publication | `Makefile` `STORE_DIR`, `USERS_DIR`, `SECRETS_DIR`, create/update/delete/list targets | Component intent: store | Root-bound operations; no symlink/reparse escape; protected atomic writes and explicit logical names. |
| Encrypted content | `Makefile` `_encrypt-content`, `_decrypt-content`, create/read/update; `secrets/**/secret.enc` | Component intent: content format and migration | Legacy format is a 32-character hex IV plus newline followed by AES-256-CBC bytes. v2 uses authenticated encryption; legacy reads require explicit migration. |
| Recipient envelopes | `Makefile` `_encrypt-key-for-user`, `_decrypt-key`, grant/read/update; `secrets/**/*.key.enc` | Component intent: recipient access | Armored OpenPGP envelope containing 64 hex characters for a 32-byte root key plus newline. Preserve existing envelopes during migration and verify integrity before accepting a key. |
| Access changes | `Makefile` grant/revoke; integration cases 6–8, 15, 20, 22, 25 | Component intent: recipient access | Preserve grants and envelope removal. Document that removing an envelope cannot revoke a key already recovered or erase Git history. |
| Internal crypto recipes | `Makefile` `_generate-key`, `_generate-iv`, `_encrypt-content`, `_decrypt-content`, `_encrypt-key-for-user`, `_decrypt-key` | Intentionally retained source: legacy internals | Retire alongside qualified embedded-library and standard-library replacements; never forward input through Make. |
| Crypto smoke entry point | `Makefile` `test-crypto`; `tests/smoke_crypto.sh` | Repository-only harness: contributor verification | Contain finding 6 first, under the [smoke contract](smoke-test-contract.md). Port to isolated Go tests when the replacement exists. |
| Integration baseline | `tests/helpers.sh`, `tests/test_trove.sh` | Repository-only harness: acceptance | Preserve all 25 original behavior cases, add security regressions, and give recipients separate identities in the Go suite. The legacy baseline's shared home is insufficient authorization evidence. |
| Smoke safety regressions | `tests/test_smoke_safety.sh`; integration smoke-safety case | Repository-only harness: independent safety evidence | Caller sentinels, owner-only allocations, success, tool failures, signals, and failed allocation; failures remain failures. |
| Contributor build/test | `Makefile` `help`, `test`, `check-deps`; root `litai.harness.mk` | Flavor requirement and retained harness: build | Make remains contributor tooling. The current “build” target prints help; it does not produce a binary. Go module compilation replaces that behavior for native candidates. |
| Runtime prerequisites | `Makefile` `check-deps`; `README.md` Requirements | Flavor requirement: implementation and dependencies | Current Make/GPG/OpenSSL/Bash/xxd requirements are legacy only. Pin a Go toolchain and embedded OpenPGP module for builds; final binaries need no installable runtime or crypto command. |
| OS-specific protection | Export recipes and directory modes; proposed filesystem acceptance | Flavor requirement: OS adapters | Linux/macOS owner modes; Windows DACLs and reparse protection. Independent target acceptance must prove them. |
| Packages and CI | No package driver or CI definition in the retained tree; `.literate/harness-inventory.json` at project root | Flavor/workflow requirement: releases | Implement five versioned archives, checksums, and execution on each target OS/architecture; cross-compilation is insufficient. |
| Checked-in public/ciphertext examples | `users/alice.pub`, four files beneath `secrets/` | Immutable assets: store examples | Preserve encrypted bytes. Use synthetic fixtures for testing; never migrate these examples with personal keys. |
| Ignored local keyring | `.gitignore` `.gnupg/`; retained directory may exist locally | Intentionally retained private state: operator | Preserve for recovery. Exclude from tests, generation inputs, Git, and cleanup. It may contain misplaced private material. |
| Original notes and plan | `.sisyphus/boulder.json`, `.sisyphus/notepads/password-manager/*`, `.sisyphus/plans/*` | Intentionally retained historical source: documentation | Preserve as adoption evidence. Current intent is owned by root `PROJECT.md` and `docs/roadmap/`; obsolete notes do not override the current plan. |
| Legacy user documentation | `README.md` | Intentionally retained source: documentation | Retain interface evidence; update current project documentation with verified Go usage and recovery instructions as replacements qualify. |
| Adoption authority and provenance | Root `.literate/`, `components/legacy-project-wrapper/component.md`, locks, `flavors/legacy-project-shim/` | Repository-only harness / conversion skill: Literate AI | CLI owns receipts, locks, retained scope, readmission and authority transfer. Never edit evidence identities by hand. |

## Operational interface to preserve

| Legacy target | Go command / disposition | Input and observable result |
| --- | --- | --- |
| `init` | `trove init` | Initialize the selected store without placing private identities inside it. |
| `add-user` | `trove add-user --name NAME --key PATH` | Validate and register one public key. |
| `generate-key` | `trove generate-key --name NAME [--email EMAIL]` | Generate a protected personal identity and register its public key. |
| `import-key` | `trove import-key --name NAME --key PATH` | Import portable public material; replace implicit GPG-keyring lookup with an explicit source. |
| `new-user` | `trove new-user --name NAME [--email EMAIL]` | Guide generation or portable import and registration. |
| `export-key` | `trove export-key --name NAME [--dir PATH]` | Export public and protected secret material with secure file creation. |
| `import-secret-key` | `trove import-secret-key --name NAME --key PATH` | Import a protected portable identity outside the store and register its public export. Explicit stdin support must not require a temporary export file. |
| `create-secret` | `trove create-secret --name NAME --file PATH` | Encrypt bytes and grant the current identity access. |
| `read-secret` | `trove read-secret --name NAME` | Authenticated plaintext bytes on stdout; error diagnostics on stderr. |
| `update-secret` | `trove update-secret --name NAME --file PATH` | Replace content safely while retaining recipient envelopes. |
| `grant-access` | `trove grant-access --name NAME --user USER` | Wrap the existing root key for a validated recipient. |
| `revoke-access` | `trove revoke-access --name NAME --user USER` | Remove the recipient envelope; explain the revocation limitation. |
| `list-secrets` / `list-users` | `trove list-secrets` / `trove list-users` | Stable lists, including nested names and recipient counts. |
| `delete-secret` | `trove delete-secret --name NAME` | Delete only within the opened store boundary. |
| No legacy equivalent | `trove migrate-secret --name NAME --accept-unauthenticated-legacy` | Explicit recoverable CBC migration, with no normal-read fallback. |
| `help` | `trove help` | Document literal arguments, global store/identity/user selection and limits. |
| `test`, `test-crypto`, `check-deps` | Contributor commands | Tests and toolchain checks stay outside the runtime interface. |

`PM_USER` and the existing username/hostname fallback are compatibility inputs, not
trusted names. The new CLI must validate every resolved identity before use. Logical
names are distinct from file paths. Make variable expansion has no runtime forwarding
role. Freeze the final CLI and byte-format contracts in native Component authority
before generating the Go implementation.

## First independently testable change

The smoke harness is a retained contributor boundary and can be contained without
changing ciphertext, recipient envelopes, or runtime operations. Its direct safety
suite qualifies the cleanup change; `litai` readmission rechecks the entire retained
baseline and wrapper. This does not transfer application authority to generated Go.
The next boundary is the embedded OpenPGP compatibility spike and the native CLI,
store, identity, format and acceptance specifications.
