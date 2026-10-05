# Trove security remediation plan

- **Status:** partial
- **Owning queue item:** [ADOPT-002](active-work.md#adopt-002)
- **Completion / archival evidence:** pending while ADOPT-002 remains open

This plan addresses the seven findings from the security review of commit `3c6849a`. It proposes implementation changes, a migration path for existing stores, and regression tests that demonstrate each fix. The review reproduced the findings with temporary stores and synthetic keys; all 25 existing integration tests passed.

Status: implementation in progress under ADOPT-002. The selected architecture is
one self-contained Go executable with embedded OpenPGP support. A native draft is
written and its native and exact packaged CLI suites pass on all five target
runtimes in [run 37366823816](https://github.com/lesserevil/trove/actions/runs/37366823816).
Source admission, independent regenerative acceptance, historical GitHub CBC+HMAC
migration qualification and release remain pending. No real keys or secrets are migrated.
The plan was approved and included in the merged Literate AI adoption branch.

## Scope and priorities

| Finding | Severity | Existing location | Required outcome |
| --- | --- | --- | --- |
| 1. Private keys accepted as public keys | High | `Makefile:242–249`, `add-user` | Only validated public material reaches `users/`. |
| 2. Shell injection before validation | High | `Makefile:446–448` and other variable-bearing recipes | User input never becomes executable shell or Make source. |
| 3. Unauthenticated ciphertext | High | `Makefile:431–432`, `458–460`, `480–486` | Modified encrypted content fails authentication before any plaintext is released. |
| 4. Symlink escape from the store | High | `Makefile:563–568` and other filesystem operations | Store operations cannot follow links into unrelated locations. |
| 5. Readable private-key exports | High | `Makefile:309–313` | Private exports are owner-only from creation through completion. |
| 6. Destructive smoke-test cleanup | High, availability | `Makefile:150–158` | Tests operate exclusively on resources they create. |
| 7. Private keys generated inside the repository | Medium | `Makefile:7–9`, `255–270` | Private identities are stored in a protected personal directory outside the repository. |

Line numbers refer to the reviewed commit. The reviewed files now live under `components/legacy-project-wrapper/implementation/` following Literate AI adoption. Target names remain useful anchors after refactoring. This document is the current roadmap; the original `.sisyphus` copy inside the retained implementation is preserved as adoption evidence.

Revocation and Git history remain separate design limitations. Deleting a recipient envelope does not revoke a previously recovered symmetric key, and this plan does not add automatic key rotation. Document that limitation accurately; do not claim that authenticated encryption fixes it.

## Proposed implementation structure

Ship a single executable named `trove`, written in Go. Compile an OpenPGP implementation into the binary for key generation, key import/export, and recipient key wrapping. Use Go's standard cryptographic libraries for authenticated content encryption and legacy CBC migration. There is no separate runtime, package installation, or external crypto command required for normal use: no Python, Go toolchain, OpenSSL, GPG executable, GPGME, or shell helper.

Use [Proton's GopenPGP v3](https://github.com/ProtonMail/gopenpgp) as the initial library candidate, with its Go OpenPGP implementation underneath. Pin a reviewed stable release and transitive dependencies in `go.mod` and `go.sum`. Prove a `CGO_ENABLED=0` build and compatibility with representative existing key exports and recipient envelopes before committing to the dependency. This embeds OpenPGP support; it does not embed GnuPG's command-line program or assume access to its agent and private-key storage.

End users download the appropriate binary. Go and Make are build/test tools for contributors only. GPG is optional for exporting an existing identity once and for developer interoperability tests. Git remains the user's separate tool for synchronizing the store; Trove does not invoke it automatically.

### Literate AI authority and generated layout

Implement this plan through the [native rewrite program](native-rewrite-program.md).
Author the CLI behavior, public interfaces, store formats, identity rules, and security
acceptance contracts in a Trove Component before generating its replacement. Keep
language/toolchain, dependency pins, OS/architecture constraints, permissions adapters,
and archive packaging policy in project-owned Flavors. Record exact resolution with
`litai lock`; generate disposable Go source and qualify it through the normal lifecycle.

The scaffold's portable-Go example Flavor is not sufficient for this application:
it assumes a JSON-only, standard-library-only sample. Select or author a Trove Go
module Flavor and conversion skill that support the pinned OpenPGP dependency,
ordinary CLI arguments, raw byte streams, platform APIs, and the tests required here.
Do not turn Trove's user interface into a JSON sample or relax a security requirement
to fit a starter Flavor. Adoption removed the scaffold's pip packaging preference;
implement binary-archive packaging for releases. Python remains, at most, tooling
used by the contributor's `litai` installation.

Keep the five-target matrix below as the product requirement and encode its build and
packaging choices in Flavors and CI. The current host default is not the release matrix.
Independently accept each replacement before transferring authority or removing retained
files. Preserve documented intended behaviors while replacing the seven vulnerable
behaviors with the explicit acceptance criteria in this plan.

Proposed generated-source layout (paths below are relative to the generated Go tree,
not hand-maintained production files at the repository root):

| File or area | Responsibility |
| --- | --- |
| `cmd/trove/main.go` | Parse literal arguments, resolve identity, dispatch commands, and report errors. |
| `internal/store/` | Validate names, enforce filesystem boundaries, and publish files safely. |
| `internal/pgp/` | Wrap the embedded library, validate keys, and encrypt/decrypt recipient envelopes. |
| `internal/identity/` | Protect personal identities, handle passphrases, and import/export portable keys. |
| `internal/crypto/` | Authenticate the new content format and isolate legacy CBC migration code. |
| `go.mod`, `go.sum` | Record the build toolchain requirement and pinned library dependencies. |
| `Makefile` | Fixed build, test, and release-preparation commands for contributors. |
| Go `*_test.go` files and `tests/integration/` | Port the existing 25 behaviors and add security, failure, migration, and interoperability cases. |
| Project `README.md` and `docs/` | Authored binary installation, CLI usage, personal identities, migration, and security guarantees. |

Preserve command names and semantics where practical, for example `trove create-secret --name dbpass --file /path/to/input`. Preserve nested secret names, per-user GPG envelopes, text and binary content, and raw plaintext stdout on successful reads.

The executable is the operational interface. Remove the old operational Make recipes, internal crypto helpers, and parse-time identity expansion, and document the command mapping. Make remains useful for contributors; users do not need it. Do not forward untrusted Make variables into the CLI: shell quoting alone does not address Make's own variable and function evaluation.

## Personal identities and GPG interoperability

Keep the portable public-key files and per-user encrypted root keys in the repository. Store passphrase-protected private OpenPGP identities in Trove's personal identity directory, defaulting to a `trove/identities` directory under `os.UserConfigDir()`, with an explicit override for isolated tests and automation. On Linux and macOS, create directories as `0700` and identity files as `0600`; on Windows, create them with restrictive access-control lists as described under finding 5. Identify keys by full fingerprint.

Import existing software keys through a portable OpenPGP secret-key export. Support a protected file or explicit stdin input, so a user can pipe an export from their existing GPG installation without creating a broadly readable temporary file. Preserve the key fingerprint and verify that the imported identity can unwrap an existing envelope before declaring migration successful. Never parse or modify GnuPG's internal key database directly.

The first release does not provide GPG-agent or smart-card integration. Non-exportable hardware keys cannot be migrated by exporting their secret material; report that limitation explicitly and leave those users' stores untouched. Supporting them would require a separately designed agent or hardware interface. Do not silently generate a replacement identity or weaken protection to make an import succeed.

Test the OpenPGP algorithm and packet profiles used by the existing project, including representative GPG-generated RSA and Curve25519 keys, encrypted private exports, and armored recipient envelopes. Select an explicit interoperable profile instead of assuming the embedded library's defaults match every GPG version. Treat unsupported keys as a clear import error, not an automatic conversion.

## Implementation order

1. Contain finding 6 first: replace the existing smoke test with an isolated harness before running any implementation tests.
2. Prove the embedded OpenPGP dependency and independent binary build. Establish the direct Go CLI and shared validation and filesystem code for findings 2 and 4, and port existing behavior tests while removing unsafe operational Make entry points.
3. Implement personal identity storage and portable import for finding 7, then public-only registration for finding 1 and secure exports for finding 5.
4. Introduce authenticated content encryption for finding 3, followed by explicit legacy migration.
5. Complete the regression matrix, exercise migration and failure recovery on synthetic stores, and update documentation.

Keep each stage independently reviewable. Do not treat a refactor as proof of a security fix; each finding needs its own regression evidence.

## Finding 1 Prevent private keys from entering public storage

The existing `add-user` checks whether GPG can display the input and then copies the entire file. A private export passes that check and is renamed to `.pub`.

Implementation:

- Parse bounded candidate key data in memory with the embedded OpenPGP library. Inspect the complete input for secret primary keys and secret subkeys, including mixed public/private input and additional armored blocks. Do not let a convenience parser accept only the first key while ignoring trailing material.
- Require exactly one primary public-key identity with a usable encryption key. Reject malformed input, secret-bearing input, and ambiguous multi-key bundles before modifying persistent files.
- Serialize only the accepted public key, selected by its full fingerprint. Publish this normalized public-only export; never copy the original input to `users/`.
- Apply the same public-export path to `new-user`, `generate-key`, `import-key`, and the public-registration part of `import-secret-key`.
- Reject an existing user name whose fingerprint differs unless an explicit replacement operation is selected. On validation or library failure, preserve the existing registration.

Acceptance criteria:

- Public armored and binary keys register successfully and can receive an encrypted symmetric key.
- Private armored and binary exports, secret-subkey exports, mixed bundles, and malformed input fail without changing `users/` or personal identities.
- A failed attempt to replace an existing registration preserves its bytes and fingerprint.
- Successful registrations contain no secret key material, and registration creates no private files in the store.

Recovery guidance: provide a read-only inspection procedure for existing registrations and document how the user's existing GPG can inspect a legacy store keyring. If private material was committed or shared, treat that key as exposed and plan key replacement and credential rotation. Deleting the current `.pub` file or adding an ignore rule does not remove copies from Git history. History rewriting and rotation are separate operational actions, not automatic effects of this remediation.

## Finding 2 Remove executable interpolation of input

Implementation:

- Parse command-line values with Go's argument parser and call filesystem and cryptographic APIs directly. Normal commands must not launch subprocesses or generate shell/Make source from supplied values.
- Validate names as whole strings. User identities must have a nonempty allowed-character representation; secret names must contain nonempty allowed-character segments and must reject absolute paths, `.` and `..` segments, control characters, and embedded newlines.
- Apply identity validation to `PM_USER` and all fallback identities, not just explicit target-user arguments. Keep filesystem paths distinct from logical names so legitimate filenames containing spaces can work.
- Pass filenames as data, support an option terminator where positional filenames are accepted, and use full fingerprints rather than ambiguous user-ID substrings for key operations.
- Remove every operational recipe that expands `NAME`, `FILE`, `KEY`, `USER`, `EMAIL`, `DIR`, or store paths into executable source. Audit the retained Makefile for parse-time expansion as well as recipes.

Acceptance criteria:

- Exercise backticks, shell substitutions, Make function syntax, quotes, semicolons, newlines, and leading dashes in all applicable input fields using harmless marker payloads.
- No payload executes, creates a marker, or invokes an unexpected program. Invalid names fail before cryptographic work or filesystem mutation.
- Existing files with spaces and shell metacharacters in their names are handled literally when supplied as file arguments.
- The old operational Make interface has no remaining implementation or forwarding path capable of handling supplied data.

## Finding 3 Authenticate encrypted content

Implementation:

- Use Go's `crypto/aes` and [`crypto/cipher` AEAD interface](https://pkg.go.dev/crypto/cipher#AEAD) for AES-256-GCM. Verify the error returned by `Open` before exposing plaintext. All content cryptography is compiled into the executable.
- Define a versioned binary format for `secret.enc` with a fixed magic value, format version, random 32-byte derivation salt, random 12-byte nonce, and ciphertext with a full 16-byte authentication tag. Freeze the byte layout and parser limits in tests before writing migration code.
- Preserve the existing 32-byte root key and recipient envelopes. Derive a distinct 32-byte content key for each write with HKDF-SHA256, using the random salt and a fixed Trove v2 domain string. This separates the new encryption keys from legacy CBC use and avoids rewrapping every recipient during migration. Use Go's [`crypto/hkdf`](https://pkg.go.dev/crypto/hkdf), with the appropriate minimum build-toolchain version.
- Authenticate the format header and normalized logical secret name as associated data, using an unambiguous encoding. Do not include machine-specific absolute paths, so clones remain readable. Document that moving a secret to another logical name requires re-encryption.
- Authenticate the complete message before writing any plaintext to stdout. Bound input size before allocation and document the supported maximum. If large-file streaming is added later, withhold output until final authentication succeeds.
- Reject malformed headers, unsupported versions, invalid root-key lengths, truncation, and authentication failures with nonzero status and empty stdout. Never fall back to CBC after a v2 parse or authentication failure.
- Generate fresh salt and nonce for every create and update with `crypto/rand`. Publish encrypted output atomically using the filesystem layer; failure must preserve the previous ciphertext and envelopes.

Use the embedded OpenPGP library to wrap and unwrap the existing root-key representation. Require integrity-protected envelopes and consume/verify the complete decrypted message before accepting the root key. Keep that layer separate from Go's authenticated content encryption. Implement legacy AES-CBC decryption and strict padding checks in the migration module using standard-library AES; migration must not invoke OpenSSL.

Acceptance criteria:

- Text, empty content, and binary files round-trip byte-for-byte. Existing recipients can read updates, and grants still work.
- Altering the header, salt, nonce, ciphertext, tag, or bound logical name causes nonzero exit and zero plaintext bytes on stdout.
- Wrong keys, truncated files, extra malformed structure, and unsupported versions fail closed.
- Repeated updates produce fresh encryption parameters. Forced RNG, encryption, authentication, or publication failures leave the previous secret readable.
- The review's IV-tampering reproduction cannot silently modify a v2 plaintext.

Authenticated content does not establish who authored a secret or prevent rollback to an older valid version. A party able to replace the public-key registrations and complete encrypted payload can substitute data; a party able to modify executable repository code can change the program itself. Trusted code distribution, public-key verification, and Git access controls remain prerequisites.

## Finding 4 Enforce filesystem boundaries

Implementation:

- Select the store root explicitly and hold it open with Go's `os.Root` or equivalent descriptor-based primitives. Resolve `users/`, `secrets/`, nested secret directories, and target files relative to verified directories. Keep the personal identity directory under a separate trusted root outside the store.
- Reject symlink components and unexpected file types using descriptor-relative operations and no-follow opens. A `realpath` check followed by an ordinary path-based write is insufficient because the path can change between the check and use.
- Implement recursive deletion without following links. Require a specific secret containing a regular content file; reject deletion of the store root, a namespace-only directory, or a parent containing nested secrets.
- Create temporary output beside its destination with restrictive permissions, and publish through the same verified directory. Avoid truncating existing paths before validation. Refuse existing files for create operations and verify the expected target for replacements.
- Validate public-key and encrypted-envelope files and give their bytes from the already-open handles to the embedded library. Do not reopen checked paths by name.
- Apply equivalent no-follow and exclusive-creation rules to private export destinations, even when the user selects a directory outside the store. Explicit input files may be outside the store; opening one must not grant authority to write or delete elsewhere.
- Use supported descriptor or handle APIs on Linux, Windows, and macOS, and fail closed if required protections are unavailable. On Windows, account for junctions and other redirecting reparse points as well as symbolic links.
- Keep `/` as the canonical separator in logical secret names and authenticated format metadata, converting to native paths only at the filesystem boundary. Reject Windows drive/UNC paths, alternate data streams, reserved device names, and ambiguous trailing dots/spaces as logical names. Detect case-insensitive collisions when accessing a store instead of silently choosing or renaming an entry.
- Implement and test publication and replacement semantics on each OS. Do not assume that Unix rename, unlink, open-file, or signal behavior transfers directly to Windows; use platform-specific primitives where needed to preserve the documented failure guarantees.

Go's [`os.Root` documentation](https://go.dev/blog/osroot) describes protection against escapes and path-replacement races. It permits symlinks that remain inside the root, so Trove's stricter no-symlink policy still needs explicit no-follow handling. `filepath.Clean` or `EvalSymlinks` alone is not the filesystem boundary. Apply permission changes to already-open handles rather than re-resolving untrusted paths.

Acceptance criteria:

- Symlinked intermediate directories, final files, public keys, envelopes, identity directories, and export paths cannot cause external reads, writes, overwrites, or deletion.
- The review's `secrets/link` reproduction leaves all outside sentinel files unchanged.
- A deterministic test that swaps a directory for a symlink between validation and use cannot redirect an operation.
- Absolute names, traversal segments, empty segments, namespace deletion, and special files fail before mutation. Valid nested secrets continue to work.
- Windows junction/reparse-point escapes, device-name paths, alternate data streams, and case aliases fail safely. Cross-platform fixtures retain the same logical name, authenticated metadata, and plaintext bytes.

## Finding 5 Protect private-key exports from creation

Implementation:

- On Linux and macOS, create private export staging files with mode `0600` using exclusive creation and no-follow semantics. Set a restrictive process umask as defense in depth; do not rely on a later `chmod`.
- On Windows, create private files and directories with an explicit protected DACL that grants access to the current user and necessary system principals while excluding other ordinary users. Apply it at creation, preventing broad inherited permissions. Go's Unix mode bits alone do not establish this protection on Windows; use Windows security APIs through Go code compiled into the binary, without an external ACL utility. See [Go's Windows permission behavior](https://pkg.go.dev/os#Chmod) and [Windows file security at creation](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea).
- Serialize the private OpenPGP export through the embedded library to an already-open private descriptor. Check serialization and write errors, validate completion, and publish only a complete export.
- Refuse existing destination names, including symlinks and hard links, instead of overwriting them. Publish without replacing an existing file; a plain overwrite-capable rename is insufficient for this operation.
- Remove only temporary or newly created files owned by the failed operation. Never delete a pre-existing public export as rollback.
- Keep passphrases out of arguments, environment variables, and logs. Prompt through a terminal without echo using code compiled into the binary, or accept a dedicated inherited descriptor for automation. Protect generated private identities and exports with a passphrase by default; require an explicit option for intentionally unprotected automation keys. Tests may use unprotected disposable keys.

Acceptance criteria:

- On Linux and macOS, with umasks `000` and `022`, the private export is `0600` from the moment it is created, including while serialization is writing.
- On Windows, verify the effective DACL during creation and writing, including a destination with permissive inherited ACLs. Another ordinary local user cannot read the private export or identity file. Reject destinations that cannot enforce the required protection.
- Symlink, hard-link, existing-file, and concurrent destination-creation cases preserve the existing target and fail safely.
- Library failure, write failure, and interruption leave no published partial private export and preserve unrelated files.
- A successful export can be imported into another isolated Trove identity directory and used to decrypt a synthetic secret. Verify interoperability with GPG in a separate developer test.

## Finding 6 Isolate smoke tests and cleanup

Implementation:

- Replace the current `test-crypto` recipe with an isolated harness immediately. Port it to Go tests using `t.TempDir` and independently generated embedded-library identities as the Go implementation becomes available. Do not derive cleanup targets from the caller's store settings.
- Register cleanup only for resources allocated by the harness. Optional GPG interoperability tests must create disposable homes and scope any agent shutdown to those homes.
- Run success, failure, and signal cleanup through the same bounded cleanup path. Abrupt termination that cannot run cleanup may leave private temporary resources; it must never trigger later deletion of arbitrary configured directories.
- Give Alice, Bob, and Carol separate disposable personal identity directories. The existing helper shares all three private keys in one home, which weakens authorization testing.

Acceptance criteria:

- Populate the surrounding store, legacy GPG home, and personal identity directory with sentinel files. Successful smoke tests, forced cryptographic failures, and interruption leave their hashes unchanged.
- Supplying an existing `STORE_DIR` or `GNUPGHOME` to the smoke-test entry point cannot redirect test setup or cleanup into it.
- All test-created private directories are `0700` on Linux/macOS or restricted by equivalent Windows DACLs; cleanup removes only the harness's resources. Exercise Windows cancellation and file-handle cleanup as well as Unix signal handling.
- Tests never consult real personal identities or GPG keyrings. Recipient-access tests pass with genuinely separate private-key homes, and ordinary tests need no installed GPG.

## Finding 7 Keep private identities outside the repository

Implementation:

- Remove the global export of the repository path as `GNUPGHOME` and retire the repository GPG cache from normal operation. The binary does not depend on GPG environment variables or private-key storage formats.
- Resolve the personal identity directory once: explicit CLI override first, then the documented per-user Trove default. Reject a directory inside the repository or one that aliases a store directory. Apply the filesystem protections from finding 4 and owner-only permissions from finding 5.
- Generate, import, export, and unlock private keys through the embedded library. Persist only protected OpenPGP private identities outside the repository; keep unlocked keys in process memory for the operation and clear library-held private parameters when finished, without promising complete memory erasure in a garbage-collected process.
- Register only the matching public export in `users/`. Verify fingerprint and encryption capability before reporting setup or import success. Correct both `import-key` and `generate-key` when porting them.
- Preserve legacy `.gnupg/` directories. Report that they may contain misplaced private keys and provide the explicit export/import recovery procedure; do not automatically delete or overwrite them.

Acceptance criteria:

- Generation creates the secret key only in the selected Trove personal identity directory; the repository contains only a sanitized public registration.
- New-user setup, existing-key registration, private import/export, grant, create, read, and update work with the intended identities, including a configured nondefault identity directory, with GPG absent.
- Failure to generate or import a key returns nonzero, reports no false success, and preserves existing registrations.
- Reject personal identity directories inside or aliased into the repository. Preserve existing GPG homes regardless of environment settings.

Recovery guidance: use the existing GPG installation to export a misplaced private key explicitly from the legacy repository home, then import the portable export into Trove through a protected file or stdin. Verify its fingerprint and decrypt a synthetic challenge before removing the old copy. Preserve a protected recovery copy until successful verification. Never delete the repository keyring merely because its documented purpose was public-only.

## Legacy migration and rollout

1. Finish the isolated harness, embedded-library compatibility tests, safe CLI, filesystem operations, and identity fixes before offering migration. Preserve encrypted backups of the original store; inspect misplaced private keys before copying a supposedly public-only cache. Import and verify the user's portable private identity before touching ciphertext.
2. Make normal reads and updates accept v2 only. Detect legacy CBC files and return a specific migration-required error with empty stdout. Keep legacy decryption reachable only through an explicit `trove migrate-secret --name ... --accept-unauthenticated-legacy` command.
3. Explain that old CBC data has no verifiable integrity. Prefer comparison with an independently trusted original before migration; successful padding or round-trip decryption is not proof that the old content is authentic.
4. For each migrated secret, validate its path, unwrap the current user's root key, decrypt legacy content into process memory without writing plaintext to disk, and produce v2 ciphertext with the derived key. Keep existing recipient envelopes byte-for-byte unchanged. Verify the staged v2 output against the recovered bytes before atomically replacing only `secret.enc`.
5. Make migration restartable: already-v2 files are verified or skipped, failures preserve the original, and interruption cannot leave a half-written content file. Test a mixed legacy/v2 store and include an inaccessible legacy secret that must remain untouched.
6. Update team clients together before publishing v2 changes. The old client cannot read the new format, and old writers must not continue creating or overwriting CBC secrets. Update scripts and README examples to the direct CLI. Users of non-exportable hardware identities must retain their existing store until a supported integration exists.
7. If rollback is needed, restore the corresponding encrypted backup explicitly. Do not add automatic downgrade or fallback behavior. Existing Git history remains legacy data; format migration does not erase it or revoke saved recipient keys.

Do not migrate the checked-in example secrets using personal keys as part of the test suite. Use independently generated legacy fixtures. Any later change to existing stored content is an explicit migration operation.

## Binary distribution and dependency checks

Produce the following five required release targets. Interpret the requested Windows `x85_64` as `x86_64`. Go calls x86_64 `amd64`, aarch64 `arm64`, and macOS `darwin`; use those values in the build matrix. See the [Go target documentation](https://go.dev/doc/install/source#environment).

| Operating system | Architecture | `GOOS` | `GOARCH` | Versioned release archive | Executable inside |
| --- | --- | --- | --- | --- | --- |
| Linux | x86_64 | `linux` | `amd64` | `trove_<version>_linux_x86_64.tar.gz` | `trove` |
| Linux | aarch64 | `linux` | `arm64` | `trove_<version>_linux_aarch64.tar.gz` | `trove` |
| Windows | x86_64 | `windows` | `amd64` | `trove_<version>_windows_x86_64.zip` | `trove.exe` |
| Windows | aarch64 | `windows` | `arm64` | `trove_<version>_windows_aarch64.zip` | `trove.exe` |
| macOS | aarch64 | `darwin` | `arm64` | `trove_<version>_macos_aarch64.tar.gz` | `trove` |

- Build every matrix entry with `CGO_ENABLED=0` from the same source version. Pin the build toolchain and record dependency versions; users need neither Go nor a package manager. Keep this matrix as the single source for build, packaging, checksum, and validation jobs.
- Verify each artifact has no third-party shared-library dependencies and runs on its documented OS baseline. OS-provided system facilities are distinct from installable runtime dependencies.
- Execute each target binary on the corresponding OS and architecture using suitable runners or virtual machines. Cross-compilation alone is not a passing runtime test. Test Windows arm64 with its arm64 binary, and run macOS tests on Apple Silicon.
- Run end-to-end tests against the built binary with no `gpg`, `openssl`, `python`, `go`, `make`, or shell helpers available on its execution path. Exercise initialization, generation, registration, create/read/update, grant/revoke, private export/import, deletion, and migration.
- Exercise platform-specific filesystem containment, private-file permissions, safe replacement, cancellation, terminal passphrase entry, and byte-preserving stdin/stdout. Run the same portable-key and encrypted-store fixtures across all five targets.
- Keep GPG interoperability tests separate from this dependency-free suite. Use synthetic golden fixtures to exercise legacy formats in the core suite without invoking GPG.
- Keep runtime operations offline and free of automatic downloads. Replace runtime tool discovery with checks of the binary's supported formats, store configuration, and identity availability.
- Package Windows binaries as ZIP archives and Linux/macOS binaries as tar.gz archives. Generate one `SHA256SUMS` manifest covering all five archives, verify archive contents and executable naming, and document download/run instructions for each platform. Building and testing artifacts does not imply publishing them during this plan-only task.

## Completion criteria

- [ ] All seven findings have a regression test demonstrating the vulnerable behavior and the corrected outcome.
- [ ] The existing 25 integration behaviors remain covered through the new CLI, with separate personal identities per user.
- [ ] Adversarial inputs never become shell or Make code, and unsafe operational Make recipes are removed.
- [ ] Store operations and exports cannot follow links outside their permitted destinations, including during tested path replacement races.
- [ ] Public registrations contain no private material; private operations use the intended external identity directory; exports are owner-only from creation.
- [ ] Every v2 tampering test fails with nonzero status and no plaintext output.
- [ ] Success, failure, and interrupted smoke tests preserve pre-existing store, identity, and legacy-keyring sentinels.
- [ ] Migration preserves recipient access, retains recoverable original data on failure, and has no silent legacy fallback.
- [ ] All five required artifacts are built, packaged, checksummed, and executed successfully: Linux amd64/arm64, Windows amd64/arm64, and macOS arm64.
- [ ] The security suite passes on Linux, Windows, and macOS, including Windows DACL and reparse-point cases; built artifacts run with no installed language runtime or external crypto tools.
- [ ] Portable GPG key and envelope interoperability is verified independently; unsupported hardware identities receive a clear migration limitation.
- [ ] README examples, format documentation, recovery instructions, and revocation limitations match the final behavior.

The implementation review should include the seven regression results, migration and interruption results, supported-platform binary results, and confirmation that normal commands launch no external programs. Committing this plan does not implement the proposed fixes or authorize release publication or operations on real secrets.
