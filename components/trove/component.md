---
namespace: trove
version: 0.1.0
display_name: Trove Native CLI
profiles:
  - application
sample: false
provides:
  - name: trove.cli
    version: 1.0.0
requires: []
authoring_inputs:
  - kind: specification-to-source-skill
    uri: skills/specification-to-source/trove-go/SKILL.md
workflow_definition: workflows/sample-host.md
routing_policy: routing/sample-host.json
flavor_slots:
  - slot_id: language
    axis: implementation.language-ecosystem
    cardinality: exactly-one
    capability_contract: trove.cli
  - slot_id: build-system
    axis: build.system
    cardinality: exactly-one
    capability_contract: trove.cli
entrypoints:
  - name: run
    kind: portable-application
    path: run
acceptance_contracts: []
source_dependencies: []
---
# Trove native CLI

This specification owns native CLI behavior. The release owner selected the tested,
checked-in Go implementation for stable binary publication. Literate AI source
admission and regenerative authority transfer remain separate follow-up work;
publication does not claim them. No checked-in ciphertext or personal identity may
be read or migrated by generation or tests.

### Requirement: Literal offline command interface

The executable SHALL implement help, version, check-deps, init, generate-key,
new-user, add-user, import-key, export-key, import-secret-key, create-secret,
read-secret, update-secret, grant-access, revoke-access, list-secrets, list-users,
delete-secret and migrate. Normal operations SHALL launch no subprocesses and
perform no networking. Arguments are literal Go flags, never Make or shell source.
Common flags are --store, --identity-dir and --user. Identity resolution is explicit
--user, PM_USER, matching USER@short-hostname registration, then USER/USERNAME.
Commands accept --name, --file, --key, --recipient, --email, --dir and
--passphrase-file as applicable. '-' denotes standard input for file/key content.
Passphrases SHALL come from a private file or terminal with echo disabled, never argv.
Binary secret input and stdout SHALL preserve exact bytes. Errors and status belong
on stderr; nonzero failures SHALL release no plaintext on authentication failure.

Names SHALL reject absolute paths, empty/dot/dot-dot components, backslashes,
control characters, shell metacharacters, trailing dots/spaces and Windows device
names. Secret names may contain slash-separated safe components; identities may
not. Limit content to 64 MiB, key/envelope files to 1 MiB, and passphrases to 4 KiB.

Namespace directories may contain secrets, but a secret SHALL NOT be an ancestor
of another secret. Deletion SHALL reject child directories. Reserve `.create-`
component prefixes for transaction staging; ordinary dot-prefixed secrets remain
visible in listings.

#### Scenario: Literal input cannot execute commands

- **WHEN** a supplied name contains shell or Make syntax
- **THEN** validation fails before filesystem mutation and no program is launched

### Requirement: Contained and transactional storage

Store layout SHALL preserve users/<identity>.pub and
secrets/<name>/{secret.enc,<identity>.key.enc}. Hold directory handles using os.Root,
validate paths and reject symbolic links/reparse points. External traversal SHALL
remain impossible even if a checked path is replaced during an operation. Serialize
writers with an exclusively created lock; stale locks require explicit operator
recovery, never automatic eviction. Writes use unique same-directory files, Sync,
close and atomic rename; creates refuse overwrite. Failed creates remove only the
new staging directory. Private directories/files SHALL be 0700/0600 on Unix and
have protected owner/System DACLs on Windows before private bytes are written.
Export destinations SHALL be external, held and symlink-free. Existing files SHALL
never be truncated or replaced by export. Store deletion requires identity access.

#### Scenario: Store path is replaced by an outside link

- **WHEN** an attacker replaces a checked directory with a symlink outside the store
- **THEN** operations fail or use the held original directory without changing outside files

### Requirement: Portable external identities

Personal identities SHALL be protected OpenPGP exports beneath the platform user's
configuration directory/trove/identities, outside the store and source repository.
Require nonempty passphrases for generated/imported/exported private identities.
Register exactly one usable, nonexpired and nonrevoked public primary key, preserving
full fingerprints. Parse every packet and reject private packets, mixed material,
additional armor blocks and trailing nonwhitespace, before writing registration.
Normalize public serialization. Invalid registration SHALL leave prior bytes intact.
Import existing GPG exports explicitly; never access ~/.gnupg or spawn an agent.
Root-key envelopes remain interoperable armored OpenPGP containing 64 hex digits
and a newline. Grant/revoke SHALL authenticate existing content first. Revocation
removes only the recipient envelope and does not revoke recovered keys or history.

#### Scenario: Private material is offered as a public registration

- **WHEN** any private primary or subkey packet appears anywhere in an input key
- **THEN** registration fails and no public store file is created or replaced

### Requirement: Authenticated version 2 content

The binary format SHALL be magic `TROVE` plus byte 2, a random 32-byte salt,
a random 12-byte GCM nonce and AES-256-GCM ciphertext with a 16-byte tag.
Derive the content key from the existing random 32-byte root key using
HKDF-SHA256, salt and info `trove/content/v2`. AAD SHALL be the entire 50-byte
header plus a big-endian uint32 length and UTF-8 canonical secret name. Fresh
salt and nonce SHALL be generated on every write. Header, nonce, salt, name,
ciphertext and tag tampering SHALL fail before stdout receives plaintext.
Updates SHALL authenticate the previous version and preserve recipient envelopes.
Read/update/grant SHALL reject CBC content with an explicit migration instruction.

#### Scenario: Reject modified authenticated content

- **WHEN** a v2 header or ciphertext byte is modified or substituted under another name
- **THEN** every read fails without writing plaintext to stdout

### Requirement: Explicit recoverable migration

`migrate --name NAME --accept-unauthenticated-legacy` SHALL decrypt the retained
32-hex-IV/newline/CBC format with strict PKCS#7 validation. It SHALL preserve a
byte-identical encrypted backup `secret.enc.legacy` without overwriting any backup,
encrypt and verify v2 in memory, then replace only content atomically. Unknown
formats, missing access, invalid padding and write failures SHALL preserve the
original. A second invocation SHALL authenticate an existing v2 file and succeed
without changing it. Existing CBC has no authenticity guarantee even when padding
is valid; the acknowledgement is mandatory. Tests use synthetic fixtures only.

#### Scenario: Migrate an accessible synthetic legacy secret

- **WHEN** the user explicitly acknowledges unauthenticated CBC migration
- **THEN** the candidate creates a byte-identical encrypted backup and verified v2 content
- **AND** recipient envelopes and inaccessible secrets remain unchanged

## Acceptance

Independent tests SHALL cover all retained operations, the seven regressions,
public/private packet mixing, authenticated mutation at every header/body offset,
cross-name substitution, recipient preservation, CBC recovery, symlink replacement,
private permissions, failure cleanup and separate identities. Unit tests for the
format/filesystem are distinct from OpenPGP interoperability and actual CLI tests;
they cannot stand in for them. Five target runtimes and regeneration remain gates.
