# Trove

Trove is a small, Git-friendly secret store with per-user public-key access.
Its defining constraint is simple installation: the replacement application is one
self-contained Go executable with embedded OpenPGP support. End users must not
need a language runtime, Make, a shell helper, or an external crypto command.
GPG may be used once to export an existing identity for import.

Ship Linux x86_64 and aarch64, Windows x86_64 and aarch64, and macOS aarch64
release binaries. Publish versioned five-target archives and checksums through
GitHub tag CI, with persistent release/X.Y.x maintenance lines and immutable tags.
The [release process](docs/user/releases.md) owns preparation and retry conventions.
Make is a contributor build/test convenience.

Literate AI currently wraps the retained Makefile application under
`components/legacy-project-wrapper/implementation/`. That application remains
source authority for the Literate AI conversion until independently qualified
replacements are accepted. Stable binary releases publish the tested checked-in
Go implementation separately from that conversion process. Adoption
does not transfer authority to the Go rewrite or migrate stored secrets. The Go
implementation is checked in under `generated/trove/source`. Native and packaged
CLI suites pass on all five target runtimes, with synthetic GPG interoperability.
Source admission and independent regeneration remain open in the active queue.

The [active work queue](docs/roadmap/active-work.md) owns execution. The
[security remediation plan](docs/roadmap/security-remediation.md) owns the agreed
fixes, interoperability, migration, release matrix, and acceptance requirements.
The conversion and plan are approved for a branch commit and merge request.
Publishing releases or operating on real secrets requires a separate instruction.
