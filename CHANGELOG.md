# Changelog

## Unreleased

- Release CI: restore annotated tag objects after checkout and support recovery
  of existing immutable tags while binding all jobs to the original source revision.

## 1.0.0 - 2026-10-06

- Ship a self-contained Go executable with embedded OpenPGP for Linux x86_64 and
  aarch64, Windows x86_64 and aarch64, and macOS aarch64. Normal operations need no
  separately installed GPG, Python, Go, Make or shell.
- Use literal command arguments, contained filesystem operations, protected
  external personal identities, public-only registration and private key exports.
- Authenticate v2 secret content and support explicit legacy GitLab CBC migration
  with encrypted recovery backups. Historical GitHub CBC/HMAC migration remains
  unqualified; do not assume compatibility with those stores.
- Protect Windows files through verified handle-relative operations and restricted
  owner/System permissions, with file and directory replacement regressions.
- Validate native and exact packaged CLI behavior on all five supported targets,
  plus synthetic GPG interoperability. Dependencies and the Go toolchain are pinned.
- Publish immutable annotated version tags on maintenance branches, with five
  archives, dependency notices and SHA256 checksums. Release CI verifies downloads
  before publication and preserves matching assets on retry.
- Release the tested checked-in Go implementation as selected by the release owner.
  Literate AI admission and regeneration remain follow-up work; this release does
  not claim conversion authority transfer or migrate existing secrets.
- Use Litai 1.1.0 from the pinned jordanhubbard/literate-ai upstream installation.
