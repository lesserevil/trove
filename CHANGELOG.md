# Changelog

## Unreleased

- Trove Windows: replace failing Win32 ACL-handle reopens with verified NT
  handle-relative opens, normalize current-user ownership and retain protected
  owner/System permissions. Added file and directory name-replacement regressions.
  CI avoids duplicate PR runs and checks Windows filesystem protection separately.

- GitHub integration: preserve both Git histories and the historical GitHub Make
  client; add five-platform native and exact packaged-executable Actions checks.
  Hosted Linux amd64/arm64 and macOS arm64 native and packaged CLI tests pass;
  the repaired Windows amd64/arm64 suites now pass as well. PR 8 is merged to main.
  GitHub CBC/HMAC store migration remains unqualified.

- Trove native candidate: added the direct Go CLI, embedded OpenPGP adapter,
  protected external identities, contained store operations, authenticated v2
  content, explicit recoverable CBC migration, and five-target archive tooling.
  The full native suite, packaged CLI tests and synthetic GPG interoperability pass
  on macOS arm64. Built all five CGO-free candidate archives with dependency notices
  and checksums. Patched the Go toolchain and transitive crypto dependencies after
  scanning; no reachable vulnerability traces remain in the local scan.
  The draft is not admitted or released, and existing secrets remain untouched.

- Replaced destructive legacy crypto smoke-test cleanup with one private temporary
  allocation and added sentinel, failure, and signal regressions. The full retained
  26-case suite passes and Literate AI has refreshed its baseline and parity evidence.
- Inventoried and classified retained application boundaries for the Go rewrite.

- Initialized the project with Literate AI's specification-led lifecycle and durable
  user-directed work queue.
- Preserved the existing Makefile application as a retained Component and recorded
  passing baseline and wrapper integration tests.
- Added the seven-finding security roadmap for a self-contained Go/OpenPGP executable,
  including migration and Linux amd64/arm64, Windows amd64/arm64, and macOS arm64
  release requirements. Implementation remains pending.
