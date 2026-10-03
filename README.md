# Trove

A small, Git-friendly secret store with per-user public-key access.

This repository now uses Literate AI. The existing Makefile application is
preserved in [the retained implementation](components/legacy-project-wrapper/implementation/README.md).
The planned replacement is one self-contained Go executable with embedded OpenPGP,
released for Linux x86_64/aarch64, Windows x86_64/aarch64, and macOS aarch64.
The [Go candidate](docs/user/native-client.md) now implements the direct CLI and
store rewrite. The full native suite and synthetic GPG interoperability pass on macOS arm64.
Candidate archives build for all five targets; source admission and remaining target
runtime qualification are pending. The retained client has not been retired.

- [Getting started and current prerequisites](docs/user/getting-started.md)
- [Project guide](docs/README.md)
- [Active roadmap](docs/roadmap/active-work.md)
- [Security remediation and binary release plan](docs/roadmap/security-remediation.md)

Contributors can inspect the adopted project with `litai status` and validate
its authority with `litai project validate`. The retained integration suite is
available through `make -f litai.harness.mk test`.
