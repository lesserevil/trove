# Trove

A small, Git-friendly secret store with per-user public-key access.

Trove ships as one self-contained Go executable with embedded OpenPGP for Linux
x86_64/aarch64, Windows x86_64/aarch64, and macOS aarch64. No separately installed
GPG, Python, Go, Make or shell is required for normal operations.

Download a versioned archive and SHA256SUMS from
[GitHub Releases](https://github.com/lesserevil/trove/releases), then follow the
[native client guide](docs/user/native-client.md). GitHub Actions validates each
native target and the exact packaged executable before publication.

The repository uses Literate AI for project specifications and contributor
workflows. Source admission and independent regeneration remain follow-up work.
The [retained Make implementation](components/legacy-project-wrapper/implementation/README.md)
is preserved for conversion evidence and recovery.

- [Getting started and current prerequisites](docs/user/getting-started.md)
- [Project guide](docs/README.md)
- [Release process and binary downloads](docs/user/releases.md)
- [Active roadmap](docs/roadmap/active-work.md)
- [Security remediation and binary release plan](docs/roadmap/security-remediation.md)

Contributors can inspect the adopted project with `litai status` and validate
its authority with `litai project validate`. The retained integration suite is
available through `make -f litai.harness.mk test`.

## Release Engineers

- `lesserevil`
