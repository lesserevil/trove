# Getting started

[Project guide](../README.md) → getting started

Trove stores encrypted secrets and per-user public-key envelopes in a Git-friendly
folder structure. Keep your team's store in its own private repository; the
checked-in store is an example.

## Binary installation

Download the versioned archive for Linux x86_64/aarch64, Windows x86_64/aarch64,
or macOS aarch64 and SHA256SUMS from
[GitHub Releases](https://github.com/lesserevil/trove/releases). Verify the archive's
SHA256 checksum, extract `trove` (`trove.exe` on Windows) and place it on PATH.
The executable embeds OpenPGP and needs no installed Go, Python, Make, shell,
GPG or OpenSSL for normal operations. GPG is optional for exporting an existing
identity once. See [binary releases](releases.md) for archive names and checks.

Run `trove --help`, then follow the [native client guide](native-client.md) for
store initialization, personal identities, secret access and explicit migration.
Private identities live in a protected personal directory outside the store.
Legacy GitLab CBC migration has synthetic acceptance; historical GitHub CBC/HMAC
migration remains unqualified. Installation does not migrate existing stores.

## Retained implementation

The old Make application remains under
`components/legacy-project-wrapper/implementation/` for conversion evidence and
recovery. It requires Make, GnuPG 2.x, OpenSSL, Bash 4 or newer and xxd. Its known
findings are recorded in the [security remediation roadmap](../roadmap/security-remediation.md).
Those contributor prerequisites are not runtime requirements for the released binary.

## Contributor workflow

Use the installed `litai` CLI from the repository root:

```console
litai project validate
litai lock --check
litai verify
```

The adopted Component retains the original source; the tested Go implementation
is separately checked in under `generated/trove/source`. `litai status` reports current evidence and the next
lifecycle step. Run the retained integration suite through the wrapper with:

```console
make -f litai.harness.mk test
```

The adoption runs passed all 25 existing tests in disposable stores. These tests
are the compatibility baseline; the roadmap adds independent regression evidence
for each security fix. Follow [active work](../roadmap/active-work.md) and the
[native rewrite program](../roadmap/native-rewrite-program.md) before replacing
retained implementation. Make and Literate AI are contributor tooling, not runtime
requirements for the planned executable.
