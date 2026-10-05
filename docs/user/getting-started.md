# Getting started

[Project guide](../README.md) → getting started

Trove stores encrypted secrets and per-user public-key envelopes in a Git-friendly
folder structure. Keep your team's store in its own private repository; the
checked-in store is an example.

## Current application

Literate AI adoption preserved the existing application under
`components/legacy-project-wrapper/implementation/`, including its Makefile,
public registrations, encrypted examples, tests, and ignored local GPG directory.
There is no released Go binary yet. The
[security remediation roadmap](../roadmap/security-remediation.md) owns the seven
known findings and the replacement's installation and release work.

The retained application requires Make, GnuPG 2.x, OpenSSL, Bash 4 or newer, and
xxd. From the repository root, inspect its commands with:

```console
make -C components/legacy-project-wrapper/implementation help
```

The command prints the available Make targets. Refer to
`components/legacy-project-wrapper/implementation/README.md`
for the existing interface and store layout; its security claims are qualified by
[the reviewed findings](../roadmap/security-remediation.md#scope-and-priorities).
The containment change replaces `test-crypto` cleanup with a private allocation;
see its [isolation contract](../architecture/smoke-test-contract.md). Current full
qualification now passes all 26 cases with fresh retained evidence;
the [active queue](../roadmap/active-work.md#adopt-002) records that evidence limit.

## Planned binary installation

Download and extract one `trove` executable (`trove.exe` on Windows) for Linux
x86_64/aarch64, Windows x86_64/aarch64, or macOS aarch64. The planned binary embeds
OpenPGP and requires no separately installed language runtime or crypto tools.
GPG is optional for exporting an existing identity once. Downloads are not yet
published; archive names, checksums, compatibility, and runtime tests are specified
in the [release matrix](../roadmap/security-remediation.md#binary-distribution-and-dependency-checks).

Private identities will live in a protected personal directory outside the store.
Existing CBC content requires the explicit migration described in the roadmap;
adoption has not changed stored keys or ciphertext.

## Contributor workflow

Use the installed `litai` CLI from the repository root:

```console
litai project validate
litai lock --check
litai verify
```

The adopted Component retains the original source; no hello sample or native Go
implementation was generated. `litai status` reports current evidence and the next
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
