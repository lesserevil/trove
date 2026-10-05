---
name: trove
description: Use the self-contained Trove Go candidate to manage encrypted secrets with embedded OpenPGP. Read the native client guide before use.
---

# Trove native candidate

Read [the native client guide](../../../docs/user/native-client.md) for the
command interface, identity protection, migration boundaries and recovery.
`make` at the repository root builds and tests the Go candidate; secret operations
use the `trove` executable. It requires no external crypto tools at runtime.

The rewrite remains a candidate with open Literate AI admission and release gates.
Use synthetic data for qualification. The historical GitHub Make client, tests,
and skill are preserved in `components/legacy-project-wrapper/github-reference/`
and Git history. Its CBC/HMAC format is distinct from the retained GitLab CBC
format; compatibility with that GitHub format is not yet qualified. Do not migrate
existing GitHub-format stores with this candidate.

Always keep plaintext and private exports outside the repository. Do not read or
change a personal keyring or store to test the application.
