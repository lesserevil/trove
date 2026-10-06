# Native Trove

Trove releases publish the tested Go implementation checked in under
`generated/trove/source`. Download the archive for your target and SHA256SUMS from
[GitHub Releases](https://github.com/lesserevil/trove/releases), verify the checksum
and extract the executable. Native and exact packaged CLI tests pass on all five
supported targets. Literate AI source admission and independent regeneration
remain separate follow-up work in the [active queue](../roadmap/active-work.md).

## Contributor build

With Go 1.26.8 and module-network access, from the candidate source directory:

```sh
make deps
make test
make interop # optional contributor GPG gate using synthetic keys only
make package
```

Dependencies are compiled into `trove`. Make and Go are contributor tools only.
The five-target matrix is `flavors/go-trove/release-targets.json`. The packaging
helper builds Windows ZIP and Unix tar.gz archives and SHA256SUMS in a new output
directory; it refuses to overwrite an existing artifact set. Runtime qualification
on Linux amd64/arm64, Windows amd64/arm64 and macOS arm64 is required separately.
Distribution must include the selected dependencies' licenses before publication.
The helper collects the linked modules' license texts into LICENSE and
THIRD_PARTY_NOTICES without inventing a license for this application. Pass
`--license` to the helper if supplying an authored application license.

## Command interface

Extract the executable for your OS and architecture. On Windows
use `trove.exe`. No installed Go, Python, Make, shell, GPG or OpenSSL is required
to run it. It never launches those tools and never downloads anything.

```sh
trove init --store /path/to/private-store
trove new-user --store /path/to/private-store --name alice --email alice@example.com
trove create-secret --store /path/to/private-store --user alice --name db/password --file password.bin
trove read-secret --store /path/to/private-store --user alice --name db/password
trove add-user --store /path/to/private-store --name bob --key bob.pub
trove grant-access --store /path/to/private-store --user alice --name db/password --recipient bob
trove update-secret --store /path/to/private-store --user alice --name db/password --file replacement.bin
trove revoke-access --store /path/to/private-store --user alice --name db/password --recipient bob
trove list-users --store /path/to/private-store
trove list-secrets --store /path/to/private-store
trove delete-secret --store /path/to/private-store --user alice --name db/password
```

The personal identity directory defaults to your OS configuration directory plus
`trove/identities`. It must be outside the store and source repository. Use
`--identity-dir` to select a protected external directory. Paths containing symbolic
links are rejected; on macOS use `/private/tmp` rather than its `/tmp` alias.
Secret names can contain nested safe components; identities cannot. Explicit
`--user` overrides `PM_USER`, matching login@hostname registration, then login name.

Passphrases are read from a terminal without echo. For unattended use, create a
private 0600 passphrase file outside the repository and pass `--passphrase-file`.
Do not put passphrases on command lines. `--file -` and `--key -` read stdin;
read-secret writes exact plaintext bytes to stdout, including NUL and newlines.
Send stdout directly to the intended destination; errors are written to stderr.

`generate-key --name alice` writes protected secret/public exports to the external
identity directory without registering a user. `new-user` generates a private
identity externally and registers its public key. Existing identities can be
imported with `import-secret-key --name alice --key alice.secret.key`, then their
public key registered using `add-user --name alice --key alice.pub`.
`import-key` requires the same explicit public export file as `add-user`.
Private/secret exports are rejected by public registration. Duplicate registrations,
identities, grants, secret creates and exports are rejected instead of overwritten.

To move an identity, use `export-key --name alice --dir /existing/private/export-dir`;
this writes alice.pub and alice.secret.key with owner-only permissions. Copy the
protected files securely, import the secret key on the other machine and remove
the transfer files. Hardware-backed/nonexportable GPG identities are not supported
by this candidate. GPG is optional for exporting existing software identities once.

## Legacy migration and recovery

Back up the encrypted store and coordinate all team clients before migration.
Import your existing protected private export into the external identity directory.
Then migrate one accessible secret explicitly:

```sh
trove migrate --store /path/to/private-store --user alice --name db/password --accept-unauthenticated-legacy
```

CBC cannot prove authenticity, even with valid padding. This acknowledgement accepts
that historical limitation. Migration keeps a byte-identical `secret.enc.legacy`
encrypted backup and replaces only content after verifying the new authenticated
format. Recipient envelopes are preserved. A repeated migration verifies v2 and
does not rewrite it. An incompatible existing backup stops migration. Keep the
encrypted backup until the whole team has verified access. Roll back by restoring
the encrypted content backup explicitly; there is no automatic downgrade.

Old Make clients cannot read v2 content and must not write migrated stores. Neither
migration nor grant/revoke changes previously recovered root keys or Git history.
Revocation only removes a recipient envelope. To revoke a recovered key, create a
new secret with a new root key and redistribute access; old history still exists.

Store mutations use `.trove.lock` and refuse concurrent writers. An interrupted
process can leave a stale lock: after verifying no Trove writer remains, remove
only that lock manually. Temporary encrypted files and incomplete `.create-*`
directories can remain after abrupt termination; inspect/recover them explicitly.
Cleanup never traverses unrelated store, identity or keyring directories.
