# Crypto smoke-test isolation contract

Owned by the contributor harness boundary in the
[retained inventory](retained-boundaries.md) and
[ADOPT-002](../roadmap/active-work.md#adopt-002), addressing finding 6 first.
`Makefile` delegates `test-crypto` to `tests/smoke_crypto.sh` using a fixed command.

## Requirements

- Allocate one new private root with `mktemp -d`. Install exit and HUP/INT/TERM
  traps before allocation or any fallible setup. An allocation failure must not
  select an inherited path as a cleanup target.
- Create every plaintext, ciphertext, public export, private identity and public
  keyring under that allocation. Use `umask 077` throughout: directories are `0700`
  and files are `0600` on supported legacy Unix hosts.
- Caller `STORE_DIR`, `USERS_DIR`, `SECRETS_DIR`, `GNUPGHOME`, and identity settings
  must not determine test setup or cleanup. All GPG calls use an explicit allocated
  home; an overridden `TMPDIR` selects only the parent of a new allocation.
- Cleanup may shut down only agents associated with allocated homes and remove
  only the root returned by this harness's successful allocation. Never recreate,
  delete, or “reset” caller directories.
- Failures and handled signals return nonzero. Cleanup preserves the preceding
  exit status. Uncatchable termination may leave a private allocation; no later
  run may sweep arbitrary directories to compensate.
- Exercise the legacy OpenPGP key envelope and AES-CBC format with synthetic keys
  and byte-for-byte text and binary comparisons. Do not claim CBC authenticity.
- Keep this harness contributor-only. Its existing GPG/OpenSSL/Bash requirements
  do not become requirements of the planned self-contained Go executable.

## Independent acceptance

`tests/test_smoke_safety.sh` creates existing caller-store, legacy-keyring, and
personal-identity sentinels and a copy to compare after each run. It invokes the
real Make entry point with explicit caller-directory overrides and an inherited
GPG home. A wrapper checks each actual GPG home and the permissions of allocated
directories and data files, then delegates successful work to the installed GPG.

The suite exercises success, GPG failure, OpenSSL failure, HUP, INT, TERM, and failed
allocation. Every case must preserve all caller bytes and entries, remove its
allocated smoke-test root when cleanup can run, and return the expected success or
failure. Real successful encryption must complete both round trips. These checks
also run as one additional case in the existing integration suite.

The Go test port will extend this contract with independent per-recipient identity
directories and Windows ACL, cancellation, and handle-cleanup evidence. Those
platform checks remain pending until the native replacement exists.
