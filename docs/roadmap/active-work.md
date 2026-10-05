# Active work

This file is the durable resumption queue for user-directed and discovered work. Before
implementation, follow `skills/agent/record-user-directed-work/SKILL.md`.
Keep detailed designs in focused roadmap documents and link them here.

## Detailed-roadmap lifecycle

This file is the sole resumable queue. Create a supporting file beneath `docs/roadmap/`
only when one item cannot keep a program's rationale, ordering, and acceptance contract
readable. Put this visible header immediately after the detailed document's title:

```markdown
- **Status:** active
- **Owning queue item:** [AREA-NNN](active-work.md#area-nnn-heading)
- **Completion / archival evidence:** pending while AREA-NNN remains open
```

Status is exactly `active`, `partial`, `deferred`, `completed`, or `historical`. The
owner must resolve to a checkbox or named program heading in this file. A terminal state
requires linked evidence. Keep a completed plan here only when doing so preserves useful
inbound links; move substantial closed programs beneath `docs/history/roadmap/`, retain
their owner, and mark them `historical`. Do not create a separate file for an ordinary
queue item or let `docs/roadmap/` become a plan archive.

## P0

<a id="onboard-001"></a>
### [x] ONBOARD-001 — Adopt Literate AI and record the security roadmap

- **Owner:** project configuration / documentation / retained harness
- **Direction:** Use the installed `litai` tool to convert Trove and add the agreed
  security remediation and Go binary plan to the roadmap. The user subsequently
  authorized committing the conversion and plan on a branch and opening a GitLab MR.
- **Conclusion:** Adopt the existing application as a retained Component with baseline
  and wrapper parity evidence. The Go rewrite and seven fixes remain planned work in
  ADOPT-002; conversion does not migrate secrets or transfer source authority.
- **Depends on:** none
- **Implementation:**
  - [x] Run `litai init --convert --empty` with Go and Make preferences and preserve
    the original tree under `components/legacy-project-wrapper/implementation/`.
  - [x] Exclude local caches from retained source membership using `litai` and remove
    the scaffold's Python packaging preference from project configuration.
  - [x] Replace onboarding placeholders with Trove documentation and connect the
    complete security plan, five release targets, and native rewrite queue.
  - [x] Make test-summary labels unambiguous to the installed `litai` observer and
    readmit the harness with fresh evidence. Its whitespace-matching parser reads
    `Passed: 25` followed by `Failed: 0` as `25 Failed`; add a unit after each
    displayed count while preserving the suite's test cases, counters, and exit status.
    Observer checks verified 25/0, 24/1, and 0/25 pass/fail counts; readmission reran
    the baseline and wrapper successfully with exactly 25 passing tests.
- **Evidence:**
  - [x] Direct baseline and wrapper parity pass the existing 25 integration tests;
    `.literate/legacy-harness-baseline.json` and `.literate/legacy-lift-shift.json`
    record the tool's successful execution evidence.
  - [x] Verified all 17 original file hashes and the same moved keyring directory;
    At adoption completion, Git HEAD remained `3c6849a` and the roadmap plan was
    untracked and uncommitted, as originally requested.
    The subsequent reporting-only change to `tests/helpers.sh` supports the observer
    compatibility described above; all 16 other original files remain byte-identical.
  - [x] `litai project validate` passes without advisories. `litai verify` passes
    authority, locks, and current receipt gates; unconfigured source-intelligence and
    HTML gates are skipped. `verification/current.json` records 25 passing tests.
    `litai project convert-stage advance --to retained` completed; the native Go
    rewrite and its independent acceptance remain open under ADOPT-002.

Check the parent only after every required subtask and evidence item passes. Add the
release-visible outcome to `CHANGELOG.md`; Git preserves prior queue states.

<a id="adopt-002"></a>
### [ ] ADOPT-002 — Secure self-contained Go executable

- **Priority:** P0
- **Owner:** Trove Component / target and packaging Flavors / acceptance contracts
- **Direction:** Fix all seven security findings with one Go executable containing
  OpenPGP support and no separately installed runtime or crypto tools. Ship Linux
  x86_64/aarch64, Windows x86_64/aarch64, and macOS aarch64 binaries.
- **Conclusion:** The [security remediation plan](security-remediation.md) owns the
  behavior, migration, release matrix, and security acceptance requirements. Follow
  [ADR 0002](../decisions/0002-native-literate-ai-rewrite.md) and the
  [native rewrite program](native-rewrite-program.md) to author specifications and
  qualify generated replacements. Make remains a contributor tool. Current retained
  behavior is evidence, including known defects that must change deliberately.
- **Depends on:** ONBOARD-001
- **Next action (in progress):** Implement the native Go rewrite, as explicitly
  requested by the user. The candidate is written in `generated/trove/source`.
  Module access is restored and `go mod tidy` and the full native suite pass.
  GPG interoperability, the patched full native suite and all five candidate
  archives pass their local gates. Complete Literate AI source admission and
  independent/regenerative acceptance, then qualify the target runtimes. Do not transfer authority before those gates.
- **Containment progress:** The [boundary inventory](../architecture/retained-boundaries.md)
  classifies every retained surface. `test-crypto` now uses one private allocation
  under the [smoke contract](../architecture/smoke-test-contract.md), with no caller
  store/keyring cleanup. Independent failure, signal and allocation checks are added
  as the 26th integration case.
- **Retained verification:** With unrestricted execution, all 26 cases pass, including
  successful synthetic crypto and all smoke cleanup failures/signals. Literate AI
  readmitted the retained harness and published a current 26-case receipt. This is
  retained parity evidence, not native acceptance or authority transfer.
- **Implementation:**
  - [ ] Isolate smoke-test setup and cleanup (finding 6) and classify retained boundaries.
    The implementation, inventory and current 26-case harness qualification
    pass. Windows and native interruption checks remain later finding-6 acceptance.
  - [ ] Author CLI, store, identity, format, migration, and acceptance contracts;
    select project-specific Go/module and binary-archive Flavors.
    Authored `components/trove/component.md`, project-owned `go-trove` and
    `build-trove` Flavors,
    conversion skill and five-target matrix. `litai lock` records host resolution.
    Full independent acceptance and release qualification remain open.
  - [x] Prove embedded OpenPGP compatibility and a `CGO_ENABLED=0` binary.
    Synthetic GPG RSA3072 and Curve25519 imports and envelope round trips pass;
    all five actual binaries build with CGO disabled.
  - [ ] Implement literal CLI input and safe filesystem operations (findings 2 and 4).
  - [ ] Implement external personal identities, public-only registration, and protected
    private exports (findings 7, 1, and 5).
  - [ ] Add authenticated v2 content and explicit recoverable legacy migration (finding 3).
  - [x] Build and package Linux amd64/arm64, Windows amd64/arm64, and macOS arm64
    candidate binaries with one checksums manifest; update installation and recovery guidance.
    `_build/releases-native-final` contains the five archives and SHA256SUMS.
    Checksums, exact archive contents, architecture, Go build metadata and Go/runtime
    dependency licenses were verified. These are candidate archives, not a release.
  - [ ] Qualify replacements before retiring operational Make recipes or retained source.
- **Evidence:**
  - [x] The safety regression fails against the pre-fix Makefile because it removes
    disposable caller sentinels. The corrected runner passes focused GPG/OpenSSL
    failures, HUP/INT/TERM and failed allocation, preserving sentinels and expected
    exit statuses. Shell syntax validation passes. The full success case now passes with the retained 26-case suite.
  - [ ] Seven security regressions and all 25 existing behavior cases pass through the CLI.
  - [x] On macOS arm64, migration, tampering, retained cleanup interruption, and
    separate-identity tests pass using synthetic keys and stores, with no change to
    real secrets. Other platform execution remains a separate gate below.
  - [ ] All five artifacts execute on their target OS/architecture without external
    runtimes or crypto commands; platform permissions and containment checks pass.
  - [ ] GPG interoperability, dependency review, independent acceptance, and
    regenerative qualification meet every completion criterion in the detailed plan.
  - [ ] Current project verification and release evidence support authority transfer.

#### Native candidate evidence

- `generated/trove/source` contains the Go module, direct CLI, Proton adapter,
  external protected identities, held-root filesystem layer, HKDF/AES-GCM format,
  explicit CBC migration with encrypted backup, contributor Make rules and Go
  archive/checksum helper. It is an **unadmitted, disposable draft**, excluded by
  the existing generated-source Git policy; the original client is not retired.
- Native standard-library suites for CLI parsing/setup, formats, filesystem
  confinement and archive contents pass on macOS arm64. Tests include every-byte
  tampering, binary round trips, cross-name substitution, strict padding, exclusive
  writes/locks, protected permissions, symlink replacement races and exact ZIP/tar
  contents. `_build/native-core-tests.jsonl` is diagnostic output, not a receipt.
  The root `make test-core` target passes as well. A five-second format fuzz run
  completed 679,550 executions without a crash or failing case.
- The filesystem test executable cross-compiles with CGO_ENABLED=0 for all five
  targets. Only the macOS arm64 suite executes here; Windows DACL tests are compiled
  but not executed. These are filesystem test artifacts, not Trove release binaries.
- Real-binary tests cover the retained behavior classes plus security and migration
  cases with separate identities and an empty runtime PATH. After network access
  was enabled, `go mod tidy` downloaded the pinned Proton modules and recorded real
  checksums. `CGO_ENABLED=0 go test -count=1 ./...` passes on macOS arm64, including
  the real-binary suite (38 seconds). GPG interoperability and other target runtimes
  remain separate gates.
- Security review of the downloaded graph found reachable CIRCL and Go standard-library
  advisories. Pins now require Go 1.26.8, CIRCL 1.6.3, x/crypto 0.56.0, x/sys 0.47.0
  and x/term 0.45.0 alongside the original Proton pins. `govulncheck` 1.8.0 against
  the 2026-10-01 database reports zero reachable traces after patching. The single
  module-level advisory GO-2026-5932 concerns deprecated x/crypto/openpgp, absent
  from `_build/native-linked-packages.txt`; the maintained Proton fork is linked.
  `go mod verify` and `go vet ./...` pass.
- `CGO_ENABLED=0 go test -tags interoperability -count=1 ./...` passes with Go 1.26.8.
  Public packet tests reject hidden private subkeys in binary and public armor,
  multiple primary keys and trailing material. Synthetic GPG tests cover RSA3072
  and Curve25519 identity import plus envelope encryption/decryption in both directions.
  The exact packaged macOS executable also passes the complete actual-CLI suite
  via `TROVE_TEST_BINARY`, with an empty runtime PATH.
- All five actual candidate executables are built and packaged under
  `_build/releases-native-final`. Linux files are static ELF executables; Windows
  files are PE executables of the correct architecture; macOS is arm64 Mach-O.
  The patched filesystem test suites cross-compile for all five. Linux and Windows
  runtime/ACL/reparse qualification awaits suitable runners; The existing Colima VM could not start: its disk is already attached to an
  instance despite reporting stopped. No disks/locks were cleared, and no Linux
  runtime evidence is inferred. GitLab has no Trove CI configuration or enabled
  project runners. The user accepted the macOS testing for this commit and deferred
  CI work; other target runtime qualification remains open.
- `litai verify` now passes authority, locks and the current retained 26-test receipt.
  Unconfigured source-intelligence and HTML gates remain skipped. Native admission
  was retried under `generated/trove-admission-patched`; its first tree was discarded
  by automatic retry and the run was stopped before changing the checksum inputs.
  The isolated generator cannot download modules; the Go Flavor now supplies actual
  verified go.sum metadata for immutable source verification. The new diagnostic run under `generated/trove-admission-checksums` failed with
  `coding_cli.empty_generation` and produced no accepted source.
  `_build/native-admission-debug.log` records the actual failure. Diagnose the
  coding-CLI handoff and complete genuine admission before claiming admitted source.
- `litai generate ... --admit --source-test-command '["go","test","-count=1","./..."]'`
  was attempted after locking/reviewing authority and failed with
  `coding_cli.generation_failed`. No source-cache membership or passing project
  receipt was created. `litai project validate` passes; the new current receipt
  qualifies retained parity only, and remains distinct from the rewrite gates.
- The user authorized committing and pushing this work based on the macOS testing.
  `generated/trove/source` is preserved as a checked-in derived candidate, distinct
  from admitted source-cache membership. This does not close admission or release gates.
- Resume from the [native client guide](../user/native-client.md). Restore the
  checked-in candidate from Git if `litai really-clean` removes the generated tree.

### [x] HOST-001 — Integrate with the public GitHub project and validate five native targets

- **Priority:** P1
- **Owner:** project hosting / GitHub Actions
- **Direction:** Move a copy to the lesserevil personal GitHub account and use hosted runners for the five Trove targets.
- **Conclusion:** The user selected the existing public lesserevil/trove repository. Preserve GitLab and both Git histories; integrate on a review branch without replacing GitHub main. Add synthetic native validation without claiming source admission or releasing binaries.
- **Depends on:** ADOPT-002
- **Implementation:**
  - [x] Push an integration branch containing both histories; keep existing GitHub main unchanged.
  - [x] Add five-platform native tests and packaged executable validation.
  - [x] Open a GitHub PR and inspect workflow results.
- **Evidence:**
  - [x] GitHub destination is public as explicitly approved and the integration commit matches local Git.
  - [x] Native and packaged CLI suites pass on all five hosted targets, or failures are recorded explicitly.

- **Integration boundary:** GitHub main has an independent Make/CBC+HMAC implementation.
  Its Makefile, tests, README and agent skill are preserved under
  `components/legacy-project-wrapper/github-reference/`; both Git histories remain
  reachable. The current native migration qualifies the retained GitLab CBC format
  only. GitHub CBC+HMAC compatibility requires a separate synthetic fixture and
  acceptance before migrating any store in that format.

- **GitHub PR:** [#8](https://github.com/lesserevil/trove/pull/8), draft.
- **Hosting evidence:** `aa54521` is pushed to the GitHub integration branch and
  contains both histories. GitHub main remains `f62f07b`; GitHub is now `origin`, and
  the original remote is retained as `gitlab`. Literate AI tracker inspection selects GitHub.
- **Hosting outcome:** [PR #8](https://github.com/lesserevil/trove/pull/8) is open
  as a draft. The integration branch is pushed; GitHub main is unchanged.
- **Initial CI correction:** The first packaging job failed because a fresh checkout
  has no `_build` parent. The workflow now creates that disposable parent before
  invoking the packager; no runtime qualification is inferred from the failed run.
- **Hosted runtime evidence:** [Run 37358454750](https://github.com/lesserevil/trove/actions/runs/37358454750)
  tested `f873a60`. Packaging and native plus exact packaged CLI tests passed on
  Linux amd64, Linux arm64 and macOS arm64. Synthetic GPG interoperability also
  passed on Linux amd64. Both Windows architectures acquired hosted runners but
  failed the native suite during private-directory protection with `Access is denied`;
  their packaged CLI gates were skipped, so Windows is not qualified.
- **Rewrite follow-up (ADOPT-002):** Diagnose Windows held-handle ACL protection
  (`internal/safefs/windows.go`, `TestWindowsPrivateDACLAndBroadFileRejection`)
  on both hosted architectures, then rerun the native and packaged suites. Preserve
  owner/System-only permissions; do not bypass the failing protection gate.

### [ ] WIN-001 — Fix Windows protection and land the native rewrite PR

- **Priority:** P0
- **Owner:** trove filesystem candidate / GitHub PR 8
- **Direction:** Fix issues in open PRs and merge passing changes to main.
- **Conclusion:** PR 8 is the only open GitHub PR. Both Windows native suites fail during held-handle DACL protection. Fix the implementation without weakening protection, qualify all five targets, then merge through the configured merge method.
- **Depends on:** none
- **Implementation:**
  - [x] Repair Windows ACL protection and add focused Windows regressions.
  - [ ] Run five native and packaged executable gates and address review feedback.
  - [ ] Merge PR 8 and synchronize local main with GitHub.
- **Evidence:**
  - [ ] All five platform jobs pass on the final implementation commit.
  - [ ] Litai verification passes and GitHub records the merge to main.

- **Windows diagnosis:** Both architectures fail the `ReOpenFile` call used to
  obtain ACL-write access on an `os.Root` directory handle. The repair uses an
  NT handle-relative reopen, verifies object identity before ACL mutation, and
  explicitly assigns current-user ownership plus a protected owner/System DACL.
  Added renamed-file and renamed-directory replacement tests; target passes remain
  required. Packaging uses Linux arm64 to avoid the queued amd64 packaging pool.

- **Focused Windows evidence:** [Run 37366154289](https://github.com/lesserevil/trove/actions/runs/37366154289)
  passed the ARM64 filesystem/application checks, including the renamed-object
  permission regression. All five archives build on Linux arm64. Full native and
  packaged target suites are still required before merging.
