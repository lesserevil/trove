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
- **Next action:** Inventory the retained boundaries and specify an isolated replacement
  for the destructive `test-crypto` harness before executing it.
- **Implementation:**
  - [ ] Isolate smoke-test setup and cleanup (finding 6) and classify retained boundaries.
  - [ ] Author CLI, store, identity, format, migration, and acceptance contracts;
    select project-specific Go/module and binary-archive Flavors.
  - [ ] Prove embedded OpenPGP compatibility and a `CGO_ENABLED=0` binary.
  - [ ] Implement literal CLI input and safe filesystem operations (findings 2 and 4).
  - [ ] Implement external personal identities, public-only registration, and protected
    private exports (findings 7, 1, and 5).
  - [ ] Add authenticated v2 content and explicit recoverable legacy migration (finding 3).
  - [ ] Build and package Linux amd64/arm64, Windows amd64/arm64, and macOS arm64
    binaries with one checksums manifest; update installation and recovery guidance.
  - [ ] Qualify replacements before retiring operational Make recipes or retained source.
- **Evidence:**
  - [ ] Seven security regressions and all 25 existing behavior cases pass through the CLI.
  - [ ] Migration, tampering, cleanup interruption, and separate-identity tests pass
    using synthetic keys and stores, with no change to real secrets.
  - [ ] All five artifacts execute on their target OS/architecture without external
    runtimes or crypto commands; platform permissions and containment checks pass.
  - [ ] GPG interoperability, dependency review, independent acceptance, and
    regenerative qualification meet every completion criterion in the detailed plan.
  - [ ] Current project verification and release evidence support authority transfer.
