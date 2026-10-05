# Native rewrite program

- **Status:** partial
- **Owning queue item:** [ADOPT-002](active-work.md#adopt-002)
- **Completion / archival evidence:** pending while ADOPT-002 remains open

The retained implementation at `components/legacy-project-wrapper/implementation` remains source-authority
until each boundary earns transfer under ADR 0002.

The [security remediation plan](security-remediation.md) supplies the product design,
seven findings, rollout rules, and five-target release matrix for this same ADOPT-002
program. This document describes the Literate AI authority-transfer process. The
retained harness containment change has passing 26-case parity evidence. The
native Go candidate is preserved under `generated/trove/source`. Its full native
and exact packaged CLI suites pass on all five hosted target runtimes, with
synthetic GPG interoperability on Linux amd64 and macOS arm64. See
[WIN-001 completion evidence](active-work.md#win-001)
and [PR 8](https://github.com/lesserevil/trove/pull/8).
Source admission, independent regeneration, GitHub CBC+HMAC migration acceptance
and release remain pending. Generated source remains disposable.

## Ordered work

1. [x] Produce a [boundary inventory](../architecture/retained-boundaries.md) and
   [specify isolated smoke-test cleanup](../architecture/smoke-test-contract.md) before
   running the unsafe legacy `test-crypto` target: deployables, public interfaces, data schemas,
   runtime state, build targets, tests, packages, CI/release jobs, assets, and target
   variance. Every row names source/test/document evidence and an owner.
2. [x] Classify each inventory row as Component intent, Flavor requirement, conversion skill,
   immutable asset, repository-only harness, or intentionally retained source.
3. [ ] Select the smallest independently buildable/testable boundary and author its
   native authority; leave later boundaries retained.
4. [ ] Generate, build, test, execute, and package the candidate through the ordinary
   lifecycle; compare intended observable results with the Phase 1.2 parity record
   and prove the deliberate security behavior changes against the seven regressions.
   Execute all five target binaries; cross-compilation alone is insufficient.
5. [ ] Independently accept and regeneratively qualify the candidate before authority
   transfer.
6. [ ] Remove only the replaced retained files (`git rm`/`rm`), rerun the full E2E
   workflow, record evidence, then repeat from step 3.
7. [ ] Prove no unclassified retained file remains; archive this program only after
   full parity and current project verification.

Current verification is recorded in ADOPT-002: the full retained 26-case suite and
current project verification pass after enabling unrestricted execution. Native
acceptance and authority transfer remain unchecked.
