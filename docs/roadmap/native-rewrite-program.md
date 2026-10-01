# Native rewrite program

- **Status:** active
- **Owning queue item:** [ADOPT-002](active-work.md#adopt-002)
- **Completion / archival evidence:** pending while ADOPT-002 remains open

The retained implementation at `components/legacy-project-wrapper/implementation` remains source-authority
until each boundary earns transfer under ADR 0002.

The [security remediation plan](security-remediation.md) supplies the product design,
seven findings, rollout rules, and five-target release matrix for this same ADOPT-002
program. This document describes the Literate AI authority-transfer process. The
current task records the program; implementation and release remain pending.

## Ordered work

1. [ ] Produce a boundary inventory and specify isolated smoke-test cleanup before
   running the unsafe legacy `test-crypto` target: deployables, public interfaces, data schemas,
   runtime state, build targets, tests, packages, CI/release jobs, assets, and target
   variance. Every row names source/test/document evidence and an owner.
2. [ ] Classify each row as Component intent, Flavor requirement, conversion skill,
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
