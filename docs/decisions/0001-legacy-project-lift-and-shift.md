# ADR 0001: Retain Legacy Source Authority During Lift-and-Shift

- Status: Accepted for adoption
- Date: 2026-10-01
- Decision owners: project maintainers
- Baseline evidence: `sha256:b9843c1d35803b010a3bfd5a33b3f199fff8072128ec1e05c1e0b7abdfa802c4`
- Shim parity evidence: `sha256:b1eda4da0f52c5d5e91ec729fcf4543235d4828b2d7838a4fb145245a43ddc7b`

## Context

Phase 1 ran the original Make help/build target and its 25 integration tests.
Phase 1.1 proved that Literate AI can drive those same stages through its wrapper.
No package target or CI configuration was detected. No source-to-specification
transfer has occurred, and these passing tests do not resolve the seven security findings.

## Decision

Move the complete original tree, preserving its internal taxonomy, from quarantine to
`components/legacy-project-wrapper/implementation`. The wrapper Component owns this retained implementation
and `litai.harness.mk` invokes it at its new location. Each move uses `git mv` when the
entry is tracked and plain filesystem move otherwise.

The move is admitted only when the post-move wrapper workflow has the same successful
exit and source-authority tree identity as the Phase 1 direct baseline. Only then is
the empty quarantine directory removed. The retained implementation is not generated
source, not a cache, and not a specification; it remains release authority until a
separate Phase 2 ADR qualifies native Components, Flavors, skills, and assets.

## Consequences

- `components/legacy-project-wrapper/implementation/` is intentionally load-bearing
  retained source and may not be cleaned as a build product.
- Build products still belong outside authority and remain fungible.
- Future migration items replace one retained surface at a time, prove parity, then
  remove its pre-adoption implementation with `git rm` or `rm`.
- Phase 2 owns source-to-specification and native rewrite; this ADR makes no semantic
  equivalence claim beyond E2E parity.
