# ADR 0002: Rewrite Retained Implementation as Native Literate AI Authority

- Status: Proposed
- Date: 2026-10-01
- Decision owners: project maintainers
- Phase 1.2 evidence: `sha256:673fd5a8e5a8b6b7c54e47f2392d3c0a99d910e6d61bbfb603e7502b439dde5d`

## Context

The original project now lives at `components/legacy-project-wrapper/implementation`
and passes the same Make help/build target and 25 integration tests through the
Literate AI wrapper. Packaging and CI are not yet configured. This move proved
project reorganization only. The retained implementation remains release authority.

The accepted product direction is a self-contained Go executable with embedded
OpenPGP and five release targets, as specified in the
[security remediation plan](../roadmap/security-remediation.md). That rewrite is
planned work; implementation and authority transfer remain pending.

## Decision

Run a second, independently reviewed migration program that replaces retained
implementation surfaces with native Literate AI Components, Flavors, skills, and
assets. Work proceeds one public boundary at a time:

1. Inventory the boundary from retained source, tests, docs, build metadata, and the
   Phase 1 evidence without treating implementation detail as product intent.
2. Author or refine a native Component specification and its named interface/data
   contracts. Target-specific behavior belongs in Flavors; conversion practice belongs
   in exact skills; immutable non-code inputs become assets.
3. Generate a candidate in the normal Literate AI lifecycle and compare its build,
   tests and intended observable behavior with the retained baseline. Validate the
   new binary packages and intentional security behavior changes against the plan's
   acceptance criteria; do not preserve a vulnerability merely to claim parity.
4. Transfer release authority only after independent acceptance and regenerative
   qualification. Until then the retained source remains authoritative.
5. Remove the replaced retained files with `git rm` when tracked or `rm` otherwise,
   rerun the complete workflow, and record parity before beginning the next boundary.

## Guardrails

- This ADR does not claim source disposability before regenerative qualification.
- Generated source stays in the accepted source cache; objects and fetched binaries
  stay under the object root and never enter Git.
- No target-specific Dockerfile, package-manager, OS, or toolchain instruction is
  copied into Component prose; those remain Flavor authority.
- A failed replacement restores the retained files and keeps their authority state.
- Publication and deletion remain separately authorized operations.

## Completion

The rewrite is complete only when every retained boundary has either transferred to a
qualified native Component or is documented as intentionally retained, the full E2E
workflow matches the Phase 1.2 baseline, and `components/legacy-project-wrapper/implementation` contains no
unclassified remainder.

## Release-owner clarification (2026-10-06)

The owner explicitly selected the tested checked-in Go implementation for stable
1.0.0 binary publication. The authority-transfer program above remains open and
does not gate product releases. Native CI and exact package validation govern
published binaries; no release claims regenerative qualification or changes the
conversion-authority projection. Retained implementations remain available for
conversion evidence and recovery.
