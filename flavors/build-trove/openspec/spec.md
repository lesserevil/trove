# Contributor build

### Requirement: Module-aware native artifact

Make SHALL remain a contributor convenience, with no secret-management recipes.
Build the Go module using the exact quoted LITAI_LANGUAGE_TOOL and honor framework
OBJECT_ROOT, OUT and EXPORT_PATH. Keep caches/objects outside admitted source.
Build/test/package/clean targets SHALL not create or destroy personal keys or
caller stores. Runtime commands SHALL need only the exported native binary.

#### Scenario: Produce a standalone native CLI

- **WHEN** a qualified source tree is built with the contributor all target
- **THEN** EXPORT_PATH contains one CGO-free executable supporting ordinary CLI flags
- **AND** the artifact does not depend on the source directory or Make at runtime

### Requirement: Versioned binary publication

Development remains on main. Stable releases SHALL use annotated immutable
vX.Y.Z tags reachable from release/X.Y.x; release-critical fixes land on main
before selective backport. Numbered rc or draft tags SHALL publish as prereleases.
Tags, project version and release notes SHALL agree. The release pipeline SHALL
build one complete five-target archive set with SHA256SUMS, execute native tests
and the exact packaged CLI on every target, and publish those same bytes only
after every gate passes. Retries SHALL verify existing assets and never replace
published bytes or move a tag. Only publication may receive repository write access.
Native publication SHALL release the tested checked-in Go implementation.
Literate AI admission and regenerative qualification remain separate follow-up
work and SHALL NOT block binary publication or be claimed by release metadata. The installer
remains a single executable; contributor release tools add no runtime dependency.

#### Scenario: Recover a partially uploaded release

- **WHEN** a release upload is retried after interruption
- **THEN** matching existing assets are preserved and only absent assets are uploaded
- **AND** a changed asset, missing target or failed native gate prevents publication
