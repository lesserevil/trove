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
