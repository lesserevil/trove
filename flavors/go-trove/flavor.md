---
schema: literate-ai/flavor-markdown@1
namespace: trove
name: go-trove
version: 1.0.0
display_name: Trove Go module CLI
primary_axis: implementation.language-ecosystem
target: go
secondary_constraints: []
applicable_capabilities:
  - trove.cli
provides:
  - name: implementation.language.go
    version: 1.0.0
    contract: null
requires: []
specification_roots:
  - openspec/spec.md
authoring_inputs:
  - kind: specification-to-source-skill
    uri: ../../skills/specification-to-source/trove-go/SKILL.md
contributions:
  - contribution_id: trove-go-command
    kind: builder
    merge_operator: exact-singleton
    slot: standard-language-command
    content:
      kind: standard-command-profile
      uri: standard-command-profile.json
conflicts:
  - "flavor://literate-ai/lang-go"
co_requisites: []
order_before: []
order_after: []
---
# Trove Go module CLI

This project-owned Flavor composes with build-trove for the module-aware build.
