---
schema: literate-ai/flavor-markdown@1
namespace: trove
name: build-trove
version: 1.0.0
display_name: Trove contributor Make build
primary_axis: build.system
target: make
secondary_constraints: []
applicable_capabilities:
  - trove.cli
provides:
  - name: build.policy.make
    version: 1.0.0
    contract: null
requires: []
specification_roots:
  - openspec/spec.md
authoring_inputs:
  - kind: specification-to-source-skill
    uri: ../../skills/specification-to-source/trove-go/SKILL.md
contributions:
  - contribution_id: trove-make-command
    kind: builder
    merge_operator: exact-singleton
    slot: standard-build-system-command
    content:
      kind: standard-command-profile
      uri: standard-command-profile.json
conflicts: []
co_requisites: []
order_before: []
order_after: []
---
# Trove contributor Make build

Select this project-owned build Flavor only for the native Trove capability.
It preserves the ordinary direct CLI and compiles Go modules into one binary.
