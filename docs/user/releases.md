# Binary releases

Trove releases contain one executable per supported target, with no separate
runtime or crypto program required. [GitHub Releases](https://github.com/lesserevil/trove/releases)
is the durable download location. Each release has these six assets:

| Target | Archive |
| --- | --- |
| Linux x86_64 | `trove_X.Y.Z_linux_x86_64.tar.gz` |
| Linux aarch64 | `trove_X.Y.Z_linux_aarch64.tar.gz` |
| Windows x86_64 | `trove_X.Y.Z_windows_x86_64.zip` |
| Windows aarch64 | `trove_X.Y.Z_windows_aarch64.zip` |
| macOS aarch64 | `trove_X.Y.Z_macos_aarch64.tar.gz` |
| All targets | `SHA256SUMS` |

Numbered prereleases include their suffix in every filename, for example
`trove_1.0.0-rc.1_linux_x86_64.tar.gz`. Each archive includes the CLI, usage guide,
license material and third-party notices. Download the matching archive and
SHA256SUMS, verify its checksum, and extract the executable to a directory on PATH.
Checksums detect changed bytes; they are not a signature. OS code signing and
notarization are not configured by this process.

## Branches and versions

Borrowing Trickle's maintenance and immutable-publication model, development
continues on `main`. A new major/minor cut creates `release/X.Y.x` from main;
the line stays for patch maintenance. Release fixes land on main first and are
selectively backported. The maintenance branch is not merged wholesale into main.
The first stable cut of a line must contain current remote main; later patches
preserve selective backporting. Advance main's development version after a cut.

`literate.project.json` is the version authority. `literate.release.json` selects
the local product gate, changelog, tag format, default branch and documentation
review updates. It uses `make release-check`, replacing the adoption template's
unrelated hello-sample gate. CI supplies the other native runtimes.

Stable tags are annotated `vX.Y.Z`. Prereleases are annotated
`vX.Y.Z-rc.N` or `vX.Y.Z-draft.N`, with N starting at one. No leading zeroes,
mutable tags or per-patch release branches are permitted. The tag version must
match project metadata; prerelease tags may use the declared stable base version,
as Trickle's numbered draft tags do. A draft on a maintenance line publishes as
a GitHub **prerelease**, distinct from the private draft used during asset upload.
An RC on main must point to exact remote main HEAD with matching Litai Pre-release
state; otherwise a prerelease must be reachable from its matching maintenance line.

Only identities under README's `## Release Engineers` section may start or retry publication. Configure GitHub rulesets for `release/*` branches
and `v*` tags to prevent unauthorized creation, updates and deletion. The workflow
checks actors and remote tag identity, but this file does not claim forge rulesets
have been installed.

## Prepare a cut

Use a clean checkout with the documented Litai installation, Go toolchain and
contributor prerequisites. Reconcile the active queue and tracker, land the intended
work on main, and run `litai release contributions sweep`. Classify open items with
`litai release contributions disposition` as required by the installed release skill.
These commands do not themselves authorize publishing a release.

When a human schedules a major/minor cut, the release engineer sets the matching
Pre-release state with `litai release state set --mode pre-release
--pre-release-version X.Y`. Ordinary development stays Free until that decision.
For a new maintenance line, plan on main; for a patch, backport approved main fixes
with `litai release backport` and plan on the existing line. Inspect the plan before
applying it:

```sh
litai release plan --version 1.1.0 > _build/release-plan.json
litai release prepare _build/release-plan.json
```

The version shown is an example. Litai preparation creates a missing maintenance
line, updates the declared version and moves Unreleased notes into its versioned
changelog section. Review and finish the authored notes. The declared documentation
authority path lets preparation refresh its review marker. Refresh the exact
current test receipt through the qualified lifecycle before committing the prepared
version, notes and evidence; do not reuse an old receipt or mark qualification by hand.

```sh
litai rebuild
litai verify
git add literate.project.json CHANGELOG.md docs/architecture/design-traceability.md verification/current.json
git commit -m 'Prepare release'
litai release check _build/release-plan.json
```

Use the prepared record path emitted by the check for publication. After explicit
release authorization, push the maintenance branch before publishing its tag:

```sh
git push -u origin HEAD
litai release publish PREPARED_RECORD --authorize-external-write
litai release verify-published PREPARED_RECORD
```

The policy deliberately leaves the Litai provider null, as Trickle does: Litai owns
version preparation and Git publication, while tag CI owns GitHub release assets.
`verify-published` proves the Git publication; also require the **Release** workflow
to pass and inspect/download the six GitHub assets. A successful tag push alone
is not a successful binary release. Use `litai release advance-default-branch`
from main after the cut; preserve all tags and shipped bytes.

For a main RC, set the matching Litai Pre-release state; for a numbered draft,
check out its maintenance line. Commit authored notes, push the reviewed branch,
and require successful CI on that exact branch commit. Then, after authorization:

```sh
python3 scripts/release.py tag-candidate --tag v1.0.0-rc.1 --actor lesserevil --authorize-external-write
```

Use `vX.Y.Z-draft.N` for a maintenance-line draft. The helper verifies actor,
version, clean checkout, pushed revision, CI and an unused tag namespace before
creating and pushing an annotated tag. Trove uses this helper because the installed
Litai `release rc` command requires a GitHub provider and builds a Python wheel;
Trove's provider remains null and binary publication belongs to tag CI.
Never reuse a candidate number. A failed tag push can leave a local annotated tag;
inspect its exact target before pushing that same tag again.

## CI and recovery

The tag workflow first validates the annotated tag, project version, branch ancestry,
release engineer and authored notes. It builds one five-archive set, then calls the
same reusable workflow as ordinary PR/main/maintenance-line CI. Every native runner
runs the full Go suite and the exact packaged CLI with its embedded version checked.
Linux x86_64 also runs synthetic GPG interoperability. All jobs must pass.

Only the final publisher has `contents: write`. It downloads the tested archives
without rebuilding, validates the complete checksum inventory and creates a private
GitHub draft. It uploads absent assets, downloads and verifies all six assets, and
only then publishes. Prereleases never become Latest; a maintenance patch older than
a newer stable line does not displace Latest. Actions use pinned commits and keep
checkout credentials disabled. Publication uses the workflow token, with no custom
stored credential required.

Retry unsuccessful jobs in the same Release run after fixing a runner outage.
When orchestration needs repair, dispatch the repaired workflow for the existing
immutable tag with `gh workflow run release.yml --ref main -f tag=vX.Y.Z`.
All validation and publication checkouts bind to the verified tagged revision,
independent of the dispatch branch. The workflow restores the exact remote annotated
tag object after checkout; it never changes the remote tag. Complete recovery before
advancing main after an initial cut, since first-cut ancestry checks require the
current default branch.
Matching assets are preserved; a partial draft can receive only missing assets.
A published complete release is an idempotent success when all bytes match.
Different bytes, unexpected files, missing targets or a moved tag fail closed:
prepare a new version/tag rather than using asset overwrite or tag force-push.

## Current readiness

[Stable 1.0.0](https://github.com/lesserevil/trove/releases/tag/v1.0.0)
publishes the tested, checked-in Go implementation with all five archives and
SHA256SUMS. Native and exact packaged validation and published download verification
pass in [Release run 37421028777](https://github.com/lesserevil/trove/actions/runs/37421028777). Every cut still requires exact-revision native tests, packaged
CLI validation on all five targets and checksum verification of published downloads.
[ADOPT-002](../roadmap/active-work.md#adopt-002) retains Literate AI source admission
and independent regeneration as separate follow-up work. Publication does not
advance conversion metadata or claim specification-authoritative source.
`make release-check-candidate` remains a local diagnostic; it cannot publish a tag.
Historical GitHub CBC+HMAC migration acceptance remains separate from the qualified
GitLab CBC migration.
