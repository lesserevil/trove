"""Contributor release gates. Product binaries have no Python dependency."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(rc|draft)\.([1-9][0-9]*))?")
TARGETS = {
    'linux_x86_64': 'tar.gz', 'linux_aarch64': 'tar.gz',
    'windows_x86_64': 'zip', 'windows_aarch64': 'zip', 'macos_aarch64': 'tar.gz',
}


def run(argv, root=ROOT):
    return subprocess.run(argv, cwd=root, check=True, text=True, capture_output=True).stdout.strip()


def parse_tag(tag):
    m = TAG.fullmatch(tag)
    if not m or len(tag) > 61:
        raise ValueError('Tag must be vX.Y.Z, vX.Y.Z-rc.N or vX.Y.Z-draft.N without leading zeroes')
    base = '.'.join(m.groups()[:3])
    return {'tag': tag, 'version': tag[1:], 'base': base,
            'branch': f'release/{m[1]}.{m[2]}.x', 'prerelease': m[4] is not None}


def engineers(readme):
    m = re.search(r'^## Release Engineers\s*\n(.*?)(?=^## |\Z)', readme, re.M | re.S)
    return set(re.findall(r'^- `([A-Za-z0-9-]+)`\s*$', m[1], re.M)) if m else set()


def notes(changelog, version, base, prerelease):
    for label in ([version, base, 'Unreleased'] if prerelease else [version]):
        m = re.search(r'^## ' + re.escape(label) + r'(?:[ \t]+[^\n]*)?\n(.*?)(?=^## |\Z)', changelog, re.M | re.S)
        if m and m[1].strip():
            text = m[1].strip() + '\n'
            if prerelease:
                text = ('Candidate prerelease: native source admission and independent '
                        'regeneration must be completed before stable publication.\n\n' + text)
            return text
    raise ValueError('No nonempty authored changelog section for the release version')


def require_qualified(root):
    state = json.loads((root / '.literate/conversion-authority.json').read_text())
    if (state.get('schema') != 'literate-ai/conversion-authority@1'
            or state.get('project_id') != 'trove' or state.get('stage') != 'qualified'
            or state.get('release_authority') != 'specification'
            or not state.get('evidence_identities')):
        raise ValueError('Stable native release requires qualified conversion authority; complete ADOPT-002 first')


def metadata(root, tag, actor, expected_sha=None):
    result = parse_tag(tag)
    run(['git', 'diff', '--quiet', 'HEAD'], root)
    project = json.loads((root / 'literate.project.json').read_text())
    declared = project['version']
    if declared != result['version'] and not (result['prerelease'] and declared == result['base']):
        raise ValueError('Tag does not match the declared project version')
    if actor not in engineers((root / 'README.md').read_text()):
        raise ValueError('Release actor is not listed under README Release Engineers')
    head = run(['git', 'rev-parse', 'HEAD'], root)
    if expected_sha and expected_sha != head:
        raise ValueError('Release checkout differs from event revision')
    ref = f'refs/tags/{tag}'
    if run(['git', 'cat-file', '-t', ref], root) != 'tag':
        raise ValueError('Release tag must be annotated')
    if run(['git', 'rev-parse', ref + '^{commit}'], root) != head:
        raise ValueError('Release tag differs from checkout')
    remote = dict(line.split()[::-1] for line in run(
        ['git', 'ls-remote', 'origin', ref, ref + '^{}'], root).splitlines())
    if remote.get(ref + '^{}') != head or remote.get(ref) != run(['git', 'rev-parse', ref], root):
        raise ValueError('Remote tag changed or is missing')
    line = 'refs/remotes/origin/' + result['branch']
    on_line = subprocess.run(['git', 'merge-base', '--is-ancestor', head, line], cwd=root,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    if not on_line:
        policy = project['repository_policy']
        on_main_rc = (result['prerelease'] and '-rc.' in tag
                      and policy['main_state'] == 'pre-release'
                      and policy['pre_release_version'] == '.'.join(result['base'].split('.')[:2])
                      and run(['git', 'rev-parse', 'refs/remotes/origin/main'], root) == head)
        if not on_main_rc:
            raise ValueError('Tag is outside its maintenance line (or exact main RC revision)')
    if not result['prerelease']:
        require_qualified(root)
        if result['base'].endswith('.0'):
            run(['git', 'merge-base', '--is-ancestor', 'refs/remotes/origin/main', head], root)
    result['revision'] = head
    result['notes'] = notes((root / 'CHANGELOG.md').read_text(), result['version'], result['base'], result['prerelease'])
    return result


def inventory(directory, version):
    expected = {f'trove_{version}_{label}.{ext}' for label, ext in TARGETS.items()}
    files = {p.name: p for p in directory.iterdir()}
    if set(files) != expected | {'SHA256SUMS'}:
        raise ValueError('Release must contain exactly five archives and SHA256SUMS')
    if any(p.is_symlink() or not p.is_file() or p.stat().st_size == 0 for p in files.values()):
        raise ValueError('Release assets must be nonempty regular files')
    manifest = {}
    for line in files['SHA256SUMS'].read_text().splitlines():
        m = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_.-]+)', line)
        if not m or m[2] in manifest:
            raise ValueError('Invalid or duplicate checksum entry')
        manifest[m[2]] = m[1]
    if set(manifest) != expected:
        raise ValueError('Checksums must cover the exact archive inventory')
    digests = {name: hashlib.sha256(p.read_bytes()).hexdigest() for name, p in files.items()}
    if any(digests[name] != digest for name, digest in manifest.items()):
        raise ValueError('Release archive checksum mismatch')
    return digests


def gh_json(argv):
    return json.loads(run(['gh', *argv]))


def publish(root, release, directory, repository):
    digests = inventory(directory, release['version'])
    # The release list (rather than a swallowed `view` error) distinguishes
    # missing releases from authentication/network failures.
    pages = gh_json(['api', '--paginate', '--slurp', f'repos/{repository}/releases?per_page=100'])
    releases = [r for page in pages for r in page]
    matches = [r for r in releases if r['tag_name'] == release['tag']]
    if len(matches) > 1:
        raise ValueError('Ambiguous existing release')
    existing = matches[0] if matches else None
    names = [a['name'] for a in existing['assets']] if existing else []
    if len(names) != len(set(names)) or not set(names) <= set(digests):
        raise ValueError('Existing release has unexpected or duplicate assets')
    if existing:
        with tempfile.TemporaryDirectory(prefix='trove-release-verify-') as tmp:
            for name in names:
                run(['gh', 'release', 'download', release['tag'], '--repo', repository,
                     '--pattern', name, '--dir', tmp], root)
                if hashlib.sha256((Path(tmp) / name).read_bytes()).hexdigest() != digests[name]:
                    raise ValueError('Existing asset differs; published bytes cannot be replaced')
        if not existing['draft']:
            if set(names) != set(digests) or existing['prerelease'] != release['prerelease']:
                raise ValueError('Published release is incomplete or has a different release class')
            print('Release already published with the exact validated assets')
            return
    else:
        metadata(root, release['tag'], os.environ.get('GITHUB_ACTOR', ''), release['revision'])
        notes_file = root / '_build' / 'RELEASE_NOTES.md'
        notes_file.write_text(release['notes'])
        run(['gh', 'release', 'create', release['tag'], '--repo', repository, '--verify-tag',
             '--draft', '--title', release['tag'], '--notes-file', str(notes_file)], root)
    for name in sorted(set(digests) - set(names)):
        run(['gh', 'release', 'upload', release['tag'], str(directory / name), '--repo', repository], root)
    with tempfile.TemporaryDirectory(prefix='trove-release-complete-') as tmp:
        run(['gh', 'release', 'download', release['tag'], '--repo', repository, '--dir', tmp], root)
        downloaded = inventory(Path(tmp), release['version'])
        if downloaded != digests:
            raise ValueError('Uploaded release differs from qualified bytes')
    stable_versions = []
    for r in releases:
        if not r['draft'] and not r['prerelease'] and TAG.fullmatch(r['tag_name']):
            info = parse_tag(r['tag_name'])
            if not info['prerelease']:
                stable_versions.append(tuple(map(int, info['base'].split('.'))))
    latest = (not release['prerelease'] and tuple(map(int, release['base'].split('.'))) >= max(stable_versions, default=(0, 0, 0)))
    metadata(root, release['tag'], os.environ.get('GITHUB_ACTOR', ''), release['revision'])
    run(['gh', 'release', 'edit', release['tag'], '--repo', repository, '--draft=false',
         '--prerelease=' + str(release['prerelease']).lower(), '--latest=' + str(latest).lower()], root)
    observed = gh_json(['api', f'repos/{repository}/releases/tags/{release["tag"]}'])
    if observed['draft'] or observed['prerelease'] != release['prerelease'] or {a['name'] for a in observed['assets']} != set(digests):
        raise ValueError('GitHub did not record the complete published release')
    print('Published verified release', release['tag'])


def local_check(candidate=False):
    version = json.loads((ROOT / 'literate.project.json').read_text())['version']
    info = parse_tag('v' + version)
    if not candidate and not info['prerelease']:
        require_qualified(ROOT)
    verification = json.loads(run(['litai', 'verify']))
    if not verification.get('result', {}).get('ok'):
        raise ValueError('Litai verification failed')
    subprocess.run([sys.executable, str(Path(__file__)), 'test'], cwd=ROOT, check=True)
    source = ROOT / 'generated/trove/source'
    env = dict(os.environ, CGO_ENABLED='0', GOTOOLCHAIN='go1.26.8')
    for argv in (['go', 'mod', 'verify'], ['go', 'vet', '-mod=readonly', './...'],
                 ['go', 'test', '-mod=readonly', '-count=1', './...'],
                 ['go', 'test', '-mod=readonly', '-tags', 'interoperability', '-count=1', './internal/pgp']):
        subprocess.run(argv, cwd=source, env=env, check=True)
    (ROOT / '_build').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='trove-release-check-', dir=ROOT / '_build') as tmp:
        packages = Path(tmp) / 'packages'
        subprocess.run(['go', 'run', '-mod=readonly', './tools/release', '--version', version,
                        '--out', str(packages)], cwd=source, env=env, check=True)
        inventory(packages, version)
        import platform
        labels = {('Darwin', 'arm64'): 'macos_aarch64', ('Linux', 'x86_64'): 'linux_x86_64',
                  ('Linux', 'aarch64'): 'linux_aarch64', ('Windows', 'AMD64'): 'windows_x86_64',
                  ('Windows', 'ARM64'): 'windows_aarch64'}
        env.update(TROVE_PACKAGE_DIR=str(packages), TROVE_PACKAGE_VERSION=version,
                   TROVE_TARGET_LABEL=labels[(platform.system(), platform.machine())])
        subprocess.run([sys.executable, str(ROOT / '.github/scripts/validate-package.py')], cwd=ROOT, env=env, check=True)
    print('Host and five cross-build gates passed; tag CI must still qualify every native target')


def tag_candidate(root, tag, actor, authorized):
    if not authorized:
        raise ValueError('Candidate tag push requires --authorize-external-write')
    info = parse_tag(tag)
    if not info['prerelease']:
        raise ValueError('Stable tags use litai release plan/prepare/check/publish')
    if run(['git', 'status', '--porcelain'], root):
        raise ValueError('Candidate tagging requires a clean checkout')
    login = gh_json(['api', 'user'])['login']
    if actor and actor != login or login not in engineers((root / 'README.md').read_text()):
        raise ValueError('Authenticated actor is not a release engineer')
    project = json.loads((root / 'literate.project.json').read_text())
    if project['version'] not in (info['version'], info['base']):
        raise ValueError('Candidate version differs from project metadata')
    notes((root / 'CHANGELOG.md').read_text(), info['version'], info['base'], True)
    branch = run(['git', 'branch', '--show-current'], root)
    if branch == 'main':
        policy = project['repository_policy']
        if ('-rc.' not in tag or policy['main_state'] != 'pre-release'
                or policy['pre_release_version'] != '.'.join(info['base'].split('.')[:2])):
            raise ValueError('Main RC requires matching Pre-release state')
    elif branch != info['branch']:
        raise ValueError('Candidate requires its maintenance line or exact main RC')
    run(['git', 'fetch', 'origin'], root)
    head = run(['git', 'rev-parse', 'HEAD'], root)
    if head != run(['git', 'rev-parse', 'refs/remotes/origin/' + branch], root):
        raise ValueError('Push the reviewed branch before candidate tagging')
    if subprocess.run(['git', 'rev-parse', '--verify', 'refs/tags/' + tag], cwd=root,
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
        raise ValueError('Candidate tag already exists locally')
    if run(['git', 'ls-remote', 'origin', 'refs/tags/' + tag], root):
        raise ValueError('Candidate tag already exists remotely')
    repository = gh_json(['repo', 'view', '--json', 'nameWithOwner'])['nameWithOwner']
    runs = gh_json(['run', 'list', '--repo', repository, '--branch', branch, '--commit', head,
                    '--workflow', 'CI', '--limit', '30', '--json', 'status,conclusion,headSha,headBranch,event'])
    if not any(item['status'] == 'completed' and item['conclusion'] == 'success'
               and item['headSha'] == head and item['headBranch'] == branch
               and item['event'] in ('push', 'workflow_dispatch') for item in runs):
        raise ValueError('Candidate requires successful CI on the exact pushed branch commit')
    existing = gh_json(['api', '--paginate', '--slurp', f'repos/{repository}/releases?per_page=100'])
    if any(item['tag_name'] == tag for page in existing for item in page):
        raise ValueError('A GitHub release already occupies the candidate tag')
    run(['git', 'tag', '-a', tag, '-m', 'Candidate ' + tag], root)
    run(['git', 'push', 'origin', 'refs/tags/' + tag], root)
    print('Candidate tag pushed; require its Release workflow to pass before using assets')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['metadata', 'publish', 'check', 'test', 'tag-candidate'])
    parser.add_argument('--tag', default=os.environ.get('GITHUB_REF_NAME'))
    parser.add_argument('--candidate', action='store_true', help='local diagnostic only; never authorizes stable publication')
    parser.add_argument('--actor')
    parser.add_argument('--authorize-external-write', action='store_true')
    args = parser.parse_args()
    if args.command == 'test':
        subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s', str(ROOT / 'tests/release'), '-v'], cwd=ROOT, check=True)
    elif args.command == 'check':
        local_check(args.candidate)
    elif args.command == 'tag-candidate':
        tag_candidate(ROOT, args.tag or '', args.actor, args.authorize_external_write)
    else:
        release = metadata(ROOT, args.tag or '', os.environ.get('GITHUB_ACTOR', ''), os.environ.get('GITHUB_SHA'))
        triggering = os.environ.get('GITHUB_TRIGGERING_ACTOR')
        if triggering and triggering not in engineers((ROOT / 'README.md').read_text()):
            raise ValueError('Retry actor is not a release engineer')
        (ROOT / '_build').mkdir(exist_ok=True)
        if args.command == 'metadata':
            (ROOT / '_build/release-metadata.json').write_text(json.dumps(release, indent=2) + '\n')
            if os.environ.get('GITHUB_OUTPUT'):
                with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
                    f.write(f'version={release["version"]}\n')
        else:
            if not os.environ.get('GITHUB_ACTIONS') == 'true' or not os.environ.get('GH_TOKEN'):
                raise ValueError('Publication requires the gated GitHub Actions job')
            publish(ROOT, release, ROOT / '_build/releases', os.environ['GITHUB_REPOSITORY'])


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError, KeyError) as exc:
        sys.exit(f'release: {exc}')
