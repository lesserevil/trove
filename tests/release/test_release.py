"""Release failures must not authorize publication or replace existing bytes."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts import release as r


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='trove-release-test-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def packages(self):
        d = self.root / 'packages'
        d.mkdir()
        sums = []
        for label, ext in r.TARGETS.items():
            name = f'trove_1.2.0_{label}.{ext}'
            (d / name).write_bytes(('fixture ' + label).encode())
            sums.append(hashlib.sha256((d / name).read_bytes()).hexdigest() + '  ' + name)
        (d / 'SHA256SUMS').write_text('\n'.join(sorted(sums)) + '\n')
        return d

    def fixture(self, tag='v1.2.0', version='1.2.0', annotated=True, line=True, qualified=True, pre_release=False):
        root = self.root / 'repo'
        root.mkdir()
        git = lambda *args: r.run(['git', '-c', 'commit.gpgsign=false', '-c', 'tag.gpgsign=false', *args], root)
        git('init', '-b', 'main')
        git('config', 'user.name', 'Synthetic Release Fixture')
        git('config', 'user.email', 'release@example.invalid')
        git('config', 'tag.gpgsign', 'false')
        (root / 'README.md').write_text('# Test\n\n## Release Engineers\n\n- `fixture`\n')
        (root / 'CHANGELOG.md').write_text('## Unreleased\n\nUpcoming.\n\n## 1.2.0 - 2026-10-05\n\nRelease fix.\n')
        (root / 'literate.project.json').write_text(json.dumps({'version': version, 'repository_policy': {
            'main_state': 'pre-release' if pre_release else 'free', 'pre_release_version': '1.2' if pre_release else None}}))
        (root / '.literate').mkdir()
        (root / '.literate/conversion-authority.json').write_text(json.dumps({
            'schema': 'literate-ai/conversion-authority@1', 'project_id': 'trove',
            'stage': 'qualified' if qualified else 'retained', 'release_authority': 'specification' if qualified else 'original-source', 'evidence_identities': ['fixture']}))
        git('add', '.')
        git('commit', '-m', 'Fixture')
        if line:
            git('branch', 'release/1.2.x')
        if annotated:
            git('tag', '-a', tag, '-m', 'Fixture')
        else:
            git('tag', tag)
        bare = self.root / 'origin.git'
        r.run(['git', 'init', '--bare', str(bare)])
        git('remote', 'add', 'origin', str(bare))
        git('push', 'origin', '--all')
        git('push', 'origin', '--tags')
        git('fetch', 'origin')
        return root, git

    def test_canonical_tags(self):
        for tag in ('v0.1.0', 'v1.2.3', 'v1.2.0-rc.1', 'v1.2.0-draft.2'):
            self.assertEqual(r.parse_tag(tag)['branch'], 'release/' + '.'.join(tag[1:].split('.')[:2]) + '.x')
        for tag in ('1.2.3', 'v01.2.3', 'v1.2.3-rc.0', 'v1.2.3-rc.01', 'v1.2.3+build', 'v1.2.3;touch file', 'v1.2.3-beta'):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                r.parse_tag(tag)

    def test_exact_stable_metadata(self):
        root, _ = self.fixture()
        m = r.metadata(root, 'v1.2.0', 'fixture')
        self.assertFalse(m['prerelease'])
        self.assertIn('Release fix', m['notes'])

    def test_reject_unauthorized_actor_and_wrong_event(self):
        root, _ = self.fixture()
        with self.assertRaisesRegex(ValueError, 'actor'):
            r.metadata(root, 'v1.2.0', 'stranger')
        with self.assertRaisesRegex(ValueError, 'event revision'):
            r.metadata(root, 'v1.2.0', 'fixture', '0' * 40)

    def test_reject_lightweight_tag(self):
        root, _ = self.fixture(annotated=False)
        with self.assertRaisesRegex(ValueError, 'annotated'):
            r.metadata(root, 'v1.2.0', 'fixture')

    def test_reject_version_mismatch(self):
        root, _ = self.fixture(version='1.3.0')
        with self.assertRaisesRegex(ValueError, 'version'):
            r.metadata(root, 'v1.2.0', 'fixture')

    def test_reject_wrong_release_line(self):
        root, _ = self.fixture(line=False)
        with self.assertRaisesRegex(ValueError, 'maintenance line'):
            r.metadata(root, 'v1.2.0', 'fixture')

    def test_reject_moved_remote_tag(self):
        root, git = self.fixture()
        git('push', 'origin', ':refs/tags/v1.2.0')
        with self.assertRaisesRegex(ValueError, 'Remote tag'):
            r.metadata(root, 'v1.2.0', 'fixture')

    def test_stable_requires_qualified_authority(self):
        root, _ = self.fixture(qualified=False)
        with self.assertRaisesRegex(ValueError, 'qualified'):
            r.metadata(root, 'v1.2.0', 'fixture')

    def test_candidate_is_explicit_prerelease(self):
        root, _ = self.fixture(tag='v1.2.0-draft.1', qualified=False)
        m = r.metadata(root, 'v1.2.0-draft.1', 'fixture')
        self.assertTrue(m['prerelease'])
        self.assertIn('Candidate prerelease', m['notes'])

    def test_main_rc_requires_exact_pre_release_state(self):
        root, _ = self.fixture(tag='v1.2.0-rc.1', line=False)
        with self.assertRaisesRegex(ValueError, 'maintenance line'):
            r.metadata(root, 'v1.2.0-rc.1', 'fixture')

    def test_main_rc_accepts_pre_release_state(self):
        root, _ = self.fixture(tag='v1.2.0-rc.1', line=False, pre_release=True)
        self.assertTrue(r.metadata(root, 'v1.2.0-rc.1', 'fixture')['prerelease'])

    def test_dirty_authority_rejected(self):
        root, _ = self.fixture()
        (root / 'README.md').write_text('changed')
        with self.assertRaises(subprocess.CalledProcessError):
            r.metadata(root, 'v1.2.0', 'fixture')

    def test_first_stable_cut_contains_current_main(self):
        root, git = self.fixture()
        (root / 'next.txt').write_text('next main work')
        git('add', 'next.txt')
        git('commit', '-m', 'Advance main')
        git('push', 'origin', 'main')
        git('checkout', 'v1.2.0')
        with self.assertRaises(subprocess.CalledProcessError):
            r.metadata(root, 'v1.2.0', 'fixture')

    def test_candidate_tag_push_requires_explicit_authorization(self):
        with self.assertRaisesRegex(ValueError, 'authorize-external-write'):
            r.tag_candidate(self.root, 'v1.2.0-rc.1', 'fixture', False)

    def test_candidate_tags_require_green_branch_commit(self):
        root, git = self.fixture(tag='v1.2.0-rc.1', line=False, pre_release=True)
        head = git('rev-parse', 'HEAD')
        github = [{'login': 'fixture'}, {'nameWithOwner': 'fixture/repo'}, []]
        with patch.object(r, 'gh_json', side_effect=github), self.assertRaisesRegex(ValueError, 'successful CI'):
            r.tag_candidate(root, 'v1.2.0-rc.2', 'fixture', True)
        self.assertEqual(git('tag', '-l', 'v1.2.0-rc.2'), '')
        github = [{'login': 'fixture'}, {'nameWithOwner': 'fixture/repo'},
                  [{'status': 'completed', 'conclusion': 'success', 'headSha': head,
                    'headBranch': 'main', 'event': 'push'}], [[]]]
        with patch.object(r, 'gh_json', side_effect=github):
            r.tag_candidate(root, 'v1.2.0-rc.2', 'fixture', True)
        self.assertEqual(git('cat-file', '-t', 'v1.2.0-rc.2'), 'tag')
        self.assertIn('refs/tags/v1.2.0-rc.2', git('ls-remote', 'origin', 'refs/tags/v1.2.0-rc.2'))

    def test_authored_notes_required(self):
        with self.assertRaises(ValueError):
            r.notes('## Unreleased\n\nSomething.\n', '1.2.0', '1.2.0', False)

    def test_complete_inventory(self):
        self.assertEqual(len(r.inventory(self.packages(), '1.2.0')), 6)

    def test_missing_extra_changed_and_duplicate_assets_rejected(self):
        d = self.packages()
        name = next(n for n in r.inventory(d, '1.2.0') if n != 'SHA256SUMS')
        original = (d / name).read_bytes()
        (d / name).unlink()
        with self.assertRaises(ValueError): r.inventory(d, '1.2.0')
        (d / name).write_bytes(original + b'changed')
        with self.assertRaises(ValueError): r.inventory(d, '1.2.0')
        (d / name).write_bytes(original)
        (d / 'extra').write_text('extra')
        with self.assertRaises(ValueError): r.inventory(d, '1.2.0')
        (d / 'extra').unlink()
        with (d / 'SHA256SUMS').open('a') as f:
            f.write((d / 'SHA256SUMS').read_text().splitlines()[0] + '\n')
        with self.assertRaises(ValueError): r.inventory(d, '1.2.0')

    def publisher(self, existing, corrupt=False):
        d = self.packages()
        info = r.parse_tag('v1.2.0')
        info.update(notes='Notes', revision='abc')
        (self.root / '_build').mkdir()
        calls = []
        def command(argv, root=None):
            calls.append(argv)
            if argv[:3] == ['gh', 'release', 'download']:
                dest = Path(argv[argv.index('--dir') + 1])
                names = [argv[argv.index('--pattern') + 1]] if '--pattern' in argv else list(r.inventory(d, '1.2.0'))
                for name in names:
                    (dest / name).write_bytes(b'changed' if corrupt else (d / name).read_bytes())
            return ''
        published = {'draft': False, 'prerelease': False, 'assets': [{'name': n} for n in r.inventory(d, '1.2.0')]}
        with patch.object(r, 'gh_json', side_effect=[[[existing]] if existing else [[]], published]), \
                patch.object(r, 'run', side_effect=command), patch.object(r, 'metadata'):
            r.publish(self.root, info, d, 'fixture/repo')
        return calls

    def test_new_release_is_draft_until_download_verified(self):
        calls = self.publisher(None)
        create = next(c for c in calls if c[1:3] == ['release', 'create'])
        self.assertIn('--draft', create)
        self.assertIn('--verify-tag', create)
        self.assertEqual(len([c for c in calls if c[1:3] == ['release', 'upload']]), 6)
        self.assertEqual(calls[-1][1:3], ['release', 'edit'])
        self.assertTrue(all('--clobber' not in c for c in calls))

    def test_partial_retry_only_uploads_missing_assets(self):
        name = 'trove_1.2.0_linux_x86_64.tar.gz'
        calls = self.publisher({'tag_name': 'v1.2.0', 'draft': True, 'prerelease': False, 'assets': [{'name': name}]})
        uploads = [c for c in calls if c[1:3] == ['release', 'upload']]
        self.assertEqual(len(uploads), 5)
        self.assertFalse(any(Path(c[4]).name == name for c in uploads))

    def test_changed_existing_asset_cannot_be_replaced(self):
        with self.assertRaisesRegex(ValueError, 'cannot be replaced'):
            self.publisher({'tag_name': 'v1.2.0', 'draft': True, 'prerelease': False,
                            'assets': [{'name': 'trove_1.2.0_linux_x86_64.tar.gz'}]}, corrupt=True)

    def test_published_release_retry_does_not_mutate(self):
        assets = [{'name': f'trove_1.2.0_{label}.{ext}'} for label, ext in r.TARGETS.items()]
        assets.append({'name': 'SHA256SUMS'})
        calls = self.publisher({'tag_name': 'v1.2.0', 'draft': False, 'prerelease': False, 'assets': assets})
        self.assertFalse(any(c[1:3] in (['release', 'upload'], ['release', 'edit'], ['release', 'create']) for c in calls))

    def test_published_incomplete_release_cannot_be_repaired(self):
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            self.publisher({'tag_name': 'v1.2.0', 'draft': False, 'prerelease': False, 'assets': []})

    def test_unexpected_remote_assets_reject_publication(self):
        with self.assertRaisesRegex(ValueError, 'unexpected'):
            self.publisher({'tag_name': 'v1.2.0', 'draft': True, 'prerelease': False, 'assets': [{'name': 'extra'}]})

    def test_uploaded_corruption_prevents_publication(self):
        with self.assertRaises(ValueError):
            self.publisher(None, corrupt=True)


if __name__ == '__main__':
    unittest.main()
