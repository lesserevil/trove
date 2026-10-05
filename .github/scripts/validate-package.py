"""Contributor CI helper: verify an archive and test its exact executable."""
import hashlib
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import zipfile

root = Path(__file__).resolve().parents[2]
packages = root / '_build' / 'releases'
label = os.environ['TROVE_TARGET_LABEL']
labels = {'linux_x86_64', 'linux_aarch64', 'windows_x86_64',
          'windows_aarch64', 'macos_aarch64'}
if label not in labels:
    raise SystemExit('Unexpected target label')
extension = '.zip' if label.startswith('windows_') else '.tar.gz'
archives = list(packages.glob(f'trove_*_{label}{extension}'))
if len(archives) != 1:
    raise SystemExit('Expected exactly one archive for this target')
archive = archives[0]
checksums = {}
for line in (packages / 'SHA256SUMS').read_text().splitlines():
    digest, name = line.split('  ', 1)
    if name in checksums:
        raise SystemExit('Duplicate checksum entry')
    checksums[name] = digest
if hashlib.sha256(archive.read_bytes()).hexdigest() != checksums.get(archive.name):
    raise SystemExit('Archive checksum mismatch')
executable = 'trove.exe' if label.startswith('windows_') else 'trove'
expected = {executable, 'README.md', 'LICENSE', 'THIRD_PARTY_NOTICES'}
with tempfile.TemporaryDirectory(prefix='trove-packaged-') as directory:
    binary = Path(directory) / executable
    if extension == '.zip':
        with zipfile.ZipFile(archive) as contents:
            names = contents.namelist()
            if set(names) != expected or len(names) != len(expected):
                raise SystemExit('Unexpected archive members')
            binary.write_bytes(contents.read(executable))
    else:
        with tarfile.open(archive, 'r:gz') as contents:
            members = contents.getmembers()
            if {m.name for m in members} != expected or len(members) != len(expected):
                raise SystemExit('Unexpected archive members')
            if not all(m.isfile() for m in members):
                raise SystemExit('Nonregular archive member')
            binary.write_bytes(contents.extractfile(executable).read())
    binary.chmod(0o700)
    env = dict(os.environ, TROVE_TEST_BINARY=str(binary))
    subprocess.run(['go', 'test', '-mod=readonly', '-count=1', './tests'],
                   cwd=root / 'generated' / 'trove' / 'source', env=env, check=True)
