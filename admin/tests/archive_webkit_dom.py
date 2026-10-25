"""Losslessly archive generated WK DOM exports; verify bytes before removing copies.

Run with explicit evidence case directories. Archives remain in scope for secret scans.
"""
import hashlib
import json
from pathlib import Path
import sys
import zipfile


def archive(directory):
    directory = Path(directory).resolve()
    evidence = Path(__file__).resolve().parent / 'evidence'
    if not directory.is_relative_to(evidence) or not directory.parent.name.startswith('webkit-'):
        raise ValueError('Expected an explicit owned WebKit evidence case directory')
    files = sorted(directory.glob('*.html'))
    if not files or any(path.is_symlink() for path in files):
        raise ValueError('Expected regular generated HTML exports')
    output = directory / 'raw-dom.zip'
    manifest = directory / 'raw-dom-manifest.json'
    if output.exists() or manifest.exists():
        raise FileExistsError('Refusing to replace an existing archive or manifest')
    originals = {path.name: path.read_bytes() for path in files}
    with zipfile.ZipFile(output, 'x', compression=zipfile.ZIP_DEFLATED) as packed:
        for name, data in originals.items():
            packed.writestr(name, data)
    members = []
    with zipfile.ZipFile(output) as packed:
        assert packed.namelist() == list(originals)
        assert packed.testzip() is None
        for name, original in originals.items():
            restored = packed.read(name)
            digest = hashlib.sha256(original).hexdigest()
            assert restored == original == (directory / name).read_bytes()
            assert hashlib.sha256(restored).hexdigest() == digest
            members.append({'name': name, 'bytes': len(original), 'sha256': digest})
    manifest.write_text(json.dumps({
        'archive': output.name, 'format': 'ZIP/DEFLATE',
        'archive_sha256': hashlib.sha256(output.read_bytes()).hexdigest(),
        'verification': 'Every member byte-compared and SHA-256 checked against original before plaintext removal',
        'secret_scan': 'Archive members MUST be included in the parent final secret scan; no exemption',
        'members': members,
    }, indent=2) + '\n')
    for path in files:
        path.unlink()
    print(f'{output}: {len(members)} members verified and archived')


if __name__ == '__main__':
    for argument in sys.argv[1:]:
        archive(argument)
