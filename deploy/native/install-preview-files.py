#!/usr/bin/python3
"""One reviewed first-preview file update. Does not initialize/start/enable services."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

SOURCE = Path('/root/aifinance-native-inputs')
BIN = Path('/opt/aifinance/bin')
SYSTEM = Path('/etc/systemd/system')
BACKUP = BIN / 'before-first-preview-v1'
HELPERS = ('release.sh', 'extract-release.py', 'run-preview.py', 'inspect-native.py',
           'first-preview.py', 'egress-guard.py', 'isolation-probe.py', 'ssh-gateway.py')
UNITS = tuple('aifinance-preview-' + role + '.service' for role in ('api', 'web', 'egress'))
OLD = {
    'release.sh': '551d2fc7b7e54f3aebcd75d147e7c162445aa5e8bcec4bc4f7b690710b8fe201',
    'run-preview.py': 'b636bc6b4d790731275263178394bdd16d9f6b4bdb1a8491578c1e67da7e9da9',
    'ssh-gateway.py': '04a66f6b0475b7a02c9192ae703658ca98f0460250515c968ce59490984e77b1',
    'inspect-native.py': 'c631995399b6b2ec90926c8ce577d73c1d53c4b49655e33e36181c0f71a64151',
}
ENV = dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin', HOME='/', LANG='C', LC_ALL='C')


def trusted(path, directory=False):
    for p in (path,) + tuple(path.parents):
        st = p.lstat()
        if st.st_uid != 0 or st.st_mode & 0o022 or not (stat.S_ISDIR(st.st_mode) if p != path or directory else stat.S_ISREG(st.st_mode)):
            raise ValueError('untrusted_path')


def data(path):
    trusted(path)
    if path.stat().st_size > 256 * 1024:
        raise ValueError('oversize_reviewed_input')
    return path.read_bytes()


def digest(path):
    return hashlib.sha256(data(path)).hexdigest()


def absent(path):
    if path.exists() or path.is_symlink():
        raise ValueError('existing_new_path_or_partial_update')


def check(manifest_sha):
    if os.getuid() != 0 or os.geteuid() != 0:
        raise ValueError('administrator_required')
    if Path(__file__).absolute() != SOURCE / 'install-preview-files.py':
        raise ValueError('fixed_source_location_required')
    if digest(SOURCE / 'preview-files.json') != manifest_sha:
        raise ValueError('reviewed_manifest_mismatch')
    manifest = json.loads(data(SOURCE / 'preview-files.json').decode())
    expected = set(HELPERS + UNITS + ('install-preview-files.py',))
    if not isinstance(manifest, dict) or set(manifest) != expected:
        raise ValueError('exact_file_manifest_required')
    for name, expected_sha in manifest.items():
        if digest(SOURCE / name) != expected_sha:
            raise ValueError('reviewed_input_hash_mismatch')
    trusted(BIN, True); trusted(SYSTEM, True); absent(BACKUP)
    for name in HELPERS:
        target = BIN / name
        if name in OLD:
            if digest(target) != OLD[name]:
                raise ValueError('unknown_installed_helper')
        else:
            absent(target)
    for name in UNITS:
        absent(SYSTEM / name); absent(SYSTEM / (name + '.d'))
        absent(Path('/run/systemd/system') / name)
        result = subprocess.run(['/usr/bin/systemctl', 'show', name, '-p', 'LoadState', '--value'],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=ENV, timeout=10)
        if result.returncode != 0 or result.stdout.strip() != b'not-found':
            raise ValueError('existing_or_unavailable_preview_unit')
    return manifest


def write_file(path, content, mode):
    fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(content); f.flush(); os.fsync(f.fileno()); os.fchmod(f.fileno(), mode)


def apply(manifest_sha):
    manifest = check(manifest_sha)
    BACKUP.mkdir(mode=0o700)
    BACKUP.chmod(0o700)
    for name in OLD:
        write_file(BACKUP / name, data(BIN / name), 0o600)
    # Install gateway last: partial failures never expose upload before all helpers.
    for name in UNITS + HELPERS:
        target = (SYSTEM if name in UNITS else BIN) / name
        content = data(SOURCE / name)
        if hashlib.sha256(content).hexdigest() != manifest[name]:
            raise ValueError('source_changed_during_update')
        if name in OLD:
            if digest(target) != OLD[name]:
                raise ValueError('installed_helper_changed_during_update')
            fd, temporary = tempfile.mkstemp(prefix='.first-preview-', dir=str(BIN))
            try:
                with os.fdopen(fd, 'wb') as f:
                    f.write(content); f.flush(); os.fsync(f.fileno()); os.fchmod(f.fileno(), 0o755)
                os.replace(temporary, str(target))
            finally:
                if os.path.exists(temporary): os.unlink(temporary)
        else:
            write_file(target, content, 0o644 if name in UNITS else 0o755)
    subprocess.run(['/usr/bin/systemctl', 'daemon-reload'], check=True, env=ENV, timeout=20,
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print('PREVIEW FILES INSTALLED: upload-only staging enabled; no unit started/enabled; backup retained')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--manifest-sha256', required=True)
    p.add_argument('--apply', action='store_true')
    args = p.parse_args()
    if args.apply: apply(args.manifest_sha256)
    else:
        check(args.manifest_sha256)
        print('CHECK ONLY: exact new inputs and known old files verified; no writes')


if __name__ == '__main__':
    try: main()
    except (ValueError, OSError, subprocess.SubprocessError):
        raise SystemExit('STOP: preserve inputs/backups/partial files for administrator review; no automatic retry')
