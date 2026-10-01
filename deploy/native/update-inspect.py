#!/usr/bin/python3
"""One reviewed root update, default check-only. No account/sshd/sudoers changes."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import tempfile

BIN = Path('/opt/aifinance/bin')
SOURCE = Path(__file__).resolve().parent
OLD_GATEWAY = '0d93245bec09662c2392a28c4c6047ba0d6c46e45f881ac508ca0436c7b265f9'


def trusted(p, directory=False):
    for parent in p.parents:
        st = parent.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise ValueError('Untrusted ancestor')
    st = p.lstat()
    if st.st_uid != 0 or st.st_mode & 0o022 or not (stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode)):
        raise ValueError('Unexpected owner/type/permissions')


def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()


def restore(gateway_digest, inspect_digest, apply=False):
    """Restore only the known old gateway, retaining all evidence and helper files."""
    if os.geteuid() != 0: raise ValueError('Trusted administrator terminal required')
    trusted(BIN, True)
    gateway = BIN / 'ssh-gateway.py'
    backup = BIN / 'ssh-gateway.py.before-inspect-0d93245b.bak'
    inspector = BIN / 'inspect-native.py'
    for value in (gateway_digest, inspect_digest):
        if not re.fullmatch('[0-9a-f]{64}', value): raise ValueError('Reviewed SHA256 required')
    trusted(backup); trusted(gateway)
    if sha(backup) != OLD_GATEWAY or sha(gateway) not in (OLD_GATEWAY, gateway_digest):
        raise ValueError('Unknown backup or gateway')
    if inspector.exists() or inspector.is_symlink():
        trusted(inspector)
        if sha(inspector) != inspect_digest: raise ValueError('Unknown inspector')
    if not apply:
        print('CHECK ONLY: restore known old gateway; retain backup and inspector')
        return
    fd, staged = tempfile.mkstemp(prefix='.gateway-restore-', dir=str(BIN))
    try:
        with os.fdopen(fd, 'wb') as f:
            os.fchmod(f.fileno(), 0o755); f.write(backup.read_bytes()); f.flush(); os.fsync(f.fileno())
        os.replace(staged, str(gateway))
    finally:
        if os.path.exists(staged): os.unlink(staged)
    print('RESTORED: original gateway; evidence retained; no automatic retry')


def update(gateway_digest, inspect_digest, apply=False):
    if os.geteuid() != 0: raise ValueError('Trusted administrator terminal required')
    trusted(BIN, True); trusted(SOURCE, True)
    gateway = BIN / 'ssh-gateway.py'
    inspector = BIN / 'inspect-native.py'
    backup = BIN / 'ssh-gateway.py.before-inspect-0d93245b.bak'
    expected = {'ssh-gateway.py': gateway_digest, 'inspect-native.py': inspect_digest}
    for name, value in expected.items():
        if not re.fullmatch('[0-9a-f]{64}', value): raise ValueError('Reviewed SHA256 required')
        trusted(SOURCE / name)
        if sha(SOURCE / name) != value: raise ValueError('Reviewed file digest mismatch')
    trusted(gateway)
    if sha(gateway) != OLD_GATEWAY: raise ValueError('Installed gateway differs; no overwrite')
    if any(p.exists() or p.is_symlink() for p in (inspector, backup)):
        raise ValueError('Existing helper/backup; inspect prior attempt, no automatic retry')
    if not apply:
        print('CHECK ONLY: two reviewed files; no account, sudoers, sshd or credential changes')
        return
    with backup.open('xb') as f:
        os.fchmod(f.fileno(), 0o600); f.write(gateway.read_bytes()); f.flush(); os.fsync(f.fileno())
    with inspector.open('xb') as f:
        os.fchmod(f.fileno(), 0o755); f.write((SOURCE / 'inspect-native.py').read_bytes()); f.flush(); os.fsync(f.fileno())
    fd, staged = tempfile.mkstemp(prefix='.gateway-inspect-', dir=str(BIN))
    try:
        with os.fdopen(fd, 'wb') as f:
            os.fchmod(f.fileno(), 0o755); f.write((SOURCE / 'ssh-gateway.py').read_bytes()); f.flush(); os.fsync(f.fileno())
        trusted(gateway)
        if sha(gateway) != OLD_GATEWAY: raise ValueError('Gateway changed; backup retained')
        os.replace(staged, str(gateway))
    finally:
        if os.path.exists(staged): os.unlink(staged)
    print('INSPECT READY: verify preserved; no deployment enabled; original gateway backup retained')


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--gateway-sha256', required=True)
    p.add_argument('--inspect-sha256', required=True)
    p.add_argument('--apply', action='store_true')
    p.add_argument('--restore', action='store_true')
    a = p.parse_args()
    try: (restore if a.restore else update)(a.gateway_sha256, a.inspect_sha256, a.apply)
    except (ValueError, OSError):
        raise SystemExit('STOP: review file hashes, ownership and any prior partial update; no automatic fallback')
