"""Install a verified, fixed one-shot export bundle. No cloud settings or DB changes.

Run with sudo: python3 -I install_export.py <confirmed-oss-region>
This does not start the unit. Existing installs/configs are never overwritten.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys

DEST = Path('/opt/aifinance-results-retry002')
CONFIG = Path('/etc/aifinance-results-retry002.json')
UNIT = Path('/etc/systemd/system/aifinance-export-retry002.service')
NAMES = ('export_results.py', 'result_common.py', 'cloud_io.py', 'retry002.sql')


def need(ok):
    if not ok:
        raise RuntimeError('install_refused')


def trusted_parent(path):
    for p in (path, *path.parents):
        st = p.lstat()
        need(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022)


def exclusive(path, value, mode=0o644):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as f:
        f.write(value); f.flush(); os.fsync(f.fileno())


def main():
    need(os.geteuid() == 0 and len(sys.argv) == 2 and re.fullmatch('[a-z]{2}-[a-z0-9-]{2,32}', sys.argv[1]))
    need(socket.gethostname() == 'iZ2zedybs3fftu1d9vnx39Z')
    source = Path(__file__).resolve().parent
    # Operator verifies the complete release manifest before invoking this installer.
    hashes = json.loads((source / 'runtime-hashes.json').read_bytes())
    need(set(hashes) == set(NAMES))
    data = {name: (source / name).read_bytes() for name in NAMES}
    need(all(len(data[n]) <= 65536 and hashlib.sha256(data[n]).hexdigest() == hashes[n] for n in NAMES))
    unit = (source / 'aifinance-export-retry002.service').read_bytes()
    need(len(unit) < 4096)
    for path in (DEST, CONFIG, UNIT):
        trusted_parent(path.parent); need(not os.path.lexists(path))
    DEST.mkdir(mode=0o755)
    for name in NAMES:
        exclusive(DEST / name, data[name])
    exclusive(DEST / 'runtime-hashes.json', (json.dumps(hashes, sort_keys=True) + '\n').encode())
    # Explicitly requires administrator to have confirmed/attached the dedicated role first.
    config = {'oss_region': sys.argv[1], 'internal_endpoint': sys.argv[1] == 'cn-beijing',
              'instance_role_confirmed': True}
    exclusive(CONFIG, (json.dumps(config) + '\n').encode(), 0o600)
    exclusive(UNIT, unit)
    subprocess.run(['/usr/bin/systemctl', 'daemon-reload'], check=True, timeout=15)
    print('Installed fixed exporter. Not started, not enabled. No credentials stored.')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('INSTALL_REFUSED: no overwrite; inspect partial installation before retrying.'); sys.exit(1)
