#!/usr/bin/python3
"""Root-managed systemd entry. Inherit EnvironmentFile; never parse or log secrets."""
import os
from pathlib import Path
import pwd
import re
import stat
import sys

ROOT = Path('/opt/aifinance')
NODE = Path('/usr/local/bin/node')
BASELINE = 'd57ba047369e666025347719caee1a4c642abe62'
ENTRIES = {'api': 'apps/api/src/main.ts', 'web': 'apps/web/server.ts'}


def trusted(path):
    for candidate in (path, *path.parents):
        info = candidate.lstat()
        kind = stat.S_ISREG(info.st_mode) if candidate == path else stat.S_ISDIR(info.st_mode)
        if info.st_uid != 0 or info.st_mode & 0o022 or not kind:
            raise ValueError('untrusted_launcher_or_node')


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ENTRIES:
        raise ValueError('invalid_role')
    if os.getuid() == 0 or os.geteuid() != os.getuid() or pwd.getpwuid(os.getuid()).pw_name != 'aifinance-deploy':
        raise ValueError('wrong_user')
    trusted(Path(__file__).resolve())
    trusted(NODE)
    if os.environ.get('HOME') != '/opt/aifinance':
        raise ValueError('runtime_home_changed')
    # Pin the cwd inherited from systemd. Do not re-resolve current after a race
    # and silently launch a different release from the one systemd entered.
    release = Path.cwd()
    sha = release.name
    if not re.fullmatch(r'[a-f0-9]{40}', sha):
        raise ValueError('invalid_release')
    expected = ROOT / ('staging' if sha == BASELINE else 'releases') / sha
    if release != expected or expected.resolve(strict=True) != expected:
        raise ValueError('invalid_release_path')
    if (ROOT / 'switch/current').resolve(strict=True) != release:
        raise ValueError('switch_changed')
    fd = os.open(release / 'RELEASE_SHA', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 64:
            raise ValueError('invalid_release_marker')
        if stream.read(65).decode().strip() != sha:
            raise ValueError('release_marker_mismatch')
    entry = release / ENTRIES[sys.argv[1]]
    if not entry.is_file() or not entry.resolve(strict=True).is_relative_to(release):
        raise ValueError('invalid_entry')
    env = dict(os.environ)
    env['AIHOT_RELEASE'] = sha
    os.execve(str(NODE), [str(NODE), '--experimental-strip-types', ENTRIES[sys.argv[1]]], env)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, UnicodeError, KeyError):
        sys.exit('Rebuilt launch refused; inspect approved layout and metadata locally')
