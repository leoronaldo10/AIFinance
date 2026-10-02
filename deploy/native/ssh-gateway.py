#!/usr/bin/python3
"""Root-owned forced-command entry. No shell evaluation or arbitrary remote paths."""
import hashlib
import os
import re
import signal
import sys
import tempfile
from pathlib import Path

ROOT = Path('/opt/aifinance')
LIMIT = 128 * 1024 * 1024
HEX40 = r'[0-9a-f]{40}'
HEX64 = r'[0-9a-f]{64}'


def parse(command):
    if command in ('verify', 'inspect'):
        return [command]
    if re.fullmatch(r'(upload|deploy) ' + HEX40 + ' ' + HEX64, command):
        return command.split(' ')
    if re.fullmatch(r'rollback ' + HEX40, command):
        return command.split(' ')
    raise ValueError('Command denied; only verify/inspect/upload/deploy/rollback are supported')


def upload(root, sha, digest, stream):
    incoming = root / 'incoming'
    target = incoming / (sha + '.tar.gz')
    if target.exists() or target.is_symlink():
        raise ValueError('Archive already exists; no overwrite allowed')
    fd, temporary = tempfile.mkstemp(prefix='.upload-', dir=incoming)
    try:
        total = 0
        h = hashlib.sha256()
        with os.fdopen(fd, 'wb') as out:
            while True:
                chunk = stream.read(min(1024 * 1024, LIMIT - total + 1))
                if not chunk:
                    break
                total += len(chunk)
                if total > LIMIT:
                    raise ValueError('Archive exceeds upload limit')
                h.update(chunk)
                out.write(chunk)
            out.flush()
            os.fsync(out.fileno())
        if not total or h.hexdigest() != digest:
            raise ValueError('Archive checksum mismatch')
        # Atomic, fails if a concurrent session already published this name.
        os.link(temporary, target)
    finally:
        os.unlink(temporary)


def main():
    command = os.environ.get('SSH_ORIGINAL_COMMAND', '')
    os.environ.clear()
    os.environ.update(PATH='/usr/bin:/bin', HOME='/var/lib/aifinance-deploy', LANG='C.UTF-8')
    os.umask(0o077)
    args = parse(command)
    if args[0] == 'verify':
        print('AIFINANCE_ACCESS_OK: restricted account; no deployment performed')
        return
    if args[0] == 'inspect':
        os.execve('/usr/bin/python3', ['/usr/bin/python3', '-I', str(ROOT / 'bin/inspect-native.py')], dict(os.environ))
        return
    # First release must be uploaded before runtime acceptance. This bounded,
    # no-overwrite data-only action never executes the uploaded contents.
    if args[0] == 'upload':
        def expired(*_):
            raise ValueError('Upload timed out')
        signal.signal(signal.SIGALRM, expired)
        signal.alarm(300)
        upload(ROOT, args[1], args[2], sys.stdin.buffer)
        signal.alarm(0)
        print('UPLOAD_OK')
    else:
        if not (ROOT / 'shared/native-ready').is_file():
            raise ValueError('Native runtime not approved for deployment')
        os.execve('/usr/bin/bash', ['/usr/bin/bash', str(ROOT / 'bin/release.sh'), *args], dict(os.environ))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError):
        # Never echo original commands, paths supplied by a caller, or credential material.
        print('ACCESS_DENIED_OR_OPERATION_FAILED', file=sys.stderr)
        sys.exit(1)
