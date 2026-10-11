#!/usr/bin/env python3
"""Send only explicit public source fixtures into an ephemeral root container."""
import io
from pathlib import Path
import subprocess
import tarfile
import tempfile

repo = Path(__file__).resolve().parents[2]
names = [line.split('  ', 1)[1] for line in
         (repo / 'deploy/native/rebuilt-baseline.sha256').read_text().splitlines()]
names += ['deploy/native/rebuilt-bootstrap.py', 'deploy/native/rebuilt-gateway.py',
          'deploy/native/rebuilt-baseline.sha256', 'scripts/tests/rebuilt-bootstrap-cli.py',
          'scripts/tests/fixtures/rebuilt-baseline-package.json']
with tempfile.TemporaryFile() as archive:
    with tarfile.open(fileobj=archive, mode='w') as output:
        for name in names:
            source = repo / name
            assert source.is_file() and source.resolve().is_relative_to(repo)
            data = source.read_bytes()
            info = tarfile.TarInfo('repo/' + name)
            info.size, info.mode, info.uid, info.gid = len(data), 0o644, 0, 0
            output.addfile(info, io.BytesIO(data))
    archive.seek(0)
    subprocess.run(['docker', 'run', '--rm', '-i', '--network', 'none',
                    '--cap-drop', 'ALL', '--cap-add', 'CHOWN', '--security-opt', 'no-new-privileges',
                    'python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1',
                    'sh', '-c', 'tar --no-same-owner -xf - -C / && python -B /repo/scripts/tests/rebuilt-bootstrap-cli.py'],
                   stdin=archive, check=True, timeout=180)
