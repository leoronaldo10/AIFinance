"""Download the pinned exporter, verify bytes, install and start it exactly once.

Requires an existing administrator host session and the already confirmed dedicated
instance role. Usage: python3 -I install-release.py <confirmed-oss-region>
No credentials, arbitrary commands, URLs, object keys or SQL arguments are accepted.
Do not run a local-only release until its pinned commits have actually been published.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import urllib.request

CODE_COMMIT = '7184256b66bd729f8e2cf52e1b76a14ed634c53b'
FILES = {'export_results.py': 'e9381aad94dc4d4dec98b7eaf17bd4df1b181035c353dabab3dfe7ca8b15ba63', 'result_common.py': '2a8ed20728602a277a9c60e783d56100f729500f9df100d350b412428d98e473', 'cloud_io.py': '52e11422dd6899d4e2645ad7078a53daa09643d8688027e9602442c82c9224ee', 'retry002.sql': '181b1266f2d801e2c25eda3929375c5a5e91ccdc5efcec9d58071630648cdf8e', 'runtime-hashes.json': '6dad1839be748478d5c164b154cfb5c1a6f6b0d941183afbd61162f5fff7a36a', 'install_export.py': '12e86bfcc93f3a58c4a9f7330dc1e8a5e7dc3f532e86155d048eb7aeff59b168', 'aifinance-export-retry002.service': '849e010018bde0881bda4b18798e03ff40daf62814e4cd2659e03ca50acee4df'}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise RuntimeError('redirect_refused')


def main():
    if len(sys.argv) != 2 or not re.fullmatch('[a-z]{2}-[a-z0-9-]{2,32}', sys.argv[1]):
        raise RuntimeError('confirmed_region_required')
    prefix = [] if os.geteuid() == 0 else ['/usr/bin/sudo']
    opener = urllib.request.build_opener(NoRedirect())
    with tempfile.TemporaryDirectory(prefix='aifinance-results-install-') as td:
        root = Path(td)
        for name, digest in FILES.items():
            url = ('https://raw.githubusercontent.com/leoronaldo10/AIFinance/' + CODE_COMMIT +
                   '/scripts/readonly-results/' + name)
            with opener.open(url, timeout=15) as response:
                if response.status != 200: raise RuntimeError('download_failed')
                data = response.read(65537)
            if len(data) > 65536 or hashlib.sha256(data).hexdigest() != digest:
                raise RuntimeError('download_hash_mismatch')
            (root / name).write_bytes(data)
        subprocess.run(prefix + ['/usr/bin/python3', '-I', str(root / 'install_export.py'), sys.argv[1]],
                       check=True, timeout=60)
        since = '@' + str(int(time.time()))
        subprocess.run(prefix + ['/usr/bin/systemctl', 'start', 'aifinance-export-retry002.service'],
                       check=True, timeout=75)
        logs = subprocess.run(prefix + ['/usr/bin/journalctl', '--unit=aifinance-export-retry002.service',
                              '--since=' + since, '--output=cat', '--no-pager', '--lines=30'],
                              capture_output=True, check=True, timeout=15)
        receipts = []
        for line in logs.stdout.splitlines():
            try: row = json.loads(line)
            except (ValueError, UnicodeError): continue
            if (isinstance(row, dict) and set(row) == {'status','articles','sha256'} and
                    row['status'] == 'uploaded_private_retry002' and row['articles'] == 3 and
                    isinstance(row['sha256'], str) and re.fullmatch('[a-f0-9]{64}', row['sha256'])):
                receipts.append(row)
        if len(receipts) != 1: raise RuntimeError('receipt_unavailable')
        print(json.dumps(receipts[0]))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('EXPORT_HANDOFF_FAILED: no automatic retry; check the fixed service and installation state.')
        sys.exit(1)
