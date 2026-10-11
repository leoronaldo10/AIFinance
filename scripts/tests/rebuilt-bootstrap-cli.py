#!/usr/bin/env python3
"""Run only inside the disposable, network-disabled Python container in Check.

Uses actual root UID, fixed production-shaped paths, filesystem trust checks,
subprocess CLI, atomic writes and locks. Only host commands are fixture programs.
Never bind host /opt, /etc, /var or /run into this container.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

assert os.getuid() == 0 and Path('/.dockerenv').exists(), 'disposable root container required'
REPO = Path('/repo')
SHA = 'd57ba047369e666025347719caee1a4c642abe62'
ROOT = Path('/opt/aifinance')
TOOLS = ROOT / 'bootstrap-v1'
OLD = ROOT / 'staging' / SHA
STATE = Path('/var/lib/aifinance-bootstrap')
TX = STATE / 'rebuilt-v1'
SWITCH = ROOT / 'switch'
original = '--original' in sys.argv


def put(path, text, mode=0o644):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(mode)


assert not ROOT.exists() and not STATE.exists()
TOOLS.mkdir(parents=True)
OLD.mkdir(parents=True)
with Path('/etc/passwd').open('a') as stream:
    stream.write('aifinance-deploy:x:1001:1001:Fixture:/nonexistent:/usr/sbin/nologin\n')
for name in ('rebuilt-bootstrap.py', 'rebuilt-gateway.py', 'rebuilt-baseline.sha256'):
    source = Path('/old-bootstrap.py') if original and name == 'rebuilt-bootstrap.py' else REPO / 'deploy/native' / name
    shutil.copyfile(source, TOOLS / name)
    (TOOLS / name).chmod(0o644)
for line in (TOOLS / 'rebuilt-baseline.sha256').read_text().splitlines():
    expected, name = line.split('  ', 1)
    source = REPO / name
    if name == 'package.json': source = REPO / 'scripts/tests/fixtures/rebuilt-baseline-package.json'
    data = source.read_bytes()
    assert hashlib.sha256(data).hexdigest() == expected, name
    target = OLD / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
put(OLD / 'RELEASE_SHA', SHA + '\n')
put(OLD / 'schema.sha256', ''.join(hashlib.sha256(p.read_bytes()).hexdigest() +
    '  database/migrations/' + p.name + '\n' for p in sorted((OLD / 'database/migrations').glob('*.sql'))))
put(OLD / 'apps/web/build/server/index.js', '// fixture build\n')
(OLD / 'node_modules').mkdir()
put(OLD / '.env', 'SECRET=CLI-SECRET-SENTINEL\n', 0o600)
put('/usr/local/bin/node', '#!/bin/sh\n[ "$1" = --version ] || exit 99\necho v24.21.0\n', 0o755)
for role, entry in [('api', 'apps/api/src/main.ts'), ('web', 'apps/web/server.ts')]:
    put(f'/etc/systemd/system/aifinance-{role}.service',
        f'[Service]\nUser=aifinance-deploy\nWorkingDirectory={OLD}\n'
        f'ExecStart=/usr/local/bin/node --experimental-strip-types {entry}\nEnvironmentFile={OLD}/.env\n')
put('/usr/bin/systemctl', '''#!/usr/local/bin/python3
import sys,json
from pathlib import Path
a=sys.argv[1:]
with open('/tmp/host-calls.jsonl','a') as f: f.write(json.dumps(a)+'\\n')
if a[0]=='show':
 unit=a[1]; assert unit in ('aifinance-api.service','aifinance-web.service')
 if '--property=Job' in a: print(''); sys.exit(0)
 path=Path('/etc/systemd/system')/unit
 fields=dict(line.split('=',1) for line in path.read_text().splitlines() if '=' in line)
 d=Path(str(path)+'.d/90-rebuilt-bootstrap.conf')
 if d.exists(): fields['WorkingDirectory']='/opt/aifinance/switch/current'
 fields['EnvironmentFiles']=fields.pop('EnvironmentFile')+' (ignore_errors=no)'
 fields['FragmentPath']=str(path); fields['DropInPaths']=str(d) if d.exists() else ''
 fields['ExecStart']='{ path=/usr/local/bin/node ; argv[]='+fields['ExecStart']+' ; ignore_errors=no ; pid=1 ; status=0/0 }'
 print('\\n'.join(k+'='+v for k,v in fields.items()))
elif a[0]=='daemon-reload': assert len(a)==1
elif a[0] in ('restart','is-active'):
 assert a[-2:]==['aifinance-api.service','aifinance-web.service']
else: raise AssertionError(a)
''', 0o755)
put('/usr/bin/ss', '#!/bin/sh\nfor p in 3000 3001 55432; do echo "LISTEN 0 10 127.0.0.1:$p 0.0.0.0:*"; done\n', 0o755)
put('/usr/bin/curl', '#!/bin/sh\nprintf \'{"ok":true,"db":"ok","release":"dev"}\\n\'\n', 0o755)
Path('/run/lock').mkdir(parents=True, exist_ok=True)
os.chown(OLD, 1001, 1001)


def cli(action, success=True, error=None):
    r = subprocess.run([sys.executable, '-I', '-B', str(TOOLS / 'rebuilt-bootstrap.py'), action],
                       cwd='/', capture_output=True, text=True, timeout=30)
    assert (r.returncode == 0) == success, (action, r.returncode, r.stdout, r.stderr)
    assert 'CLI-SECRET-SENTINEL' not in r.stdout + r.stderr
    if error: assert json.loads(r.stderr)['error'] == error, r.stderr
    return json.loads(r.stdout) if r.stdout else None


if original:
    r = subprocess.run([sys.executable, '-I', '-B', str(TOOLS / 'rebuilt-bootstrap.py'), 'status'],
                       capture_output=True, text=True)
    assert r.returncode != 0 and 'invalid_state_or_file' in r.stderr
    print('Original CLI: absent status reports generic error (reproduced)', flush=True)
else:
    assert cli('status') == {'phase': 'not_initialized', 'receipt_exists': False}
    assert not STATE.exists(), 'status must not fabricate a receipt/directory'
    cli('rollback', False, 'receipt_not_initialized')
assert cli('check')['phase'] == 'prepared'
assert not STATE.exists(), 'check must not initialize state'
# Match the reported administrator-created STATE, but keep TX/state absent.
STATE.mkdir(mode=0o700)
assert cli('apply')['phase'] == 'same_version_ready'
assert (TX / 'state.json').is_file()
assert cli('status')['phase'] == 'same_version_ready'
assert TX.stat().st_uid == 0 and TX.stat().st_mode & 0o777 == 0o700
assert (TX / 'state.json').stat().st_mode & 0o777 == 0o600
if not original: cli('apply', False, 'receipt_exists_use_status_or_rollback')
assert cli('rollback')['phase'] == 'rolled_back'
assert not SWITCH.exists()
assert (OLD / '.env').read_text() == 'SECRET=CLI-SECRET-SENTINEL\n'
print('CLI: first check/apply/status/rollback with real root-owned files PASS', flush=True)

if not original:
    # Interrupted initialization is not the same as absence; do not auto-repair.
    receipt = (TX / 'state.json').read_bytes()
    (TX / 'state.json').unlink()
    for action in ('status', 'apply', 'rollback'):
        cli(action, False, 'receipt_missing_in_existing_transaction')
    put(TX / 'state.json', '{broken', 0o600)
    cli('status', False, 'receipt_invalid_json')
    put(TX / 'state.json', '[]', 0o600)
    cli('status', False, 'invalid_receipt_shape')
    (TX / 'state.json').write_bytes(receipt)
    os.chown(TX / 'state.json', 1001, 1001)
    cli('status', False, 'untrusted_path')
    os.chown(TX / 'state.json', 0, 0)
    # A valid helper hash does not establish trusted ownership/ancestor modes.
    os.chown('/usr/local/bin/node', 1001, 1001)
    cli('check', False, 'untrusted_path')
    os.chown('/usr/local/bin/node', 0, 0)
    ROOT.chmod(0o775)
    cli('check', False, 'bootstrap_dependency_untrusted')
    ROOT.chmod(0o755)
    put('/etc/aifinance-rebuilt.json', '[]', 0o600)
    cli('check', False, 'policy_invalid_shape')
    Path('/etc/aifinance-rebuilt.json').unlink()
    os.chown(OLD, 0, 0)
    (OLD / 'RELEASE_SHA').unlink()
    os.chown(OLD, 1001, 1001)
    cli('check', False, 'filesystem_error')
    print('CLI: absent/incomplete/corrupt/untrusted state and parent diagnostics PASS', flush=True)
