#!/usr/bin/python3
"""One fixed nft 1.0.4 empty-table recovery. Default is check-only; Python 3.6+.

No downloads, application execution, unit edits, database operations, or starts.
Apply requires specific approval and an exclusive administrator maintenance window.
/run backups are deliberately retained but do not survive reboot.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess

GUARD = Path('/opt/aifinance/bin/egress-guard.py')
RUNNER = Path('/root/aifinance-egress-acceptance.sh')
INPUT = Path('/root/aifinance-egress-repair-inputs')
BACKUP = Path('/run/aifinance-egress-repair-backup')
RECEIPT = Path('/run/aifinance-preview-egress/receipt.json')
EVIDENCE = Path('/run/aifinance-egress-acceptance')
GUARD_NEXT = GUARD.with_name('.egress-guard.py.nft104-next')
RUNNER_NEXT = RUNNER.with_name('.aifinance-egress-acceptance.sh.nft104-next')
UNIT = 'aifinance-preview-egress.service'
TABLE = 'aifinance_preview_egress_v1'
UID = 989
HANDLE = 42
OLD_GUARD = 'f46d15ad0d52c5d7c75a5599750ea2535a036c195c4169faff0f6c64162e538a'
NEW_GUARD = '5c407c3916e1f44441f0a3962ea802d148084c281426ec0f809e9ad542913367'
OLD_RUNNER = 'd3e99be10c4ce2e105196828585066d533945265b15b4ad7d7f6424599eda0f8'
NEW_RUNNER = '65f7cbeb13ec4f9da72996351f04e7a4b0ad7d1337d9bebc4a26db9ab17c1d08'
PROBES = tuple('aifinance-isolation-' + name + '.service' for name in
               ('listener', 'before', 'after', 'api-budget', 'web-budget', 'control'))
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/', 'LANG': 'C', 'LC_ALL': 'C'}


def trusted(path, directory=False, private=False):
    path = Path(path)
    for current in (path,) + tuple(path.parents):
        info = current.lstat()
        correct = stat.S_ISDIR(info.st_mode) if current != path or directory else stat.S_ISREG(info.st_mode)
        if not correct or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('untrusted_root_path')
        if current == path and private and info.st_mode & 0o777 != (0o700 if directory else 0o600):
            raise ValueError('private_root_path_required')
    return path


def absent(path):
    if path.exists() or path.is_symlink():
        raise ValueError('backup_or_staging_path_already_exists')


def data(path, digest=None):
    trusted(path)
    if path.stat().st_size > 65536:
        raise ValueError('oversize_input')
    raw = path.read_bytes()
    if digest and hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('fixed_file_hash_mismatch')
    return raw


def call(arguments):
    trusted(Path(arguments[0]).resolve())
    result = subprocess.run(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, universal_newlines=True,
                            env=ENV, cwd='/', timeout=10, shell=False)
    if result.returncode or len(result.stdout) > 65536:
        raise ValueError('fixed_command_failed')
    return result.stdout


def state(unit):
    output = call(['/usr/bin/systemctl', 'show', unit, '-p', 'LoadState', '-p', 'ActiveState', '-p', 'MainPID'])
    result = {}
    for line in output.splitlines():
        key, separator, value = line.partition('=')
        if not separator or key in result:
            raise ValueError('invalid_unit_state')
        result[key] = value
    return result


def idle_conditions():
    account = pwd.getpwnam('aifinance')
    if account.pw_uid != UID or [p.pw_name for p in pwd.getpwall() if p.pw_uid == UID] != ['aifinance']:
        raise ValueError('fixed_exclusive_app_uid_mismatch')
    for path in Path('/proc').iterdir():
        if not path.name.isdigit():
            continue
        try:
            text = (path / 'status').read_text()
        except FileNotFoundError:
            continue
        values = [line.split()[1:] for line in text.splitlines() if line.startswith('Uid:')]
        if len(values) != 1 or len(values[0]) != 4:
            raise ValueError('process_uid_unreadable')
        if UID in [int(value) for value in values[0]]:
            raise ValueError('app_uid_process_exists')
    for role in ('api', 'web'):
        value = state('aifinance-preview-' + role + '.service')
        if value != {'LoadState': 'loaded', 'ActiveState': 'inactive', 'MainPID': '0'}:
            raise ValueError('app_unit_not_inactive')
    if state(UNIT) != {'LoadState': 'loaded', 'ActiveState': 'failed', 'MainPID': '0'}:
        raise ValueError('guard_not_exact_failed_idle_state')
    for unit in PROBES:
        if state(unit).get('LoadState') != 'not-found':
            raise ValueError('probe_unit_still_exists')
    if call(['/usr/sbin/ss', '-H', '-lntp', 'sport = :48173']).strip():
        raise ValueError('probe_listener_still_exists')
    addresses = call(['/usr/sbin/ip', '-o', 'address', 'show'])
    if '192.0.2.254/' in addresses or '2001:db8:ffff::254/' in addresses:
        raise ValueError('probe_address_still_exists')


def empty_table():
    value = json.loads(call(['/usr/sbin/nft', '--json', '--handle', 'list', 'table', 'inet', TABLE]))
    objects = value['nftables']
    if not isinstance(objects, list):
        raise ValueError('invalid_nft_result')
    objects = [item for item in objects if not (isinstance(item, dict) and set(item) == {'metainfo'})]
    if objects != [{'table': {'family': 'inet', 'name': TABLE, 'handle': HANDLE}}]:
        raise ValueError('table_is_not_exact_empty_handle_42')


def evidence():
    trusted(RECEIPT, private=True)
    receipt = json.loads(data(RECEIPT).decode('utf-8'))
    if not isinstance(receipt, dict) or set(receipt) != {'uid', 'token'} or type(receipt['uid']) is not int or receipt['uid'] != UID or not isinstance(receipt['token'], str) or not re.fullmatch('[0-9a-f]{32}', receipt['token']):
        raise ValueError('receipt_shape_or_uid_mismatch')
    trusted(EVIDENCE, directory=True, private=True)
    for path in EVIDENCE.iterdir():
        trusted(path, private=True)
    result = data(EVIDENCE / 'result.txt').decode('ascii')
    if result != 'probe_passed=false\napplication_accepted=false\ncleanup_failed=0\n':
        raise ValueError('expected_failed_probe_with_successful_cleanup')
    # Rename only, never a cross-device copy-and-delete fallback.
    if len({RECEIPT.stat().st_dev, EVIDENCE.stat().st_dev, BACKUP.parent.stat().st_dev}) != 1:
        raise ValueError('evidence_backup_would_cross_filesystems')


def check():
    for path in (BACKUP, GUARD_NEXT, RUNNER_NEXT):
        absent(path)
    trusted(INPUT, directory=True, private=True)
    trusted(BACKUP.parent, directory=True)
    content = (data(GUARD, OLD_GUARD), data(RUNNER, OLD_RUNNER),
               data(INPUT / 'egress-guard.py', NEW_GUARD),
               data(INPUT / 'aifinance-egress-acceptance.sh', NEW_RUNNER))
    ast.parse(content[2].decode('utf-8'))
    call(['/usr/bin/bash', '--noprofile', '--norc', '-n', str(INPUT / 'aifinance-egress-acceptance.sh')])
    idle_conditions()
    empty_table()
    evidence()
    return content


def new_file(path, raw, mode=0o600):
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    os.chmod(str(path), mode)


def apply(content):
    # Nothing is automatically rolled back or removed if a later step fails.
    BACKUP.mkdir(mode=0o700)
    new_file(BACKUP / 'egress-guard.py.before', content[0])
    new_file(BACKUP / 'aifinance-egress-acceptance.sh.before', content[1])
    new_file(GUARD_NEXT, content[2], 0o644)
    new_file(RUNNER_NEXT, content[3], 0o600)
    # Revalidate the narrow destructive action immediately before deletion.
    idle_conditions()
    data(GUARD, OLD_GUARD)
    data(RUNNER, OLD_RUNNER)
    evidence()
    empty_table()
    new_file(BACKUP / 'recovery.json', json.dumps({'uid': UID, 'table': TABLE, 'approved_empty_handle': HANDLE,
             'old_guard_sha256': OLD_GUARD, 'new_guard_sha256': NEW_GUARD,
             'old_runner_sha256': OLD_RUNNER, 'new_runner_sha256': NEW_RUNNER,
             'application_started': False, 'backup_survives_reboot': False}, sort_keys=True).encode('ascii'))
    call(['/usr/sbin/nft', 'delete', 'table', 'inet', 'handle', str(HANDLE)])
    tables = json.loads(call(['/usr/sbin/nft', '--json', 'list', 'tables']))['nftables']
    for item in tables:
        if 'metainfo' in item:
            continue
        value = item['table']
        if value['family'] == 'inet' and value['name'] == TABLE:
            raise ValueError('guard_table_still_present_after_delete')
    os.rename(str(RECEIPT), str(BACKUP / 'receipt.before.json'))
    os.rename(str(EVIDENCE), str(BACKUP / 'acceptance.before'))
    # Individually atomic file replacements; a partial pair requires manual review.
    os.replace(str(GUARD_NEXT), str(GUARD))
    os.replace(str(RUNNER_NEXT), str(RUNNER))
    data(GUARD, NEW_GUARD)
    data(RUNNER, NEW_RUNNER)
    if state(UNIT) != {'LoadState': 'loaded', 'ActiveState': 'failed', 'MainPID': '0'}:
        raise ValueError('guard_state_changed_before_exact_reset')
    call(['/usr/bin/systemctl', 'reset-failed', UNIT])
    if state(UNIT) != {'LoadState': 'loaded', 'ActiveState': 'inactive', 'MainPID': '0'}:
        raise ValueError('guard_not_inactive_after_exact_reset')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    try:
        if os.getuid() != 0 or os.geteuid() != 0:
            raise ValueError('root_required')
        os.umask(0o077)
        content = check()
        if args.apply:
            apply(content)
        print(json.dumps({'check_passed': True, 'repair_applied': args.apply,
                          'application_started': False, 'run_acceptance_separately': args.apply,
                          'backup': str(BACKUP) if args.apply else None}))
        return 0
    except (ValueError, KeyError, OSError, TypeError, SyntaxError, subprocess.TimeoutExpired) as error:
        print(json.dumps({'repair_failed': True, 'reason': str(error) if isinstance(error, ValueError)
                          else type(error).__name__, 'application_started': False,
                          'automatic_cleanup': False}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
