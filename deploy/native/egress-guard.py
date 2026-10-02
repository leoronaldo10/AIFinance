#!/usr/bin/python3
"""Approved-root-only preview UID guard. Python 3.6+; never runs application code.

No installer, firewall reload, global flush, arbitrary arguments, or live watcher.
A failed apply/verification deliberately retains this invocation's receipt/rules
for reviewed cleanup; it never removes an unknown or modified table.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess

SELF = Path('/opt/aifinance/bin/egress-guard.py')
RUNTIME = Path('/run/aifinance-preview-egress')
RECEIPT = RUNTIME / 'receipt.json'
LOCK = RUNTIME / 'lock'
NFT = '/usr/sbin/nft'
TABLE = 'aifinance_preview_egress_v1'
CHAIN = 'app_output'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/', 'LANG': 'C', 'LC_ALL': 'C'}


def trusted(path, directory=False):
    path = Path(path)
    if not path.is_absolute():
        raise ValueError('absolute_trusted_path_required')
    for current in (path,) + tuple(path.parents):
        info = current.lstat()
        correct_type = stat.S_ISDIR(info.st_mode) if current != path or directory else stat.S_ISREG(info.st_mode)
        if not correct_type or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('root_owned_nonwritable_path_required')
    return path


def app_uid():
    account = pwd.getpwnam('aifinance')
    uid = account.pw_uid
    if uid <= 0 or uid >= 4294967295:
        raise ValueError('nonroot_app_uid_required')
    if [entry.pw_name for entry in pwd.getpwall() if entry.pw_uid == uid] != ['aifinance']:
        raise ValueError('exclusive_app_uid_required')
    return uid


def no_app_processes(uid):
    # Reject all real/effective/saved/fs UID matches, including unrelated jobs.
    # Root must serialize starts with maintenance; /proc scans are not a launch lock.
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            text = (entry / 'status').read_text()
        except FileNotFoundError:
            continue
        lines = [line.split()[1:] for line in text.splitlines() if line.startswith('Uid:')]
        if len(lines) != 1 or len(lines[0]) != 4:
            raise ValueError('cannot_verify_process_uids')
        if uid in [int(value) for value in lines[0]]:
            raise ValueError('app_uid_processes_exist_keep_guard')


def nft(arguments, payload=None):
    trusted(Path(NFT).resolve())
    result = subprocess.run([NFT] + arguments, input=payload, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, universal_newlines=True,
                            env=ENV, cwd='/', timeout=10, shell=False)
    if result.returncode != 0 or len(result.stdout) > 131072:
        raise ValueError('nft_command_failed')
    return result.stdout


def table_exists():
    document = json.loads(nft(['--json', 'list', 'tables']))
    if not isinstance(document, dict) or not isinstance(document.get('nftables'), list):
        raise ValueError('invalid_nft_table_list')
    for entry in document['nftables']:
        if not isinstance(entry, dict) or len(entry) != 1:
            raise ValueError('invalid_nft_table_list')
        if 'metainfo' in entry:
            continue
        value = entry.get('table')
        if not isinstance(value, dict) or not isinstance(value.get('family'), str) or not isinstance(value.get('name'), str):
            raise ValueError('invalid_nft_table_list')
        if value['family'] == 'inet' and value['name'] == TABLE:
            return True
    return False


def rules(uid, token):
    # The only interpolation is validated numeric UID and random hex owned by root.
    if type(uid) is not int or uid <= 0 or uid >= 4294967295 or not re.fullmatch('[0-9a-f]{32}', token):
        raise ValueError('invalid_guard_identity')
    # nft 1.0.4 expands nested table contents only for CMD_ADD, not CMD_CREATE.
    # Keep exclusive creation, but spell every object out in the same transaction.
    return '''create table inet %s
add chain inet %s %s { type filter hook output priority -10; policy accept; }
add rule inet %s %s meta skuid %d ip daddr 127.0.0.0/8 counter accept comment "%s:loopback-v4"
add rule inet %s %s meta skuid %d ip6 daddr ::1 counter accept comment "%s:loopback-v6"
add rule inet %s %s meta skuid %d meta nfproto ipv4 counter reject with icmp type admin-prohibited comment "%s:deny-v4"
add rule inet %s %s meta skuid %d meta nfproto ipv6 counter reject with icmpv6 type admin-prohibited comment "%s:deny-v6"
''' % (TABLE, TABLE, CHAIN, TABLE, CHAIN, uid, token, TABLE, CHAIN, uid, token,
       TABLE, CHAIN, uid, token, TABLE, CHAIN, uid, token)


def expected_objects(uid, token):
    def match(left, right):
        return {'match': {'op': '==', 'left': left, 'right': right}}
    base = {'family': 'inet', 'table': TABLE, 'chain': CHAIN}
    identity = match({'meta': {'key': 'skuid'}}, uid)
    output = [{'table': {'family': 'inet', 'name': TABLE}},
              {'chain': {'family': 'inet', 'table': TABLE, 'name': CHAIN,
                         'type': 'filter', 'hook': 'output', 'prio': -10, 'policy': 'accept'}}]
    for version, protocol, address in ((4, 'ip', {'prefix': {'addr': '127.0.0.0', 'len': 8}}),
                                        (6, 'ip6', '::1')):
        value = dict(base)
        value.update({'comment': token + ':loopback-v' + str(version),
                      'expr': [identity, match({'payload': {'protocol': protocol, 'field': 'daddr'}}, address),
                               {'counter': None}, {'accept': None}]})
        output.append({'rule': value})
    for version, protocol in ((4, 'icmp'), (6, 'icmpv6')):
        value = dict(base)
        value.update({'comment': token + ':deny-v' + str(version),
                      'expr': [identity, match({'meta': {'key': 'nfproto'}}, 'ipv' + str(version)),
                               {'counter': None}, {'reject': {'type': protocol, 'expr': 'admin-prohibited'}}]})
        output.append({'rule': value})
    return output


def inspect_table(uid, token):
    # Compare semantics and order, not just table name/comments or service state.
    document = json.loads(nft(['--json', '--handle', 'list', 'table', 'inet', TABLE]))
    if not isinstance(document, dict) or not isinstance(document.get('nftables'), list):
        raise ValueError('invalid_nft_table')
    objects, counters, handle = [], {}, None
    for item in document['nftables']:
        if not isinstance(item, dict) or len(item) != 1:
            raise ValueError('unexpected_nft_object')
        kind = next(iter(item))
        if kind == 'metainfo':
            continue
        if kind not in ('table', 'chain', 'rule') or not isinstance(item[kind], dict):
            raise ValueError('unexpected_nft_object')
        value = dict(item[kind])
        object_handle = value.pop('handle', None)
        if type(object_handle) is not int or object_handle <= 0:
            raise ValueError('nft_handle_required')
        if kind == 'table':
            handle = object_handle
        if kind == 'rule':
            expressions = []
            for expression in value.get('expr', []):
                if isinstance(expression, dict) and set(expression) == {'counter'}:
                    counter = expression['counter']
                    if not isinstance(counter, dict) or set(counter) != {'packets', 'bytes'} or any(
                            type(number) is not int or number < 0 for number in counter.values()):
                        raise ValueError('invalid_nft_counter')
                    counters[value.get('comment')] = counter
                    expression = {'counter': None}
                expressions.append(expression)
            value['expr'] = expressions
        objects.append({kind: value})
    if objects != expected_objects(uid, token):
        raise ValueError('guard_table_missing_or_modified')
    return handle, counters


def read_receipt():
    trusted(RECEIPT)
    if RECEIPT.stat().st_mode & 0o077:
        raise ValueError('private_receipt_required')
    with RECEIPT.open('r') as source:
        text = source.read(4097)
    if len(text) > 4096:
        raise ValueError('invalid_receipt')
    value = json.loads(text)
    if not isinstance(value, dict) or set(value) != {'uid', 'token'}:
        raise ValueError('invalid_receipt')
    rules(value['uid'], value['token'])
    return value


def start(uid):
    no_app_processes(uid)
    if table_exists() or RECEIPT.exists():
        raise ValueError('existing_guard_or_receipt_requires_reviewed_cleanup')
    token = os.urandom(16).hex()
    payload = rules(uid, token)
    nft(['--check', '--file', '-'], payload)
    # Persist ownership before the transaction, so interrupted loading is recoverable.
    descriptor = os.open(str(RECEIPT), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as target:
        json.dump({'uid': uid, 'token': token}, target)
        target.flush()
        os.fsync(target.fileno())
    nft(['--file', '-'], payload)
    return verify(uid)


def verify(uid):
    receipt = read_receipt()
    if receipt['uid'] != uid:
        raise ValueError('app_uid_changed_keep_guard')
    handle, counters = inspect_table(uid, receipt['token'])
    return {'guard_loaded': True, 'uid': uid, 'table': TABLE, 'handle': handle, 'counters': counters,
            'target_probe_accepted': False, 'continuous_monitor': False}


def stop(uid):
    no_app_processes(uid)
    if not table_exists():
        if RECEIPT.exists():
            receipt = read_receipt()
            if receipt['uid'] != uid:
                raise ValueError('app_uid_changed_keep_receipt')
            RECEIPT.unlink()
        return {'guard_removed': True, 'table': TABLE}
    receipt = read_receipt()
    if receipt['uid'] != uid:
        raise ValueError('app_uid_changed_keep_guard')
    handle, _ = inspect_table(uid, receipt['token'])
    # A handle targets this exact inspected table, never a replacement of its name.
    nft(['delete', 'table', 'inet', 'handle', str(handle)])
    if table_exists():
        raise ValueError('table_still_present_keep_receipt')
    RECEIPT.unlink()
    return {'guard_removed': True, 'table': TABLE}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('start', 'verify', 'stop'))
    args = parser.parse_args(argv)
    descriptor = None
    try:
        if os.getuid() != 0 or os.geteuid() != 0:
            raise ValueError('root_only_guard_operation')
        if Path(__file__).absolute() != SELF:
            raise ValueError('fixed_installed_helper_required')
        trusted(SELF)
        trusted(RUNTIME, directory=True)
        if RUNTIME.stat().st_mode & 0o077:
            raise ValueError('private_runtime_directory_required')
        flags = os.O_RDONLY if args.action == 'verify' else os.O_RDWR | os.O_CREAT
        descriptor = os.open(str(LOCK), flags | os.O_NOFOLLOW, 0o600)
        trusted(LOCK)
        fcntl.flock(descriptor, (fcntl.LOCK_SH if args.action == 'verify' else fcntl.LOCK_EX) | fcntl.LOCK_NB)
        result = {'start': start, 'verify': verify, 'stop': stop}[args.action](app_uid())
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, KeyError, OSError, TypeError, subprocess.TimeoutExpired) as error:
        print(json.dumps({'guard_failed': True, 'reason': str(error) if isinstance(error, ValueError)
                          else type(error).__name__, 'target_probe_accepted': False}))
        return 1
    finally:
        if descriptor is not None:
            os.close(descriptor)


if __name__ == '__main__':
    raise SystemExit(main())
