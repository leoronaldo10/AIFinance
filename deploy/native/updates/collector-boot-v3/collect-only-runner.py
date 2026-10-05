#!/usr/bin/python3
"""Reviewed root operator entry; Python 3.6/systemd 239/cgroup v1.

No production action is implied by possessing this file. Install the reviewed
helper at its fixed path first. check is read-only. No SSH/sudo grant is added.
The first seed/run require the existing application writers to be stopped.
The timer is absent until explicit admin-view acceptance after a successful run.
"""
import argparse
import fcntl
import grp
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import resource
import selectors
import signal
import stat
import subprocess
import sys
import time
from urllib.parse import urlsplit

ROOT = Path('/opt/aifinance')
SELF = ROOT / 'bin/collect-only-runner.py'
RELEASE_SHA = 'd57ba047369e666025347719caee1a4c642abe62'
RELEASE = ROOT / 'releases' / RELEASE_SHA
MAINTENANCE = Path('/var/lib/aifinance-maintenance')
STATE = MAINTENANCE / 'collect-only'
CONFIG = Path('/etc/aifinance-collect')
SYSTEM = Path('/etc/systemd/system')
NODE = ROOT / 'runtime/node/bin/node'
ACCOUNT = 'aifinance-collect'
PREFIX = 'aifinance-collect-'
TABLE = 'aifinance_collect_egress_v1'
NFT = '/usr/sbin/nft'
CTL = '/usr/bin/systemctl'
ENV = dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin', HOME='/', LANG='C', LC_ALL='C')
LIMIT = 256 * 1024 ** 2
FEEDS = {
    'collect-dynamics-finance': 'https://www.microsoft.com/en-us/dynamics-365/blog/product/dynamics-365-finance/feed/',
    'collect-journal-accountancy': 'https://www.journalofaccountancy.com/news/feed/',
    'collect-accounting-today': 'https://www.accountingtoday.com/feed?rss=true',
}
PINS = {
    'scripts/collect-only.ts': '6efcefbba537b8f11365fc7bec6de8164343b9f133402facb819b90ecfe4ee9b',
    'scripts/collect-only-check.ts': 'e19769f869da8236de24849a69c33d161c7cfe3b4f590d03a31d4a4c3fa1a374',
    'industry/collect-sources.json': 'fd07adf77e69906fdcc7f003fd823093c6d3977da2ddab126a243f87e27bdc8a',
    'packages/backend/src/sources/collect-only.ts': '1c91090fcb9a9fc0b1dbd4ad095d767d4eef0ad9e51d2c66af2122df8abd2504',
    'packages/backend/src/sources/rss.ts': 'd930fe7f8f0c3b4b7d692e9314673c0be187996c4f44c42c416047ea25cbe9b3',
    'packages/backend/src/lib/http-fetch.ts': 'bd9fce7b669a33341ef0e95450ead07842a0549933f5939d3823868750ecba03',
}
ZERO_TABLES = ('pgboss.job', 'analyses', 'receipts', 'editorial_overrides',
               'editorial_review_state', 'editorial_versions', 'editorial_exports',
               'publications', 'deliveries', 'grouping_decisions')


def trusted(path, directory=False):
    path = Path(path)
    if not path.is_absolute():
        raise ValueError('absolute_trusted_path_required')
    for current in (path,) + tuple(path.parents):
        info = current.lstat()
        kind = stat.S_ISDIR(info.st_mode) if current != path or directory else stat.S_ISREG(info.st_mode)
        if not kind or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('root_owned_nonwritable_path_required')
    return path


def read(path, limit=131072):
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError('bounded_regular_file_required')
        # procfs seq_file reads may stop at a page even with a larger buffer.
        # Read through EOF so later namespace mounts remain part of the proof.
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, limit + 1 - len(data))
            if not chunk:
                return bytes(data).decode('utf-8', 'strict')
            data.extend(chunk)
        raise ValueError('bounded_regular_file_required')
    finally:
        os.close(fd)


def write_new(path, text, mode=0o600, gid=0):
    trusted(path.parent, directory=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'w') as out:
        os.fchmod(out.fileno(), mode)
        os.fchown(out.fileno(), 0, gid)
        out.write(text)
        out.flush()
        os.fsync(out.fileno())


def replace_owned(path, text, mode=0o600, gid=0):
    if path.exists() or path.is_symlink():
        trusted(path)
    temporary = path.with_name(path.name + '.next')
    write_new(temporary, text, mode, gid)
    os.replace(str(temporary), str(path))


def command(args, payload=None, timeout=15):
    trusted(Path(args[0]).resolve())
    result = subprocess.run(args, input=payload, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            universal_newlines=True, env=ENV, cwd='/', timeout=timeout, check=True)
    if len(result.stdout) > 262144:
        raise ValueError('command_output_limit')
    return result.stdout.strip()


def prop(unit, name):
    return command([CTL, 'show', unit, '-p', name, '--value'])


def unit_name(mode):
    if mode not in ('probe', 'check', 'seed', 'run'):
        raise ValueError('invalid_collect_mode')
    return PREFIX + mode + '.service'


def account():
    user = pwd.getpwnam(ACCOUNT)
    forbidden = {0, 989}
    for name in ('aifinance', 'aifinance-deploy', 'postgres'):
        forbidden.add(pwd.getpwnam(name).pw_uid)
    if (user.pw_uid in forbidden or user.pw_uid <= 0 or user.pw_shell != '/sbin/nologin' or
            user.pw_dir != '/nonexistent' or user.pw_gid != grp.getgrnam(ACCOUNT).gr_gid):
        raise ValueError('dedicated_no_login_collector_required')
    if [entry.pw_name for entry in pwd.getpwall() if entry.pw_uid == user.pw_uid] != [ACCOUNT]:
        raise ValueError('exclusive_collector_uid_required')
    if any(ACCOUNT in group.gr_mem or (group.gr_gid == user.pw_gid and group.gr_mem) for group in grp.getgrall()):
        raise ValueError('collector_supplementary_or_shared_group_refused')
    if any(entry.pw_name != ACCOUNT and entry.pw_gid == user.pw_gid for entry in pwd.getpwall()):
        raise ValueError('exclusive_collector_group_required')
    return user


def no_processes(uid):
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            status = (entry / 'status').read_text()
        except FileNotFoundError:
            continue
        lines = [line.split()[1:] for line in status.splitlines() if line.startswith('Uid:')]
        if len(lines) != 1 or len(lines[0]) != 4:
            raise ValueError('unreadable_process_identity')
        if str(uid) in lines[0]:
            raise ValueError('unexpected_identity_process_exists')


def database_url(text):
    lines = text.splitlines()
    if len(lines) != 1 or not lines[0].startswith('DATABASE_URL='):
        raise ValueError('database_only_configuration_required')
    value = lines[0][len('DATABASE_URL='):]
    db = urlsplit(value)
    if (value != value.strip() or db.scheme not in ('postgres', 'postgresql') or
            db.hostname != '127.0.0.1' or db.port != 55432 or db.username != 'aifinance_preview' or
            not db.password or db.path != '/aifinance_preview' or db.query or db.fragment):
        raise ValueError('unchanged_preview_database_required')
    return value


def db_environment():
    user = account()
    path = CONFIG / 'database.env'
    trusted(path)
    if (stat.S_IMODE(path.stat().st_mode) != 0o440 or path.stat().st_gid != user.pw_gid or
            stat.S_IMODE(CONFIG.stat().st_mode) != 0o750 or CONFIG.stat().st_gid != user.pw_gid):
        raise ValueError('protected_db_only_configuration_required')
    value = database_url(read(path, 8192))
    # Construct, never merge. No NODE_OPTIONS, proxy, model/admin/provider keys.
    return dict(ENV, DATABASE_URL=value, NODE_ENV='production', PREVIEW_MODE='false',
                MODEL_CALLS_ENABLED='false', COLLECT_ENABLED='false', ALLOW_PRIVATE_NETWORK_FETCH='false',
                FEISHU_INTERNAL_ENABLED='false', FEISHU_CONTENT_PUSH_ENABLED='false',
                INDEXNOW_SUBMIT_ENABLED='false', AIHOT_CREDENTIALS_DIR='', DATABASE_POOL_MAX='1')


def release_parent_chain():
    deploy_uid = pwd.getpwnam('aifinance-deploy').pw_uid
    for path in (ROOT, ROOT / 'releases', ROOT / 'state'):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, deploy_uid) or info.st_mode & 0o022:
            raise ValueError('unexpected_existing_release_parent')
    # These two parents remain owned by the restricted existing deployment
    # account; all authorized mutations serialize on the same release.lock.
    trusted(ROOT.parent, directory=True)


def release_lock():
    release_parent_chain()
    path = ROOT / 'state/release.lock'
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, pwd.getpwnam('aifinance-deploy').pw_uid)
            or info.st_mode & 0o022 or (info.st_dev, info.st_ino) != (path.lstat().st_dev, path.lstat().st_ino)):
        os.close(fd)
        raise ValueError('existing_release_lock_inode_required')
    return fd


def validate_release():
    release_parent_chain()
    info = RELEASE.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('immutable_root_owned_release_required')
    if read(RELEASE / 'RELEASE_SHA', 64).strip() != RELEASE_SHA:
        raise ValueError('fixed_release_required')
    if (ROOT / 'state/current').resolve() != RELEASE:
        raise ValueError('current_must_be_accepted_collect_release')
    # Every executable dependency must be frozen too, not just a mutable SHA label.
    for parent, dirs, files in os.walk(str(RELEASE), followlinks=False):
        for name in dirs + files:
            path = Path(parent) / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                if info.st_uid != 0:
                    raise ValueError('immutable_root_owned_release_required')
                resolved = path.resolve()
                if RELEASE not in resolved.parents:
                    raise ValueError('release_symlink_escape')
                continue
            if info.st_uid != 0 or info.st_mode & 0o022 or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise ValueError('immutable_root_owned_release_required')
    for name, digest in PINS.items():
        if hashlib.sha256(read(RELEASE / name, 1048576).encode()).hexdigest() != digest:
            raise ValueError('reviewed_collector_source_changed')
    rows = json.loads(read(RELEASE / 'industry/collect-sources.json'))['sources']
    if len(rows) != 3 or {row['id']: row['config']['feedUrl'] for row in rows} != FEEDS:
        raise ValueError('fixed_feed_set_required')
    trusted(NODE)
    trusted(ROOT / 'bin/egress-guard.py')
    command(['/usr/bin/python3', '-I', '-B', str(ROOT / 'bin/egress-guard.py'), 'verify'])


def upgrade_gate():
    gate = MAINTENANCE / 'collect-only-upgrade.json'
    trusted(gate)
    data = json.loads(read(gate))
    if data.get('status') != 'healthy' or data.get('release') != RELEASE_SHA:
        raise ValueError('accepted_upgrade_required')


def allowed_addresses(mapping):
    hosts = sorted(urlsplit(url).hostname for url in FEEDS.values())
    if not isinstance(mapping, dict) or (mapping and sorted(mapping) != hosts):
        raise ValueError('exact_feed_hosts_required')
    addresses = []
    for host, values in sorted(mapping.items()):
        if not isinstance(values, list) or not 1 <= len(values) <= 8 or values != sorted(set(values)):
            raise ValueError('bounded_unique_address_list_required')
        for value in values:
            ip = ipaddress.ip_address(value)
            if ip.version != 4 or not ip.is_global or ip.is_multicast or ip.is_reserved or str(ip) != value:
                raise ValueError('public_ipv4_only')
            addresses.append(value)
    return sorted(set(addresses))


def resolve_feeds():
    mapping = {}
    for url in FEEDS.values():
        host = urlsplit(url).hostname
        # Bound libc/NSS resolution in a trusted subprocess; getaddrinfo itself
        # has no Python timeout and must not hold the release lock indefinitely.
        output = command(['/usr/bin/getent', 'ahostsv4', host], timeout=10)
        mapping[host] = sorted(set(line.split()[0] for line in output.splitlines() if line.split()))
    allowed_addresses(mapping)
    return mapping


def network_objects(uid, mapping):
    addresses = allowed_addresses(mapping)
    if type(uid) is not int or uid <= 0 or uid >= 4294967295 or uid == 989:
        raise ValueError('dedicated_network_uid_required')
    def match(left, right):
        return {'match': {'op': '==', 'left': left, 'right': right}}
    identity = match({'meta': {'key': 'skuid'}}, uid)
    base = {'family': 'inet', 'table': TABLE, 'chain': 'output'}
    objects = [{'table': {'family': 'inet', 'name': TABLE}},
               {'chain': dict(base, name='output', type='filter', hook='output', prio=-11, policy='accept')}]
    objects[1]['chain'].pop('chain')
    for address, port in [('127.0.0.1', 55432)] + [(address, 443) for address in addresses]:
        objects.append({'rule': dict(base, expr=[identity,
            match({'payload': {'protocol': 'ip', 'field': 'daddr'}}, address),
            match({'payload': {'protocol': 'tcp', 'field': 'dport'}}, port), {'counter': None}, {'accept': None}])})
    for version, protocol in ((4, 'icmp'), (6, 'icmpv6')):
        objects.append({'rule': dict(base, expr=[identity,
            match({'meta': {'key': 'nfproto'}}, 'ipv' + str(version)), {'counter': None},
            {'reject': {'type': protocol, 'expr': 'admin-prohibited'}}])})
    return objects


def network_rules(uid, mapping):
    network_objects(uid, mapping)
    lines = ['create table inet ' + TABLE,
             'add chain inet ' + TABLE + ' output { type filter hook output priority -11; policy accept; }']
    for address, port in [('127.0.0.1', 55432)] + [(a, 443) for a in allowed_addresses(mapping)]:
        lines.append('add rule inet %s output meta skuid %d ip daddr %s tcp dport %d counter accept' % (TABLE, uid, address, port))
    for version, protocol in ((4, 'icmp'), (6, 'icmpv6')):
        lines.append('add rule inet %s output meta skuid %d meta nfproto ipv%d counter reject with %s type admin-prohibited' % (TABLE, uid, version, protocol))
    return '\n'.join(lines) + '\n'


def network_table():
    data = json.loads(command([NFT, '--json', 'list', 'tables']))
    return any(item.get('table', {}).get('family') == 'inet' and item.get('table', {}).get('name') == TABLE for item in data['nftables'])


def verify_network(user):
    path = STATE / 'network.json'
    trusted(path)
    receipt = json.loads(read(path))
    if receipt.get('uid') != user.pw_uid:
        raise ValueError('network_uid_changed')
    objects, handle = [], None
    for item in json.loads(command([NFT, '--json', '--handle', 'list', 'table', 'inet', TABLE]))['nftables']:
        if 'metainfo' in item:
            continue
        if len(item) != 1 or next(iter(item)) not in ('table', 'chain', 'rule'):
            raise ValueError('unexpected_network_object')
        kind = next(iter(item)); value = dict(item[kind]); found = value.pop('handle', None)
        if type(found) is not int or found <= 0:
            raise ValueError('network_handle_required')
        if kind == 'table':
            handle = found
        if kind == 'rule':
            value['expr'] = [{'counter': None} if set(e) == {'counter'} else e for e in value['expr']]
        objects.append({kind: value})
    if objects != network_objects(user.pw_uid, receipt['hosts']):
        raise ValueError('collector_network_modified')
    if read(CONFIG / 'hosts') != hosts_text(receipt['hosts']) or read(CONFIG / 'nsswitch.conf') != 'hosts: files\n':
        raise ValueError('collector_name_resolution_modified')
    return handle


def hosts_text(mapping):
    allowed_addresses(mapping)
    return ''.join('%s %s\n' % (address, host) for host, values in sorted(mapping.items()) for address in values)


def configure_network(user, mapping):
    no_processes(user.pw_uid)
    handle = verify_network(user) if network_table() else None
    payload = ('delete table inet handle %d\n' % handle if handle else '') + network_rules(user.pw_uid, mapping)
    command([NFT, '--check', '--file', '-'], payload)
    # Any interrupted replacement remains fail-closed to starts. Never clean up an
    # unknown/modified table, flush a ruleset, or alter the application's guard.
    replace_owned(CONFIG / 'hosts', hosts_text(mapping), 0o440, user.pw_gid)
    replace_owned(CONFIG / 'nsswitch.conf', 'hosts: files\n', 0o440, user.pw_gid)
    command([NFT, '--file', '-'], payload)
    replace_owned(STATE / 'network.json', json.dumps({'uid': user.pw_uid, 'hosts': mapping}, sort_keys=True))
    verify_network(user)


def unit_text(mode):
    unit_name(mode)
    executable = '/usr/bin/sleep 30' if mode == 'probe' else '/usr/bin/python3 -I -B %s _execute --mode %s' % (SELF, mode)
    network = 'PrivateNetwork=yes\n' if mode == 'probe' else 'BindReadOnlyPaths=%s/hosts:/etc/hosts %s/nsswitch.conf:/etc/nsswitch.conf\n' % (CONFIG, CONFIG)
    text = '''[Unit]
Description=Bounded finance collect-only %s
Requisite=aifinance-preview-db.service
After=aifinance-preview-db.service
[Service]
Type=oneshot
User=%s
Group=%s
WorkingDirectory=%s
ExecStartPre=+/usr/bin/python3 -I -B %s _verify --mode %s
ExecStart=%s
TimeoutStartSec=120
TimeoutStopSec=5
KillMode=control-group
MemoryAccounting=yes
MemoryLimit=256M
TasksMax=32
CPUQuota=50%%
LimitNOFILE=512
LimitCORE=0
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
RestrictAddressFamilies=AF_UNIX AF_INET
InaccessiblePaths=/etc/aifinance-preview.env -/run/nscd -/var/run/nscd
%sStandardOutput=file:%s/output.json
StandardError=null
''' % (mode, ACCOUNT, ACCOUNT, RELEASE, SELF, mode, executable, network, STATE)
    # The no-network sleep probe needs no root helper inside its private network namespace.
    if mode == 'probe':
        text = text.replace('ExecStartPre=+/usr/bin/python3 -I -B %s _verify --mode probe\n' % SELF, '')
    return text


def effective_exec(unit, property_name, expected):
    value = prop(unit, property_name)
    prefix = '{ path=%s ; argv[]=%s ; ignore_errors=no ;' % (expected.split()[0], expected)
    if not value.startswith(prefix) or value.count('{') != 1 or value.count('}') != 1 or not value.endswith('}'):
        raise ValueError('loaded_exec_command_mismatch')


def verify_units():
    for mode in ('probe', 'check', 'seed', 'run'):
        unit = unit_name(mode); path = SYSTEM / unit
        trusted(path)
        if (read(path) != unit_text(mode) or prop(unit, 'DropInPaths') or
                prop(unit, 'FragmentPath') != str(path) or prop(unit, 'LoadState') != 'loaded'):
            raise ValueError('reviewed_unit_or_dropin_mismatch')
        properties = {'User': ACCOUNT, 'Group': ACCOUNT, 'MemoryAccounting': 'yes',
                      'MemoryLimit': str(LIMIT), 'TasksMax': '32', 'TimeoutStartUSec': '2min',
                      'NoNewPrivileges': 'yes', 'CapabilityBoundingSet': '', 'AmbientCapabilities': '',
                      'ProtectSystem': 'strict', 'ProtectHome': 'yes', 'PrivateTmp': 'yes',
                      'WorkingDirectory': str(RELEASE), 'KillMode': 'control-group',
                      'Requisite': 'aifinance-preview-db.service'}
        for name, expected in properties.items():
            if prop(unit, name) != expected:
                raise ValueError('loaded_collector_safety_property_mismatch')
        # Requisite checks existing state but never queues a database start.
        for relationship in ('Requires', 'Wants', 'BindsTo'):
            if 'aifinance-preview-db.service' in prop(unit, relationship).split():
                raise ValueError('collector_must_not_start_database')
        command_line = '/usr/bin/sleep 30' if mode == 'probe' else '/usr/bin/python3 -I -B %s _execute --mode %s' % (SELF, mode)
        effective_exec(unit, 'ExecStart', command_line)
        if mode == 'probe':
            if prop(unit, 'ExecStartPre'):
                raise ValueError('probe_must_only_execute_trusted_sleep')
        else:
            effective_exec(unit, 'ExecStartPre', '/usr/bin/python3 -I -B %s _verify --mode %s' % (SELF, mode))


RESOLVER_REASONS = ('mount_id_missing', 'mount_path_mismatch', 'mount_not_readonly',
                    'inode_mismatch', 'content_mismatch', 'untrusted_path')


def resolver_failure(reason):
    error = ValueError('actual_read_only_hosts_binding_required')
    error.resolver_reason = reason if reason in RESOLVER_REASONS else 'untrusted_path'
    return error


def resolver_file(root_fd, target):
    # Never let an absolute symlink after /proc/PID/root resolve in the observer's
    # root. Resolve link text ourselves, using only no-follow, root-relative FDs.
    pending = target.split('/')[1:]; names = []; directories = [os.dup(root_fd)]
    links = 0; steps = 0
    try:
        while pending:
            steps += 1
            if steps > 256:
                raise resolver_failure('untrusted_path')
            name = pending.pop(0)
            if name in ('', '.'):
                continue
            if name == '..':
                if not names:
                    raise resolver_failure('untrusted_path')
                names.pop(); os.close(directories.pop()); continue
            if not names and name in ('proc', 'sys', 'dev'):
                raise resolver_failure('untrusted_path')
            entry = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directories[-1])
            try:
                info = os.fstat(entry)
                if info.st_uid != 0:
                    raise resolver_failure('untrusted_path')
                if stat.S_ISLNK(info.st_mode):
                    links += 1
                    # readlinkat(AT_EMPTY_PATH) reads this pinned link, not a
                    # potentially replaced entry. A link's normal 0777 is OK.
                    link = os.readlink('', dir_fd=entry)
                    if links > 40 or not link or len(link) > 4096:
                        raise resolver_failure('untrusted_path')
                    if link.startswith('/'):
                        while len(directories) > 1:
                            os.close(directories.pop())
                        names = []
                    pending = link.split('/') + pending
                elif info.st_mode & 0o022:
                    raise resolver_failure('untrusted_path')
                elif pending and stat.S_ISDIR(info.st_mode):
                    directories.append(entry); entry = None; names.append(name)
                elif not pending and stat.S_ISREG(info.st_mode):
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                 dir_fd=directories[-1])
                    actual = os.fstat(fd)
                    if (actual.st_dev, actual.st_ino, actual.st_mode, actual.st_uid) != (
                            info.st_dev, info.st_ino, info.st_mode, info.st_uid):
                        os.close(fd)
                        raise resolver_failure('inode_mismatch')
                    return fd, '/' + '/'.join(names + [name])
                else:
                    raise resolver_failure('untrusted_path')
            finally:
                if entry is not None:
                    os.close(entry)
        raise resolver_failure('untrusted_path')
    finally:
        for fd in directories:
            os.close(fd)


def resolver_evidence(pid):
    # Check the opened child-namespace files, including a trusted canonical NSS
    # target (e.g. authselect). Content alone or path-only mountinfo is not proof.
    expected = {'/etc/hosts': CONFIG / 'hosts', '/etc/nsswitch.conf': CONFIG / 'nsswitch.conf'}
    root_fd = None
    try:
        root_fd = os.open('/proc/%d/root' % pid, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
        root = os.fstat(root_fd)
        if root.st_uid != 0 or root.st_mode & 0o022:
            raise resolver_failure('untrusted_path')
        mounts = []
        for line in read(Path('/proc/%d/mountinfo' % pid), 1048576).splitlines():
            left, sep, right = line.partition(' - ')
            fields = left.split()
            if sep and len(fields) >= 6:
                mounts.append(fields)
        for target, source in expected.items():
            trusted(source)
            source_fd = os.open(str(source), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            try:
                original = os.fstat(source_fd)
                if (not stat.S_ISREG(original.st_mode) or original.st_uid != 0 or
                        original.st_mode & 0o022 or original.st_size > 131072):
                    raise resolver_failure('untrusted_path')
                content = os.read(source_fd, 131073)
                if len(content) != original.st_size or target == '/etc/nsswitch.conf' and content != b'hosts: files\n':
                    raise resolver_failure('content_mismatch')
                fd, canonical = resolver_file(root_fd, target)
                try:
                    actual = os.fstat(fd)
                    ids = re.findall(r'^mnt_id:\s*([0-9]+)\s*$', read(Path('/proc/self/fdinfo/%d' % fd), 4096), re.M)
                    matches = [fields for fields in mounts if len(ids) == 1 and fields[0] == ids[0]]
                    # mnt_id ties mount flags to this FD even with stacked mounts.
                    mount = matches[0] if len(matches) == 1 else []
                    mount_path = re.sub(r'\\(040|011|012|134)', lambda found: chr(int(found.group(1), 8)), mount[4]) if mount else ''
                    if not mount:
                        raise resolver_failure('mount_id_missing')
                    if mount_path != canonical:
                        raise resolver_failure('mount_path_mismatch')
                    if ('ro' not in mount[5].split(',') or 'rw' in mount[5].split(',') or
                            not os.fstatvfs(fd).f_flag & os.ST_RDONLY):
                        raise resolver_failure('mount_not_readonly')
                    if (actual.st_dev, actual.st_ino) != (original.st_dev, original.st_ino):
                        raise resolver_failure('inode_mismatch')
                    if os.read(fd, 131073) != content:
                        raise resolver_failure('content_mismatch')
                finally:
                    os.close(fd)
            finally:
                os.close(source_fd)
    except (OSError, ValueError) as error:
        if getattr(error, 'resolver_reason', None) not in RESOLVER_REASONS:
            error.resolver_reason = 'untrusted_path'
        raise
    finally:
        if root_fd is not None:
            os.close(root_fd)
    return {'hosts_only': True, 'read_only_bindings': sorted(expected)}


def kernel_evidence(pid, mode, uid):
    status = dict(line.split(':', 1) for line in Path('/proc/%d/status' % pid).read_text().splitlines() if ':' in line)
    if (status.get('Uid', '').split() != [str(uid)] * 4 or status.get('NoNewPrivs', '').strip() != '1' or
            int(status.get('CapEff', '1').strip(), 16) != 0):
        raise ValueError('collector_process_identity_or_privileges')
    groups = {}
    for line in Path('/proc/%d/cgroup' % pid).read_text().splitlines():
        fields = line.split(':', 2)
        if len(fields) == 3:
            for name in fields[1].split(','):
                if name in ('memory', 'pids'):
                    if name in groups:
                        raise ValueError('duplicate_cgroup_controller')
                    groups[name] = fields[2]
    expected = '/system.slice/' + unit_name(mode)
    if groups != {'memory': expected, 'pids': expected}:
        raise ValueError('both_expected_v1_controllers_required')
    values = {}
    for controller, fields in (('memory', ('limit_in_bytes', 'usage_in_bytes', 'max_usage_in_bytes', 'failcnt')),
                               ('pids', ('max', 'current'))):
        base = Path('/sys/fs/cgroup') / controller / expected.lstrip('/')
        if str(pid) not in (base / 'cgroup.procs').read_text().split():
            raise ValueError('pid_missing_from_kernel_cgroup')
        for field in fields:
            value = (base / (controller + '.' + field)).read_text().strip()
            if not re.fullmatch('[0-9]{1,20}', value):
                raise ValueError('invalid_kernel_counter')
            values[controller + '.' + field] = int(value)
    if (values['memory.limit_in_bytes'] != LIMIT or values['memory.usage_in_bytes'] >= LIMIT or
            values['memory.max_usage_in_bytes'] >= LIMIT or values['memory.failcnt'] != 0 or
            values['pids.max'] != 32 or values['pids.current'] > 32):
        raise ValueError('kernel_budget_not_enforced_or_hit')
    return dict(values, pid=pid, uid=uid, cgroup=expected)


def resource_evidence(mode, user):
    unit = unit_name(mode)
    properties = {name: prop(unit, name) for name in ('MainPID', 'User', 'MemoryAccounting', 'MemoryLimit', 'TasksMax', 'TimeoutStartUSec')}
    if (properties['User'] != ACCOUNT or properties['MemoryAccounting'] != 'yes' or
            properties['MemoryLimit'] != str(LIMIT) or properties['TasksMax'] != '32' or
            properties['TimeoutStartUSec'] != '2min' or not re.fullmatch('[1-9][0-9]*', properties['MainPID'])):
        raise ValueError('actual_systemd_budget_or_pid_mismatch')
    kernel = kernel_evidence(int(properties['MainPID']), mode, user.pw_uid)
    resolver = resolver_evidence(int(properties['MainPID'])) if mode != 'probe' else None
    if prop(unit, 'MainPID') != properties['MainPID']:
        raise ValueError('pid_changed_during_resource_sample')
    return {'properties': properties, 'kernel': kernel, 'resolver': resolver}


def bounded_child(args, env, timeout=105, drop=None):
    process = subprocess.Popen(args, env=env, cwd=str(RELEASE), stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, preexec_fn=drop,
                               start_new_session=True)
    selector = selectors.DefaultSelector(); selector.register(process.stdout, selectors.EVENT_READ)
    data = bytearray(); deadline = time.monotonic() + timeout
    try:
        while True:
            if not selector.select(max(0, deadline - time.monotonic())):
                raise ValueError('bounded_child_timeout')
            chunk = os.read(process.stdout.fileno(), 4096)
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > 131072:
                raise ValueError('bounded_child_output_limit')
        if process.wait(timeout=max(.01, deadline - time.monotonic())) != 0:
            raise ValueError('collect_command_failed_no_automatic_retry')
        return data.decode('utf-8', 'strict')
    finally:
        selector.close(); process.stdout.close()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL); process.wait()


def batch_summary(data):
    if not isinstance(data, list) or len(data) != 3 or {row.get('sourceId') for row in data} != set(FEEDS):
        raise ValueError('unexpected_batch_summary')
    rows = []
    for row in data:
        if any(type(row.get(key)) is not int or row[key] < 0 for key in ('found', 'processed', 'created', 'revised')):
            raise ValueError('invalid_batch_counts')
        if row['created'] + row['revised'] > row['processed'] or row['processed'] > row['found']:
            raise ValueError('invalid_batch_counts')
        rows.append({key: row[key] for key in ('sourceId', 'found', 'processed', 'created', 'revised')})
    if sum(row['processed'] for row in rows) > 3:
        raise ValueError('batch_exceeds_three')
    return rows


def execute(mode):
    if mode not in ('check', 'seed', 'run'):
        raise ValueError('invalid_unprivileged_mode')
    user = account()
    if os.getuid() != user.pw_uid or os.geteuid() != user.pw_uid:
        raise ValueError('application_code_requires_collector_uid')
    before = kernel_evidence(os.getpid(), mode, user.pw_uid)
    resolver_evidence(os.getpid())
    # Permit the root observer to sample the real worker PID before any DB/HTTP.
    time.sleep(2)
    args = [str(NODE), '--max-old-space-size=128', 'scripts/collect-only-check.ts' if mode == 'check' else 'scripts/collect-only.ts']
    args += ['--check' if mode == 'check' else '--seed-only' if mode == 'seed' else '--run']
    output = bounded_child(args, db_environment())
    result = {'seeded': True} if mode == 'seed' else json.loads(output)
    if mode == 'run':
        result = batch_summary(result)
    after = kernel_evidence(os.getpid(), mode, user.pw_uid)
    print(json.dumps({'mode': mode, 'result': result, 'before': before, 'after': after}, sort_keys=True), flush=True)


def run_unit(mode, user):
    unit = unit_name(mode)
    verify_units(); verify_network(user)
    initial_state = prop(unit, 'ActiveState')
    if initial_state not in ('inactive', 'failed'):
        raise ValueError('collector_unit_already_running')
    replace_owned(STATE / 'output.json', '')
    # systemd 239 may unload an inactive unit between queries. ResetFailedUnit
    # does not load it again; StartUnit does. Only a failed unit needs resetting.
    if initial_state == 'failed':
        command([CTL, 'reset-failed', unit])
    started = time.monotonic(); samples = []
    launch = STATE / 'launch.json'
    write_new(launch, json.dumps({'mode': mode, 'pid': os.getpid(), 'start_ticks': Path('/proc/self/stat').read_text().split(') ', 1)[1].split()[19]}))
    observed_start = False
    try:
        command([CTL, 'start', '--no-block', unit])
        while time.monotonic() - started < 125:
            active = prop(unit, 'ActiveState')
            pid = prop(unit, 'MainPID')
            if active not in ('inactive', 'failed'):
                observed_start = True
            if active == 'failed' or active == 'inactive' and observed_start:
                break
            if pid != '0':
                try:
                    samples.append(resource_evidence(mode, user))
                except FileNotFoundError:
                    # /proc may vanish before systemd clears MainPID. Earlier
                    # root samples plus the wrapper's final kernel sample are
                    # still required; terminal Result/status decide acceptance.
                    pass
                except ValueError as error:
                    if (str(error) not in ('pid_changed_during_resource_sample', 'actual_systemd_budget_or_pid_mismatch')
                            or prop(unit, 'MainPID') != '0'):
                        raise
            time.sleep(.2)
        elapsed = time.monotonic() - started
        if (not samples or prop(unit, 'Result') != 'success' or prop(unit, 'ExecMainStatus') != '0' or
                prop(unit, 'ActiveState') != 'inactive' or elapsed > 120):
            raise ValueError('unit_failed_timed_out_or_resource_evidence_missing')
        result = {} if mode == 'probe' else json.loads(read(STATE / 'output.json'))
        report = {'mode': mode, 'elapsed_seconds': round(elapsed, 3), 'samples': samples, 'output': result}
        stamp = '%d-%s' % (int(time.time()), os.urandom(6).hex())
        write_new(STATE / (mode + '-' + stamp + '.json'), json.dumps(report, sort_keys=True))
        return report
    except BaseException:
        command([CTL, 'stop', unit], timeout=15)
        raise
    finally:
        launch.unlink()


def no_other_writers(user):
    for role in ('api', 'web'):
        if prop('aifinance-preview-' + role + '.service', 'ActiveState') != 'inactive':
            raise ValueError('stop_preview_api_and_web_for_first_batch')
    no_processes(pwd.getpwnam('aifinance').pw_uid)
    no_processes(user.pw_uid)
    def drop():
        os.setgroups([]); os.setgid(user.pw_gid); os.setuid(user.pw_uid)
    password = urlsplit(db_environment()['DATABASE_URL']).password
    args = ['/usr/pgsql-17/bin/psql', '-X', '-w', '-A', '-t', '-v', 'ON_ERROR_STOP=1',
            '-h', '127.0.0.1', '-p', '55432', '-U', 'aifinance_preview', '-d', 'aifinance_preview',
            '-c', "SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid()"]
    if bounded_child(args, dict(ENV, PGPASSWORD=password), timeout=15, drop=drop).strip() != '0':
        raise ValueError('other_database_clients_present')


def validate_snapshot(snapshot, seeded=True):
    if snapshot.get('checkOnly') is not True or snapshot.get('readyForApply') is not False or snapshot.get('database') != 'aifinance_preview':
        raise ValueError('read_only_snapshot_required')
    if '0041_collect_only.sql' not in snapshot.get('migrations', []):
        raise ValueError('collect_migration_missing')
    columns = snapshot.get('columns', [])
    if len(columns) != 2 or {row.get('table_name') for row in columns} != {'articles', 'sources'} or any(
            row.get('column_name') != 'collect_only' or row.get('column_default') != 'false' or row.get('is_nullable') != 'NO' for row in columns):
        raise ValueError('collect_column_defaults_not_accepted')
    constraints = snapshot.get('constraints', [])
    if len(constraints) != 1 or constraints[0].get('conname') != 'collect_only_source_isolation' or constraints[0].get('convalidated') is not True:
        raise ValueError('validated_source_constraint_required')
    counts = snapshot.get('counts', {})
    for table in ('articles', 'article_revisions') + ZERO_TABLES:
        if table == 'pgboss.job' and counts.get(table) is None:
            continue
        if type(counts.get(table)) is not int or counts[table] < 0:
            raise ValueError('required_exact_count_missing')
    if any(row.get('processing_state') != 'skipped' for row in snapshot.get('rawStates', [])):
        raise ValueError('unexpected_collect_processing_state')
    sources = snapshot.get('sources', [])
    if seeded and (len(sources) != 3 or {row.get('id') for row in sources} != set(FEEDS)):
        raise ValueError('three_seeded_sources_required')
    for row in sources:
        if (row.get('kind') != 'rss' or row.get('collect_only') != 'true' or row.get('enabled') is not False or
                row.get('participation_mode') != 'isolated' or row.get('site_fulltext') is not False or row.get('syndicate_fulltext') is not False):
            raise ValueError('source_isolation_not_accepted')


def accept_delta(before, after, rows=None):
    validate_snapshot(before, seeded=rows is not None); validate_snapshot(after)
    for table in ZERO_TABLES:
        if before['counts'][table] != after['counts'][table]:
            raise ValueError('forbidden_downstream_count_change')
    max_delta = 3 if rows is not None else 0
    for table in ('articles', 'article_revisions'):
        delta = after['counts'][table] - before['counts'][table]
        if not 0 <= delta <= max_delta:
            raise ValueError('unexpected_material_count_delta')
    if rows is not None:
        batch_summary(rows)
        if after['counts']['articles'] - before['counts']['articles'] != sum(row['created'] for row in rows):
            raise ValueError('created_count_does_not_match_database')
        if after['counts']['article_revisions'] - before['counts']['article_revisions'] != sum(row['created'] + row['revised'] for row in rows):
            raise ValueError('revision_count_does_not_match_database')
    if before['migrations'] != after['migrations']:
        raise ValueError('migration_changed_during_collection')


def install():
    upgrade_gate(); validate_release(); trusted(MAINTENANCE, directory=True)
    for path in (STATE, CONFIG):
        if path.exists() or path.is_symlink():
            raise ValueError('existing_or_partial_collector_install_requires_review')
    for mode in ('probe', 'check', 'seed', 'run'):
        if (SYSTEM / unit_name(mode)).exists() or prop(unit_name(mode), 'LoadState') != 'not-found':
            raise ValueError('collector_unit_already_exists')
    for name in ('aifinance-collect-hourly.service', 'aifinance-collect-hourly.timer'):
        if (SYSTEM / name).exists() or (SYSTEM / name).is_symlink() or prop(name, 'LoadState') != 'not-found':
            raise ValueError('hourly_units_must_not_preexist_install')
    try:
        pwd.getpwnam(ACCOUNT)
    except KeyError:
        command(['/usr/sbin/useradd', '--system', '--user-group', '--no-create-home', '--home-dir', '/nonexistent', '--shell', '/sbin/nologin', ACCOUNT])
    user = account(); no_processes(user.pw_uid)
    STATE.mkdir(mode=0o700); CONFIG.mkdir(mode=0o750)
    os.chmod(str(CONFIG), 0o750)
    os.chown(str(CONFIG), 0, user.pw_gid)
    # Use the already reviewed parser; its full result never becomes a child env.
    parser_path = ROOT / 'bin/run-preview.py'; trusted(parser_path)
    source = Path('/etc/aifinance-preview.env'); trusted(source)
    source_stat = source.stat()
    if (source_stat.st_mode & 0o007 or source_stat.st_mode & 0o022 or
            source_stat.st_gid not in (0, pwd.getpwnam('aifinance').pw_gid)):
        raise ValueError('protected_preview_environment_required')
    spec = importlib.util.spec_from_file_location('approved_preview_environment', str(parser_path))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    url = module.environment(read(source, 8192))['DATABASE_URL']
    text = 'DATABASE_URL=' + url + '\n'; database_url(text)
    write_new(CONFIG / 'database.env', text, 0o440, user.pw_gid)
    configure_network(user, {})
    for mode in ('probe', 'check', 'seed', 'run'):
        write_new(SYSTEM / unit_name(mode), unit_text(mode), 0o644)
    command([CTL, 'daemon-reload']); verify_units()
    write_new(STATE / 'installed.json', json.dumps({'release': RELEASE_SHA, 'uid': user.pw_uid}))
    return {'installed': True, 'uid': user.pw_uid, 'timer_installed': False}


def first_operation(mode, user):
    if not (STATE / 'probe.json').is_file():
        raise ValueError('successful_no_network_probe_required')
    if (STATE / (mode + '.json')).exists() or (STATE / (mode + '-attempt.json')).exists():
        raise ValueError('first_operation_already_attempted_requires_review')
    write_new(STATE / (mode + '-attempt.json'), json.dumps({'release': RELEASE_SHA, 'mode': mode, 'started': int(time.time())}))
    app_units = ['aifinance-preview-' + role + '.service' for role in ('api', 'web')]
    command([CTL, 'stop'] + app_units, timeout=40)
    no_other_writers(user)
    before = run_unit('check', user)['output']['result']
    validate_snapshot(before, seeded=mode == 'run')
    if mode == 'run':
        if not (STATE / 'seed.json').is_file():
            raise ValueError('successful_seed_required')
        configure_network(user, resolve_feeds())
    result = run_unit(mode, user)
    no_other_writers(user)
    after = run_unit('check', user)['output']['result']
    rows = result['output']['result'] if mode == 'run' else None
    accept_delta(before, after, rows)
    receipt = {'release': RELEASE_SHA, 'mode': mode, 'before': before, 'after': after,
               'result': result, 'passed': True, 'admin_view_accepted': False}
    configure_network(user, {})
    command([CTL, 'start'] + app_units, timeout=40)
    first = ROOT / 'bin/first-preview.py'; trusted(first)
    spec = importlib.util.spec_from_file_location('approved_preview_health', str(first))
    health = importlib.util.module_from_spec(spec); spec.loader.exec_module(health)
    health.health(RELEASE_SHA)
    write_new(STATE / (mode + '.json'), json.dumps(receipt, sort_keys=True))
    return {'mode': mode, 'passed': True, 'batch': rows, 'timer_installed': False}


def hourly_text():
    service = '''[Unit]
Description=Accepted hourly finance collector controller
[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/python3 -I -B %s run --scheduled
TimeoutStartSec=180
LimitCORE=0
UMask=0077
StandardOutput=journal
StandardError=null
''' % SELF
    timer = '''[Unit]
Description=Accepted hourly fixed-source RSS batch
[Timer]
OnActiveSec=1h
OnUnitActiveSec=1h
RandomizedDelaySec=60
Persistent=false
Unit=aifinance-collect-hourly.service
[Install]
WantedBy=timers.target
'''
    return service, timer


def enable_hourly(user, accepted):
    if not accepted:
        raise ValueError('explicit_admin_view_acceptance_required')
    trusted(STATE / 'run.json')
    receipt = json.loads(read(STATE / 'run.json', 1048576))
    if receipt.get('passed') is not True or receipt.get('release') != RELEASE_SHA:
        raise ValueError('first_batch_acceptance_required')
    service, timer = hourly_text()
    write_new(SYSTEM / 'aifinance-collect-hourly.service', service, 0o644)
    write_new(SYSTEM / 'aifinance-collect-hourly.timer', timer, 0o644)
    write_new(STATE / 'hourly-approved.json', json.dumps({'release': RELEASE_SHA, 'admin_view_accepted': True}))
    command([CTL, 'daemon-reload'])
    for name, content in (('aifinance-collect-hourly.service', service), ('aifinance-collect-hourly.timer', timer)):
        path = SYSTEM / name; trusted(path)
        if read(path) != content or prop(name, 'FragmentPath') != str(path) or prop(name, 'DropInPaths'):
            raise ValueError('hourly_unit_override_or_content_mismatch')
    effective_exec('aifinance-collect-hourly.service', 'ExecStart', '/usr/bin/python3 -I -B %s run --scheduled' % SELF)
    command([CTL, 'enable', '--now', 'aifinance-collect-hourly.timer'])
    if prop('aifinance-collect-hourly.timer', 'ActiveState') != 'active' or command([CTL, 'is-enabled', 'aifinance-collect-hourly.timer']) != 'enabled':
        raise ValueError('timer_enable_not_verified')
    return {'hourly_enabled': True, 'admin_view_accepted': True}


def verify_launch(mode):
    unit_name(mode)
    path = STATE / 'launch.json'; trusted(path)
    launch = json.loads(read(path))
    if launch.get('mode') != mode or type(launch.get('pid')) is not int or launch['pid'] <= 1:
        raise ValueError('active_root_controller_required')
    proc = Path('/proc') / str(launch['pid'])
    status = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines() if ':' in line)
    if (status.get('Uid', '').split() != ['0'] * 4 or
            (proc / 'stat').read_text().split(') ', 1)[1].split()[19] != launch.get('start_ticks')):
        raise ValueError('root_controller_identity_changed')
    if mode != 'probe':
        trusted(STATE / 'probe.json')
    if mode == 'run':
        trusted(STATE / 'seed.json')


def disable(user):
    # Preserve data, schema, receipts and the application's existing guard.
    # Unknown or modified nft tables are never deleted or replaced.
    timer = 'aifinance-collect-hourly.timer'
    if prop(timer, 'LoadState') != 'not-found':
        command([CTL, 'disable', '--now', timer])
    command([CTL, 'stop'] + [unit_name(mode) for mode in ('probe', 'check', 'seed', 'run')], timeout=20)
    path = CONFIG / 'database.env'
    trusted(path)
    os.chown(str(path), 0, 0); os.chmod(str(path), 0o400)
    no_processes(user.pw_uid)
    configure_network(user, {})
    return {'collector_disabled': True, 'db_read_revoked': True, 'data_preserved': True}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('check', 'install', 'probe', 'seed', 'run', 'enable-hourly', 'disable', '_execute', '_verify'))
    parser.add_argument('--accept-admin-view', action='store_true')
    parser.add_argument('--scheduled', action='store_true')
    parser.add_argument('--mode', choices=('probe', 'check', 'seed', 'run'))
    args = parser.parse_args(argv)
    if args.action == '_execute':
        execute(args.mode); return
    if os.getuid() != 0 or os.geteuid() != 0 or Path(__file__).absolute() != SELF:
        raise ValueError('fixed_installed_root_operator_entry_required')
    trusted(SELF); resource.setrlimit(resource.RLIMIT_CORE, (0, 0)); os.umask(0o077)
    if args.accept_admin_view and args.action != 'enable-hourly' or args.scheduled and args.action != 'run' or args.mode and args.action != '_verify':
        raise ValueError('invalid_operation_flags')
    # Same inode as release.sh; no alternate collector-only lock.
    fd = release_lock()
    try:
        if args.action != '_verify':
            fcntl.flock(fd, (fcntl.LOCK_SH if args.action == 'check' else fcntl.LOCK_EX) | fcntl.LOCK_NB)
        if args.action == 'disable':
            print(json.dumps(disable(account()), sort_keys=True)); return
        upgrade_gate(); validate_release()
        if args.action == 'check':
            print(json.dumps({'check_only': True, 'release': RELEASE_SHA, 'ready_for_apply': False,
                              'installed': STATE.exists(), 'requires_root_approved_install_and_target_probe': True})); return
        if args.action == 'install':
            result = install()
        else:
            user = account(); verify_units()
            if not args.scheduled:
                verify_network(user)
            if args.action not in ('probe', '_verify', 'disable'):
                db_environment()
            if args.action == '_verify':
                verify_launch(args.mode)
                return
            if args.action == 'probe':
                if (STATE / 'probe.json').exists():
                    raise ValueError('probe_already_recorded')
                report = run_unit('probe', user)
                write_new(STATE / 'probe.json', json.dumps(report, sort_keys=True))
                result = {'probe_passed': True, 'pressure_and_reboot_accepted': False}
            elif args.action in ('seed', 'run') and not args.scheduled:
                attempt = STATE / (args.action + '-attempt.json')
                attempted_before = attempt.exists()
                try:
                    result = first_operation(args.action, user)
                except Exception:
                    if not attempted_before and attempt.exists():
                        disable(user)
                    raise
            elif args.action == 'run':
                trusted(STATE / 'hourly-approved.json')
                accepted = json.loads(read(STATE / 'hourly-approved.json'))
                if accepted != {'release': RELEASE_SHA, 'admin_view_accepted': True}:
                    raise ValueError('hourly_acceptance_required')
                try:
                    configure_network(user, resolve_feeds())
                    result = {'hourly_batch': run_unit('run', user)['output']['result'], 'full_table_delta_acceptance': False}
                    configure_network(user, {})
                except Exception:
                    disable(user)
                    raise
            else:
                result = enable_hourly(user, args.accept_admin_view)
        print(json.dumps(result, sort_keys=True))
    finally:
        os.close(fd)


if __name__ == '__main__':
    def interrupted(signum, frame):
        raise ValueError('operator_interrupted')
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupted)
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        # Never emit exceptions, URLs, app stderr, environment, or database secrets.
        print(json.dumps({'failed': True, 'stop_and_review': True, 'automatic_retry': False,
                          'rollback_or_ready_claimed': False}), file=sys.stderr)
        raise SystemExit(1)
