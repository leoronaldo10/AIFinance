#!/usr/bin/python3
"""One reviewed website-only postboot recovery; Python 3.6.8+.

Run the two reviewed payloads from a private root-owned source directory with
python3 -I -B. check is read-only. apply retains evidence and the guard on failure;
it never initializes a database, updates a helper, or invokes the collector.
"""
import argparse
import contextlib
import fcntl
import grp
import hashlib
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
import types

ROOT = Path('/opt/aifinance')
BIN = ROOT / 'bin'
SYSTEM = Path('/etc/systemd/system')
MAINTENANCE = Path('/var/lib/aifinance-maintenance')
COLLECT = MAINTENANCE / 'collect-only'
OPS = Path('/var/lib/aifinance-ops')
COLLECT_CONFIG = Path('/etc/aifinance-collect')
APP_ENV = Path('/etc/aifinance-preview.env')
PGDATA = Path('/var/lib/pgsql/aifinance-preview')
PGCONFIG = Path('/etc/aifinance-preview-db')
PROC = Path('/proc')
ACCEPTANCE = Path('/run/aifinance-egress-after-boot')
GUARD_RUNTIME = Path('/run/aifinance-preview-egress')
RELEASE = 'd57ba047369e666025347719caee1a4c642abe62'
SCHEMA = '405672156ea4ef49bc9272d47f23de3a7208a8c80a9d2bee066e6d607152cafc'
SOURCE_PATTERN = r'/root/aifinance-preview-recovery-[A-Za-z0-9]{12}'
ACCEPT_SHA = '74776aa4ae53bbc5728b4fd98da25b4624e31da65054ffbd86c158f122da3b13'
CTL = '/usr/bin/systemctl'
ENV = dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin', HOME='/', LANG='C', LC_ALL='C', TZ='UTC')
API = 'aifinance-preview-api.service'
WEB = 'aifinance-preview-web.service'
DB = 'aifinance-preview-db.service'
GUARD = 'aifinance-preview-egress.service'
UNITS = (GUARD, DB, API, WEB)
UNIT_PINS = {
    API: 'a233ae654f3fc5c1c67c5b1cb3c0f7029428e7852afeea4934fa1ce4c54f70ed',
    WEB: 'b18f56c0461808d128786b74a425baf42c7a7abb6583a4828e531b7686468af6',
    DB: '6f887ef4c0b7e753c2d80929963fabde5e630d9bbca7b298e24fa6cb4573a02a',
    GUARD: 'e89d001be5bb1929553c1b219759a9f123da6484229af3264e954f072047773e',
}
HELPER_PINS = {
    'egress-guard.py': '5c407c3916e1f44441f0a3962ea802d148084c281426ec0f809e9ad542913367',
    'isolation-probe.py': '46350936233416c282bd8941c063cdffb09bf138e5f4e29158afc236dfd8ac7e',
    'first-preview.py': 'c8c87688c7bac6d17e412c2eaf81df49a0401f5191f9294ee15c8f359af2bb56',
    'run-preview.py': '60a9105825ea58f57098c601ce157ac83c996d97db4a4be7732860552e54659c',
    'collect-only-upgrade.py': '9eb61d5b9357a31ed319202efd14ffedbc591aac1fe090179f719246971dfca5',
    'collect-only-runner.py': '7555b956d26f93c2829683008a3f78f71e1e122d21f6c2fc25bcf3d222769cdf',
    'ops-broker.py': '2620884dbba3acad9abc68db50ca2d09aa434b2d6f5e82f2ab28144228559fcc',
}
COLLECT_SIZES = {'installed.json': 67, 'probe.json': 46767, 'seed-attempt.json': 94,
                 'network.json': 25, 'output.json': 0}
ACTIONS = ['diagnose', 'restart-preview', 'probe', 'recover-pre-seed', 'seed', 'run', 'disable', 'enable-hourly']
HOOKS = ('ExecStartPre', 'ExecStartPost', 'ExecStop', 'ExecStopPost', 'ExecReload')
# v239 omits these empty structured arrays from systemctl show. Only a typed
# D-Bus zero-length array proves absence; missing metadata itself proves nothing.
OMITTED_ARRAYS = dict((name, 'a(sasbttttuii)') for name in HOOKS)
OMITTED_ARRAYS['EnvironmentFiles'] = 'a(sb)'
SERVICE_PATHS = {
    API: '/org/freedesktop/systemd1/unit/aifinance_2dpreview_2dapi_2eservice',
    WEB: '/org/freedesktop/systemd1/unit/aifinance_2dpreview_2dweb_2eservice',
    DB: '/org/freedesktop/systemd1/unit/aifinance_2dpreview_2ddb_2eservice',
    GUARD: '/org/freedesktop/systemd1/unit/aifinance_2dpreview_2degress_2eservice',
}
PROPERTIES = ('LoadState', 'ActiveState', 'SubState', 'Result', 'MainPID', 'ControlPID',
              'UnitFileState', 'FragmentPath', 'DropInPaths', 'NeedDaemonReload',
              'ExecStart', 'User', 'Group', 'BindsTo', 'After', 'Requires', 'Wants',
              'Slice', 'DefaultDependencies', 'RequiresMountsFor',
              'Requisite', 'OnFailure', 'Environment', 'EnvironmentFiles', 'PassEnvironment',
              'MemoryAccounting', 'MemoryLimit', 'TasksMax', 'Restart') + HOOKS


class Refused(Exception):
    def __init__(self, reason, target=None):
        self.reason = reason
        self.target = target
        Exception.__init__(self, 'reviewed recovery refused')


def require(condition, reason):
    if not condition:
        raise Refused(reason)


@contextlib.contextmanager
def checking(target):
    # Callers supply fixed helper/unit/config labels, never credential values.
    try:
        yield
    except Refused as error:
        if error.target is None:
            error.target = target
        raise
    except OSError as error:
        raise Refused('filesystem_or_process_error_errno_' + str(error.errno or 0), target)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def attributes(info):
    return dict(device=info.st_dev, inode=info.st_ino, uid=info.st_uid, gid=info.st_gid,
                mode=stat.S_IMODE(info.st_mode), size=info.st_size,
                mtime_ns=info.st_mtime_ns, ctime_ns=info.st_ctime_ns)


def trusted_dir(path, mode=None, gid=0):
    for item in (path,) + tuple(path.parents):
        info = item.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'untrusted_directory_ancestor')
        if item == path:
            require(info.st_gid == gid and (mode is None or stat.S_IMODE(info.st_mode) == mode),
                    'directory_owner_or_mode_mismatch')


def read(path, maximum=1048576, mode=None, uid=0, gid=0, parents=True):
    if parents:
        trusted_dir(path.parent, gid=path.parent.lstat().st_gid)
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_gid == gid and
                info.st_nlink == 1 and not info.st_mode & 0o022 and info.st_size <= maximum and
                (mode is None or stat.S_IMODE(info.st_mode) == mode), 'file_owner_mode_or_size_mismatch')
        raw = stream.read(maximum + 1)
        require(len(raw) == info.st_size and attributes(info) == attributes(path.lstat()),
                'file_changed_during_read')
        return raw


def metadata(path, uid, gid, mode, maximum):
    # Credentials are not opened, parsed, hashed, copied or included in evidence.
    trusted_dir(path.parent, gid=path.parent.lstat().st_gid)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == uid and
            info.st_gid == gid and stat.S_IMODE(info.st_mode) == mode and 0 < info.st_size <= maximum,
            'credential_file_metadata_mismatch')
    return attributes(info)


def absent(path, reason='unexpected_existing_path'):
    try:
        path.lstat()
    except FileNotFoundError:
        return
    raise Refused(reason)


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'duplicate_json_key')
        value[key] = item
    return value


def document(raw):
    result = json.loads(raw.decode('utf-8'), object_pairs_hook=unique)
    require(isinstance(result, dict), 'json_object_required')
    return result


def command(args, timeout=20, maximum=262144, output=None):
    # Fixed argv only. Never forward subprocess output or exception text publicly.
    p = subprocess.Popen(args, cwd='/', env=ENV, stdin=subprocess.DEVNULL,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT if output is not None else subprocess.DEVNULL,
                         start_new_session=True)
    selector = selectors.DefaultSelector(); selector.register(p.stdout, selectors.EVENT_READ)
    data = bytearray(); deadline = time.monotonic() + timeout
    try:
        while True:
            require(selector.select(max(0, deadline - time.monotonic())), 'command_timeout')
            block = os.read(p.stdout.fileno(), 16384)
            if not block:
                break
            data.extend(block)
            require(len(data) <= maximum, 'command_output_limit')
            if output is not None:
                output.write(block); output.flush()
        code = p.wait(timeout=max(0.01, deadline - time.monotonic()))
        require(code == 0, 'command_exit_nonzero')
        return data.decode('utf-8', 'strict').strip()
    finally:
        selector.close(); p.stdout.close()
        if p.poll() is None:
            os.killpg(p.pid, signal.SIGKILL); p.wait()


def properties(unit, keys=PROPERTIES):
    args = [CTL, 'show', unit, '--no-pager', '--property=' + ','.join(keys)]
    if unit == '-.mount':
        # The fixed root mount name begins with an option prefix.
        args = [CTL, 'show', '--no-pager', '--property=' + ','.join(keys), '--', unit]
    text = command(args)
    values = {}
    for line in text.splitlines():
        key, separator, value = line.partition('=')
        require(separator and key in keys and key not in values, 'invalid_unit_metadata')
        values[key] = value
    missing = set(keys) - set(values)
    if missing:
        require(unit in SERVICE_PATHS and missing.issubset(OMITTED_ARRAYS), 'incomplete_unit_metadata')
        for key in keys:
            if key not in missing:
                continue
            with checking(unit + ':' + key):
                empty = command(['/usr/bin/busctl', '--system', '--no-pager', 'get-property',
                                 'org.freedesktop.systemd1', SERVICE_PATHS[unit],
                                 'org.freedesktop.systemd1.Service', key], timeout=10, maximum=256)
                require(empty == OMITTED_ARRAYS[key] + ' 0', 'omitted_unit_array_not_verified_empty')
            values[key] = ''
    require(set(values) == set(keys), 'incomplete_unit_metadata')
    return values


def exact_exec(value, expected):
    prefix = '{ path=%s ; argv[]=%s ; ignore_errors=no ;' % (expected.split()[0], expected)
    require(value.startswith(prefix) and value.count('{') == value.count('}') == 1 and value.endswith('}'),
            'effective_command_mismatch')


def source_inputs(expected):
    source = Path(__file__).absolute().parent
    require(re.fullmatch(SOURCE_PATTERN, str(source)) is not None and
            re.fullmatch('[0-9a-f]{64}', expected or '') is not None, 'fixed_source_and_payload_digest_required')
    trusted_dir(source, 0o700)
    require({p.name for p in source.iterdir()} == {'recover-preview-after-boot.py', 'accept-egress-after-boot.sh'},
            'exact_two_source_payloads_required')
    require(sha(read(source / 'recover-preview-after-boot.py', mode=0o600)) == expected,
            'controller_payload_digest_mismatch')
    require(sha(read(source / 'accept-egress-after-boot.sh', mode=0o600)) == ACCEPT_SHA,
            'acceptance_payload_digest_mismatch')
    return source


def release_parents():
    deploy = pwd.getpwnam('aifinance-deploy')
    trusted_dir(ROOT.parent)
    for path in (ROOT, ROOT / 'state', ROOT / 'releases'):
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, deploy.pw_uid) and
                stat.S_IMODE(info.st_mode) == 0o755, 'release_parent_mismatch')
    return deploy


@contextlib.contextmanager
def release_lock(apply):
    owner = release_parents(); path = ROOT / 'state/release.lock'
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == owner.pw_uid and
                info.st_gid == owner.pw_gid and stat.S_IMODE(info.st_mode) == 0o644,
                'canonical_lock_owner_or_mode_mismatch')
        require(attributes(info) == attributes(path.lstat()), 'canonical_lock_replaced')
        fcntl.flock(fd, (fcntl.LOCK_EX if apply else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        require(attributes(info) == attributes(path.lstat()), 'canonical_lock_replaced')
        yield attributes(info)
        require(attributes(info) == attributes(path.lstat()), 'canonical_lock_replaced')
    finally:
        os.close(fd)


def pinned_helpers():
    raw = {}
    for name, expected in HELPER_PINS.items():
        with checking(name):
            raw[name] = read(BIN / name)
            require(sha(raw[name]) == expected, 'installed_helper_digest_mismatch')
    # Import only the pinned read-only schema/health/resource helpers. Its CLI,
    # first-install preflight, activate, query-as-superuser and setup are unused.
    fp = types.ModuleType('pinned_first_preview'); fp.__file__ = str(BIN / 'first-preview.py')
    exec(compile(raw['first-preview.py'], fp.__file__, 'exec'), fp.__dict__)
    fp.ENV = dict(fp.ENV, PGOPTIONS='-c default_transaction_read_only=on -c search_path=pg_catalog -c statement_timeout=10000 -c lock_timeout=1000')
    return fp


def accounts():
    for name, uid in (('aifinance', 989), ('postgres', 26), ('aifinance-collect', 986)):
        user = pwd.getpwnam(name)
        require(user.pw_uid == user.pw_gid == uid and grp.getgrnam(name).gr_gid == uid and
                [p.pw_name for p in pwd.getpwall() if p.pw_uid == uid] == [name], 'service_identity_mismatch')
    collector = pwd.getpwnam('aifinance-collect')
    require(collector.pw_shell == '/sbin/nologin' and collector.pw_dir == '/nonexistent',
            'collector_login_identity_changed')


def no_processes():
    controllers = (b'/opt/aifinance/bin/collect-only-runner.py', b'/opt/aifinance/bin/ops-broker.py',
                   b'/opt/aifinance/bin/collect-only-upgrade.py', b'update-ops-nss-proof.py')
    for process in PROC.iterdir():
        if not process.name.isdigit() or int(process.name) == os.getpid():
            continue
        try:
            raw = (process / 'status').read_bytes()
            require(len(raw) <= 65536, 'process_metadata_limit')
            rows = [line.split()[1:] for line in raw.splitlines() if line.startswith(b'Uid:')]
            require(len(rows) == 1 and len(rows[0]) == 4, 'process_identity_unverifiable')
            uids = {int(x) for x in rows[0]}
            require(not uids.intersection({989, 986}), 'application_or_collector_process_present')
            if 0 in uids or 26 in uids:
                cmd = (process / 'cmdline').read_bytes()
                require(len(cmd) <= 16384, 'process_command_limit')
                require(not any(name in cmd for name in controllers) and str(PGDATA).encode() not in cmd,
                        'maintenance_or_preview_database_process_present')
        except (FileNotFoundError, ProcessLookupError):
            continue


def check_unit(unit):
    require(sha(read(SYSTEM / unit, mode=0o644)) == UNIT_PINS[unit], 'installed_unit_digest_mismatch')
    v = properties(unit)
    for key, value in dict(LoadState='loaded', ActiveState='inactive', SubState='dead', Result='success',
                          MainPID='0', ControlPID='0', UnitFileState='disabled',
                          FragmentPath=str(SYSTEM / unit), DropInPaths='', NeedDaemonReload='no').items():
        require(v[key] == value, 'preview_unit_not_exact_postboot_state')
    app = unit in (API, WEB)
    identity = 'aifinance' if app else 'postgres' if unit == DB else 'root'
    require(v['User'] == v['Group'] == identity, 'effective_unit_identity_mismatch')
    require(v['BindsTo'].split() == ([GUARD] if app else []), 'effective_binds_to_mismatch')
    after = {'network.target'} | ({GUARD} if app else {'firewalld.service'} if unit == GUARD else set())
    require(after.issubset(set(v['After'].split())) and
            not any(x.startswith('aifinance-') and x not in after for x in v['After'].split()),
            'effective_after_dependency_mismatch')
    mounts = {'/var/tmp'} | ({'/run/aifinance-preview-egress'} if unit == GUARD else
                            {'/run/aifinance-preview-db'} if unit == DB else set())
    # Exactly the observed v239 default dependencies, not arbitrary services or
    # mounts. check_units verifies the already-active generated root mount first.
    require(set(v['Requires'].split()) == {'-.mount', 'system.slice', 'sysinit.target'} and
            v['Slice'] == 'system.slice' and v['DefaultDependencies'] == 'yes' and
            set(v['RequiresMountsFor'].split()) == mounts and
            all(not v[key] for key in ('Wants', 'Requisite', 'OnFailure', 'Environment', 'EnvironmentFiles', 'PassEnvironment')),
            'unexpected_activation_or_environment_dependency')
    starts = {API: '/usr/bin/python3 -I /opt/aifinance/bin/run-preview.py api',
              WEB: '/usr/bin/python3 -I /opt/aifinance/bin/run-preview.py web',
              DB: '/usr/pgsql-17/bin/postgres -D /var/lib/pgsql/aifinance-preview -c config_file=/etc/aifinance-preview-db/postgresql.conf',
              GUARD: '/usr/bin/python3 -I -B /opt/aifinance/bin/egress-guard.py start'}
    exact_exec(v['ExecStart'], starts[unit])
    for hook in HOOKS:
        if app and hook == 'ExecStartPre':
            exact_exec(v[hook], '/usr/bin/python3 -I -B /opt/aifinance/bin/egress-guard.py verify')
        elif unit == GUARD and hook == 'ExecStop':
            exact_exec(v[hook], '/usr/bin/python3 -I -B /opt/aifinance/bin/egress-guard.py stop')
        else:
            require(not v[hook], 'unexpected_loaded_service_hook')
    budget = {API: 320, WEB: 256, DB: 256, GUARD: 64}[unit]
    require(v['MemoryAccounting'] == 'yes' and v['MemoryLimit'] == str(budget * 1024 ** 2) and
            v['TasksMax'] == ('16' if unit == GUARD else '64') and
            v['Restart'] == ('on-failure' if app else 'no'), 'effective_resource_or_restart_mismatch')


def check_units():
    with checking('-.mount'):
        expected = dict(LoadState='loaded', ActiveState='active', FragmentPath='/run/systemd/generator/-.mount',
                        SourcePath='/etc/fstab', Where='/', DropInPaths='')
        require(properties('-.mount', tuple(expected)) == expected, 'reviewed_active_root_mount_required')
    for unit in UNITS:
        with checking(unit):
            check_unit(unit)
    jobs = command([CTL, 'list-jobs', '--no-legend', '--no-pager', '--plain'])
    require(not any('aifinance' in line for line in jobs.splitlines()), 'pending_aifinance_job')


def collector_idle():
    keys = ('LoadState', 'ActiveState', 'SubState', 'MainPID', 'ControlPID', 'UnitFileState')
    for mode in ('probe', 'check', 'seed', 'run'):
        v = properties('aifinance-collect-' + mode + '.service', keys)
        require(v['LoadState'] == 'loaded' and v['ActiveState'] == 'inactive' and v['SubState'] == 'dead' and
                v['MainPID'] == v['ControlPID'] == '0' and v['UnitFileState'] in ('static', 'disabled'),
                'collector_not_idle_after_boot')
    for name in ('aifinance-collect-hourly.service', 'aifinance-collect-hourly.timer'):
        # Timer units have no service PID properties on systemd 239.
        keys = ('LoadState', 'ActiveState', 'SubState', 'FragmentPath', 'DropInPaths')
        v = properties(name, keys)
        require(v['LoadState'] == 'not-found' and v['ActiveState'] == 'inactive' and v['SubState'] == 'dead' and
                not v['FragmentPath'] and not v['DropInPaths'], 'collector_timer_not_absent')
        for root in (SYSTEM, Path('/run/systemd/system'), Path('/usr/lib/systemd/system')):
            for path in (root / name, root / (name + '.d'), root / 'timers.target.wants' / name):
                absent(path, 'collector_timer_file_present')
    rows = command([CTL, 'list-units', '--all', '--plain', '--no-legend', '--no-pager', 'aifinance*'])
    for line in rows.splitlines():
        fields = line.split()
        require(len(fields) >= 4, 'invalid_aifinance_unit_list')
        require(fields[0] in UNITS or fields[2] not in ('active', 'activating', 'reloading', 'deactivating'),
                'unreviewed_aifinance_service_active')


def tables(guard_allowed=False):
    value = document(command(['/usr/sbin/nft', '--json', 'list', 'tables']).encode())
    require(isinstance(value.get('nftables'), list), 'invalid_nft_table_list')
    forbidden = {'aifinance_collect_egress_v1', 'aifinance_preview_probe'}
    if not guard_allowed:
        forbidden.add('aifinance_preview_egress_v1')
    for item in value['nftables']:
        require(isinstance(item, dict) and len(item) == 1, 'invalid_nft_table_entry')
        if 'metainfo' in item:
            continue
        table = item.get('table')
        require(isinstance(table, dict) and isinstance(table.get('family'), str) and
                isinstance(table.get('name'), str), 'invalid_nft_table_entry')
        require(table['name'] not in forbidden, 'unexpected_preview_or_collector_nft_table')


def release_check(fp):
    release_parents(); selected = ROOT / 'state/current'; release = ROOT / 'releases' / RELEASE
    require(selected.is_symlink() and selected.resolve(strict=True) == release, 'current_release_mismatch')
    absent(ROOT / 'state/.current-next'); absent(ROOT / 'shared/native-ready')
    for parent, dirs, files in os.walk(str(release), followlinks=False):
        for path in [Path(parent)] + [Path(parent) / name for name in dirs + files]:
            info = path.lstat()
            require(info.st_uid == info.st_gid == 0, 'release_not_root_owned')
            if stat.S_ISLNK(info.st_mode):
                require(release in path.resolve(strict=True).parents, 'release_symlink_escape')
            else:
                require((stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o555) or
                        (stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) in (0o444, 0o555)),
                        'release_not_immutable')
    require(read(release / 'RELEASE_SHA', 64, parents=False).decode().strip() == RELEASE, 'release_label_mismatch')
    manifest, names = fp.schema(release)
    require(sha(manifest.encode()) == SCHEMA and read(ROOT / 'shared/schema.sha256') == manifest.encode(),
            'immutable_or_shared_schema_mismatch')
    require((release / 'apps/web/build/server/index.js').is_file() and (release / 'node_modules').is_dir(),
            'existing_production_build_missing')
    return sorted(names)


def configuration():
    # Exact provision-database.py.configuration() bytes (baa27c22...), no includes.
    return ("data_directory = '/var/lib/pgsql/aifinance-preview'\nhba_file = '/etc/aifinance-preview-db/pg_hba.conf'\n"
            "ident_file = '/etc/aifinance-preview-db/pg_ident.conf'\nlisten_addresses = '127.0.0.1'\nport = 55432\n"
            "unix_socket_directories = '/run/aifinance-preview-db'\nunix_socket_permissions = 0700\n"
            "password_encryption = 'scram-sha-256'\nmax_connections = 12\nsuperuser_reserved_connections = 3\n"
            "shared_buffers = '32MB'\nwork_mem = '1MB'\nmaintenance_work_mem = '16MB'\n"
            "autovacuum_max_workers = 1\nautovacuum_work_mem = '8MB'\nwal_buffers = '1MB'\n"
            "min_wal_size = '64MB'\nmax_wal_size = '128MB'\nmax_worker_processes = 0\nmax_parallel_workers = 0\n"
            "max_parallel_workers_per_gather = 0\ntemp_file_limit = '64MB'\nhuge_pages = off\njit = off\nssl = off\n"
            "log_statement = 'none'\nlog_min_duration_statement = -1\nlog_min_duration_sample = -1\n"
            "log_transaction_sample_rate = 0\nlog_min_error_statement = 'panic'\nlog_parameter_max_length = 0\n"
            "log_parameter_max_length_on_error = 0\nlogging_collector = off\nlog_destination = 'stderr'\n")


HBA = ('local all postgres peer\nlocal all all reject\n'
       'host aifinance_preview aifinance_preview 127.0.0.1/32 scram-sha-256\n'
       'host all all 0.0.0.0/0 reject\nhost all all ::0/0 reject\n')


def database_files():
    trusted_dir(PGCONFIG, 0o750, 26)
    result = {}
    for name, expected in (('postgresql.conf', configuration()), ('pg_hba.conf', HBA), ('pg_ident.conf', '')):
        path = PGCONFIG / name
        with checking(name):
            raw = read(path, mode=0o640, gid=26)
            require(raw == expected.encode('ascii'), 'database_fixed_configuration_mismatch')
        result[str(path)] = dict(attributes(path.lstat()), sha256=sha(raw))
    trusted_dir(PGDATA.parent.parent)
    parent = PGDATA.parent.lstat()
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid in (0, 26) and parent.st_gid in (0, 26) and
            not parent.st_mode & 0o022, 'pgdata_parent_mismatch')
    info = PGDATA.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 26 and
            stat.S_IMODE(info.st_mode) == 0o700, 'existing_pgdata_owner_mode_mismatch')
    require(read(PGDATA / 'PG_VERSION', 32, mode=0o600, uid=26, gid=26, parents=False) == b'17\n',
            'existing_pgdata_version_mismatch')
    auto = read(PGDATA / 'postgresql.auto.conf', 16384, mode=0o600, uid=26, gid=26, parents=False)
    require(all(not line.strip() or line.lstrip().startswith(b'#') for line in auto.splitlines()),
            'database_auto_conf_startup_hook_refused')
    for name in ('postmaster.pid', 'recovery.signal', 'standby.signal', 'recovery.conf', 'backup_label'):
        absent(PGDATA / name, 'database_startup_or_recovery_marker_present')
    absent(Path('/run/aifinance-preview-db'), 'database_runtime_already_exists')
    for tool in ('postgres', 'pg_isready', 'psql'):
        path = Path('/usr/pgsql-17/bin') / tool
        read(path, maximum=64 * 1024 ** 2)
        require(command([str(path), '--version']) == tool + ' (PostgreSQL) 17.11', 'postgresql_17_11_required')
    return result


def preserved_state():
    trusted_dir(COLLECT, 0o700); trusted_dir(OPS, 0o700)
    present = {p.name for p in COLLECT.iterdir()}
    require(set(COLLECT_SIZES).issubset(present) and all(name in COLLECT_SIZES or
            re.fullmatch(r'probe-[0-9]+-[0-9a-f]{12}\.json', name) for name in present), 'collector_history_set_changed')
    result, contents = {}, {}
    for name, size in COLLECT_SIZES.items():
        path = COLLECT / name; raw = read(path, mode=0o600)
        require(len(raw) == size, 'collector_history_size_changed')
        result[str(path)] = dict(attributes(path.lstat()), sha256=sha(raw))
        contents[name] = raw
    require(document(contents['installed.json']) == {'release': RELEASE, 'uid': 986}, 'collector_install_receipt_mismatch')
    require(document(contents['network.json']) == {'uid': 986, 'hosts': {}}, 'collector_network_receipt_mismatch')
    attempt = document(contents['seed-attempt.json'])
    require(set(attempt) == {'release', 'mode', 'started'} and attempt['release'] == RELEASE and attempt['mode'] == 'seed' and
            type(attempt['started']) is int and attempt['started'] > 0, 'historical_seed_attempt_mismatch')
    validate_probe(document(contents['probe.json']))
    for name in sorted(present - set(COLLECT_SIZES)):
        path = COLLECT / name; raw = read(path, mode=0o600)
        validate_probe(document(raw))
        result[str(path)] = dict(attributes(path.lstat()), sha256=sha(raw))
    docs = {}
    for name in ('policy.json', 'install.json', 'complete.json'):
        path = OPS / name; raw = read(path, mode=0o600)
        result[str(path)] = dict(attributes(path.lstat()), sha256=sha(raw)); docs[name] = document(raw)
    expected = dict(schema=1, broker_sha256=HELPER_PINS['ops-broker.py'], runner_sha256=HELPER_PINS['collect-only-runner.py'],
                    upgrade_sha256=HELPER_PINS['collect-only-upgrade.py'], app_release=RELEASE, actions=ACTIONS)
    require(docs['policy.json'] == expected and docs['complete.json'] ==
            dict(schema=1, status='complete', broker_sha256=expected['broker_sha256'], app_release=RELEASE),
            'persistent_ops_policy_or_completion_mismatch')
    history = docs['install.json']; baseline = history.get('recovery_baseline', {})
    require(history.get('application_release') == RELEASE and history.get('actions') == ACTIONS and
            baseline.get('attempt_sha256') == sha(contents['seed-attempt.json']) and
            baseline.get('attempt_started') == attempt['started'] and baseline.get('collector_gid') == 986,
            'persistent_ops_install_baseline_mismatch')
    for name in ('recovery.json', 'pre-seed-attempt-v1.json', 'recovery.json.next', 'nss-proof-v1-update'):
        absent(OPS / name, 'collector_recovery_or_update_already_present')
    trusted_dir(COLLECT_CONFIG, 0o750, 986)
    collector_env = metadata(COLLECT_CONFIG / 'database.env', 0, 0, 0o400, 8192)
    require(collector_env['device'] == baseline.get('db_device') and collector_env['inode'] == baseline.get('db_inode'),
            'collector_database_file_identity_changed')
    result[str(COLLECT_CONFIG / 'database.env')] = collector_env
    result[str(APP_ENV)] = metadata(APP_ENV, 0, 989, 0o640, 8192)
    gate_path = MAINTENANCE / 'collect-only-upgrade.json'; raw = read(gate_path, mode=0o600)
    gate = document(raw)
    require(gate.get('status') == 'healthy' and gate.get('release') == RELEASE and gate.get('restore_verified') is True,
            'persistent_upgrade_acceptance_missing')
    result[str(gate_path)] = dict(attributes(gate_path.lstat()), sha256=sha(raw))
    return result


def validate_probe(probe):
    # Same accepted report shape as the historical installer, with fixed UID986.
    require(set(probe) == {'mode', 'elapsed_seconds', 'samples', 'output'} and probe['mode'] == 'probe' and
            probe['output'] == {} and type(probe['elapsed_seconds']) in (int, float) and
            0 < probe['elapsed_seconds'] <= 120 and isinstance(probe['samples'], list) and
            1 <= len(probe['samples']) <= 1024, 'historical_probe_receipt_mismatch')
    fixed = dict(User='aifinance-collect', MemoryAccounting='yes', MemoryLimit=str(256 * 1024 ** 2),
                 TasksMax='32', TimeoutStartUSec='2min')
    counters = {'memory.limit_in_bytes', 'memory.usage_in_bytes', 'memory.max_usage_in_bytes',
                'memory.failcnt', 'pids.max', 'pids.current', 'pid', 'uid'}
    for sample in probe['samples']:
        require(isinstance(sample, dict) and set(sample) == {'properties', 'kernel', 'resolver'} and
                sample['resolver'] is None, 'historical_probe_sample_mismatch')
        props, kernel = sample['properties'], sample['kernel']
        require(isinstance(props, dict) and set(props) == set(fixed) | {'MainPID'} and
                all(props[k] == value for k, value in fixed.items()) and isinstance(kernel, dict) and
                set(kernel) == counters | {'cgroup'} and
                all(type(kernel[k]) is int and kernel[k] >= 0 for k in counters) and
                kernel['pid'] > 1 and props['MainPID'] == str(kernel['pid']) and kernel['uid'] == 986 and
                kernel['cgroup'] == '/system.slice/aifinance-collect-probe.service' and
                kernel['memory.limit_in_bytes'] == 256 * 1024 ** 2 and kernel['memory.failcnt'] == 0 and
                kernel['memory.usage_in_bytes'] < 256 * 1024 ** 2 and kernel['memory.max_usage_in_bytes'] < 256 * 1024 ** 2 and
                kernel['pids.max'] == 32 and 1 <= kernel['pids.current'] <= 32, 'historical_probe_resource_mismatch')


def boot(expected):
    require(re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}', expected or '') is not None,
            'explicit_reviewed_boot_id_required')
    require((PROC / 'sys/kernel/random/boot_id').read_text().strip() == expected, 'boot_id_mismatch')


def guard_verify():
    return document(command(['/usr/bin/python3', '-I', '-B', str(BIN / 'egress-guard.py'), 'verify']).encode())


def listeners(fp, running=False):
    value = fp.listeners()
    require(not value['8000'], 'port_8000_must_remain_absent')
    for port in ('3100', '3101', '55432'):
        if running:
            require(value[port] and all(address == '0100007F' for address, inode in value[port]),
                    'preview_listener_not_exact_ipv4_loopback')
        else:
            require(not value[port], 'preview_listener_already_present')
    return value


def sync(path):
    fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path, raw):
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        os.fchown(stream.fileno(), 0, 0); os.fchmod(stream.fileno(), 0o600)
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    sync(path.parent)


def safe_error(error):
    if isinstance(error, Refused):
        return error.reason
    if isinstance(error, BlockingIOError):
        return 'canonical_release_lock_busy'
    if isinstance(error, (KeyboardInterrupt, InterruptedError)):
        return 'administrator_run_interrupted'
    if isinstance(error, subprocess.TimeoutExpired):
        return 'fixed_command_timeout'
    if isinstance(error, subprocess.CalledProcessError):
        return 'fixed_command_exit_nonzero'
    if isinstance(error, OSError):
        return 'filesystem_or_process_error_errno_' + str(error.errno or 0)
    # Imported helper exception messages may include values; publish only stage.
    return 'stage_validation_failed'


def acceptance_failure(evidence):
    try:
        raw = read(evidence / 'guard-acceptance.log', maximum=262144, mode=0o600)
        matches = re.findall(rb'^STOP: postboot acceptance command failed at line ([0-9]{1,4}) \(status ([0-9]{1,3})\)$', raw, re.M)
        if matches:
            line, status = map(int, matches[-1])
            if 1 <= line <= 269 and 1 <= status <= 255:
                return dict(acceptance_failed_line=line, acceptance_exit_status=status)
    except (OSError, Refused):
        pass
    return {}


class Recovery:
    def __init__(self, expected_boot):
        self.expected_boot = expected_boot
        self.evidence = Path('/var/lib/aifinance-preview-recovery-' + expected_boot)
        self.stage = 'entry'; self.started = []; self.writing = False; self.event_number = 0
        self.database_start_requested = False

    def event(self, value):
        if self.writing:
            self.event_number += 1
            write_new(self.evidence / ('%02d-%s.json' % (self.event_number, self.stage)),
                      (json.dumps(value, sort_keys=True) + '\n').encode('ascii'))

    def step(self, stage, function, *args):
        self.stage = stage
        return function(*args)

    def preflight(self):
        self.step('boot', boot, self.expected_boot)
        self.fp = self.step('helpers', pinned_helpers)
        self.step('accounts', accounts)
        self.step('units', check_units)
        self.step('collector_idle', collector_idle)
        self.step('processes', no_processes)
        self.step('release', release_check, self.fp)
        self.step('database_files', database_files)
        self.before = self.step('persistent_state', preserved_state)
        self.step('guard_absence', absent, GUARD_RUNTIME, 'guard_runtime_or_receipt_already_present')
        self.step('guard_absence', absent, ACCEPTANCE, 'guard_acceptance_already_attempted')
        self.step('guard_absence', tables)
        self.step('listeners', listeners, self.fp)
        self.step('evidence_absence', absent, self.evidence, 'recovery_evidence_exists_no_automatic_retry')
        trusted_dir(self.evidence.parent)
        self.stage = 'resources'
        memory = re.search(r'^MemAvailable:\s+(\d+) kB$', (PROC / 'meminfo').read_text(), re.M)
        require(memory is not None and int(memory.group(1)) >= 700 * 1024, 'memory_reserve_below_700_mib')
        require(os.statvfs(str(PGDATA)).f_bavail * os.statvfs(str(PGDATA)).f_frsize >= 1024 ** 3,
                'database_free_space_below_one_gib')

    def copy_acceptance(self):
        if not ACCEPTANCE.exists():
            return
        trusted_dir(ACCEPTANCE, 0o700)
        target = self.evidence / 'guard-acceptance'; target.mkdir(mode=0o700)
        files = list(ACCEPTANCE.iterdir()); require(len(files) <= 128, 'guard_evidence_file_limit')
        total = 0
        for path in files:
            raw = read(path, maximum=1048576, mode=0o600); total += len(raw)
            require(total <= 8 * 1024 ** 2, 'guard_evidence_total_limit')
            write_new(target / path.name, raw)
        sync(self.evidence)

    def preserved(self):
        require(preserved_state() == self.before, 'persistent_state_changed')
        collector_idle(); tables(guard_allowed=True)

    def start(self, unit):
        v = properties(unit, ('ActiveState', 'MainPID', 'ControlPID'))
        require(v == dict(ActiveState='inactive', MainPID='0', ControlPID='0'), 'unit_changed_before_start')
        if unit in (API, WEB):
            guard_verify()
            # A start command can partially launch before reporting failure.
            self.started.append(unit)
        if unit == DB:
            self.database_start_requested = True
        command([CTL, 'start', unit], timeout=45)
        self.event({'start_requested': unit})

    def database_ready(self):
        for attempt in range(30):
            require(properties(DB, ('ActiveState',))['ActiveState'] == 'active', 'existing_database_start_failed')
            try:
                command(['/usr/pgsql-17/bin/pg_isready', '-h', '/run/aifinance-preview-db', '-p', '55432', '-t', '1'])
                break
            except Refused:
                if attempt == 29:
                    raise Refused('existing_database_readiness_timeout')
                time.sleep(1)
        # Pinned helper constructs its own application login internally. Force a
        # read-only session, never query application-owned objects as postgres.
        proof = self.fp.query("SELECT pg_catalog.current_database(), current_user, pg_catalog.current_setting('transaction_read_only'), "
            "EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname=current_user AND r.rolcanlogin "
            "AND NOT (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls) "
            "AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member=r.oid)), "
            "EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
            "JOIN pg_catalog.pg_roles r ON r.oid=c.relowner WHERE n.nspname='public' AND c.relname='schema_migrations' "
            "AND c.relkind='r' AND r.rolname=current_user)", app=True)
        require(proof == 'aifinance_preview|aifinance_preview|on|t|t', 'database_read_only_role_or_ledger_identity_mismatch')
        names = self.fp.query('SELECT pg_catalog.left(name::pg_catalog.text, 256) FROM public.schema_migrations ORDER BY name LIMIT 1000', app=True).splitlines()
        require(names == release_check(self.fp), 'existing_database_migration_ledger_mismatch')

    def apply(self, source):
        self.stage = 'evidence_create'; self.evidence.mkdir(mode=0o700); self.writing = True
        sync(self.evidence.parent)
        self.event({'release': RELEASE, 'boot_id': self.expected_boot, 'preserved_before': self.before})
        self.stage = 'guard_acceptance'
        # The acceptance script alone creates/starts the guard after its baseline.
        log = self.evidence / 'guard-acceptance.log'
        fd = os.open(str(log), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, 'wb') as out:
                command(['/usr/bin/bash', str(source / 'accept-egress-after-boot.sh')], timeout=300, output=out)
                out.flush(); os.fsync(out.fileno())
        finally:
            self.copy_acceptance()
        require(read(ACCEPTANCE / 'result.txt', mode=0o600) == b'probe_passed=true\napplication_accepted=false\n',
                'real_guard_acceptance_not_passed')
        self.step('guard_verify', guard_verify)
        self.step('preserved_before_database', self.preserved)
        self.step('database_start', self.start, DB)
        self.step('database_readiness', self.database_ready)
        self.step('api_start', self.start, API)
        self.step('web_start', self.start, WEB)
        self.step('health', self.fp.health, RELEASE)
        ports = self.step('listener_acceptance', listeners, self.fp, True)
        resources = self.step('resource_acceptance', self.fp.resource_evidence)
        self.step('guard_final', guard_verify)
        self.step('boot_final', boot, self.expected_boot)
        self.step('release_final', release_check, self.fp)
        self.step('preserved_final', self.preserved)
        self.stage = 'complete'
        self.event({'website_healthy': True, 'resources': resources, 'listeners': ports,
                    'preserved_after': self.before, 'collector_started': False, 'native_ready_written': False})

    def cleanup(self):
        result = {}
        # Only starts requested by this invocation. Keep DB, guard, receipts and
        # every evidence file for review; no restart, reset-failed or blind retry.
        for unit in reversed(self.started):
            try:
                command([CTL, 'stop', unit], timeout=40)
                v = properties(unit, ('ActiveState', 'MainPID', 'ControlPID'))
                result[unit] = v['ActiveState'] in ('inactive', 'failed') and v['MainPID'] == v['ControlPID'] == '0'
            except Exception:
                result[unit] = False
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('check', 'apply'), nargs='?', default='check')
    parser.add_argument('--script-sha256', required=True)
    parser.add_argument('--expected-boot-id', required=True)
    args = parser.parse_args(argv)
    recovery = Recovery(args.expected_boot_id)
    try:
        require(sys.version_info >= (3, 6, 8) and os.getuid() == os.geteuid() == os.getegid() == 0 and
                sys.flags.isolated and sys.dont_write_bytecode and not os.environ.get('SSH_ORIGINAL_COMMAND') and
                not os.environ.get('SUDO_USER'), 'isolated_root_entry_required')
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0)); os.umask(0o077)
        source = recovery.step('source', source_inputs, args.script_sha256)
        recovery.stage = 'lock'
        with release_lock(args.action == 'apply'):
            try:
                recovery.preflight()
                if args.action == 'apply':
                    recovery.apply(source)
            except BaseException as error:
                return failed(recovery, args.action, error)
        result = dict(ok=True, action=args.action, stage='complete', release=RELEASE,
                      website_healthy=args.action == 'apply', collector_started=False, native_ready_written=False)
        if recovery.writing:
            result['evidence_directory'] = str(recovery.evidence)
        print(json.dumps(result, sort_keys=True))
        return 0
    except BaseException as error:
        return failed(recovery, args.action, error)


def failed(recovery, action, error):
    if isinstance(error, SystemExit):
        raise error
    stage = recovery.stage
    # Ignore subsequent terminal signals during this bounded cleanup. The lock
    # stays held through stop checks and final evidence when apply has begun.
    handlers = [(sig, signal.signal(sig, signal.SIG_IGN)) for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)]
    try:
        cleanup = recovery.cleanup() if recovery.writing else {}
        result = dict(ok=False, action=action, stage=stage, reason=safe_error(error),
                      application_cleanup=cleanup, evidence_preserved=recovery.writing,
                      guard_not_removed=True, database_not_reset=True,
                      database_start_requested=recovery.database_start_requested, automatic_retry=False)
        if isinstance(error, Refused) and error.target:
            result['object'] = error.target
        if recovery.writing:
            result['evidence_directory'] = str(recovery.evidence)
            if stage == 'guard_acceptance':
                result.update(acceptance_failure(recovery.evidence))
        try:
            recovery.stage = 'failure'; recovery.event(result)
        except Exception:
            result['failure_evidence_write_failed'] = True
        print(json.dumps(result, sort_keys=True))
        return 1
    finally:
        for sig, handler in handlers:
            signal.signal(sig, handler)


if __name__ == '__main__':
    def interrupted(signum, frame):
        raise InterruptedError('administrator_run_interrupted')
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupted)
    sys.exit(main())
