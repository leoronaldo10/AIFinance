#!/usr/bin/python3
"""One-time, reviewed root-terminal installer; Python 3.6/systemd 239.

The pinned downloader supplies exactly five files in a unique root-only SOURCE.
check is read-only; apply never runs a collector, alters credentials/network,
restarts services, or creates native-ready. It replaces only the reviewed
collector runner and its four templates to require an already-running database.
This installer is
never an SSH verb or sudo permission. Partial installs require administrator
review: preserve SOURCE, /var/lib/aifinance-ops and any *.ops-v1.next files.
Before the final gateway rename, the old gateway remains unchanged. Recovery
holds the same lock and requires no active operations or collection since the
backup. Verify every old/new hash, reconcile the runner and all four units as
one set from root-only backups, daemon-reload and verify that set; restore the
old gateway only if its live hash is the approved new hash, and archive only
this install's exact sudo fragment. Unknown files or post-install operations
require fresh review. Never remove evidence or retry apply on partial state.
"""
import argparse
import base64
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
import struct
import subprocess
import sys
import time
import types

ROOT = Path('/opt/aifinance')
BIN = ROOT / 'bin'
STATE = Path('/var/lib/aifinance-ops')
COLLECT = Path('/var/lib/aifinance-maintenance/collect-only')
CONFIG = Path('/etc/aifinance-collect')
SUDO_DIR = Path('/etc/sudoers.d')
SUDO_OLD = SUDO_DIR / 'aifinance-preview'
SUDO_NEW = SUDO_DIR / 'aifinance-ops-v1'
SUDO_NEXT = SUDO_DIR / '.aifinance-ops-v1.ops-v1.next'
GATEWAY = BIN / 'ssh-gateway.py'
GATEWAY_NEXT = BIN / '.ssh-gateway.py.ops-v1.next'
BROKER = BIN / 'ops-broker.py'
RUNNER_PATH = BIN / 'collect-only-runner.py'
RUNNER_NEXT = BIN / '.collect-only-runner.py.ops-v1.next'
SYSTEM = Path('/etc/systemd/system')
CTL = '/usr/bin/systemctl'
VISUDO = '/usr/sbin/visudo'
SSHD = '/usr/sbin/sshd'
PASSWD = '/usr/bin/passwd'
DEPLOY_HOME = Path('/var/lib/aifinance-deploy')
APP = 'd57ba047369e666025347719caee1a4c642abe62'
OLD_GATEWAY = 'd5f87fa494475c2686e9cc19bf3f00c06f9984205d6f840e52ad7ac9841ce6c6'
OLD_RUNNER = 'ebc68aa6e7b3512e52735ab4114a81035c3da2f71a385d5192bb8e7825d9501d'
NEW_RUNNER = '7555b956d26f93c2829683008a3f78f71e1e122d21f6c2fc25bcf3d222769cdf'
UPGRADE = '9eb61d5b9357a31ed319202efd14ffedbc591aac1fe090179f719246971dfca5'
ACTIONS = ('diagnose', 'restart-preview', 'probe', 'recover-pre-seed', 'seed', 'run', 'disable', 'enable-hourly')
OLD_RULE = b'aifinance-deploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart aifinance-preview-api.service aifinance-preview-web.service\n'
ENV = dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin', HOME='/', LANG='C', LC_ALL='C')
SOURCE_PATTERN = r'/root/aifinance-ops-v1-[A-Za-z0-9]{12}'
SOURCE_FILES = frozenset(('install-ops.py', 'ops-broker.py', 'ops-gateway.py', 'collect-only-runner.py', 'manifest.json'))
UNIT_DIRS = tuple(Path(p) for p in ('/etc/systemd/system', '/run/systemd/system', '/usr/lib/systemd/system'))
ACCEPT_ENV = frozenset(('LANG', 'LANGUAGE', 'XMODIFIERS', 'LC_*', 'LC_CTYPE',
    'LC_NUMERIC', 'LC_TIME', 'LC_COLLATE', 'LC_MONETARY', 'LC_MESSAGES', 'LC_PAPER',
    'LC_NAME', 'LC_ADDRESS', 'LC_TELEPHONE', 'LC_MEASUREMENT', 'LC_IDENTIFICATION', 'LC_ALL'))
ACCESS_TIMEOUT = 10


def sha(data):
    return hashlib.sha256(data).hexdigest()


def safe_directory(path, mode=None, gid=0):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('absolute_canonical_path_required')
    for item in (path,) + tuple(path.parents):
        info = item.lstat()
        expected_gid = gid if item == path else 0
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != expected_gid or
                info.st_mode & 0o022 or (item == path and mode is not None and stat.S_IMODE(info.st_mode) != mode)):
            raise ValueError('unsafe_root_directory')


def read_file(path, mode=None, gid=0, maximum=262144, parent_gid=0):
    path = Path(path)
    safe_directory(path.parent, gid=parent_gid)
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        current = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0 or info.st_gid != gid or
                info.st_mode & 0o022 or info.st_size > maximum or
                (mode is not None and stat.S_IMODE(info.st_mode) != mode) or
                (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino)):
            raise ValueError('unsafe_root_file')
        chunks, total = [], 0
        while True:
            part = os.read(fd, min(65536, maximum + 1 - total))
            if not part:
                break
            chunks.append(part); total += len(part)
            if total > maximum:
                raise ValueError('file_size_limit')
        after = os.fstat(fd)
        if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('file_changed_while_reading')
        return b''.join(chunks)
    finally:
        os.close(fd)


def absent(path):
    try:
        path.lstat()
    except FileNotFoundError:
        return
    raise ValueError('existing_or_partial_install_requires_review')


def unique_json(data):
    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise ValueError('duplicate_json_key')
            result[key] = value
        return result
    return json.loads(data.decode('utf-8', 'strict'), object_pairs_hook=pairs)


def load_source(source, manifest_sha):
    if not re.fullmatch(SOURCE_PATTERN, str(source)) or not re.fullmatch(r'[0-9a-f]{64}', manifest_sha):
        raise ValueError('fixed_source_and_manifest_pin_required')
    safe_directory(source, 0o700)
    if set(p.name for p in source.iterdir()) != SOURCE_FILES:
        raise ValueError('exact_source_files_required')
    raw = read_file(source / 'manifest.json', 0o600, maximum=4096)
    if sha(raw) != manifest_sha:
        raise ValueError('manifest_hash_mismatch')
    manifest = unique_json(raw)
    keys = {'schema', 'installer_sha256', 'broker_sha256', 'gateway_sha256', 'runner_sha256'}
    if (not isinstance(manifest, dict) or set(manifest) != keys or type(manifest['schema']) is not int or
            manifest['schema'] != 1 or any(not isinstance(manifest[k], str) or
            not re.fullmatch(r'[0-9a-f]{64}', manifest[k]) for k in keys - {'schema'})):
        raise ValueError('exact_manifest_schema_required')
    contents = {}
    for name, key in (('install-ops.py', 'installer_sha256'), ('ops-broker.py', 'broker_sha256'), ('ops-gateway.py', 'gateway_sha256'),
                      ('collect-only-runner.py', 'runner_sha256')):
        content = read_file(source / name, 0o600)
        if sha(content) != manifest[key]:
            raise ValueError('reviewed_source_hash_mismatch')
        compile(content, name, 'exec')
        contents[name] = content
    if manifest['gateway_sha256'] == OLD_GATEWAY:
        raise ValueError('new_reviewed_gateway_required')
    if manifest['runner_sha256'] != NEW_RUNNER:
        raise ValueError('new_reviewed_runner_required')
    return manifest, contents


def sudo_rules():
    lines = []
    for action in ACTIONS:
        flag = ' --accept-admin-view' if action == 'enable-hourly' else ''
        lines.append('aifinance-deploy ALL=(root) NOPASSWD: NOSETENV: /usr/bin/python3 -I -B /opt/aifinance/bin/ops-broker.py ' + action + flag)
    return ('\n'.join(lines) + '\n').encode('ascii')


def trusted_executable(path):
    safe_directory(Path(path).parent)
    info = Path(path).lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022:
        raise ValueError('trusted_system_executable_required')


def validate_sudo(path):
    trusted_executable(VISUDO)
    subprocess.run([VISUDO, '-c', '-f', str(path)], stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=ENV,
                   cwd='/', timeout=10, check=True)


def access_output(args):
    trusted_executable(args[0])
    process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, env=ENV, cwd='/', start_new_session=True)
    selector = selectors.DefaultSelector(); selector.register(process.stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + ACCESS_TIMEOUT
    data = bytearray()
    try:
        while True:
            if not selector.select(max(0, deadline - time.monotonic())):
                raise ValueError('access_metadata_timeout')
            part = os.read(process.stdout.fileno(), 4096)
            if not part:
                break
            data.extend(part)
            if len(data) > 32768:
                raise ValueError('access_metadata_size_limit')
        if process.wait(timeout=max(.01, deadline - time.monotonic())) != 0:
            raise ValueError('access_metadata_command_failed')
        return data.decode('utf-8', 'strict')
    finally:
        selector.close(); process.stdout.close()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()


def deploy_account():
    deploy = pwd.getpwnam('aifinance-deploy')
    forbidden = {0} | {pwd.getpwnam(name).pw_uid for name in ('aifinance', 'postgres', 'aifinance-collect')}
    if (type(deploy.pw_uid) is not int or deploy.pw_uid <= 0 or deploy.pw_uid in forbidden or
            deploy.pw_name != 'aifinance-deploy' or deploy.pw_shell != '/bin/sh' or deploy.pw_dir != str(DEPLOY_HOME) or
            deploy.pw_gid <= 0 or deploy.pw_gid != grp.getgrnam('aifinance-deploy').gr_gid):
        raise ValueError('existing_deploy_identity_required')
    aliases = [(entry.pw_name, entry.pw_uid) for entry in pwd.getpwall()
               if entry.pw_uid == deploy.pw_uid or entry.pw_name == 'aifinance-deploy']
    if aliases != [('aifinance-deploy', deploy.pw_uid)]:
        raise ValueError('exclusive_deploy_uid_required')
    return deploy


def verify_access():
    deploy_account()
    safe_directory(DEPLOY_HOME, 0o755); safe_directory(DEPLOY_HOME / '.ssh', 0o755)
    for path in (DEPLOY_HOME / '.ssh/environment', DEPLOY_HOME / '.ssh/rc', DEPLOY_HOME / '.ssh/authorized_keys2'):
        absent(path)
    raw = read_file(DEPLOY_HOME / '.ssh/authorized_keys', 0o644, maximum=4096).decode('ascii', 'strict')
    prefix = 'restrict,command="/usr/bin/python3 -I /opt/aifinance/bin/ssh-gateway.py" ssh-ed25519 '
    if not raw.startswith(prefix) or not raw.endswith(' aifinance-actions\n') or len(raw.splitlines()) != 1:
        raise ValueError('original_forced_key_boundary_required')
    key = raw[len(prefix):-len(' aifinance-actions\n')]
    decoded = base64.b64decode(key.encode('ascii'), validate=True)
    header = struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32)
    if len(decoded) != len(header) + 32 or not decoded.startswith(header):
        raise ValueError('valid_original_ed25519_key_required')
    # Public key and status bytes remain private; never emit them or their hash.
    status = access_output([PASSWD, '--status', 'aifinance-deploy']).split()
    if len(status) < 2 or status[0] != 'aifinance-deploy' or status[1] not in ('L', 'LK'):
        raise ValueError('locked_deploy_password_required')
    rows = access_output([SSHD, '-T', '-C', 'user=aifinance-deploy,host=localhost,addr=127.0.0.1']).splitlines()
    settings = {}
    for row in rows:
        words = row.split()
        if not words:
            continue
        settings.setdefault(words[0], []).append(words[1:])
    for key, expected in (('permituserenvironment', ['no']), ('forcecommand', ['none']), ('authorizedkeyscommand', ['none'])):
        if settings.get(key) != [expected]:
            raise ValueError('existing_sshd_boundary_changed')
    files = settings.get('authorizedkeysfile', [])
    if len(files) != 1 or files[0] not in (['.ssh/authorized_keys'], ['.ssh/authorized_keys', '.ssh/authorized_keys2']):
        raise ValueError('fixed_authorized_keys_location_required')
    if any(value not in ACCEPT_ENV for row in settings.get('acceptenv', []) for value in row):
        raise ValueError('unsafe_sshd_environment_policy')


def load_runner():
    # Import only bytes that have already passed the fixed official digest.
    code = read_file(RUNNER_PATH, 0o755)
    if sha(code) != OLD_RUNNER or sha(read_file(BIN / 'collect-only-upgrade.py', 0o755)) != UPGRADE:
        raise ValueError('installed_helper_hash_mismatch')
    return runner_module(code, 'approved_ops_install_old_runner')


def runner_module(code, name):
    # The only callers supply either the fixed old hash or pinned SOURCE bytes.
    module = types.ModuleType(name)
    module.__file__ = str(RUNNER_PATH)
    exec(compile(code, module.__file__, 'exec'), module.__dict__)
    return module


@contextlib.contextmanager
def release_lock(runner):
    fd = runner.release_lock()
    try:
        info = os.fstat(fd); owner = pwd.getpwnam('aifinance-deploy')
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != owner.pw_uid or
                info.st_gid != owner.pw_gid or stat.S_IMODE(info.st_mode) != 0o644):
            raise ValueError('canonical_lock_metadata_changed')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        current = (ROOT / 'state/release.lock').lstat()
        if (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino):
            raise ValueError('canonical_lock_inode_changed')
        yield
    finally:
        os.close(fd)


def validate_probe(probe, uid):
    if (not isinstance(probe, dict) or set(probe) != {'mode', 'elapsed_seconds', 'samples', 'output'} or
            probe['mode'] != 'probe' or probe['output'] != {} or
            type(probe['elapsed_seconds']) not in (int, float) or not 0 < probe['elapsed_seconds'] <= 120 or
            not isinstance(probe['samples'], list) or not 1 <= len(probe['samples']) <= 1024):
        raise ValueError('original_valid_probe_receipt_required')
    fixed = {'User': 'aifinance-collect', 'MemoryAccounting': 'yes', 'MemoryLimit': str(256 * 1024 ** 2),
             'TasksMax': '32', 'TimeoutStartUSec': '2min'}
    counters = {'memory.limit_in_bytes', 'memory.usage_in_bytes', 'memory.max_usage_in_bytes',
                'memory.failcnt', 'pids.max', 'pids.current', 'pid', 'uid'}
    for sample in probe['samples']:
        if not isinstance(sample, dict) or set(sample) != {'properties', 'kernel', 'resolver'} or sample['resolver'] is not None:
            raise ValueError('original_probe_resource_evidence_required')
        properties, kernel = sample['properties'], sample['kernel']
        if (not isinstance(properties, dict) or set(properties) != set(fixed) | {'MainPID'} or
                any(properties[k] != value for k, value in fixed.items()) or not isinstance(kernel, dict) or
                set(kernel) != counters | {'cgroup'} or any(type(kernel[k]) is not int or kernel[k] < 0 for k in counters) or
                kernel['pid'] <= 1 or properties['MainPID'] != str(kernel['pid']) or kernel['uid'] != uid or
                kernel['cgroup'] != '/system.slice/aifinance-collect-probe.service' or
                kernel['memory.limit_in_bytes'] != 256 * 1024 ** 2 or kernel['memory.failcnt'] != 0 or
                kernel['memory.usage_in_bytes'] >= 256 * 1024 ** 2 or kernel['memory.max_usage_in_bytes'] >= 256 * 1024 ** 2 or
                kernel['pids.max'] != 32 or not 1 <= kernel['pids.current'] <= 32):
            raise ValueError('original_probe_resource_limits_required')


def collector_state(runner):
    runner.upgrade_gate(); runner.validate_release()
    user = runner.account()
    if type(user.pw_uid) is not int or user.pw_uid <= 0:
        raise ValueError('approved_collector_identity_required')
    safe_directory(COLLECT, 0o700)
    fixed_receipts = {'installed.json', 'network.json', 'probe.json', 'seed-attempt.json', 'output.json'}
    for path in COLLECT.iterdir():
        if path.name not in fixed_receipts and not re.fullmatch(r'probe-[0-9]+-[0-9a-f]{12}\.json', path.name):
            raise ValueError('unexpected_collector_history_requires_review')
        read_file(path, 0o600)
    safe_directory(CONFIG, 0o750, user.pw_gid)
    # Parsing is in memory; no credential, credential hash or raw error is emitted.
    runner.database_url(read_file(CONFIG / 'database.env', 0o400, parent_gid=user.pw_gid, maximum=8192).decode('utf-8', 'strict'))
    for name in ('hosts', 'nsswitch.conf'):
        read_file(CONFIG / name, 0o440, gid=user.pw_gid, parent_gid=user.pw_gid)
    runner.verify_units(); runner.verify_network(user); runner.no_processes(user.pw_uid)
    network = unique_json(read_file(COLLECT / 'network.json', 0o600))
    if not isinstance(network, dict) or type(network.get('uid')) is not int or network != {'uid': user.pw_uid, 'hosts': {}}:
        raise ValueError('disabled_db_only_network_required')
    for name in ('launch.json', 'seed.json', 'run.json', 'run-attempt.json', 'hourly-approved.json'):
        absent(COLLECT / name)
    installed = unique_json(read_file(COLLECT / 'installed.json', 0o600))
    if not isinstance(installed, dict) or type(installed.get('uid')) is not int or installed != {'release': APP, 'uid': user.pw_uid}:
        raise ValueError('original_collector_install_required')
    attempt_bytes = read_file(COLLECT / 'seed-attempt.json', 0o600)
    attempt = unique_json(attempt_bytes)
    if (not isinstance(attempt, dict) or set(attempt) != {'release', 'mode', 'started'} or
            attempt['release'] != APP or attempt['mode'] != 'seed' or type(attempt['started']) is not int or attempt['started'] <= 0):
        raise ValueError('original_failed_attempt_required')
    # Recovery independently repeats this proof and the no-side-effect SQL.
    probe = unique_json(read_file(COLLECT / 'probe.json', 0o600))
    validate_probe(probe, user.pw_uid)
    for mode in ('probe', 'check', 'seed', 'run'):
        unit = runner.unit_name(mode)
        if (runner.prop(unit, 'ActiveState') not in ('inactive', 'failed') or
                runner.prop(unit, 'SubState') not in ('dead', 'failed') or
                runner.prop(unit, 'MainPID') != '0' or runner.prop(unit, 'ControlPID') != '0'):
            raise ValueError('collector_must_be_idle')
        if mode in ('seed', 'run') and any(runner.prop(unit, field) != '0' for field in
                ('ExecMainPID', 'ExecMainStartTimestampMonotonic', 'ExecMainCode', 'ExecMainStatus')):
            raise ValueError('seed_or_run_must_never_have_started')
    check_unit = runner.unit_name('check')
    if runner.prop(check_unit, 'ExecMainCode') != '2' or runner.prop(check_unit, 'ExecMainStatus') != '15':
        raise ValueError('reviewed_pre_seed_failure_required')
    check_start = runner.prop(check_unit, 'ExecMainStartTimestampMonotonic')
    check_exit = runner.prop(check_unit, 'ExecMainExitTimestampMonotonic')
    if (not re.fullmatch(r'[1-9][0-9]{0,19}', check_start) or not re.fullmatch(r'[1-9][0-9]{0,19}', check_exit) or
            int(check_exit) < int(check_start)):
        raise ValueError('original_check_timestamps_required')
    for name in ('aifinance-collect-hourly.service', 'aifinance-collect-hourly.timer'):
        for directory in UNIT_DIRS:
            absent(directory / name); absent(directory / (name + '.d'))
            absent(directory / 'timers.target.wants' / name)
        if (runner.prop(name, 'LoadState') != 'not-found' or runner.prop(name, 'FragmentPath') or
                runner.prop(name, 'DropInPaths') or runner.prop(name, 'MainPID') not in ('', '0')):
            raise ValueError('hourly_unit_must_be_absent')
    db = (CONFIG / 'database.env').lstat()
    return {'attempt_sha256': sha(attempt_bytes), 'attempt_started': attempt['started'],
            'check_start_monotonic': check_start, 'check_exit_monotonic': check_exit,
            'db_device': db.st_dev, 'db_inode': db.st_ino, 'collector_gid': user.pw_gid}


def unit_stage(name):
    return SYSTEM / ('.' + name + '.ops-v1.next')


def replacement_units(runner, replacement):
    old_units, new_units = {}, {}
    safe_directory(SYSTEM)
    for mode in ('probe', 'check', 'seed', 'run'):
        name = runner.unit_name(mode)
        absent(unit_stage(name))
        old = runner.unit_text(mode).encode('ascii')
        expected_line = b'Requires=aifinance-preview-db.service\n'
        if old.count(expected_line) != 1:
            raise ValueError('original_collector_dependency_required')
        new = replacement.unit_text(mode).encode('ascii')
        if new != old.replace(expected_line, b'Requisite=aifinance-preview-db.service\n'):
            raise ValueError('only_collector_database_requisite_change_allowed')
        if read_file(SYSTEM / name, 0o644) != old:
            raise ValueError('original_collector_unit_changed')
        old_units[name], new_units[name] = old, new
    return old_units, new_units


def check_target(runner, replacement):
    safe_directory(BIN, 0o755); safe_directory(STATE.parent); safe_directory(SUDO_DIR)
    if stat.S_IMODE(SUDO_DIR.lstat().st_mode) not in (0o750, 0o755):
        raise ValueError('unexpected_sudo_directory_mode')
    for path in (STATE, BROKER, GATEWAY_NEXT, RUNNER_NEXT, SUDO_NEW, SUDO_NEXT):
        absent(path)
    old_gateway = read_file(GATEWAY, 0o755)
    if sha(old_gateway) != OLD_GATEWAY:
        raise ValueError('installed_gateway_hash_mismatch')
    if read_file(SUDO_OLD, 0o440) != OLD_RULE:
        raise ValueError('original_exact_sudo_rule_required')
    verify_access()
    validate_sudo(Path('/etc/sudoers'))
    baseline = collector_state(runner)
    old_runner = read_file(RUNNER_PATH, 0o755)
    if sha(old_runner) != OLD_RUNNER:
        raise ValueError('old_runner_changed_before_install')
    old_units, new_units = replacement_units(runner, replacement)
    return {'gateway': old_gateway, 'baseline': baseline, 'runner': old_runner,
            'old_units': old_units, 'new_units': new_units, 'replacement': replacement}


def sync_directory(path):
    fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path, content, mode):
    safe_directory(path.parent)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    # A short/failed write deliberately leaves its exclusive evidence file.
    with os.fdopen(fd, 'wb') as out:
        os.fchown(out.fileno(), 0, 0)
        out.write(content); out.flush(); os.fsync(out.fileno()); os.fchmod(out.fileno(), mode); os.fsync(out.fileno())
    sync_directory(path.parent)


def write_evidence(name, value):
    write_new(STATE / name, (json.dumps(value, sort_keys=True) + '\n').encode('ascii'), 0o600)


def publish_new(stage, target):
    # link is atomic and cannot overwrite a surprise destination.
    read_file(stage, 0o440)
    os.link(str(stage), str(target), follow_symlinks=False)
    sync_directory(target.parent)
    # This is the single known staging link, never an unknown file or backup.
    a, b = stage.lstat(), target.lstat()
    if (a.st_dev, a.st_ino, a.st_nlink) != (b.st_dev, b.st_ino, 2):
        raise ValueError('staging_link_changed')
    stage.unlink(); sync_directory(stage.parent)


def replace_known(stage, target, old, new, mode):
    if read_file(target, mode) != old or read_file(stage, mode) != new:
        raise ValueError('known_replacement_bytes_changed')
    os.replace(str(stage), str(target)); sync_directory(target.parent)
    if read_file(target, mode) != new:
        raise ValueError('known_replacement_verification_failed')


def reload_units():
    trusted_executable(CTL)
    subprocess.run([CTL, 'daemon-reload'], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, env=ENV, cwd='/', timeout=20, check=True)


def install(manifest, contents, checked):
    old_gateway, baseline = checked['gateway'], checked['baseline']
    STATE.mkdir(mode=0o700)
    os.chmod(str(STATE), 0o700); sync_directory(STATE.parent)
    write_evidence('install.json', {'schema': 1, 'manifest': manifest, 'old_gateway_sha256': OLD_GATEWAY,
                                   'old_runner_sha256': OLD_RUNNER,
                                   'old_unit_sha256': {name: sha(content) for name, content in checked['old_units'].items()},
                                   'new_unit_sha256': {name: sha(content) for name, content in checked['new_units'].items()},
                                   'actions': list(ACTIONS), 'application_release': APP, 'recovery_baseline': baseline})
    write_new(STATE / 'ssh-gateway.before.py', old_gateway, 0o600)
    write_new(STATE / 'collect-only-runner.before.py', checked['runner'], 0o600)
    for name, content in sorted(checked['old_units'].items()):
        write_new(STATE / (name + '.before'), content, 0o600)
    write_evidence('10-backup.json', {'old_gateway_verified': True})
    write_new(RUNNER_NEXT, contents['collect-only-runner.py'], 0o755)
    for name, content in sorted(checked['new_units'].items()):
        write_new(unit_stage(name), content, 0o644)
    replace_known(RUNNER_NEXT, RUNNER_PATH, checked['runner'], contents['collect-only-runner.py'], 0o755)
    for name, content in sorted(checked['new_units'].items()):
        replace_known(unit_stage(name), SYSTEM / name, checked['old_units'][name], content, 0o644)
    reload_units(); checked['replacement'].verify_units()
    write_evidence('15-runner-units.json', {'runner_sha256': manifest['runner_sha256'], 'database_requisite_verified': True})
    write_new(BROKER, contents['ops-broker.py'], 0o755)
    policy = {'schema': 1, 'broker_sha256': manifest['broker_sha256'], 'runner_sha256': manifest['runner_sha256'],
              'upgrade_sha256': UPGRADE, 'app_release': APP, 'actions': list(ACTIONS)}
    write_evidence('policy.json', policy)
    write_evidence('20-broker-policy.json', {'installed': True})
    write_new(SUDO_NEXT, sudo_rules(), 0o440)
    validate_sudo(SUDO_NEXT)
    publish_new(SUDO_NEXT, SUDO_NEW)
    validate_sudo(Path('/etc/sudoers'))
    write_evidence('30-sudo.json', {'validated': True})
    write_new(GATEWAY_NEXT, contents['ops-gateway.py'], 0o755)
    if (any(read_file(SYSTEM / name, 0o644) != content for name, content in checked['new_units'].items()) or
            sha(read_file(GATEWAY, 0o755)) != OLD_GATEWAY or
            sha(read_file(STATE / 'ssh-gateway.before.py', 0o600)) != OLD_GATEWAY or
            sha(read_file(BROKER, 0o755)) != manifest['broker_sha256'] or
            sha(read_file(RUNNER_PATH, 0o755)) != manifest['runner_sha256'] or
            sha(read_file(GATEWAY_NEXT, 0o755)) != manifest['gateway_sha256'] or
            unique_json(read_file(STATE / 'policy.json', 0o600)) != policy or
            read_file(SUDO_OLD, 0o440) != OLD_RULE or read_file(SUDO_NEW, 0o440) != sudo_rules()):
        raise ValueError('installed_files_changed_before_gateway_switch')
    write_evidence('40-ready-to-switch.json', {'verified': True})
    # The gateway is the last replacement, after the exact reviewed runner/unit
    # update and durable broker/policy/sudo installation have all been verified.
    os.replace(str(GATEWAY_NEXT), str(GATEWAY)); sync_directory(BIN)
    if sha(read_file(GATEWAY, 0o755)) != manifest['gateway_sha256']:
        raise ValueError('gateway_switch_verification_failed')
    write_evidence('complete.json', {'schema': 1, 'status': 'complete', 'broker_sha256': manifest['broker_sha256'],
                                     'app_release': APP})


def terminal_root():
    if (os.getuid() != 0 or os.geteuid() != 0 or not sys.flags.isolated or not sys.dont_write_bytecode or
            os.environ.get('SSH_ORIGINAL_COMMAND') or os.environ.get('SUDO_USER') or not os.isatty(0) or not os.isatty(1)):
        raise ValueError('isolated_root_terminal_required')
    fd = os.open('/dev/tty', os.O_RDONLY | os.O_NOCTTY)
    try:
        if not os.isatty(fd):
            raise ValueError('controlling_terminal_required')
    finally:
        os.close(fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('check', 'apply'))
    parser.add_argument('--source', required=True)
    parser.add_argument('--manifest-sha256', required=True)
    args = parser.parse_args(argv)
    terminal_root(); os.umask(0o077); resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    source = Path(args.source)
    if Path(__file__).absolute() != source / 'install-ops.py':
        raise ValueError('exact_pinned_source_entry_required')
    os.environ.clear(); os.environ.update(ENV)
    manifest, contents = load_source(source, args.manifest_sha256)
    runner = load_runner()
    replacement = runner_module(contents['collect-only-runner.py'], 'approved_ops_install_new_runner')
    with release_lock(runner):
        checked = check_target(runner, replacement)
        if args.action == 'apply':
            install(manifest, contents, checked)
        print(json.dumps({'schema': 1, 'check_only': args.action == 'check', 'installed': args.action == 'apply',
                          'changes': ['database_requisite_runner_and_four_units', 'fixed_broker', 'root_only_policy_and_backup', 'eight_exact_sudo_commands', 'gateway_last'],
                          'collector_started': False, 'hourly_enabled': False, 'first_remote_action': 'diagnose'}, sort_keys=True))


if __name__ == '__main__':
    def interrupted(signum, frame):
        raise ValueError('installer_interrupted')
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupted)
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, SyntaxError, subprocess.SubprocessError):
        print(json.dumps({'failed': True, 'preserve_source_and_evidence': True, 'automatic_retry': False,
                          'administrator_review_required': True, 'rollback_performed': False}), file=sys.stderr)
        raise SystemExit(1)
