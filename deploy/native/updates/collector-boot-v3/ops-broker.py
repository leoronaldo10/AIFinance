#!/usr/bin/python3
"""Fixed, hash-pinned root operations. No command/path/unit supplied by callers.

Public JSON is deliberately smaller than the private root-only audit. Never
prints environment, credentials, exception text, raw logs, host addresses or PIDs.
Install and code updates remain separate administrator-reviewed operations.
"""
import base64
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import selectors
import signal
import stat
import subprocess
import sys
import time
from urllib.parse import urlsplit, unquote

SELF = Path('/opt/aifinance/bin/ops-broker.py')
OPS = Path('/var/lib/aifinance-ops')
POLICY = OPS / 'policy.json'
INSTALL = OPS / 'complete.json'
INSTALL_EVIDENCE = OPS / 'install.json'
BOOT_ID = Path('/proc/sys/kernel/random/boot_id')
BOOT_RECOVERY = OPS / 'collector-boot-v2'
BOOT_CONTINUATION = OPS / 'collector-boot-v3'
WEBSITE_PARENT = Path('/var/lib')
BOOT_ARCHIVES = frozenset(('installed.json', 'probe.json', 'seed-attempt.json', 'network.json', 'output.json'))
BOOT_COUNTS = frozenset(('articles', 'article_revisions', 'analyses', 'receipts', 'editorial_overrides',
    'editorial_review_state', 'editorial_versions', 'editorial_exports', 'publications', 'deliveries', 'grouping_decisions'))
BIN = SELF.parent
COLLECT = Path('/var/lib/aifinance-maintenance/collect-only')
CONFIG = Path('/etc/aifinance-collect')
SYSTEM = Path('/etc/systemd/system')
RELEASE = 'd57ba047369e666025347719caee1a4c642abe62'
RUNNER_SHA = 'b1485bcac62972b2f2145c2ec6ad6163eb49c0e4f3a7e0eee1abdb1bbe98da0f'
UPGRADE_SHA = '9eb61d5b9357a31ed319202efd14ffedbc591aac1fe090179f719246971dfca5'
ACTIONS = ('diagnose', 'restart-preview', 'probe', 'recover-pre-seed', 'seed', 'run', 'disable', 'enable-hourly')
UNIT_ALIASES = {'api': 'aifinance-preview-api.service', 'web': 'aifinance-preview-web.service',
                'db': 'aifinance-preview-db.service', 'guard': 'aifinance-preview-egress.service'}
UNIT_ALIASES.update({mode: 'aifinance-collect-' + mode + '.service' for mode in ('probe', 'check', 'seed', 'run', 'hourly')})
UNIT_ALIASES['timer'] = 'aifinance-collect-hourly.timer'
APP_UNITS = [UNIT_ALIASES['api'], UNIT_ALIASES['web']]
ENV = dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin', HOME='/', LANG='C', LC_ALL='C', TZ='UTC')
PROPERTIES = ('Id', 'LoadState', 'ActiveState', 'SubState', 'Result', 'MainPID', 'ControlPID',
              'ExecMainCode', 'ExecMainStatus', 'ExecMainStartTimestampMonotonic',
              'ExecMainExitTimestampMonotonic', 'User', 'Group', 'FragmentPath', 'DropInPaths',
              'UnitFileState', 'MemoryAccounting', 'MemoryLimit', 'TasksMax', 'TimeoutStartUSec')
RECEIPTS = ('installed.json', 'probe.json', 'seed-attempt.json', 'seed.json', 'run-attempt.json',
            'run.json', 'hourly-approved.json', 'launch.json')
STAGES = frozenset(('entry', 'policy', 'installation', 'lock', 'diagnose', 'helpers', 'upgrade_gate',
    'release', 'account', 'units', 'network', 'idle', 'timer', 'probe_receipt', 'attempt', 'history',
    'db_file', 'db_read_only', 'archive', 'restore_db_read', 'app_gate', 'app_stop', 'app_restart',
    'app_health', 'collector_probe', 'collector_check', 'collector_seed', 'collector_run',
    'resource_check', 'resolver_check', 'no_other_writers', 'count_acceptance', 'resolve_feeds',
    'disable', 'enable_hourly', 'audit', 'complete'))
KNOWN_REASONS = frozenset(('collector_process_identity_or_privileges', 'both_expected_v1_controllers_required', 'collector_must_not_start_database',
    'duplicate_cgroup_controller', 'pid_missing_from_kernel_cgroup', 'invalid_kernel_counter',
    'kernel_budget_not_enforced_or_hit', 'actual_systemd_budget_or_pid_mismatch',
    'pid_changed_during_resource_sample', 'actual_read_only_hosts_binding_required',
    'unit_failed_timed_out_or_resource_evidence_missing', 'loaded_exec_command_mismatch',
    'reviewed_unit_or_dropin_mismatch', 'loaded_collector_safety_property_mismatch',
    'collect_command_failed_no_automatic_retry', 'other_database_clients_present',
    'unexpected_identity_process_exists', 'collector_network_modified', 'network_uid_changed',
    'collector_name_resolution_modified', 'required_exact_count_missing',
    'forbidden_downstream_count_change', 'unexpected_material_count_delta', 'batch_exceeds_three',
    'created_count_does_not_match_database', 'revision_count_does_not_match_database',
    'source_isolation_not_accepted', 'fixed_release_required', 'reviewed_collector_source_changed',
    'current_must_be_accepted_collect_release', 'accepted_upgrade_required'))






REFUSAL_REASONS = frozenset(('archive_verification_failed', 'collector_https_not_revoked', 'collector_identity_changed', 'collector_not_idle', 'command_failed', 'command_output_limit', 'command_timeout', 'database_or_app_guard_not_active', 'db_directory_group_changed', 'db_file_changed_during_recovery', 'db_file_identity_or_permissions_changed', 'different_seed_attempt_not_authorized', 'duplicate_json_field', 'existing_service_listener_missing', 'file_output_limit', 'fixed_action_required', 'fixed_input_limit', 'fixed_root_entry_required', 'helper_hash_mismatch', 'hourly_approval_already_present', 'hourly_state_not_absent', 'hourly_timer_not_stopped', 'incomplete_unit_metadata', 'installation_not_complete', 'installation_recovery_baseline_invalid', 'invalid_unit_metadata', 'journal_evidence_limit', 'original_attempt_changed', 'original_db_file_changed', 'original_probe_not_valid', 'original_seed_attempt_invalid', 'pre_seed_database_proof_failed', 'preview_listener_boundary_changed', 'preview_unit_changed', 'prior_or_partial_recovery_requires_review', 'private_ops_directory_required', 'recovered_db_file_changed', 'recovery_archive_or_index_mismatch', 'recovery_database_proof_missing', 'reviewed_policy_mismatch', 'reviewed_pre_seed_failure_not_present', 'run_already_attempted', 'seed_already_attempted', 'seed_or_run_evidence_present', 'seed_or_run_start_evidence_present', 'successful_first_run_required', 'successful_first_seed_required', 'unexpected_file_mode', 'unexpected_loaded_service_hook', 'unknown_hourly_approval', 'unknown_hourly_unit', 'unresolved_collector_launch', 'untrusted_or_oversize_file', 'untrusted_path', 'verified_restore_required'))

REFUSAL_REASONS = REFUSAL_REASONS | frozenset(('boot_recovery_receipt_invalid', 'boot_recovery_archive_invalid',
    'boot_recovery_fresh_report_invalid', 'boot_recovery_website_proof_invalid', 'boot_recovery_boot_changed',
    'boot_recovery_counts_changed', 'boot_continuation_provenance_invalid'))


class Interrupted(BaseException):
    pass


class Refused(Exception):
    def __init__(self, reason):
        self.reason = reason
        Exception.__init__(self, 'fixed operation refused')


def reason(error):
    if isinstance(error, Interrupted):
        return 'operation_interrupted'
    if isinstance(error, Refused):
        return error.reason if type(error.reason) is str and error.reason in REFUSAL_REASONS else 'operation_refused'
    if isinstance(error, ValueError) and len(error.args) == 1 and type(error.args[0]) is str and error.args[0] in KNOWN_REASONS:
        return error.args[0]
    if isinstance(error, subprocess.TimeoutExpired):
        return 'command_timeout'
    if isinstance(error, subprocess.CalledProcessError):
        return 'command_failed'
    if isinstance(error, ProcessLookupError):
        return 'process_disappeared'
    if isinstance(error, FileNotFoundError):
        return 'required_file_or_process_missing'
    if isinstance(error, PermissionError):
        return 'permission_denied'
    if isinstance(error, BlockingIOError):
        return 'operation_in_progress'
    return 'unclassified_check_failure'


def parse(argv):
    if argv == ['enable-hourly', '--accept-admin-view']:
        return 'enable-hourly'
    if len(argv) == 1 and argv[0] in ACTIONS and argv[0] != 'enable-hourly':
        return argv[0]
    raise Refused('fixed_action_required')


def trusted(path, directory=False, mode=None):
    path = Path(path)
    if not path.is_absolute():
        raise Refused('untrusted_path')
    for item in (path,) + tuple(path.parents):
        info = item.lstat()
        kind = stat.S_ISDIR(info.st_mode) if item != path or directory else stat.S_ISREG(info.st_mode)
        if not kind or info.st_uid != 0 or info.st_mode & 0o022:
            raise Refused('untrusted_path')
        if item == path and (mode is not None and stat.S_IMODE(info.st_mode) != mode):
            raise Refused('unexpected_file_mode')
    return path


def read(path, maximum=131072, mode=None):
    trusted(path, mode=mode)
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1 or info.st_size > maximum:
            raise Refused('untrusted_or_oversize_file')
        data = os.read(fd, maximum + 1)
        if len(data) > maximum:
            raise Refused('file_output_limit')
        return data
    finally:
        os.close(fd)


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Refused('duplicate_json_field')
        result[key] = value
    return result


def document(path, maximum=131072):
    return json.loads(read(path, maximum, mode=0o600).decode('utf-8'), object_pairs_hook=unique)


def boot_private_directory(path):
    trusted(path, directory=True, mode=0o700)
    if path.lstat().st_gid != 0:
        raise Refused('boot_recovery_receipt_invalid')


def boot_recovery_present():
    return any(path.exists() or path.is_symlink() for path in (BOOT_CONTINUATION, BOOT_RECOVERY))


def boot_digest(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def boot_record(value, modes=(0o600,), database=False):
    fields = {'device', 'inode', 'uid', 'gid', 'mode', 'size', 'mtime_ns', 'ctime_ns'}
    extra = set() if database else {'sha256', 'security_attributes'}
    if (not isinstance(value, dict) or set(value) != fields | extra or
            any(type(value[key]) is not int or value[key] < 0 for key in fields) or
            value['inode'] == 0 or value['uid'] != 0 or value['gid'] != 0 or
            value['mode'] not in modes or value['size'] > 1048576):
        raise Refused('boot_continuation_provenance_invalid')
    if not database:
        labels = value['security_attributes']
        if (not boot_digest(value['sha256']) or not isinstance(labels, dict) or
                not set(labels).issubset({'security.selinux'}) or
                any(not isinstance(label, str) or len(label) > 16384 for label in labels.values())):
            raise Refused('boot_continuation_provenance_invalid')
        for label in labels.values():
            try:
                if base64.b64encode(base64.b64decode(label, validate=True)).decode('ascii') != label:
                    raise ValueError()
            except (ValueError, TypeError):
                raise Refused('boot_continuation_provenance_invalid')
    return value


def boot_retained_record(path, expected):
    # Durable predecessor files must remain the same objects, not just copies
    # with the same bytes. Database and live collector paths are never read here.
    boot_record(expected)
    before = path.lstat()
    raw = read(path, 1048576, mode=0o600)
    names = os.listxattr(str(path), follow_symlinks=False)
    if any(name != 'security.selinux' for name in names):
        raise Refused('boot_continuation_provenance_invalid')
    labels = {name: base64.b64encode(os.getxattr(str(path), name, follow_symlinks=False)).decode('ascii') for name in names}
    for info in (before, path.lstat()):
        actual = dict(device=info.st_dev, inode=info.st_ino, uid=info.st_uid, gid=info.st_gid,
                      mode=stat.S_IMODE(info.st_mode), size=info.st_size,
                      mtime_ns=info.st_mtime_ns, ctime_ns=info.st_ctime_ns,
                      sha256=hashlib.sha256(raw).hexdigest(), security_attributes=labels)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or actual != expected:
            raise Refused('boot_continuation_provenance_invalid')
    return raw


def boot_counts(value):
    if (not isinstance(value, dict) or set(value) not in (BOOT_COUNTS, BOOT_COUNTS | {'pgboss.job'}) or
            any(not (key == 'pgboss.job' and count is None) and
                (type(count) is not int or count < 0) for key, count in value.items())):
        raise Refused('boot_recovery_counts_changed')
    return value


def boot_kernel(value, mode, user):
    counters = {'memory.limit_in_bytes', 'memory.usage_in_bytes', 'memory.max_usage_in_bytes',
                'memory.failcnt', 'pids.max', 'pids.current', 'pid', 'uid'}
    if (not isinstance(value, dict) or set(value) != counters | {'cgroup'} or
            any(type(value[key]) is not int or value[key] < 0 for key in counters) or
            value['uid'] != user.pw_uid or value['pid'] <= 1 or
            value['cgroup'] != '/system.slice/' + UNIT_ALIASES[mode] or
            value['memory.limit_in_bytes'] != 256 * 1024 ** 2 or value['memory.failcnt'] != 0 or
            value['memory.usage_in_bytes'] >= 256 * 1024 ** 2 or value['memory.max_usage_in_bytes'] >= 256 * 1024 ** 2 or
            value['pids.max'] != 32 or not 1 <= value['pids.current'] <= 32):
        raise Refused('boot_recovery_fresh_report_invalid')


def boot_report(value, mode, user, runner):
    if (not isinstance(value, dict) or set(value) != {'mode', 'elapsed_seconds', 'samples', 'output'} or
            value['mode'] != mode or type(value['elapsed_seconds']) not in (int, float) or
            not 0 < value['elapsed_seconds'] <= 120 or mode == 'probe' and value['elapsed_seconds'] < 25 or
            not isinstance(value['samples'], list) or not 1 <= len(value['samples']) <= 1024):
        raise Refused('boot_recovery_fresh_report_invalid')
    fixed = dict(User='aifinance-collect', MemoryAccounting='yes', MemoryLimit=str(256 * 1024 ** 2),
                 TasksMax='32', TimeoutStartUSec='2min')
    for sample in value['samples']:
        if not isinstance(sample, dict) or set(sample) != {'properties', 'kernel', 'resolver'}:
            raise Refused('boot_recovery_fresh_report_invalid')
        props = sample['properties']; boot_kernel(sample['kernel'], mode, user)
        resolver = None if mode == 'probe' else {'hosts_only': True, 'read_only_bindings': ['/etc/hosts', '/etc/nsswitch.conf']}
        if (not isinstance(props, dict) or set(props) != set(fixed) | {'MainPID'} or
                any(props[key] != expected for key, expected in fixed.items()) or
                props['MainPID'] != str(sample['kernel']['pid']) or sample['resolver'] != resolver):
            raise Refused('boot_recovery_fresh_report_invalid')
        if mode != 'probe' and sample['resolver'].get('hosts_only') is not True:
            raise Refused('boot_recovery_fresh_report_invalid')
    output = value['output']
    if mode == 'probe':
        if output != {}:
            raise Refused('boot_recovery_fresh_report_invalid')
    else:
        if (not isinstance(output, dict) or set(output) != {'mode', 'result', 'before', 'after'} or output['mode'] != mode or
                not isinstance(output['result'], dict)):
            raise Refused('boot_recovery_fresh_report_invalid')
        boot_kernel(output['before'], mode, user); boot_kernel(output['after'], mode, user)
        runner.validate_snapshot(output['result'], seeded=False)
        if output['result'].get('sources') != [] or output['result'].get('rawStates') != []:
            raise Refused('boot_recovery_fresh_report_invalid')
        boot_counts(output['result'].get('counts'))
    return value


def fsync_dir(path):
    fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path, data):
    trusted(path.parent, directory=True, mode=0o700)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as target:
        os.fchmod(target.fileno(), 0o600)
        target.write(data)
        target.flush(); os.fsync(target.fileno())
    fsync_dir(path.parent)


def replace_index(path, value):
    read(path, mode=0o600)
    temporary = path.with_name(path.name + '.next')
    write_new(temporary, json.dumps(value, sort_keys=True).encode())
    os.replace(str(temporary), str(path)); fsync_dir(path.parent)


def bounded_command(args, payload=None, timeout=10, env=None, drop=None, limit=65536):
    trusted(Path(args[0]).resolve())
    process = subprocess.Popen(args, stdin=subprocess.PIPE if payload is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd='/', env=dict(ENV if env is None else env),
        preexec_fn=drop, start_new_session=True)
    selector = selectors.DefaultSelector(); selector.register(process.stdout, selectors.EVENT_READ)
    end = time.monotonic() + min(timeout, 10)
    data = bytearray()
    try:
        if payload is not None:
            encoded = payload.encode() if isinstance(payload, str) else payload
            if len(encoded) > 4096:
                raise Refused('fixed_input_limit')
            process.stdin.write(encoded); process.stdin.close()
        while True:
            if not selector.select(max(0, end - time.monotonic())):
                raise Refused('command_timeout')
            part = os.read(process.stdout.fileno(), min(4096, limit + 1 - len(data)))
            if not part:
                break
            data.extend(part)
            if len(data) > limit:
                raise Refused('command_output_limit')
        if process.wait(timeout=max(.01, end - time.monotonic())) != 0:
            raise Refused('command_failed')
        return data.decode('utf-8', 'strict').strip()
    finally:
        selector.close(); process.stdout.close()
        if process.stdin is not None and not process.stdin.closed:
            process.stdin.close()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL); process.wait()


def pinned_module(name, expected):
    data = read(BIN / name, 262144)
    if hashlib.sha256(data).hexdigest() != expected:
        raise Refused('helper_hash_mismatch')
    # Execute the already checked bytes, not a second path lookup after hashing.
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(name.replace('-', '_'), loader=None))
    module.__file__ = str(BIN / name)
    exec(compile(data, str(BIN / name), 'exec'), module.__dict__)
    return module


def policy():
    trusted(OPS, directory=True, mode=0o700)
    if OPS.stat().st_gid != 0:
        raise Refused('private_ops_directory_required')
    policy_info = POLICY.lstat()
    if policy_info.st_gid != 0 or policy_info.st_nlink != 1:
        raise Refused('reviewed_policy_mismatch')
    value = json.loads(read(POLICY, 8192, mode=0o600), object_pairs_hook=unique)
    keys = {'schema', 'broker_sha256', 'runner_sha256', 'upgrade_sha256', 'app_release', 'actions'}
    if (not isinstance(value, dict) or set(value) != keys or type(value['schema']) is not int or value['schema'] != 1 or
            value['runner_sha256'] != RUNNER_SHA or value['upgrade_sha256'] != UPGRADE_SHA or
            value['app_release'] != RELEASE or value['actions'] != list(ACTIONS) or
            value['broker_sha256'] != hashlib.sha256(read(SELF, 262144)).hexdigest()):
        raise Refused('reviewed_policy_mismatch')
    return value


def installation_complete(value):
    info = INSTALL.lstat()
    installed = json.loads(read(INSTALL, 8192, mode=0o600), object_pairs_hook=unique)
    if (info.st_gid != 0 or info.st_nlink != 1 or not isinstance(installed, dict) or
            set(installed) != {'schema', 'status', 'broker_sha256', 'app_release'} or
            type(installed.get('schema')) is not int or installed.get('schema') != 1 or installed.get('status') != 'complete' or
            installed.get('broker_sha256') != value['broker_sha256'] or installed.get('app_release') != RELEASE):
        raise Refused('installation_not_complete')


def number(value, maximum=10 ** 18):
    return int(value) if isinstance(value, str) and re.fullmatch(r'[0-9]{1,20}', value) and int(value) <= maximum else None


def unit_states():
    args = ['/usr/bin/systemctl', 'show'] + list(UNIT_ALIASES.values()) + ['--no-pager']
    args += ['--property=' + ','.join(PROPERTIES)]
    text = bounded_command(args)
    result = {}
    reverse = {unit: alias for alias, unit in UNIT_ALIASES.items()}
    for block in text.split('\n\n'):
        values = {}
        for line in block.splitlines():
            key, sep, value = line.partition('=')
            if not sep or key not in PROPERTIES or key in values:
                raise Refused('invalid_unit_metadata')
            values[key] = value
        unit = values.get('Id')
        if unit not in reverse or reverse[unit] in result:
            raise Refused('invalid_unit_metadata')
        result[reverse[unit]] = values
    if set(result) != set(UNIT_ALIASES):
        raise Refused('incomplete_unit_metadata')
    return result


def public_unit(values):
    allowed = {'LoadState': ('loaded', 'not-found', 'masked', 'error', 'bad-setting'),
               'ActiveState': ('active', 'inactive', 'failed', 'activating', 'deactivating', 'reloading'),
               'Result': ('', 'success', 'exit-code', 'signal', 'core-dump', 'timeout', 'resources', 'start-limit-hit', 'protocol')}
    result = {key: value if value in allowed[key] else 'invalid' for key, value in ((k, values.get(k, '')) for k in allowed)}
    result['process_running'] = any(number(values.get(k, '')) not in (0, None) for k in ('MainPID', 'ControlPID'))
    result['process_metadata_valid'] = all(number(values.get(k, '')) is not None for k in ('MainPID', 'ControlPID'))
    result['exit_class'] = 'terminated' if values.get('ExecMainCode') == '2' and values.get('ExecMainStatus') == '15' else (
        'success' if values.get('ExecMainStatus') == '0' else 'other')
    result['has_dropins'] = bool(values.get('DropInPaths'))
    result['collector_identity_configured'] = values.get('User') == values.get('Group') == 'aifinance-collect'
    result['collector_memory_budget'] = values.get('MemoryLimit') == str(256 * 1024 ** 2)
    result['collector_task_budget'] = values.get('TasksMax') == '32'
    result['collector_timeout_budget'] = values.get('TimeoutStartUSec') == '2min'
    return result


RESOLVER_PATHS = {'hosts': Path('/etc/hosts'), 'nss': Path('/etc/nsswitch.conf')}


def resolver_path_metadata():
    public, private = {}, {}
    for alias, path in RESOLVER_PATHS.items():
        try:
            original = path.lstat(); canonical = path.resolve(); info = canonical.lstat()
            public[alias] = {'metadata_readable': True,
                'target_is_symlink': stat.S_ISLNK(original.st_mode),
                'canonical_target_is_root_owned_regular': info.st_uid == 0 and stat.S_ISREG(info.st_mode),
                'desired_mount_path_differs': canonical != path}
            private[alias] = {'canonical_target': str(canonical)}
        except OSError:
            public[alias] = {'metadata_readable': False}
    return public, private


class Broker:
    def __init__(self, runner, upgrade):
        self.r = runner; self.u = upgrade
        self.stage = 'entry'; self.details = {}; self.mutated = False; self.safe_to_cleanup = False
        self.r.command = lambda args, payload=None, timeout=15: bounded_command(args, payload, timeout)
        # Instrument approved calls without weakening any of their checks.
        for name, stage in (('resource_evidence', 'resource_check'), ('resolver_evidence', 'resolver_check'),
            ('no_other_writers', 'no_other_writers'), ('accept_delta', 'count_acceptance'),
            ('configure_network', 'network'), ('resolve_feeds', 'resolve_feeds')):
            original = getattr(self.r, name)
            setattr(self.r, name, self.instrument(original, stage))
        original_units = self.r.verify_units
        def verify_units():
            original_units()
            for mode in ('probe', 'check', 'seed', 'run'):
                for hook in ('ExecStop', 'ExecStopPost', 'ExecStartPost', 'ExecReload'):
                    if self.r.prop(self.r.unit_name(mode), hook):
                        raise Refused('unexpected_loaded_service_hook')
        self.r.verify_units = verify_units
        original = self.r.run_unit
        def run_unit(mode, user):
            previous = self.stage; self.stage = 'collector_' + mode
            result = original(mode, user)
            self.stage = previous
            return result
        self.r.run_unit = run_unit

    def instrument(self, function, stage):
        def call(*args, **kwargs):
            previous = self.stage; self.stage = stage
            result = function(*args, **kwargs)
            self.stage = previous
            return result
        return call

    def call(self, stage, function, *args):
        previous = self.stage; self.stage = stage
        result = function(*args)
        self.stage = previous
        return result

    def identity(self):
        user = self.call('account', self.r.account)
        receipt = document(COLLECT / 'installed.json', 4096)
        if (not isinstance(receipt, dict) or set(receipt) != {'release', 'uid'} or receipt.get('release') != RELEASE or
                type(receipt.get('uid')) is not int or user.pw_uid != receipt['uid']):
            raise Refused('collector_identity_changed')
        return user

    def base(self):
        self.call('upgrade_gate', self.r.upgrade_gate)
        gate = document(Path('/var/lib/aifinance-maintenance/collect-only-upgrade.json'))
        if gate.get('restore_verified') is not True:
            raise Refused('verified_restore_required')
        self.call('release', self.r.validate_release)
        self.call('units', self.r.verify_units)
        user = self.identity()
        self.call('network', self.r.verify_network, user)
        return user

    def no_timer(self, states):
        self.stage = 'timer'
        for alias in ('hourly', 'timer'):
            if states[alias].get('LoadState') != 'not-found' or (SYSTEM / UNIT_ALIASES[alias]).exists() or (SYSTEM / UNIT_ALIASES[alias]).is_symlink():
                raise Refused('hourly_state_not_absent')
        if (COLLECT / 'hourly-approved.json').exists():
            raise Refused('hourly_approval_already_present')

    def known_timer(self, states, quiet=False):
        self.stage = 'timer'
        if all(states[alias].get('LoadState') == 'not-found' for alias in ('hourly', 'timer')):
            self.no_timer(states)
            return
        service, timer = self.r.hourly_text()
        for alias, content in (('hourly', service), ('timer', timer)):
            path = SYSTEM / UNIT_ALIASES[alias]
            if (read(path).decode('utf-8') != content or states[alias].get('FragmentPath') != str(path) or
                    states[alias].get('DropInPaths') or states[alias].get('LoadState') != 'loaded'):
                raise Refused('unknown_hourly_unit')
        approved = document(COLLECT / 'hourly-approved.json', 4096)
        if approved != {'release': RELEASE, 'admin_view_accepted': True}:
            raise Refused('unknown_hourly_approval')
        self.r.effective_exec(UNIT_ALIASES['hourly'], 'ExecStart',
            '/usr/bin/python3 -I -B /opt/aifinance/bin/collect-only-runner.py run --scheduled')
        for hook in ('ExecStartPre', 'ExecStartPost', 'ExecStop', 'ExecStopPost', 'ExecReload'):
            if self.r.prop(UNIT_ALIASES['hourly'], hook):
                raise Refused('unexpected_loaded_service_hook')
        if quiet and (states['timer'].get('ActiveState') not in ('inactive', 'failed') or states['timer'].get('UnitFileState') != 'disabled'):
            raise Refused('hourly_timer_not_stopped')

    def idle(self, user, states):
        self.stage = 'idle'
        for alias in ('probe', 'check', 'seed', 'run', 'hourly'):
            value = states[alias]
            if value.get('ActiveState') not in ('inactive', 'failed') or any(value.get(key) != '0' for key in ('MainPID', 'ControlPID')):
                raise Refused('collector_not_idle')
        self.r.no_processes(user.pw_uid)
        if (COLLECT / 'launch.json').exists() or (COLLECT / 'launch.json').is_symlink():
            raise Refused('unresolved_collector_launch')

    def db_only_network(self, user):
        self.call('network', self.r.verify_network, user)
        receipt = document(COLLECT / 'network.json')
        if receipt != {'uid': user.pw_uid, 'hosts': {}}:
            raise Refused('collector_https_not_revoked')

    def probe_receipt(self, user):
        self.stage = 'probe_receipt'
        report = document(COLLECT / 'probe.json', 1048576)
        if (report.get('mode') != 'probe' or type(report.get('elapsed_seconds')) not in (int, float) or
                not 25 <= report['elapsed_seconds'] <= 120 or not isinstance(report.get('samples'), list) or not report['samples']):
            raise Refused('original_probe_not_valid')
        for sample in report['samples']:
            kernel = sample.get('kernel', {})
            if (kernel.get('uid') != user.pw_uid or kernel.get('memory.limit_in_bytes') != 256 * 1024 ** 2 or
                    kernel.get('memory.failcnt') != 0 or kernel.get('pids.max') != 32 or
                    kernel.get('cgroup') != '/system.slice/aifinance-collect-probe.service' or
                    not 0 <= kernel.get('pids.current', -1) <= 32 or
                    not 0 <= kernel.get('memory.max_usage_in_bytes', -1) < 256 * 1024 ** 2):
                raise Refused('original_probe_not_valid')
        return report

    def environment_fd(self, disabled):
        self.stage = 'db_file'; user = self.identity()
        trusted(CONFIG, directory=True, mode=0o750)
        if CONFIG.stat().st_gid != user.pw_gid:
            raise Refused('db_directory_group_changed')
        path = CONFIG / 'database.env'; trusted(path)
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = os.fstat(fd)
        mode, group = (0o400, 0) if disabled else (0o440, user.pw_gid)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != group or
                stat.S_IMODE(info.st_mode) != mode or info.st_nlink != 1 or info.st_size > 8192):
            os.close(fd); raise Refused('db_file_identity_or_permissions_changed')
        return fd, info

    def sql_proof(self, fd, user):
        self.stage = 'db_read_only'
        os.lseek(fd, 0, os.SEEK_SET)
        value = self.r.database_url(os.read(fd, 8193).decode('utf-8'))
        password = unquote(urlsplit(value).password)
        ids = "('collect-dynamics-finance','collect-journal-accountancy','collect-accounting-today')"
        sql = "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL search_path=pg_catalog,public,pg_temp; SET LOCAL row_security=off; SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='1s'; "
        sql += "DO $$ BEGIN IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname IN ('schema_migrations','sources','articles','article_discoveries','fetch_runs') AND c.relkind IN ('r','p') AND c.relowner=pg_catalog.to_regrole('aifinance_preview')) <> 5 THEN RAISE EXCEPTION 'unreviewed_relations'; END IF; END $$; "
        sql += "SELECT pg_catalog.json_build_object('database_ok',pg_catalog.current_database()='aifinance_preview','role_ok',current_user='aifinance_preview',"
        sql += "'role_safe',(SELECT rolcanlogin AND NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls) FROM pg_catalog.pg_roles WHERE rolname=current_user),"
        sql += "'migration_ok',(SELECT pg_catalog.count(*)=1 FROM public.schema_migrations WHERE name='0041_collect_only.sql'),"
        sql += "'other_clients',(SELECT pg_catalog.count(*) FROM pg_catalog.pg_stat_activity WHERE datname=pg_catalog.current_database() AND pid<>pg_catalog.pg_backend_pid()),"
        sql += "'sources',(SELECT pg_catalog.count(*) FROM public.sources WHERE collect_only OR id IN " + ids + "),"
        sql += "'articles',(SELECT pg_catalog.count(*) FROM public.articles WHERE collect_only OR source_id IN " + ids + "),"
        sql += "'discoveries',(SELECT pg_catalog.count(*) FROM public.article_discoveries WHERE source_id IN " + ids + "),"
        sql += "'fetch_runs',(SELECT pg_catalog.count(*) FROM public.fetch_runs WHERE source_id IN " + ids + "))::text; COMMIT;"
        def drop():
            os.setgroups([]); os.setgid(user.pw_gid); os.setuid(user.pw_uid)
        env = dict(ENV, PGPASSWORD=password, PGCONNECT_TIMEOUT='5', PGOPTIONS='-c default_transaction_read_only=on')
        args = ['/usr/pgsql-17/bin/psql', '-X', '-w', '-q', '-A', '-t', '-v', 'ON_ERROR_STOP=1',
                '-h', '127.0.0.1', '-p', '55432', '-U', 'aifinance_preview', '-d', 'aifinance_preview']
        result = json.loads(bounded_command(args, sql, env=env, drop=drop, limit=4096), object_pairs_hook=unique)
        expected = {'database_ok': True, 'role_ok': True, 'role_safe': True, 'migration_ok': True,
                    'other_clients': 0, 'sources': 0, 'articles': 0, 'discoveries': 0, 'fetch_runs': 0}
        if (result != expected or any(result.get(k) is not True for k in ('database_ok', 'role_ok', 'role_safe', 'migration_ok')) or
                any(type(result.get(k)) is not int for k in ('other_clients', 'sources', 'articles', 'discoveries', 'fetch_runs'))):
            raise Refused('pre_seed_database_proof_failed')
        return expected

    def app_gate(self, user, states):
        self.stage = 'app_gate'
        self.idle(user, states); self.db_only_network(user)
        for alias in ('api', 'web', 'db', 'guard'):
            unit = UNIT_ALIASES[alias]; path = SYSTEM / unit
            if (hashlib.sha256(read(path)).hexdigest() != self.u.UNIT_DIGESTS[unit] or
                    states[alias].get('FragmentPath') != str(path) or states[alias].get('DropInPaths')):
                raise Refused('preview_unit_changed')
        for alias in ('api', 'web'):
            unit = UNIT_ALIASES[alias]
            self.r.effective_exec(unit, 'ExecStart', '/usr/bin/python3 -I /opt/aifinance/bin/run-preview.py ' + alias)
            self.r.effective_exec(unit, 'ExecStartPre', '/usr/bin/python3 -I -B /opt/aifinance/bin/egress-guard.py verify')
            for hook in ('ExecStop', 'ExecStopPost', 'ExecStartPost', 'ExecReload'):
                if self.r.prop(unit, hook):
                    raise Refused('unexpected_loaded_service_hook')
        if any(states[alias].get('ActiveState') != 'active' for alias in ('db', 'guard')):
            raise Refused('database_or_app_guard_not_active')
        return self.u.helper('first-preview.py')

    def restart(self, user, restart=True):
        states = unit_states(); self.known_timer(states, quiet=True)
        fp = self.app_gate(user, states)
        before = fp.listeners()['8000']
        if boot_recovery_present():
            if before != []:
                raise Refused('preview_listener_boundary_changed')
            self.boot_recovery_receipt(user)
        elif not before:
            raise Refused('existing_service_listener_missing')
        self.stage = 'app_restart'
        bounded_command(['/usr/bin/systemctl', 'restart' if restart else 'start'] + APP_UNITS)
        self.stage = 'app_health'; fp.health(RELEASE)
        after = fp.listeners()
        if before != after['8000'] or any(not after[str(port)] or any(address != '0100007F' for address, inode in after[str(port)]) for port in (3100, 3101, 55432)):
            raise Refused('preview_listener_boundary_changed')
        self.r.validate_release()
        return {'preview_healthy': True, 'existing_service_preserved': True}

    def journal_metadata(self, alias, since):
        args = ['/usr/bin/journalctl', '--no-pager', '--output=json', '--lines=21',
                '--unit=' + UNIT_ALIASES[alias], '--since=@' + str(since)]
        text = bounded_command(args, limit=65536)
        rows = [json.loads(line, object_pairs_hook=unique) for line in text.splitlines() if line]
        if len(rows) > 20:
            raise Refused('journal_evidence_limit')
        return [{'timestamp_valid': number(row.get('__REALTIME_TIMESTAMP', '')) is not None,
                 'unit_matches': row.get('UNIT', row.get('_SYSTEMD_UNIT')) == UNIT_ALIASES[alias],
                 'exit_is_terminated': row.get('EXIT_CODE') == 'killed' and row.get('EXIT_STATUS') == '15'} for row in rows]

    def recovery_baseline(self):
        value = document(INSTALL_EVIDENCE, 16384).get('recovery_baseline')
        keys = {'attempt_sha256', 'attempt_started', 'check_start_monotonic', 'check_exit_monotonic',
                'db_device', 'db_inode', 'collector_gid'}
        if (not isinstance(value, dict) or set(value) != keys or
                not isinstance(value['attempt_sha256'], str) or not re.fullmatch('[0-9a-f]{64}', value['attempt_sha256']) or
                any(type(value[k]) is not int or value[k] < 0 for k in ('attempt_started', 'db_device', 'db_inode', 'collector_gid')) or
                any(number(value[k]) is None for k in ('check_start_monotonic', 'check_exit_monotonic')) or
                int(value['check_start_monotonic']) <= 0 or int(value['check_exit_monotonic']) < int(value['check_start_monotonic'])):
            raise Refused('installation_recovery_baseline_invalid')
        return value

    def boot_recovery_receipt(self, user):
        # This only verifies durable provenance. In particular it must also work
        # after cleanup has revoked database access so the website can restart.
        self.stage = 'history'
        continuation = BOOT_CONTINUATION.exists() or BOOT_CONTINUATION.is_symlink()
        recovery = BOOT_CONTINUATION if continuation else BOOT_RECOVERY
        boot_private_directory(recovery)
        if (recovery / 'failure.json').exists() or (recovery / 'failure.json').is_symlink():
            raise Refused('prior_or_partial_recovery_requires_review')
        boot = read(BOOT_ID, 128).decode('ascii').strip()
        if not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', boot):
            raise Refused('boot_recovery_boot_changed')
        value = document(recovery / 'ready.json', 65536)
        keys = {'schema', 'status', 'boot_id', 'release', 'runner_sha256', 'broker_sha256', 'baseline',
                'db_file_device', 'db_file_inode', 'collector_gid', 'database_proof', 'counts_before', 'counts_after',
                'archive_sha256', 'probe_sha256', 'check_sha256', 'website_evidence', 'listener_8000'}
        if continuation:
            keys.add('continuation')
        baseline = self.recovery_baseline()
        if (not isinstance(value, dict) or set(value) != keys or type(value['schema']) is not int or value['schema'] != (3 if continuation else 2) or
                value['status'] != 'ready' or value['boot_id'] != boot or value['release'] != RELEASE or
                value['runner_sha256'] != RUNNER_SHA or value['broker_sha256'] != hashlib.sha256(read(SELF, 262144, mode=0o755)).hexdigest() or
                hashlib.sha256(read(BIN / 'collect-only-runner.py', 262144, mode=0o755)).hexdigest() != RUNNER_SHA or
                value['baseline'] != baseline or value['listener_8000'] != [] or
                any(type(value[key]) is not int for key in ('db_file_device', 'db_file_inode', 'collector_gid')) or
                (value['db_file_device'], value['db_file_inode'], value['collector_gid']) !=
                    (baseline['db_device'], baseline['db_inode'], user.pw_gid) or user.pw_gid != baseline['collector_gid']):
            raise Refused('boot_recovery_receipt_invalid')
        proof = {'database_ok': True, 'role_ok': True, 'role_safe': True, 'migration_ok': True,
                 'other_clients': 0, 'sources': 0, 'articles': 0, 'discoveries': 0, 'fetch_runs': 0}
        actual = value['database_proof']
        if (not isinstance(actual, dict) or actual != proof or
                any(actual.get(key) is not True for key in ('database_ok', 'role_ok', 'role_safe', 'migration_ok')) or
                any(type(actual.get(key)) is not int for key in ('other_clients', 'sources', 'articles', 'discoveries', 'fetch_runs'))):
            raise Refused('recovery_database_proof_missing')
        if boot_counts(value['counts_before']) != boot_counts(value['counts_after']):
            raise Refused('boot_recovery_counts_changed')
        archived = value['archive_sha256']; archive = recovery / 'archive'
        boot_private_directory(archive)
        if (not isinstance(archived, dict) or not BOOT_ARCHIVES.issubset(archived) or len(archived) > 128 or
                any(name not in BOOT_ARCHIVES and not re.fullmatch(r'probe-[0-9]+-[0-9a-f]{12}\.json', name) for name in archived) or
                {entry.name for entry in archive.iterdir()} != set(archived)):
            raise Refused('boot_recovery_archive_invalid')
        archive_raw = {}; total = 0
        for name, digest in archived.items():
            raw = read(archive / name, 1048576, mode=0o600); total += len(raw)
            if (not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest) or
                    hashlib.sha256(raw).hexdigest() != digest or total > 8 * 1024 ** 2):
                raise Refused('boot_recovery_archive_invalid')
            archive_raw[name] = raw
        if (archived['seed-attempt.json'] != baseline['attempt_sha256'] or
                json.loads(archive_raw['seed-attempt.json'].decode('utf-8'), object_pairs_hook=unique) !=
                    {'release': RELEASE, 'mode': 'seed', 'started': baseline['attempt_started']} or
                json.loads(archive_raw['installed.json'].decode('utf-8'), object_pairs_hook=unique) !=
                    {'release': RELEASE, 'uid': user.pw_uid} or
                json.loads(archive_raw['network.json'].decode('utf-8'), object_pairs_hook=unique) != {'uid': user.pw_uid, 'hosts': {}}):
            raise Refused('boot_recovery_archive_invalid')
        for mode in ('probe', 'check'):
            raw = read(recovery / ('fresh-' + mode + '.json'), 1048576, mode=0o600)
            if hashlib.sha256(raw).hexdigest() != value[mode + '_sha256']:
                raise Refused('boot_recovery_fresh_report_invalid')
            report = boot_report(json.loads(raw.decode('utf-8'), object_pairs_hook=unique), mode, user, self.r)
            if mode == 'check' and report['output']['result']['counts'] != value['counts_after']:
                raise Refused('boot_recovery_counts_changed')
        website_path = WEBSITE_PARENT / ('aifinance-preview-recovery-' + boot)
        website = value['website_evidence']; boot_private_directory(website_path)
        names = [entry.name for entry in website_path.iterdir()]
        if (not isinstance(website, dict) or set(website) != {'name', 'sha256'} or not isinstance(website['name'], str) or
                website['name'] != '05-complete.json' or
                [name for name in names if re.fullmatch(r'[0-9]{2}-complete\.json', name)] != ['05-complete.json'] or
                any(name.endswith('-failure.json') for name in names)):
            raise Refused('boot_recovery_website_proof_invalid')
        raw = read(website_path / website['name'], 1048576, mode=0o600)
        if hashlib.sha256(raw).hexdigest() != website['sha256']:
            raise Refused('boot_recovery_website_proof_invalid')
        complete = json.loads(raw.decode('utf-8'), object_pairs_hook=unique)
        original = document(website_path / '01-evidence_create.json', 1048576)
        if (not isinstance(complete, dict) or complete.get('website_healthy') is not True or
                complete.get('collector_started') is not False or complete.get('native_ready_written') is not False or
                not isinstance(complete.get('listeners'), dict) or complete['listeners'].get('8000') != [] or
                not isinstance(complete.get('preserved_after'), dict)):
            raise Refused('boot_recovery_website_proof_invalid')
        if (not isinstance(original, dict) or original.get('boot_id') != boot or original.get('release') != RELEASE or
                original.get('preserved_before') != complete['preserved_after']):
            raise Refused('boot_recovery_website_proof_invalid')
        for port in ('3100', '3101', '55432'):
            rows = complete['listeners'].get(port)
            if (not isinstance(rows, list) or not rows or
                    any(not isinstance(row, list) or len(row) != 2 or row[0] != '0100007F' for row in rows)):
                raise Refused('boot_recovery_website_proof_invalid')
        for name, digest in archived.items():
            if complete['preserved_after'].get(str(COLLECT / name), {}).get('sha256') != digest:
                raise Refused('boot_recovery_website_proof_invalid')
        if continuation:
            self.boot_continuation_receipt(value, boot, user)
        return value

    def boot_continuation_receipt(self, value, boot, user):
        def require(ok):
            if not ok:
                raise Refused('boot_continuation_provenance_invalid')

        def decode(raw):
            result = json.loads(raw.decode('ascii'), object_pairs_hook=unique)
            require(isinstance(result, dict))
            return result

        continuation = value['continuation']
        require(isinstance(continuation, dict) and set(continuation) ==
                {'manifest_sha256', 'snapshot_sha256', 'prior_evidence_sha256', 'attempt_before_sha256'})
        manifest_raw = read(BOOT_CONTINUATION / 'manifest.json', 65536, mode=0o600)
        snapshot_raw = read(BOOT_CONTINUATION / 'validated-snapshot.json', 1048576, mode=0o600)
        require(boot_digest(continuation['manifest_sha256']) and boot_digest(continuation['snapshot_sha256']) and
                hashlib.sha256(manifest_raw).hexdigest() == continuation['manifest_sha256'] and
                hashlib.sha256(snapshot_raw).hexdigest() == continuation['snapshot_sha256'])
        manifest = decode(manifest_raw); snapshot = decode(snapshot_raw)
        payloads = {'continue-collector-after-boot.py', 'recover-collector-after-boot.py', 'update-ops-nss-proof.py',
                    'recover-preview-after-boot.py', 'collect-only-runner.py', 'ops-broker.py'}
        require(set(manifest) == {'schema', 'boot_id', 'release', 'payloads', 'predecessor'} and
                type(manifest['schema']) is int and manifest['schema'] == 3 and
                manifest['boot_id'] == boot and manifest['release'] == RELEASE and
                isinstance(manifest['payloads'], dict) and set(manifest['payloads']) == payloads and
                all(boot_digest(digest) for digest in manifest['payloads'].values()) and
                manifest['payloads']['collect-only-runner.py'] == RUNNER_SHA and
                manifest['payloads']['ops-broker.py'] == value['broker_sha256'] and
                isinstance(manifest['predecessor'], dict) and set(manifest['predecessor']) ==
                    {'manifest_sha256', 'failure_sha256', 'website_sha256'} and
                all(boot_digest(digest) for digest in manifest['predecessor'].values()))
        require(set(snapshot) == {'schema', 'boot_id', 'release', 'manifest_sha256', 'prior', 'current',
                                 'database', 'units', 'helpers', 'history', 'legacy_stage', 'website'} and
                type(snapshot['schema']) is int and snapshot['schema'] == 3 and snapshot['boot_id'] == boot and
                snapshot['release'] == RELEASE and snapshot['manifest_sha256'] == continuation['manifest_sha256'])
        for group in ('prior', 'current', 'helpers', 'website'):
            require(isinstance(snapshot[group], dict) and 0 < len(snapshot[group]) <= 256)
            for name, record in snapshot[group].items():
                require(isinstance(name, str) and len(name) <= 256)
                boot_record(record, (0o600, 0o755) if group == 'helpers' else (0o600,))
        boot_record(snapshot['database'], (0o400,), database=True)
        boot_record(snapshot['history']); boot_record(snapshot['legacy_stage'])
        require(set(snapshot['helpers']) == {'runner', 'broker', 'policy'} and
                set(snapshot['website']) == {'01-evidence_create.json', '05-complete.json'})
        require(isinstance(snapshot['units'], dict) and set(snapshot['units']) == {'probe', 'check', 'seed', 'run'} and
                all(isinstance(unit, dict) and unit and all(isinstance(key, str) and isinstance(item, str)
                    for key, item in unit.items()) for unit in snapshot['units'].values()))
        require((snapshot['database']['device'], snapshot['database']['inode']) ==
                (value['db_file_device'], value['db_file_inode']))
        prior = snapshot['prior']; current = snapshot['current']
        prior_files = {'manifest.json', 'failure.json', 'sql-before.json', 'fresh-probe.json'}
        update_files = {'manifest.json', 'plan.json', 'runner.before', 'broker.before', 'policy.before',
                        'complete.before', 'complete.withheld'}
        require(set(prior) == prior_files | {'helper-update/' + name for name in update_files} |
                {'archive/' + name for name in value['archive_sha256']})
        require(BOOT_ARCHIVES.issubset(current) and len(current) <= 128 and
                all(name in BOOT_ARCHIVES or re.fullmatch(r'probe-[0-9]+-[0-9a-f]{12}\.json', name) for name in current) and
                set(value['archive_sha256']).issubset(current) and len(set(current) - set(value['archive_sha256'])) == 1)
        require(continuation['prior_evidence_sha256'] == {name: record['sha256'] for name, record in prior.items()} and
                continuation['attempt_before_sha256'] == {name: record['sha256'] for name, record in current.items()})
        boot_private_directory(BOOT_RECOVERY)
        require({path.name for path in BOOT_RECOVERY.iterdir()} == prior_files | {'archive', 'helper-update'})
        for name, expected in (('archive', set(value['archive_sha256'])), ('helper-update', update_files)):
            path = BOOT_RECOVERY / name; boot_private_directory(path)
            require({entry.name for entry in path.iterdir()} == expected)
        raw_prior = {}; total = 0
        for name, record in prior.items():
            raw_prior[name] = boot_retained_record(BOOT_RECOVERY / name, record)
            total += len(raw_prior[name]); require(total <= 16 * 1024 ** 2)
        require(manifest['predecessor']['manifest_sha256'] == prior['manifest.json']['sha256'] and
                manifest['predecessor']['failure_sha256'] == prior['failure.json']['sha256'] and
                manifest['predecessor']['website_sha256'] == value['website_evidence']['sha256'] and
                '05-complete.json' in snapshot['website'] and
                snapshot['website']['05-complete.json']['sha256'] == value['website_evidence']['sha256'])
        for name, digest in value['archive_sha256'].items():
            require(prior['archive/' + name]['sha256'] == digest)
        boot_retained_record(INSTALL_EVIDENCE, snapshot['history'])
        boot_retained_record(OPS / '.complete.json.nss-v1.next', snapshot['legacy_stage'])
        for name, record in snapshot['website'].items():
            boot_retained_record(WEBSITE_PARENT / ('aifinance-preview-recovery-' + boot) / name, record)
        before = BOOT_CONTINUATION / 'attempt-before'; boot_private_directory(before)
        require({path.name for path in before.iterdir()} == set(current))
        total = 0; raw_before = {}
        for name, record in current.items():
            raw = read(before / name, 1048576, mode=0o600); total += len(raw)
            require(len(raw) == record['size'] and hashlib.sha256(raw).hexdigest() == record['sha256'] and
                    (before / name).lstat().st_gid == 0 and total <= 8 * 1024 ** 2)
            raw_before[name] = raw
        for name, digest in value['archive_sha256'].items():
            if name not in ('probe.json', 'output.json'):
                require(current[name]['sha256'] == digest)
        require(raw_before['output.json'] == b'')
        fresh = boot_report(decode(raw_prior['fresh-probe.json']), 'probe', user, self.r)
        extra = next(iter(set(current) - set(value['archive_sha256'])))
        require(decode(raw_before['probe.json']) == fresh and decode(raw_before[extra]) == fresh)
        sql = decode(raw_prior['sql-before.json'])
        require(set(sql) == {'proof', 'counts'} and sql['proof'] == value['database_proof'] and
                isinstance(sql['proof'], dict) and
                all(type(sql['proof'][key]) is type(item) for key, item in value['database_proof'].items()) and
                boot_counts(sql['counts']) == value['counts_before'])
        failed = decode(raw_prior['failure.json'])
        require(set(failed) == {'stage', 'cleanup', 'automatic_retry'} and
                failed['stage'] == 'fresh_read_only_nss_check' and failed['automatic_retry'] is False and
                isinstance(failed['cleanup'], dict) and set(failed['cleanup']) ==
                    {'collector_stopped', 'database_read_revoked', 'collector_https_revoked', 'website_restored'} and
                failed['cleanup']['website_restored'] is False and
                all(failed['cleanup'][name] is True for name in ('collector_stopped', 'database_read_revoked', 'collector_https_revoked')))
        previous = decode(raw_prior['manifest.json'])
        require(set(previous) == {'schema', 'boot_id', 'release', 'payloads'} and
                type(previous['schema']) is int and previous['schema'] == 2 and previous['boot_id'] == boot and
                previous['release'] == RELEASE and isinstance(previous['payloads'], dict) and
                set(previous['payloads']) == payloads - {'continue-collector-after-boot.py'} and
                all(boot_digest(digest) for digest in previous['payloads'].values()) and
                decode(raw_prior['helper-update/manifest.json']) == previous)
        plan = decode(raw_prior['helper-update/plan.json'])
        require(set(plan) == {'schema', 'files', 'history_sha256', 'history_identity'} and
                type(plan['schema']) is int and plan['schema'] == 1 and isinstance(plan['files'], dict) and
                set(plan['files']) == {'runner', 'broker', 'policy', 'complete'} and
                plan['history_sha256'] == snapshot['history']['sha256'] and
                plan['history_identity'] == [snapshot['history']['device'], snapshot['history']['inode']])
        for name, item in plan['files'].items():
            require(isinstance(item, dict) and set(item) == {'old_sha256', 'new_sha256', 'mode', 'old_identity',
                                                          'staged_identity', 'security_attributes'} and
                    item['old_sha256'] == prior['helper-update/' + name + '.before']['sha256'] and
                    boot_digest(item['new_sha256']) and type(item['mode']) is int and
                    item['mode'] == (0o755 if name in ('runner', 'broker') else 0o600) and
                    isinstance(item['security_attributes'], dict))
            origin = prior['helper-update/complete.withheld'] if name == 'complete' else snapshot['helpers'][name]
            require(item['old_sha256'] == origin['sha256'] and item['security_attributes'] == origin['security_attributes'])
            for field in ('old_identity', 'staged_identity'):
                require(isinstance(item[field], list) and len(item[field]) == 2 and
                        all(type(number) is int and number >= 0 for number in item[field]) and item[field][1] > 0)
        require(plan['files']['runner']['new_sha256'] == previous['payloads']['collect-only-runner.py'] and
                plan['files']['broker']['new_sha256'] == previous['payloads']['ops-broker.py'] and
                raw_prior['helper-update/complete.withheld'] == raw_prior['helper-update/complete.before'] and
                plan['files']['complete']['old_identity'] ==
                    [prior['helper-update/complete.withheld']['device'], prior['helper-update/complete.withheld']['inode']] and
                plan['files']['complete']['staged_identity'] ==
                    [snapshot['legacy_stage']['device'], snapshot['legacy_stage']['inode']] and
                plan['files']['complete']['new_sha256'] == snapshot['legacy_stage']['sha256'] and
                plan['files']['complete']['security_attributes'] == snapshot['legacy_stage']['security_attributes'])
        old_policy = decode(raw_prior['helper-update/policy.before'])
        old_complete = decode(raw_prior['helper-update/complete.before'])
        require(set(old_policy) == {'schema', 'broker_sha256', 'runner_sha256', 'upgrade_sha256', 'app_release', 'actions'} and
                type(old_policy['schema']) is int and old_policy['schema'] == 1 and
                old_policy['runner_sha256'] == plan['files']['runner']['old_sha256'] and
                old_policy['broker_sha256'] == plan['files']['broker']['old_sha256'] and
                old_policy['upgrade_sha256'] == UPGRADE_SHA and old_policy['app_release'] == RELEASE and
                old_policy['actions'] == list(ACTIONS) and
                set(old_complete) == {'schema', 'status', 'broker_sha256', 'app_release'} and
                type(old_complete['schema']) is int and old_complete['schema'] == 1 and
                old_complete['status'] == 'complete' and old_complete['app_release'] == RELEASE and
                old_complete['broker_sha256'] == old_policy['broker_sha256'])
        replacements = dict(policy=dict(old_policy, runner_sha256=previous['payloads']['collect-only-runner.py'],
                                        broker_sha256=previous['payloads']['ops-broker.py']),
                            complete=dict(old_complete, broker_sha256=previous['payloads']['ops-broker.py']))
        for name, replacement in replacements.items():
            require(plan['files'][name]['new_sha256'] ==
                    hashlib.sha256((json.dumps(replacement, sort_keys=True) + '\n').encode('ascii')).hexdigest())

    def ready_recovery(self, user):
        self.stage = 'history'
        if boot_recovery_present():
            index = self.boot_recovery_receipt(user)
            fd, info = self.environment_fd(disabled=False)
            try:
                if (info.st_dev, info.st_ino, info.st_gid) != (index['db_file_device'], index['db_file_inode'], user.pw_gid):
                    raise Refused('recovered_db_file_changed')
            finally:
                os.close(fd)
            return
        index = document(OPS / 'recovery.json', 8192)
        keys = {'schema', 'status', 'release', 'attempt_sha256', 'attempt_started', 'db_file_device',
                'db_file_inode', 'collector_gid', 'database_proof', 'baseline'}
        baseline = self.recovery_baseline()
        archived = read(OPS / 'pre-seed-attempt-v1.json', 4096, mode=0o600)
        if (not isinstance(index, dict) or set(index) != keys or type(index['schema']) is not int or index['schema'] != 1 or index['status'] != 'ready' or
                index['release'] != RELEASE or index['baseline'] != baseline or
                index['attempt_sha256'] != baseline['attempt_sha256'] or hashlib.sha256(archived).hexdigest() != baseline['attempt_sha256'] or
                index['attempt_started'] != baseline['attempt_started'] or index['collector_gid'] != user.pw_gid or
                index['db_file_device'] != baseline['db_device'] or index['db_file_inode'] != baseline['db_inode']):
            raise Refused('recovery_archive_or_index_mismatch')
        proof = {'database_ok': True, 'role_ok': True, 'role_safe': True, 'migration_ok': True,
                 'other_clients': 0, 'sources': 0, 'articles': 0, 'discoveries': 0, 'fetch_runs': 0}
        recorded = index['database_proof']
        if (recorded != proof or any(recorded.get(k) is not True for k in ('database_ok', 'role_ok', 'role_safe', 'migration_ok')) or
                any(type(recorded.get(k)) is not int for k in ('other_clients', 'sources', 'articles', 'discoveries', 'fetch_runs'))):
            raise Refused('recovery_database_proof_missing')
        fd, info = self.environment_fd(disabled=False)
        try:
            if (info.st_dev, info.st_ino, info.st_gid) != (baseline['db_device'], baseline['db_inode'], user.pw_gid):
                raise Refused('recovered_db_file_changed')
        finally:
            os.close(fd)

    def recover(self, user):
        self.stage = 'attempt'
        if boot_recovery_present():
            raise Refused('prior_or_partial_recovery_requires_review')
        for name in ('recovery.json', 'pre-seed-attempt-v1.json', 'recovery.json.next'):
            if (OPS / name).exists() or (OPS / name).is_symlink():
                raise Refused('prior_or_partial_recovery_requires_review')
        for name in ('seed.json', 'run.json', 'run-attempt.json', 'hourly-approved.json'):
            if (COLLECT / name).exists() or (COLLECT / name).is_symlink():
                raise Refused('seed_or_run_evidence_present')
        attempt_path = COLLECT / 'seed-attempt.json'
        raw = read(attempt_path, 4096, mode=0o600)
        attempt = json.loads(raw, object_pairs_hook=unique)
        if (set(attempt) != {'release', 'mode', 'started'} or attempt['release'] != RELEASE or
                attempt['mode'] != 'seed' or type(attempt['started']) is not int or not 0 < attempt['started'] <= int(time.time())):
            raise Refused('original_seed_attempt_invalid')
        baseline = self.recovery_baseline()
        if hashlib.sha256(raw).hexdigest() != baseline['attempt_sha256'] or attempt['started'] != baseline['attempt_started']:
            raise Refused('different_seed_attempt_not_authorized')
        self.probe_receipt(user)
        states = unit_states(); self.no_timer(states); self.idle(user, states); self.db_only_network(user)
        check = states['check']
        if (check.get('ActiveState') != 'failed' or check.get('Result') != 'signal' or
                check.get('ExecMainCode') != '2' or check.get('ExecMainStatus') != '15' or
                check.get('ExecMainStartTimestampMonotonic') != baseline['check_start_monotonic'] or
                check.get('ExecMainExitTimestampMonotonic') != baseline['check_exit_monotonic']):
            raise Refused('reviewed_pre_seed_failure_not_present')
        self.stage = 'history'
        for alias in ('seed', 'run'):
            if states[alias].get('ExecMainStartTimestampMonotonic') != '0' or self.journal_metadata(alias, attempt['started']):
                raise Refused('seed_or_run_start_evidence_present')
        # Absence of receipts/journal is not proof: a quiet, actual nonsuperuser,
        # read-only DB transaction must independently prove zero side effects.
        fp = self.app_gate(user, states); before_listener = fp.listeners()['8000']
        if not before_listener:
            raise Refused('existing_service_listener_missing')
        fd, info = self.environment_fd(disabled=True)
        try:
            if (info.st_dev, info.st_ino, user.pw_gid) != (baseline['db_device'], baseline['db_inode'], baseline['collector_gid']):
                raise Refused('original_db_file_changed')
            self.mutated = True
            self.stage = 'app_stop'; bounded_command(['/usr/bin/systemctl', 'stop'] + APP_UNITS)
            self.r.no_processes(self.r.pwd.getpwnam('aifinance').pw_uid)
            self.r.no_processes(user.pw_uid)
            proof = self.sql_proof(fd, user)
            self.stage = 'archive'
            if read(attempt_path, 4096, mode=0o600) != raw or attempt_path.stat().st_nlink != 1:
                raise Refused('original_attempt_changed')
            index = {'schema': 1, 'status': 'prepared', 'release': RELEASE,
                     'attempt_sha256': hashlib.sha256(raw).hexdigest(), 'attempt_started': attempt['started'],
                     'db_file_device': info.st_dev, 'db_file_inode': info.st_ino,
                     'collector_gid': user.pw_gid, 'database_proof': proof, 'baseline': baseline}
            write_new(OPS / 'pre-seed-attempt-v1.json', raw)
            write_new(OPS / 'recovery.json', json.dumps(index, sort_keys=True).encode())
            if read(OPS / 'pre-seed-attempt-v1.json', 4096, mode=0o600) != raw:
                raise Refused('archive_verification_failed')
            self.stage = 'restore_db_read'
            now = os.fstat(fd); selected = (CONFIG / 'database.env').lstat()
            if (now.st_dev, now.st_ino, now.st_uid, now.st_gid, stat.S_IMODE(now.st_mode)) != (info.st_dev, info.st_ino, 0, 0, 0o400) or (selected.st_dev, selected.st_ino) != (info.st_dev, info.st_ino):
                raise Refused('db_file_changed_during_recovery')
            # Archive and index are durable BEFORE the original name is removed
            # or group read restored. Any partial recovery blocks future retries.
            attempt_path.unlink(); fsync_dir(COLLECT)
            os.fchown(fd, 0, user.pw_gid); os.fchmod(fd, 0o440); os.fsync(fd)
            self.r.db_environment()  # Validate exact restored file, never expose it.
            index['status'] = 'permission_restored'; replace_index(OPS / 'recovery.json', index)
            restored = self.restart(user, restart=False)
            if fp.listeners()['8000'] != before_listener:
                raise Refused('preview_listener_boundary_changed')
            index['status'] = 'ready'; replace_index(OPS / 'recovery.json', index)
            return dict(restored, recovered_pre_seed=True, history_preserved=True, collector_enabled=False)
        finally:
            os.close(fd)

    def diagnose(self):
        self.stage = 'diagnose'; results = {}
        states = unit_states()
        results['services'] = {alias: public_unit(value) for alias, value in states.items()}
        results['receipts'] = {}
        for name in RECEIPTS:
            path = COLLECT / name
            entry = {'present': path.exists() or path.is_symlink()}
            if entry['present']:
                try:
                    value = document(path, 1048576)
                    entry['valid_object'] = isinstance(value, dict)
                    entry['passed'] = value.get('passed') is True if isinstance(value, dict) else False
                except Exception:
                    entry['valid_object'] = False
            results['receipts'][name[:-5]] = entry
        checks = (('upgrade_gate', self.r.upgrade_gate), ('release', self.r.validate_release),
                  ('units', self.r.verify_units), ('account', self.identity),
                  ('network', lambda: self.r.verify_network(self.identity())))
        results['checks'] = {}
        for stage, function in checks:
            self.stage = stage
            try:
                function(); results['checks'][stage] = {'ok': True}
            except Exception as error:
                results['checks'][stage] = {'ok': False, 'reason': reason(error)}
        results['db_access'] = 'invalid'
        for disabled, classification in ((True, 'revoked'), (False, 'collector_readable')):
            try:
                descriptor, info = self.environment_fd(disabled)
                os.close(descriptor); results['db_access'] = classification
                break
            except Exception:
                pass
        results['resolver_paths'], self.details['resolver_paths'] = resolver_path_metadata()
        self.details['services'] = states
        return results

    def execute(self, action):
        if action == 'diagnose':
            return self.diagnose()
        user = self.base()
        if action == 'disable':
            self.known_timer(unit_states())
            self.stage = 'disable'; self.r.disable(user)
            return {'collector_disabled': True, 'db_read_revoked': True}
        if boot_recovery_present():
            if action == 'recover-pre-seed':
                raise Refused('prior_or_partial_recovery_requires_review')
            self.boot_recovery_receipt(user)
        states = unit_states(); self.idle(user, states); self.db_only_network(user)
        if action == 'restart-preview':
            return self.restart(user)
        self.no_timer(states)
        self.app_gate(user, states)
        self.safe_to_cleanup = True
        if action == 'probe':
            report = self.call('collector_probe', self.r.run_unit, 'probe', user)
            self.details['probe'] = report
            return {'probe_passed': True, 'resources_verified': True, 'database_accessed': False, 'collection_started': False}
        if action == 'recover-pre-seed':
            return self.recover(user)
        if action == 'seed':
            self.ready_recovery(user)
            self.probe_receipt(user)
            self.r.db_environment()
            attempt = COLLECT / 'seed-attempt.json'
            if attempt.exists() or (COLLECT / 'seed.json').exists():
                raise Refused('seed_already_attempted')
            try:
                result = self.call('collector_seed', self.r.first_operation, 'seed', user)
            finally:
                self.mutated = attempt.exists()
            return {'seed_passed': result.get('passed') is True, 'collection_started': False, 'timer_enabled': False}
        if action == 'run':
            self.r.db_environment()
            seed = document(COLLECT / 'seed.json', 1048576)
            if seed.get('passed') is not True or seed.get('release') != RELEASE:
                raise Refused('successful_first_seed_required')
            attempt = COLLECT / 'run-attempt.json'
            if attempt.exists() or (COLLECT / 'run.json').exists():
                raise Refused('run_already_attempted')
            try:
                result = self.call('collector_run', self.r.first_operation, 'run', user)
            finally:
                self.mutated = attempt.exists()
            batch = self.r.batch_summary(result['batch'])
            return {'first_batch_passed': True, 'processed': sum(row['processed'] for row in batch),
                    'created': sum(row['created'] for row in batch), 'revised': sum(row['revised'] for row in batch), 'timer_enabled': False}
        if action == 'enable-hourly':
            self.r.db_environment()
            first = document(COLLECT / 'run.json', 1048576)
            if first.get('passed') is not True or first.get('release') != RELEASE:
                raise Refused('successful_first_run_required')
            self.mutated = True
            result = self.call('enable_hourly', self.r.enable_hourly, user, True)
            self.known_timer(unit_states())
            return {'hourly_enabled': result.get('hourly_enabled') is True, 'admin_view_accepted': True}
        raise Refused('fixed_action_required')

    def cleanup(self, action):
        result = {}
        if not self.safe_to_cleanup or not self.mutated or action not in ('recover-pre-seed', 'seed', 'run', 'enable-hourly'):
            return result
        try:
            user = self.identity(); self.known_timer(unit_states()); self.stage = 'disable'; self.r.disable(user)
            result['collector_disabled'] = True
        except Exception as error:
            result['collector_disabled'] = False; result['disable_reason'] = reason(error)
        try:
            user = self.identity(); self.r.upgrade_gate(); self.r.validate_release()
            self.restart(user, restart=False); result['preview_restored'] = True
        except Exception as error:
            result['preview_restored'] = False; result['preview_reason'] = reason(error)
        return result


def emit(value):
    data = json.dumps(value, sort_keys=True, separators=(',', ':'))
    if len(data.encode()) > 32768:
        data = '{"ok":false,"stage":"audit","reason":"public_output_limit"}'
    print(data)


def main(argv=None):
    action = 'invalid'; broker = None; lock = None; authorized = False
    output = {'ok': False, 'stage': 'entry', 'reason': 'entry_refused'}
    try:
        action = parse(sys.argv[1:] if argv is None else argv)
        if os.getuid() != 0 or os.geteuid() != 0 or Path(__file__).absolute() != SELF:
            raise Refused('fixed_root_entry_required')
        os.environ.clear(); os.environ.update(ENV); os.umask(0o077)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        output['stage'] = 'policy'; value = policy()
        output['stage'] = 'installation'
        if action != 'diagnose':
            installation_complete(value)
        output['stage'] = 'helpers'
        runner = pinned_module('collect-only-runner.py', RUNNER_SHA)
        upgrade = pinned_module('collect-only-upgrade.py', UPGRADE_SHA)
        broker = Broker(runner, upgrade)
        broker.stage = 'lock'; lock = runner.release_lock()
        fcntl.flock(lock, (fcntl.LOCK_SH if action == 'diagnose' else fcntl.LOCK_EX) | fcntl.LOCK_NB)
        authorized = True
        signal.alarm(60 if action == 'diagnose' else 360)
        result = broker.execute(action)
        output = dict(ok=True, action=action, stage='complete', result=result)
    except BaseException as error:
        failed_stage = broker.stage if broker is not None else output['stage']
        output = {'ok': False, 'action': action, 'stage': failed_stage if failed_stage in STAGES else 'entry', 'reason': reason(error)}
        signal.alarm(0)
        if authorized and broker is not None:
            signal.alarm(90)
            try:
                cleanup = broker.cleanup(action)
                if cleanup:
                    output['cleanup'] = cleanup
            except BaseException:
                output['cleanup'] = {'completed': False, 'reason': 'cleanup_interrupted'}
            signal.alarm(0)
    finally:
        signal.alarm(0)
        if lock is not None:
            os.close(lock)
    if authorized and broker is not None:
        try:
            stamp = '%d-%s' % (int(time.time()), os.urandom(8).hex())
            write_new(OPS / ('event-' + stamp + '.json'), json.dumps({'public': output, 'private': broker.details}, sort_keys=True).encode())
        except Exception:
            output['audit_saved'] = False
    emit(output)
    return 0 if output['ok'] else 1


if __name__ == '__main__':
    def interrupted(signum, frame):
        raise Interrupted()
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGALRM):
        signal.signal(sig, interrupted)
    raise SystemExit(main())
