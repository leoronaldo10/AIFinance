#!/usr/bin/python3
"""One reviewed boot-bound collector/NSS recovery. No seed, run or timer.

The unchanged NSS updater owns its four-file transaction. Its two legacy
preconditions are replaced only inside this isolated, pinned root-terminal
entry: old-set validation checks the reviewed postboot baseline; new-set
validation performs recovery while the updater's completion gate is withheld.
Any attempted recovery makes legacy rollback unable to reopen that gate.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import subprocess
import sys
import types
from urllib.parse import unquote, urlsplit

BOOT_PATTERN = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
BOOT = None  # Explicit private invocation and manifest, never a public host ID.
RELEASE = 'd57ba047369e666025347719caee1a4c642abe62'
OPS = Path('/var/lib/aifinance-ops')
COLLECT = Path('/var/lib/aifinance-maintenance/collect-only')
CONFIG = Path('/etc/aifinance-collect')
BIN = Path('/opt/aifinance/bin')
EVIDENCE = OPS / 'collector-boot-v2'
WEBSITE = None
PROC = Path('/proc')
SOURCE_PATTERN = r'/root/aifinance-collector-boot-v2-[A-Za-z0-9]{12}'
UPDATER_SHA = 'e739df77eae255378c7f5982bf9e76fce7f60b8dd1f7f52309bcd754f5f6ba12'
WEBSITE_SHA = 'a484a7b35529e8101644e1dd382cb28b20a4d4142fab0d6c30b56dcbdc949dd7'
RUNNER_SHA = '95716db9e4c32be5555790147ff9b06a7ba8b916e26ade06b81d2cf79132fc35'
BROKER_SHA = '86083919fc3cbd21c8117b790d11c8a29592f25bccc1e30d6e16088f2bed7426'
FILES = {'recover-collector-after-boot.py', 'update-ops-nss-proof.py',
         'recover-preview-after-boot.py', 'collect-only-runner.py', 'ops-broker.py'}
COUNTS = ('articles', 'article_revisions', 'analyses', 'receipts', 'editorial_overrides',
          'editorial_review_state', 'editorial_versions', 'editorial_exports',
          'publications', 'deliveries', 'grouping_decisions', 'pgboss.job')
ENV = dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin', HOME='/', LANG='C', LC_ALL='C', TZ='UTC')
CONTEXT = {'stage': 'entry', 'object': 'root_terminal'}


class Refused(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise Refused(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def trusted_dir(path, mode=None):
    require(path.is_absolute() and '..' not in path.parts, 'unsafe_path')
    for item in (path,) + tuple(path.parents):
        info = item.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and
                not info.st_mode & 0o022 and (item != path or mode is None or stat.S_IMODE(info.st_mode) == mode),
                'unsafe_directory')


def read(path, mode=0o600, maximum=1048576):
    trusted_dir(path.parent)
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno()); selected = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_nlink == 1 and
                stat.S_IMODE(info.st_mode) == mode and info.st_size <= maximum and
                (info.st_dev, info.st_ino) == (selected.st_dev, selected.st_ino), 'unsafe_file')
        raw = stream.read(maximum + 1)
        require(len(raw) == info.st_size, 'file_changed_or_oversize')
        return raw


def unique(rows):
    value = {}
    for key, item in rows:
        require(key not in value, 'duplicate_json_key'); value[key] = item
    return value


def document(raw):
    value = json.loads(raw.decode('ascii'), object_pairs_hook=unique)
    require(isinstance(value, dict), 'json_object_required')
    return value


def module(raw, path, name):
    result = types.ModuleType(name); result.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), result.__dict__)
    return result


def source_inputs(source, expected):
    require(re.fullmatch(SOURCE_PATTERN, str(source)) and re.fullmatch('[0-9a-f]{64}', expected),
            'fixed_source_and_manifest_pin_required')
    trusted_dir(source, 0o700)
    require({p.name for p in source.iterdir()} == FILES | {'manifest.json'}, 'exact_source_payloads_required')
    raw = read(source / 'manifest.json', maximum=8192)
    require(sha(raw) == expected, 'manifest_digest_mismatch')
    manifest = document(raw)
    require(set(manifest) == {'schema', 'boot_id', 'release', 'payloads'} and type(manifest['schema']) is int and
            manifest['schema'] == 2 and manifest['boot_id'] == BOOT and manifest['release'] == RELEASE and
            isinstance(manifest['payloads'], dict) and set(manifest['payloads']) == FILES, 'fixed_manifest_required')
    pinned = {'update-ops-nss-proof.py': UPDATER_SHA, 'recover-preview-after-boot.py': WEBSITE_SHA,
              'collect-only-runner.py': RUNNER_SHA, 'ops-broker.py': BROKER_SHA}
    data = {}
    for name in sorted(FILES):
        data[name] = read(source / name, maximum=262144)
        digest = sha(data[name])
        require(digest == manifest['payloads'][name] and (name not in pinned or digest == pinned[name]),
                'source_payload_digest_mismatch')
        compile(data[name], name, 'exec')
    return manifest, data


def boot():
    require(isinstance(BOOT, str) and re.fullmatch(BOOT_PATTERN, BOOT), 'explicit_reviewed_boot_id_required')
    require((PROC / 'sys/kernel/random/boot_id').read_text().strip() == BOOT, 'reviewed_boot_changed')


def safe_error(error, recovery=None):
    if type(error) is Refused:
        return {'reason': error.args[0]}
    if recovery is not None:
        if type(error) is recovery.u.Refused:
            return {'reason': error.args[0]}
        if isinstance(getattr(recovery.w, 'Refused', None), type) and isinstance(error, recovery.w.Refused):
            return {'reason': recovery.w.safe_error(error)}
    if isinstance(error, subprocess.CalledProcessError):
        fixed = {'/usr/bin/systemctl', '/usr/sbin/nft', '/usr/pgsql-17/bin/psql', '/usr/bin/busctl', '/usr/bin/journalctl'}
        command = error.cmd[0] if isinstance(error.cmd, (tuple, list)) and error.cmd else None
        return dict(reason='fixed_command_failed', executable=Path(command).name if command in fixed else 'fixed_helper',
                    returncode=error.returncode if type(error.returncode) is int else None)
    if isinstance(error, OSError):
        return dict(reason='filesystem_or_process_error', error_type=type(error).__name__, errno=error.errno)
    if recovery is not None:
        return {'reason': recovery.b.reason(error)}
    return {'reason': 'preflight_failed', 'error_type': type(error).__name__}


class Recovery:
    def __init__(self, updater, website, broker, runner, upgrade):
        self.u = updater; self.w = website; self.b = broker; self.r = runner; self.upgrade = upgrade
        self.stage = 'preflight'; self.started = False; self.app_stop_attempted = False
        self.db_fd = None; self.db_info = None; self.worker = None; self.cleanup_result = {}
        self.failure_info = None
        self.u.UPDATE = EVIDENCE / 'helper-update'
        self.u.NEW_RUNNER = RUNNER_SHA; self.u.NEW_BROKER = BROKER_SHA
        self.u.preconditions = self.transaction_preconditions

    def website_evidence(self):
        trusted_dir(WEBSITE, 0o700)
        names = [p.name for p in WEBSITE.iterdir() if re.fullmatch(r'[0-9]{2}-complete\.json', p.name)]
        require(names == ['05-complete.json'] and not any(p.name.endswith('-failure.json') for p in WEBSITE.iterdir()),
                'current_boot_website_completion_required')
        raw = read(WEBSITE / names[0]); value = document(raw)
        origin = document(read(WEBSITE / '01-evidence_create.json'))
        require(value.get('website_healthy') is True and value.get('collector_started') is False and
                value.get('native_ready_written') is False and value.get('listeners', {}).get('8000') == [] and
                isinstance(value.get('preserved_after'), dict) and origin.get('boot_id') == BOOT and
                origin.get('release') == RELEASE and origin.get('preserved_before') == value['preserved_after'],
                'website_evidence_not_healthy')
        for port in ('3100', '3101', '55432'):
            require(value.get('listeners', {}).get(port) and all(row[0] == '0100007F' for row in value['listeners'][port]),
                    'website_evidence_listener_boundary')
        return {'name': names[0], 'sha256': sha(raw)}, value

    def website_gate(self, healthy=True):
        """Check actual healthy/stopped state, exact reviewed activation graph and guard."""
        boot(); self.r.validate_release()
        for name, digest in self.w.HELPER_PINS.items():
            if name not in ('ops-broker.py', 'collect-only-runner.py'):
                CONTEXT.update(object=name)
                require(sha(self.w.read(BIN / name, maximum=262144)) == digest, 'website_helper_changed')
        CONTEXT.update(object='website_units_guard_and_listeners')
        root = dict(LoadState='loaded', ActiveState='active', FragmentPath='/run/systemd/generator/-.mount',
                    SourcePath='/etc/fstab', Where='/', DropInPaths='')
        require(self.w.properties('-.mount', tuple(root)) == root, 'reviewed_active_root_mount_required')
        for unit in self.w.UNITS:
            require(sha(self.w.read(self.w.SYSTEM / unit, mode=0o644)) == self.w.UNIT_PINS[unit], 'website_unit_changed')
            v = self.w.properties(unit); app = unit in (self.w.API, self.w.WEB)
            active = (v['ActiveState'] == 'active') if app and healthy is None else healthy or not app
            expected = dict(LoadState='loaded', ActiveState='active' if active else 'inactive',
                            SubState=('exited' if unit == self.w.GUARD else 'running') if active else 'dead',
                            Result='success', ControlPID='0', UnitFileState='disabled',
                            FragmentPath=str(self.w.SYSTEM / unit), DropInPaths='', NeedDaemonReload='no')
            if app and healthy is None:
                require(v['ActiveState'] in ('active', 'inactive', 'failed'), 'website_restore_unit_busy')
                expected.pop('ActiveState'); expected.pop('SubState'); expected.pop('Result')
            require(all(v[k] == val for k, val in expected.items()), 'website_unit_state_changed')
            require(re.fullmatch('[0-9]+', v['MainPID']) and
                    (v['MainPID'] == '0') == (not active or unit == self.w.GUARD), 'website_unit_pid_changed')
            identity = 'aifinance' if app else 'postgres' if unit == self.w.DB else 'root'
            require(v['User'] == v['Group'] == identity, 'website_unit_identity_changed')
            after = {'network.target'} | ({self.w.GUARD} if app else {'firewalld.service'} if unit == self.w.GUARD else set())
            mounts = {'/var/tmp'} | ({'/run/aifinance-preview-egress'} if unit == self.w.GUARD else
                                    {'/run/aifinance-preview-db'} if unit == self.w.DB else set())
            require(v['BindsTo'].split() == ([self.w.GUARD] if app else []) and after.issubset(set(v['After'].split())) and
                    not any(x.startswith('aifinance-') and x not in after for x in v['After'].split()) and
                    set(v['Requires'].split()) == {'-.mount', 'system.slice', 'sysinit.target'} and
                    v['Slice'] == 'system.slice' and v['DefaultDependencies'] == 'yes' and
                    set(v['RequiresMountsFor'].split()) == mounts and
                    all(not v[k] for k in ('Wants', 'Requisite', 'OnFailure', 'Environment', 'EnvironmentFiles', 'PassEnvironment')),
                    'website_activation_or_environment_changed')
            commands = {self.w.API: '/usr/bin/python3 -I /opt/aifinance/bin/run-preview.py api',
                        self.w.WEB: '/usr/bin/python3 -I /opt/aifinance/bin/run-preview.py web',
                        self.w.DB: '/usr/pgsql-17/bin/postgres -D /var/lib/pgsql/aifinance-preview -c config_file=/etc/aifinance-preview-db/postgresql.conf',
                        self.w.GUARD: '/usr/bin/python3 -I -B /opt/aifinance/bin/egress-guard.py start'}
            self.w.exact_exec(v['ExecStart'], commands[unit])
            for hook in self.w.HOOKS:
                if app and hook == 'ExecStartPre':
                    self.w.exact_exec(v[hook], '/usr/bin/python3 -I -B /opt/aifinance/bin/egress-guard.py verify')
                elif unit == self.w.GUARD and hook == 'ExecStop':
                    self.w.exact_exec(v[hook], '/usr/bin/python3 -I -B /opt/aifinance/bin/egress-guard.py stop')
                else:
                    require(not v[hook], 'unexpected_website_hook')
            budget = {self.w.API: 320, self.w.WEB: 256, self.w.DB: 256, self.w.GUARD: 64}[unit]
            require(v['MemoryAccounting'] == 'yes' and v['MemoryLimit'] == str(budget * 1024 ** 2) and
                    v['TasksMax'] == ('16' if unit == self.w.GUARD else '64') and
                    v['Restart'] == ('on-failure' if app else 'no'), 'website_resource_boundary_changed')
        jobs = self.w.command([self.w.CTL, 'list-jobs', '--no-legend', '--no-pager', '--plain'])
        require(not any('aifinance' in row for row in jobs.splitlines()), 'pending_aifinance_job')
        self.w.guard_verify()
        ports = self.fp.listeners()
        require(ports['8000'] == [], 'port_8000_must_remain_absent')
        for port in ('3100', '3101', '55432'):
            if healthy is None and port != '55432':
                require(all(row[0] == '0100007F' for row in ports[port]), 'website_listener_boundary_changed')
                continue
            if healthy or port == '55432':
                require(ports[port] and all(row[0] == '0100007F' for row in ports[port]), 'website_listener_boundary_changed')
            else:
                require(not ports[port], 'website_writer_listener_remains')
        if healthy is True:
            self.fp.health(RELEASE)

    def original_state(self, broker, runner):
        require(not self.started, 'recovery_attempted_gate_stays_closed')
        self.stage = 'boot'; CONTEXT.update(stage=self.stage, object='current_boot_and_controllers')
        boot(); self.u.no_controllers()
        worker = broker.Broker(runner, self.upgrade)
        self.stage = 'collector_units'; CONTEXT.update(stage=self.stage, object='fixed_collector_units')
        runner.upgrade_gate(); runner.validate_release(); runner.verify_units()
        self.collector_units(runner)
        gate = broker.document(Path('/var/lib/aifinance-maintenance/collect-only-upgrade.json'))
        require(gate.get('restore_verified') is True, 'accepted_restore_required')
        user = worker.identity(); require(user.pw_uid == user.pw_gid == 986, 'fixed_collector_identity_required')
        states = broker.unit_states(); worker.no_timer(states); worker.idle(user, states)
        for alias in ('probe', 'check', 'seed', 'run'):
            v = states[alias]
            require(all(v.get(k) == val for k, val in dict(ActiveState='inactive', SubState='dead', Result='success',
                    MainPID='0', ControlPID='0', ExecMainStartTimestampMonotonic='0',
                    ExecMainExitTimestampMonotonic='0', ExecMainCode='0', ExecMainStatus='0').items()),
                    'collector_not_exact_reviewed_postboot_state')
        self.w.collector_idle()
        require(not runner.network_table(), 'collector_table_must_be_absent_after_boot')
        for name, expected in (('hosts', b''), ('nsswitch.conf', b'hosts: files\n')):
            require(self.w.read(CONFIG / name, maximum=8192, mode=0o440, uid=0, gid=986) == expected,
                    'protected_collector_resolver_changed')
        self.stage = 'collector_history'; CONTEXT.update(stage=self.stage, object='original_collect_receipts')
        for name in ('recovery.json', 'pre-seed-attempt-v1.json', 'recovery.json.next', 'nss-proof-v1-update'):
            self.u.absent(OPS / name)
        for name in ('seed.json', 'run.json', 'run-attempt.json', 'hourly-approved.json', 'launch.json'):
            self.u.absent(COLLECT / name)
        baseline = worker.recovery_baseline()
        raw = read(COLLECT / 'seed-attempt.json', maximum=4096); attempt = document(raw)
        require(set(attempt) == {'release', 'mode', 'started'} and attempt['release'] == RELEASE and
                attempt['mode'] == 'seed' and type(attempt['started']) is int and
                attempt['started'] == baseline['attempt_started'] and sha(raw) == baseline['attempt_sha256'],
                'historical_attempt_changed')
        worker.probe_receipt(user)
        for alias in ('seed', 'run'):
            require(not worker.journal_metadata(alias, attempt['started']), 'historical_collection_start_present')
        self.stage = 'database_metadata'; CONTEXT.update(stage=self.stage, object='collector_database.env_metadata')
        fd, info = worker.environment_fd(disabled=True)
        try:
            require((info.st_dev, info.st_ino, user.pw_gid) == (baseline['db_device'], baseline['db_inode'], baseline['collector_gid']),
                    'original_database_identity_changed')
            selected = (CONFIG / 'database.env').lstat()
            require((selected.st_dev, selected.st_ino) == (info.st_dev, info.st_ino), 'database_path_identity_changed')
        finally:
            os.close(fd)
        self.stage = 'website_evidence'; CONTEXT.update(stage=self.stage, object='current_boot_website_evidence')
        evidence, website = self.website_evidence()
        preserved = website['preserved_after']; records = {}
        trusted_dir(COLLECT, 0o700)
        names = {p.name for p in COLLECT.iterdir()}
        required = {'installed.json', 'probe.json', 'seed-attempt.json', 'network.json', 'output.json'}
        require(required.issubset(names) and all(n in required or re.fullmatch(r'probe-[0-9]+-[0-9a-f]{12}\.json', n) for n in names),
                'collector_history_set_changed')
        for name in sorted(names):
            path = COLLECT / name; raw = read(path)
            require(preserved.get(str(path)) == dict(self.w.attributes(path.lstat()), sha256=sha(raw)),
                    'website_preserved_collector_history_changed')
            records[name] = raw
        require(document(records['network.json']) == {'uid': 986, 'hosts': {}}, 'historical_network_not_db_only')
        for path in (OPS / 'install.json', Path('/var/lib/aifinance-maintenance/collect-only-upgrade.json')):
            raw = read(path)
            require(preserved.get(str(path)) == dict(self.w.attributes(path.lstat()), sha256=sha(raw)),
                    'website_preserved_install_history_changed')
        require(preserved.get(str(CONFIG / 'database.env')) == self.w.metadata(CONFIG / 'database.env', 0, 0, 0o400, 8192),
                'website_preserved_database_metadata_changed')
        self.fp = self.upgrade.helper('first-preview.py')
        self.stage = 'website_live'; CONTEXT.update(stage=self.stage, object='website_units_guard_and_listeners')
        self.website_gate()
        return user, baseline, records, evidence

    def collector_units(self, runner):
        # Extend only the private copy's fixed D-Bus object map. On v239 a
        # missing empty array must be verified through its typed D-Bus property.
        keys = ('Requires', 'Wants', 'BindsTo', 'After', 'Requisite', 'OnFailure', 'Slice',
                'DefaultDependencies', 'RequiresMountsFor', 'NeedDaemonReload', 'Environment',
                'EnvironmentFiles', 'PassEnvironment', 'ExecStartPost', 'ExecStop', 'ExecStopPost', 'ExecReload')
        for mode in ('probe', 'check', 'seed', 'run'):
            unit = runner.unit_name(mode)
            self.w.SERVICE_PATHS[unit] = '/org/freedesktop/systemd1/unit/aifinance_2dcollect_2d' + mode + '_2eservice'
            v = self.w.properties(unit, keys)
            require(set(v['Requires'].split()) == {'-.mount', 'system.slice', 'sysinit.target'} and
                    v['Requisite'].split() == ['aifinance-preview-db.service'] and
                    'aifinance-preview-db.service' in v['After'].split() and
                    not any(x.startswith('aifinance-') and x != 'aifinance-preview-db.service' for x in v['After'].split()) and
                    v['Slice'] == 'system.slice' and v['DefaultDependencies'] == 'yes' and
                    set(v['RequiresMountsFor'].split()) == {'/var/tmp', '/opt/aifinance/releases/' + RELEASE} and
                    v['NeedDaemonReload'] == 'no' and
                    all(not v[k] for k in ('Wants', 'BindsTo', 'OnFailure', 'Environment', 'EnvironmentFiles',
                                           'PassEnvironment', 'ExecStartPost', 'ExecStop', 'ExecStopPost', 'ExecReload')),
                    'collector_activation_or_environment_changed')

    def preflight(self):
        CONTEXT.update(stage='evidence_absence', object='collector_boot_v2_evidence')
        self.u.absent(EVIDENCE); trusted_dir(OPS, 0o700)
        self.user, self.baseline, self.records, self.web_receipt = self.original_state(self.b, self.r)

    def prepared(self, data):
        self.stage = 'prepare_helper_transaction'; CONTEXT.update(stage=self.stage, object='fixed_four_helper_targets')
        u = self.u; old, identities, labels = {}, {}, {}
        u.absent(u.UPDATE)
        for key, path in u.TARGETS.items():
            old[key], identities[key] = u.read(path, u.MODES[key]); labels[key] = u.attrs(path)
            u.absent(path.with_name('.' + path.name + '.nss-v1.next'))
            u.absent(path.with_name('.' + path.name + '.nss-v1.restore'))
        require(sha(old['runner']) == u.OLD_RUNNER and sha(old['broker']) == u.OLD_BROKER, 'old_helper_set_changed')
        policy = self.b.policy(); self.b.installation_complete(policy)
        completion = dict(schema=1, status='complete', broker_sha256=u.OLD_BROKER, app_release=RELEASE)
        require(old['policy'] == u.encoded(policy) and old['complete'] == u.encoded(completion), 'old_policy_bytes_changed')
        new = {'runner': data['collect-only-runner.py'], 'broker': data['ops-broker.py'],
               'policy': u.encoded(dict(policy, runner_sha256=RUNNER_SHA, broker_sha256=BROKER_SHA)),
               'complete': u.encoded(dict(completion, broker_sha256=BROKER_SHA))}
        replacement = module(new['runner'], u.TARGETS['runner'], 'boot_v2_template_runner')
        require(all(self.r.unit_text(m) == replacement.unit_text(m) for m in ('probe', 'check', 'seed', 'run')) and
                self.r.hourly_text() == replacement.hourly_text(), 'unit_templates_must_not_change')
        history = u.read(u.HISTORY, 0o600)
        return dict(old=old, new=new, identities=identities, labels=labels, history=history)

    def transaction_preconditions(self, broker, runner, upgrade):
        if broker.RUNNER_SHA == self.u.OLD_RUNNER:
            self.original_state(broker, runner)
        elif broker.RUNNER_SHA == RUNNER_SHA:
            require(not self.started, 'recovery_callback_must_run_once')
            self.recover(broker, runner)
        else:
            raise Refused('unknown_transaction_helper_set')

    def archive(self):
        destination = EVIDENCE / 'archive'; destination.mkdir(mode=0o700); self.u.sync(EVIDENCE)
        for name, raw in sorted(self.records.items()):
            require(read(COLLECT / name) == raw, 'historical_receipt_changed_before_archive')
            self.u.write_new(destination / name, raw)
            require(read(destination / name) == raw, 'archive_verification_failed')
        self.u.sync(destination)

    def restore_network(self):
        require(not self.r.network_table(), 'collector_network_changed_before_restore')
        payload = self.r.network_rules(self.user.pw_uid, {})
        self.r.command([self.r.NFT, '--check', '--file', '-'], payload)
        self.r.command([self.r.NFT, '--file', '-'], payload)
        self.worker.db_only_network(self.user)

    def counts(self):
        """Actual app login, read-only transactions, fixed regular app-owned relations."""
        os.lseek(self.db_fd, 0, os.SEEK_SET)
        value = self.r.database_url(os.read(self.db_fd, 8193).decode('utf-8'))
        env = dict(ENV, PGPASSWORD=unquote(urlsplit(value).password), PGCONNECT_TIMEOUT='5',
                   PGOPTIONS='-c default_transaction_read_only=on')
        def drop():
            os.setgroups([]); os.setgid(self.user.pw_gid); os.setuid(self.user.pw_uid)
        args = ['/usr/pgsql-17/bin/psql', '-X', '-w', '-q', '-A', '-t', '-v', 'ON_ERROR_STOP=1',
                '-h', '127.0.0.1', '-p', '55432', '-U', 'aifinance_preview', '-d', 'aifinance_preview']
        prefix = "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL search_path=pg_catalog,public,pg_temp; SET LOCAL row_security=off; SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='1s'; "
        present = self.b.bounded_command(args, prefix + "SELECT pg_catalog.to_regclass('pgboss.job') IS NOT NULL; COMMIT;", env=env, drop=drop, limit=64)
        require(present in ('t', 'f'), 'job_relation_presence_unverified')
        names = [n for n in COUNTS if n != 'pgboss.job' or present == 't']
        qualified = [n if '.' in n else 'public.' + n for n in names]
        sql = prefix + "DO $$ BEGIN IF current_user <> 'aifinance_preview' OR pg_catalog.current_setting('transaction_read_only') <> 'on' OR EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members WHERE member=pg_catalog.to_regrole(current_user)) OR "
        sql += "(SELECT pg_catalog.count(*) FROM pg_catalog.pg_class WHERE oid IN (" + ','.join("pg_catalog.to_regclass('%s')" % n for n in qualified) + ") AND relkind IN ('r','p') AND relowner=pg_catalog.to_regrole(current_user)) <> %d THEN RAISE EXCEPTION 'unreviewed_relations'; END IF; END $$; " % len(names)
        sql += 'SELECT pg_catalog.json_build_object(' + ','.join("'%s',(SELECT pg_catalog.count(*) FROM %s)" % (n, q) for n, q in zip(names, qualified)) + ')::text; COMMIT;'
        result = document(self.b.bounded_command(args, sql, env=env, drop=drop, limit=4096).encode())
        if present == 'f':
            result['pgboss.job'] = None
        require(set(result) == set(COUNTS) and all(v is None and k == 'pgboss.job' or type(v) is int and v >= 0 for k, v in result.items()),
                'exact_downstream_counts_required')
        return result

    def same_database(self, disabled):
        info = os.fstat(self.db_fd); selected = (CONFIG / 'database.env').lstat()
        require((info.st_dev, info.st_ino) == (self.db_info.st_dev, self.db_info.st_ino) == (selected.st_dev, selected.st_ino) and
                info.st_uid == 0 and info.st_gid == (0 if disabled else self.user.pw_gid) and
                stat.S_IMODE(info.st_mode) == (0o400 if disabled else 0o440) and info.st_nlink == 1,
                'same_database_inode_required')

    def restore_website(self):
        require(self.website_evidence()[0] == self.web_receipt, 'website_provenance_changed')
        # Mixed state is expected after a partial stop/start. The complete
        # activation graph and effective commands are still checked before start.
        self.website_gate(healthy=None)
        self.w.command([self.w.CTL, 'start', self.w.API, self.w.WEB], timeout=45)
        self.website_gate()

    def cleanup(self):
        result = {}
        try:
            self.r.command([self.r.CTL, 'stop', self.r.unit_name('probe'), self.r.unit_name('check')], timeout=15)
            self.r.no_processes(self.user.pw_uid); result['collector_stopped'] = True
        except BaseException:
            result['collector_stopped'] = False
        try:
            require(self.db_fd is not None, 'database_fd_unavailable')
            info = os.fstat(self.db_fd); selected = (CONFIG / 'database.env').lstat()
            require((info.st_dev, info.st_ino) == (self.db_info.st_dev, self.db_info.st_ino) == (selected.st_dev, selected.st_ino),
                    'database_identity_changed_cleanup_refused')
            os.fchown(self.db_fd, 0, 0); os.fchmod(self.db_fd, 0o400); os.fsync(self.db_fd)
            self.same_database(True); result['database_read_revoked'] = True
        except BaseException:
            result['database_read_revoked'] = False
        try:
            self.worker.db_only_network(self.user); result['collector_https_revoked'] = True
        except BaseException:
            result['collector_https_revoked'] = False
        if self.app_stop_attempted:
            try:
                self.restore_website(); result['website_restored'] = True
            except BaseException:
                result['website_restored'] = False
        else:
            result['website_restored'] = True
        self.cleanup_result = result
        return result

    def recover(self, broker, runner):
        self.started = True; self.b = broker; self.r = runner
        self.worker = broker.Broker(runner, self.upgrade)
        try:
            self.db_fd, self.db_info = self.worker.environment_fd(disabled=True)
            self.stage = 'archive'; self.archive()
            self.stage = 'db_only_network'; self.restore_network()
            self.stage = 'website_pause'; self.website_gate(); self.app_stop_attempted = True
            self.w.command([self.w.CTL, 'stop', self.w.API, self.w.WEB], timeout=45)
            self.website_gate(healthy=False)
            runner.no_processes(runner.pwd.getpwnam('aifinance').pw_uid); runner.no_processes(self.user.pw_uid)
            self.stage = 'read_only_sql'; proof = self.worker.sql_proof(self.db_fd, self.user)
            before = self.counts()
            self.u.write_new(EVIDENCE / 'sql-before.json', self.u.encoded(dict(proof=proof, counts=before)))
            self.stage = 'restore_same_database_permission'; self.same_database(True)
            os.fchown(self.db_fd, 0, self.user.pw_gid); os.fchmod(self.db_fd, 0o440); os.fsync(self.db_fd)
            self.same_database(False); runner.db_environment()
            self.stage = 'fresh_no_network_probe'
            probe = runner.run_unit('probe', self.user)
            self.u.write_new(EVIDENCE / 'fresh-probe.json', self.u.encoded(probe))
            # The original remains in the durable private archive before the
            # installed receipt is replaced. No legacy recovery record is made.
            require(read(COLLECT / 'probe.json') == self.records['probe.json'], 'original_probe_changed')
            runner.replace_owned(COLLECT / 'probe.json', json.dumps(probe, sort_keys=True))
            self.worker.probe_receipt(self.user)
            self.stage = 'fresh_read_only_nss_check'
            check = runner.run_unit('check', self.user)
            runner.validate_snapshot(check['output']['result'], seeded=False)
            require(check['output']['result']['sources'] == [] and check['output']['result']['rawStates'] == [],
                    'preseed_check_not_empty')
            self.u.write_new(EVIDENCE / 'fresh-check.json', self.u.encoded(check))
            runner.no_processes(self.user.pw_uid)
            require(self.worker.sql_proof(self.db_fd, self.user) == proof, 'preseed_proof_changed')
            after = self.counts()
            require(before == after == check['output']['result']['counts'], 'downstream_counts_changed')
            self.u.write_new(EVIDENCE / 'sql-after.json', self.u.encoded(dict(proof=proof, counts=after)))
            self.stage = 'website_restore'; self.restore_website()
            self.worker.no_timer(broker.unit_states()); self.worker.db_only_network(self.user); self.same_database(False)
            self.stage = 'archive_then_rearm'
            attempt = COLLECT / 'seed-attempt.json'
            require(read(attempt) == self.records['seed-attempt.json'] and read(EVIDENCE / 'archive/seed-attempt.json') == self.records['seed-attempt.json'],
                    'original_attempt_changed_before_rearm')
            attempt.unlink(); self.u.sync(COLLECT)
            index = dict(schema=2, status='ready', boot_id=BOOT, release=RELEASE,
                         runner_sha256=RUNNER_SHA, broker_sha256=BROKER_SHA, baseline=self.baseline,
                         db_file_device=self.db_info.st_dev, db_file_inode=self.db_info.st_ino, collector_gid=self.user.pw_gid,
                         database_proof=proof, counts_before=before, counts_after=after,
                         archive_sha256={n: sha(raw) for n, raw in self.records.items()},
                         probe_sha256=sha(read(EVIDENCE / 'fresh-probe.json')),
                         check_sha256=sha(read(EVIDENCE / 'fresh-check.json')),
                         website_evidence=self.web_receipt, listener_8000=[])
            self.u.write_new(EVIDENCE / 'ready.json', self.u.encoded(index))
            self.worker.ready_recovery(self.user)
            self.stage = 'ready'
        except BaseException as error:
            self.failure_info = dict(stage=self.stage, **safe_error(error, self))
            handlers = [(sig, signal.signal(sig, signal.SIG_IGN)) for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)]
            try:
                self.u.write_new(EVIDENCE / 'failure.json', self.u.encoded(dict(stage=self.stage, cleanup=self.cleanup(), automatic_retry=False)))
            finally:
                for sig, handler in handlers:
                    signal.signal(sig, handler)
            raise

    def apply(self, manifest, change):
        EVIDENCE.mkdir(mode=0o700); self.u.sync(OPS)
        self.u.write_new(EVIDENCE / 'manifest.json', self.u.encoded(manifest))
        try:
            result = self.u.apply(self.b, self.r, self.upgrade, manifest, change)
            # The callback can finish before a later completion-gate write,
            # fsync or coherence check fails. Keep its descriptor through the
            # entire updater transaction so those failures also revoke access.
            if not result['ok'] and self.started and not self.cleanup_result:
                handlers = [(sig, signal.signal(sig, signal.SIG_IGN)) for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)]
                try:
                    self.cleanup()
                    self.u.write_new(EVIDENCE / 'failure.json', self.u.encoded(dict(stage='helper_transaction', cleanup=self.cleanup_result, automatic_retry=False)))
                finally:
                    for sig, handler in handlers:
                        signal.signal(sig, handler)
        finally:
            if self.db_fd is not None:
                os.close(self.db_fd); self.db_fd = None
        result.update(boot_id=BOOT, recovery_stage=self.stage, collection_started=False,
                      seed_run_started=False, timer_enabled=False, automatic_retry=False)
        if self.cleanup_result:
            result['cleanup'] = self.cleanup_result
        if self.failure_info:
            result['recovery_failure'] = self.failure_info
        return result


def main(argv=None):
    global BOOT, WEBSITE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('check', 'apply')); parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--expected-boot-id', required=True)
    args = parser.parse_args(argv)
    require(re.fullmatch(BOOT_PATTERN, args.expected_boot_id), 'explicit_reviewed_boot_id_required')
    BOOT = args.expected_boot_id; WEBSITE = Path('/var/lib/aifinance-preview-recovery-' + BOOT)
    require(os.getuid() == os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode and
            os.isatty(0) and os.isatty(1) and not os.environ.get('SUDO_USER') and not os.environ.get('SSH_ORIGINAL_COMMAND'),
            'isolated_root_terminal_required')
    require(Path(__file__).absolute() == args.source / 'recover-collector-after-boot.py', 'fixed_controller_entry_required')
    fd = os.open('/dev/tty', os.O_RDONLY | os.O_NOCTTY)
    try:
        require(os.isatty(fd), 'controlling_root_terminal_required')
    finally:
        os.close(fd)
    os.umask(0o077); resource.setrlimit(resource.RLIMIT_CORE, (0, 0)); os.environ.clear(); os.environ.update(ENV)
    CONTEXT.update(stage='source_inputs', object='fixed_source_payloads')
    manifest, data = source_inputs(args.source, args.manifest_sha256)
    u = module(data['update-ops-nss-proof.py'], args.source / 'update-ops-nss-proof.py', 'held_nss_updater')
    w = module(data['recover-preview-after-boot.py'], args.source / 'recover-preview-after-boot.py', 'held_website_validator')
    old = {}
    CONTEXT.update(stage='installed_helpers', object='fixed_old_helper_set')
    for key, name, pin in (('broker', 'ops-broker.py', u.OLD_BROKER), ('runner', 'collect-only-runner.py', u.OLD_RUNNER),
                           ('upgrade', 'collect-only-upgrade.py', u.UPGRADE)):
        raw = read(BIN / name, 0o755, 262144); require(sha(raw) == pin, 'fixed_old_helper_set_required')
        old[key] = module(raw, BIN / name, 'approved_boot_' + key)
    recovery = Recovery(u, w, old['broker'], old['runner'], old['upgrade'])
    try:
        CONTEXT.update(stage='release_lock', object='canonical_release_lock')
        with u.lock(old['runner']):
            recovery.preflight(); change = recovery.prepared(data)
            result = recovery.apply(manifest, change) if args.action == 'apply' else dict(ok=True, stage='check', changed=False, boot_id=BOOT)
    except BaseException as error:
        result = dict(CONTEXT, ok=False, automatic_retry=False, **safe_error(error, recovery))
    print(json.dumps(result, sort_keys=True)); return 0 if result['ok'] else 1


if __name__ == '__main__':
    def interrupted(signum, frame):
        raise Refused('recovery_interrupted')
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupted)
    try:
        sys.exit(main())
    except BaseException as error:
        if isinstance(error, SystemExit):
            raise
        print(json.dumps(dict(CONTEXT, ok=False, automatic_retry=False, **safe_error(error)), sort_keys=True))
        sys.exit(1)
