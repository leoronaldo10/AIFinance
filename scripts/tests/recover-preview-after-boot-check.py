"""Public fixtures and mocked host actions only: never runs nft/systemctl/PG."""
import ast
import contextlib
import hashlib
import importlib.util
import io
import itertools
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
SOURCE = REPO / 'deploy/native/recover-preview-after-boot.py'
spec = importlib.util.spec_from_file_location('recover', str(SOURCE))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
BOOT = '12345678-1234-4123-8123-123456789abc'


def exec_value(command):
    return '{ path=%s ; argv[]=%s ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }' % (command.split()[0], command)


def root_mount_values():
    return dict(LoadState='loaded', ActiveState='active', FragmentPath='/run/systemd/generator/-.mount',
                SourcePath='/etc/fstab', Where='/', DropInPaths='')


def unit_values(unit, keys=None):
    if unit == '-.mount':
        return root_mount_values()
    app = unit in (m.API, m.WEB)
    identity = 'aifinance' if app else 'postgres' if unit == m.DB else 'root'
    values = dict((name, '') for name in m.PROPERTIES)
    values.update(LoadState='loaded', ActiveState='inactive', SubState='dead', Result='success',
                  MainPID='0', ControlPID='0', UnitFileState='disabled',
                  FragmentPath=str(m.SYSTEM / unit), NeedDaemonReload='no', User=identity, Group=identity,
                  MemoryAccounting='yes', MemoryLimit=str({m.API: 320, m.WEB: 256, m.DB: 256, m.GUARD: 64}[unit] * 1024 ** 2),
                  TasksMax='16' if unit == m.GUARD else '64', Restart='on-failure' if app else 'no',
                  Requires='-.mount system.slice sysinit.target', Slice='system.slice', DefaultDependencies='yes',
                  RequiresMountsFor='/var/tmp')
    # Target read-only sweep: preserve actual implicit ordering alongside the
    # explicit guard BindsTo; guard is not also reported in Requires on v239.
    values['After'] = {
        m.GUARD: '-.mount firewalld.service systemd-tmpfiles-setup.service basic.target system.slice sysinit.target network.target systemd-journald.socket tmp.mount',
        m.DB: 'systemd-tmpfiles-setup.service tmp.mount basic.target sysinit.target system.slice -.mount network.target',
        m.API: 'sysinit.target basic.target system.slice -.mount network.target tmp.mount aifinance-preview-egress.service systemd-journald.socket systemd-tmpfiles-setup.service',
        m.WEB: 'aifinance-preview-egress.service network.target -.mount systemd-journald.socket systemd-tmpfiles-setup.service basic.target tmp.mount sysinit.target system.slice',
    }[unit]
    if app:
        values['BindsTo'] = m.GUARD
        values['ExecStart'] = exec_value('/usr/bin/python3 -I /opt/aifinance/bin/run-preview.py ' + ('api' if unit == m.API else 'web'))
        values['ExecStartPre'] = exec_value('/usr/bin/python3 -I -B /opt/aifinance/bin/egress-guard.py verify')
    elif unit == m.DB:
        values['RequiresMountsFor'] += ' /run/aifinance-preview-db'
        values['ExecStart'] = exec_value('/usr/pgsql-17/bin/postgres -D /var/lib/pgsql/aifinance-preview -c config_file=/etc/aifinance-preview-db/postgresql.conf')
    else:
        values['RequiresMountsFor'] += ' /run/aifinance-preview-egress'
        values['ExecStart'] = exec_value('/usr/bin/python3 -I -B /opt/aifinance/bin/egress-guard.py start')
        values['ExecStop'] = exec_value('/usr/bin/python3 -I -B /opt/aifinance/bin/egress-guard.py stop')
    return values


def probe_fixture():
    return dict(mode='probe', elapsed_seconds=30, output={}, samples=[dict(resolver=None,
        properties=dict(User='aifinance-collect', MemoryAccounting='yes', MemoryLimit=str(256 * 1024 ** 2),
                        TasksMax='32', TimeoutStartUSec='2min', MainPID='123'),
        kernel={'memory.limit_in_bytes': 256 * 1024 ** 2, 'memory.usage_in_bytes': 10000,
                'memory.max_usage_in_bytes': 20000, 'memory.failcnt': 0, 'pids.max': 32,
                'pids.current': 1, 'pid': 123, 'uid': 986, 'cgroup': '/system.slice/aifinance-collect-probe.service'})])


class RecoveryChecks(unittest.TestCase):
    def test_every_embedded_payload_pin_matches_reviewed_local_bytes(self):
        for name, expected in dict(m.HELPER_PINS, **m.UNIT_PINS).items():
            self.assertEqual(hashlib.sha256((REPO / 'deploy/native' / name).read_bytes()).hexdigest(), expected, name)
        self.assertEqual(hashlib.sha256((REPO / 'deploy/native/accept-egress-after-boot.sh').read_bytes()).hexdigest(), m.ACCEPT_SHA)

    def test_python36_syntax_and_exact_original_pg_configuration(self):
        if sys.version_info >= (3, 8):
            ast.parse(SOURCE.read_text(), feature_version=(3, 6))
        else:
            ast.parse(SOURCE.read_text())
        spec = importlib.util.spec_from_file_location('provision_fixture', str(REPO / 'deploy/native/provision-database.py'))
        provision = importlib.util.module_from_spec(spec); spec.loader.exec_module(provision)
        self.assertEqual(m.configuration(), provision.configuration())
        self.assertEqual(m.HBA, provision.HBA)

    def test_source_pins_are_required_before_using_payload(self):
        with patch.object(m, '__file__', '/root/aifinance-preview-recovery-abcdefghijkl/recover-preview-after-boot.py'), \
                patch.object(m, 'trusted_dir'), patch.object(m.Path, 'iterdir', return_value=iter([Path('recover-preview-after-boot.py'), Path('accept-egress-after-boot.sh')])), \
                patch.object(m, 'read', side_effect=[b'controller', b'changed-shell']):
            with self.assertRaisesRegex(m.Refused, 'reviewed recovery refused') as caught:
                m.source_inputs(hashlib.sha256(b'controller').hexdigest())
            self.assertEqual(caught.exception.reason, 'acceptance_payload_digest_mismatch')
        with patch.object(m, '__file__', '/tmp/unsafe/recover-preview-after-boot.py'), patch.object(m, 'read') as read:
            with self.assertRaises(m.Refused): m.source_inputs('a' * 64)
            read.assert_not_called()

    def test_boot_is_exact_and_requires_reviewed_uuid(self):
        with patch.object(m.Path, 'read_text', return_value=BOOT + '\n'):
            m.boot(BOOT)
            for value in ('', 'unreviewed', '12345678-1234-4123-9123-123456789abc'):
                with self.assertRaises(m.Refused): m.boot(value)

    def test_units_require_loaded_commands_dependencies_and_no_hooks(self):
        data = lambda path, **kw: (REPO / 'deploy/native' / path.name).read_bytes()
        with patch.object(m, 'read', side_effect=data), patch.object(m, 'properties', side_effect=unit_values), patch.object(m, 'command', return_value=''):
            m.check_units()
        changes = [('NeedDaemonReload', 'yes'), ('DropInPaths', '/run/override'), ('ExecStartPost', exec_value('/bin/true')),
                   ('ExecStart', exec_value('/usr/bin/python3 -I /opt/aifinance/bin/run-preview.py migrate')),
                   ('BindsTo', ''), ('After', 'network.target'), ('Wants', 'aifinance-collect-run.service'),
                   ('Requires', 'sysinit.target aifinance-collect-seed.service'), ('OnFailure', 'other.service'),
                   ('EnvironmentFiles', '/etc/unreviewed.env'), ('MemoryLimit', '999'), ('Restart', 'always')]
        for key, value in changes:
            def changed(unit, keys=None):
                values = unit_values(unit, keys)
                if unit == m.API: values[key] = value
                return values
            with self.subTest(key=key), patch.object(m, 'read', side_effect=data), patch.object(m, 'properties', side_effect=changed), patch.object(m, 'command', return_value=''):
                with self.assertRaises(m.Refused): m.check_units()
        with patch.object(m, 'read', return_value=b'unreviewed unit'), patch.object(m, 'properties') as prop:
            with self.assertRaises(m.Refused): m.check_unit(m.GUARD)
            prop.assert_not_called()

    def test_target_dependencies_accept_only_exact_sets_in_any_order(self):
        for unit in m.UNITS:
            for ordered in itertools.permutations(('-.mount', 'system.slice', 'sysinit.target')):
                values = unit_values(unit); values['Requires'] = ' '.join(ordered)
                values['RequiresMountsFor'] = ' '.join(reversed(values['RequiresMountsFor'].split()))
                with self.subTest(unit=unit, requires=ordered), patch.object(m, 'properties', return_value=values), \
                        patch.object(m, 'read', side_effect=lambda path, **kw: (REPO / 'deploy/native' / path.name).read_bytes()):
                    m.check_unit(unit)

    def test_target_dependencies_refuse_other_mount_service_slice_or_missing_requirement(self):
        for unit in m.UNITS:
            expected = unit_values(unit)
            changes = [('Requires', 'system.slice sysinit.target'), ('Requires', '-.mount sysinit.target'),
                       ('Requires', '-.mount system.slice'), ('Requires', expected['Requires'] + ' tmp.mount'),
                       ('Requires', expected['Requires'] + ' other.service'), ('Requires', expected['Requires'] + ' custom.slice'),
                       ('Requires', expected['Requires'] + ' ' + m.GUARD), ('Slice', 'custom.slice'),
                       ('DefaultDependencies', 'no'), ('RequiresMountsFor', ''),
                       ('RequiresMountsFor', expected['RequiresMountsFor'] + ' /tmp'),
                       ('RequiresMountsFor', '/var/tmp /run/other-service'),
                       ('Wants', 'tmp.mount'), ('Requisite', 'other.service'), ('OnFailure', 'other.service'),
                       ('Environment', 'UNREVIEWED=value'), ('EnvironmentFiles', '/etc/unreviewed.env'),
                       ('PassEnvironment', 'UNREVIEWED'), ('ExecReload', exec_value('/bin/true')),
                       ('DropInPaths', '/run/unreviewed.conf'), ('NeedDaemonReload', 'yes')]
            if unit in (m.GUARD, m.DB):
                changes.append(('RequiresMountsFor', '/var/tmp'))
            for key, value in changes:
                values = dict(expected); values[key] = value
                with self.subTest(unit=unit, key=key, value=value), patch.object(m, 'properties', return_value=values), \
                        patch.object(m, 'read', side_effect=lambda path, **kw: (REPO / 'deploy/native' / path.name).read_bytes()):
                    with self.assertRaises(m.Refused): m.check_unit(unit)

    def test_root_mount_proof_is_first_and_uses_option_separator(self):
        queries = []
        def command(args, **kwargs):
            queries.append(args)
            if args[1] == 'list-jobs': return ''
            if args[-1] == '-.mount':
                self.assertEqual(args, [m.CTL, 'show', '--no-pager', '--property=' + ','.join(root_mount_values()), '--', '-.mount'])
                values = root_mount_values()
            else:
                values = unit_values(args[2])
            return '\n'.join(key + '=' + value for key, value in values.items())
        with patch.object(m, 'command', side_effect=command), \
                patch.object(m, 'read', side_effect=lambda path, **kw: (REPO / 'deploy/native' / path.name).read_bytes()):
            m.check_units()
        self.assertEqual(queries[0][-2:], ['--', '-.mount'])
        self.assertEqual(len(queries), 6)
        self.assertTrue(all(args[1] in ('show', 'list-jobs') for args in queries))

    def test_unverified_root_mount_blocks_all_preview_checks(self):
        for key, value in (('LoadState', 'not-found'), ('ActiveState', 'inactive'), ('FragmentPath', '/etc/systemd/system/-.mount'),
                           ('SourcePath', '/etc/other-fstab'), ('Where', '/tmp'), ('DropInPaths', '/run/unreviewed.conf')):
            values = root_mount_values(); values[key] = value
            with self.subTest(key=key), patch.object(m, 'properties', return_value=values) as properties, patch.object(m, 'check_unit') as check:
                with self.assertRaises(m.Refused) as caught: m.check_units()
                self.assertEqual(caught.exception.reason, 'reviewed_active_root_mount_required')
                self.assertEqual(caught.exception.target, '-.mount')
                self.assertEqual(properties.call_count, 1); check.assert_not_called()
        for missing in root_mount_values():
            text = '\n'.join(key + '=' + value for key, value in root_mount_values().items() if key != missing)
            with self.subTest(missing=missing), patch.object(m, 'command', return_value=text) as command, patch.object(m, 'check_unit') as check:
                with self.assertRaises(m.Refused) as caught: m.check_units()
                self.assertEqual(caught.exception.reason, 'incomplete_unit_metadata')
                self.assertEqual(caught.exception.target, '-.mount')
                self.assertEqual(command.call_count, 1); check.assert_not_called()

    def test_extra_effective_command_is_refused(self):
        expected = '/usr/bin/python3 -I /opt/aifinance/bin/run-preview.py api'
        m.exact_exec(exec_value(expected), expected)
        for value in (exec_value(expected) + ' ' + exec_value('/bin/true'), exec_value(expected).replace('ignore_errors=no', 'ignore_errors=yes')):
            with self.assertRaises(m.Refused): m.exact_exec(value, expected)

    def test_v239_omitted_arrays_require_typed_empty_dbus_proof_for_all_four_units(self):
        for unit in m.UNITS:
            expected = unit_values(unit)
            omitted = {key for key in m.OMITTED_ARRAYS if not expected[key]}
            text = '\n'.join(key + '=' + value for key, value in expected.items() if key not in omitted)
            queried = []
            def command(args, **kwargs):
                if args[0] == m.CTL:
                    self.assertEqual(args, [m.CTL, 'show', unit, '--no-pager', '--property=' + ','.join(m.PROPERTIES)])
                    return text
                key = args[-1]; queried.append(key)
                self.assertEqual(args, ['/usr/bin/busctl', '--system', '--no-pager', 'get-property',
                                        'org.freedesktop.systemd1', m.SERVICE_PATHS[unit],
                                        'org.freedesktop.systemd1.Service', key])
                self.assertEqual(kwargs, {'timeout': 10, 'maximum': 256})
                self.assertIn(key, omitted)
                return m.OMITTED_ARRAYS[key] + ' 0'
            with self.subTest(unit=unit), patch.object(m, 'command', side_effect=command), \
                    patch.object(m, 'read', side_effect=lambda path, **kw: (REPO / 'deploy/native' / path.name).read_bytes()):
                self.assertEqual(m.properties(unit), expected)
                self.assertEqual(set(queried), omitted)
                queried[:] = []
                m.check_unit(unit)
                self.assertEqual(set(queried), omitted)

    def test_complete_systemctl_metadata_does_not_need_dbus_fallback(self):
        expected = unit_values(m.GUARD)
        text = '\n'.join(key + '=' + value for key, value in expected.items())
        with patch.object(m, 'command', return_value=text) as command:
            self.assertEqual(m.properties(m.GUARD), expected)
            self.assertEqual(command.call_count, 1)

    def test_unsupported_missing_fields_never_default_or_probe_dbus(self):
        for missing in ('ExecStart', 'User', 'MainPID', 'After', 'Environment', 'PassEnvironment',
                        'Slice', 'DefaultDependencies', 'RequiresMountsFor', 'UnknownProperty'):
            keys = m.PROPERTIES + (('UnknownProperty',) if missing == 'UnknownProperty' else ())
            text = '\n'.join(key + '=' + value for key, value in unit_values(m.GUARD).items()
                             if key not in (missing, 'EnvironmentFiles'))
            with self.subTest(missing=missing), patch.object(m, 'command', return_value=text) as command:
                with self.assertRaises(m.Refused) as caught: m.properties(m.GUARD, keys)
                self.assertEqual(caught.exception.reason, 'incomplete_unit_metadata')
                self.assertEqual(command.call_count, 1)
        for unit in ('aifinance-collect-run.service', 'unreviewed.service', m.API + '/escape'):
            with patch.object(m, 'command', return_value='') as command:
                with self.assertRaises(m.Refused): m.properties(unit, ('ExecStop',))
                self.assertEqual(command.call_count, 1)

    def test_malformed_duplicate_unknown_metadata_is_rejected_before_dbus(self):
        for text in ('LoadState', 'LoadState=loaded\nLoadState=loaded', 'Other=unexpected',
                     '=empty-key', 'LoadState=loaded\n\nUser=root'):
            with self.subTest(text=text), patch.object(m, 'command', return_value=text) as command:
                with self.assertRaises(m.Refused) as caught: m.properties(m.GUARD)
                self.assertEqual(caught.exception.reason, 'invalid_unit_metadata')
                self.assertEqual(command.call_count, 1)

    def test_dbus_nonempty_wrong_signature_and_malformed_arrays_fail_closed(self):
        fixtures = {
            'EnvironmentFiles': ('a(sb) 1 "/unreviewed.env" false', 'a(sasbttttuii) 0', 'as 0'),
            'ExecStartPost': ('a(sasbttttuii) 1 "/bin/true"', 'a(sb) 0', 'as 0'),
        }
        for key, outputs in fixtures.items():
            for response in outputs + ('', '0', 'a(sb) 0\nSECRET FIXTURE', m.OMITTED_ARRAYS[key] + ' 00'):
                with self.subTest(key=key, response=response), patch.object(m, 'command', side_effect=['', response]):
                    with self.assertRaises(m.Refused) as caught: m.properties(m.GUARD, (key,))
                    self.assertEqual(caught.exception.reason, 'omitted_unit_array_not_verified_empty')
                    self.assertEqual(caught.exception.target, m.GUARD + ':' + key)
                    self.assertNotIn('SECRET', repr(caught.exception))

    def test_missing_expected_hooks_are_still_required_after_empty_array_proof(self):
        for unit, key in ((m.API, 'ExecStartPre'), (m.WEB, 'ExecStartPre'), (m.GUARD, 'ExecStop')):
            values = unit_values(unit)
            text = '\n'.join(name + '=' + value for name, value in values.items() if name != key)
            with self.subTest(unit=unit, key=key), patch.object(m, 'command', side_effect=[text, m.OMITTED_ARRAYS[key] + ' 0']), \
                    patch.object(m, 'read', side_effect=lambda path, **kw: (REPO / 'deploy/native' / path.name).read_bytes()):
                with self.assertRaises(m.Refused) as caught: m.check_unit(unit)
                self.assertEqual(caught.exception.reason, 'effective_command_mismatch')

    def test_unavailable_failing_or_timed_out_dbus_never_proves_empty(self):
        errors = (FileNotFoundError(2, 'private fixture'), PermissionError(13, 'private fixture'),
                  m.Refused('command_exit_nonzero'), m.Refused('command_timeout'), m.Refused('command_output_limit'),
                  subprocess.TimeoutExpired('/usr/bin/busctl', 10), subprocess.CalledProcessError(1, '/usr/bin/busctl'))
        for error in errors:
            with self.subTest(error=type(error).__name__), patch.object(m, 'command', side_effect=['', error]) as command:
                with self.assertRaises(m.Refused if isinstance(error, OSError) else type(error)) as caught:
                    m.properties(m.GUARD, ('EnvironmentFiles',))
                if isinstance(caught.exception, m.Refused):
                    self.assertEqual(caught.exception.target, m.GUARD + ':EnvironmentFiles')
                    self.assertNotIn('private fixture', m.safe_error(caught.exception))
                self.assertEqual(command.call_count, 2)

    def test_unknown_guard_or_collector_table_blocks_before_start(self):
        for name in ('aifinance_collect_egress_v1', 'aifinance_preview_egress_v1', 'aifinance_preview_probe'):
            value = json.dumps({'nftables': [{'table': {'family': 'inet', 'name': name}}]})
            with patch.object(m, 'command', return_value=value) as command:
                with self.assertRaises(m.Refused): m.tables()
                self.assertEqual(command.call_args[0][0], ['/usr/sbin/nft', '--json', 'list', 'tables'])
        with patch.object(m, 'command', return_value='{"nftables":[{"table":{"family":"inet","name":"firewalld"}}]}'):
            m.tables()
        with patch.object(m, 'command', return_value='{"nftables":[{"nonsense":{}}]}'):
            with self.assertRaises(m.Refused): m.tables()

    def test_systemd239_absent_timer_has_no_service_pid_properties(self):
        def command(args):
            if args[1] == 'list-units': return ''
            name = args[2]
            keys = args[-1].split('=', 1)[1].split(',')
            absent = name in ('aifinance-collect-hourly.service', 'aifinance-collect-hourly.timer')
            values = dict(LoadState='not-found' if absent else 'loaded', ActiveState='inactive', SubState='dead',
                          FragmentPath='', DropInPaths='')
            if not absent:
                values.update(MainPID='0', ControlPID='0', UnitFileState='static')
            if name.endswith('.timer'):
                self.assertNotIn('MainPID', keys); self.assertNotIn('ControlPID', keys)
            return '\n'.join(key + '=' + values[key] for key in keys if key in values)
        with patch.object(m, 'command', side_effect=command), patch.object(m, 'absent'):
            m.collector_idle()

    def test_historical_probe_reports_are_all_preserved_and_unknown_receipts_refused(self):
        extra = 'probe-1234567890-abcdef123456.json'
        files = {
            'installed.json': {'release': m.RELEASE, 'uid': 986},
            'network.json': {'uid': 986, 'hosts': {}},
            'seed-attempt.json': {'release': m.RELEASE, 'mode': 'seed', 'started': 1234567890},
            'probe.json': probe_fixture(), extra: probe_fixture(),
        }
        contents = dict((name, json.dumps(value).encode()) for name, value in files.items())
        contents['output.json'] = b''
        for name, size in m.COLLECT_SIZES.items():
            contents[name] += b' ' * (size - len(contents[name]))
            self.assertEqual(len(contents[name]), size)
        baseline = dict(attempt_sha256=m.sha(contents['seed-attempt.json']), attempt_started=1234567890,
                        collector_gid=986, db_device=1, db_inode=2)
        policy = dict(schema=1, broker_sha256=m.HELPER_PINS['ops-broker.py'], runner_sha256=m.HELPER_PINS['collect-only-runner.py'],
                      upgrade_sha256=m.HELPER_PINS['collect-only-upgrade.py'], app_release=m.RELEASE, actions=m.ACTIONS)
        docs = {'policy.json': policy, 'complete.json': dict(schema=1, status='complete', broker_sha256=policy['broker_sha256'], app_release=m.RELEASE),
                'install.json': dict(application_release=m.RELEASE, actions=m.ACTIONS, recovery_baseline=baseline),
                'collect-only-upgrade.json': dict(status='healthy', release=m.RELEASE, restore_verified=True)}
        def read(path, **kw):
            return contents[path.name] if path.parent == m.COLLECT else json.dumps(docs[path.name]).encode()
        with patch.object(m, 'trusted_dir'), patch.object(m.Path, 'iterdir', lambda path: iter(m.COLLECT / name for name in contents)), \
                patch.object(m, 'read', side_effect=read), patch.object(m.Path, 'lstat', return_value=None), \
                patch.object(m, 'attributes', return_value={}), patch.object(m, 'metadata', return_value={'device': 1, 'inode': 2}), patch.object(m, 'absent'):
            before = m.preserved_state()
            self.assertEqual(before[str(m.COLLECT / extra)]['sha256'], m.sha(contents[extra]))
            changed = probe_fixture(); changed['elapsed_seconds'] = 31
            contents[extra] = json.dumps(changed).encode()
            self.assertNotEqual(before, m.preserved_state())
            contents['seed.json'] = b'{}'
            with self.assertRaises(m.Refused) as caught: m.preserved_state()
            self.assertEqual(caught.exception.reason, 'collector_history_set_changed')
        for key, value in (('uid', 0), ('memory.failcnt', 1), ('pids.max', 999)):
            report = probe_fixture(); report['samples'][0]['kernel'][key] = value
            with self.assertRaises(m.Refused): m.validate_probe(report)

    def test_guard_receipt_or_prior_evidence_is_not_adopted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / 'receipt.json').write_bytes(b'fixture')
            for path in (root, root / 'receipt.json'):
                with self.assertRaises(m.Refused): m.absent(path)
            (root / 'dangling').symlink_to('/nonexistent-fixture')
            with self.assertRaises(m.Refused): m.absent(root / 'dangling')

    def test_lock_is_same_readonly_inode_never_created_or_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / 'state').mkdir(); path = root / 'state/release.lock'; path.write_bytes(b'unchanged'); path.chmod(0o644)
            owner = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
            original = path.stat(); real_open = m.os.open; opened = []
            def record(name, flags, *args):
                opened.append(flags); return real_open(name, flags, *args)
            with patch.object(m, 'ROOT', root), patch.object(m, 'release_parents', return_value=owner), patch.object(m.os, 'open', side_effect=record):
                with m.release_lock(False): self.assertEqual(path.read_bytes(), b'unchanged')
                with m.release_lock(True): self.assertEqual(path.stat().st_ino, original.st_ino)
                self.assertTrue(all(not flags & (os.O_CREAT | os.O_TRUNC | os.O_WRONLY) for flags in opened))
                with m.release_lock(True):
                    with self.assertRaises(BlockingIOError):
                        with m.release_lock(True): pass
                with self.assertRaises(m.Refused):
                    with m.release_lock(True):
                        path.rename(root / 'state/old.lock'); path.write_bytes(b'new'); path.chmod(0o644)

    def test_credential_checks_never_read_values_and_require_separate_modes(self):
        for path, gid, mode in ((m.APP_ENV, 989, 0o640), (m.COLLECT_CONFIG / 'database.env', 0, 0o400)):
            info = SimpleNamespace(st_mode=stat.S_IFREG | mode, st_uid=0, st_gid=gid, st_nlink=1,
                                   st_size=500, st_dev=1, st_ino=2, st_mtime_ns=3, st_ctime_ns=4)
            with patch.object(m, 'trusted_dir'), patch.object(m.Path, 'lstat', return_value=info), patch.object(m.os, 'open') as opened:
                self.assertEqual(m.metadata(path, 0, gid, mode, 8192)['mode'], mode)
                opened.assert_not_called()
                info.st_mode |= 0o004
                with self.assertRaises(m.Refused): m.metadata(path, 0, gid, mode, 8192)

    def test_postgresql_auto_conf_and_recovery_markers_fail_closed(self):
        def lstat(path):
            if path == m.PGDATA:
                return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=26, st_gid=26)
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=26, st_gid=26)
        for payload in (b"shared_preload_libraries='evil'\n", b"include='/tmp/unsafe'\n", b"archive_command='bad'\n", b"restore_command='bad'\n"):
            def read(path, *args, **kwargs):
                if path.parent == m.PGCONFIG:
                    return {'postgresql.conf': m.configuration().encode(), 'pg_hba.conf': m.HBA.encode(), 'pg_ident.conf': b''}[path.name]
                return b'17\n' if path.name == 'PG_VERSION' else payload
            with patch.object(m, 'trusted_dir'), patch.object(m, 'read', side_effect=read), patch.object(m, 'attributes', return_value={}), \
                    patch.object(m.Path, 'lstat', lstat), patch.object(m, 'command') as command:
                with self.assertRaises(m.Refused) as caught: m.database_files()
                self.assertEqual(caught.exception.reason, 'database_auto_conf_startup_hook_refused')
                command.assert_not_called()
        with patch.object(m, 'trusted_dir'), patch.object(m, 'read', return_value=b'unexpected-config'), patch.object(m, 'command') as command:
            with self.assertRaises(m.Refused) as caught: m.database_files()
            self.assertEqual(caught.exception.reason, 'database_fixed_configuration_mismatch')
            command.assert_not_called()

    def test_no_app_collector_or_maintenance_processes(self):
        for uid, cmd in ((989, b'node'), (986, b'sleep'), (0, b'python /opt/aifinance/bin/collect-only-runner.py run'), (26, str(m.PGDATA).encode())):
            with patch.object(m.Path, 'iterdir', return_value=iter([Path('/proc/999999')])), \
                    patch.object(m.Path, 'read_bytes', lambda path: (('Uid: ' + ' '.join([str(uid)] * 4) + '\n').encode() if path.name == 'status' else cmd)):
                with self.assertRaises(m.Refused): m.no_processes()

    def test_listener_boundary(self):
        empty = {port: [] for port in ('8000', '3100', '3101', '55432')}
        fp = SimpleNamespace(listeners=lambda: empty)
        m.listeners(fp)
        empty['8000'] = [('0100007F', 'fixture')]
        with self.assertRaises(m.Refused): m.listeners(fp)
        good = {'8000': [], '3100': [('0100007F', '1')], '3101': [('0100007F', '2')], '55432': [('0100007F', '3')]}
        fp.listeners = lambda: good
        m.listeners(fp, True)
        for port in ('3100', '3101', '55432'):
            saved = good[port]; good[port] = [('00000000', '1')]
            with self.assertRaises(m.Refused): m.listeners(fp, True)
            good[port] = saved

    @contextlib.contextmanager
    def main_fixture(self, failure=None, apply=None):
        held = []
        @contextlib.contextmanager
        def lock(writing):
            held.append(True)
            try: yield {}
            finally: held.pop()
        def preflight(recovery):
            recovery.stage = 'persistent_state'
            if failure: raise m.Refused(failure)
        patches = [patch.object(m.sys, 'flags', SimpleNamespace(isolated=True)), patch.object(m.sys, 'dont_write_bytecode', True),
                   patch.object(m.os, 'getuid', return_value=0), patch.object(m.os, 'geteuid', return_value=0),
                   patch.object(m.os, 'getegid', return_value=0), patch.dict(m.os.environ, {}, clear=True),
                   patch.object(m.resource, 'setrlimit'), patch.object(m.os, 'umask'), patch.object(m, 'source_inputs', return_value=Path('/fixture')),
                   patch.object(m, 'release_lock', side_effect=lock), patch.object(m.Recovery, 'preflight', preflight)]
        with contextlib.ExitStack() as stack:
            for item in patches: stack.enter_context(item)
            if apply: stack.enter_context(patch.object(m.Recovery, 'apply', apply))
            yield held

    def test_check_has_no_writes_events_starts_or_cleanup(self):
        with self.main_fixture(), patch.object(m.Recovery, 'event') as event, patch.object(m.Recovery, 'apply') as apply, \
                patch.object(m.Recovery, 'cleanup') as cleanup, patch.object(m.Path, 'mkdir') as mkdir, patch.object(m, 'write_new') as write, patch('sys.stdout', new_callable=io.StringIO):
            self.assertEqual(m.main(['check', '--script-sha256', 'a' * 64, '--expected-boot-id', BOOT]), 0)
            for mocked in (event, apply, cleanup, mkdir, write): mocked.assert_not_called()

    def test_preflight_failure_causes_no_mutation_and_returns_safe_stage(self):
        with self.main_fixture(failure='collector_history_size_changed'), patch.object(m.Recovery, 'apply') as apply, \
                patch.object(m.Recovery, 'cleanup') as cleanup, patch.object(m.Path, 'mkdir') as mkdir, patch.object(m, 'write_new') as write, patch('sys.stdout', new_callable=io.StringIO) as out:
            self.assertEqual(m.main(['apply', '--script-sha256', 'a' * 64, '--expected-boot-id', BOOT]), 1)
            result = json.loads(out.getvalue()); self.assertEqual(result['stage'], 'persistent_state')
            self.assertEqual(result['reason'], 'collector_history_size_changed')
            for mocked in (apply, cleanup, mkdir, write): mocked.assert_not_called()

    def test_failure_cleanup_and_evidence_happen_while_lock_is_held(self):
        def apply(recovery, source):
            recovery.stage = 'health'; recovery.writing = True
            raise ValueError('SENSITIVE FIXTURE MUST NOT APPEAR')
        with self.main_fixture(apply=apply) as held:
            with patch.object(m.Recovery, 'cleanup', side_effect=lambda: self.assertTrue(held) or {}) as cleanup, \
                    patch.object(m.Recovery, 'event', side_effect=lambda value: self.assertTrue(held)) as event, patch('sys.stdout', new_callable=io.StringIO) as out:
                self.assertEqual(m.main(['apply', '--script-sha256', 'a' * 64, '--expected-boot-id', BOOT]), 1)
                cleanup.assert_called_once(); event.assert_called_once()
                self.assertNotIn('SENSITIVE', out.getvalue()); self.assertEqual(json.loads(out.getvalue())['stage'], 'health')

    def test_success_public_result_reports_durable_evidence(self):
        def apply(recovery, source):
            recovery.writing = True; recovery.stage = 'complete'
        with self.main_fixture(apply=apply), patch.object(m.Recovery, 'cleanup') as cleanup, patch('sys.stdout', new_callable=io.StringIO) as out:
            self.assertEqual(m.main(['apply', '--script-sha256', 'a' * 64, '--expected-boot-id', BOOT]), 0)
            value = json.loads(out.getvalue()); self.assertTrue(value['website_healthy'])
            self.assertEqual(value['evidence_directory'], '/var/lib/aifinance-preview-recovery-' + BOOT)
            cleanup.assert_not_called()

    def test_acceptance_failure_exposes_only_fixed_line_status_integers(self):
        raw = b'sensitive fixture not for output\nSTOP: postboot acceptance command failed at line 238 (status 1)\n'
        with patch.object(m, 'read', return_value=raw):
            self.assertEqual(m.acceptance_failure(Path('/fixture')), {'acceptance_failed_line': 238, 'acceptance_exit_status': 1})
        for raw in (b'STOP: arbitrary sensitive text', b'STOP: postboot acceptance command failed at line 9999 (status 1)\n'):
            with patch.object(m, 'read', return_value=raw): self.assertEqual(m.acceptance_failure(Path('/fixture')), {})

    def exercise_apply(self, fail_stage=None):
        trace = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); recovery = m.Recovery(BOOT); recovery.evidence = root / 'evidence'; recovery.before = {'fixture': 'immutable'}
            recovery.fp = SimpleNamespace(health=lambda release: trace.append('health'), resource_evidence=lambda: {'fixture': 'resources'})
            recovery.database_ready = lambda: trace.append('database_ready')
            real_step = recovery.step
            def step(stage, function, *args):
                if stage == fail_stage:
                    recovery.stage = stage; raise m.Refused('fixture_stage_failure')
                return real_step(stage, function, *args)
            recovery.step = step
            def command(args, **kw):
                trace.append(args)
                if args[0] == '/usr/bin/bash' and fail_stage == 'guard_acceptance': raise m.Refused('command_exit_nonzero')
                if args[:2] == [m.CTL, 'start'] and fail_stage == 'partial_' + args[-1]: raise m.Refused('command_exit_nonzero')
                return ''
            def write(path, raw): path.write_bytes(raw); path.chmod(0o600)
            def properties(unit, keys): return {'ActiveState': 'inactive', 'MainPID': '0', 'ControlPID': '0'}
            with patch.object(m, 'command', side_effect=command), patch.object(m, 'properties', side_effect=properties), \
                    patch.object(m, 'write_new', side_effect=write), patch.object(m.Recovery, 'copy_acceptance'), \
                    patch.object(m, 'read', return_value=b'probe_passed=true\napplication_accepted=false\n'), \
                    patch.object(m, 'guard_verify', side_effect=lambda: trace.append('guard_verify')), patch.object(m.Recovery, 'preserved'), \
                    patch.object(m, 'boot'), patch.object(m, 'release_check'), patch.object(m, 'listeners', return_value={'8000': []}):
                try:
                    recovery.apply(Path('/reviewed/source'))
                except m.Refused:
                    recovery.cleanup()
                self.assertTrue(recovery.evidence.exists())
                self.assertTrue((recovery.evidence / '01-evidence_create.json').exists())
                self.assertEqual(stat.S_IMODE(recovery.evidence.stat().st_mode), 0o700)
            return trace

    def test_successful_order_is_real_guard_then_existing_db_api_web(self):
        trace = self.exercise_apply()
        commands = [x for x in trace if isinstance(x, list)]
        self.assertEqual(commands, [['/usr/bin/bash', '/reviewed/source/accept-egress-after-boot.sh'],
                                    [m.CTL, 'start', m.DB], [m.CTL, 'start', m.API], [m.CTL, 'start', m.WEB]])
        self.assertLess(trace.index('database_ready'), trace.index([m.CTL, 'start', m.API]))
        self.assertEqual(trace.count('guard_verify'), 4)

    def test_failures_stop_only_application_starts_from_this_invocation(self):
        cases = [('guard_acceptance', []), ('database_start', []), ('database_readiness', []), ('api_start', []),
                 ('partial_' + m.API, [m.API]), ('web_start', [m.API]), ('partial_' + m.WEB, [m.WEB, m.API]),
                 ('health', [m.WEB, m.API]), ('resource_acceptance', [m.WEB, m.API]), ('preserved_final', [m.WEB, m.API])]
        for stage, stopped in cases:
            with self.subTest(stage=stage):
                trace = self.exercise_apply(stage)
                self.assertEqual([x[-1] for x in trace if isinstance(x, list) and x[:2] == [m.CTL, 'stop']], stopped)
                self.assertFalse(any('aifinance-collect-' in str(x) for x in trace))
                self.assertFalse(any(isinstance(x, list) and x[:2] == [m.CTL, 'stop'] and x[-1] in (m.DB, m.GUARD) for x in trace))

    def test_persistent_state_changes_block_next_service(self):
        recovery = m.Recovery(BOOT); recovery.before = {'receipt': 'original'}
        with patch.object(m, 'preserved_state', return_value={'receipt': 'changed'}), patch.object(m, 'collector_idle') as idle, patch.object(m, 'tables') as tables:
            with self.assertRaises(m.Refused) as caught: recovery.preserved()
            self.assertEqual(caught.exception.reason, 'persistent_state_changed'); idle.assert_not_called(); tables.assert_not_called()

    def test_existing_database_query_is_app_login_readonly_and_no_migration(self):
        recovery = m.Recovery(BOOT)
        query = unittest.mock.Mock(side_effect=['aifinance_preview|aifinance_preview|on|t|t', '0001_core.sql'])
        recovery.fp = SimpleNamespace(query=query)
        with patch.object(m, 'properties', return_value={'ActiveState': 'active'}), patch.object(m, 'command') as command, \
                patch.object(m, 'release_check', return_value=['0001_core.sql']):
            recovery.database_ready()
            self.assertEqual(command.call_count, 1)
            self.assertTrue(all(call[1] == {'app': True} for call in query.call_args_list))
            self.assertTrue(all(call[0][0].startswith('SELECT ') for call in query.call_args_list))
            self.assertIn('pg_catalog.pg_roles', query.call_args_list[0][0][0])
            self.assertIn("c.relkind='r'", query.call_args_list[0][0][0])
        for unsafe in ('aifinance_preview|aifinance_preview|on|f|t', 'aifinance_preview|aifinance_preview|on|t|f',
                       'aifinance_preview|aifinance_preview|off|t|t', 'aifinance_preview|postgres|on|t|t'):
            recovery.fp.query = unittest.mock.Mock(return_value=unsafe)
            with patch.object(m, 'properties', return_value={'ActiveState': 'active'}), patch.object(m, 'command'), patch.object(m, 'release_check') as release:
                with self.assertRaises(m.Refused): recovery.database_ready()
                self.assertEqual(recovery.fp.query.call_count, 1); release.assert_not_called()
        helper_source = (REPO / 'deploy/native/first-preview.py').read_bytes()
        def read(path):
            return helper_source if path.name == 'first-preview.py' else (REPO / 'deploy/native' / path.name).read_bytes()
        with patch.object(m, 'read', side_effect=read):
            fp = m.pinned_helpers()
            self.assertIn('-c default_transaction_read_only=on', fp.ENV['PGOPTIONS'])
            self.assertIn('-c search_path=pg_catalog', fp.ENV['PGOPTIONS'])


if __name__ == '__main__':
    unittest.main()
