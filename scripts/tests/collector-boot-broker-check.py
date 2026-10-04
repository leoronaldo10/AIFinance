#!/usr/bin/python3
"""Offline boot-bound broker fixtures; never host units, credentials, DB or network."""
import ast
import copy
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parents[2]
BROKER = REPO / 'deploy/native/updates/collector-boot-v2/ops-broker.py'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


m = load('collector_boot_broker', BROKER)
legacy = load('legacy_boot_broker_tests', REPO / 'scripts/tests/ops-broker-check.py')
legacy.m = m
installer = load('boot_broker_install_fixture', REPO / 'scripts/tests/install-ops-check.py')
runner_tests = load('boot_broker_runner_fixture', REPO / 'scripts/tests/collect-only-runner-check.py')
reviewed_runner = load('boot_broker_nss_runner', REPO / 'deploy/native/updates/nss-proof-v1/collect-only-runner.py')
USER = legacy.USER
BOOT = '11111111-1111-4111-8111-111111111111'
NEXT_BOOT = '22222222-2222-4222-8222-222222222222'


def encoded(value):
    return (json.dumps(value, sort_keys=True) + '\n').encode('ascii')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def report(mode):
    kernel = {'uid': USER.pw_uid, 'pid': 123, 'cgroup': '/system.slice/' + m.UNIT_ALIASES[mode],
              'memory.limit_in_bytes': 256 * 1024 ** 2, 'memory.usage_in_bytes': 2000,
              'memory.max_usage_in_bytes': 3000, 'memory.failcnt': 0, 'pids.max': 32, 'pids.current': 1}
    sample = {'kernel': kernel, 'properties': dict(User='aifinance-collect', MainPID='123', MemoryAccounting='yes',
              MemoryLimit=str(256 * 1024 ** 2), TasksMax='32', TimeoutStartUSec='2min'),
              'resolver': None if mode == 'probe' else {'hosts_only': True, 'read_only_bindings': ['/etc/hosts', '/etc/nsswitch.conf']}}
    output = {} if mode == 'probe' else {'mode': mode, 'result': runner_tests.snapshot(False),
                                        'before': dict(kernel), 'after': dict(kernel)}
    return {'mode': mode, 'elapsed_seconds': 30.1 if mode == 'probe' else 2.8, 'samples': [sample], 'output': output}


class Fixture:
    def __enter__(self):
        self.stack = ExitStack(); self.f = self.stack.enter_context(installer.Fixture())
        self.root = self.f.root; ops = self.root / 'boot-ops'; ops.mkdir(mode=0o700)
        paths = {'OPS': ops, 'BIN': installer.m.BIN, 'SELF': installer.m.BIN / 'ops-broker.py',
                 'COLLECT': installer.m.COLLECT, 'CONFIG': installer.m.CONFIG,
                 'INSTALL_EVIDENCE': ops / 'install.json', 'BOOT_ID': self.root / 'boot-id',
                 'BOOT_RECOVERY': ops / 'collector-boot-v2', 'WEBSITE_PARENT': self.root}
        for key, path in paths.items(): self.stack.enter_context(patch.object(m, key, path))
        real_stat = Path.stat
        self.stack.enter_context(patch.object(Path, 'stat', lambda path, *args, **kwargs:
            self.f.lstat(path) if path == m.CONFIG and kwargs.get('follow_symlinks', True) else real_stat(path, *args, **kwargs)))
        self.website_path = m.WEBSITE_PARENT / ('aifinance-preview-recovery-' + BOOT)
        for directory in (m.BOOT_RECOVERY, m.BOOT_RECOVERY / 'archive', self.website_path): directory.mkdir(mode=0o700)
        self.f.put(m.SELF, BROKER.read_bytes(), 0o755)
        self.f.put(m.BIN / 'collect-only-runner.py', (REPO / 'deploy/native/updates/nss-proof-v1/collect-only-runner.py').read_bytes(), 0o755)
        self.f.put(m.BOOT_ID, (BOOT + '\n').encode(), 0o444)
        self.f.metadata(m.CONFIG, st_gid=USER.pw_gid)
        self.db = m.CONFIG / 'database.env'; self.db.chmod(0o440); self.f.metadata(self.db, st_gid=USER.pw_gid)
        self.raw = {'installed.json': encoded({'release': m.RELEASE, 'uid': USER.pw_uid}),
                    'network.json': encoded({'uid': USER.pw_uid, 'hosts': {}}),
                    'seed-attempt.json': encoded({'release': m.RELEASE, 'mode': 'seed', 'started': 1000}),
                    'output.json': b'', 'probe.json': encoded(report('probe')),
                    'probe-1000-0123456789ab.json': encoded(report('probe'))}
        for name, raw in self.raw.items(): self.f.put(m.BOOT_RECOVERY / 'archive' / name, raw)
        st = self.db.stat()
        self.baseline = {'attempt_sha256': sha(self.raw['seed-attempt.json']), 'attempt_started': 1000,
                         'check_start_monotonic': '100', 'check_exit_monotonic': '200',
                         'db_device': st.st_dev, 'db_inode': st.st_ino, 'collector_gid': USER.pw_gid}
        self.f.put(m.INSTALL_EVIDENCE, encoded({'recovery_baseline': self.baseline}))
        self.probe = report('probe'); self.check = report('check')
        self.website = {'website_healthy': True, 'collector_started': False, 'native_ready_written': False,
                        'listeners': {'8000': [], '3100': [['0100007F', '1']], '3101': [['0100007F', '2']], '55432': [['0100007F', '3']]},
                        'preserved_after': {str(m.COLLECT / name): {'sha256': sha(raw)} for name, raw in self.raw.items()}}
        self.value = {'schema': 2, 'status': 'ready', 'boot_id': BOOT, 'release': m.RELEASE,
                      'runner_sha256': m.RUNNER_SHA, 'broker_sha256': sha(BROKER.read_bytes()), 'baseline': self.baseline,
                      'db_file_device': st.st_dev, 'db_file_inode': st.st_ino, 'collector_gid': USER.pw_gid,
                      'database_proof': dict(legacy.PROOF), 'counts_before': dict(self.check['output']['result']['counts']),
                      'counts_after': dict(self.check['output']['result']['counts']),
                      'archive_sha256': {name: sha(raw) for name, raw in self.raw.items()},
                      'probe_sha256': sha(encoded(self.probe)), 'check_sha256': sha(encoded(self.check)),
                      'website_evidence': {'name': '05-complete.json', 'sha256': sha(encoded(self.website))}, 'listener_8000': []}
        self.write_reports(); self.write_website(); self.write_receipt()
        self.b = legacy.broker(); self.b.identity = Mock(return_value=USER)
        self.b.r.run_unit = Mock()
        self.b.r.validate_snapshot = reviewed_runner.validate_snapshot
        self.command = self.stack.enter_context(patch.object(m, 'bounded_command', side_effect=AssertionError('no external command')))
        return self

    def __exit__(self, *args): self.stack.close()

    def write_receipt(self): self.f.put(m.BOOT_RECOVERY / 'ready.json', encoded(self.value))

    def write_reports(self):
        for mode in ('probe', 'check'):
            raw = encoded(getattr(self, mode)); self.f.put(m.BOOT_RECOVERY / ('fresh-' + mode + '.json'), raw)
            self.value[mode + '_sha256'] = sha(raw)

    def write_website(self):
        raw = encoded(self.website); self.f.put(self.website_path / '05-complete.json', raw)
        self.value['website_evidence']['sha256'] = sha(raw)
        self.f.put(self.website_path / '01-evidence_create.json', encoded({'boot_id': BOOT, 'release': m.RELEASE,
                                                                         'preserved_before': self.website['preserved_after']}))


class LegacyCompatibility(legacy.BrokerTests):
    def test_python36_syntax_and_existing_helper_hashes(self):
        ast.parse(BROKER.read_text(), **({'feature_version': (3, 6)} if sys.version_info >= (3, 8) else {}))
        self.assertEqual(sha((REPO / 'deploy/native/updates/nss-proof-v1/collect-only-runner.py').read_bytes()), m.RUNNER_SHA)
        self.assertEqual(sha((REPO / 'deploy/native/collect-only-upgrade.py').read_bytes()), m.UPGRADE_SHA)


class BootBrokerTests(unittest.TestCase):
    def test_recovery_path_is_stable_and_public_broker_has_no_boot_identifier(self):
        self.assertEqual(m.BOOT_RECOVERY.name, 'collector-boot-v2')
        self.assertFalse(hasattr(m, 'BOOT'))
        self.assertEqual(re.findall(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', BROKER.read_text()), [])

    def test_held_updater_and_nss_payload_remain_byte_identical(self):
        expected = {'deploy/native/update-ops-nss-proof.py': 'e739df77eae255378c7f5982bf9e76fce7f60b8dd1f7f52309bcd754f5f6ba12',
                    'deploy/native/updates/nss-proof-v1/collect-only-runner.py': '95716db9e4c32be5555790147ff9b06a7ba8b916e26ade06b81d2cf79132fc35',
                    'deploy/native/updates/nss-proof-v1/ops-broker.py': '42adff178fdbbba3a352f958a48faee96a5e2ef96c2bfe1074c76285669f6d47'}
        for name, digest in expected.items(): self.assertEqual(sha((REPO / name).read_bytes()), digest, name)

    def test_unmodified_legacy_gates_and_exact_actions(self):
        old = ast.parse((REPO / 'deploy/native/updates/nss-proof-v1/ops-broker.py').read_text())
        new = ast.parse(BROKER.read_text())
        before = next(node for node in old.body if isinstance(node, ast.ClassDef) and node.name == 'Broker')
        after = next(node for node in new.body if isinstance(node, ast.ClassDef) and node.name == 'Broker')
        changed = {'ready_recovery', 'restart', 'recover', 'execute'}
        methods = {node.name: node for node in after.body if isinstance(node, ast.FunctionDef)}
        for node in before.body:
            if isinstance(node, ast.FunctionDef) and node.name not in changed:
                self.assertEqual(ast.dump(node), ast.dump(methods[node.name]), node.name)
        self.assertEqual(m.ACTIONS, ('diagnose', 'restart-preview', 'probe', 'recover-pre-seed', 'seed', 'run', 'disable', 'enable-hourly'))

    def test_valid_ready_receipt_is_read_only_without_database_access(self):
        with Fixture() as f:
            before = {str(p): p.read_bytes() for p in f.root.rglob('*') if p.is_file()}
            with patch.object(f.b, 'environment_fd', side_effect=AssertionError('must not access credentials')):
                self.assertEqual(f.b.boot_recovery_receipt(USER), f.value)
            self.assertEqual({str(p): p.read_bytes() for p in f.root.rglob('*') if p.is_file()}, before)
            f.command.assert_not_called()

    def test_seed_readiness_requires_same_database_inode_and_readable_permissions(self):
        with Fixture() as f:
            f.b.ready_recovery(USER)
            f.db.chmod(0o400)
            with self.assertRaises(m.Refused): f.b.ready_recovery(USER)
            f.db.chmod(0o440)
            old = f.db.with_name('original.env'); f.db.rename(old)
            f.f.put(f.db, b'unrelated same path', 0o440); f.f.metadata(f.db, st_gid=USER.pw_gid)
            with self.assertRaises(m.Refused): f.b.ready_recovery(USER)

    def test_stale_boot_and_partial_receipt_never_fall_back_to_legacy(self):
        for issue in ('next_boot', 'missing_ready', 'malformed_ready', 'symlink_directory', 'wrong_group', 'wrong_mode', 'failed_after_ready'):
            with self.subTest(issue=issue), Fixture() as f:
                f.f.put(m.OPS / 'recovery.json', b'{}')
                if issue == 'next_boot': f.f.put(m.BOOT_ID, (NEXT_BOOT + '\n').encode(), 0o444)
                if issue == 'missing_ready': (m.BOOT_RECOVERY / 'ready.json').unlink()
                if issue == 'malformed_ready': f.f.put(m.BOOT_RECOVERY / 'ready.json', b'{"schema":2,"schema":2}')
                if issue == 'symlink_directory':
                    moved = m.BOOT_RECOVERY.with_name('moved'); m.BOOT_RECOVERY.rename(moved); m.BOOT_RECOVERY.symlink_to(moved, target_is_directory=True)
                if issue == 'wrong_group': f.f.metadata(m.BOOT_RECOVERY, st_gid=USER.pw_gid)
                if issue == 'wrong_mode': m.BOOT_RECOVERY.chmod(0o750)
                if issue == 'failed_after_ready': f.f.put(m.BOOT_RECOVERY / 'failure.json', b'{}')
                original = m.document; seen = []
                def document(path, *args): seen.append(path); return original(path, *args)
                with patch.object(m, 'document', side_effect=document), patch.object(f.b, 'environment_fd') as environment:
                    with self.assertRaises((m.Refused, OSError, ValueError)): f.b.ready_recovery(USER)
                    environment.assert_not_called()
                self.assertNotIn(m.OPS / 'recovery.json', seen)

    def test_schema_identity_proof_and_counts_fail_closed(self):
        changes = [('schema', True), ('schema', 1), ('status', 'prepared'), ('boot_id', 'other'), ('release', '0' * 40),
                   ('runner_sha256', '0' * 64), ('broker_sha256', '0' * 64), ('db_file_inode', True),
                   ('collector_gid', 0), ('listener_8000', [['0100007F', 'old']]), ('extra', True)]
        for key, value in changes:
            with self.subTest(key=key, value=value), Fixture() as f:
                f.value[key] = value; f.write_receipt()
                with self.assertRaises(m.Refused): f.b.boot_recovery_receipt(USER)
        for issue in ('proof_boolean_count', 'proof_integer_bool', 'proof_extra', 'count_changed', 'count_boolean', 'count_negative', 'count_missing', 'count_extra'):
            with self.subTest(issue=issue), Fixture() as f:
                if issue == 'proof_boolean_count': f.value['database_proof']['sources'] = False
                if issue == 'proof_integer_bool': f.value['database_proof']['database_ok'] = 1
                if issue == 'proof_extra': f.value['database_proof']['other'] = 0
                if issue == 'count_changed': f.value['counts_after']['articles'] = 1
                if issue == 'count_boolean': f.value['counts_before']['articles'] = f.value['counts_after']['articles'] = False
                if issue == 'count_negative': f.value['counts_before']['articles'] = f.value['counts_after']['articles'] = -1
                if issue == 'count_missing': del f.value['counts_before']['articles']
                if issue == 'count_extra': f.value['counts_before']['extra'] = 0
                f.write_receipt()
                with self.assertRaises(m.Refused): f.b.boot_recovery_receipt(USER)

    def test_archives_are_complete_bounded_single_link_and_pinned(self):
        for issue in ('changed_bytes', 'missing_file', 'extra_file', 'traversal_name', 'missing_required', 'hardlink', 'symlink', 'group_directory'):
            with self.subTest(issue=issue), Fixture() as f:
                path = m.BOOT_RECOVERY / 'archive' / 'probe.json'
                if issue == 'changed_bytes': f.f.put(path, path.read_bytes() + b' ')
                if issue == 'missing_file': path.unlink()
                if issue == 'extra_file': f.f.put(path.parent / 'check.json', b'{}')
                if issue == 'traversal_name': f.value['archive_sha256']['../probe.json'] = 'a' * 64
                if issue == 'missing_required': del f.value['archive_sha256']['probe.json']
                if issue == 'hardlink': os.link(str(path), str(f.root / 'hardlink'))
                if issue == 'symlink': path.unlink(); path.symlink_to(m.BOOT_RECOVERY / 'fresh-probe.json')
                if issue == 'group_directory': f.f.metadata(path.parent, st_gid=USER.pw_gid)
                f.write_receipt()
                with self.assertRaises((m.Refused, OSError)): f.b.boot_recovery_receipt(USER)

    def test_fresh_reports_require_nss_kernel_samples_and_zero_seed_side_effects(self):
        for issue in ('probe_short', 'samples_empty', 'resolver_missing', 'resolver_boolean', 'kernel_uid', 'kernel_boolean',
                      'memory_hit', 'tasks_hit', 'check_output_mode', 'check_final_kernel', 'seed_sources', 'raw_states', 'snapshot_counts'):
            with self.subTest(issue=issue), Fixture() as f:
                if issue == 'probe_short': f.probe['elapsed_seconds'] = 24
                if issue == 'samples_empty': f.check['samples'] = []
                if issue == 'resolver_missing': f.check['samples'][0]['resolver'] = None
                if issue == 'resolver_boolean': f.check['samples'][0]['resolver']['hosts_only'] = 1
                if issue == 'kernel_uid': f.check['samples'][0]['kernel']['uid'] = 0
                if issue == 'kernel_boolean': f.check['samples'][0]['kernel']['memory.failcnt'] = False
                if issue == 'memory_hit': f.check['samples'][0]['kernel']['memory.max_usage_in_bytes'] = 256 * 1024 ** 2
                if issue == 'tasks_hit': f.check['samples'][0]['kernel']['pids.current'] = 33
                if issue == 'check_output_mode': f.check['output']['mode'] = 'run'
                if issue == 'check_final_kernel': f.check['output']['after']['uid'] = 0
                if issue == 'seed_sources': f.check['output']['result']['sources'] = runner_tests.snapshot()['sources']
                if issue == 'raw_states': f.check['output']['result']['rawStates'] = [{'processing_state': 'skipped'}]
                if issue == 'snapshot_counts': f.check['output']['result']['counts']['articles'] = 1
                f.write_reports(); f.write_receipt()
                with self.assertRaises((m.Refused, ValueError)): f.b.boot_recovery_receipt(USER)

    def test_website_absent8000_provenance_cannot_be_fabricated_by_ready_receipt(self):
        for issue in ('missing', 'changed_hash', 'not_healthy', 'collector_started', 'native_ready', 'old_listener',
                      'archive_mismatch', 'traversal', 'public_listener', 'missing_db_listener', 'later_failure'):
            with self.subTest(issue=issue), Fixture() as f:
                if issue == 'missing': (f.website_path / '05-complete.json').unlink()
                if issue == 'changed_hash': f.value['website_evidence']['sha256'] = '0' * 64
                if issue == 'not_healthy': f.website['website_healthy'] = False
                if issue == 'collector_started': f.website['collector_started'] = True
                if issue == 'native_ready': f.website['native_ready_written'] = True
                if issue == 'old_listener': f.website['listeners']['8000'] = [['0100007F', 'old']]
                if issue == 'archive_mismatch': f.website['preserved_after'][str(m.COLLECT / 'probe.json')]['sha256'] = '0' * 64
                if issue == 'traversal': f.value['website_evidence']['name'] = '../05-complete.json'
                if issue == 'public_listener': f.website['listeners']['3100'] = [['00000000', '1']]
                if issue == 'missing_db_listener': f.website['listeners']['55432'] = []
                if issue == 'later_failure': f.f.put(f.website_path / '06-failure.json', b'{}')
                if issue not in ('missing', 'changed_hash', 'traversal'): f.write_website()
                f.write_receipt()
                with self.assertRaises((m.Refused, OSError)): f.b.boot_recovery_receipt(USER)

    def test_original_website_boot_and_preservation_must_match(self):
        for issue in ('missing_original', 'other_boot', 'other_release', 'other_preserved', 'different_complete_name'):
            with self.subTest(issue=issue), Fixture() as f:
                path = f.website_path / '01-evidence_create.json'
                original = json.loads(path.read_text())
                if issue == 'other_boot': original['boot_id'] = NEXT_BOOT
                if issue == 'other_release': original['release'] = '0' * 40
                if issue == 'other_preserved': original['preserved_before'] = {}
                f.f.put(path, encoded(original))
                if issue == 'missing_original': path.unlink()
                if issue == 'different_complete_name':
                    (f.website_path / '05-complete.json').rename(f.website_path / '06-complete.json')
                    f.value['website_evidence']['name'] = '06-complete.json'; f.write_receipt()
                with self.assertRaises((m.Refused, OSError)): f.b.boot_recovery_receipt(USER)

    def test_later_output_changes_preserve_bound_receipt_but_fresh_archive_tamper_does_not(self):
        with Fixture() as f:
            f.f.put(m.COLLECT / 'output.json', b'later accepted run output')
            f.b.boot_recovery_receipt(USER)
            fresh = m.BOOT_RECOVERY / 'fresh-probe.json'; f.f.put(fresh, fresh.read_bytes() + b' ')
            with self.assertRaises(m.Refused): f.b.boot_recovery_receipt(USER)

    def test_cleanup_restores_absent8000_website_even_after_database_revocation(self):
        with Fixture() as f:
            f.b.mutated = True; f.b.safe_to_cleanup = True; f.b.known_timer = Mock()
            listeners = {'8000': [], '3100': [('0100007F', '1')], '3101': [('0100007F', '2')], '55432': [('0100007F', '3')]}
            fp = SimpleNamespace(listeners=Mock(return_value=listeners), health=Mock())
            f.b.app_gate = Mock(return_value=fp)
            f.b.r.disable.side_effect = lambda user: f.db.chmod(0o400)
            with patch.object(m, 'unit_states', return_value=legacy.states()), patch.object(m, 'bounded_command') as command:
                result = f.b.cleanup('seed')
            self.assertEqual(result, {'collector_disabled': True, 'preview_restored': True})
            command.assert_called_once_with(['/usr/bin/systemctl', 'start'] + m.APP_UNITS)
            self.assertEqual(f.db.stat().st_mode & 0o777, 0o400)
            f.b.r.first_operation.assert_not_called(); f.b.r.enable_hourly.assert_not_called()

    def test_empty8000_restart_still_requires_loopback_app_db_listeners(self):
        for issue in ('valid', '8000_appeared', 'public_web', 'missing_db'):
            with self.subTest(issue=issue), Fixture() as f:
                f.b.known_timer = Mock()
                before = {'8000': [], '3100': [('0100007F', '1')], '3101': [('0100007F', '2')], '55432': [('0100007F', '3')]}
                after = copy.deepcopy(before)
                if issue == '8000_appeared': after['8000'] = [('0100007F', 'old')]
                if issue == 'public_web': after['3100'] = [('00000000', '1')]
                if issue == 'missing_db': after['55432'] = []
                f.b.app_gate = Mock(return_value=SimpleNamespace(listeners=Mock(side_effect=[before, after]), health=Mock()))
                with patch.object(m, 'unit_states', return_value=legacy.states()), patch.object(m, 'bounded_command'):
                    if issue == 'valid': self.assertTrue(f.b.restart(USER)['preview_healthy'])
                    else:
                        with self.assertRaises(m.Refused): f.b.restart(USER)

    def test_v2_unexpected8000_refuses_restart_and_cleanup_start(self):
        for cleanup in (False, True):
            with self.subTest(cleanup=cleanup), Fixture() as f:
                f.b.known_timer = Mock(); f.b.mutated = True; f.b.safe_to_cleanup = True
                listeners = {'8000': [('0100007F', 'unexpected')], '3100': [('0100007F', '1')],
                             '3101': [('0100007F', '2')], '55432': [('0100007F', '3')]}
                f.b.app_gate = Mock(return_value=SimpleNamespace(listeners=Mock(return_value=listeners), health=Mock()))
                with patch.object(m, 'unit_states', return_value=legacy.states()), patch.object(m, 'bounded_command') as command:
                    if cleanup:
                        result = f.b.cleanup('seed')
                        self.assertTrue(result['collector_disabled']); self.assertFalse(result['preview_restored'])
                        self.assertEqual(result['preview_reason'], 'preview_listener_boundary_changed')
                    else:
                        with self.assertRaises(m.Refused): f.b.restart(USER)
                    command.assert_not_called()

    def test_partial_v2_prevents_all_new_work_but_disable_and_diagnose_still_work(self):
        for action in ('restart-preview', 'probe', 'recover-pre-seed', 'seed', 'run', 'enable-hourly'):
            with self.subTest(action=action), Fixture() as f:
                (m.BOOT_RECOVERY / 'ready.json').unlink(); f.b.base = Mock(return_value=USER)
                with self.assertRaises((m.Refused, OSError)): f.b.execute(action)
                self.assertFalse(f.b.mutated); f.command.assert_not_called()
                f.b.r.run_unit.assert_not_called(); f.b.r.first_operation.assert_not_called(); f.b.r.enable_hourly.assert_not_called()
        with Fixture() as f:
            (m.BOOT_RECOVERY / 'ready.json').unlink(); f.b.base = Mock(return_value=USER); f.b.known_timer = Mock()
            with patch.object(m, 'unit_states', return_value=legacy.states()): self.assertTrue(f.b.execute('disable')['collector_disabled'])
            f.b.diagnose = Mock(return_value={'read_only': True})
            self.assertEqual(f.b.execute('diagnose'), {'read_only': True})

    def test_stale_stable_directory_blocks_next_boot_legacy_fallback_for_all_actions(self):
        for action in ('restart-preview', 'probe', 'recover-pre-seed', 'seed', 'run', 'enable-hourly'):
            with self.subTest(action=action), Fixture() as f:
                f.f.put(m.BOOT_ID, (NEXT_BOOT + '\n').encode(), 0o444)
                f.f.put(m.OPS / 'recovery.json', b'{"legacy":"must never be selected"}')
                f.b.base = Mock(return_value=USER)
                self.assertTrue(m.BOOT_RECOVERY.exists())
                self.assertFalse((m.OPS / ('collector-boot-v2-' + NEXT_BOOT)).exists())
                with self.assertRaises(m.Refused): f.b.execute(action)
                self.assertFalse(f.b.mutated); f.command.assert_not_called()
                f.b.r.run_unit.assert_not_called(); f.b.r.first_operation.assert_not_called(); f.b.r.enable_hourly.assert_not_called()
        with Fixture() as f:
            f.f.put(m.BOOT_ID, (NEXT_BOOT + '\n').encode(), 0o444)
            f.b.base = Mock(return_value=USER); f.b.known_timer = Mock()
            with patch.object(m, 'unit_states', return_value=legacy.states()): self.assertTrue(f.b.execute('disable')['collector_disabled'])
            f.b.diagnose = Mock(return_value={'read_only': True})
            self.assertEqual(f.b.execute('diagnose'), {'read_only': True})

    def test_boot_identifier_is_validated_before_deriving_website_path(self):
        for boot in ('', '../website', 'not-a-uuid', 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA'):
            with self.subTest(boot=boot), Fixture() as f:
                f.f.put(m.BOOT_ID, (boot + '\n').encode(), 0o444)
                with self.assertRaises(m.Refused) as caught: f.b.boot_recovery_receipt(USER)
                self.assertEqual(caught.exception.reason, 'boot_recovery_boot_changed')


if __name__ == '__main__':
    unittest.main()
