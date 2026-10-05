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
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parents[2]
BROKER = REPO / 'deploy/native/updates/collector-boot-v2/ops-broker.py'
V3_BROKER = REPO / 'deploy/native/updates/collector-boot-v3/ops-broker.py'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


m = load('collector_boot_broker', BROKER)
v3 = load('collector_continuation_broker', V3_BROKER)
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
        if hasattr(m, 'BOOT_CONTINUATION'): paths['BOOT_CONTINUATION'] = ops / 'collector-boot-v3'
        for key, path in paths.items(): self.stack.enter_context(patch.object(m, key, path))
        self.evidence = m.BOOT_RECOVERY
        real_stat = Path.stat
        self.stack.enter_context(patch.object(Path, 'stat', lambda path, *args, **kwargs:
            self.f.lstat(path) if path == m.CONFIG and kwargs.get('follow_symlinks', True) else real_stat(path, *args, **kwargs)))
        self.website_path = m.WEBSITE_PARENT / ('aifinance-preview-recovery-' + BOOT)
        for directory in (m.BOOT_RECOVERY, m.BOOT_RECOVERY / 'archive', self.website_path): directory.mkdir(mode=0o700)
        self.f.put(m.SELF, BROKER.read_bytes(), 0o755)
        runner = BROKER.parent / 'collect-only-runner.py' if m is v3 else REPO / 'deploy/native/updates/nss-proof-v1/collect-only-runner.py'
        self.f.put(m.BIN / 'collect-only-runner.py', runner.read_bytes(), 0o755)
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

    def write_receipt(self): self.f.put(self.evidence / 'ready.json', encoded(self.value))

    def write_reports(self):
        for mode in ('probe', 'check'):
            raw = encoded(getattr(self, mode)); self.f.put(self.evidence / ('fresh-' + mode + '.json'), raw)
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


class V3Module:
    def setUp(self):
        self.modules = ExitStack()
        self.modules.enter_context(patch.dict(globals(), m=v3, BROKER=V3_BROKER))
        self.modules.enter_context(patch.object(legacy, 'm', v3))

    def tearDown(self):
        self.modules.close()


class V3LegacyCompatibility(V3Module, LegacyCompatibility):
    def test_python36_syntax_and_existing_helper_hashes(self):
        ast.parse(BROKER.read_text(), **({'feature_version': (3, 6)} if sys.version_info >= (3, 8) else {}))
        self.assertEqual(sha((BROKER.parent / 'collect-only-runner.py').read_bytes()), m.RUNNER_SHA)
        self.assertEqual(sha((REPO / 'deploy/native/collect-only-upgrade.py').read_bytes()), m.UPGRADE_SHA)


class V3BootCompatibility(V3Module, BootBrokerTests):
    pass


class ContinuationFixture(Fixture):
    def record(self, path):
        info = path.lstat()
        return dict(device=info.st_dev, inode=info.st_ino, uid=info.st_uid, gid=info.st_gid,
                    mode=stat.S_IMODE(info.st_mode), size=info.st_size, mtime_ns=info.st_mtime_ns,
                    ctime_ns=info.st_ctime_ns, sha256=sha(path.read_bytes()), security_attributes={})

    def __enter__(self):
        super(ContinuationFixture, self).__enter__()
        prior = m.BOOT_RECOVERY
        (prior / 'ready.json').unlink(); (prior / 'fresh-check.json').unlink()
        self.evidence = m.BOOT_CONTINUATION
        for directory in (self.evidence, self.evidence / 'archive', self.evidence / 'attempt-before', prior / 'helper-update'):
            directory.mkdir(mode=0o700)
        for name, raw in self.raw.items(): self.f.put(self.evidence / 'archive' / name, raw)
        self.current = dict(self.raw)
        self.current['probe.json'] = encoded(self.probe)
        self.current['probe-2000-abcdef012345.json'] = encoded(self.probe)
        for name, raw in self.current.items(): self.f.put(self.evidence / 'attempt-before' / name, raw)
        self.previous = dict(schema=2, boot_id=BOOT, release=m.RELEASE, payloads={name: sha(raw) for name, raw in {
            'recover-collector-after-boot.py': (REPO / 'deploy/native/recover-collector-after-boot.py').read_bytes(),
            'update-ops-nss-proof.py': (REPO / 'deploy/native/update-ops-nss-proof.py').read_bytes(),
            'recover-preview-after-boot.py': (REPO / 'deploy/native/recover-preview-after-boot.py').read_bytes(),
            'collect-only-runner.py': (REPO / 'deploy/native/updates/nss-proof-v1/collect-only-runner.py').read_bytes(),
            'ops-broker.py': (REPO / 'deploy/native/updates/collector-boot-v2/ops-broker.py').read_bytes()}.items()})
        self.f.put(prior / 'manifest.json', encoded(self.previous))
        self.f.put(prior / 'helper-update/manifest.json', encoded(self.previous))
        self.failure = dict(stage='fresh_read_only_nss_check', automatic_retry=False,
                            cleanup=dict(collector_stopped=True, database_read_revoked=True,
                                         collector_https_revoked=True, website_restored=False))
        self.f.put(prior / 'failure.json', encoded(self.failure))
        self.f.put(prior / 'sql-before.json', encoded(dict(proof=legacy.PROOF, counts=self.value['counts_before'])))
        policy = dict(schema=1, broker_sha256=sha(b'old broker'), runner_sha256=sha(b'old runner'),
                      upgrade_sha256=m.UPGRADE_SHA, app_release=m.RELEASE, actions=list(m.ACTIONS))
        complete = dict(schema=1, status='complete', broker_sha256=policy['broker_sha256'], app_release=m.RELEASE)
        old = dict(runner=b'old runner', broker=b'old broker', policy=encoded(policy), complete=encoded(complete))
        new = dict(runner=self.previous['payloads']['collect-only-runner.py'], broker=self.previous['payloads']['ops-broker.py'],
                   policy=sha(encoded(dict(policy, runner_sha256=self.previous['payloads']['collect-only-runner.py'],
                                           broker_sha256=self.previous['payloads']['ops-broker.py']))),
                   complete=sha(encoded(dict(complete, broker_sha256=self.previous['payloads']['ops-broker.py']))))
        self.f.put(prior / 'helper-update/complete.withheld', old['complete'])
        self.f.put(m.OPS / '.complete.json.nss-v1.next', encoded(dict(complete, broker_sha256=self.previous['payloads']['ops-broker.py'])))
        files = {}; helpers = {}
        for name, raw in old.items():
            mode = 0o755 if name in ('runner', 'broker') else 0o600
            self.f.put(prior / ('helper-update/' + name + '.before'), raw)
            original = prior / 'helper-update/complete.withheld' if name == 'complete' else self.root / ('old-' + name)
            if name != 'complete':
                self.f.put(original, raw, mode); helpers[name] = self.record(original)
            info = original.lstat()
            staged = (m.OPS / '.complete.json.nss-v1.next').lstat()
            files[name] = dict(old_sha256=sha(raw), new_sha256=new[name], mode=mode,
                               old_identity=[info.st_dev, info.st_ino], staged_identity=[staged.st_dev, staged.st_ino], security_attributes={})
        history = self.record(m.INSTALL_EVIDENCE)
        self.plan = dict(schema=1, files=files, history_sha256=history['sha256'], history_identity=[history['device'], history['inode']])
        self.f.put(prior / 'helper-update/plan.json', encoded(self.plan))
        self.manifest = dict(schema=3, boot_id=BOOT, release=m.RELEASE,
            payloads=dict(self.previous['payloads'], **{'continue-collector-after-boot.py': sha(b'continuation controller'),
                'collect-only-runner.py': m.RUNNER_SHA, 'ops-broker.py': sha(BROKER.read_bytes())}),
            predecessor=dict(manifest_sha256=sha(encoded(self.previous)), failure_sha256=sha(encoded(self.failure)),
                             website_sha256=self.value['website_evidence']['sha256']))
        database = self.record(self.db)
        database.pop('sha256'); database.pop('security_attributes'); database.update(gid=0, mode=0o400)
        self.snapshot = dict(schema=3, boot_id=BOOT, release=m.RELEASE, manifest_sha256=sha(encoded(self.manifest)),
            prior={str(path.relative_to(prior)): self.record(path) for path in prior.rglob('*') if path.is_file()},
            current={name: self.record(self.evidence / 'attempt-before' / name) for name in self.current},
            database=database, units={mode: {'ActiveState': 'failed' if mode == 'check' else 'inactive'} for mode in ('probe', 'check', 'seed', 'run')},
            helpers=helpers, history=history, legacy_stage=self.record(m.OPS / '.complete.json.nss-v1.next'),
            website={name: self.record(self.website_path / name) for name in ('01-evidence_create.json', '05-complete.json')})
        self.value.update(schema=3, continuation={})
        self.write_bindings(); self.write_reports(); self.write_receipt()
        return self

    def write_bindings(self):
        manifest_raw = encoded(self.manifest)
        self.snapshot['manifest_sha256'] = sha(manifest_raw)
        self.f.put(self.evidence / 'manifest.json', manifest_raw)
        self.f.put(self.evidence / 'validated-snapshot.json', encoded(self.snapshot))
        self.value['continuation'] = dict(manifest_sha256=sha(manifest_raw), snapshot_sha256=sha(encoded(self.snapshot)),
            prior_evidence_sha256={name: record['sha256'] for name, record in self.snapshot['prior'].items()},
            attempt_before_sha256={name: record['sha256'] for name, record in self.snapshot['current'].items()})
        self.write_receipt()


class ContinuationBrokerTests(V3Module, unittest.TestCase):
    def test_v2_payload_stays_byte_identical(self):
        self.assertEqual(sha((REPO / 'deploy/native/updates/collector-boot-v2/ops-broker.py').read_bytes()),
                         '86083919fc3cbd21c8117b790d11c8a29592f25bccc1e30d6e16088f2bed7426')

    def test_v3_ready_validates_full_provenance_without_live_database_or_commands(self):
        with ContinuationFixture() as f:
            before = {str(path): path.read_bytes() for path in f.root.rglob('*') if path.is_file()}
            with patch.object(f.b, 'environment_fd', side_effect=AssertionError('no credentials')):
                self.assertEqual(f.b.boot_recovery_receipt(USER), f.value)
            self.assertEqual(before, {str(path): path.read_bytes() for path in f.root.rglob('*') if path.is_file()})
            f.command.assert_not_called()

    def test_v3_archive_stays_original_while_attempt_before_keeps_failed_v2_current(self):
        with ContinuationFixture() as f:
            self.assertNotEqual(set(f.value['archive_sha256']), set(f.value['continuation']['attempt_before_sha256']))
            for name, digest in f.value['archive_sha256'].items():
                self.assertEqual(digest, f.website['preserved_after'][str(m.COLLECT / name)]['sha256'])
                self.assertEqual((m.BOOT_RECOVERY / 'archive' / name).read_bytes(), (f.evidence / 'archive' / name).read_bytes())
            f.b.boot_recovery_receipt(USER)

    def test_v3_presence_blocks_v2_and_legacy_fallback_for_every_action(self):
        for issue in ('empty', 'dangling_symlink', 'symlink', 'failed', 'missing_ready'):
            for action in ('restart-preview', 'probe', 'recover-pre-seed', 'seed', 'run', 'enable-hourly'):
                with self.subTest(issue=issue, action=action), Fixture() as f:
                    f.b.base = Mock(return_value=USER)
                    f.f.put(m.OPS / 'recovery.json', b'{"legacy":"never select"}')
                    if issue == 'dangling_symlink': m.BOOT_CONTINUATION.symlink_to(f.root / 'absent')
                    elif issue == 'symlink': m.BOOT_CONTINUATION.symlink_to(m.BOOT_RECOVERY, target_is_directory=True)
                    else:
                        m.BOOT_CONTINUATION.mkdir(mode=0o700)
                        if issue == 'failed': f.f.put(m.BOOT_CONTINUATION / 'failure.json', b'{}')
                    with self.assertRaises((m.Refused, OSError, ValueError)): f.b.execute(action)
                    self.assertFalse(f.b.mutated); f.command.assert_not_called()
                    f.b.r.run_unit.assert_not_called(); f.b.r.first_operation.assert_not_called(); f.b.r.enable_hourly.assert_not_called()

    def test_v3_failed_after_ready_refuses_even_with_valid_v2(self):
        with ContinuationFixture() as f:
            f.f.put(f.evidence / 'failure.json', b'{}')
            with patch.object(f.b, 'environment_fd') as environment:
                with self.assertRaises(m.Refused): f.b.ready_recovery(USER)
            environment.assert_not_called()

    def test_all_retained_prior_files_and_copied_receipts_are_required_and_immutable(self):
        with ContinuationFixture() as f:
            paths = list(f.snapshot['prior'])
        for name in paths:
            for issue in ('changed', 'missing', 'symlink', 'identity', 'hardlink', 'mode', 'group', 'timestamp'):
                with self.subTest(name=name, issue=issue), ContinuationFixture() as f:
                    path = m.BOOT_RECOVERY / name
                    if issue == 'changed': f.f.put(path, path.read_bytes() + b' ')
                    if issue == 'missing': path.unlink()
                    if issue == 'symlink': path.unlink(); path.symlink_to(f.evidence / 'fresh-probe.json')
                    if issue == 'identity':
                        raw = path.read_bytes(); path.rename(f.root / 'replaced-evidence'); f.f.put(path, raw)
                    if issue == 'hardlink': os.link(str(path), str(f.root / 'extra-link'))
                    if issue == 'mode': path.chmod(0o640)
                    if issue == 'group': f.f.metadata(path, st_gid=USER.pw_gid)
                    if issue == 'timestamp':
                        info = path.lstat(); os.utime(str(path), ns=(info.st_atime_ns, info.st_mtime_ns + 1))
                    with self.assertRaises((m.Refused, OSError, ValueError)): f.b.boot_recovery_receipt(USER)
        for group, name in (('archive', 'probe.json'), ('attempt-before', 'probe.json'), ('attempt-before', 'probe-2000-abcdef012345.json')):
            for issue in ('changed', 'missing', 'symlink', 'extra'):
                with self.subTest(group=group, name=name, issue=issue), ContinuationFixture() as f:
                    path = f.evidence / group / name
                    if issue == 'changed': f.f.put(path, path.read_bytes() + b' ')
                    if issue == 'missing': path.unlink()
                    if issue == 'symlink': path.unlink(); path.symlink_to(f.evidence / 'fresh-probe.json')
                    if issue == 'extra': f.f.put(path.parent / 'extra.json', b'{}')
                    with self.assertRaises((m.Refused, OSError, ValueError)): f.b.boot_recovery_receipt(USER)

    def test_manifest_snapshot_and_receipt_bindings_fail_closed(self):
        for issue in ('manifest_bytes', 'snapshot_bytes', 'manifest_symlink', 'snapshot_symlink', 'manifest_missing', 'snapshot_missing',
                      'manifest_schema', 'manifest_extra', 'manifest_predecessor', 'snapshot_schema', 'snapshot_extra',
                      'snapshot_boot', 'snapshot_database', 'snapshot_prior', 'snapshot_current', 'receipt_prior', 'receipt_attempt'):
            with self.subTest(issue=issue), ContinuationFixture() as f:
                if issue.endswith(('_bytes', '_symlink', '_missing')):
                    path = f.evidence / ('manifest.json' if issue.startswith('manifest') else 'validated-snapshot.json')
                    if issue.endswith('_bytes'): f.f.put(path, path.read_bytes() + b' ')
                    if issue.endswith('_symlink'): path.unlink(); path.symlink_to(f.evidence / 'ready.json')
                    if issue.endswith('_missing'): path.unlink()
                else:
                    if issue == 'manifest_schema': f.manifest['schema'] = True
                    if issue == 'manifest_extra': f.manifest['extra'] = True
                    if issue == 'manifest_predecessor': f.manifest['predecessor']['failure_sha256'] = '0' * 64
                    if issue == 'snapshot_schema': f.snapshot['schema'] = True
                    if issue == 'snapshot_extra': f.snapshot['extra'] = True
                    if issue == 'snapshot_boot': f.snapshot['boot_id'] = NEXT_BOOT
                    if issue == 'snapshot_database': f.snapshot['database']['inode'] += 1
                    if issue == 'snapshot_prior': f.snapshot['prior']['failure.json']['inode'] += 1
                    if issue == 'snapshot_current': f.snapshot['current']['probe.json']['sha256'] = '0' * 64
                    f.write_bindings()
                    if issue == 'receipt_prior': f.value['continuation']['prior_evidence_sha256'].pop('failure.json')
                    if issue == 'receipt_attempt': f.value['continuation']['attempt_before_sha256']['probe.json'] = '0' * 64
                    f.write_receipt()
                with self.assertRaises((m.Refused, OSError, ValueError)): f.b.boot_recovery_receipt(USER)

    def test_other_immutable_evidence_and_security_attributes_are_bound(self):
        for name in ('history', 'legacy_stage', 'website_origin', 'website_complete', 'fresh_probe', 'fresh_check'):
            for issue in ('changed', 'missing', 'symlink'):
                with self.subTest(name=name, issue=issue), ContinuationFixture() as f:
                    paths = dict(history=m.INSTALL_EVIDENCE, legacy_stage=m.OPS / '.complete.json.nss-v1.next',
                        website_origin=f.website_path / '01-evidence_create.json', website_complete=f.website_path / '05-complete.json',
                        fresh_probe=f.evidence / 'fresh-probe.json', fresh_check=f.evidence / 'fresh-check.json')
                    path = paths[name]
                    if issue == 'changed': f.f.put(path, path.read_bytes() + b' ')
                    if issue == 'missing': path.unlink()
                    if issue == 'symlink': path.unlink(); path.symlink_to(f.evidence / 'ready.json')
                    with self.assertRaises((m.Refused, OSError, ValueError)): f.b.boot_recovery_receipt(USER)
        with ContinuationFixture() as f:
            with patch.object(m.os, 'listxattr', return_value=['security.selinux']), patch.object(m.os, 'getxattr', return_value=b'changed'):
                with self.assertRaises(m.Refused): f.b.boot_recovery_receipt(USER)

    def test_semantic_prior_failure_plan_and_manifest_refuse_even_when_rebound(self):
        for issue in ('failure_cleanup', 'failure_stage', 'failure_retry', 'plan_old_hash', 'plan_new_hash',
                      'plan_policy_hash', 'plan_complete_hash', 'plan_stage_identity', 'plan_identity', 'plan_history',
                      'manifest_payload', 'manifest_schema', 'sql_counts', 'sql_proof_type'):
            with self.subTest(issue=issue), ContinuationFixture() as f:
                name = ('failure.json' if issue.startswith('failure') else 'helper-update/plan.json' if issue.startswith('plan')
                        else 'sql-before.json' if issue.startswith('sql') else 'manifest.json')
                path = m.BOOT_RECOVERY / name; value = json.loads(path.read_text())
                if issue == 'failure_cleanup': value['cleanup']['website_restored'] = True
                if issue == 'failure_stage': value['stage'] = 'ready'
                if issue == 'failure_retry': value['automatic_retry'] = True
                if issue == 'plan_old_hash': value['files']['runner']['old_sha256'] = '0' * 64
                if issue == 'plan_new_hash': value['files']['runner']['new_sha256'] = '0' * 64
                if issue == 'plan_policy_hash': value['files']['policy']['new_sha256'] = '0' * 64
                if issue == 'plan_complete_hash': value['files']['complete']['new_sha256'] = '0' * 64
                if issue == 'plan_stage_identity': value['files']['complete']['staged_identity'][1] += 1
                if issue == 'plan_identity': value['files']['complete']['old_identity'][1] += 1
                if issue == 'plan_history': value['history_sha256'] = '0' * 64
                if issue == 'manifest_payload': value['payloads'].pop('ops-broker.py')
                if issue == 'manifest_schema': value['schema'] = True
                if issue == 'sql_counts': value['counts']['articles'] += 1
                if issue == 'sql_proof_type': value['proof']['sources'] = False
                f.f.put(path, encoded(value)); f.snapshot['prior'][name] = f.record(path)
                if name == 'failure.json': f.manifest['predecessor']['failure_sha256'] = sha(encoded(value))
                if name == 'manifest.json': f.manifest['predecessor']['manifest_sha256'] = sha(encoded(value))
                f.write_bindings()
                with self.assertRaises((m.Refused, OSError, ValueError)): f.b.boot_recovery_receipt(USER)

    def test_revoked_database_and_later_collector_output_allow_immutable_website_restore(self):
        with ContinuationFixture() as f:
            f.db.chmod(0o400); f.f.metadata(f.db, st_gid=0)
            f.f.put(m.COLLECT / 'output.json', b'later output')
            with patch.object(f.b, 'environment_fd', side_effect=AssertionError('no credentials')):
                self.assertEqual(f.b.boot_recovery_receipt(USER), f.value)
            f.b.known_timer = Mock()
            listeners = {'8000': [], '3100': [('0100007F', '1')], '3101': [('0100007F', '2')], '55432': [('0100007F', '3')]}
            f.b.app_gate = Mock(return_value=SimpleNamespace(listeners=Mock(return_value=listeners), health=Mock()))
            with patch.object(m, 'unit_states', return_value=legacy.states()), patch.object(m, 'bounded_command') as command:
                self.assertTrue(f.b.restart(USER, restart=False)['preview_healthy'])
            command.assert_called_once_with(['/usr/bin/systemctl', 'start'] + m.APP_UNITS)
            with self.assertRaises(m.Refused): f.b.ready_recovery(USER)


if __name__ == '__main__':
    unittest.main()
