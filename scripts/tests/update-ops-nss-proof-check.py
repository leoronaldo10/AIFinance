#!/usr/bin/python3
"""Offline four-file update fixtures. No host units, database, network or root calls."""
import ast
from contextlib import ExitStack
import importlib.util
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

REPO = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


u = load('ops_nss_update', REPO / 'deploy/native/update-ops-nss-proof.py')
legacy = load('ops_nss_legacy_fixture', REPO / 'scripts/tests/install-ops-check.py')
REAL_CONTROLLERS, REAL_PRECONDITIONS = u.no_controllers, u.preconditions


class Fixture:
    def __enter__(self):
        self.stack = ExitStack(); self.f = self.stack.enter_context(legacy.Fixture())
        for key, path in [('ROOT', legacy.m.ROOT), ('BIN', legacy.m.BIN), ('OPS', legacy.m.STATE),
                          ('COLLECT', legacy.m.COLLECT), ('HISTORY', legacy.m.STATE / 'install.json'),
                          ('UPDATE', legacy.m.STATE / 'nss-proof-v1-update'), ('PROC', self.f.root / 'proc')]:
            self.stack.enter_context(patch.object(u, key, path))
        u.OPS.mkdir(mode=0o700); u.PROC.mkdir()
        paths = {'runner': u.BIN / 'collect-only-runner.py', 'broker': u.BIN / 'ops-broker.py',
                 'policy': u.OPS / 'policy.json', 'complete': u.OPS / 'complete.json'}
        self.stack.enter_context(patch.object(u, 'TARGETS', paths))
        old_runner, new_runner = b'# old reviewed runner\n', b'# new reviewed NSS runner\n'
        self.stack.enter_context(patch.object(u, 'OLD_RUNNER', u.sha(old_runner)))
        self.stack.enter_context(patch.object(u, 'NEW_RUNNER', u.sha(new_runner)))
        old_broker = ('RUNNER_SHA = ' + repr(u.OLD_RUNNER) + '\n').encode()
        new_broker = ('RUNNER_SHA = ' + repr(u.NEW_RUNNER) + '\n').encode()
        self.stack.enter_context(patch.object(u, 'OLD_BROKER', u.sha(old_broker)))
        self.stack.enter_context(patch.object(u, 'NEW_BROKER', u.sha(new_broker)))
        self.old_policy = {'schema': 1, 'broker_sha256': u.OLD_BROKER, 'runner_sha256': u.OLD_RUNNER,
            'upgrade_sha256': u.UPGRADE, 'app_release': legacy.m.APP, 'actions': list(legacy.m.ACTIONS)}
        self.old_complete = {'schema': 1, 'status': 'complete', 'broker_sha256': u.OLD_BROKER, 'app_release': legacy.m.APP}
        self.new_policy = dict(self.old_policy, broker_sha256=u.NEW_BROKER, runner_sha256=u.NEW_RUNNER)
        self.new_complete = dict(self.old_complete, broker_sha256=u.NEW_BROKER)
        self.old = {'runner': old_runner, 'broker': old_broker, 'policy': u.encoded(self.old_policy), 'complete': u.encoded(self.old_complete)}
        self.new = {'runner': new_runner, 'broker': new_broker, 'policy': u.encoded(self.new_policy), 'complete': u.encoded(self.new_complete)}
        for key, path in u.TARGETS.items(): self.f.put(path, self.old[key], u.MODES[key])
        self.f.put(u.HISTORY, b'{"historical_original_install":true}\n')
        self.f.put(u.OPS / 'event-prior.json', b'{"private_original_event":true}\n')
        self.history = u.HISTORY.read_bytes()
        self.runner = self.f.runner; self.runner.hourly_text = lambda: ('original service', 'original timer')
        self.new_runner = SimpleNamespace(unit_text=self.runner.unit_text, hourly_text=self.runner.hourly_text)
        self.upgrade = SimpleNamespace()
        self.broker = self.broker_module(False); self.new_broker = self.broker_module(True)
        self.stack.enter_context(patch.object(u, 'module', side_effect=lambda code, path, name:
            self.new_broker if path == u.TARGETS['broker'] else self.new_runner))
        self.precondition = self.stack.enter_context(patch.object(u, 'preconditions'))
        self.controllers = self.stack.enter_context(patch.object(u, 'no_controllers'))
        self.source = self.f.root / 'update-source'; self.source.mkdir(mode=0o700)
        self.stack.enter_context(patch.object(u, 'SOURCE_PATTERN', str(self.source)))
        self.data = {'updater': b'# pinned updater\n', 'runner': new_runner, 'broker': new_broker}
        for key, name in [('updater', 'update-ops-nss-proof.py'), ('runner', 'collect-only-runner.py'), ('broker', 'ops-broker.py')]:
            self.f.put(self.source / name, self.data[key])
        self.manifest = dict(schema=1, updater_sha256=u.sha(self.data['updater']), runner_sha256=u.NEW_RUNNER, broker_sha256=u.NEW_BROKER)
        self.f.put(self.source / 'update-manifest.json', u.encoded(self.manifest))
        self.pin = u.sha(u.encoded(self.manifest))
        return self

    def __exit__(self, *args):
        self.stack.close()

    def broker_module(self, new):
        expected_policy = self.new_policy if new else self.old_policy
        expected_complete = self.new_complete if new else self.old_complete
        def policy():
            if (u.TARGETS['policy'].read_bytes() != u.encoded(expected_policy) or
                    u.sha(u.TARGETS['broker'].read_bytes()) != expected_policy['broker_sha256']):
                raise ValueError('fixture_policy_mismatch')
            return dict(expected_policy)
        def complete(value):
            if value != expected_policy or u.TARGETS['complete'].read_bytes() != u.encoded(expected_complete):
                raise ValueError('fixture_completion_mismatch')
        return SimpleNamespace(policy=policy, installation_complete=complete, RELEASE=legacy.m.APP,
                               reason=lambda error: 'operation_refused', unique=lambda rows: dict(rows))

    def prepared(self):
        return u.prepared(self.broker, self.runner, self.upgrade, self.data)

    def apply(self, prepared=None):
        with u.lock(self.runner):
            return u.apply(self.broker, self.runner, self.upgrade, self.manifest, prepared or self.prepared())


class UpdateTests(unittest.TestCase):
    def test_python36_syntax_and_versioned_payload_pins(self):
        ast.parse((REPO / 'deploy/native/update-ops-nss-proof.py').read_text(),
                  **({'feature_version': (3, 6)} if sys.version_info >= (3, 8) else {}))
        old = (REPO / 'deploy/native/ops-broker.py').read_bytes()
        new = old.replace(('RUNNER_SHA = ' + repr(u.OLD_RUNNER)).encode(), ('RUNNER_SHA = ' + repr(u.NEW_RUNNER)).encode(), 1)
        self.assertEqual(u.sha(old), u.OLD_BROKER); self.assertEqual(u.sha(new), u.NEW_BROKER)
        self.assertEqual(u.sha((REPO / 'deploy/native/collect-only-runner.py').read_bytes()), u.OLD_RUNNER)
        self.assertEqual(u.sha((REPO / 'deploy/native/updates/nss-proof-v1/collect-only-runner.py').read_bytes()), u.NEW_RUNNER)

    def test_manifest_exact_four_files_pins_and_duplicates(self):
        with Fixture() as f:
            self.assertEqual(u.source_inputs(f.source, f.pin), (f.manifest, f.data))
            with self.assertRaises(u.Refused): u.source_inputs(f.source, '0' * 64)
            f.f.put(f.source / 'unexpected.py', b'bad')
            with self.assertRaisesRegex(u.Refused, 'exact_update_inputs'): u.source_inputs(f.source, f.pin)
            (f.source / 'unexpected.py').unlink()
            duplicate = b'{"schema":1,"schema":1}'
            f.f.put(f.source / 'update-manifest.json', duplicate)
            with self.assertRaisesRegex(u.Refused, 'duplicate_manifest_key'): u.source_inputs(f.source, u.sha(duplicate))

    def test_unknown_helper_policy_mode_symlink_or_broker_logic_rejected(self):
        for kind in ('helper', 'policy', 'mode', 'symlink', 'broker_logic'):
            with Fixture() as f:
                if kind == 'helper': f.f.put(u.TARGETS['runner'], b'unknown', 0o755)
                if kind == 'policy': f.f.put(u.TARGETS['policy'], u.TARGETS['policy'].read_bytes() + b' ')
                if kind == 'mode': u.TARGETS['broker'].chmod(0o775)
                if kind == 'symlink':
                    u.TARGETS['broker'].unlink(); u.TARGETS['broker'].symlink_to(u.TARGETS['runner'])
                if kind == 'broker_logic': f.data['broker'] += b'# extra broker change\n'
                with self.assertRaises((u.Refused, ValueError, OSError)): f.prepared()
                self.assertFalse(u.UPDATE.exists())

    def test_canonical_lock_contention_preserves_inode_and_contents(self):
        with Fixture() as f:
            path = u.ROOT / 'state/release.lock'; before = path.read_bytes(); inode = path.stat().st_ino
            with u.lock(f.runner):
                with self.assertRaises(BlockingIOError):
                    with u.lock(f.runner): pass
            self.assertEqual(path.read_bytes(), before); self.assertEqual(path.stat().st_ino, inode)

    def test_units_must_remain_byte_identical(self):
        with Fixture() as f:
            f.new_runner.unit_text = lambda mode: 'changed unit'
            with self.assertRaisesRegex(u.Refused, 'unit_templates'): f.prepared()

    def test_read_only_preparation_creates_no_update_directory_or_stages(self):
        with Fixture() as f:
            before = {str(p): p.read_bytes() for p in f.f.root.rglob('*') if p.is_file()}
            with u.lock(f.runner): f.prepared()
            self.assertEqual({str(p): p.read_bytes() for p in f.f.root.rglob('*') if p.is_file()}, before)
            self.assertFalse(u.UPDATE.exists())
            for path in u.TARGETS.values(): self.assertFalse(path.with_name('.' + path.name + '.nss-v1.next').exists())

    def test_success_changes_only_four_targets_and_publishes_gate_last(self):
        with Fixture() as f:
            source = {p.name: p.read_bytes() for p in f.source.iterdir()}
            original = u.os.replace; seen = []
            def replace(stage, target):
                key = next(key for key, path in u.TARGETS.items() if path == Path(target))
                if key != 'complete': self.assertFalse(u.TARGETS['complete'].exists())
                else:
                    for other in ('policy', 'runner', 'broker'): self.assertEqual(u.TARGETS[other].read_bytes(), f.new[other])
                for name in u.TARGETS: self.assertEqual((u.UPDATE / (name + '.before')).read_bytes(), f.old[name])
                seen.append(key); original(stage, target)
            with patch.object(u.os, 'replace', side_effect=replace): result = f.apply()
            self.assertTrue(result['ok']); self.assertEqual(seen, ['policy', 'runner', 'broker', 'complete'])
            self.assertEqual(result['completion_gate'], 'new_verified')
            self.assertEqual(f.controllers.call_count, 2)
            plan = json.loads((u.UPDATE / 'plan.json').read_text())
            self.assertEqual(set(plan['files']), set(u.TARGETS))
            for key, entry in plan['files'].items():
                self.assertEqual(entry['old_sha256'], u.sha(f.old[key])); self.assertEqual(entry['new_sha256'], u.sha(f.new[key]))
                self.assertEqual(entry['mode'], u.MODES[key]); self.assertEqual(len(entry['old_identity']), 2)
                self.assertEqual(len(entry['staged_identity']), 2); self.assertEqual(entry['security_attributes'], {})
            self.assertNotIn('DATABASE_URL', json.dumps(plan))
            self.assertEqual(u.HISTORY.read_bytes(), f.history)
            self.assertEqual((u.OPS / 'event-prior.json').read_bytes(), b'{"private_original_event":true}\n')
            self.assertEqual({p.name: p.read_bytes() for p in f.source.iterdir()}, source)
            for key in u.TARGETS: self.assertEqual(u.TARGETS[key].read_bytes(), f.new[key])

    def test_each_partial_switch_rolls_back_entire_known_old_set(self):
        for fail_key in ('policy', 'runner', 'broker', 'complete'):
            with Fixture() as f:
                original = u.os.replace; failed = [False]
                def replace(stage, target):
                    original(stage, target)
                    if not failed[0] and Path(target) == u.TARGETS[fail_key]:
                        failed[0] = True; raise OSError('private fixture failure')
                with patch.object(u.os, 'replace', side_effect=replace): result = f.apply()
                self.assertFalse(result['ok']); self.assertEqual(result['rollback'], 'old_set_verified')
                self.assertEqual(result['completion_gate'], 'original_verified')
                for key in u.TARGETS: self.assertEqual(u.TARGETS[key].read_bytes(), f.old[key])
                self.assertEqual(u.HISTORY.read_bytes(), f.history)
                self.assertNotIn('private', json.dumps(result))

    def test_unknown_concurrent_bytes_or_inode_are_never_overwritten(self):
        for identical in (False, True):
            with Fixture() as f:
                original = u.os.replace; injected = [False]
                def replace(stage, target):
                    original(stage, target)
                    if not injected[0] and Path(target) == u.TARGETS['policy']:
                        injected[0] = True
                        replacement = u.BIN / '.unknown-concurrent'
                        replacement.write_bytes(f.old['broker'] if identical else b'unknown concurrent broker')
                        replacement.chmod(0o755); original(str(replacement), str(u.TARGETS['broker']))
                with patch.object(u.os, 'replace', side_effect=replace): result = f.apply()
                self.assertFalse(result['ok']); self.assertEqual(result['rollback'], 'rollback_refused_unknown_change')
                self.assertEqual(result['completion_gate'], 'withheld'); self.assertFalse(u.TARGETS['complete'].exists())
                self.assertEqual(u.TARGETS['broker'].read_bytes(), f.old['broker'] if identical else b'unknown concurrent broker')

    def test_inflight_before_switch_or_before_completion_never_restores_gate(self):
        for fail_at in (0, 1):
            with Fixture() as f:
                count = [0]
                def scan():
                    current = count[0]; count[0] += 1
                    if current >= fail_at: raise u.Refused('root_controller_in_flight')
                f.controllers.side_effect = scan; result = f.apply()
                self.assertFalse(result['ok']); self.assertFalse(u.TARGETS['complete'].exists())
                self.assertEqual(result['rollback'], 'root_controller_in_flight')
                self.assertEqual(result['completion_gate'], 'withheld')

    def test_staged_write_failure_preserves_original_set_and_partial_evidence(self):
        with Fixture() as f:
            original = u.write_new
            def write(path, data, mode=0o600, attributes=None):
                if path.name == '.ops-broker.py.nss-v1.next':
                    original(path, b'partial', mode, attributes); raise OSError('fixture interruption')
                return original(path, data, mode, attributes)
            with patch.object(u, 'write_new', side_effect=write): result = f.apply()
            self.assertFalse(result['ok']); self.assertEqual(result['rollback'], 'not_needed')
            self.assertTrue(u.UPDATE.exists())
            for key in u.TARGETS: self.assertEqual(u.TARGETS[key].read_bytes(), f.old[key])

    def test_gate_removed_by_someone_else_during_staging_is_never_reopened(self):
        with Fixture() as f:
            original = u.write_new
            def write(path, data, mode=0o600, attributes=None):
                value = original(path, data, mode, attributes)
                if path == u.UPDATE / 'plan.json': u.TARGETS['complete'].unlink()
                return value
            with patch.object(u, 'write_new', side_effect=write): result = f.apply()
            self.assertFalse(result['ok']); self.assertEqual(result['reason'], 'files_changed_before_gate_withdrawal')
            self.assertEqual(result['rollback'], 'not_needed'); self.assertEqual(result['completion_gate'], 'unverified')
            self.assertFalse(u.TARGETS['complete'].exists()); f.controllers.assert_not_called()
            for key in ('runner', 'broker', 'policy'): self.assertEqual(u.TARGETS[key].read_bytes(), f.old[key])

    def test_missing_gate_before_rename_has_no_republish_authority(self):
        with Fixture() as f:
            original = u.withdraw_known
            def withdraw(change, staged, name, required=False):
                if required: u.TARGETS['complete'].unlink()
                return original(change, staged, name, required)
            with patch.object(u, 'withdraw_known', side_effect=withdraw): result = f.apply()
            self.assertFalse(result['ok']); self.assertFalse(u.TARGETS['complete'].exists())
            self.assertEqual(result['reason'], 'completion_gate_missing_before_withdrawal')
            self.assertEqual(result['rollback'], 'not_needed'); self.assertEqual(result['completion_gate'], 'unverified')

    def test_exact_private_withheld_inode_proves_ownership_after_fsync_failure(self):
        with Fixture() as f:
            original = u.sync; failed = [False]
            def sync(path):
                if not failed[0] and path == u.OPS and (u.UPDATE / 'complete.withheld').exists():
                    failed[0] = True; raise OSError('fixture fsync failure after rename')
                return original(path)
            with patch.object(u, 'sync', side_effect=sync): result = f.apply()
            self.assertFalse(result['ok']); self.assertEqual(result['rollback'], 'old_set_verified')
            self.assertEqual(result['completion_gate'], 'original_verified')
            for key in u.TARGETS: self.assertEqual(u.TARGETS[key].read_bytes(), f.old[key])

    def test_unknown_gate_moved_during_first_rename_never_grants_rollback_authority(self):
        for same_bytes in (False, True):
            with Fixture() as f:
                original = u.os.rename
                def rename(source, destination):
                    if Path(source) == u.TARGETS['complete'] and Path(destination) == u.UPDATE / 'complete.withheld':
                        replacement = u.OPS / '.concurrent-gate'
                        f.f.put(replacement, f.old['complete'] if same_bytes else b'private_unknown_gate')
                        os.replace(str(replacement), str(u.TARGETS['complete']))
                    original(source, destination)
                with patch.object(u.os, 'rename', side_effect=rename): result = f.apply()
                self.assertFalse(result['ok']); self.assertEqual(result['reason'], 'original_gate_withdrawal_unverified')
                self.assertFalse(u.TARGETS['complete'].exists()); self.assertEqual(result['rollback'], 'not_needed')
                self.assertEqual(result['completion_gate'], 'unverified'); f.controllers.assert_not_called()
                self.assertNotIn('private_unknown', json.dumps(result))

    def test_unknown_completion_file_is_not_overwritten_or_reported_closed(self):
        with Fixture() as f:
            original = u.os.replace; injected = [False]
            def replace(stage, target):
                original(stage, target)
                if not injected[0] and Path(target) == u.TARGETS['policy']:
                    injected[0] = True; f.f.put(u.TARGETS['complete'], b'unknown completion')
            with patch.object(u.os, 'replace', side_effect=replace): result = f.apply()
            self.assertFalse(result['ok']); self.assertEqual(result['completion_gate'], 'unknown')
            self.assertEqual(u.TARGETS['complete'].read_bytes(), b'unknown completion')

    def test_new_gate_withdrawn_even_when_unrelated_target_metadata_becomes_unsafe(self):
        with Fixture() as f:
            original = u.write_new
            def fail(path, data, mode=0o600, attributes=None):
                if path == u.UPDATE / 'complete.json':
                    u.TARGETS['runner'].chmod(0o775)
                    raise OSError('fixture evidence write failed')
                return original(path, data, mode, attributes)
            with patch.object(u, 'write_new', side_effect=fail): result = f.apply()
            self.assertFalse(result['ok']); self.assertEqual(result['completion_gate'], 'withheld')
            self.assertFalse(u.TARGETS['complete'].exists())
            self.assertEqual(result['rollback'], 'rollback_refused_unknown_change')
            self.assertEqual(u.TARGETS['runner'].stat().st_mode & 0o777, 0o775)

    def test_restored_gate_withdrawn_if_rollback_completion_verification_fails(self):
        with Fixture() as f:
            change = f.prepared(); original = u.os.replace; failed = [False]
            def replace(stage, target):
                original(stage, target)
                if not failed[0] and Path(target) == u.TARGETS['policy']:
                    failed[0] = True; raise OSError('fixture switch failure')
            f.broker.installation_complete = Mock(side_effect=ValueError('fixture completion verification failure'))
            with patch.object(u.os, 'replace', side_effect=replace): result = f.apply(change)
            self.assertFalse(result['ok']); self.assertEqual(result['completion_gate'], 'withheld')
            self.assertFalse(u.TARGETS['complete'].exists())
            self.assertNotEqual(result['rollback'], 'old_set_verified')
            for key in ('policy', 'runner', 'broker'): self.assertEqual(u.TARGETS[key].read_bytes(), f.old[key])

    def test_known_old_runner_is_not_accepted_as_coherent_new_set(self):
        with Fixture() as f:
            original = u.os.replace; saved = u.BIN / '.held-old-runner'; held = [False]; scans = [0]
            def replace(stage, target):
                if not held[0] and Path(target) == u.TARGETS['runner']:
                    original(str(target), str(saved)); held[0] = True
                original(stage, target)
            def controllers():
                scans[0] += 1
                if scans[0] == 2: original(str(saved), str(u.TARGETS['runner']))
            f.controllers.side_effect = controllers
            with patch.object(u.os, 'replace', side_effect=replace): result = f.apply()
            self.assertFalse(result['ok']); self.assertEqual(result['reason'], 'new_set_not_coherent')
            self.assertEqual(result['rollback'], 'old_set_verified')
            for key in u.TARGETS: self.assertEqual(u.TARGETS[key].read_bytes(), f.old[key])

    def test_original_attempt_database_and_idle_gates_are_read_only(self):
        with Fixture() as f:
            user = SimpleNamespace(pw_uid=990, pw_gid=990)
            database = legacy.m.CONFIG / 'database.env'; original_info = database.stat()
            attempt = (u.COLLECT / 'seed-attempt.json').read_bytes()
            baseline = {'attempt_sha256': u.sha(attempt), 'attempt_started': 42, 'check_start_monotonic': '10',
                        'check_exit_monotonic': '20', 'db_device': original_info.st_dev,
                        'db_inode': original_info.st_ino, 'collector_gid': 990}
            states = {'check': {'ActiveState': 'failed', 'Result': 'signal', 'ExecMainCode': '2', 'ExecMainStatus': '15',
                       'ExecMainStartTimestampMonotonic': '10', 'ExecMainExitTimestampMonotonic': '20'},
                      'seed': {'ExecMainStartTimestampMonotonic': '0'}, 'run': {'ExecMainStartTimestampMonotonic': '0'}}
            def environment(disabled):
                self.assertTrue(disabled)
                fd = os.open(str(database), os.O_RDONLY | os.O_NOFOLLOW)
                return fd, os.fstat(fd)
            worker = SimpleNamespace(base=Mock(return_value=user), idle=Mock(), no_timer=Mock(), db_only_network=Mock(),
                probe_receipt=Mock(), recovery_baseline=Mock(return_value=baseline), journal_metadata=Mock(return_value=[]),
                environment_fd=Mock(side_effect=environment))
            f.broker.Broker = Mock(return_value=worker); f.broker.unit_states = Mock(return_value=states)
            REAL_PRECONDITIONS(f.broker, f.runner, f.upgrade)
            worker.idle.assert_called_once_with(user, states); worker.no_timer.assert_called_once_with(states)
            worker.db_only_network.assert_called_once_with(user); self.assertEqual(database.stat().st_mode & 0o777, 0o400)
            baseline['attempt_sha256'] = '0' * 64
            with self.assertRaisesRegex(u.Refused, 'original_attempt'): REAL_PRECONDITIONS(f.broker, f.runner, f.upgrade)
            baseline['attempt_sha256'] = u.sha(attempt); baseline['db_inode'] += 1
            with self.assertRaisesRegex(u.Refused, 'original_database'): REAL_PRECONDITIONS(f.broker, f.runner, f.upgrade)
            baseline['db_inode'] -= 1; states['seed']['ExecMainStartTimestampMonotonic'] = '1'
            with self.assertRaisesRegex(u.Refused, 'collection_start'): REAL_PRECONDITIONS(f.broker, f.runner, f.upgrade)
            self.assertEqual((u.COLLECT / 'seed-attempt.json').read_bytes(), attempt)

    def test_real_broker_state_gates_reject_busy_timer_credentials_and_recovery_history(self):
        for problem in ('positive', 'busy', 'timer', 'db_mode', 'db_group', 'db_inode', 'recovery', 'timestamp'):
            with Fixture() as f:
                b = load('real_broker_preconditions_' + problem, REPO / 'deploy/native/ops-broker.py')
                for key, path in [('OPS', u.OPS), ('COLLECT', u.COLLECT), ('CONFIG', legacy.m.CONFIG),
                                  ('SYSTEM', legacy.m.SYSTEM), ('INSTALL_EVIDENCE', u.HISTORY)]:
                    f.stack.enter_context(patch.object(b, key, path))
                user = f.runner.account(); database = legacy.m.CONFIG / 'database.env'; info = database.stat()
                attempt = (u.COLLECT / 'seed-attempt.json').read_bytes()
                baseline = {'attempt_sha256': u.sha(attempt), 'attempt_started': 42, 'check_start_monotonic': '10',
                            'check_exit_monotonic': '20', 'db_device': info.st_dev, 'db_inode': info.st_ino, 'collector_gid': user.pw_gid}
                f.f.put(u.HISTORY, u.encoded({'recovery_baseline': baseline}))
                states = {name: {'ActiveState': 'inactive', 'MainPID': '0', 'ControlPID': '0', 'LoadState': 'not-found',
                                 'ExecMainStartTimestampMonotonic': '0'} for name in ('probe', 'check', 'seed', 'run', 'hourly', 'timer')}
                states['check'].update(ActiveState='failed', Result='signal', ExecMainCode='2', ExecMainStatus='15',
                                       ExecMainStartTimestampMonotonic='10', ExecMainExitTimestampMonotonic='20')
                worker = object.__new__(b.Broker); worker.r = f.runner; worker.u = f.upgrade; worker.stage = 'entry'
                worker.base = Mock(return_value=user); worker.journal_metadata = Mock(return_value=[])
                f.stack.enter_context(patch.object(b, 'Broker', return_value=worker))
                f.stack.enter_context(patch.object(b, 'unit_states', return_value=states))
                real_stat = b.Path.stat
                f.stack.enter_context(patch.object(b.Path, 'stat', lambda path, *args, **kwargs:
                    f.f.info(real_stat(path, *args, **kwargs), path) if path == b.CONFIG else real_stat(path, *args, **kwargs)))
                if problem == 'busy': states['run']['ActiveState'] = 'active'
                if problem == 'timer': states['timer']['LoadState'] = 'loaded'
                if problem == 'db_mode': database.chmod(0o440)
                if problem == 'db_group': f.f.metadata(database, st_gid=user.pw_gid)
                if problem == 'db_inode':
                    replacement = database.with_name('.replacement'); f.f.put(replacement, database.read_bytes(), 0o400)
                    os.replace(str(replacement), str(database))
                if problem == 'recovery': f.f.put(u.OPS / 'recovery.json', b'{}')
                if problem == 'timestamp': states['check']['ExecMainStartTimestampMonotonic'] = '11'
                if problem == 'positive': REAL_PRECONDITIONS(b, f.runner, f.upgrade)
                else:
                    with self.assertRaises((u.Refused, b.Refused)): REAL_PRECONDITIONS(b, f.runner, f.upgrade)
                self.assertFalse(u.UPDATE.exists()); self.assertEqual((u.COLLECT / 'seed-attempt.json').read_bytes(), attempt)

    def test_root_controller_scan_uses_fixed_scripts_and_rejects_unreadable_identity(self):
        with Fixture() as f:
            proc = u.PROC / '123456'; proc.mkdir()
            f.f.put(proc / 'status', b'Name: python3\nUid:\t0\t0\t0\t0\n')
            f.f.put(proc / 'cmdline', b'/usr/bin/python3\0-I\0-B\0' + str(u.TARGETS['broker']).encode() + b'\0diagnose\0')
            with self.assertRaisesRegex(u.Refused, 'root_controller'): REAL_CONTROLLERS()
            f.f.put(proc / 'cmdline', b'/usr/sbin/sshd\0-D\0'); REAL_CONTROLLERS()
            f.f.put(proc / 'status', b'Uid:\t0\t0\n')
            with self.assertRaisesRegex(u.Refused, 'process_identity'): REAL_CONTROLLERS()

    def test_process_disappearance_is_ignored_but_permission_failure_is_not(self):
        with Fixture() as f:
            proc = u.PROC / '123456'; proc.mkdir()
            with patch.object(u.Path, 'open', side_effect=ProcessLookupError()): REAL_CONTROLLERS()
            with patch.object(u.Path, 'open', side_effect=PermissionError()):
                with self.assertRaises(PermissionError): REAL_CONTROLLERS()


v3 = load('collector_v3_update', REPO / 'deploy/native/updates/collector-boot-v3/update-ops-nss-proof.py')


class WithheldFixture(Fixture):
    def __enter__(self):
        self.modules = ExitStack(); self.modules.enter_context(patch.dict(globals(), u=v3))
        try:
            super().__enter__()
            self.change = super().prepared()
            self.stack.enter_context(patch.object(v3, 'PRIOR', v3.OPS / 'collector-boot-v2'))
            v3.PRIOR.mkdir(mode=0o700); archive = v3.PRIOR / 'helper-update'; archive.mkdir(mode=0o700)
            continuation = v3.OPS / 'collector-boot-v3'; continuation.mkdir(mode=0o700)
            self.stack.enter_context(patch.object(v3, 'UPDATE', continuation / 'helper-update'))
            self.withheld = archive / 'complete.withheld'; self.plan_path = archive / 'plan.json'
            os.rename(str(v3.TARGETS['complete']), str(self.withheld))
            self.v2_stage = v3.TARGETS['complete'].with_name('.complete.json.nss-v1.next')
            self.f.put(self.v2_stage, self.new['complete'])
            plan = {'schema': 1, 'files': {key: {'old_sha256': v3.sha(self.old[key]),
                'new_sha256': v3.sha(self.new[key]), 'mode': v3.MODES[key],
                'old_identity': list(self.change['identities'][key]), 'staged_identity': [1, 2],
                'security_attributes': {}} for key in v3.TARGETS},
                'history_sha256': v3.sha(self.history), 'history_identity': list(self.change['history'][1])}
            self.f.put(self.plan_path, v3.encoded(plan))
            self.change['withheld'] = {'path': self.withheld, 'plan_path': self.plan_path,
                'plan_raw': self.plan_path.read_bytes(), 'plan_identity': v3.read(self.plan_path, 0o600)[1],
                'raw': self.change['old']['complete'], 'identity': self.change['identities']['complete'],
                'labels': self.change['labels']['complete']}
            for field in ('old', 'identities', 'labels'): self.change[field].pop('complete')
            self.precondition.reset_mock()
            self.preserved = {path: (v3.read(path, 0o600), v3.attrs(path))
                              for path in (self.withheld, self.plan_path, self.v2_stage)}
            return self
        except BaseException:
            self.__exit__(*sys.exc_info()); raise

    def __exit__(self, *args):
        super().__exit__(*args); self.modules.close()

    def apply(self, prepared=None):
        with v3.lock(self.runner):
            return v3.apply_withheld(self.broker, self.runner, self.upgrade, self.manifest,
                                     self.change if prepared is None else prepared)


class WithheldUpdateTests(unittest.TestCase):
    def preserved(self, fixture):
        for path, value in fixture.preserved.items():
            self.assertEqual((v3.read(path, 0o600), v3.attrs(path)), value)
        self.assertFalse((v3.UPDATE / 'complete.before').exists())
        self.assertFalse((v3.UPDATE / 'complete.withheld').exists())
        self.assertFalse(v3.TARGETS['complete'].with_name('.complete.json.collector-v3.restore').exists())

    def test_versioned_legacy_apply_is_unchanged_and_python36_compatible(self):
        original = ast.parse((REPO / 'deploy/native/update-ops-nss-proof.py').read_text())
        updated = ast.parse((REPO / 'deploy/native/updates/collector-boot-v3/update-ops-nss-proof.py').read_text(),
                            **({'feature_version': (3, 6)} if sys.version_info >= (3, 8) else {}))
        for node in original.body:
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                replacement = next(value for value in updated.body if getattr(value, 'name', None) == node.name)
                self.assertEqual(ast.dump(node), ast.dump(replacement), node.name)

    def test_absent_gate_success_keeps_real_v2_evidence_and_publishes_last(self):
        with WithheldFixture() as f:
            original = v3.os.replace; seen = []
            def replace(stage, target):
                key = next(key for key, path in v3.TARGETS.items() if path == Path(target))
                self.assertFalse(v3.TARGETS['complete'].exists())
                if key == 'complete':
                    for helper in ('policy', 'runner', 'broker'):
                        self.assertEqual(v3.TARGETS[helper].read_bytes(), f.new[helper])
                seen.append(key); original(stage, target)
            with patch.object(v3.os, 'replace', side_effect=replace): result = f.apply()
            self.assertTrue(result['ok'], result); self.assertEqual(seen, ['policy', 'runner', 'broker', 'complete'])
            self.assertEqual(result['completion_gate'], 'new_verified'); self.preserved(f)
            complete = json.loads((v3.UPDATE / 'plan.json').read_text())['files']['complete']
            self.assertEqual(complete['initial_state'], 'absent')
            self.assertNotIn('old_sha256', complete); self.assertNotIn('old_identity', complete)
            self.assertNotIn('complete', f.change['old']); self.assertNotIn('complete', f.change['identities'])
            for key in v3.TARGETS: self.assertEqual(v3.TARGETS[key].read_bytes(), f.new[key])

    def test_staging_failure_before_callback_never_creates_or_restores_gate(self):
        with WithheldFixture() as f:
            original = v3.write_new
            def write(path, data, mode=0o600, attributes=None):
                if path.name == '.ops-broker.py.collector-v3.next':
                    original(path, b'partial', mode, attributes); raise OSError('fixture staging failure')
                return original(path, data, mode, attributes)
            with patch.object(v3, 'write_new', side_effect=write): result = f.apply()
            self.assertFalse(result['ok']); self.assertEqual(result['completion_gate'], 'withheld')
            self.assertEqual(result['rollback'], 'old_set_verified'); self.assertFalse(v3.TARGETS['complete'].exists())
            self.assertTrue(all(call.args[0] is f.broker for call in f.precondition.call_args_list))
            for key in ('runner', 'broker', 'policy'): self.assertEqual(v3.TARGETS[key].read_bytes(), f.old[key])
            self.preserved(f)

    def test_failures_at_each_switch_callback_and_after_publication_keep_gate_closed(self):
        for fail_at in ('policy', 'runner', 'broker', 'callback', 'complete', 'receipt'):
            with WithheldFixture() as f:
                original = v3.os.replace; write_new = v3.write_new; failed = [False]
                f.broker.installation_complete = Mock(side_effect=AssertionError('old gate must never be verified'))
                def replace(stage, target):
                    original(stage, target)
                    if not failed[0] and fail_at in v3.TARGETS and Path(target) == v3.TARGETS[fail_at]:
                        failed[0] = True; raise OSError('fixture partial switch')
                def preconditions(broker, runner, upgrade):
                    if fail_at == 'callback' and broker is f.new_broker: raise ValueError('fixture callback failure')
                def write(path, data, mode=0o600, attributes=None):
                    if fail_at == 'receipt' and path == v3.UPDATE / 'complete.json': raise OSError('fixture receipt failure')
                    return write_new(path, data, mode, attributes)
                f.precondition.side_effect = preconditions
                with patch.object(v3.os, 'replace', side_effect=replace), patch.object(v3, 'write_new', side_effect=write):
                    result = f.apply()
                self.assertFalse(result['ok'], fail_at); self.assertEqual(result['rollback'], 'old_set_verified', result)
                self.assertEqual(result['completion_gate'], 'withheld'); self.assertFalse(v3.TARGETS['complete'].exists())
                f.broker.installation_complete.assert_not_called()
                for key in ('runner', 'broker', 'policy'): self.assertEqual(v3.TARGETS[key].read_bytes(), f.old[key])
                self.preserved(f)

    def test_unknown_concurrent_helper_bytes_or_inode_are_not_overwritten(self):
        for identical in (False, True):
            with WithheldFixture() as f:
                original = v3.os.replace; injected = [False]
                def replace(stage, target):
                    original(stage, target)
                    if not injected[0] and Path(target) == v3.TARGETS['policy']:
                        injected[0] = True; other = v3.BIN / '.unknown-broker'
                        f.f.put(other, f.old['broker'] if identical else b'unknown broker', 0o755)
                        original(str(other), str(v3.TARGETS['broker']))
                with patch.object(v3.os, 'replace', side_effect=replace): result = f.apply()
                self.assertFalse(result['ok']); self.assertEqual(result['rollback'], 'rollback_refused_unknown_change')
                self.assertEqual(v3.TARGETS['broker'].read_bytes(), f.old['broker'] if identical else b'unknown broker')
                self.assertFalse(v3.TARGETS['complete'].exists()); self.preserved(f)

    def test_changed_withheld_plan_or_reintroduced_gate_refused_before_mutation(self):
        for kind in ('withheld_inode', 'withheld_bytes', 'withheld_mode', 'plan_inode', 'plan_bytes', 'plan_mode',
                     'live_gate', 'extra_field', 'missing_field', 'bad_identity_type', 'wrong_path', 'fake_old_complete'):
            with WithheldFixture() as f:
                if kind in ('withheld_inode', 'plan_inode'):
                    path = f.withheld if kind == 'withheld_inode' else f.plan_path
                    other = path.with_name(path.name + '.replacement'); f.f.put(other, path.read_bytes())
                    os.replace(str(other), str(path))
                if kind == 'withheld_bytes': f.withheld.write_bytes(b'changed')
                if kind == 'withheld_mode': f.withheld.chmod(0o644)
                if kind == 'plan_bytes': f.plan_path.write_bytes(f.plan_path.read_bytes() + b' ')
                if kind == 'plan_mode': f.plan_path.chmod(0o644)
                if kind == 'live_gate': f.f.put(v3.TARGETS['complete'], f.old['complete'])
                if kind == 'extra_field': f.change['withheld']['extra'] = True
                if kind == 'missing_field': f.change['withheld'].pop('raw')
                if kind == 'bad_identity_type': f.change['withheld']['identity'] = list(f.change['withheld']['identity'])
                if kind == 'wrong_path': f.change['withheld']['path'] = v3.TARGETS['complete']
                if kind == 'fake_old_complete': f.change['old']['complete'] = f.old['complete']
                before = {path: path.read_bytes() for path in f.f.root.rglob('*') if path.is_file()}
                result = f.apply()
                self.assertFalse(result['ok'], kind); self.assertFalse(v3.UPDATE.exists(), kind)
                self.assertEqual({path: path.read_bytes() for path in f.f.root.rglob('*') if path.is_file()}, before, kind)
                f.precondition.assert_not_called(); f.controllers.assert_not_called()

    def test_pinned_plan_must_match_archived_completion_hash_inode_and_attributes(self):
        for field, value in [('old_sha256', '0' * 64), ('old_identity', [1, 2]), ('mode', 0o644),
                             ('security_attributes', {'security.selinux': 'Y2hhbmdlZA=='})]:
            with WithheldFixture() as f:
                plan = json.loads(f.plan_path.read_text()); plan['files']['complete'][field] = value
                f.plan_path.write_bytes(v3.encoded(plan)); f.change['withheld']['plan_raw'] = f.plan_path.read_bytes()
                result = f.apply()
                self.assertFalse(result['ok']); self.assertEqual(result['reason'], 'withheld_plan_mismatch')
                self.assertFalse(v3.UPDATE.exists()); self.assertFalse(v3.TARGETS['complete'].exists())

    def test_gate_reintroduced_during_staging_switch_or_callback_is_never_overwritten(self):
        for when in ('staging', 'switch', 'callback'):
            with WithheldFixture() as f:
                write_new = v3.write_new; replace_file = v3.os.replace
                def insert(): f.f.put(v3.TARGETS['complete'], b'unknown gate')
                def write(path, data, mode=0o600, attributes=None):
                    value = write_new(path, data, mode, attributes)
                    if when == 'staging' and path == v3.UPDATE / 'plan.json': insert()
                    return value
                def replace(stage, target):
                    replace_file(stage, target)
                    if when == 'switch' and Path(target) == v3.TARGETS['policy']: insert()
                def preconditions(broker, runner, upgrade):
                    if when == 'callback' and broker is f.new_broker: insert()
                f.precondition.side_effect = preconditions
                with patch.object(v3, 'write_new', side_effect=write), patch.object(v3.os, 'replace', side_effect=replace):
                    result = f.apply()
                self.assertFalse(result['ok']); self.assertEqual(result['completion_gate'], 'unknown')
                self.assertEqual(v3.TARGETS['complete'].read_bytes(), b'unknown gate'); self.preserved(f)

    def test_published_gate_withdrawn_even_if_helper_metadata_changes(self):
        with WithheldFixture() as f:
            original = v3.write_new
            def write(path, data, mode=0o600, attributes=None):
                if path == v3.UPDATE / 'complete.json':
                    v3.TARGETS['runner'].chmod(0o775); raise OSError('fixture receipt failure')
                return original(path, data, mode, attributes)
            with patch.object(v3, 'write_new', side_effect=write): result = f.apply()
            self.assertFalse(result['ok']); self.assertEqual(result['rollback'], 'rollback_refused_unknown_change')
            self.assertFalse(v3.TARGETS['complete'].exists()); self.assertEqual(result['completion_gate'], 'withheld')
            self.assertEqual(v3.TARGETS['runner'].stat().st_mode & 0o777, 0o775); self.preserved(f)

    def test_removed_or_replaced_gate_after_publication_cannot_report_success(self):
        for when in ('verification', 'receipt'):
            for replace in (False, True):
                with WithheldFixture() as f:
                    original = v3.write_new; verify = f.new_broker.installation_complete
                    def change_gate():
                        v3.TARGETS['complete'].unlink()
                        if replace: f.f.put(v3.TARGETS['complete'], b'unknown replacement gate')
                    def complete(policy):
                        verify(policy)
                        if when == 'verification': change_gate()
                    def write(path, data, mode=0o600, attributes=None):
                        value = original(path, data, mode, attributes)
                        if when == 'receipt' and path == v3.UPDATE / 'complete.json': change_gate()
                        return value
                    f.new_broker.installation_complete = complete
                    with patch.object(v3, 'write_new', side_effect=write): result = f.apply()
                    self.assertFalse(result['ok'], (when, replace, result))
                    if replace:
                        self.assertEqual(result['completion_gate'], 'unknown')
                        self.assertEqual(v3.TARGETS['complete'].read_bytes(), b'unknown replacement gate')
                    else:
                        self.assertEqual(result['completion_gate'], 'withheld')
                        self.assertFalse(v3.TARGETS['complete'].exists())
                    self.preserved(f)


if __name__ == '__main__':
    unittest.main()
