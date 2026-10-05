#!/usr/bin/python3
"""Offline boot-v2 recovery: real fixture files, no host/system/network commands."""
import ast
import copy
from contextlib import ExitStack
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


m = load('collector_boot_controller', REPO / 'deploy/native/recover-collector-after-boot.py')
m.BOOT = '12345678-1234-4123-8123-123456789abc'
t = load('collector_boot_transaction_fixture', REPO / 'scripts/tests/update-ops-nss-proof-check.py')
w = load('collector_boot_website_fixture', REPO / 'scripts/tests/recover-preview-after-boot-check.py')
USER = SimpleNamespace(pw_uid=986, pw_gid=986)
PROOF = dict(database_ok=True, role_ok=True, role_safe=True, migration_ok=True,
             other_clients=0, sources=0, articles=0, discoveries=0, fetch_runs=0)
COUNTS = dict((name, None if name == 'pgboss.job' else 0) for name in m.COUNTS)


class FlowFixture:
    def __enter__(self):
        self.stack = ExitStack(); self.f = self.stack.enter_context(t.Fixture()); self.u = t.u
        self.root = self.f.f.root
        for key, value in [('OPS', self.u.OPS), ('COLLECT', self.u.COLLECT), ('CONFIG', t.legacy.m.CONFIG),
                           ('EVIDENCE', self.u.OPS / 'collector-boot-v2-fixture'), ('WEBSITE', self.root / 'website')]:
            self.stack.enter_context(patch.object(m, key, value))
        self.stack.enter_context(patch.object(m, 'RUNNER_SHA', self.u.NEW_RUNNER))
        self.stack.enter_context(patch.object(m, 'BROKER_SHA', self.u.NEW_BROKER))
        self.stack.enter_context(patch.object(self.u, 'preconditions'))
        self.r = Mock(); self.worker = Mock(); self.b = Mock(); self.b.Broker.return_value = self.worker
        self.r.unit_name.side_effect = lambda mode: 'aifinance-collect-' + mode + '.service'
        self.r.CTL = '/usr/bin/systemctl'; self.r.NFT = '/usr/sbin/nft'
        self.r.pwd.getpwnam.return_value = SimpleNamespace(pw_uid=989)
        self.r.database_url.side_effect = lambda raw: raw.split('=', 1)[1].strip()
        self.website = Mock(); self.website.CTL = '/usr/bin/systemctl'
        self.website.API = 'aifinance-preview-api.service'; self.website.WEB = 'aifinance-preview-web.service'
        self.recovery = m.Recovery(self.u, self.website, self.b, self.r, Mock())
        r = self.recovery; r.user = USER; r.baseline = dict(db_device=1, db_inode=2, collector_gid=986)
        r.records = {name: (m.COLLECT / name).read_bytes() for name in ('installed.json', 'probe.json', 'seed-attempt.json', 'network.json')}
        r.records['output.json'] = b''; self.f.f.put(m.COLLECT / 'output.json', b'')
        r.web_receipt = dict(name='05-complete.json', sha256='a' * 64)
        r.fp = Mock(); r.original_state = Mock(); r.website_gate = Mock(); r.same_database = Mock()
        r.restore_website = Mock(); r.counts = Mock(return_value=dict(COUNTS))
        self.worker.sql_proof.return_value = dict(PROOF)
        self.events = []; self.fail = None
        db = m.CONFIG / 'database.env'; self.f.f.put(db, b'DATABASE_URL=fixture-value-never-print\n', 0o400)
        self.db_fd = os.open(str(db), os.O_RDONLY); self.db_info = os.fstat(self.db_fd)
        self.worker.environment_fd.return_value = (self.db_fd, self.db_info)
        self.probe = dict(mode='probe', elapsed_seconds=30, output={}, samples=[{}])
        self.check = dict(mode='check', elapsed_seconds=3, samples=[{}], output=dict(result=dict(sources=[], rawStates=[], counts=dict(COUNTS))))
        def run(mode, user):
            self.events.append('run_' + mode)
            if self.fail == mode:
                raise ValueError('fixture-interruption')
            self.assert_archive()
            self.f.f.put(m.COLLECT / 'output.json', b'new-output')
            return self.probe if mode == 'probe' else self.check
        self.r.run_unit.side_effect = run
        def replace(path, text):
            self.assert_archive(); self.f.f.put(path, text.encode()); self.events.append('replace_probe')
        self.r.replace_owned.side_effect = replace
        self.r.network_table.return_value = False
        self.r.network_rules.return_value = 'fixed-db-only-payload'
        m.EVIDENCE.mkdir(mode=0o700)
        return self

    def assert_archive(self):
        for name, raw in self.recovery.records.items():
            if (m.EVIDENCE / 'archive' / name).read_bytes() != raw:
                raise AssertionError('archive not durable before mutation')

    def __exit__(self, *args):
        if self.recovery.db_fd is not None:
            os.close(self.recovery.db_fd); self.recovery.db_fd = None
        else:
            try:
                os.close(self.db_fd)
            except OSError:
                pass
        self.stack.close()


class RecoveryChecks(unittest.TestCase):
    def test_python36_and_payload_pins(self):
        ast.parse((REPO / 'deploy/native/recover-collector-after-boot.py').read_text(),
                  **({'feature_version': (3, 6)} if sys.version_info >= (3, 8) else {}))
        for name, pin in [('update-ops-nss-proof.py', m.UPDATER_SHA), ('recover-preview-after-boot.py', m.WEBSITE_SHA),
                          ('updates/nss-proof-v1/collect-only-runner.py', m.RUNNER_SHA),
                          ('updates/collector-boot-v2/ops-broker.py', m.BROKER_SHA)]:
            self.assertEqual(m.sha((REPO / 'deploy/native' / name).read_bytes()), pin)

    def test_current_boot_exact(self):
        with tempfile.TemporaryDirectory() as temp:
            proc = Path(temp); p = proc / 'sys/kernel/random/boot_id'; p.parent.mkdir(parents=True)
            with patch.object(m, 'PROC', proc):
                p.write_text(m.BOOT + '\n'); m.boot()
                p.write_text('stale-other-boot\n')
                with self.assertRaisesRegex(m.Refused, 'reviewed_boot_changed'): m.boot()

    def test_source_manifest_exact_boot_pins_and_no_extra_files(self):
        with t.Fixture() as f:
            source = f.f.root / 'boot-source'; source.mkdir(mode=0o700)
            locations = {'recover-collector-after-boot.py': 'recover-collector-after-boot.py',
                         'update-ops-nss-proof.py': 'update-ops-nss-proof.py',
                         'recover-preview-after-boot.py': 'recover-preview-after-boot.py',
                         'collect-only-runner.py': 'updates/nss-proof-v1/collect-only-runner.py',
                         'ops-broker.py': 'updates/collector-boot-v2/ops-broker.py'}
            data = {name: (REPO / 'deploy/native' / relative).read_bytes() for name, relative in locations.items()}
            for name, raw in data.items(): f.f.put(source / name, raw)
            manifest = dict(schema=2, boot_id=m.BOOT, release=m.RELEASE, payloads={name: m.sha(raw) for name, raw in data.items()})
            raw = f.u.encoded(manifest) if hasattr(f, 'u') else t.u.encoded(manifest)
            f.f.put(source / 'manifest.json', raw)
            with patch.object(m, 'SOURCE_PATTERN', re.escape(str(source))):
                self.assertEqual(m.source_inputs(source, m.sha(raw)), (manifest, data))
                with self.assertRaisesRegex(m.Refused, 'manifest_digest_mismatch'): m.source_inputs(source, '0' * 64)
                f.f.put(source / 'extra.py', b'')
                with self.assertRaisesRegex(m.Refused, 'exact_source_payloads_required'): m.source_inputs(source, m.sha(raw))
                (source / 'extra.py').unlink()
                for change in (dict(schema=True), dict(boot_id='old'), dict(release='old')):
                    bad = t.u.encoded(dict(manifest, **change)); f.f.put(source / 'manifest.json', bad)
                    with self.assertRaises(m.Refused): m.source_inputs(source, m.sha(bad))
                duplicate = b'{"schema":2,"schema":2}'; f.f.put(source / 'manifest.json', duplicate)
                with self.assertRaisesRegex(m.Refused, 'duplicate_json_key'): m.source_inputs(source, m.sha(duplicate))
                f.f.put(source / 'manifest.json', raw); f.f.put(source / 'ops-broker.py', data['ops-broker.py'] + b'\n')
                with self.assertRaisesRegex(m.Refused, 'source_payload_digest_mismatch'): m.source_inputs(source, m.sha(raw))

    def test_website_evidence_requires_matching_origin_and_exact_complete(self):
        with FlowFixture() as f:
            m.WEBSITE.mkdir(mode=0o700)
            before = {'fixture': {'sha256': 'b' * 64}}
            origin = dict(boot_id=m.BOOT, release=m.RELEASE, preserved_before=before)
            done = dict(website_healthy=True, collector_started=False, native_ready_written=False,
                        preserved_after=before, listeners={'8000': [], '3100': [['0100007F', '1']],
                        '3101': [['0100007F', '2']], '55432': [['0100007F', '3']]})
            put = f.f.f.put
            put(m.WEBSITE / '01-evidence_create.json', f.u.encoded(origin)); put(m.WEBSITE / '05-complete.json', f.u.encoded(done))
            self.assertEqual(f.recovery.website_evidence()[1], done)
            for change in (dict(boot_id='old'), dict(release='old'), dict(preserved_before={})):
                put(m.WEBSITE / '01-evidence_create.json', f.u.encoded(dict(origin, **change)))
                with self.assertRaises(m.Refused): f.recovery.website_evidence()
            put(m.WEBSITE / '01-evidence_create.json', f.u.encoded(origin))
            put(m.WEBSITE / '06-failure.json', b'{}')
            with self.assertRaises(m.Refused): f.recovery.website_evidence()

    def test_recovery_archives_before_overwrite_rearm_and_only_probe_check_run(self):
        with FlowFixture() as f:
            f.recovery.recover(f.b, f.r)
            f.assert_archive()
            self.assertEqual(f.events, ['run_probe', 'replace_probe', 'run_check'])
            self.assertFalse((m.COLLECT / 'seed-attempt.json').exists())
            index = m.document(m.read(m.EVIDENCE / 'ready.json'))
            self.assertEqual(index['schema'], 2); self.assertEqual(index['boot_id'], m.BOOT)
            self.assertEqual(index['counts_before'], index['counts_after'])
            self.assertFalse((m.OPS / 'recovery.json').exists())
            self.assertFalse((m.OPS / 'pre-seed-attempt-v1.json').exists())
            self.assertEqual(f.worker.sql_proof.call_count, 2)
            f.r.configure_network.assert_not_called(); f.r.resolve_feeds.assert_not_called()
            f.r.first_operation.assert_not_called(); f.r.enable_hourly.assert_not_called()
            self.assertIsNotNone(f.recovery.db_fd, 'keep DB descriptor until updater completion')
            f.recovery.restore_website.assert_called_once()

    def test_db_only_network_does_not_replace_original_receipt_or_resolver_files(self):
        with FlowFixture() as f:
            f.recovery.worker = f.worker
            originals = {p: p.read_bytes() for p in [m.COLLECT / 'network.json', m.CONFIG / 'hosts', m.CONFIG / 'nsswitch.conf']}
            f.recovery.restore_network()
            self.assertEqual(f.r.command.call_args_list[0][0], (['/usr/sbin/nft', '--check', '--file', '-'], 'fixed-db-only-payload'))
            self.assertEqual(f.r.command.call_args_list[1][0], (['/usr/sbin/nft', '--file', '-'], 'fixed-db-only-payload'))
            self.assertEqual(originals, {p: p.read_bytes() for p in originals})
            f.r.network_table.return_value = True
            with self.assertRaisesRegex(m.Refused, 'collector_network_changed'): f.recovery.restore_network()

    def test_probe_check_and_postcheck_failures_restore_website_preserve_attempt(self):
        for stage in ('probe', 'check', 'counts', 'restore', 'rearm'):
            with self.subTest(stage=stage), FlowFixture() as f:
                f.fail = stage
                if stage == 'counts': f.recovery.counts.side_effect = [COUNTS, dict(COUNTS, articles=1)]
                if stage == 'restore': f.recovery.restore_website.side_effect = [ValueError('failed-start'), None]
                if stage == 'rearm': f.worker.no_timer.side_effect = ValueError('timer-changed')
                with self.assertRaises(Exception): f.recovery.recover(f.b, f.r)
                self.assertTrue((m.EVIDENCE / 'failure.json').exists())
                self.assertTrue((m.COLLECT / 'seed-attempt.json').exists())
                self.assertFalse((m.EVIDENCE / 'ready.json').exists())
                self.assertTrue(f.recovery.cleanup_result['website_restored'])
                self.assertTrue(f.recovery.cleanup_result['database_read_revoked'])
                self.assertTrue(f.recovery.cleanup_result['collector_https_revoked'])
                f.r.first_operation.assert_not_called()

    def test_archive_failure_leaves_website_running_and_attempt_original(self):
        with FlowFixture() as f:
            f.recovery.archive = Mock(side_effect=OSError('fixture'))
            with self.assertRaises(OSError): f.recovery.recover(f.b, f.r)
            self.assertFalse(f.recovery.app_stop_attempted)
            f.website.command.assert_not_called(); f.recovery.restore_website.assert_not_called()
            self.assertTrue((m.COLLECT / 'seed-attempt.json').exists())

    def test_database_descriptor_open_failure_preserves_website_and_never_archives_or_runs(self):
        with FlowFixture() as f:
            f.worker.environment_fd.side_effect = PermissionError('fixture-private-detail')
            f.recovery.archive = Mock()
            with self.assertRaises(PermissionError): f.recovery.recover(f.b, f.r)
            self.assertTrue(f.recovery.started); self.assertFalse(f.recovery.app_stop_attempted)
            self.assertIsNone(f.recovery.db_fd)
            self.assertFalse(f.recovery.cleanup_result['database_read_revoked'])
            self.assertTrue(f.recovery.cleanup_result['website_restored'])
            f.recovery.archive.assert_not_called(); f.r.run_unit.assert_not_called()
            f.website.command.assert_not_called(); f.recovery.restore_website.assert_not_called()
            self.assertNotIn('fixture-private-detail', (m.EVIDENCE / 'failure.json').read_text())

    def test_cleanup_revokes_exact_open_database_inode_and_refuses_replacement(self):
        for replaced in (False, True):
            with self.subTest(replaced=replaced), FlowFixture() as f:
                db = m.CONFIG / 'database.env'; db.chmod(0o440); f.f.f.metadata(db, st_gid=USER.pw_gid)
                f.recovery.worker = f.worker; f.recovery.db_fd = f.db_fd; f.recovery.db_info = f.db_info
                f.recovery.same_database = m.Recovery.same_database.__get__(f.recovery)
                f.recovery.app_stop_attempted = True
                original = db
                if replaced:
                    original = db.with_name('original-held.env'); db.rename(original)
                    f.f.f.put(db, b'unrecognized replacement', 0o440); f.f.f.metadata(db, st_gid=USER.pw_gid)
                def chown(descriptor, uid, gid):
                    self.assertEqual(descriptor, f.db_fd)
                    f.f.f.metadata(original, st_uid=uid, st_gid=gid)
                with patch.object(m.os, 'fchown', side_effect=chown) as owner:
                    result = f.recovery.cleanup()
                self.assertEqual(result['database_read_revoked'], not replaced)
                self.assertTrue(result['website_restored'])
                if replaced:
                    owner.assert_not_called(); self.assertEqual(db.read_bytes(), b'unrecognized replacement')
                    self.assertEqual(original.stat().st_mode & 0o777, 0o440)
                else:
                    owner.assert_called_once_with(f.db_fd, 0, 0)
                    self.assertEqual(db.stat().st_mode & 0o777, 0o400)
                    self.assertEqual(os.fstat(f.db_fd).st_gid, 0)

    def test_cleanup_failures_are_independent_and_never_start_collection(self):
        with FlowFixture() as f:
            f.recovery.worker = f.worker; f.recovery.db_fd = f.db_fd; f.recovery.db_info = f.db_info
            f.recovery.app_stop_attempted = True
            f.r.command.side_effect = ValueError('stop failed')
            f.worker.db_only_network.side_effect = ValueError('unknown table')
            f.recovery.restore_website.side_effect = ValueError('restore failed')
            result = f.recovery.cleanup()
            self.assertEqual(result, dict(collector_stopped=False, database_read_revoked=True,
                                         collector_https_revoked=False, website_restored=False))
            f.recovery.restore_website.assert_called_once()
            f.r.run_unit.assert_not_called(); f.r.configure_network.assert_not_called()

    def test_old_callback_cannot_reopen_gate_after_any_recovery_attempt(self):
        with FlowFixture() as f:
            f.recovery.original_state = m.Recovery.original_state.__get__(f.recovery)
            f.recovery.started = True
            with self.assertRaisesRegex(m.Refused, 'gate_stays_closed'):
                f.recovery.original_state(f.b, f.r)
            f.b.Broker.assert_not_called()

    def test_late_updater_failure_invokes_cleanup_before_closing_database_descriptor(self):
        with FlowFixture() as f:
            m.EVIDENCE.rmdir()
            f.recovery.started = True; f.recovery.db_fd = f.db_fd; f.recovery.db_info = f.db_info
            def cleanup():
                self.assertEqual(os.fstat(f.recovery.db_fd).st_ino, f.db_info.st_ino)
                f.recovery.cleanup_result.update(database_read_revoked=True, website_restored=True)
                return f.recovery.cleanup_result
            f.recovery.cleanup = Mock(side_effect=cleanup)
            with patch.object(f.u, 'apply', return_value=dict(ok=False, stage='publish_completion', completion_gate='withheld')):
                result = f.recovery.apply({}, {})
            f.recovery.cleanup.assert_called_once(); self.assertIsNone(f.recovery.db_fd)
            self.assertTrue(result['cleanup']['database_read_revoked'])
            self.assertTrue((m.EVIDENCE / 'failure.json').exists())

    def test_real_transaction_late_failures_close_gate_then_cleanup_held_database(self):
        for failing in ('after_callback', 'completion_rename', 'completion_evidence'):
            with self.subTest(failing=failing), t.Fixture() as f, ExitStack() as stack:
                evidence = t.u.OPS / 'collector-boot-v2-fixture'
                for key, value in (('EVIDENCE', evidence), ('OPS', t.u.OPS), ('RUNNER_SHA', t.u.NEW_RUNNER), ('BROKER_SHA', t.u.NEW_BROKER)):
                    stack.enter_context(patch.object(m, key, value))
                f.broker.RUNNER_SHA = t.u.OLD_RUNNER; f.new_broker.RUNNER_SHA = t.u.NEW_RUNNER
                r = m.Recovery(t.u, Mock(), f.broker, f.runner, f.upgrade)
                def original(*args): m.require(not r.started, 'recovery_attempted_gate_stays_closed')
                r.original_state = original
                opened = []; cleanup = []
                def recover(*args):
                    self.assertFalse(t.u.TARGETS['complete'].exists())
                    r.started = True; r.stage = 'ready'
                    r.db_fd = os.open(str(t.legacy.m.CONFIG / 'database.env'), os.O_RDONLY)
                    r.db_info = os.fstat(r.db_fd); opened.append(r.db_fd)
                    t.u.write_new(evidence / 'ready.json', b'{"status":"fixture-ready"}\n')
                r.recover = recover
                def revoke():
                    self.assertFalse(t.u.TARGETS['complete'].exists())
                    self.assertEqual(os.fstat(r.db_fd).st_ino, r.db_info.st_ino)
                    os.fchmod(r.db_fd, 0o400); cleanup.append(True)
                    r.cleanup_result = dict(database_read_revoked=True, website_restored=True)
                    return r.cleanup_result
                r.cleanup = revoke
                change = f.prepared(); real_write = t.u.write_new; real_replace = t.u.os.replace
                def write(path, *args, **kwargs):
                    if failing == 'completion_evidence' and path == t.u.UPDATE / 'complete.json': raise OSError('private-final-write')
                    return real_write(path, *args, **kwargs)
                def replace(source, destination):
                    real_replace(source, destination)
                    if failing == 'completion_rename' and Path(destination) == t.u.TARGETS['complete']:
                        raise OSError('private-after-gate-rename')
                def controllers():
                    if failing == 'after_callback' and r.started: raise t.u.Refused('root_controller_in_flight')
                f.controllers.side_effect = controllers
                with patch.object(t.u, 'write_new', side_effect=write), patch.object(t.u.os, 'replace', side_effect=replace), t.u.lock(f.runner):
                    result = r.apply(f.manifest, change)
                self.assertFalse(result['ok']); self.assertEqual(result['completion_gate'], 'withheld')
                self.assertFalse(t.u.TARGETS['complete'].exists()); self.assertEqual(cleanup, [True])
                self.assertTrue((evidence / 'ready.json').exists()); self.assertTrue((evidence / 'failure.json').exists())
                self.assertIsNone(r.db_fd); self.assertNotIn('private-', json.dumps(result))
                for descriptor in opened:
                    with self.assertRaises(OSError): os.fstat(descriptor)
                self.assertEqual(t.u.HISTORY.read_bytes(), f.history)

    def test_transaction_recovery_failure_restores_known_helpers_but_withholds_gate(self):
        with t.Fixture() as f, ExitStack() as stack:
            evidence = f.f.root / 'boot-v2'; stack.enter_context(patch.object(m, 'EVIDENCE', evidence))
            stack.enter_context(patch.object(m, 'OPS', f.f.root))
            stack.enter_context(patch.object(m, 'RUNNER_SHA', t.u.NEW_RUNNER))
            stack.enter_context(patch.object(m, 'BROKER_SHA', t.u.NEW_BROKER))
            f.broker.RUNNER_SHA = t.u.OLD_RUNNER; f.new_broker.RUNNER_SHA = t.u.NEW_RUNNER
            r = m.Recovery(t.u, Mock(), f.broker, f.runner, f.upgrade)
            def original(*args):
                m.require(not r.started, 'recovery_attempted_gate_stays_closed')
            r.original_state = original
            def recover(*args):
                r.started = True; r.cleanup_result = dict(database_read_revoked=True, website_restored=True)
                raise m.Refused('fresh_check_failed')
            r.recover = recover
            change = f.prepared()
            result = r.apply(f.manifest, change)
            self.assertFalse(result['ok']); self.assertEqual(result['completion_gate'], 'withheld')
            self.assertFalse(t.u.TARGETS['complete'].exists())
            for key in ('runner', 'broker', 'policy'): self.assertEqual(t.u.TARGETS[key].read_bytes(), f.old[key])
            self.assertEqual(t.u.HISTORY.read_bytes(), f.history)
            self.assertTrue((t.u.UPDATE / 'complete.withheld').exists())

    def test_website_restore_checks_graph_before_start_and_accepts_absent_8000(self):
        with FlowFixture() as f:
            f.recovery.website_evidence = Mock(return_value=(f.recovery.web_receipt, {}))
            f.recovery.restore_website = m.Recovery.restore_website.__get__(f.recovery)
            f.recovery.restore_website()
            self.assertEqual(f.recovery.website_gate.call_args_list[0][1], {'healthy': None})
            self.assertEqual(f.website.command.call_args[0][0], ['/usr/bin/systemctl', 'start', f.website.API, f.website.WEB])
            f.recovery.website_gate.side_effect = m.Refused('effective_command_changed')
            f.website.command.reset_mock()
            with self.assertRaises(m.Refused): f.recovery.restore_website()
            f.website.command.assert_not_called()

    def test_actual_website_gate_observed_v239_graph_and_mixed_restore_state(self):
        with FlowFixture() as f, ExitStack() as stack:
            r = f.recovery; r.w = w.m; r.website_gate = m.Recovery.website_gate.__get__(r)
            rows = {unit: w.unit_values(unit) for unit in w.m.UNITS}
            for unit, row in rows.items():
                row.update(ActiveState='active', SubState='exited' if unit == w.m.GUARD else 'running',
                           MainPID='0' if unit == w.m.GUARD else '123')
            ports = {'8000': [], '3100': [('0100007F', '1')], '3101': [('0100007F', '2')], '55432': [('0100007F', '3')]}
            r.fp.listeners.return_value = ports
            stack.enter_context(patch.object(m, 'boot'))
            stack.enter_context(patch.object(w.m, 'HELPER_PINS', {}))
            stack.enter_context(patch.object(w.m, 'UNIT_PINS', dict((unit, m.sha(b'fixed-unit')) for unit in w.m.UNITS)))
            stack.enter_context(patch.object(w.m, 'read', return_value=b'fixed-unit'))
            stack.enter_context(patch.object(w.m, 'properties', side_effect=lambda unit, *keys: w.root_mount_values() if unit == '-.mount' else rows[unit]))
            stack.enter_context(patch.object(w.m, 'command', return_value=''))
            stack.enter_context(patch.object(w.m, 'guard_verify'))
            r.website_gate()
            for unit, state in ((w.m.API, 'inactive'), (w.m.WEB, 'failed')):
                rows[unit].update(ActiveState=state, SubState='failed' if state == 'failed' else 'dead',
                                  Result='exit-code' if state == 'failed' else 'success', MainPID='0')
            ports['3100'] = []; ports['3101'] = []
            r.website_gate(healthy=None)
            for key, value in [('Wants', 'unreviewed.service'), ('Requires', 'sysinit.target'),
                               ('EnvironmentFiles', '/unreviewed'), ('ExecStop', w.exec_value('/usr/bin/true')),
                               ('RequiresMountsFor', '/unreviewed'), ('NeedDaemonReload', 'yes'), ('MainPID', 'secret')]:
                prior = rows[w.m.API][key]; rows[w.m.API][key] = value
                with self.subTest(property=key), self.assertRaises((m.Refused, w.m.Refused)):
                    r.website_gate(healthy=None)
                rows[w.m.API][key] = prior
            ports['8000'] = [('00000000', 'other')]
            with self.assertRaisesRegex(m.Refused, '8000'): r.website_gate(healthy=None)
            ports['8000'] = []; ports['55432'] = [('00000000', 'db')]
            with self.assertRaisesRegex(m.Refused, 'listener_boundary'): r.website_gate(healthy=None)

    def test_legacy_website_helper_modes_use_real_approved_reader_and_exact_hashes(self):
        helpers = {name: digest for name, digest in w.m.HELPER_PINS.items()
                   if name not in ('ops-broker.py', 'collect-only-runner.py')}
        self.assertEqual(len(helpers), 5)
        for mode in (0o400, 0o444, 0o600, 0o644, 0o700, 0o755):
            with self.subTest(mode=oct(mode)), FlowFixture() as f, ExitStack() as stack:
                r = f.recovery; r.w = w.m; r.website_gate = m.Recovery.website_gate.__get__(r)
                stack.enter_context(patch.object(m, 'boot'))
                stack.enter_context(patch.object(m, 'BIN', f.u.BIN))
                # All file content, access modes, opens, O_NOFOLLOW, lengths,
                # nlink and inode comparisons are real fixture filesystem work.
                # The shared nonroot fixture only supplies root UID/GID views.
                for name in helpers:
                    f.f.f.put(f.u.BIN / name, (REPO / 'deploy/native' / name).read_bytes(), mode)
                next_gate = stack.enter_context(patch.object(w.m, 'properties', side_effect=RuntimeError('reached-unit-gates')))
                with self.assertRaisesRegex(RuntimeError, 'reached-unit-gates'):
                    r.website_gate()
                next_gate.assert_called_once()
                self.assertEqual(m.CONTEXT['object'], 'website_units_guard_and_listeners')
                # Readability never substitutes for the fixed reviewed digest.
                name = 'first-preview.py'; path = f.u.BIN / name
                f.f.f.put(path, path.read_bytes() + b'\n# unreviewed\n', mode)
                next_gate.reset_mock()
                with self.assertRaisesRegex(m.Refused, 'website_helper_changed'):
                    r.website_gate()
                next_gate.assert_not_called(); self.assertEqual(m.CONTEXT['object'], name)

    def test_legacy_helper_real_reader_rejects_unsafe_metadata_links_and_replacement(self):
        helpers = {name: digest for name, digest in w.m.HELPER_PINS.items()
                   if name not in ('ops-broker.py', 'collect-only-runner.py')}
        for bad in ('group_write', 'world_write', 'nonroot_owner', 'nonroot_group', 'symlink', 'hardlink', 'inode_swap'):
            with self.subTest(bad=bad), FlowFixture() as f, ExitStack() as stack:
                r = f.recovery; r.w = w.m; r.website_gate = m.Recovery.website_gate.__get__(r)
                stack.enter_context(patch.object(m, 'boot'))
                stack.enter_context(patch.object(m, 'BIN', f.u.BIN))
                for name in helpers:
                    f.f.f.put(f.u.BIN / name, (REPO / 'deploy/native' / name).read_bytes(), 0o644)
                name = 'first-preview.py'; path = f.u.BIN / name
                if bad == 'group_write': path.chmod(0o664)
                if bad == 'world_write': path.chmod(0o646)
                if bad == 'nonroot_owner': f.f.f.metadata(path, st_uid=986)
                if bad == 'nonroot_group': f.f.f.metadata(path, st_gid=986)
                if bad == 'symlink':
                    target = path.with_name('fixture-target.py'); path.rename(target); path.symlink_to(target)
                if bad == 'hardlink': os.link(str(path), str(path.with_name('fixture-hardlink.py')))
                if bad == 'inode_swap':
                    actual_fstat = w.m.os.fstat; swapped = [False]
                    def fstat(descriptor):
                        info = actual_fstat(descriptor)
                        if not swapped[0] and info.st_ino == path.lstat().st_ino:
                            swapped[0] = True
                            replacement = path.with_name('fixture-replacement.py')
                            f.f.f.put(replacement, path.read_bytes(), 0o644)
                            os.replace(str(replacement), str(path))
                        return info
                    stack.enter_context(patch.object(w.m.os, 'fstat', side_effect=fstat))
                next_gate = stack.enter_context(patch.object(w.m, 'properties', side_effect=AssertionError('unsafe-helper-reached-units')))
                with self.assertRaises((w.m.Refused, OSError)):
                    r.website_gate()
                next_gate.assert_not_called()
                self.assertEqual(m.CONTEXT['object'], name)

    def test_collector_effective_graph_requires_exact_observed_mounts_no_activation_hooks(self):
        with FlowFixture() as f, ExitStack() as stack:
            f.recovery.w = w.m
            stack.enter_context(patch.object(w.m, 'SERVICE_PATHS', dict(w.m.SERVICE_PATHS)))
            values = dict(Requires='-.mount system.slice sysinit.target', Wants='', BindsTo='',
                          Requisite='aifinance-preview-db.service', After='sysinit.target aifinance-preview-db.service',
                          OnFailure='', Slice='system.slice', DefaultDependencies='yes',
                          RequiresMountsFor='/var/tmp /opt/aifinance/releases/' + m.RELEASE, NeedDaemonReload='no',
                          Environment='', EnvironmentFiles='', PassEnvironment='', ExecStartPost='', ExecStop='', ExecStopPost='', ExecReload='')
            stack.enter_context(patch.object(w.m, 'properties', return_value=values))
            f.recovery.collector_units(f.r)
            for key, changed in [('Requires', 'aifinance-preview-db.service'), ('Wants', 'arbitrary.service'),
                                 ('RequiresMountsFor', '/var/tmp'), ('OnFailure', 'arbitrary.service'),
                                 ('Environment', 'NODE_OPTIONS=arbitrary'), ('ExecStartPost', 'arbitrary'),
                                 ('NeedDaemonReload', 'yes')]:
                before = values[key]; values[key] = changed
                with self.subTest(property=key), self.assertRaises(m.Refused): f.recovery.collector_units(f.r)
                values[key] = before

    def test_safe_diagnostics_never_emit_arbitrary_exception_or_command_text(self):
        secret = 'fixture-credential-must-never-appear'
        cases = [ValueError(secret), PermissionError(13, secret),
                 m.subprocess.CalledProcessError(3, ['/usr/bin/systemctl', secret], output=secret, stderr=secret),
                 m.subprocess.CalledProcessError(2, [secret], output=secret)]
        for error in cases:
            result = m.safe_error(error)
            self.assertNotIn(secret, json.dumps(result))
            self.assertIn('reason', result)
        self.assertEqual(m.safe_error(cases[2])['executable'], 'systemctl')
        self.assertEqual(m.safe_error(m.Refused('current_boot_changed')), {'reason': 'current_boot_changed'})


c = load('collector_boot_continuation', REPO / 'deploy/native/continue-collector-after-boot.py')
cb = load('collector_boot_continuation_proof_fixture', REPO / 'scripts/tests/collector-boot-broker-check.py')


class ContinuationFixture(FlowFixture):
    def __enter__(self):
        super(ContinuationFixture, self).__enter__()
        for name, value in (('OPS', m.OPS), ('COLLECT', m.COLLECT), ('CONFIG', m.CONFIG),
                            ('BIN', m.BIN), ('EVIDENCE', m.EVIDENCE), ('PRIOR', m.OPS / 'collector-boot-v2')):
            self.stack.enter_context(patch.object(c, name, value))
        self.stack.enter_context(patch.object(m, 'RUNNER_SHA_V2', 'a' * 64, create=True))
        self.stack.enter_context(patch.object(m, 'BROKER_SHA_V2', 'b' * 64, create=True))
        self.recovery.__class__ = c.make_recovery(m)
        r = self.recovery; r.current_records = dict(r.records)
        r.snapshot = {'prior': {n: {'sha256': m.sha(raw)} for n, raw in r.records.items()}}
        r.manifest_sha = 'c' * 64; r.validator = cb.m; r.prior_counts = dict(COUNTS)
        r.w.attributes.side_effect = w.m.attributes
        r.b.reason.return_value = 'operation_refused'
        self.stack.enter_context(patch.object(c, 'UPGRADE_RECORD', self.root / 'upgrade.json'))
        c.PRIOR.mkdir(mode=0o700); (c.PRIOR / 'archive').mkdir(mode=0o700)
        for name, raw in r.records.items(): self.f.f.put(c.PRIOR / 'archive' / name, raw)
        self.assert_archive = lambda: self.check_archives()
        return self

    def check_archives(self):
        for dirname, values in [('archive', self.recovery.records), ('attempt-before', self.recovery.current_records)]:
            for name, raw in values.items():
                if (c.EVIDENCE / dirname / name).read_bytes() != raw:
                    raise AssertionError('both archives must be durable before mutation')

    def prior_fixture(self):
        r = self.recovery; r.b = self.f.broker
        proof = cb.report('probe')
        r.records = {'installed.json': self.u.encoded(dict(release=m.RELEASE, uid=USER.pw_uid)),
                     'network.json': self.u.encoded(dict(uid=USER.pw_uid, hosts={})),
                     'seed-attempt.json': self.u.encoded(dict(release=m.RELEASE, mode='seed', started=1000)),
                     'output.json': b'', 'probe.json': self.u.encoded(proof),
                     'probe-1000-0123456789ab.json': self.u.encoded(proof)}
        for path in (c.PRIOR / 'archive').iterdir(): path.unlink()
        for name, raw in r.records.items(): self.f.f.put(c.PRIOR / 'archive' / name, raw)
        baseline = dict(attempt_started=1000, attempt_sha256=c.sha(r.records['seed-attempt.json']))
        website = dict(preserved_after={str(c.COLLECT / n): {'sha256': c.sha(raw)} for n, raw in r.records.items()})
        prior_manifest = dict(schema=2, boot_id=m.BOOT, release=m.RELEASE, payloads={
            'recover-collector-after-boot.py': c.BASE_SHA, 'update-ops-nss-proof.py': m.UPDATER_SHA,
            'recover-preview-after-boot.py': c.WEBSITE_SHA, 'collect-only-runner.py': m.RUNNER_SHA_V2,
            'ops-broker.py': m.BROKER_SHA_V2})
        prior_raw = self.u.encoded(prior_manifest)
        failure_raw = self.u.encoded(dict(stage='fresh_read_only_nss_check', automatic_retry=False,
            cleanup=dict(collector_stopped=True, database_read_revoked=True, collector_https_revoked=True, website_restored=False)))
        r.manifest = dict(predecessor=dict(manifest_sha256=c.sha(prior_raw), failure_sha256=c.sha(failure_raw), website_sha256='e' * 64))
        self.f.f.put(c.PRIOR / 'manifest.json', prior_raw); self.f.f.put(c.PRIOR / 'failure.json', failure_raw)
        self.f.f.put(c.PRIOR / 'sql-before.json', self.u.encoded(dict(proof=dict(PROOF), counts=dict(COUNTS))))
        self.f.f.put(c.PRIOR / 'fresh-probe.json', self.u.encoded(proof))
        helper = c.PRIOR / 'helper-update'; helper.mkdir(mode=0o700)
        self.f.f.put(helper / 'manifest.json', prior_raw)
        policy = self.f.old_policy
        complete = dict(schema=1, status='complete', broker_sha256=self.u.OLD_BROKER, app_release=m.RELEASE)
        old = dict(self.f.old)
        new = dict(runner=m.RUNNER_SHA_V2, broker=m.BROKER_SHA_V2,
            policy=c.sha(self.u.encoded(dict(policy, runner_sha256=m.RUNNER_SHA_V2, broker_sha256=m.BROKER_SHA_V2))),
            complete=c.sha(self.u.encoded(dict(complete, broker_sha256=m.BROKER_SHA_V2))))
        for key, raw in old.items(): self.f.f.put(helper / (key + '.before'), raw)
        self.f.f.put(helper / 'complete.withheld', old['complete'])
        stage = c.OPS / '.complete.json.nss-v1.next'
        self.f.f.put(stage, self.u.encoded(dict(complete, broker_sha256=m.BROKER_SHA_V2)))
        withheld_id = self.u.read(helper / 'complete.withheld', 0o600)[1]
        stage_id = self.u.read(stage, 0o600)[1]
        plan = dict(schema=1, files={key: dict(old_sha256=c.sha(raw), new_sha256=new[key], mode=self.u.MODES[key],
            old_identity=list(withheld_id if key == 'complete' else self.u.read(self.u.TARGETS[key], self.u.MODES[key])[1]),
            staged_identity=list(stage_id), security_attributes={}) for key, raw in old.items()},
            history_sha256=c.sha(self.f.history), history_identity=list(self.u.read(self.u.HISTORY, 0o600)[1]))
        self.f.f.put(helper / 'plan.json', self.u.encoded(plan))
        return baseline, website

    def current_fixture(self):
        baseline, website = self.prior_fixture(); r = self.recovery
        for path in c.COLLECT.iterdir():
            if path.is_file(): path.unlink()
        for name, raw in r.records.items(): self.f.f.put(c.COLLECT / name, raw)
        self.f.f.put(c.COLLECT / 'probe-2000-fedcba987654.json', self.u.encoded(cb.report('probe')))
        self.f.f.put(c.UPGRADE_RECORD, b'{"restore_verified":true}\n')
        db = c.CONFIG / 'database.env'; dbmeta = w.m.attributes(db.lstat())
        baseline.update(db_device=dbmeta['device'], db_inode=dbmeta['inode'], collector_gid=USER.pw_gid,
                        check_start_monotonic='10', check_exit_monotonic='20')
        website['preserved_after'][str(db)] = dict(dbmeta)
        for path in (c.OPS / 'install.json', c.UPGRADE_RECORD):
            website['preserved_after'][str(path)] = dict(w.m.attributes(path.lstat()), sha256=c.sha(path.read_bytes()))
        states = {name: dict(ActiveState='inactive', SubState='dead', Result='success', MainPID='0', ControlPID='0',
                  ExecMainCode='0', ExecMainStatus='0', ExecMainStartTimestampMonotonic='0', ExecMainExitTimestampMonotonic='0')
                  for name in ('probe', 'check', 'seed', 'run')}
        states['check'].update(ActiveState='failed', SubState='failed', Result='signal', ExecMainCode='2', ExecMainStatus='15',
                               ExecMainStartTimestampMonotonic='210', ExecMainExitTimestampMonotonic='220')
        r.b.Broker = Mock(return_value=self.worker); r.b.unit_states = Mock(return_value=states)
        r.b.document = Mock(return_value={'restore_verified': True})
        self.worker.identity.return_value = USER; self.worker.recovery_baseline.return_value = baseline
        self.worker.journal_metadata.return_value = []
        self.worker.environment_fd.side_effect = lambda **kw: (os.open(str(db), os.O_RDONLY), db.lstat())
        self.u.TARGETS['complete'].unlink()
        r.website_evidence = Mock(return_value=(r.web_receipt, website))
        r.manifest['predecessor']['website_sha256'] = r.web_receipt['sha256']
        r.w.metadata.return_value = dbmeta
        r.w.read.side_effect = lambda path, **kw: path.read_bytes()
        m.WEBSITE.mkdir(mode=0o700)
        for name in ('01-evidence_create.json', '05-complete.json'): self.f.f.put(m.WEBSITE / name, b'{}')
        self.stack.enter_context(patch.object(m, 'boot'))
        r.collector_units = Mock(); r.snapshot = None
        del r.original_state
        return states


class ContinuationChecks(unittest.TestCase):
    def test_v3_real_transaction_late_failures_restore_helpers_and_revoke_held_db(self):
        for failing in ('callback', 'completion_rename', 'completion_evidence'):
            with self.subTest(failing=failing), t.WithheldFixture() as f, ExitStack() as stack:
                u = t.v3; evidence = u.UPDATE.parent; evidence.rmdir()
                for module_ in (m, c):
                    for key, value in (('EVIDENCE', evidence), ('OPS', u.OPS), ('RUNNER_SHA', u.NEW_RUNNER), ('BROKER_SHA', u.NEW_BROKER)):
                        stack.enter_context(patch.object(module_, key, value))
                f.broker.RUNNER_SHA = u.OLD_RUNNER; f.new_broker.RUNNER_SHA = u.NEW_RUNNER
                r = object.__new__(c.make_recovery(m)); m.Recovery.__init__(r, u, Mock(), f.broker, f.runner, f.upgrade)
                r.snapshot = {}; opened = []; cleaned = []
                def original(*args): c.require(not r.started, 'continuation_attempted_gate_stays_closed')
                r.original_state = original
                def recover(*args):
                    self.assertFalse(u.TARGETS['complete'].exists()); r.started = True; r.stage = 'ready'
                    r.db_fd = os.open(str(t.legacy.m.CONFIG / 'database.env'), os.O_RDONLY)
                    r.db_info = os.fstat(r.db_fd); opened.append(r.db_fd)
                    u.write_new(evidence / 'ready.json', b'{"status":"fixture-ready"}\n')
                    if failing == 'callback': raise c.Refused('fixture_callback_failed')
                r.recover = recover
                def cleanup():
                    self.assertFalse(u.TARGETS['complete'].exists())
                    self.assertEqual(os.fstat(r.db_fd).st_ino, r.db_info.st_ino)
                    os.fchmod(r.db_fd, 0o400); cleaned.append(True)
                    r.cleanup_result = dict(database_read_revoked=True, website_restored=True)
                    return r.cleanup_result
                r.cleanup = cleanup
                real_write = u.write_new; real_replace = u.os.replace
                def write(path, *args, **kwargs):
                    if failing == 'completion_evidence' and path == u.UPDATE / 'complete.json': raise OSError('fixture-secret')
                    return real_write(path, *args, **kwargs)
                def replace(source, destination):
                    real_replace(source, destination)
                    if failing == 'completion_rename' and Path(destination) == u.TARGETS['complete']: raise OSError('fixture-secret')
                with patch.object(u, 'write_new', side_effect=write), patch.object(u.os, 'replace', side_effect=replace), u.lock(f.runner):
                    result = r.apply(f.manifest, f.change)
                self.assertFalse(result['ok']); self.assertEqual(result['completion_gate'], 'withheld')
                self.assertEqual(result['rollback'], 'old_set_verified'); self.assertEqual(cleaned, [True])
                self.assertFalse(u.TARGETS['complete'].exists()); self.assertIsNone(r.db_fd)
                self.assertTrue((evidence / 'ready.json').exists()); self.assertTrue((evidence / 'failure.json').exists())
                for key in ('runner', 'broker', 'policy'): self.assertEqual(u.TARGETS[key].read_bytes(), f.old[key])
                self.assertEqual(u.HISTORY.read_bytes(), f.history); self.assertNotIn('fixture-secret', json.dumps(result))
                for descriptor in opened:
                    with self.assertRaises(OSError): os.fstat(descriptor)
                for path, before in f.preserved.items(): self.assertEqual((u.read(path, 0o600), u.attrs(path)), before)

    def test_v3_source_pins_and_canonical_private_manifest(self):
        locations = {'continue-collector-after-boot.py': 'continue-collector-after-boot.py',
                     'recover-collector-after-boot.py': 'recover-collector-after-boot.py',
                     'recover-preview-after-boot.py': 'recover-preview-after-boot.py',
                     'update-ops-nss-proof.py': 'updates/collector-boot-v3/update-ops-nss-proof.py',
                     'collect-only-runner.py': 'updates/collector-boot-v3/collect-only-runner.py',
                     'ops-broker.py': 'updates/collector-boot-v3/ops-broker.py'}
        data = {name: (REPO / 'deploy/native' / filename).read_bytes() for name, filename in locations.items()}
        with t.Fixture() as f:
            source = f.f.root / 'continuation-source'; source.mkdir(mode=0o700)
            for name, raw in data.items(): f.f.put(source / name, raw)
            manifest = dict(schema=3, boot_id=m.BOOT, release=c.RELEASE, payloads={n: c.sha(raw) for n, raw in data.items()},
                            predecessor=dict(manifest_sha256='a' * 64, failure_sha256='b' * 64, website_sha256='c' * 64))
            raw = t.u.encoded(manifest); f.f.put(source / 'manifest.json', raw)
            with patch.object(c, 'SOURCE_PATTERN', re.escape(str(source))):
                self.assertEqual(c.source_inputs(source, c.sha(raw), m.BOOT), (manifest, data))
                with self.assertRaisesRegex(c.Refused, 'manifest_digest'): c.source_inputs(source, '0' * 64, m.BOOT)
                for changed in (dict(schema=True), dict(boot_id='stale'), dict(predecessor={})):
                    bad = t.u.encoded(dict(manifest, **changed)); f.f.put(source / 'manifest.json', bad)
                    with self.assertRaises(c.Refused): c.source_inputs(source, c.sha(bad), m.BOOT)
                bad = json.dumps(manifest).encode(); f.f.put(source / 'manifest.json', bad)
                with self.assertRaisesRegex(c.Refused, 'canonical_manifest'): c.source_inputs(source, c.sha(bad), m.BOOT)
                f.f.put(source / 'manifest.json', raw); f.f.put(source / 'ops-broker.py', data['ops-broker.py'] + b'\n')
                with self.assertRaisesRegex(c.Refused, 'source_payload'): c.source_inputs(source, c.sha(raw), m.BOOT)

    def test_check_failure_projection_uses_only_exported_codes(self):
        for error in (c.Refused('prior_manifest_changed'), ValueError('fixture-secret'), PermissionError(13, 'fixture-secret')):
            result = c.safe_error(error)
            self.assertIn(result['reason'], c.SAFE_REASON_CODES)
            if 'error_type' in result: self.assertIn(result['error_type'], c.SAFE_ERROR_TYPES)
        for stage in ('check', 'entry', 'prior_v2_inventory', 'prior_v2_transaction'):
            self.assertIn(stage, c.SAFE_STAGE_CODES)

    def test_current_failed_state_is_read_only_and_snapshot_detects_drift(self):
        with ContinuationFixture() as f:
            f.current_fixture(); r = f.recovery
            before = {str(p): (p.read_bytes(), p.stat().st_ino) for p in f.root.rglob('*') if p.is_file()}
            r.original_state(r.b, f.r)
            self.assertEqual(before, {str(p): (p.read_bytes(), p.stat().st_ino) for p in f.root.rglob('*') if p.is_file()})
            self.assertEqual(r.snapshot['units']['check']['ExecMainStatus'], '15')
            f.f.f.put(c.COLLECT / 'output.json', b'')
            with self.assertRaisesRegex(c.Refused, 'snapshot_changed'): r.original_state(r.b, f.r)

    def test_current_unknown_receipts_units_and_database_metadata_refused(self):
        for kind in ('seed_receipt', 'run_receipt', 'launch', 'check', 'probe', 'probe_metadata', 'seed_start', 'db_ctime', 'db_mtime'):
            with self.subTest(kind=kind), ContinuationFixture() as f:
                states = f.current_fixture(); r = f.recovery
                if kind == 'seed_receipt': f.f.f.put(c.COLLECT / 'seed.json', b'{}')
                if kind == 'run_receipt': f.f.f.put(c.COLLECT / 'run-attempt.json', b'{}')
                if kind == 'launch': f.f.f.put(c.COLLECT / 'launch.json', b'{}')
                if kind == 'check': states['check']['ExecMainStatus'] = '0'
                if kind == 'probe': states['probe']['Result'] = 'signal'
                if kind == 'probe_metadata': states['probe'].update(ExecMainCode='1', ExecMainStartTimestampMonotonic='100', ExecMainExitTimestampMonotonic='200')
                if kind == 'seed_start': states['seed']['ExecMainStartTimestampMonotonic'] = '1'
                if kind.startswith('db_'):
                    metadata = dict(r.w.metadata.return_value); metadata['ctime_ns' if kind == 'db_ctime' else 'mtime_ns'] -= 1
                    r.w.metadata.return_value = metadata
                with self.assertRaises(c.Refused): r.original_state(r.b, f.r)

    def test_historical_count_change_refused_before_permissions_or_probe(self):
        with ContinuationFixture() as f:
            f.recovery.prior_counts = dict(COUNTS, articles=1)
            with self.assertRaisesRegex(c.Refused, 'historical_downstream'): f.recovery.recover(f.b, f.r)
            f.r.run_unit.assert_not_called(); self.assertTrue((c.COLLECT / 'seed-attempt.json').exists())
            self.assertFalse((c.EVIDENCE / 'fresh-probe.json').exists())

    def test_imported_run_handles_and_restores_interruption_signals(self):
        original = {sig: c.signal.getsignal(sig) for sig in (c.signal.SIGINT, c.signal.SIGTERM, c.signal.SIGHUP)}
        def checked(argv):
            for sig in original: self.assertIs(c.signal.getsignal(sig), c.interrupted)
            c.signal.getsignal(c.signal.SIGTERM)(c.signal.SIGTERM, None)
        with patch.object(c, 'checked_run', side_effect=checked): result = c.run(['check'])
        self.assertEqual(result['reason'], 'continuation_interrupted')
        self.assertEqual({sig: c.signal.getsignal(sig) for sig in original}, original)

    def test_v3_syntax_and_immutable_v2_source(self):
        ast.parse((REPO / 'deploy/native/continue-collector-after-boot.py').read_text(),
                  **({'feature_version': (3, 6)} if sys.version_info >= (3, 8) else {}))
        self.assertEqual(c.sha((REPO / 'deploy/native/recover-collector-after-boot.py').read_bytes()), c.BASE_SHA)
        self.assertEqual(c.sha((REPO / 'deploy/native/update-ops-nss-proof.py').read_bytes()), m.UPDATER_SHA)

    def test_exact_prior_evidence_is_read_only_and_preserves_chain(self):
        with ContinuationFixture() as f:
            baseline, website = f.prior_fixture()
            before = {str(p): (p.read_bytes(), p.stat().st_ino) for p in c.PRIOR.rglob('*') if p.is_file()}
            records, fresh, inventory = f.recovery.prior_evidence(USER, baseline, website)
            self.assertEqual(records, f.recovery.records); self.assertEqual(fresh['mode'], 'probe')
            self.assertEqual(set(inventory), set(str(Path(p).relative_to(c.PRIOR)) for p in before))
            self.assertEqual(before, {str(p): (p.read_bytes(), p.stat().st_ino) for p in c.PRIOR.rglob('*') if p.is_file()})

    def test_prior_provenance_tampering_is_refused(self):
        for kind in ('manifest', 'failure', 'archive', 'proof', 'fresh', 'plan', 'withheld', 'stage', 'extra', 'symlink'):
            with self.subTest(kind=kind), ContinuationFixture() as f:
                baseline, website = f.prior_fixture()
                helper = c.PRIOR / 'helper-update'
                if kind == 'manifest': f.f.f.put(c.PRIOR / 'manifest.json', b'{}')
                if kind == 'failure': f.f.f.put(c.PRIOR / 'failure.json', b'{}')
                if kind == 'archive': f.f.f.put(c.PRIOR / 'archive/output.json', b'changed')
                if kind == 'proof': f.f.f.put(c.PRIOR / 'sql-before.json', f.u.encoded(dict(proof=dict(PROOF, sources=1), counts=dict(COUNTS))))
                if kind == 'fresh': f.f.f.put(c.PRIOR / 'fresh-probe.json', f.u.encoded(dict(cb.report('probe'), elapsed_seconds=1)))
                if kind == 'plan':
                    value = c.document(c.read(helper / 'plan.json')); value['files']['runner']['new_sha256'] = '0' * 64
                    f.f.f.put(helper / 'plan.json', f.u.encoded(value))
                if kind == 'withheld':
                    raw = (helper / 'complete.withheld').read_bytes(); (helper / 'complete.withheld').unlink(); f.f.f.put(helper / 'complete.withheld', raw)
                if kind == 'stage': f.f.f.put(c.OPS / '.complete.json.nss-v1.next', b'{}')
                if kind == 'extra': f.f.f.put(c.PRIOR / 'ready.json', b'{}')
                if kind == 'symlink':
                    (c.PRIOR / 'fresh-probe.json').unlink(); (c.PRIOR / 'fresh-probe.json').symlink_to(c.PRIOR / 'manifest.json')
                with self.assertRaises((c.Refused, OSError, cb.m.Refused)):
                    f.recovery.prior_evidence(USER, baseline, website)

    def test_v3_flow_archives_both_receipt_generations_and_only_runs_probe_check(self):
        with ContinuationFixture() as f:
            original = dict(f.recovery.records)
            changed = dict(f.probe, elapsed_seconds=31)
            f.recovery.current_records['probe.json'] = f.u.encoded(changed)
            f.f.f.put(c.COLLECT / 'probe.json', f.recovery.current_records['probe.json'])
            f.recovery.recover(f.b, f.r)
            f.check_archives(); self.assertEqual(f.events, ['run_probe', 'replace_probe', 'run_check'])
            self.assertEqual(f.recovery.records, original)
            ready = c.document(c.read(c.EVIDENCE / 'ready.json'))
            self.assertEqual(ready['schema'], 3)
            self.assertEqual(ready['archive_sha256']['probe.json'], c.sha(original['probe.json']))
            self.assertEqual(ready['continuation']['attempt_before_sha256']['probe.json'], c.sha(f.recovery.current_records['probe.json']))
            self.assertFalse((c.COLLECT / 'seed-attempt.json').exists())
            self.assertEqual(f.worker.sql_proof.call_count, 2)
            f.r.configure_network.assert_not_called(); f.r.first_operation.assert_not_called(); f.r.enable_hourly.assert_not_called()

    def test_v3_failures_before_rearm_preserve_attempt_and_fail_closed(self):
        for stage in ('probe', 'check', 'counts', 'restore'):
            with self.subTest(stage=stage), ContinuationFixture() as f:
                before = c.read(c.COLLECT / 'seed-attempt.json')
                if stage in ('probe', 'check'): f.fail = stage
                if stage == 'counts': f.recovery.counts.side_effect = [dict(COUNTS), dict(COUNTS, articles=1)]
                if stage == 'restore': f.recovery.restore_website.side_effect = [ValueError('fixture-secret'), None]
                with self.assertRaises((ValueError, c.Refused)): f.recovery.recover(f.b, f.r)
                self.assertEqual(c.read(c.COLLECT / 'seed-attempt.json'), before)
                self.assertFalse((c.EVIDENCE / 'ready.json').exists())
                self.assertTrue(f.recovery.cleanup_result['website_restored'])
                self.assertNotIn('fixture-secret', c.read(c.EVIDENCE / 'failure.json').decode())

    def test_v3_restore_health_wait_precedes_strict_listener_gate(self):
        with ContinuationFixture() as f:
            r = f.recovery; events = []
            r.website_evidence = Mock(return_value=(r.web_receipt, {}))
            r.website_gate.side_effect = lambda healthy=True: events.append('final_gate' if healthy else 'prestart_gate')
            f.website.command.side_effect = lambda *a, **kw: events.append('start')
            r.fp.health.side_effect = lambda *a: events.append('health_wait')
            del r.restore_website
            r.restore_website()
            self.assertEqual(events, ['prestart_gate', 'start', 'health_wait', 'final_gate'])

    def test_safe_entry_and_resolver_diagnostics_never_emit_secrets(self):
        secret = 'private-fixture-secret'
        error = ValueError(secret); error.resolver_reason = 'mount_id_missing'
        self.assertEqual(c.safe_error(error)['resolver_reason'], 'mount_id_missing')
        error.resolver_reason = secret
        self.assertNotIn(secret, json.dumps(c.safe_error(error)))
        for failure in (error, SystemExit(2), PermissionError(13, secret)):
            with patch.object(c, 'checked_run', side_effect=failure):
                result = c.run(['check'])
                self.assertFalse(result['ok']); self.assertNotIn(secret, json.dumps(result))

    def test_cleanup_reports_independent_safe_reasons(self):
        with ContinuationFixture() as f:
            r = f.recovery; r.worker = f.worker; r.app_stop_attempted = True
            r.restore_website.side_effect = ValueError('private-fixture-secret')
            result = r.cleanup()
            self.assertFalse(result['website_restored'])
            self.assertIn('reason', result['website_restored_reason'])
            self.assertNotIn('private-fixture-secret', json.dumps(result))
            self.assertTrue(result['collector_https_revoked'])


if __name__ == '__main__':
    unittest.main()
