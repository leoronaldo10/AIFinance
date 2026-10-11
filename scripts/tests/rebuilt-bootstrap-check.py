#!/usr/bin/python3
"""No host operations: temporary files and mocked systemd/HTTP only."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('bootstrap', REPO / 'deploy/native/rebuilt-bootstrap.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
REAL_HEALTH = m.health


class Bootstrap(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        values = {'ROOT': root / 'opt', 'SYSTEM': root / 'system', 'STATE': root / 'state',
                  'LOCK': root / 'lock', 'MANIFEST': root / 'source.sha256', 'NODE': root / 'node'}
        values.update(OLD=values['ROOT'] / 'staging' / m.g.BASELINE,
                      SWITCH=values['ROOT'] / 'switch', CURRENT=values['ROOT'] / 'switch/current',
                      TX=values['STATE'] / 'rebuilt-v1')
        for name, value in values.items():
            p = patch.object(m, name, value); p.start(); self.addCleanup(p.stop)
        self.patches = [patch.object(m.g, 'POLICY', root / 'policy.json'),
                        patch.object(m.g, 'trusted'),
                        patch.object(m.pwd, 'getpwnam', return_value=types.SimpleNamespace(pw_uid=os.getuid()))]
        for p in self.patches:
            p.start(); self.addCleanup(p.stop)
        m.SYSTEM.mkdir()
        m.OLD.mkdir(parents=True)
        m.NODE.write_text('fixture')
        (m.OLD / 'database/migrations').mkdir(parents=True)
        (m.OLD / 'database/migrations/001.sql').write_text('SELECT 1;')
        manifest = m.digest(b'SELECT 1;') + '  database/migrations/001.sql\n'
        m.MANIFEST.write_text(manifest)
        p = patch.object(m, 'MANIFEST_DIGEST', m.digest(manifest.encode()))
        p.start(); self.addCleanup(p.stop)
        (m.OLD / 'schema.sha256').write_text(manifest)
        (m.OLD / 'RELEASE_SHA').write_text(m.g.BASELINE + '\n')
        (m.OLD / 'apps/web/build/server').mkdir(parents=True)
        (m.OLD / 'apps/web/build/server/index.js').write_text('fixture')
        (m.OLD / 'node_modules').mkdir()
        (m.OLD / '.env').write_text('SECRET=do-not-read-or-copy')
        (m.OLD / '.env').chmod(0o600)
        for unit in m.g.UNITS.values():
            (m.SYSTEM / unit).write_text('[Service]\n# immutable original fixture\n')
        self.calls = []
        self.override = {}
        def properties(unit):
            alias = next(k for k, v in m.g.UNITS.items() if v == unit)
            switched = m.drop(alias).exists()
            result = {'User': 'aifinance-deploy',
                      'WorkingDirectory': str(m.CURRENT if switched else m.OLD),
                      'ExecStart': '{ path=' + str(m.NODE) + ' ; argv[]=' + str(m.NODE) +
                          ' --experimental-strip-types ' + m.ENTRIES[alias] +
                          ' ; ignore_errors=no ; start_time=n/a ; stop_time=n/a ; pid=0 ; code=(null) ; status=0/0 }',
                      'EnvironmentFiles': str(m.OLD / '.env') + ' (ignore_errors=no)',
                      'FragmentPath': str(m.SYSTEM / unit),
                      'DropInPaths': str(m.drop(alias)) if switched else ''}
            result.update(self.override)
            return result
        def run(argv, **kw):
            self.calls.append(argv)
            if argv == [str(m.NODE), '--version']: return 'v24.21.0'
            if argv[:2] == ['/usr/bin/systemctl', 'show'] and '--property=Job' in argv: return ''
            if argv == ['/usr/bin/systemctl', 'daemon-reload']: return ''
            if argv == ['/usr/bin/systemctl', 'restart', *m.g.UNITS.values()]: return ''
            raise AssertionError('unexpected host command: ' + repr(argv))
        for p in [patch.object(m.g, 'properties', side_effect=properties),
                  patch.object(m, 'run', side_effect=run),
                  patch.object(m.g, 'run', side_effect=AssertionError('real host access')),
                  patch.object(m, 'health', return_value='dev'),
                  patch.object(m, 'wait_health')]:
            p.start(); self.addCleanup(p.stop)

    def test_check_is_read_only_and_does_not_read_environment(self):
        original_read = m.read
        def checked(path, *args):
            self.assertNotEqual(path, m.OLD / '.env')
            return original_read(path, *args)
        with patch.object(m, 'read', side_effect=checked):
            self.assertEqual(m.preflight()['health_release'], 'dev')
        self.assertFalse(m.STATE.exists())
        self.assertFalse(m.SWITCH.exists())
        self.assertFalse(any('restart' in c for c in self.calls))

    def test_status_distinguishes_absence_partial_and_invalid_receipts(self):
        self.assertEqual(m.status(), {'phase': 'not_initialized', 'receipt_exists': False})
        self.assertFalse(m.STATE.exists())
        with self.assertRaisesRegex(m.Refused, 'receipt_not_initialized'): m.load()
        m.directory(m.STATE); m.directory(m.TX)
        with self.assertRaisesRegex(m.Refused, 'receipt_missing_in_existing_transaction'): m.status()
        m.write(m.TX / 'state.json', b'{bad')
        with self.assertRaisesRegex(m.Refused, 'receipt_invalid_json'): m.status()
        m.write(m.TX / 'state.json', b'[]')
        with self.assertRaisesRegex(m.Refused, 'invalid_receipt_shape'): m.status()

    def test_layout_without_receipt_is_not_mistaken_for_fresh_install(self):
        m.SWITCH.mkdir()
        with self.assertRaisesRegex(m.Refused, 'layout_exists_without_receipt'): m.status()

    def test_apply_only_changes_cwd_and_preserves_env_and_original_units(self):
        before = {u: (m.SYSTEM / u).read_bytes() for u in m.g.UNITS.values()}
        record = m.apply()
        self.assertEqual(record['phase'], 'same_version_ready')
        self.assertEqual(record['health_release'], 'dev')
        self.assertEqual(os.readlink(m.CURRENT), str(m.OLD))
        for alias, unit in m.g.UNITS.items():
            self.assertEqual((m.SYSTEM / unit).read_bytes(), before[unit])
            self.assertEqual(m.drop(alias).read_bytes(), m.content())
            self.assertNotIn(b'AIHOT_RELEASE=', m.drop(alias).read_bytes())
            self.assertEqual(m.drop(alias).stat().st_mode & 0o777, 0o644)
        self.assertEqual(m.TX.stat().st_mode & 0o777, 0o700)
        self.assertNotIn('SECRET', (m.TX / 'state.json').read_text())
        self.assertFalse((m.ROOT / 'releases').exists())

    def test_successful_bootstrap_can_restore_original_units_and_absent_link(self):
        record = m.apply()
        m.restore(record)
        self.assertEqual(m.load()['phase'], 'rolled_back')
        self.assertFalse(m.SWITCH.exists())
        self.assertTrue((m.OLD / '.env').exists())
        for alias in m.ENTRIES: self.assertFalse(m.drop(alias).parent.exists())

    def test_new_health_failure_rolls_back_but_still_fails_apply(self):
        m.wait_health.side_effect = [m.Refused('health_timeout'), None]
        with self.assertRaisesRegex(m.Refused, 'bootstrap_failed_rolled_back'): m.apply()
        self.assertEqual(m.load()['phase'], 'rolled_back')
        self.assertFalse(m.SWITCH.exists())

    def test_failed_rollback_retains_evidence_for_manual_recovery(self):
        m.wait_health.side_effect = m.Refused('health_timeout')
        with self.assertRaisesRegex(m.Refused, 'recovery_required'): m.apply()
        self.assertEqual(m.load()['phase'], 'recovery_required')
        self.assertTrue((m.TX / 'api.unit.backup').exists())
        m.wait_health.side_effect = None
        m.restore(m.load())
        self.assertEqual(m.load()['phase'], 'rolled_back')

    def test_pending_job_refuses_without_layout_changes(self):
        with patch.object(m, 'idle', side_effect=m.Refused('unit_job_pending')):
            with self.assertRaises(m.Refused): m.apply()
        self.assertFalse(m.SWITCH.exists())
        self.assertFalse(m.TX.exists())

    def test_effective_exec_env_or_other_dropin_changes_refuse(self):
        for key, value in [('ExecStart', 'unexpected command'), ('EnvironmentFiles', ''),
                           ('DropInPaths', '/other.conf'), ('User', 'root')]:
            self.override = {key: value}
            with self.assertRaises(m.Refused): m.preflight()
        self.assertFalse(m.TX.exists())

    def test_marker_and_source_manifest_are_verified_not_assumed(self):
        (m.OLD / 'RELEASE_SHA').write_text('a' * 40)
        with self.assertRaisesRegex(m.Refused, 'baseline_identity'): m.preflight()
        (m.OLD / 'RELEASE_SHA').write_text(m.g.BASELINE)
        (m.OLD / 'database/migrations/001.sql').write_text('changed')
        with self.assertRaisesRegex(m.Refused, 'source_mismatch'): m.preflight()

    def test_schema_manifest_and_new_migration_refuse(self):
        (m.OLD / 'schema.sha256').write_text('invalid')
        with self.assertRaisesRegex(m.Refused, 'baseline_schema_manifest'): m.preflight()
        (m.OLD / 'schema.sha256').write_text(m.MANIFEST.read_text())
        (m.OLD / 'database/migrations/002.sql').write_text('SELECT 2;')
        with self.assertRaisesRegex(m.Refused, 'baseline_migration_set_changed'): m.preflight()

    def test_enabled_policy_existing_switch_or_env_symlink_refuse(self):
        m.g.POLICY.write_text('{"accepted":true}')
        with self.assertRaises(m.Refused): m.preflight()
        m.g.POLICY.unlink()
        m.SWITCH.mkdir()
        with self.assertRaises(m.Refused): m.preflight()
        m.SWITCH.rmdir()
        (m.OLD / '.env').unlink()
        (m.OLD / '.env').symlink_to(m.NODE)
        with self.assertRaises(m.Refused): m.preflight()

    def test_external_unit_or_dropin_edit_not_overwritten_by_rollback(self):
        record = m.apply()
        m.drop('api').write_text('external edit')
        with self.assertRaisesRegex(m.Refused, 'dropin_changed'): m.restore(record)
        self.assertEqual(m.drop('api').read_text(), 'external edit')
        m.drop('api').write_bytes(m.content())
        (m.SYSTEM / m.g.UNITS['web']).write_text('external unit edit')
        with self.assertRaisesRegex(m.Refused, 'original_unit_changed'): m.restore(record)

    def test_partial_dropin_install_can_be_rolled_back(self):
        record = m.preflight()
        m.directory(m.STATE); m.directory(m.TX); m.save(record)
        m.directory(m.SWITCH, 0o755); m.CURRENT.symlink_to(m.OLD)
        m.directory(m.drop('api').parent, 0o755); m.write(m.drop('api'), m.content(), 0o644)
        m.restore(record)
        self.assertEqual(m.load()['phase'], 'rolled_back')

    def test_same_receipt_cannot_repeat_restart(self):
        m.apply()
        calls = len(self.calls)
        with self.assertRaisesRegex(m.Refused, 'receipt_exists'): m.apply()
        self.assertEqual(len(self.calls), calls)

    def test_health_requires_database_ok_and_preserves_unstamped_dev(self):
        def response(argv, **kw):
            if 'http://127.0.0.1:3001/api/health' in argv:
                return json.dumps(payload)
            if argv[:2] == ['/usr/bin/systemctl', 'is-active'] or 'http://127.0.0.1:3000/' in argv:
                return ''
            raise AssertionError('unexpected call')
        with patch.object(m.g, 'listeners'), patch.object(m, 'run', side_effect=response):
            payload = {'ok': True, 'db': 'ok', 'release': 'dev'}
            self.assertEqual(REAL_HEALTH(), 'dev')
            for payload in ({'ok': True, 'db': 'broken', 'release': 'dev'},
                            {'ok': True, 'db': 'ok', 'release': 'a'*40}, []):
                with self.assertRaises(m.Refused): REAL_HEALTH()

    def test_lock_refuses_another_process(self):
        original = os.fstat
        def root_stat(fd):
            s = original(fd)
            return types.SimpleNamespace(st_mode=s.st_mode, st_nlink=s.st_nlink, st_uid=0)
        with patch.object(m.os, 'fstat', side_effect=root_stat): fd = m.lock()
        try:
            result = subprocess.run(['python3', '-c',
                'import fcntl,sys; f=open(sys.argv[1]); fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)',
                str(m.LOCK)], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
        finally: os.close(fd)


class Manifest(unittest.TestCase):
    def test_installation_checksums_and_dropin_samples_match_implementation(self):
        root = REPO / 'deploy/native'
        for line in (root / 'rebuilt-bootstrap-files.sha256').read_text().splitlines():
            expected, name = line.split('  ', 1)
            self.assertEqual(hashlib.sha256((root / name).read_bytes()).hexdigest(), expected)
        for alias in ('api', 'web'):
            self.assertEqual((root / ('rebuilt-bootstrap-' + alias + '.conf')).read_bytes(), m.content())

    def test_reviewed_runtime_manifest_has_pinned_digest_and_safe_paths(self):
        # Generated from d57ba047's Git blobs, not the live server. This check also
        # works in shallow CI checkouts without granting network/fetch permissions.
        actual = (REPO / 'deploy/native/rebuilt-baseline.sha256').read_text()
        self.assertEqual(hashlib.sha256(actual.encode()).hexdigest(), m.MANIFEST_DIGEST)
        self.assertEqual(len(actual.splitlines()), 398)
        names = [line.split('  ', 1)[1] for line in actual.splitlines()]
        self.assertEqual(names, sorted(set(names)))
        self.assertTrue(all(not Path(n).is_absolute() and '..' not in Path(n).parts for n in names))
        self.assertTrue(all(re.fullmatch(r'([0-9a-f]{64})  ([a-zA-Z0-9_./@+\[\]$()-]+)', line)
                            for line in actual.splitlines()))


if __name__ == '__main__': unittest.main()
