#!/usr/bin/python3
"""Temporary fixtures and mocked host commands only; no SSH, systemd or database."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('rebuilt', REPO/'deploy/native/rebuilt-gateway.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
REAL_RUN = m.run
REAL_HEALTH = m.healthy
OLD = m.BASELINE
NEW = 'b'*40
ID = '1'*32
OTHER = '2'*32


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.root_patch = patch.object(m, 'ROOT', self.root)
        self.root_patch.start()
        for directory in ('incoming', 'bin', 'releases', 'staging', 'state/rebuilt'):
            (self.root/directory).mkdir(parents=True)
        self.state = self.root/'state/rebuilt'
        self.state.chmod(0o700)
        self.manifest = hashlib.sha256(b'SELECT 1;').hexdigest()+'  database/migrations/001.sql\n'
        self.p = {'current_link': str(self.root/'current'), 'releases_dir': str(self.root/'releases'),
                  'schema_sha256': hashlib.sha256(self.manifest.encode()).hexdigest(),
                  'approved_artifacts': {}, 'rollback_targets': [OLD, NEW]}
        self.make(OLD)
        Path(self.p['current_link']).symlink_to(m.release_path(self.p, OLD))
        self.restart_count = 0
        self.restart_patch = patch.object(m, 'restart', side_effect=self.restart)
        self.restart_patch.start()
        # Any unmocked command is a test failure, so a regression cannot reach host services/DB.
        self.run_patch = patch.object(m, 'run', side_effect=AssertionError('real host command attempted'))
        self.run_patch.start()
        self.health_patch = patch.object(m, 'healthy', side_effect=lambda sha: m.current_sha(self.p) == sha)
        self.health_patch.start()

    def tearDown(self):
        self.health_patch.stop(); self.run_patch.stop(); self.restart_patch.stop(); self.root_patch.stop()
        self.tmp.cleanup()

    def restart(self):
        self.restart_count += 1

    def make(self, sha):
        target = m.release_path(self.p, sha)
        (target/'apps/web/build/server').mkdir(parents=True)
        (target/'node_modules').mkdir()
        (target/'database/migrations').mkdir(parents=True)
        (target/'database/migrations/001.sql').write_text('SELECT 1;')
        (target/'schema.sha256').write_text(self.manifest)
        (target/'RELEASE_SHA').write_text(sha)
        (target/'apps/web/build/server/index.js').write_text('')
        return target

    def publish(self, sha=NEW, opid=ID):
        return m.publish(self.p, self.state, 'rollback', sha, '', opid)

    def test_protocol_is_exact_and_has_no_legacy_fallback(self):
        for command in ('verify', 'status', 'status '+ID, 'resume '+ID, 'logs api', 'logs web',
                        'rollback '+NEW+' '+ID, 'deploy '+NEW+' '+'f'*64+' '+ID):
            self.assertEqual(m.parse('rebuilt-v1 '+command), command.split())
        for command in ('verify', 'rebuilt-v1 logs db', 'rebuilt-v1 status '+ID+'\n',
                        'rebuilt-v1 logs api;id', 'rebuilt-v1 rollback main '+ID,
                        'rebuilt-v1 ops-v1 diagnose', 'rebuilt-v1 resume ../../etc/passwd'):
            with self.assertRaises(m.Refused): m.parse(command)

    def test_upload_retry_compares_bytes_without_overwrite(self):
        digest = hashlib.sha256(b'fixture').hexdigest()
        m.upload(NEW, digest, io.BytesIO(b'fixture'))
        before = (self.root/'incoming'/ (NEW+'.tar.gz')).stat().st_ino
        m.upload(NEW, digest, io.BytesIO(b'fixture'))
        self.assertEqual(before, (self.root/'incoming'/ (NEW+'.tar.gz')).stat().st_ino)
        for data in (b'different', b''):
            with self.assertRaises(m.Refused):m.upload(NEW, digest, io.BytesIO(data))
        with patch.object(m, 'LIMIT', 3), self.assertRaises(m.Refused):
            m.upload('c'*40, digest, io.BytesIO(b'fixture'))
        self.assertEqual(list((self.root/'incoming').glob('.upload-*')), [])

    def test_cross_process_lock_refuses_duplicate_mutator(self):
        fd = m.lock(self.state)
        try:
            result = subprocess.run([sys.executable, '-c',
                'import fcntl,sys; f=open(sys.argv[1],"r+"); fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)',
                str(self.state/'release.lock')], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            with self.assertRaises(m.Refused):m.lock(self.state)
        finally:os.close(fd)
        os.close(m.lock(self.state))

    def test_completed_retry_does_not_restart_and_superseded_id_cannot_redeploy(self):
        self.make(NEW)
        self.assertEqual(self.publish()['phase'], 'succeeded')
        self.assertEqual(self.publish()['phase'], 'succeeded')
        self.assertEqual(self.restart_count, 1)
        self.assertEqual(self.publish(OLD, OTHER)['phase'], 'succeeded')
        with self.assertRaisesRegex(m.Refused, 'superseded'):self.publish()
        self.assertEqual(m.current_sha(self.p), OLD)

    def test_health_failure_restores_previous_and_remains_failure_on_retry(self):
        self.make(NEW)
        with patch.object(m, 'healthy', side_effect=lambda sha: sha == OLD):
            self.assertEqual(self.publish()['phase'], 'rolled_back')
            self.assertEqual(self.publish()['phase'], 'rolled_back')
        self.assertEqual(m.current_sha(self.p), OLD)
        self.assertEqual(self.restart_count, 2)

    def test_failed_rollback_blocks_subsequent_operations(self):
        self.make(NEW)
        with patch.object(m, 'healthy', side_effect=[True, False, False]):
            self.assertEqual(self.publish()['phase'], 'recovery_required')
        with self.assertRaisesRegex(m.Refused, 'unfinished'):self.publish(OLD, OTHER)

    def test_identity_schema_and_layout_fail_before_restart(self):
        target = self.make(NEW)
        (target/'database/migrations/001.sql').write_text('DROP TABLE dangerous;')
        with self.assertRaisesRegex(m.Refused, 'manifest'):self.publish()
        self.assertEqual(self.restart_count, 0)
        self.assertEqual(m.current_sha(self.p), OLD)
        Path(self.p['current_link']).unlink()
        Path(self.p['current_link']).mkdir()
        with self.assertRaises(m.Refused):m.current_sha(self.p)

    def test_interrupted_check_recovers_after_new_process_without_duplicate_restart(self):
        self.make(NEW)
        def interrupted_restart():raise KeyboardInterrupt()
        with patch.object(m, 'restart', side_effect=interrupted_restart), self.assertRaises(KeyboardInterrupt):
            self.publish()
        self.assertEqual(m.receipt(self.state, ID)['phase'], 'checking')
        self.assertEqual(self.publish()['phase'], 'succeeded')
        self.assertEqual(self.restart_count, 0)

    def test_interrupted_rollback_is_resumed_and_conflicting_id_blocked(self):
        self.make(NEW)
        with patch.object(m, 'healthy', side_effect=[True, False]), patch.object(m, 'restart', side_effect=[None, KeyboardInterrupt()]):
            with self.assertRaises(KeyboardInterrupt):self.publish()
        self.assertEqual(m.receipt(self.state, ID)['phase'], 'rolling_back')
        with self.assertRaisesRegex(m.Refused, 'unfinished'):self.publish(OLD, OTHER)
        self.assertEqual(self.publish()['phase'], 'rolled_back')
        with self.assertRaisesRegex(m.Refused, 'conflict'):self.publish(OLD, ID)

    def test_missing_baseline_or_healthy_baseline_cannot_be_bypassed(self):
        self.make(NEW)
        self.p['approved_artifacts'][NEW] = 'f'*64
        with patch.object(m, 'healthy', return_value=False), self.assertRaisesRegex(m.Refused, 'baseline'):
            m.publish(self.p, self.state, 'deploy', NEW, 'f'*64, ID)
        self.assertFalse((self.state/(ID+'.json')).exists())
        self.assertEqual(self.restart_count, 0)

    def test_deploy_uses_existing_reviewed_extractor_and_then_can_retry(self):
        # Real bounded tar extractor executes only against the temporary fixture.
        import tarfile
        target = self.make(NEW)
        archive = self.root/'incoming'/(NEW+'.tar.gz')
        with tarfile.open(archive, 'w:gz') as tar:tar.add(target, arcname='.')
        import shutil
        shutil.rmtree(target)
        digest = m.file_digest(archive)
        self.p['approved_artifacts'][NEW] = digest
        def extract(argv, **kw):
            self.assertEqual(argv[:3], ['/usr/bin/python3', '-I', '-B'])
            self.assertEqual(argv[3], str(self.root/'bin/extract-release.py'))
            result = subprocess.run([sys.executable, '-I', '-B', str(REPO/'deploy/native/extract-release.py'), *argv[4:]], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            return ''
        with patch.object(m, 'trusted'), patch.object(m, 'run', side_effect=extract):
            result = m.publish(self.p, self.state, 'deploy', NEW, digest, ID)
        self.assertEqual(result['phase'], 'succeeded')
        self.assertEqual(m.publish(self.p, self.state, 'deploy', NEW, digest, ID)['phase'], 'succeeded')
        self.assertEqual(self.restart_count, 1)

    def test_log_output_omits_secret_message_and_arbitrary_fields(self):
        row = {'_SYSTEMD_UNIT':m.UNITS['api'], '__REALTIME_TIMESTAMP':'123', 'PRIORITY':'3',
               'MESSAGE':'Bearer secret-canary password=do-not-print', '_CMDLINE':'also secret'}
        with patch.object(m, 'run', return_value=json.dumps(row)) as run:
            output = m.logs('api')
        self.assertNotIn('secret', json.dumps(output))
        self.assertEqual(output['entries'], [{'timestamp_us':'123', 'priority':3}])
        self.assertIn('--lines=50', run.call_args.args[0])
        row['_SYSTEMD_UNIT'] = 'ssh.service'
        with patch.object(m, 'run', return_value=json.dumps(row)), self.assertRaises(m.Refused):m.logs('api')
        with patch.object(m, 'run', side_effect=m.Refused('command_failed')), self.assertRaises(m.Refused):m.logs('web')

    def test_loopback_ports_required_and_wildcard_is_rejected(self):
        rows = '\n'.join('LISTEN 0 128 127.0.0.1:%d 0.0.0.0:*'%p for p in (3000,3001,55432))
        with patch.object(m, 'run', return_value=rows):m.listeners()
        for bad in (rows.replace('127.0.0.1:3000','0.0.0.0:3000'), rows.splitlines()[0]):
            with patch.object(m, 'run', return_value=bad), self.assertRaises(m.Refused):m.listeners()

    def test_policy_template_is_disabled_and_changed_unit_is_rejected(self):
        path = self.root/'policy.json'
        template = json.loads((REPO/'deploy/native/rebuilt-policy.example.json').read_text())
        path.write_text(json.dumps(template))
        with patch.object(m, 'POLICY', path), patch.object(m, 'trusted'), self.assertRaisesRegex(m.Refused, 'accepted'):
            m.policy()
        (self.root/'switch').mkdir()
        template.update(self.p, accepted=True, node='/usr/local/bin/node', current_link=str(self.root/'switch/current'))
        template['database']['verified'] = True
        template['helpers_sha256'] = {}
        for name in ('rebuilt-gateway.py', 'extract-release.py', 'rebuilt-launch.py'):
            helper = self.root/'bin'/name; helper.write_text('fixture')
            template['helpers_sha256'][str(helper)] = hashlib.sha256(b'fixture').hexdigest()
        for alias in m.UNITS:
            template['units'][alias] = dict.fromkeys(m.PROPERTIES, '')
            template['units'][alias].update(HOME='/opt/aifinance', files_sha256={})
            template['units'][alias]['ExecStart'] = {'path':'/usr/bin/python3','argv':['/usr/bin/python3','-I','-B',str(self.root/'bin/rebuilt-launch.py'),alias]}
            template['units'][alias].update(User='aifinance-deploy', WorkingDirectory=template['current_link'], FragmentPath='/etc/systemd/system/'+m.UNITS[alias])
        path.write_text(json.dumps(template))
        actual = copy.deepcopy(template['units']['api']);actual['User'] = 'root'
        with patch.object(m, 'POLICY', path), patch.object(m, 'trusted'), patch.object(m, 'unit_snapshot', return_value=actual), self.assertRaisesRegex(m.Refused, 'unit_changed'):
            m.policy()
        def expected_properties(unit):
            return template['units'][next(alias for alias, name in m.UNITS.items() if name == unit)]
        # Diagnosis and a pending rollback must not be gated on a running API.
        with patch.object(m, 'POLICY', path), patch.object(m, 'trusted'), patch.object(m, 'unit_snapshot', side_effect=expected_properties), patch.object(m, 'run', return_value='v24.19.0\n'), patch.object(m, 'listeners', side_effect=AssertionError('live health in policy')):
            self.assertTrue(m.policy()['accepted'])
            for key, bad in (('current_link', str(self.root/'current')), ('releases_dir', str(self.root/'releases-v2'))):
                correct = template[key]
                template[key] = bad; path.write_text(json.dumps(template))
                with self.assertRaisesRegex(m.Refused, 'launcher_layout_mismatch'): m.policy()
                template[key] = correct; path.write_text(json.dumps(template))
            template['version'] = 1; path.write_text(json.dumps(template))
            with self.assertRaisesRegex(m.Refused, 'layout_not_accepted'): m.policy()
            template['version'] = 2; path.write_text(json.dumps(template))
            (self.root/'bin/rebuilt-launch.py').write_text('changed')
            with self.assertRaisesRegex(m.Refused, 'helper_changed'): m.policy()

    def test_command_wrapper_limits_output_and_never_echoes_failed_stderr(self):
        self.assertEqual(REAL_RUN([sys.executable, '-c', 'print("ok")']), 'ok\n')
        with self.assertRaisesRegex(m.Refused, 'output_limit'):
            REAL_RUN([sys.executable, '-c', 'print("x"*5000)'], limit=100)
        with self.assertRaisesRegex(m.Refused, '^command_failed$'):
            REAL_RUN([sys.executable, '-c', 'import sys;sys.stderr.write("secret-canary");sys.exit(1)'])
        with self.assertRaisesRegex(m.Refused, 'timeout'):
            REAL_RUN([sys.executable, '-c', 'import time;time.sleep(2)'], timeout=.05)

    def test_health_checks_sha_and_fixed_endpoints_without_real_network(self):
        def command(argv, **kwargs):
            if argv[0] == '/usr/bin/systemctl':
                self.assertEqual(argv[1:], ['is-active','--quiet',*m.UNITS.values()])
                return ''
            self.assertEqual(argv[0], '/usr/bin/curl')
            self.assertIn('--noproxy', argv)
            self.assertIn(argv[-1], ('http://127.0.0.1:3001/api/health','http://127.0.0.1:3000/'))
            return json.dumps({'ok':True,'db':'ok','release':NEW}) if argv[-1].endswith('health') else ''
        with patch.object(m, 'listeners'), patch.object(m, 'run', side_effect=command), patch.object(m.time, 'sleep'):
            self.assertTrue(REAL_HEALTH(NEW))
            self.assertFalse(REAL_HEALTH(OLD))

    def test_symlink_upload_target_cannot_be_reused(self):
        target = self.root/'incoming'/(NEW+'.tar.gz')
        other = self.root/'other'
        other.write_bytes(b'fixture')
        target.symlink_to(other)
        with self.assertRaises(OSError):m.upload(NEW, hashlib.sha256(b'fixture').hexdigest(), io.BytesIO(b'fixture'))
        self.assertTrue(target.is_symlink())

    def test_rebuilt_workflow_is_manual_pinned_and_credential_separated(self):
        text = (REPO/'.github/workflows/deploy-rebuilt.yml').read_text()
        self.assertIn('workflow_dispatch:', text)
        self.assertNotIn('  push:', text)
        self.assertIn('StrictHostKeyChecking=yes', text)
        self.assertIn('environment: aifinance-preview', text)
        access = text.split('  access:',1)[1]
        self.assertNotIn('actions/checkout', access)
        self.assertNotIn('ops-v1', access)
        self.assertIn('rebuilt-v1 $*', access)
        self.assertIn('remote resume "$OPERATION_ID"', access)
        self.assertIn('git merge-base --is-ancestor', text)

    def test_metadata_symlink_is_never_read(self):
        secret = self.root/'do-not-read'
        secret.write_text('secret')
        (self.state/(ID+'.json')).symlink_to(secret)
        with self.assertRaises(OSError):m.receipt(self.state, ID)

    def test_nonobject_health_response_triggers_rollback(self):
        self.make(NEW)
        def health(sha):
            return True if sha == OLD else REAL_HEALTH(sha)
        def command(argv, **kwargs):
            return '[]' if argv[-1].endswith('/api/health') else ''
        with patch.object(m, 'healthy', side_effect=health), patch.object(m, 'listeners'), patch.object(m, 'run', side_effect=command), patch.object(m.time, 'sleep'):
            self.assertEqual(self.publish()['phase'], 'rolled_back')
        self.assertEqual(m.current_sha(self.p), OLD)

    def test_closed_stdout_but_running_child_is_a_controlled_timeout(self):
        with self.assertRaisesRegex(m.Refused, '^command_timeout$'):
            REAL_RUN([sys.executable, '-c', 'import os,time;os.close(1);time.sleep(2)'], timeout=.05)

    def test_missing_new_release_during_interrupted_check_restores_old(self):
        target = self.make(NEW)
        with patch.object(m, 'restart', side_effect=KeyboardInterrupt()), self.assertRaises(KeyboardInterrupt):
            self.publish()
        import shutil
        shutil.rmtree(target)
        self.assertEqual(self.publish()['phase'], 'rolled_back')
        self.assertEqual(m.current_sha(self.p), OLD)

    def test_damaged_new_release_does_not_block_pending_rollback(self):
        target = self.make(NEW)
        with patch.object(m, 'healthy', side_effect=[True, False]), patch.object(m, 'restart', side_effect=[None, KeyboardInterrupt()]):
            with self.assertRaises(KeyboardInterrupt):self.publish()
        (target/'schema.sha256').write_text('damaged')
        self.assertEqual(self.publish()['phase'], 'rolled_back')
        self.assertEqual(m.current_sha(self.p), OLD)

    def test_dangling_state_links_are_not_treated_as_absent(self):
        self.make(NEW)
        for name in ('active.json', ID+'.json'):
            link = self.state/name
            link.symlink_to(self.root/'missing')
            try:
                with self.assertRaises(OSError):self.publish()
                self.assertTrue(link.is_symlink())
                self.assertEqual(self.restart_count, 0)
            finally:link.unlink()

    def test_switch_preserves_replaced_file_or_unrelated_release(self):
        self.make(NEW)
        current = Path(self.p['current_link'])
        current.unlink();current.write_text('preserve')
        with self.assertRaises(m.Refused):m.switch(self.p, NEW, ID, OLD)
        self.assertEqual(current.read_text(), 'preserve')
        current.unlink()
        other = 'c'*40
        current.symlink_to(self.make(other))
        with self.assertRaises(m.Refused):m.switch(self.p, NEW, ID, OLD)
        self.assertEqual(m.current_sha(self.p), other)

    def test_nonregular_hardlinked_or_writable_lock_is_refused(self):
        path = self.state/'release.lock'
        os.mkfifo(path, 0o600)
        with self.assertRaisesRegex(m.Refused, 'invalid_lock'):m.lock(self.state)
        path.unlink()
        path.write_text('');path.chmod(0o660)
        with self.assertRaisesRegex(m.Refused, 'invalid_lock'):m.lock(self.state)
        path.chmod(0o600)
        os.link(path, self.state/'other-lock')
        with self.assertRaisesRegex(m.Refused, 'invalid_lock'):m.lock(self.state)

    def test_migration_directory_and_build_symlinks_cannot_escape(self):
        target = self.make(NEW)
        migrations = target/'database/migrations'
        outside = self.root/'external-migrations'
        migrations.rename(outside);migrations.symlink_to(outside)
        with self.assertRaisesRegex(m.Refused, 'migration_directory_symlink'):m.validate_release(self.p, NEW)
        migrations.unlink();outside.rename(migrations)
        entry = target/'apps/web/build/server/index.js'
        entry.unlink();entry.symlink_to(self.root/'external-code')
        (self.root/'external-code').write_text('untrusted')
        with self.assertRaisesRegex(m.Refused, 'release_build_escape'):m.validate_release(self.p, NEW)

    def test_effective_root_and_insecure_state_are_denied(self):
        previous_umask = os.umask(0o077)
        try:
            with patch.dict(os.environ, {'SSH_ORIGINAL_COMMAND':'rebuilt-v1 verify'}, clear=True), patch.object(m.os, 'getuid', return_value=1000), patch.object(m.os, 'geteuid', return_value=0), patch.object(m, 'policy', side_effect=AssertionError('policy read')):
                with self.assertRaisesRegex(m.Refused, 'wrong_user'):m.main()
        finally:os.umask(previous_umask)
        self.state.chmod(0o770)
        with self.assertRaisesRegex(m.Refused, 'state_permissions'):m.state_dir()
        with self.assertRaisesRegex(m.Refused, 'not_absolute'):m.trusted(Path('node'))

    def test_successful_retry_rechecks_schema_integrity(self):
        target = self.make(NEW)
        self.assertEqual(self.publish()['phase'], 'succeeded')
        (target/'database/migrations/001.sql').write_text('changed')
        with self.assertRaisesRegex(m.Refused, 'manifest'):self.publish()
        self.assertEqual(self.restart_count, 1)

    def test_running_systemd_job_blocks_resume_without_cancelling_it(self):
        with patch.object(m, 'run', return_value=''):m.services_idle()
        with patch.object(m, 'run', return_value='12 unrelated.service start running\n'):m.services_idle()
        for unit in m.UNITS.values():
            with patch.object(m, 'run', return_value='12 '+unit+' restart running\n'), self.assertRaisesRegex(m.Refused, 'service_job_pending'):
                m.services_idle()
        with patch.object(m, 'run', return_value='unknown format'), self.assertRaisesRegex(m.Refused, 'job_metadata_invalid'):
            m.services_idle()

    def test_interruption_preserves_recoverable_phase(self):
        self.make(NEW)
        with patch.object(m, 'restart', side_effect=m.Interrupted()), self.assertRaises(m.Interrupted):
            self.publish()
        self.assertEqual(m.receipt(self.state, ID)['phase'], 'checking')
        self.assertEqual(self.publish()['phase'], 'succeeded')

    def test_unhealthy_current_can_rollback_to_approved_target_and_retry(self):
        self.make(NEW)
        with patch.object(m, 'healthy', side_effect=lambda sha: sha == NEW):
            self.assertEqual(self.publish()['phase'], 'succeeded')
            self.assertFalse(m.receipt(self.state, ID)['fallback_allowed'])
            self.assertEqual(self.publish()['phase'], 'succeeded')
        self.assertEqual(self.restart_count, 1)

    def test_failed_emergency_rollback_never_returns_to_known_broken_current(self):
        self.make(NEW)
        with patch.object(m, 'healthy', return_value=False):
            self.assertEqual(self.publish()['phase'], 'recovery_required')
        self.assertEqual(m.current_sha(self.p), NEW)
        self.assertEqual(self.restart_count, 1)
        self.assertEqual(self.publish()['phase'], 'recovery_required')
        with self.assertRaisesRegex(m.Refused, 'unfinished'): self.publish(OLD, OTHER)

    def test_emergency_rollback_interruption_resumes_without_broken_source(self):
        self.make(NEW)
        with patch.object(m, 'healthy', return_value=False), patch.object(m, 'restart', side_effect=m.Interrupted):
            with self.assertRaises(m.Interrupted): self.publish()
        (m.release_path(self.p, OLD)/'schema.sha256').write_text('broken')
        self.assertEqual(self.publish()['phase'], 'succeeded')

    def test_unapproved_target_or_digest_never_creates_receipt(self):
        self.make(NEW)
        self.p['rollback_targets'] = [OLD]
        with self.assertRaisesRegex(m.Refused, 'rollback_not_approved'): self.publish()
        self.p['approved_artifacts'][NEW] = 'a'*64
        with self.assertRaisesRegex(m.Refused, 'artifact_not_approved'):
            m.publish(self.p, self.state, 'deploy', NEW, 'b'*64, ID)
        self.assertFalse((self.state/(ID+'.json')).exists())
        self.assertEqual(self.restart_count, 0)

    def test_revoked_rollback_during_resume_refuses_switch(self):
        self.make(NEW)
        with patch.object(m, 'restart', side_effect=m.Interrupted):
            with self.assertRaises(m.Interrupted): self.publish()
        self.p['rollback_targets'] = [OLD]
        self.assertEqual(self.publish()['phase'], 'rolled_back')
        self.assertEqual(m.current_sha(self.p), OLD)

    def test_health_rejects_missing_or_bad_database_status(self):
        for db in (None, 'error', False):
            with patch.object(m, 'listeners'), patch.object(m, 'run', return_value=json.dumps({'ok':True,'release':NEW,'db':db})), patch.object(m.time, 'sleep'):
                self.assertFalse(REAL_HEALTH(NEW))

    def test_unit_snapshot_ignores_runtime_fields_but_detects_config_and_home(self):
        unit = self.root/'api.service'; unit.write_text('[Service]\n')
        drop = self.root/'90-home-compat.conf'; drop.write_text('[Service]\nEnvironment="HOME=/opt/aifinance"\n')
        props = dict.fromkeys(m.PROPERTIES, '')
        props.update(FragmentPath=str(unit), DropInPaths=str(drop), ExecStart='{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -I -B /opt/aifinance/bin/rebuilt-launch.py api ; ignore_errors=no ; pid=1 ; start_time=old }')
        with patch.object(m, 'trusted'), patch.object(m, 'properties', side_effect=lambda _: dict(props)), patch.object(m, 'run', return_value='HOME=/opt/aifinance SECRET=not-output'):
            before = m.unit_snapshot('fixture')
            self.assertNotIn('SECRET', json.dumps(before))
            props['ExecStart'] = props['ExecStart'].replace('pid=1', 'pid=2').replace('start_time=old', 'start_time=new')
            self.assertEqual(before, m.unit_snapshot('fixture'))
            drop.write_text('[Service]\nEnvironment="HOME=/tmp"\n')
            self.assertNotEqual(before, m.unit_snapshot('fixture'))
            props['ExecStart'] = props['ExecStart'].replace(' api ', ' web ')
            self.assertNotEqual(before['ExecStart'], m.unit_snapshot('fixture')['ExecStart'])
            with patch.object(m, 'run', return_value='HOME=/tmp'), self.assertRaisesRegex(m.Refused, 'unit_home'): m.unit_snapshot('fixture')
            with patch.object(m, 'trusted', side_effect=m.Refused('untrusted')), self.assertRaises(m.Refused): m.unit_snapshot('fixture')
            props['ExecStart'] += ' { path=/bin/sh ; argv[]=/bin/sh ; ignore_errors=no ; pid=0 }'
            with self.assertRaisesRegex(m.Refused, 'unit_exec_format'): m.unit_snapshot('fixture')

    def test_old_or_malformed_receipt_fails_closed(self):
        self.make(NEW); self.publish()
        value = m.receipt(self.state, ID)
        for bad in (None, 'true', 1):
            changed = dict(value, fallback_allowed=bad)
            m.atomic(self.state/(ID+'.json'), changed)
            with self.assertRaisesRegex(m.Refused, 'receipt_invalid'): self.publish()
        value.pop('fallback_allowed'); m.atomic(self.state/(ID+'.json'), value)
        with self.assertRaisesRegex(m.Refused, 'receipt_invalid'): self.publish()

    def test_damaged_current_with_healthy_http_does_not_block_emergency_rollback(self):
        self.make(NEW)
        (m.release_path(self.p, OLD)/'schema.sha256').write_text('broken')
        self.assertEqual(self.publish()['phase'], 'succeeded')
        self.assertFalse(m.receipt(self.state, ID)['fallback_allowed'])

    def test_upload_main_refuses_unapproved_bytes_before_reading_stream(self):
        import types
        before = os.umask(0o077)
        try:
            with patch.dict(os.environ, {'SSH_ORIGINAL_COMMAND':'rebuilt-v1 upload '+NEW+' '+'a'*64}, clear=True), patch.object(m.os,'getuid',return_value=999), patch.object(m.os,'geteuid',return_value=999), patch.object(m.pwd,'getpwuid',return_value=types.SimpleNamespace(pw_name='aifinance-deploy')), patch.object(m,'policy',return_value=self.p), patch.object(m,'state_dir',return_value=self.state), patch.object(m,'lock',return_value=os.open(os.devnull,os.O_RDONLY)), patch.object(m,'upload',side_effect=AssertionError('upload entered')):
                with self.assertRaisesRegex(m.Refused, 'artifact_not_approved'):m.main()
        finally:os.umask(before)

    def test_non_utf8_current_marker_does_not_block_emergency_rollback(self):
        self.make(NEW)
        (m.release_path(self.p, OLD)/'RELEASE_SHA').write_bytes(b'\xff')
        self.assertEqual(self.publish()['phase'], 'succeeded')
        self.assertFalse(m.receipt(self.state, ID)['fallback_allowed'])
        self.assertEqual(m.current_sha(self.p), NEW)

    def test_non_utf8_new_marker_on_resume_restores_previous(self):
        self.make(NEW)
        with patch.object(m, 'restart', side_effect=m.Interrupted):
            with self.assertRaises(m.Interrupted): self.publish()
        self.assertEqual(m.receipt(self.state, ID)['phase'], 'checking')
        (m.release_path(self.p, NEW)/'RELEASE_SHA').write_bytes(b'\xff')
        self.assertEqual(self.publish()['phase'], 'rolled_back')
        self.assertEqual(m.current_sha(self.p), OLD)


if __name__ == '__main__':
    unittest.main()
