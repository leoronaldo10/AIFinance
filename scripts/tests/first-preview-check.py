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
from types import SimpleNamespace
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('first', str(REPO / 'deploy/native/first-preview.py'))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
SHA = 'a' * 40
DIGEST = 'b' * 64


class FirstPreview(unittest.TestCase):
    def test_root_health_never_follows_redirects(self):
        from urllib.request import Request
        for address in ('http://outside.example/', 'http://127.0.0.1:8000/', 'https://outside.example/'):
            with self.assertRaises(ValueError):
                m.NoRedirect().redirect_request(Request('http://127.0.0.1:3100/'), None, 302, 'Found', {}, address)

    def test_actual_memory_cgroup_and_process_privilege_evidence(self):
        def prop(unit, name): return '123'
        def read(path, *args, **kw):
            path = str(path)
            if path.endswith('/status'):
                return 'Uid: 1007 1007 1007 1007\nNoNewPrivs: 1\nCapEff: 0000000000000000\n'
            if path.endswith('/cgroup'):
                return '4:memory:/system.slice/aifinance-preview-api.service\n'
            if path.endswith('/cgroup.procs'): return '123\n'
            if path.endswith('memory.limit_in_bytes'): return str(320 * 1024 ** 2)
            return '0'
        # API accepted; second service deliberately mismatches fixed cgroup path.
        with patch.object(m, 'property_value', side_effect=prop), patch.object(m.Path, 'read_text', read), patch.object(m.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=1007)):
            with self.assertRaisesRegex(ValueError, 'expected_v1_memory_cgroup'):
                m.resource_evidence()
        for uid, nnp, cap in (('0 0 0 0', '1', '0'), ('1007 1007 1007 1007', '0', '0'), ('1007 1007 1007 1007', '1', '1')):
            with patch.object(m, 'property_value', return_value='123'), patch.object(m.Path, 'read_text', return_value='Uid: '+uid+'\nNoNewPrivs: '+nnp+'\nCapEff: '+cap+'\n'), patch.object(m.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=1007)):
                with self.assertRaisesRegex(ValueError, 'identity_or_privileges'):
                    m.resource_evidence()

    def test_all_three_kernel_limits_and_pid_stability(self):
        budgets = {'api': 320, 'web': 256, 'db': 256}
        pids = {'api': '101', 'web': '102', 'db': '103'}
        roles = {value: key for key, value in pids.items()}
        def props(unit, name): return pids[unit.split('-')[2].split('.')[0]]
        def read(path, *args, **kw):
            text = str(path)
            if text.startswith('/proc/'):
                pid = text.split('/')[2]; role = roles[pid]; uid = '26' if role == 'db' else '1007'
                if text.endswith('/status'): return 'Uid: '+(' '.join([uid]*4))+'\nNoNewPrivs: 1\nCapEff: 0\n'
                return '4:memory:/system.slice/aifinance-preview-'+role+'.service\n'
            role = text.split('aifinance-preview-')[1].split('.')[0]
            if text.endswith('cgroup.procs'): return pids[role]
            if text.endswith('memory.limit_in_bytes'): return str(budgets[role]*1024**2)
            return '0'
        account = lambda name: SimpleNamespace(pw_uid=26 if name == 'postgres' else 1007)
        with patch.object(m, 'property_value', side_effect=props), patch.object(m.Path, 'read_text', read), patch.object(m.pwd, 'getpwnam', side_effect=account):
            self.assertEqual(set(m.resource_evidence()), {'api', 'web', 'db'})
            def failcnt(path, *args, **kw): return '1' if str(path).endswith('memory.failcnt') else read(path)
            with patch.object(m.Path, 'read_text', failcnt), self.assertRaisesRegex(ValueError, 'limit_not_enforced_or_hit'):
                m.resource_evidence()
            with patch.object(m, 'property_value', side_effect=['101', '999']), self.assertRaisesRegex(ValueError, 'restarted'):
                m.resource_evidence()

    def test_app_sql_uses_real_app_login_drops_uid_and_bounds_output(self):
        configuration = ('DATABASE_URL=postgres://aifinance_preview:'+'d'*64+'@127.0.0.1:55432/aifinance_preview\n'
                         'SITE_URL=http://127.0.0.1:3100\nADMIN_PASSWORD=public-fixture-password\n'
                         'SESSION_SECRET='+'s'*64+'\nIMG_PROXY_SIGN_SECRET='+'i'*64+'\n')
        actual = subprocess.Popen
        captured = []
        for output, success in (('0001_core.sql', True), ('x'*40000, False)):
            def run(args, **kw):
                captured.append((args, kw))
                # Real pipe/selector/length handling, fixed public fixture only;
                # UID changes are asserted separately, never applied on this host.
                local = dict(kw); local.pop('preexec_fn')
                return actual([sys.executable, '-c', 'print('+repr(output)+')'], **local)
            with patch.object(m, 'BIN', REPO/'deploy/native'), patch.object(m, 'trusted'), patch.object(m, 'text_file', return_value=configuration), patch.object(m.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=1007,pw_gid=1007)), patch.object(m.subprocess, 'Popen', side_effect=run):
                if success: self.assertEqual(m.query('SELECT fixed_fixture', app=True), output)
                else:
                    with self.assertRaisesRegex(ValueError, 'output_limit'): m.query('SELECT fixed_fixture', app=True)
            args, kw = captured[-1]
            self.assertEqual(args[args.index('-U')+1], 'aifinance_preview')
            self.assertNotIn('d'*64, repr(args))
            self.assertEqual(kw['env']['PGPASSWORD'], 'd'*64)
            with patch.object(m.os, 'setgroups') as groups, patch.object(m.os, 'setgid') as gid, patch.object(m.os, 'setuid') as uid:
                kw['preexec_fn']()
                groups.assert_called_once_with([]); gid.assert_called_once_with(1007); uid.assert_called_once_with(1007)

    def test_nonobject_health_json_is_a_controlled_failure(self):
        class Response:
            def __enter__(self): return self
            def __exit__(self, *a): pass
            def read(self, size): return b'null'
        with patch.object(m, 'property_value', return_value='active'), patch.object(m, 'build_opener', return_value=SimpleNamespace(open=lambda *a, **kw: Response())), patch.object(m.time, 'sleep'):
            with self.assertRaisesRegex(ValueError, 'health_failed'): m.health(SHA)

    def test_schema_checks_real_digest_and_full_manifest(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d); (p / 'database/migrations').mkdir(parents=True)
            sql = p / 'database/migrations/0001_core.sql'; sql.write_text('SELECT 1;\n')
            manifest = hashlib.sha256(sql.read_bytes()).hexdigest() + '  database/migrations/0001_core.sql\n'
            (p / 'schema.sha256').write_text(manifest)
            self.assertEqual(m.schema(p), (manifest, ['0001_core.sql']))
            sql.write_text('SELECT 2;\n')
            with self.assertRaises(ValueError): m.schema(p)
            sql.unlink(); sql.symlink_to(p / 'schema.sha256')
            with self.assertRaises(OSError): m.schema(p)

    def test_schema_rejects_missing_extra_and_escape(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d); (p / 'database/migrations').mkdir(parents=True)
            (p / 'schema.sha256').write_text(DIGEST + '  ../../etc/shadow\n')
            with self.assertRaises(ValueError): m.schema(p)
            (p / 'schema.sha256').write_text('')
            with self.assertRaises(ValueError): m.schema(p)

    def test_stage_root_is_rejected_before_archive_read(self):
        with patch.object(m.os, 'geteuid', return_value=0), patch.object(m.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=1002)), patch.object(m.os, 'open') as opened:
            with self.assertRaises(ValueError): m.stage(SHA, DIGEST)
            opened.assert_not_called()

    def test_no_existing_release_or_current_is_adopted(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d); (p / 'state').mkdir(); (p / 'releases').mkdir(); (p / 'state/current').symlink_to('/missing')
            with patch.object(m, 'ROOT', p), patch.object(m.os, 'geteuid', return_value=1002), patch.object(m.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=1002)), patch.object(m.os, 'open') as opened:
                with self.assertRaises(ValueError): m.stage(SHA, DIGEST)
                opened.assert_not_called()

    def test_migration_uses_existing_runtime_uid_and_confined_transient(self):
        for role in ('migrate', 'seed-topics'):
            with patch.object(m, 'property_value', return_value='not-found'), patch.object(m, 'call') as call:
                m.setup_role(role)
                args = call.call_args[0][0]
                for expected in ('--wait', '--collect', '--property=User=aifinance', '--property=Group=aifinance', '--property=MemoryLimit=320M', '--property=NoNewPrivileges=yes', '--property=CapabilityBoundingSet=', '--property=BindsTo=aifinance-preview-egress.service', '--property=StandardOutput=null', '--property=StandardError=null'):
                    self.assertIn(expected, args)
                self.assertEqual(args[-1], role)
                self.assertNotIn('root', args)
        with self.assertRaises(ValueError): m.setup_role('worker')

    def test_existing_transient_is_never_stopped(self):
        with patch.object(m, 'property_value', return_value='loaded'), patch.object(m, 'call') as call:
            with self.assertRaises(ValueError): m.setup_role('migrate')
            call.assert_not_called()

    def test_failed_transient_only_stops_exact_new_setup(self):
        with patch.object(m, 'property_value', return_value='not-found'), patch.object(m, 'call', side_effect=[None, subprocess.TimeoutExpired('fixture', 1), None]) as call:
            with self.assertRaises(subprocess.TimeoutExpired): m.setup_role('migrate')
            self.assertEqual(call.call_args_list[-1][0][0], [m.SYSTEMCTL, 'stop', 'aifinance-preview-migrate.service'])

    def test_database_requires_exact_migrations_extension_and_safe_role(self):
        with patch.object(m, 'query', side_effect=['0001_core.sql', 'aifinance_preview|t|t']) as query:
            m.database_accepted(['0001_core.sql'])
            self.assertTrue(query.call_args_list[0][1]['app'])
            self.assertIn('public.schema_migrations', query.call_args_list[0][0][0])
        for result in ('aifinance_preview|f|t', 'aifinance_preview|t|f', 'postgres|t|t'):
            with patch.object(m, 'query', side_effect=['0001_core.sql', result]):
                with self.assertRaises(ValueError): m.database_accepted(['0001_core.sql'])
        with patch.object(m, 'query', return_value='other.sql'):
            with self.assertRaises(ValueError): m.database_accepted(['0001_core.sql'])

    def test_first_failure_stops_only_new_preview_services_keeps_database_and_no_ready(self):
        with patch.object(m, 'preflight', return_value=[('old', '8000')]), patch.object(m, 'call', side_effect=[ValueError('fixture'), None]) as call, patch.object(m, 'health') as health:
            with self.assertRaises(ValueError): m.activate(SHA, DIGEST)
            self.assertEqual(call.call_args_list[0][0][0][2], 'aifinance-deploy')
            self.assertEqual(call.call_args_list[-1][0][0], [m.SYSTEMCTL, 'stop'] + m.APP_UNITS + [m.DB_UNIT])
            health.assert_not_called()
            joined = repr(call.call_args_list)
            for bad in ('8000', 'delete', 'rm ', 'native-ready', 'firewalld', 'postgresql-17.service'): self.assertNotIn(bad, joined)

    def test_preflight_failure_does_not_stop_any_service(self):
        with patch.object(m, 'preflight', side_effect=ValueError('existing')), patch.object(m, 'call') as call:
            with self.assertRaises(ValueError): m.activate(SHA, DIGEST)
            call.assert_not_called()

    def test_success_marks_schema_but_never_native_ready(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d); (p / 'shared').mkdir()
            before = [('old', '8000')]
            ports = {'8000': before, '3100': [('0100007F', '1')], '3101': [('0100007F', '2')], '55432': [('0100007F', '3')]}
            with patch.object(m, 'ROOT', p), patch.object(m, 'preflight', return_value=before), patch.object(m, 'schema', return_value=('schema-fixture', ['0001_core.sql'])), patch.object(m, 'query', return_value='0'), patch.object(m, 'setup_role') as setup, patch.object(m, 'database_accepted'), patch.object(m, 'health'), patch.object(m, 'resource_evidence', return_value={}), patch.object(m, 'listeners', return_value=ports), patch.object(m, 'call') as call, patch('sys.stdout', new_callable=io.StringIO) as out:
                m.activate(SHA, DIGEST)
                self.assertEqual([c[0][0] for c in setup.call_args_list], ['migrate', 'seed-topics'])
                self.assertFalse(json.loads(out.getvalue())['native_ready_written'])
                self.assertEqual((p / 'shared/schema.sha256').read_text(), 'schema-fixture')
                self.assertFalse((p / 'shared/native-ready').exists())
                self.assertFalse(any(c[0][0][1] == 'stop' for c in call.call_args_list))

    def test_occupied_or_public_port_and_old_8000_change_fail(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d); (p / 'shared').mkdir()
            ports = {'8000': [('changed', '8000')], '3100': [('00000000', '1')], '3101': [('0100007F', '2')], '55432': [('0100007F', '3')]}
            with patch.object(m, 'ROOT', p), patch.object(m, 'preflight', return_value=[('old', '8000')]), patch.object(m, 'schema', return_value=('manifest', ['0001_core.sql'])), patch.object(m, 'query', return_value='0'), patch.object(m, 'setup_role'), patch.object(m, 'database_accepted'), patch.object(m, 'health'), patch.object(m, 'resource_evidence', return_value={}), patch.object(m, 'listeners', return_value=ports), patch.object(m, 'call') as call:
                with self.assertRaises(ValueError): m.activate(SHA, DIGEST)
                self.assertEqual(call.call_args_list[-1][0][0], [m.SYSTEMCTL, 'stop'] + m.APP_UNITS + [m.DB_UNIT])
                self.assertFalse((p / 'shared/schema.sha256').exists())

    def test_existing_database_never_migrated(self):
        with patch.object(m, 'preflight', return_value=[]), patch.object(m, 'call'), patch.object(m, 'schema', return_value=('manifest', [])), patch.object(m, 'query', return_value='1'), patch.object(m, 'setup_role') as setup:
            with self.assertRaises(ValueError): m.activate(SHA, DIGEST)
            setup.assert_not_called()


if __name__ == '__main__': unittest.main()
