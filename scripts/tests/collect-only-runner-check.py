#!/usr/bin/python3
"""Offline fixtures only: never systemctl, useradd, DNS, nft, DB or live env."""
import ast
import copy
import hashlib
from contextlib import ExitStack
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('collector_runner', str(REPO / 'deploy/native/collect-only-runner.py'))
m = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(m)
USER = SimpleNamespace(pw_uid=990, pw_gid=990, pw_name='aifinance-collect', pw_shell='/sbin/nologin', pw_dir='/nonexistent')
HOSTS = {m.urlsplit(url).hostname: ['8.8.4.4'] for url in m.FEEDS.values()}
URL = 'postgres://aifinance_preview:public-fixture-password@127.0.0.1:55432/aifinance_preview'


def snapshot(seeded=True):
    return dict(checkOnly=True, readyForApply=False, database='aifinance_preview', migrations=['0041_collect_only.sql'],
        columns=[dict(table_name=table, column_name='collect_only', column_default='false', is_nullable='NO') for table in ('articles', 'sources')],
        constraints=[dict(conname='collect_only_source_isolation', convalidated=True)],
        sources=[dict(id=key, kind='rss', enabled=False, participation_mode='isolated', site_fulltext=False,
                      syndicate_fulltext=False, collect_only='true') for key in sorted(m.FEEDS)] if seeded else [],
        rawStates=[], counts={key: 0 for key in ('articles', 'article_revisions') + m.ZERO_TABLES})


def rows():
    return [dict(sourceId=key, found=10, processed=1, created=1, revised=0) for key in sorted(m.FEEDS)]


class CollectorFixtures(unittest.TestCase):
    def test_python36_syntax_and_source_pins(self):
        source = (REPO / 'deploy/native/collect-only-runner.py').read_text()
        ast.parse(source, **({'feature_version': (3, 6)} if sys.version_info >= (3, 8) else {}))
        for path, digest in m.PINS.items():
            self.assertEqual(hashlib.sha256((REPO / path).read_bytes()).hexdigest(), digest)

    def test_db_only_exact_identity_no_extra_config(self):
        self.assertEqual(m.database_url('DATABASE_URL=' + URL + '\n'), URL)
        for bad in ('DATABASE_URL=' + URL + '\nNODE_OPTIONS=--inspect\n',
                    'DATABASE_URL=' + URL + '\nADMIN_PASSWORD=x\n',
                    'DATABASE_URL=' + URL + '\nDATABASE_URL=' + URL,
                    'DATABASE_URL=' + URL.replace('127.0.0.1', 'localhost'),
                    'DATABASE_URL=' + URL.replace('55432', '5432'),
                    'DATABASE_URL=' + URL + '?sslmode=disable',
                    'DATABASE_URL=' + URL + ' ', 'OTHER=' + URL):
            with self.assertRaises(ValueError): m.database_url(bad)

    def test_environment_rebuilt_without_injection_or_credentials(self):
        file_stat = SimpleNamespace(st_mode=0o440, st_gid=990)
        directory_stat = SimpleNamespace(st_mode=0o750, st_gid=990)
        def st(path): return directory_stat if path == m.CONFIG else file_stat
        with patch.object(m, 'account', return_value=USER), patch.object(m, 'trusted'), patch.object(m, 'read', return_value='DATABASE_URL=' + URL), patch.object(m.Path, 'stat', st), patch.dict(m.os.environ, {'NODE_OPTIONS':'bad', 'HTTPS_PROXY':'bad', 'ADMIN_PASSWORD':'bad', 'OPENAI_API_KEY':'bad'}):
            env = m.db_environment()
        self.assertEqual(env['DATABASE_URL'], URL)
        self.assertEqual(env['MODEL_CALLS_ENABLED'], 'false')
        self.assertEqual(env['COLLECT_ENABLED'], 'false')
        self.assertEqual(env['ALLOW_PRIVATE_NETWORK_FETCH'], 'false')
        for key in ('NODE_OPTIONS', 'HTTPS_PROXY', 'ADMIN_PASSWORD', 'OPENAI_API_KEY', 'SESSION_SECRET'):
            self.assertNotIn(key, env)

    def test_public_ipv4_fixed_hosts_only(self):
        self.assertEqual(m.allowed_addresses(HOSTS), ['8.8.4.4'])
        for address in ('127.0.0.1', '10.0.0.1', '169.254.169.254', '100.64.0.1', '198.18.0.1', '192.0.2.1', '224.0.0.1', '::1', '2606:4700::1111'):
            with self.assertRaises(ValueError): m.allowed_addresses({host:[address] for host in HOSTS})
        with self.assertRaises(ValueError): m.allowed_addresses({'evil.example':['8.8.4.4']})
        with self.assertRaises(ValueError): m.allowed_addresses({host:['8.8.4.4', '8.8.4.4'] for host in HOSTS})
        self.assertEqual(m.allowed_addresses({}), [])

    def test_resolution_only_three_actual_hosts_ipv4(self):
        with patch.object(m, 'command', return_value='8.8.4.4 STREAM host\n8.8.4.4 DGRAM host') as dns:
            self.assertEqual(m.resolve_feeds(), HOSTS)
            self.assertEqual({call[0][0][-1] for call in dns.call_args_list}, set(HOSTS))
            for call in dns.call_args_list:
                self.assertEqual(call[0][0][:2], ['/usr/bin/getent', 'ahostsv4'])
                self.assertEqual(call[1]['timeout'], 10)

    def test_nft_uid_only_exact_db_and_https_no_dns_or_app_uid(self):
        rules = m.network_rules(990, HOSTS)
        self.assertIn('meta skuid 990 ip daddr 127.0.0.1 tcp dport 55432', rules)
        self.assertIn('meta skuid 990 ip daddr 8.8.4.4 tcp dport 443', rules)
        self.assertNotIn('dport 53', rules)
        self.assertNotIn('127.0.0.0/8', rules)
        self.assertNotIn('989', rules)
        self.assertNotIn('flush', rules)
        self.assertIn('ipv4 counter reject', rules); self.assertIn('ipv6 counter reject', rules)
        for uid in (0,989,-1,'990'):
            with self.assertRaises(ValueError): m.network_rules(uid, HOSTS)
        baseline = m.network_rules(990,{})
        self.assertNotIn('dport 443', baseline)

    def test_nft_semantic_verification_not_just_table_name(self):
        objects = copy.deepcopy(m.network_objects(990, HOSTS))
        for index, obj in enumerate(objects):
            value = next(iter(obj.values())); value['handle'] = index + 1
            if 'rule' in obj:
                value['expr'] = [{'counter': {'packets':0,'bytes':0}} if e == {'counter':None} else e for e in value['expr']]
        def read(path, *unused):
            if path.name == 'network.json': return json.dumps({'uid':990,'hosts':HOSTS})
            if path.name == 'hosts': return m.hosts_text(HOSTS)
            return 'hosts: files\n'
        with patch.object(m,'trusted'), patch.object(m,'read',side_effect=read), patch.object(m,'command',side_effect=lambda *a, **k:json.dumps({'nftables':objects})):
            self.assertEqual(m.verify_network(USER),1)
            objects[-1]['rule']['expr'][-1] = {'accept':None}
            with self.assertRaisesRegex(ValueError,'modified'): m.verify_network(USER)

    def test_units_have_real_limits_no_environment_file_or_timer(self):
        for mode in ('check','seed','run','probe'):
            unit = m.unit_text(mode)
            for text in ('MemoryLimit=256M','TasksMax=32','TimeoutStartSec=120','NoNewPrivileges=yes',
                         'CapabilityBoundingSet=\n','AmbientCapabilities=\n','LimitCORE=0',
                         'User=aifinance-collect','ProtectSystem=strict','StandardError=null'):
                self.assertIn(text,unit)
            if mode != 'probe':self.assertIn('_verify --mode '+mode,unit)
            self.assertNotIn('EnvironmentFile=',unit)
            self.assertNotIn('NODE_OPTIONS',unit)
            self.assertNotIn('WantedBy=',unit)
        probe=m.unit_text('probe')
        self.assertIn('ExecStart=/usr/bin/sleep 30',probe)
        self.assertIn('PrivateNetwork=yes',probe)
        self.assertNotIn('_execute',probe)
        self.assertNotIn('database.env',probe)
        self.assertIn('BindReadOnlyPaths=',m.unit_text('run'))

    def test_kernel_memory_pids_identity_and_cgroup_checks(self):
        def fixture(path):
            text=str(path)
            if text.endswith('/status'): return 'Uid: 990 990 990 990\nNoNewPrivs: 1\nCapEff: 0\n'
            if text.endswith('/cgroup'): return '4:memory:/system.slice/aifinance-collect-run.service\n5:pids:/system.slice/aifinance-collect-run.service\n'
            if text.endswith('/cgroup.procs'): return '123\n'
            if text.endswith('memory.limit_in_bytes'): return str(m.LIMIT)
            if text.endswith('pids.max'): return '32'
            if text.endswith('pids.current'): return '2'
            return '0'
        with patch.object(m.Path,'read_text',fixture):
            self.assertEqual(m.kernel_evidence(123,'run',990)['pids.max'],32)
            for ending, replacement in (('/status','Uid: 0 0 0 0\nNoNewPrivs: 1\nCapEff: 0\n'),
                ('/cgroup','0::/system.slice/aifinance-collect-run.service'),('memory.failcnt','1'),
                ('memory.limit_in_bytes','99999999999'),('pids.max','max'),('pids.current','33'),('/cgroup.procs','124')):
                def bad(path): return replacement if str(path).endswith(ending) else fixture(path)
                with patch.object(m.Path,'read_text',bad), self.assertRaises(ValueError): m.kernel_evidence(123,'run',990)

    def test_actual_resolver_mounts_required_read_only(self):
        def fixture(path):
            text=str(path)
            if text.endswith('/mountinfo'): return '1 0 1:1 /x /etc/hosts ro - x x rw\n2 0 1:1 /y /etc/nsswitch.conf ro - x x rw\n'
            return 'hosts: files\n' if text.endswith('nsswitch.conf') else m.hosts_text(HOSTS)
        with patch.object(m,'read',return_value=m.hosts_text(HOSTS)),patch.object(m.Path,'read_text',fixture):
            self.assertTrue(m.resolver_evidence(123)['hosts_only'])
            def bad(path): return fixture(path).replace('/etc/hosts ro','/etc/hosts rw')
            with patch.object(m.Path,'read_text',bad),self.assertRaises(ValueError):m.resolver_evidence(123)

    def test_batch_limit_and_sanitized_fields(self):
        self.assertEqual(len(m.batch_summary(rows())),3)
        extra=rows();extra[0]['reason']='secret fixture';self.assertNotIn('reason',m.batch_summary(extra)[0])
        for change in ({'processed':2,'created':2},{'processed':-1},{'processed':True},{'created':2},{'sourceId':'evil'}):
            bad=rows();bad[0].update(change)
            with self.assertRaises(ValueError):m.batch_summary(bad)

    def test_zero_downstream_and_material_delta_acceptance(self):
        before=snapshot();after=snapshot();after['counts'].update(articles=3,article_revisions=3)
        m.accept_delta(before,after,rows())
        for table in m.ZERO_TABLES:
            bad=copy.deepcopy(after);bad['counts'][table]=1
            with self.assertRaises(ValueError):m.accept_delta(before,bad,rows())
        before['counts']['pgboss.job']=None;after['counts']['pgboss.job']=None
        m.accept_delta(before,after,rows())
        for table in ('articles','article_revisions','analyses'):
            bad=copy.deepcopy(after);bad['counts'][table]=None
            with self.assertRaises(ValueError):m.accept_delta(before,bad,rows())
        bad=copy.deepcopy(after);bad['counts']['articles']=4
        with self.assertRaises(ValueError):m.accept_delta(before,bad,rows())
        bad=copy.deepcopy(after);bad['counts']['article_revisions']=2
        with self.assertRaises(ValueError):m.accept_delta(before,bad,rows())

    def test_seed_delta_zero_and_required_isolation_schema(self):
        m.accept_delta(snapshot(False),snapshot())
        for key,value in (('columns',[]),('constraints',[]),('rawStates',[{'processing_state':'new'}]),('sources',[])):
            bad=snapshot();bad[key]=value
            with self.assertRaises(ValueError):m.validate_snapshot(bad)
        bad=snapshot();bad['counts']['articles']=1
        with self.assertRaises(ValueError):m.accept_delta(snapshot(False),bad)

    def test_first_operation_rejects_existing_receipt_or_attempt_before_mutation(self):
        with tempfile.TemporaryDirectory() as d:
            base=Path(d);(base/'probe.json').write_text('{}')
            for marker in ('run.json','run-attempt.json'):
                path=base/marker;path.write_text('{}')
                with patch.object(m,'STATE',base),patch.object(m,'command') as call,patch.object(m,'run_unit') as run:
                    with self.assertRaisesRegex(ValueError,'already_attempted'):m.first_operation('run',USER)
                    call.assert_not_called();run.assert_not_called()
                path.unlink()

    def test_root_cannot_execute_application_and_probe_never_executes_js(self):
        with patch.object(m,'account',return_value=USER),patch.object(m.os,'getuid',return_value=0),patch.object(m,'bounded_child') as run:
            with self.assertRaises(ValueError):m.execute('run')
            run.assert_not_called()
        with self.assertRaises(ValueError):m.execute('probe')

    def test_no_timer_without_admin_and_first_success(self):
        with patch.object(m,'command') as call,patch.object(m,'write_new') as write:
            with self.assertRaises(ValueError):m.enable_hourly(USER,False)
            write.assert_not_called();call.assert_not_called()
        with patch.object(m,'trusted'),patch.object(m,'read',return_value=json.dumps({'passed':False,'release':m.RELEASE_SHA})),patch.object(m,'write_new') as write:
            with self.assertRaises(ValueError):m.enable_hourly(USER,True)
            write.assert_not_called()
        service,timer=m.hourly_text()
        self.assertIn('run --scheduled',service)
        self.assertIn('OnActiveSec=1h',timer);self.assertIn('OnUnitActiveSec=1h',timer)
        self.assertNotIn('Persistent=true',timer)

    def test_no_writer_requires_all_clients_gone_and_exact_app_units(self):
        with patch.object(m,'prop',return_value='active'),patch.object(m,'bounded_child') as child:
            with self.assertRaises(ValueError):m.no_other_writers(USER)
            child.assert_not_called()
        with patch.object(m,'prop',return_value='inactive'),patch.object(m,'no_processes'),patch.object(m.pwd,'getpwnam',return_value=USER),patch.object(m,'db_environment',return_value={'DATABASE_URL':URL}),patch.object(m,'bounded_child',return_value='1') as child:
            with self.assertRaises(ValueError):m.no_other_writers(USER)
            args=child.call_args[0][0]
            self.assertNotIn('public-fixture-password',repr(args))
            self.assertNotIn('backend_type',args[-1])

    def test_disable_preserves_data_revokes_db_and_narrow_network_only(self):
        with patch.object(m,'prop',return_value='loaded'),patch.object(m,'command') as command,patch.object(m,'trusted'),patch.object(m.os,'chown') as owner,patch.object(m.os,'chmod') as chmod,patch.object(m,'no_processes'),patch.object(m,'configure_network') as network:
            self.assertTrue(m.disable(USER)['data_preserved'])
            chmod.assert_called_once_with(str(m.CONFIG/'database.env'),0o400)
            network.assert_called_once_with(USER,{})
            text=repr(command.call_args_list)
            self.assertNotIn('preview-api',text);self.assertNotIn('preview-web',text)
            self.assertNotIn('delete',text);self.assertNotIn('flush',text)

    def test_install_modes_with_real_restrictive_umask_and_db_only_copy(self):
        configuration=('DATABASE_URL='+URL+'\nSITE_URL=http://127.0.0.1:3100\n'
                       'ADMIN_PASSWORD=public-fixture-admin\nSESSION_SECRET='+'s'*32+'\nIMG_PROXY_SIGN_SECRET='+'i'*32+'\n')
        actual_stat=m.Path.stat;actual_read=m.read
        with tempfile.TemporaryDirectory() as d:
            base=Path(d);root=base/'opt';(root/'bin').mkdir(parents=True)
            (root/'bin/run-preview.py').write_text((REPO/'deploy/native/run-preview.py').read_text())
            maintenance=base/'maintenance';maintenance.mkdir();system=base/'system';system.mkdir()
            config=base/'config';state=maintenance/'collect-only'
            def st(path,*args,**kw):
                if str(path)=='/etc/aifinance-preview.env':return SimpleNamespace(st_mode=0o100640,st_gid=990)
                return actual_stat(path,*args,**kw)
            def read(path,*args):return configuration if str(path)=='/etc/aifinance-preview.env' else actual_read(path,*args)
            old=m.os.umask(0o077)
            try:
                with ExitStack() as stack:
                    for target, key, value in [(m,'ROOT',root),(m,'STATE',state),(m,'CONFIG',config),(m,'SYSTEM',system),(m,'MAINTENANCE',maintenance),(m.Path,'stat',st)]:
                        stack.enter_context(patch.object(target,key,value))
                    for key in ('upgrade_gate','validate_release','trusted','no_processes','configure_network','command','verify_units'):
                        stack.enter_context(patch.object(m,key))
                    stack.enter_context(patch.object(m,'prop',return_value='not-found'))
                    stack.enter_context(patch.object(m,'account',return_value=USER))
                    stack.enter_context(patch.object(m.pwd,'getpwnam',return_value=USER))
                    stack.enter_context(patch.object(m.os,'chown'))
                    stack.enter_context(patch.object(m.os,'fchown'))
                    stack.enter_context(patch.object(m,'read',side_effect=read))
                    result=m.install()
                self.assertFalse(result['timer_installed'])
                self.assertEqual(config.stat().st_mode & 0o777,0o750)
                self.assertEqual((config/'database.env').stat().st_mode & 0o777,0o440)
                self.assertEqual((config/'database.env').read_text(),'DATABASE_URL='+URL+'\n')
                self.assertEqual(state.stat().st_mode & 0o777,0o700)
                self.assertFalse(any(path.suffix=='.timer' for path in system.iterdir()))
            finally:m.os.umask(old)

    def test_effective_exec_rejects_extra_commands_and_different_loaded_argv(self):
        expected='/usr/bin/sleep 30'
        good='{ path=/usr/bin/sleep ; argv[]=/usr/bin/sleep 30 ; ignore_errors=no ; start_time=[n/a] ; pid=0 }'
        with patch.object(m,'prop',return_value=good):m.effective_exec('fixture','ExecStart',expected)
        for bad in (good.replace('sleep 30','sleep 10'),good+' '+good,good.replace('ignore_errors=no','ignore_errors=yes')):
            with patch.object(m,'prop',return_value=bad),self.assertRaises(ValueError):m.effective_exec('fixture','ExecStart',expected)

    def test_unit_start_failure_removes_launch_and_stops_only_own_unit(self):
        with tempfile.TemporaryDirectory() as d:
            state=Path(d)
            def cmd(args,**kw):
                if args[1:3]==['start','--no-block']:raise ValueError('fixture_start_failure')
                return ''
            with patch.object(m,'STATE',state),patch.object(m,'verify_units'),patch.object(m,'verify_network'),patch.object(m,'trusted'),patch.object(m,'prop',return_value='inactive'),patch.object(m,'command',side_effect=cmd) as command,patch.object(m.os,'fchown'):
                with self.assertRaisesRegex(ValueError,'fixture_start_failure'):m.run_unit('probe',USER)
                self.assertFalse((state/'launch.json').exists())
                self.assertEqual(command.call_args_list[-1][0][0],[m.CTL,'stop','aifinance-collect-probe.service'])

    def test_normal_exit_proc_race_uses_terminal_result_but_needs_prior_sample(self):
        for samples, accepted in (([{'kernel':'fixture'},FileNotFoundError()],True),([FileNotFoundError(),FileNotFoundError()],False)):
            with tempfile.TemporaryDirectory() as d:
                active=iter(['inactive','activating','activating','inactive','inactive'])
                def prop(unit,name):
                    if name=='ActiveState':return next(active)
                    return {'MainPID':'123','Result':'success','ExecMainStatus':'0'}[name]
                with patch.object(m,'STATE',Path(d)),patch.object(m,'verify_units'),patch.object(m,'verify_network'),patch.object(m,'trusted'),patch.object(m.os,'fchown'),patch.object(m,'command'),patch.object(m,'prop',side_effect=prop),patch.object(m,'resource_evidence',side_effect=samples),patch.object(m.time,'sleep'):
                    if accepted:self.assertEqual(len(m.run_unit('probe',USER)['samples']),1)
                    else:
                        with self.assertRaisesRegex(ValueError,'resource_evidence_missing'):m.run_unit('probe',USER)

    def test_inactive_unloaded_unit_starts_without_reset_failed(self):
        with tempfile.TemporaryDirectory() as d, ExitStack() as stack:
            active=iter(['inactive','activating','inactive','inactive'])
            def prop(unit,name):
                if name=='ActiveState':return next(active)
                return {'MainPID':'123','Result':'success','ExecMainStatus':'0'}[name]
            def cmd(args,**kw):
                if args[1]=='reset-failed':
                    raise subprocess.CalledProcessError(1,args,stderr='Unit not loaded')
                return ''
            stack.enter_context(patch.object(m,'STATE',Path(d)))
            for key in ('verify_units','verify_network','trusted'):
                stack.enter_context(patch.object(m,key))
            stack.enter_context(patch.object(m.os,'fchown'))
            call=stack.enter_context(patch.object(m,'command',side_effect=cmd))
            stack.enter_context(patch.object(m,'prop',side_effect=prop))
            stack.enter_context(patch.object(m,'resource_evidence',return_value={'kernel':'fixture'}))
            stack.enter_context(patch.object(m.time,'sleep'))
            self.assertEqual(len(m.run_unit('probe',USER)['samples']),1)
            self.assertEqual([c[0][0][1:] for c in call.call_args_list],
                             [['start','--no-block','aifinance-collect-probe.service']])

    def test_failed_unit_reset_error_still_stops_before_start(self):
        for reset_fails in (False,True):
            with tempfile.TemporaryDirectory() as d, ExitStack() as stack:
                state=Path(d);active=iter(['failed','activating','inactive','inactive'])
                def prop(unit,name):
                    if name=='ActiveState':return next(active)
                    return {'MainPID':'123','Result':'success','ExecMainStatus':'0'}[name]
                def cmd(args,**kw):
                    if reset_fails and args[1]=='reset-failed':
                        raise subprocess.CalledProcessError(1,args)
                    return ''
                stack.enter_context(patch.object(m,'STATE',state))
                for key in ('verify_units','verify_network','trusted'):
                    stack.enter_context(patch.object(m,key))
                stack.enter_context(patch.object(m.os,'fchown'))
                call=stack.enter_context(patch.object(m,'command',side_effect=cmd))
                stack.enter_context(patch.object(m,'prop',side_effect=prop))
                stack.enter_context(patch.object(m,'resource_evidence',return_value={'kernel':'fixture'}))
                stack.enter_context(patch.object(m.time,'sleep'))
                if reset_fails:
                    with self.assertRaises(subprocess.CalledProcessError):m.run_unit('probe',USER)
                else:self.assertEqual(len(m.run_unit('probe',USER)['samples']),1)
                calls=[c[0][0][1:] for c in call.call_args_list]
                self.assertEqual(calls,[['reset-failed','aifinance-collect-probe.service']]+
                                 ([] if reset_fails else [['start','--no-block','aifinance-collect-probe.service']]))
                self.assertFalse((state/'launch.json').exists())

    def test_nonidle_unit_refused_before_any_state_write(self):
        for active in ('active','activating','deactivating','reloading','','unknown'):
            with patch.object(m,'verify_units'),patch.object(m,'verify_network'),patch.object(m,'prop',return_value=active),patch.object(m,'command') as call,patch.object(m,'replace_owned') as replace:
                with self.assertRaisesRegex(ValueError,'collector_unit_already_running'):m.run_unit('probe',USER)
                call.assert_not_called();replace.assert_not_called()

    def test_launch_requires_live_root_controller_and_mode_gates(self):
        launch={'mode':'run','pid':123,'start_ticks':'999'}
        def proc(path):
            if str(path).endswith('/status'):return 'Uid: 0 0 0 0\n'
            return '123 (python3) '+ ' '.join(['S']+['0']*18+['999'])
        with patch.object(m,'trusted') as trusted,patch.object(m,'read',return_value=json.dumps(launch)),patch.object(m.Path,'read_text',proc):
            m.verify_launch('run')
            self.assertIn(((m.STATE/'probe.json',),),[(c[0],) for c in trusted.call_args_list])
            self.assertIn(((m.STATE/'seed.json',),),[(c[0],) for c in trusted.call_args_list])
            with self.assertRaises(ValueError):m.verify_launch('seed')

    def test_bounded_child_suppresses_stderr_and_caps_output(self):
        actual=subprocess.Popen
        for output,success in (('fixture',True),('x'*140000,False)):
            captured=[]
            def run(args,**kw):
                captured.append(kw);kw['cwd']='/'
                return actual([sys.executable,'-c','print("x"*140000)' if not success else 'print('+repr(output)+')'],**kw)
            with patch.object(m.subprocess,'Popen',side_effect=run):
                if success:self.assertEqual(m.bounded_child(['fixed'],m.ENV).strip(),output)
                else:
                    with self.assertRaises(ValueError):m.bounded_child(['fixed'],m.ENV)
            self.assertEqual(captured[0]['stderr'],subprocess.DEVNULL)


if __name__=='__main__':unittest.main()
