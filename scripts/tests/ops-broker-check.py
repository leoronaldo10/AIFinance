#!/usr/bin/python3
"""Offline fixtures. No real systemctl, nft, DB, environment files or user changes."""
import ast
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
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('ops_broker', str(REPO/'deploy/native/ops-broker.py'))
m = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(m)
USER = SimpleNamespace(pw_uid=986, pw_gid=987)
SECRET = 'fixture-secret-password-that-must-never-appear'
URL = 'postgres://aifinance_preview:'+SECRET+'@127.0.0.1:55432/aifinance_preview'
PROOF = {'database_ok':True,'role_ok':True,'role_safe':True,'migration_ok':True,'other_clients':0,
         'sources':0,'articles':0,'discoveries':0,'fetch_runs':0}


def runner():
    r = SimpleNamespace()
    for name in ('resource_evidence','resolver_evidence','no_other_writers','accept_delta','configure_network',
                 'resolve_feeds','verify_units','run_unit','upgrade_gate','validate_release','verify_network',
                 'no_processes','effective_exec','db_environment','disable','first_operation','enable_hourly'):
        setattr(r,name,Mock())
    r.account=Mock(return_value=USER);r.prop=Mock(return_value='')
    r.unit_name=lambda mode:m.UNIT_ALIASES[mode]
    r.hourly_text=Mock(return_value=('User=root\nExecStart=/usr/bin/python3 -I -B /opt/aifinance/bin/collect-only-runner.py run --scheduled\n','fixed hourly timer'))
    r.database_url=lambda value:value.split('=',1)[1].strip()
    r.pwd=SimpleNamespace(getpwnam=lambda name:SimpleNamespace(pw_uid=989))
    r.batch_summary=lambda rows:rows
    return r


def broker():
    return m.Broker(runner(),SimpleNamespace(UNIT_DIGESTS={},helper=Mock()))


def states():
    result={}
    for alias,unit in m.UNIT_ALIASES.items():
        result[alias]={'Id':unit,'LoadState':'not-found' if alias in ('hourly','timer') else 'loaded',
            'ActiveState':'inactive','SubState':'dead','Result':'success','MainPID':'0','ControlPID':'0',
            'ExecMainCode':'0','ExecMainStatus':'0','ExecMainStartTimestampMonotonic':'0',
            'ExecMainExitTimestampMonotonic':'0','FragmentPath':str(m.SYSTEM/unit),'DropInPaths':'',
            'UnitFileState':'disabled','User':'aifinance-collect','Group':'aifinance-collect',
            'MemoryAccounting':'yes','MemoryLimit':str(256*1024**2),'TasksMax':'32','TimeoutStartUSec':'2min'}
    result['check'].update(ActiveState='failed',Result='signal',ExecMainCode='2',ExecMainStatus='15',
                           ExecMainStartTimestampMonotonic='100',ExecMainExitTimestampMonotonic='200')
    return result


class BrokerTests(unittest.TestCase):
    def test_python36_syntax_and_existing_helper_hashes(self):
        source=(REPO/'deploy/native/ops-broker.py').read_text()
        ast.parse(source,**({'feature_version':(3,6)} if sys.version_info>=(3,8) else {}))
        for name,digest in (('collect-only-runner.py',m.RUNNER_SHA),('collect-only-upgrade.py',m.UPGRADE_SHA)):
            self.assertEqual(hashlib.sha256((REPO/'deploy/native'/name).read_bytes()).hexdigest(),digest)

    def test_exact_action_parser(self):
        for action in m.ACTIONS:
            args=[action,'--accept-admin-view'] if action=='enable-hourly' else [action]
            self.assertEqual(m.parse(args),action)
        for args in ([],['enable-hourly'],['run','--scheduled'],['seed','--path','/tmp/x'],['diagnose\nseed'],
                     ['disable; id'],['/bin/sh'],['probe','--accept-admin-view'],['enable-hourly','--accept-admin-view','x']):
            with self.assertRaises(m.Refused):m.parse(args)

    def test_errors_never_echo_secrets_or_throw(self):
        for error in (ValueError(SECRET),ValueError([SECRET]),ValueError({'x':SECRET}),ValueError(object()),
                      m.Refused(SECRET),m.Refused([SECRET]),RuntimeError(SECRET),OSError(SECRET)):
            value=m.reason(error);self.assertNotIn(SECRET,value);self.assertIsInstance(value,str)
        self.assertEqual(m.reason(ValueError('collector_process_identity_or_privileges')),'collector_process_identity_or_privileges')
        self.assertEqual(m.reason(m.Interrupted()),'operation_interrupted')

    def test_complete_receipt_exact_keys_type_and_single_link(self):
        value={'broker_sha256':'a'*64}
        receipt={'schema':1,'status':'complete','broker_sha256':'a'*64,'app_release':m.RELEASE}
        info=SimpleNamespace(st_gid=0,st_nlink=1)
        self.assertEqual(m.INSTALL.name,'complete.json')
        with patch.object(m.Path,'lstat',return_value=info),patch.object(m,'read',return_value=json.dumps(receipt).encode()):
            m.installation_complete(value)
            for change in ({'schema':True},{'extra':SECRET},{'status':'prepared'},{'broker_sha256':'b'*64}):
                bad=dict(receipt,**change)
                with patch.object(m,'read',return_value=json.dumps(bad).encode()),self.assertRaises(m.Refused):m.installation_complete(value)
            info.st_nlink=2
            with self.assertRaises(m.Refused):m.installation_complete(value)

    def test_identity_uses_original_receipt_and_named_exclusive_group(self):
        b=broker()
        with patch.object(m,'document',return_value={'release':m.RELEASE,'uid':986}):
            self.assertIs(b.identity(),USER)
        with patch.object(m,'document',return_value={'release':m.RELEASE,'uid':987}),self.assertRaises(m.Refused):b.identity()

    def test_public_service_metadata_has_no_host_detail_or_raw_values(self):
        item=states()['check'];item.update(MainPID='12345',ControlPID='0',User=SECRET,FragmentPath='/secret/'+SECRET,
                                          SubState=SECRET,Result=SECRET,MemoryLimit='123456789')
        public=m.public_unit(item);text=json.dumps(public)
        for forbidden in (SECRET,'12345','123456789','FragmentPath','User','SubState'):self.assertNotIn(forbidden,text)
        self.assertEqual(public['Result'],'invalid');self.assertTrue(public['process_running'])
        self.assertEqual(public['exit_class'],'terminated')

    def test_bounded_subprocess_kills_oversize_and_timeout_clean_env(self):
        actual=subprocess.Popen;captured=[]
        for program,expected in (("print('x'*70000)",'command_output_limit'),('import time;time.sleep(2)','command_timeout')):
            def run(args,**kw):
                captured.append(kw);return actual([sys.executable,'-c',program],**kw)
            with patch.object(m,'trusted'),patch.object(m.subprocess,'Popen',side_effect=run),patch.dict(os.environ,{'NODE_OPTIONS':SECRET,'HTTPS_PROXY':SECRET}):
                with self.assertRaises(m.Refused) as error:m.bounded_command(['/fixed'],timeout=.05)
                self.assertEqual(error.exception.reason,expected)
        self.assertEqual(captured[0]['stderr'],subprocess.DEVNULL)
        self.assertNotIn('NODE_OPTIONS',captured[0]['env']);self.assertNotIn('HTTPS_PROXY',captured[0]['env'])

    def test_unit_snapshot_single_bounded_call_rejects_unknown_fields(self):
        data='\n\n'.join('\n'.join(k+'='+v for k,v in item.items()) for item in states().values())
        with patch.object(m,'bounded_command',return_value=data) as command:
            self.assertEqual(set(m.unit_states()),set(m.UNIT_ALIASES));self.assertEqual(command.call_count,1)
        with patch.object(m,'bounded_command',return_value=data+'\nEnvironment='+SECRET),self.assertRaises(m.Refused):m.unit_states()

    def test_diagnostic_interruption_is_not_swallowed(self):
        b=broker();b.r.upgrade_gate.side_effect=m.Interrupted()
        with patch.object(m,'unit_states',return_value=states()),patch.object(m.Path,'exists',return_value=False),patch.object(m.Path,'is_symlink',return_value=False):
            with self.assertRaises(m.Interrupted):b.diagnose()
        b.r.validate_release.assert_not_called()

    def test_successful_nested_stage_restored_error_keeps_narrow_stage(self):
        b=broker();b.stage='collector_seed'
        b.r.resource_evidence('probe',USER)
        self.assertEqual(b.stage,'collector_seed')
        failure=b.instrument(Mock(side_effect=ValueError('kernel_budget_not_enforced_or_hit')),'resource_check')
        with self.assertRaises(ValueError):failure()
        self.assertEqual(b.stage,'resource_check')

    def test_no_cleanup_on_unknown_preflight_or_no_mutation(self):
        b=broker()
        for safe,mutated in ((False,False),(False,True),(True,False)):
            b.safe_to_cleanup=safe;b.mutated=mutated
            self.assertEqual(b.cleanup('seed'),{})
        b.r.disable.assert_not_called()

    def test_read_only_sql_exact_identity_role_no_shadow_or_rls(self):
        b=broker()
        with tempfile.TemporaryFile() as fd:
            fd.write(('DATABASE_URL='+URL+'\n').encode());fd.flush()
            with patch.object(m,'bounded_command',return_value=json.dumps(PROOF)) as command:
                self.assertEqual(b.sql_proof(fd.fileno(),USER),PROOF)
                args,sql=command.call_args[0];kw=command.call_args[1]
                self.assertNotIn(SECRET,repr(args));self.assertEqual(kw['env']['PGPASSWORD'],SECRET)
                for required in ('REPEATABLE READ READ ONLY','SET LOCAL search_path=pg_catalog,public,pg_temp',
                    'SET LOCAL row_security=off','pg_catalog.pg_roles','rolcanlogin','rolbypassrls',
                    'pg_catalog.pg_class','c.relkind IN (\'r\',\'p\')','public.sources','public.articles',
                    'public.article_discoveries','public.fetch_runs','public.schema_migrations','pg_catalog.pg_stat_activity'):
                    self.assertIn(required,sql)
                self.assertNotIn('SET ROLE',sql)
                with patch.object(m.os,'setgroups') as groups,patch.object(m.os,'setgid') as gid,patch.object(m.os,'setuid') as uid:
                    kw['drop']();groups.assert_called_once_with([]);gid.assert_called_once_with(987);uid.assert_called_once_with(986)
            for key in PROOF:
                bad=dict(PROOF);bad[key]=False if type(PROOF[key]) is bool else 1
                with patch.object(m,'bounded_command',return_value=json.dumps(bad)),self.assertRaises(m.Refused):b.sql_proof(fd.fileno(),USER)

    def test_known_timer_rejects_unknown_and_accepts_only_quiet_verified_lifecycle(self):
        b=broker();value=states()
        for alias in ('hourly','timer'):value[alias]['LoadState']='loaded'
        def read(path,*args,**kw):return (b.r.hourly_text()[0] if path.name.endswith('.service') else b.r.hourly_text()[1]).encode()
        with patch.object(m,'read',side_effect=read),patch.object(m,'document',return_value={'release':m.RELEASE,'admin_view_accepted':True}):
            b.known_timer(value,quiet=True)
            value['timer']['ActiveState']='active'
            with self.assertRaises(m.Refused):b.known_timer(value,quiet=True)
            value['timer']['ActiveState']='inactive';value['hourly']['DropInPaths']=SECRET
            with self.assertRaises(m.Refused):b.known_timer(value)

    def test_refuse_historical_seed_or_run_before_app_pause(self):
        b=broker()
        with patch.object(m.Path,'exists',return_value=True),patch.object(m.Path,'is_symlink',return_value=False),patch.object(m,'bounded_command') as command:
            with self.assertRaises(m.Refused):b.recover(USER)
            command.assert_not_called();self.assertFalse(b.mutated)

    def test_cleanup_restoration_failure_is_separate_and_never_retries(self):
        b=broker();b.safe_to_cleanup=True;b.mutated=True
        with patch.object(b,'identity',return_value=USER),patch.object(b,'known_timer'),patch.object(m,'unit_states',return_value=states()),patch.object(b,'restart',side_effect=ValueError(SECRET)):
            result=b.cleanup('run')
        self.assertTrue(result['collector_disabled']);self.assertFalse(result['preview_restored'])
        self.assertNotIn(SECRET,json.dumps(result));b.r.disable.assert_called_once_with(USER)
        b.r.first_operation.assert_not_called()

    def recovery_fixture(self, directory):
        root=Path(directory);ops=root/'ops';collect=root/'collect';config=root/'config';system=root/'system'
        for path in (ops,collect,config,system):path.mkdir(mode=0o700)
        raw=json.dumps({'release':m.RELEASE,'mode':'seed','started':1000}).encode()
        attempt=collect/'seed-attempt.json';attempt.write_bytes(raw);attempt.chmod(0o600)
        (collect/'network.json').write_text(json.dumps({'uid':986,'hosts':{}}));(collect/'network.json').chmod(0o600)
        db=config/'database.env';db.write_text('DATABASE_URL='+URL+'\n');db.chmod(0o400)
        fd=os.open(str(db),os.O_RDONLY);actual=os.fstat(fd)
        permissions={'gid':0,'mode':0o400};events=[]
        baseline={'attempt_sha256':hashlib.sha256(raw).hexdigest(),'attempt_started':1000,
                  'check_start_monotonic':'100','check_exit_monotonic':'200',
                  'db_device':actual.st_dev,'db_inode':actual.st_ino,'collector_gid':987}
        (ops/'install.json').write_text(json.dumps({'recovery_baseline':baseline}));(ops/'install.json').chmod(0o600)
        def info():return SimpleNamespace(st_dev=actual.st_dev,st_ino=actual.st_ino,st_uid=0,
            st_gid=permissions['gid'],st_mode=0o100000|permissions['mode'],st_nlink=1,st_size=actual.st_size)
        b=broker();b.safe_to_cleanup=True
        b.identity=Mock(return_value=USER);b.probe_receipt=Mock();b.journal_metadata=Mock(return_value=[])
        fp=SimpleNamespace(listeners=Mock(return_value={'8000':[('fixture','old-inode')]}))
        b.app_gate=Mock(return_value=fp);b.sql_proof=Mock(return_value=PROOF)
        b.restart=Mock(return_value={'preview_healthy':True,'existing_service_preserved':True})
        b.environment_fd=Mock(return_value=(fd,info()))
        b.known_timer=Mock()
        def disable(user):permissions.update(gid=0,mode=0o400);events.append('disable')
        b.r.disable.side_effect=disable
        actual_fstat=os.fstat;actual_fchmod=os.fchmod
        def fstat(descriptor):return info() if descriptor==fd else actual_fstat(descriptor)
        def fchown(descriptor,uid,gid):
            if descriptor==fd:permissions['gid']=gid;events.append('permission_group')
        def fchmod(descriptor,mode):
            if descriptor==fd:permissions['mode']=mode;events.append('permission_mode')
            actual_fchmod(descriptor,mode)
        def read(path,maximum=131072,mode=None):
            data=Path(path).read_bytes()
            if len(data)>maximum:raise m.Refused('file_output_limit')
            if mode is not None and Path(path).stat().st_mode&0o777!=mode:raise m.Refused('unexpected_file_mode')
            return data
        return SimpleNamespace(root=root,ops=ops,collect=collect,config=config,system=system,raw=raw,db=db,
            fd=fd,baseline=baseline,b=b,permissions=permissions,events=events,read=read,fstat=fstat,fchown=fchown,fchmod=fchmod)

    def recovery_patches(self,f):
        from contextlib import ExitStack
        stack=ExitStack()
        for name,value in (('OPS',f.ops),('COLLECT',f.collect),('CONFIG',f.config),('SYSTEM',f.system),('INSTALL_EVIDENCE',f.ops/'install.json')):
            stack.enter_context(patch.object(m,name,value))
        for name,kwargs in (('trusted',{}),('read',{'side_effect':f.read}),('unit_states',{'return_value':states()}),('bounded_command',{})):
            stack.enter_context(patch.object(m,name,**kwargs))
        stack.enter_context(patch.object(m.os,'fstat',side_effect=f.fstat))
        stack.enter_context(patch.object(m.os,'fchown',side_effect=f.fchown))
        stack.enter_context(patch.object(m.os,'fchmod',side_effect=f.fchmod))
        return stack

    def test_recovery_preserves_attempt_before_permission_and_binds_same_inode(self):
        with tempfile.TemporaryDirectory() as directory:
            f=self.recovery_fixture(directory);original_write=m.write_new
            def write(path,data):
                original_write(path,data);f.events.append(path.name)
            with self.recovery_patches(f),patch.object(m,'write_new',side_effect=write):
                result=f.b.recover(USER)
                self.assertTrue(result['recovered_pre_seed']);self.assertTrue(result['preview_healthy'])
                self.assertEqual((f.ops/'pre-seed-attempt-v1.json').read_bytes(),f.raw)
                self.assertFalse((f.collect/'seed-attempt.json').exists())
                index=json.loads((f.ops/'recovery.json').read_text())
                self.assertEqual(index['status'],'ready');self.assertEqual(index['baseline'],f.baseline)
                self.assertEqual(f.permissions,{'gid':987,'mode':0o440})
                self.assertLess(f.events.index('pre-seed-attempt-v1.json'),f.events.index('permission_group'))
                self.assertLess(f.events.index('recovery.json'),f.events.index('permission_group'))
                with self.assertRaises(m.Refused):f.b.recover(USER)
                self.assertEqual(f.b.sql_proof.call_count,1)
            self.assertNotIn(SECRET,(f.ops/'recovery.json').read_text())

    def test_recovery_failures_preserve_history_and_refuse_partial_retry(self):
        for failure in ('sql','archive','index','permission','post_permission'):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as directory:
                f=self.recovery_fixture(directory);original_write=m.write_new;original_replace=m.replace_index
                def write(path,data):
                    if failure=='archive' and path.name=='pre-seed-attempt-v1.json':raise OSError(SECRET)
                    if failure=='index' and path.name=='recovery.json':raise OSError(SECRET)
                    return original_write(path,data)
                def owner(fd,uid,gid):
                    if failure=='permission' and fd==f.fd:raise PermissionError(SECRET)
                    return f.fchown(fd,uid,gid)
                def replace(path,value):
                    if failure=='post_permission':raise OSError(SECRET)
                    return original_replace(path,value)
                if failure=='sql':f.b.sql_proof.side_effect=m.Refused('pre_seed_database_proof_failed')
                with self.recovery_patches(f),patch.object(m,'write_new',side_effect=write),patch.object(m.os,'fchown',side_effect=owner),patch.object(m,'replace_index',side_effect=replace):
                    with self.assertRaises(Exception):f.b.recover(USER)
                    self.assertTrue(f.b.mutated)
                    cleanup=f.b.cleanup('recover-pre-seed')
                    self.assertTrue(cleanup['collector_disabled']);self.assertTrue(cleanup['preview_restored'])
                    f.b.restart.assert_called_once()
                    self.assertEqual(f.permissions,{'gid':0,'mode':0o400})
                    preserved=(f.collect/'seed-attempt.json').exists() or (f.ops/'pre-seed-attempt-v1.json').exists()
                    self.assertTrue(preserved)
                    if failure in ('index','permission','post_permission'):
                        with self.assertRaises(m.Refused):f.b.recover(USER)

    def test_ready_recovery_rejects_archive_or_database_identity_tamper(self):
        with tempfile.TemporaryDirectory() as directory:
            f=self.recovery_fixture(directory)
            with self.recovery_patches(f):f.b.recover(USER)
            archived=f.ops/'pre-seed-attempt-v1.json';original=archived.read_bytes()
            current=os.open(str(f.db),os.O_RDONLY);st=os.fstat(current)
            f.b.environment_fd=Mock(return_value=(current,SimpleNamespace(st_dev=st.st_dev,st_ino=st.st_ino,st_gid=987)))
            with self.recovery_patches(f):f.b.ready_recovery(USER)
            archived.write_bytes(original+b' ')
            with self.recovery_patches(f),self.assertRaises(m.Refused):f.b.ready_recovery(USER)
            archived.write_bytes(original)
            current=os.open(str(f.db),os.O_RDONLY)
            f.b.environment_fd=Mock(return_value=(current,SimpleNamespace(st_dev=st.st_dev,st_ino=st.st_ino+1,st_gid=987)))
            with self.recovery_patches(f),self.assertRaises(m.Refused):f.b.ready_recovery(USER)

    def test_recovery_baseline_change_refuses_before_pause(self):
        with tempfile.TemporaryDirectory() as directory:
            f=self.recovery_fixture(directory)
            (f.collect/'seed-attempt.json').write_bytes(f.raw.replace(b'1000',b'1001'))
            with self.recovery_patches(f),self.assertRaises(m.Refused):f.b.recover(USER)
            self.assertFalse(f.b.mutated);f.b.sql_proof.assert_not_called();os.close(f.fd)

    def test_write_preflight_app_gate_refusal_never_creates_attempt_or_stops_services(self):
        for action in ('probe','seed','run','enable-hourly'):
            b=broker();b.base=Mock(return_value=USER);b.idle=Mock();b.no_timer=Mock();b.db_only_network=Mock()
            b.app_gate=Mock(side_effect=m.Refused('preview_unit_changed'))
            with patch.object(m,'unit_states',return_value=states()),patch.object(m,'bounded_command') as command:
                with self.assertRaises(m.Refused):b.execute(action)
                self.assertFalse(b.safe_to_cleanup);self.assertFalse(b.mutated)
                self.assertEqual(b.cleanup(action),{})
                command.assert_not_called();b.r.first_operation.assert_not_called();b.r.disable.assert_not_called()

    def test_restart_only_exact_api_web_and_requires_old_listener(self):
        b=broker();b.known_timer=Mock()
        listeners={'8000':[('old','inode')], '3100':[('0100007F','web')],
                   '3101':[('0100007F','api')], '55432':[('0100007F','db')]}
        fp=SimpleNamespace(listeners=Mock(return_value=listeners),health=Mock())
        b.app_gate=Mock(return_value=fp)
        with patch.object(m,'unit_states',return_value=states()),patch.object(m,'bounded_command') as command:
            self.assertTrue(b.restart(USER)['existing_service_preserved'])
            command.assert_called_once_with(['/usr/bin/systemctl','restart']+m.APP_UNITS)
            command.reset_mock();fp.listeners.return_value={'8000':[]}
            with self.assertRaises(m.Refused):b.restart(USER)
            command.assert_not_called()

    def test_interruption_after_app_pause_always_attempts_separate_cleanup(self):
        b=broker();b.identity=Mock(return_value=USER);b.known_timer=Mock();b.restart=Mock(return_value={})
        def interrupted(action):
            b.stage='app_stop';b.mutated=True;b.safe_to_cleanup=True
            raise m.Interrupted()
        b.execute=Mock(side_effect=interrupted)
        with tempfile.TemporaryFile() as lockfile:
            fd=os.dup(lockfile.fileno());b.r.release_lock=Mock(return_value=fd)
            with patch.object(m,'SELF',Path(m.__file__).absolute()),patch.object(m.os,'getuid',return_value=0),patch.object(m.os,'geteuid',return_value=0),patch.object(m,'policy',return_value={'broker_sha256':'a'*64}),patch.object(m,'installation_complete'),patch.object(m,'pinned_module',side_effect=[b.r,b.u]),patch.object(m,'Broker',return_value=b),patch.object(m.signal,'alarm'),patch.object(m.resource,'setrlimit'),patch.object(m,'unit_states',return_value=states()),patch.object(m,'write_new'),patch.dict(os.environ,{'SECRET_FIXTURE':SECRET}),patch('sys.stdout',new_callable=io.StringIO) as out:
                self.assertEqual(m.main(['recover-pre-seed']),1)
                result=json.loads(out.getvalue())
            self.assertEqual(result['stage'],'app_stop');self.assertEqual(result['reason'],'operation_interrupted')
            self.assertTrue(result['cleanup']['collector_disabled']);self.assertTrue(result['cleanup']['preview_restored'])
            self.assertNotIn(SECRET,json.dumps(result));b.r.disable.assert_called_once();b.restart.assert_called_once()

    def test_resolver_metadata_reveals_only_booleans_never_contents_or_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);hosts=root/'hosts';hosts.write_text(SECRET)
            target=root/SECRET;target.write_text(SECRET);nss=root/'nsswitch.conf';nss.symlink_to(target)
            original_lstat=m.Path.lstat
            def lstat(path,*args,**kw):
                info=original_lstat(path,*args,**kw)
                return SimpleNamespace(st_mode=info.st_mode,st_uid=0)
            with patch.object(m,'RESOLVER_PATHS',{'hosts':hosts,'nss':nss}),patch.object(m.Path,'lstat',lstat):
                public,private=m.resolver_path_metadata()
            self.assertFalse(public['hosts']['target_is_symlink']);self.assertFalse(public['hosts']['desired_mount_path_differs'])
            self.assertTrue(public['nss']['target_is_symlink']);self.assertTrue(public['nss']['desired_mount_path_differs'])
            self.assertTrue(public['nss']['canonical_target_is_root_owned_regular'])
            self.assertNotIn(SECRET,json.dumps(public));self.assertNotIn(directory,json.dumps(public))
            self.assertEqual(private['nss']['canonical_target'],str(target))

    def test_public_output_cap_no_raw_dump(self):
        with patch('sys.stdout',new_callable=io.StringIO) as out:
            m.emit({'too_large':'x'*40000})
            self.assertEqual(json.loads(out.getvalue())['reason'],'public_output_limit')
            self.assertLess(len(out.getvalue()),32768)


if __name__=='__main__':unittest.main()
