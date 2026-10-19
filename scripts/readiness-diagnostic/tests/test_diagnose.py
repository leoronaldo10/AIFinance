"""Offline ownership, lifecycle and failure tests. No real systemd assertion."""
import hashlib,json,pathlib,runpy,subprocess,tempfile,types,unittest,os,sys
from unittest.mock import patch,Mock
R=pathlib.Path(__file__).resolve().parents[1]
M=runpy.run_path(str(R/'diagnose.py'));G=M['cleanup'].__globals__
class Lifecycle(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.base=pathlib.Path(self.tmp.name);self.root=self.base/'root';self.inputs=self.base/'input';self.units=self.base/'units';self.old=self.base/'old'
  for p in (self.root,self.units,self.old):p.mkdir()
  self.calls=[];self.guards={'consumed':None}
  def exclusive(p,data,mode=0o600,gid=0):
   with p.open('xb') as f:f.write(data)
  def props(unit,keys,timeout=5):
   v={'LoadState':'not-found','MainPID':'0','ActiveState':'inactive'}
   return {k:v[k] for k in keys}
  self.patch=patch.dict(G,ROOT=self.root,INPUT=self.inputs,UNITS=self.units,OLD=self.old,trusted=lambda p:None,exclusive=exclusive,guard_snapshot=lambda:self.guards.copy(),props=props,systemctl=lambda args,**kw:self.calls.append(args))
  self.patch.start();self.addCleanup(self.patch.stop)
  (self.root/'DIAGNOSTIC.SHA256').write_bytes(b'fixture manifest')
  self.sha=hashlib.sha256(b'fixture manifest').hexdigest()
  (self.root/'guards.json').write_text(json.dumps(self.guards))
 def owned_inputs(self):
  self.inputs.mkdir();(self.inputs/'owner').write_text(self.sha);data=b'hosts: files\n';(self.inputs/'nsswitch.conf').write_bytes(data)
  (self.root/'inputs.json').write_text(json.dumps({'nsswitch.conf':hashlib.sha256(data).hexdigest()}))
 def owned_units(self):
  for u in M['CHILDREN']:(self.units/u).write_text(M['child_text'](u))
  (self.units/M['CONTROLLER']).write_text(M['controller_text'](self.sha))
 def test_cleanup_success_preserves_report_and_original_state(self):
  self.owned_units();self.owned_inputs();M['save_report']({'tests_passed':True})
  self.assertTrue(M['cleanup'](self.sha));r=M['read_report']();self.assertTrue(r['passed']);self.assertTrue(r['final']);self.assertFalse(self.inputs.exists());self.assertFalse(list(self.units.iterdir()))
  self.assertEqual(self.guards,{'consumed':None})
 def test_cleanup_failed_tests_never_pass(self):
  M['save_report']({'tests_passed':False,'reason':'process_uid_matches_failed'});M['cleanup'](self.sha)
  r=M['read_report']();self.assertFalse(r['passed']);self.assertTrue(r['cleanup_complete'])
 def test_changed_unit_preserved_and_not_stopped(self):
  p=self.units/M['SLEEP'];p.write_text('foreign content');self.assertFalse(M['cleanup'](self.sha));self.assertEqual(p.read_text(),'foreign content');self.assertNotIn(['stop',M['SLEEP']],self.calls)
 def test_changed_input_preserved(self):
  self.owned_inputs();(self.inputs/'nsswitch.conf').write_text('changed');self.assertFalse(M['cleanup'](self.sha));self.assertTrue((self.inputs/'nsswitch.conf').exists())
 def test_unknown_input_preserved(self):
  self.owned_inputs();(self.inputs/'foreign').write_text('keep');self.assertFalse(M['cleanup'](self.sha));self.assertTrue((self.inputs/'foreign').exists())
 def test_partial_owned_input_setup_cleaned(self):
  self.owned_inputs();(self.inputs/'nsswitch.conf').unlink();self.assertTrue(M['cleanup'](self.sha));self.assertFalse(self.inputs.exists())
 def test_unowned_input_not_deleted(self):
  self.inputs.mkdir();self.assertFalse(M['cleanup'](self.sha));self.assertTrue(self.inputs.exists())
 def test_audit_change_fails_closed(self):
  M['save_report']({'tests_passed':True});self.guards['consumed']='changed';self.assertFalse(M['cleanup'](self.sha));self.assertIn('original_audit_changed',M['read_report']()['cleanup_errors'])
 def test_session_claim_is_exclusive(self):
  (self.root/'guards.json').unlink();M['claim_session']()
  with self.assertRaises(FileExistsError):M['claim_session']()
 def test_repeat_finished_launch_does_not_start(self):
  (self.root/'validation.started').write_text('claimed');M['save_report']({'final':True,'passed':False})
  with patch.object(M['os'],'uname',return_value=types.SimpleNamespace(nodename='iZ2zedybs3fftu1d9vnx39Z')):M['launch'](self.sha)
  self.assertEqual(self.calls,[])
 def test_no_collection_or_database_code_loaded(self):
  core=runpy.run_path(str(R/'diagnostic_core.py'))
  self.assertNotIn('Database',core);self.assertNotIn('Operator',core)
  for u in M['CHILDREN']:
   text=M['child_text'](u)
   for expected in ('PrivateNetwork=yes','NoNewPrivileges=yes','CapabilityBoundingSet=\n','AmbientCapabilities=\n','ProtectSystem=strict','User=aifinance-collect-once','BindReadOnlyPaths=','-/run/postgresql','-/opt/aifinance/switch'):self.assertIn(expected,text)
   self.assertNotIn('EnvironmentFile=',text);self.assertNotIn('ExecStartPre=',text)
   start=next(x for x in text.splitlines() if x.startswith('ExecStart='));self.assertNotIn('collect',start);self.assertNotIn('psql',start)
 def test_detached_controller_always_has_cleanup(self):
  t=M['controller_text'](self.sha)
  self.assertIn('ExecStopPost=',t);self.assertIn(' cleanup --manifest-sha ',t);self.assertIn('TimeoutStartSec=90',t);self.assertIn('Restart=no',t);self.assertIn('PrivateNetwork=yes',t)
 def test_sanitized_error_does_not_include_secret(self):
  self.assertEqual(M['reason'](RuntimeError('postgres://secret')),'diagnostic_operation_failed')
 def test_nonzero_not_found_unit_is_accepted(self):
  original=M['props']
  with patch.dict(G,systemctl=lambda *a,**kw:types.SimpleNamespace(returncode=1,stdout=b'LoadState=not-found\n')):self.assertEqual(original(M['SLEEP'],('LoadState',)),{'LoadState':'not-found'})
 def test_stop_failure_reported_and_unit_preserved(self):
  self.owned_units()
  def fail(args,**kw):
   if args[0]=='stop':raise M['Refused']('diagnostic_systemctl_failed')
  with patch.dict(G,props=lambda u,k,**kw:{x:'loaded' for x in k},systemctl=fail):self.assertFalse(M['cleanup'](self.sha))
  self.assertTrue((self.units/M['SLEEP']).exists())
 def test_installer_is_parseable_and_pinned(self):
  subprocess.run(['/bin/bash','-n',str(R/'diagnose-install.sh')],check=True)
  t=(R/'diagnose-install.sh').read_text();self.assertIn('?ref=$COMMIT',t);self.assertIn('sha256sum --quiet -c DIAGNOSTIC.SHA256',t);self.assertIn('if ! sudo test -e "$DEST"',t);self.assertIn('trap cleanup_downloads EXIT',t)
 def adapter(self):
  a=M['Adapter'](types.SimpleNamespace(pw_uid=995,pw_gid=996),{'trusted_tool':lambda p:None,'require_cgroup_v2':lambda:None,'verify_cgroup_v2':lambda *a:None});a.verify_profile=lambda u:None;return a
 def test_evidence_writer_rejects_secrets(self):
  a=self.adapter();a.process_diagnostic('process_readiness_failed',{'role':'collector','reason':'process_uid_matches_failed','uids':[0]*4})
  with self.assertRaises(M['Refused']):a.process_diagnostic('failed',{'environment':'SECRET'})
  p=self.root/'events.jsonl';self.assertEqual(p.stat().st_mode&0o777,0o600);self.assertNotIn('SECRET',p.read_text());self.assertIn('python_diagnostic',p.read_text())
 def test_both_children_stop_when_shared_readiness_fails(self):
  def failure(*args,**kw):raise M['Refused']('fixture_failure')
  for u in M['CHILDREN']:
   self.calls.clear()
   with self.assertRaisesRegex(M['Refused'],'fixture_failure'):self.adapter().test(u,{'wait_for_process':failure})
   self.assertEqual(self.calls,[['start','--no-block',u],['stop',u]])
 def test_both_children_wait_for_natural_exit_and_close_sample(self):
  calls=[];closed=[]
  def waiter(*args,**kw):
   calls.append((args[1],str(args[2])));return types.SimpleNamespace(pid=123,evidence={'memory_bytes':268435456},observe_running=lambda s:None,verify_exit=lambda s:None,diagnostic={'unit_transition':{}},close=lambda:closed.append(True))
  def props(u,keys,timeout=5,**kw):
   values={'MainPID':'0','ActiveState':'active','SubState':'exited','Result':'success','ExecMainStatus':'0','ExecMainCode':'1'};return {k:values[k] for k in keys}
  with patch.dict(G,props=props),patch.object(M['os'],'stat',side_effect=lambda p:types.SimpleNamespace(st_ino=1 if p=='/proc/1/ns/net' else 2)):
   for u in M['CHILDREN']:self.assertTrue(self.adapter().test(u,{'wait_for_process':waiter,'EXIT_FIELDS':('MainPID','ActiveState','SubState','Result','ExecMainStatus','ExecMainCode')})['natural_exit'])
  self.assertEqual(calls,[(M['SLEEP'],'/usr/bin/sleep'),(M['PYTHON'],'/usr/bin/python3')]);self.assertEqual(closed,[True,True])
 def test_runtime_failure_report_keeps_readiness_success(self):
  adapter=types.SimpleNamespace(progress={'readiness':True,'exit_verified':False,'natural_exit':False},last={'stage':'process_runtime_failed'},test=Mock(side_effect=M['Refused']('unit_execution_changed')))
  invocation='a'*32
  def properties(unit,keys):return {'MainPID':str(M['os'].getpid()),'InvocationID':invocation} if unit==M['CONTROLLER'] else {'MainPID':'0'}
  with patch.dict(G,props=properties,claim_session=lambda:None,busctl_preflight=lambda:None,prepare_children=lambda:None,Adapter=lambda *a:adapter,cleanup=Mock()),patch.dict(M['os'].environ,INVOCATION_ID=invocation),patch.object(M['signal'],'signal'),patch.object(M['runpy'],'run_path',return_value={}):self.assertFalse(M['run'](self.sha))
  report=M['read_report']();self.assertEqual(len(report['tests']),2)
  for result in report['tests']:self.assertTrue(result['readiness']);self.assertFalse(result['exit_verified']);self.assertFalse(result['natural_exit'])
 def test_terminal_recheck_rejects_changed_result_and_cleans_child(self):
  a=self.adapter();calls=[];close=Mock()
  def verify(state):
   calls.append(state['ExecMainStatus'])
   if state['ExecMainStatus']!='0':raise M['Refused']('diagnostic_natural_exit_failed')
  sample=types.SimpleNamespace(pid=123,observe_running=lambda s:None,verify_exit=verify,close=close)
  rows=iter(['0','1'])
  def properties(unit,keys,timeout=5):
   if keys==('MainPID',):return {'MainPID':'0'}
   return {'MainPID':'0','ActiveState':'active','SubState':'exited','ExecMainStatus':next(rows)}
  with patch.dict(G,props=properties),patch.object(M['os'],'stat',side_effect=lambda p:types.SimpleNamespace(st_ino=1 if p=='/proc/1/ns/net' else 2)):
   with self.assertRaisesRegex(M['Refused'],'diagnostic_natural_exit_failed'):a.test(M['SLEEP'],{'wait_for_process':lambda *a,**kw:sample,'EXIT_FIELDS':('MainPID','ActiveState','SubState','ExecMainStatus')})
  self.assertEqual(calls,['0','1']);self.assertTrue(a.progress['readiness']);self.assertFalse(a.progress['exit_verified']);close.assert_called_once();self.assertIn(['stop',M['SLEEP']],self.calls)
 def test_slow_query_cannot_pass_after_observation_deadline(self):
  a=self.adapter();clock=[100.0];verify=Mock();sample=types.SimpleNamespace(pid=123,observe_running=lambda s:None,verify_exit=verify,close=Mock());timeouts=[]
  def properties(unit,keys,timeout=5):
   if keys==('MainPID',):return {'MainPID':'0'}
   timeouts.append(timeout);clock[0]+=21;return {'MainPID':'0','ActiveState':'active','SubState':'exited'}
  with patch.dict(G,props=properties),patch.object(M['time'],'monotonic',side_effect=lambda:clock[0]),patch.object(M['os'],'stat',side_effect=lambda p:types.SimpleNamespace(st_ino=1 if p=='/proc/1/ns/net' else 2)):
   with self.assertRaisesRegex(M['Refused'],'diagnostic_natural_exit_timeout'):a.test(M['SLEEP'],{'wait_for_process':lambda *a,**kw:sample,'EXIT_FIELDS':('MainPID','ActiveState','SubState')})
  self.assertEqual(timeouts,[2]);verify.assert_not_called();self.assertTrue(a.progress['readiness']);self.assertFalse(a.progress['exit_verified']);sample.close.assert_called_once()
 def test_bundle_rejects_changed_payload_or_manifest(self):
  names=('diagnose.py','diagnose-install.sh','diagnostic_core.py','process_readiness.py')
  for n in names:(self.root/n).write_text('fixture')
  data=''.join(hashlib.sha256(b'fixture').hexdigest()+'  '+n+'\n' for n in names).encode();(self.root/'DIAGNOSTIC.SHA256').write_bytes(data);sha=hashlib.sha256(data).hexdigest()
  with patch.object(M['os'],'geteuid',return_value=0):
   M['verify_bundle'](sha)
   (self.root/'diagnose.py').write_text('changed')
   with self.assertRaisesRegex(M['Refused'],'diagnostic_file_changed'):M['verify_bundle'](sha)
   with self.assertRaisesRegex(M['Refused'],'diagnostic_manifest_changed'):M['verify_bundle']('0'*64)
 def test_live_repeat_launch_does_not_start_or_cleanup(self):
  (self.root/'validation.started').write_text('claimed');M['save_report']({'final':False})
  with patch.object(M['os'],'uname',return_value=types.SimpleNamespace(nodename='iZ2zedybs3fftu1d9vnx39Z')),patch.dict(G,props=lambda u,k:{'ActiveState':'activating','LoadState':'loaded'}):M['launch'](self.sha)
  self.assertEqual(self.calls,[]);self.assertFalse(M['read_report']()['final'])
 def test_show_explicitly_requests_all_and_retains_empty_scalar(self):
  seen=[]
  def command(args,**kw):seen.append(args);return types.SimpleNamespace(returncode=0,stdout=b'DropInPaths=\n')
  with patch.dict(G,systemctl=command):self.assertEqual(M['props'](M['SLEEP'],('DropInPaths',)),{'DropInPaths':''})
  self.assertEqual(seen,[['show',M['SLEEP'],'--all','--property=DropInPaths']])
 def test_missing_scalar_reports_exact_name_never_assumes_empty(self):
  with patch.dict(G,systemctl=lambda *a,**kw:types.SimpleNamespace(returncode=0,stdout=b'User=fixture\n')):
   with self.assertRaises(M['Refused']) as caught:M['props'](M['SLEEP'],('User','DropInPaths'))
  self.assertEqual(caught.exception.evidence['missing'],['DropInPaths']);self.assertEqual(caught.exception.evidence['returncode'],0)
 def test_query_error_is_not_misclassified_missing_properties(self):
  with patch.dict(G,systemctl=lambda *a,**kw:types.SimpleNamespace(returncode=1,stdout=b'')):
   with self.assertRaisesRegex(M['Refused'],'diagnostic_systemctl_failed'):M['props'](M['SLEEP'],('User',))
 def test_duplicate_or_unrequested_property_rejected(self):
  for data in (b'User=a\nUser=a\n',b'User=a\nEnvironment=SECRET\n'):
   with patch.dict(G,systemctl=lambda *a,**kw:types.SimpleNamespace(returncode=0,stdout=data)):
    with self.assertRaisesRegex(M['Refused'],'invalid_unit_properties'):M['props'](M['SLEEP'],('User',))
 def test_typed_arrays_require_exact_types_and_zero_count(self):
  for key,sig in [('ExecStartPre','a(sasbttttuii)'),('EnvironmentFiles','a(sb)')]:
   with patch.object(M['subprocess'],'run',return_value=types.SimpleNamespace(returncode=0,stdout=(sig+' 0\n').encode(),stderr=b'')) as command:
    self.assertTrue(M['typed_empty'](M['SLEEP'],key)['empty'])
    args=command.call_args.args[0];self.assertIn('--system',args);self.assertEqual(args[-1],key);self.assertIn('aifinance_2dreadiness_2dv3_2dsleep_2dprobe_2eservice',args[-3])
   for data in (b'',b'as 0',b'a(sb) 1 SECRET',b'a(sasbttttuii) 1 SECRET'):
    if data==(sig+' 0').encode():continue
    with patch.object(M['subprocess'],'run',return_value=types.SimpleNamespace(returncode=0,stdout=data,stderr=b'')):
     with self.assertRaisesRegex(M['Refused'],'typed_property_not_verified_empty') as caught:M['typed_empty'](M['SLEEP'],key)
    self.assertNotIn('SECRET',json.dumps(caught.exception.evidence))
 def test_typed_unknown_property_or_bus_failure_fails_closed(self):
  with patch.object(M['subprocess'],'run',return_value=types.SimpleNamespace(returncode=1,stdout=b'',stderr=b'SECRET')):
   with self.assertRaisesRegex(M['Refused'],'typed_property_query_failed'):M['typed_empty'](M['SLEEP'],'ExecStartPre')
 def test_typed_timeout_is_safe_failure(self):
  with patch.object(M['subprocess'],'run',side_effect=subprocess.TimeoutExpired('SECRET',4)):
   with self.assertRaisesRegex(M['Refused'],'typed_property_query_timeout'):M['typed_empty'](M['SLEEP'],'ExecStartPre')
 def test_profile_failure_is_recorded_before_start(self):
  a=M['Adapter'](types.SimpleNamespace(pw_uid=995,pw_gid=996),{})
  with patch.dict(G,props=lambda *a,**kw:(_ for _ in ()).throw(M['Refused']('missing_unit_properties',{'missing':['User'],'returncode':0}))):
   with self.assertRaisesRegex(M['Refused'],'missing_unit_properties'):a.test(M['SLEEP'],{})
  self.assertEqual(a.last['unit_query']['missing'],['User']);self.assertEqual(self.calls,[])
 def test_query_evidence_survives_readiness_failure_record(self):
  a=self.adapter();a.query_failure={'missing':['InvocationID'],'returncode':0};a.process_diagnostic('process_readiness_failed',{'role':'resource_probe','reason':'missing_unit_properties'})
  self.assertEqual(a.last['unit_query']['missing'],['InvocationID'])
 def test_busctl_preflight_distinguishes_missing_untrusted_and_permissions(self):
  with patch.object(pathlib.Path,'lstat',side_effect=FileNotFoundError()):
   with self.assertRaisesRegex(M['Refused'],'busctl_missing'):M['busctl_preflight']()
  with patch.dict(G,trusted=lambda p:(_ for _ in ()).throw(M['Refused']('untrusted_diagnostic_path'))):
   with self.assertRaisesRegex(M['Refused'],'busctl_untrusted_path'):M['busctl_preflight']()
  with patch.object(M['os'],'access',return_value=False):
   with self.assertRaisesRegex(M['Refused'],'busctl_not_executable'):M['busctl_preflight']()
 def test_busctl_preflight_precedes_child_setup(self):
  prepare=Mock();clean=Mock();invocation='a'*32
  with patch.dict(G,props=lambda *a:{'MainPID':str(M['os'].getpid()),'InvocationID':invocation},claim_session=lambda:None,busctl_preflight=Mock(side_effect=M['Refused']('busctl_missing')),prepare_children=prepare,cleanup=clean),patch.dict(M['os'].environ,INVOCATION_ID=invocation),patch.object(M['signal'],'signal'),patch.object(M['runpy'],'run_path',return_value={}):
   self.assertFalse(M['run'](self.sha))
  prepare.assert_not_called();clean.assert_called_once_with(self.sha,final=False);self.assertEqual(M['read_report']()['reason'],'busctl_missing')
class InstallerFlow(unittest.TestCase):
 """Execute the real Bash installer with local downloads and privilege/launch stubs."""
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.base=pathlib.Path(self.tmp.name)
  self.home=self.base/'home';self.root=self.base/'root';self.bin=self.base/'bin'
  for p in (self.home,self.root,self.bin):p.mkdir()
  self.v1=self.root/'aifinance-readiness-diagnostic-v1';self.v1.mkdir();(self.v1/'report.json').write_text('old report');(self.v1/'validation.started').write_text('old marker')
  self.v2=self.root/'aifinance-readiness-diagnostic-v2';self.v2.mkdir();(self.v2/'report.json').write_text('old v2 report');(self.v2/'validation.started').write_text('old v2 marker')
  self.before={str(p.relative_to(self.root)):p.read_bytes() for d in (self.v1,self.v2) for p in d.iterdir()}
  self.installer=self.base/'installer.sh';self.installer.write_text((R/'diagnose-install.sh').read_text().replace('/root/',str(self.root)+'/'))
  shim=self.bin/'shim';shim.write_text('#!'+sys.executable+'\n'+'''import os,sys,pathlib,shutil,urllib.parse,json
name=pathlib.Path(sys.argv[0]).name;a=sys.argv[1:]
if name=='id':print('ecs-user');sys.exit(0)
if name=='hostname':print('iZ2zedybs3fftu1d9vnx39Z');sys.exit(0)
if name=='curl':
 if os.environ.get('FIXTURE_DOWNLOAD_FAIL'):sys.exit(22)
 url=next(x for x in a if x.startswith('https://'));file=urllib.parse.urlsplit(url).path.rsplit('/',1)[1];shutil.copyfile(pathlib.Path(os.environ['FIXTURE_SOURCE'])/file,a[a.index('-o')+1]);sys.exit(0)
assert name=='sudo'
if a==['-v']:sys.exit(0)
if a[0]=='install':
 for flag in ('-o','-g'):
  i=a.index(flag);del a[i:i+2]
if len(a)>3 and a[0]=='/usr/bin/python3' and a[3].endswith('/diagnose.py'):
 p=pathlib.Path(a[3]).parent;mode=a[4]
 assert p.name=='aifinance-readiness-diagnostic-v3'
 if mode=='launch':
  marker=p/'fixture.started'
  if not marker.exists():marker.write_text('one session')
 elif mode=='status':print(json.dumps({'final':True,'passed':True,'cleanup_complete':True}))
 else:raise AssertionError('unexpected mode')
 sys.exit(0)
os.execvp(a[0],a)
''');shim.chmod(0o755)
  for n in ('id','hostname','curl','sudo'):(self.bin/n).symlink_to(shim)
  self.env=dict(os.environ,PATH=str(self.bin)+':/usr/bin:/bin',HOME=str(self.home),FIXTURE_SOURCE=str(R));self.sha=hashlib.sha256((R/'DIAGNOSTIC.SHA256').read_bytes()).hexdigest()
 def invoke(self):return subprocess.run(['/bin/bash',str(self.installer),'f'*40,self.sha],env=self.env,capture_output=True,text=True,timeout=15)
 def assert_old(self):self.assertEqual({str(p.relative_to(self.root)):p.read_bytes() for d in (self.v1,self.v2) for p in d.iterdir()},self.before)
 def test_new_v3_install_and_repeat_preserve_v1_v2(self):
  first=self.invoke();self.assertEqual(first.returncode,0,first.stderr);self.assertIn('DIAGNOSTIC_EXIT=0',first.stdout)
  v2=self.root/'aifinance-readiness-diagnostic-v3';marker=(v2/'fixture.started').stat()
  self.env['FIXTURE_DOWNLOAD_FAIL']='1';second=self.invoke();self.assertEqual(second.returncode,0,second.stderr);self.assertEqual((v2/'fixture.started').stat().st_mtime_ns,marker.st_mtime_ns);self.assert_old()
  self.assertFalse(list(self.home.iterdir()));self.assertEqual(sorted(p.name for p in self.root.iterdir()),[self.v1.name,self.v2.name,v2.name])
 def test_corrupted_existing_v3_stops_before_launch(self):
  self.assertEqual(self.invoke().returncode,0);v2=self.root/'aifinance-readiness-diagnostic-v3';(v2/'diagnose.py').write_text('changed');(v2/'fixture.started').unlink()
  self.assertNotEqual(self.invoke().returncode,0);self.assertFalse((v2/'fixture.started').exists());self.assert_old()
 def test_download_failure_does_not_install_or_launch(self):
  self.env['FIXTURE_DOWNLOAD_FAIL']='1';self.assertNotEqual(self.invoke().returncode,0);self.assertFalse((self.root/'aifinance-readiness-diagnostic-v3').exists());self.assertFalse(list(self.home.iterdir()));self.assert_old()
if __name__=='__main__':unittest.main(verbosity=2)
