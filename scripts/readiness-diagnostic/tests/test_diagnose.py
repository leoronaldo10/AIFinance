"""Offline ownership, lifecycle and failure tests. No real systemd assertion."""
import hashlib,json,pathlib,runpy,subprocess,tempfile,types,unittest
from unittest.mock import patch
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
   calls.append((args[1],str(args[2])));return types.SimpleNamespace(pid=123,evidence={'memory_bytes':268435456},observe_running=lambda s:None,close=lambda:closed.append(True))
  def props(u,keys,timeout=5,**kw):
   values={'MainPID':'0','ActiveState':'inactive','Result':'success','ExecMainStatus':'0','ExecMainCode':'1'};return {k:values[k] for k in keys}
  with patch.dict(G,props=props),patch.object(M['os'],'stat',side_effect=lambda p:types.SimpleNamespace(st_ino=1 if p=='/proc/1/ns/net' else 2)):
   for u in M['CHILDREN']:self.assertTrue(self.adapter().test(u,{'wait_for_process':waiter,'FIELDS':('MainPID','ActiveState')})['natural_exit'])
  self.assertEqual(calls,[(M['SLEEP'],'/usr/bin/sleep'),(M['PYTHON'],'/usr/bin/python3')]);self.assertEqual(closed,[True,True])
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
if __name__=='__main__':unittest.main(verbosity=2)
