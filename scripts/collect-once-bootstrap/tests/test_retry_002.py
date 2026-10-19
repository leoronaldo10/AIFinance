"""Fixed-round adapter fixtures. No actual root/systemd/network/production DB."""
import contextlib,copy,hashlib,io,json,os,pathlib,runpy,signal,subprocess,sys,tempfile,types,unittest
from unittest.mock import patch
R=pathlib.Path(__file__).resolve().parents[1]
N=runpy.run_path(str(R/'retry-002.py'));G=N['main'].__globals__
class Retry002(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=pathlib.Path(self.tmp.name);self.state=self.root/'state';self.state.mkdir();self.audit=self.state/'retry-002';self.prev=self.state/'retry-001';self.prev.mkdir();self.oldreview=self.root/'old-review';self.review=self.root/'review';self.units=self.root/'units';self.units.mkdir()
  self.patch=patch.dict(G,STATE=self.state,AUDIT=self.audit,PREVIOUS=self.prev,OLD_REVIEW=self.oldreview,REVIEW=self.review,UNITS=self.units,trusted=lambda p:None);self.patch.start();self.addCleanup(self.patch.stop)
  self.old={'nonce':'a'*32,'phase':'disabled','artifact_sha256':N['ARTIFACT_SHA'],'admin_auth':{'fixture':True},'role_attempted':True}
  (self.state/'state.json').write_text(json.dumps(self.old));self.fill_history()
 def fill_history(self):
  (self.prev/'original-state.json').write_text(json.dumps(self.old));(self.prev/'started').write_bytes(b'approved retry-001; never repeat\n');(self.prev/'before.dump').write_bytes(b'old-backup')
  prev=dict(self.old,network_attempted=False,network_owned=False,backup_sha256=N['digest'](b'old-backup'),backup_bytes=10)
  (self.prev/'state.json').write_text(json.dumps(prev));(self.prev/'events.jsonl').write_text(json.dumps({'stage':'retry_stopped','reason':'probe_identity_or_capabilities'})+'\n');(self.prev/'cleanup-100.json').write_text(json.dumps({'complete':True,'errors':[]}))
 def test_history_accepts_exact_prestart_cleaned_attempt_and_pins(self):
  pins=N['history'](self.old);self.assertIn(str(self.prev/'started'),pins);self.assertEqual(pins,N['tree_history']())
 def test_history_rejects_activation_success_or_missing_proof(self):
  for rows in ([],[{'stage':'retry_stopped','reason':'other'}],[{'stage':'retry_stopped','reason':'probe_identity_or_capabilities'},{'stage':'retry_tcp_scram_probe_passed'}]):
   (self.prev/'events.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in rows))
   with self.assertRaises(N['Refused']):N['history'](self.old)
 def test_history_rejects_hba_receipt_and_cleanup_failure(self):
  (self.prev/'hba-receipt.json').write_text('{}')
  with self.assertRaisesRegex(N['Refused'],'previous_reached_hba'):N['history'](self.old)
  (self.prev/'hba-receipt.json').unlink();(self.prev/'cleanup-200.json').write_text('{"complete":false,"errors":["failed"]}')
  with self.assertRaisesRegex(N['Refused'],'previous_cleanup_incomplete'):N['history'](self.old)
 def test_history_rejects_modified_backup_or_original(self):
  (self.prev/'before.dump').write_bytes(b'changed')
  with self.assertRaisesRegex(N['Refused'],'previous_backup_changed'):N['history'](self.old)
 def test_claim_preserves_old_files_and_refuses_repeat_even_without_consumed(self):
  before=N['history'](self.old);state=N['claim'](self.old,before);self.assertEqual(state['phase'],'retry002_claimed');self.assertEqual(N['tree_history'](),before)
  with self.assertRaises(FileExistsError):N['claim'](self.old,before)
  self.assertFalse((self.state/'consumed').exists());self.assertTrue((self.audit/'claim-complete').exists())
 def test_partial_claim_is_never_resumed(self):
  original=G['exclusive'];calls=[]
  def fail(p,data):
   calls.append(p.name)
   if p.name=='started':raise OSError('power loss')
   return original(p,data)
  with patch.dict(G,exclusive=fail):
   with self.assertRaises(OSError):N['claim'](self.old,{})
  self.assertTrue(self.audit.exists());self.assertFalse((self.audit/'claim-complete').exists())
  with self.assertRaises(FileExistsError):N['claim'](self.old,{})
 def test_atomic_state_update_ignores_stale_state_next_without_deleting_it(self):
  self.audit.mkdir();p=self.audit/'state.json';p.write_text('{}');(self.audit/'state.next').write_text('old evidence');N['save'](p,{'phase':'disabled'})
  self.assertEqual(json.loads(p.read_text()),{'phase':'disabled'});self.assertEqual((self.audit/'state.next').read_text(),'old evidence')
 def test_real_flock_blocks_second_operator_and_releases_after_exception(self):
  with N['lock']():
   with self.assertRaisesRegex(N['Refused'],'retry002_busy'):
    with N['lock']():pass
  with N['lock']():pass
 def test_symlink_lock_refused(self):
  (self.state/'retry-002.lock').symlink_to(self.state/'state.json')
  with self.assertRaises(OSError):
   with N['lock']():pass
 def test_parser_rejects_arbitrary_round_reset_and_implicit_approval(self):
  for args in (['run','--round','retry-003'],['reset'],['run','--state-dir','/tmp/x']):
   with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):N['parser']().parse_args(args)
  a=N['parser']().parse_args(['run','--manifest-sha256','a'*64]);self.assertFalse(a.approve_retry_002_once)
 def review_fixture(self):
  cfg=runpy.run_path(str(R/'configure.py'));values=cfg['bindings']('aifinance_preview',55432,'aifinance_app','aifinance-deploy',2345);render=cfg['rendered_templates'](values)
  legacy={k:v for k,v in render.items() if k!='process_readiness.py'};base=(R/'retry-002-base-bootstrap.py.txt').read_text()
  for k,v in values.items():base=base.replace(k,v)
  legacy['bootstrap.py']=base;legacy['aifinance-collect-once.service']=render['aifinance-collect-once.service'].replace('RemainAfterExit=yes\n','')
  self.oldreview.mkdir()
  for n,text in legacy.items():(self.oldreview/n).write_text(text)
  (self.oldreview/'SHA256SUMS').write_text(''.join(N['sha'](self.oldreview/n)+'  '+n+'\n' for n in sorted(legacy)))
  artifact=b'fixture immutable runtime';(self.oldreview/'collector-runtime.tar.gz').write_bytes(artifact);h=N['digest'](artifact);(self.oldreview/'RUNTIME.SHA256').write_text(h+'  collector-runtime.tar.gz\n')
  p=patch.dict(G,ARTIFACT_SHA=h);p.start();self.addCleanup(p.stop)
  # Filesystem root ownership only is simulated; full template/hash checks run.
  up=runpy.run_path(str(R/'upgrade-review.py'));real=runpy.run_path
  def loader(path,*a,**kw):
   if str(path)==str(R/'upgrade-review.py'):return up
   return real(path,*a,**kw)
  patcher=patch.object(runpy,'run_path',side_effect=loader);patcher.start();self.addCleanup(patcher.stop)
  return render,legacy
 def test_old_review_exact_match_new_review_installs_and_reuses(self):
  self.review_fixture();before={p.name:N['sha'](p) for p in self.oldreview.iterdir()}
  with contextlib.redirect_stdout(io.StringIO()):N['install']();N['install']()
  N['verify_install']();self.assertEqual({p.name:N['sha'](p) for p in self.oldreview.iterdir()},before);self.assertFalse(self.audit.exists());self.assertEqual(list(self.units.iterdir()),[])
 def test_partial_review_install_can_finish_without_overwriting(self):
  render,_=self.review_fixture();stage=self.review.with_name(self.review.name+'.staging');stage.mkdir();(stage/'bootstrap.py').write_text(render['bootstrap.py'])
  with contextlib.redirect_stdout(io.StringIO()):N['install']()
  self.assertTrue(self.review.exists());self.assertFalse(stage.exists());N['verify_install']()
 def test_partial_install_changed_bytes_refused(self):
  self.review_fixture();stage=self.review.with_name(self.review.name+'.staging');stage.mkdir();(stage/'bootstrap.py').write_text('tampered')
  with self.assertRaisesRegex(N['Refused'],'partial_install_content_changed'):N['install']()
  self.assertEqual((stage/'bootstrap.py').read_text(),'tampered');self.assertFalse(self.review.exists())
 def test_old_review_change_rejected_even_with_recomputed_manifest(self):
  self.review_fixture();p=self.oldreview/'bootstrap.py';p.write_text(p.read_text()+'# modified\n');mf=self.oldreview/'SHA256SUMS';mf.write_text('\n'.join((N['sha'](p)+'  bootstrap.py') if line.endswith('  bootstrap.py') else line for line in mf.read_text().splitlines())+'\n')
  with self.assertRaises(Exception):N['source_review']()
 def test_installed_new_review_tampering_refused(self):
  self.review_fixture()
  with contextlib.redirect_stdout(io.StringIO()):N['install']()
  (self.review/'process_readiness.py').write_text('tampered')
  with self.assertRaisesRegex(N['Refused'],'package_file_changed'):N['verify_install']()
 def units_fixture(self):
  self.review.mkdir();unit='Type=oneshot\nExecStart=/usr/bin/python3 -I -B /opt/aifinance-collect-once/bin/run.py\n';name='aifinance-collect-once.service';(self.review/name).write_text(unit.replace('Type=oneshot\n','Type=oneshot\nRemainAfterExit=yes\n'))
  m={'UNIT':name,'PROBE':'aifinance-collect-once-probe.service','cmd':lambda args:None};legacy={name:unit}
  for n,(before,after) in N['unit_bytes'](m,legacy).items():(self.units/n).write_bytes(before)
  return m,legacy
 def test_unit_switch_and_restore_exact_bytes(self):
  m,legacy=self.units_fixture();pairs=N['unit_bytes'](m,legacy);N['switch_units'](m,legacy)
  for n,(_,new) in pairs.items():self.assertEqual((self.units/n).read_bytes(),new)
  N['switch_units'](m,legacy,True)
  for n,(old,_) in pairs.items():self.assertEqual((self.units/n).read_bytes(),old)
 def test_partial_unit_switch_can_restore_but_concurrent_edit_preserved(self):
  m,legacy=self.units_fixture();pairs=N['unit_bytes'](m,legacy);first=next(iter(pairs));(self.units/first).write_bytes(pairs[first][1]);N['switch_units'](m,legacy,True)
  (self.units/first).write_text('concurrent')
  with self.assertRaisesRegex(N['Refused'],'concurrent_unit_change'):N['switch_units'](m,legacy,True)
  self.assertEqual((self.units/first).read_text(),'concurrent')
 def test_preflight_preserves_old_guard_then_restores_new_configuration(self):
  m,legacy=self.units_fixture();oldverify=lambda:None;op=types.SimpleNamespace(verify_units=oldverify);g={'REVIEW':self.review};called=[]
  class OldOperator:
   def verify_units(self):called.append('old_units')
  def gates(*args):
   self.assertEqual(g['REVIEW'],self.oldreview);op.verify_units();called.append('all_original_gates')
  g['gates']=gates
  with patch.object(runpy,'run_path',return_value={'Operator':OldOperator}):N['preflight'](m,g,op,self.old,legacy)
  self.assertEqual(called,['old_units','all_original_gates']);self.assertEqual(g['REVIEW'],self.review);self.assertIs(op.verify_units,oldverify)
 def test_preflight_guard_failure_not_bypassed_and_scope_restored(self):
  m,legacy=self.units_fixture();op=types.SimpleNamespace(verify_units=lambda:None)
  class OldOperator:
   def verify_units(self):pass
  def fail(*args):raise N['Refused']('collector_start_or_secret_evidence')
  g={'gates':fail}
  with patch.object(runpy,'run_path',return_value={'Operator':OldOperator}):
   with self.assertRaisesRegex(N['Refused'],'collector_start_or_secret_evidence'):N['preflight'](m,g,op,self.old,legacy)
  self.assertEqual(g['REVIEW'],self.review);self.assertFalse(self.audit.exists())
 def test_cleanup_failure_does_not_skip_other_restorations_or_remove_latch(self):
  N['claim'](self.old,N['history'](self.old));(self.state/'consumed').write_text('permanent');events=[]
  def fail():events.append('operator');raise RuntimeError()
  db=types.SimpleNamespace(auth_binding=lambda:self.old['admin_auth']);op=types.SimpleNamespace(cleanup=fail,property=lambda u,k:'0' if k=='MainPID' else 'inactive')
  resolver=types.SimpleNamespace(recover=lambda fn:events.append('resolver_receipt'),restore=lambda:events.append('resolver'))
  g={'make_resolver':lambda *a:resolver,'website':lambda *a:events.append('website')};m={'UNIT':'unit','PROBE':'probe'}
  with patch.dict(G,hba_module=lambda:{},recover_hba=lambda *a:types.SimpleNamespace(restore=lambda:events.append('hba')),switch_units=lambda *a:events.append('units')),contextlib.redirect_stdout(io.StringIO()):
   with self.assertRaisesRegex(N['Refused'],'retry002_cleanup_incomplete'):N['cleanup'](m,g,db,op,self.old,{})
  self.assertEqual(events,['operator','hba','resolver_receipt','resolver','units','website']);self.assertEqual((self.state/'consumed').read_text(),'permanent');self.assertTrue((self.audit/'started').exists())
 def test_execution_failures_always_cleanup_without_second_claim(self):
  for point in ('units','verify','inspect','backup','resolver','probe','hba','activate','interrupt','hangup','run','success'):
   with self.subTest(point=point):
    events=[]
    def step(name):
     events.append(name)
     if point in ('interrupt','hangup') and name=='activate':
      sig=signal.SIGHUP if point=='hangup' else signal.SIGTERM;signal.getsignal(sig)(sig,None)
     if name==point:raise N['Refused']('fixture_'+name)
    resolver=types.SimpleNamespace(install=lambda:(step('resolver') or (0,{}, {'nft':'fixture'})))
    op=types.SimpleNamespace(verify_units=lambda:step('verify'),backup=lambda:step('backup'),resolver=resolver,save=lambda:None,probe=lambda:step('probe'),activate=lambda:step('activate'),run_once=lambda:step('run'))
    h=types.SimpleNamespace(inspect=lambda:step('inspect'),install=lambda:step('hba'));db=types.SimpleNamespace(local_identity=(os.getuid(),os.getgid()))
    with patch.dict(G,tree_history=lambda:{},claim=lambda *a:{},switch_units=lambda *a:step('units'),hba_module=lambda:{'TemporaryHBA':lambda *a:h},cleanup=lambda *a:events.append('cleanup'),exclusive=lambda *a:events.append('completed')):
     if point=='success':N['execute']({'CONF':self.root}, {}, db,op,self.old,{}, {})
     else:
      with self.assertRaises(N['Refused']):N['execute']({'CONF':self.root}, {}, db,op,self.old,{}, {})
    self.assertEqual(events[-1],'cleanup');self.assertEqual(events.count('cleanup'),1)
 def test_repeated_cli_run_refuses_before_loading_or_any_collection(self):
  N['claim'](self.old,N['history'](self.old))
  with patch.dict(G,HELPER=R,load=lambda:self.fail('must not load DB')),patch.object(sys,'argv',['retry-002.py','run','--manifest-sha256',N['sha'](R/'SHA256SUMS'),'--approve-retry-002-once','--exclusive-writer-window']),patch.object(os,'geteuid',return_value=0),patch.object(os,'uname',return_value=types.SimpleNamespace(nodename='iZ2zedybs3fftu1d9vnx39Z')),patch.object(sys.stdin,'isatty',return_value=True),patch.dict(G,lock=contextlib.nullcontext):
   with self.assertRaisesRegex(N['Refused'],'retry002_already_claimed'):N['main']()
 def test_execute_refuses_consumed_before_claim(self):
  (self.state/'consumed').write_text('original latch')
  with patch.dict(G,tree_history=lambda:{},claim=lambda *a:self.fail('must not claim')):
   with self.assertRaisesRegex(N['Refused'],'collector_start_or_secret_evidence'):N['execute']({'CONF':self.root},{},None,None,self.old,{}, {})
  self.assertEqual((self.state/'consumed').read_text(),'original latch')
 def test_cleanup_can_be_repeated_without_consuming_again(self):
  N['claim'](self.old,N['history'](self.old));(self.state/'consumed').write_text('permanent');calls=[]
  db=types.SimpleNamespace(auth_binding=lambda:self.old['admin_auth']);op=types.SimpleNamespace(cleanup=lambda:calls.append('cleanup'),property=lambda u,k:'0' if k=='MainPID' else 'inactive')
  resolver=types.SimpleNamespace(recover=lambda fn:None,restore=lambda:None);g={'make_resolver':lambda *a:resolver,'website':lambda *a:None};m={'UNIT':'unit','PROBE':'probe'}
  with patch.dict(G,hba_module=lambda:{},recover_hba=lambda *a:types.SimpleNamespace(restore=lambda:None),switch_units=lambda *a:None),contextlib.redirect_stdout(io.StringIO()):
   N['cleanup'](m,g,db,op,self.old,{});N['cleanup'](m,g,db,op,self.old,{})
  self.assertEqual(calls,['cleanup','cleanup']);self.assertEqual((self.state/'consumed').read_text(),'permanent');self.assertEqual(len(list(self.audit.glob('cleanup-*.json'))),2)
 def test_missing_explicit_run_approval_refuses_before_db(self):
  with patch.dict(G,HELPER=R,load=lambda:self.fail('must not load DB'),lock=contextlib.nullcontext),patch.object(sys,'argv',['retry-002.py','run','--manifest-sha256',N['sha'](R/'SHA256SUMS')]),patch.object(os,'geteuid',return_value=0),patch.object(os,'uname',return_value=types.SimpleNamespace(nodename='iZ2zedybs3fftu1d9vnx39Z')),patch.object(sys.stdin,'isatty',return_value=True):
   with self.assertRaisesRegex(N['Refused'],'explicit_retry002_scope_required'):N['main']()
 def test_cleanup_main_refuses_same_lock_before_loading_or_stopping_services(self):
  real_fstat=os.fstat
  def root_fstat(fd):
   st=real_fstat(fd);return types.SimpleNamespace(st_uid=0,st_mode=st.st_mode,st_nlink=st.st_nlink)
  with N['lock']():
   with patch.dict(G,HELPER=R,load=lambda:self.fail('cleanup must not load or stop anything')),patch.object(sys,'argv',['retry-002.py','cleanup','--manifest-sha256',N['sha'](R/'SHA256SUMS')]),patch.object(os,'geteuid',return_value=0),patch.object(os,'fstat',side_effect=root_fstat),patch.object(os,'uname',return_value=types.SimpleNamespace(nodename='iZ2zedybs3fftu1d9vnx39Z')),patch.object(sys.stdin,'isatty',return_value=True):
    with self.assertRaisesRegex(N['Refused'],'retry002_busy'):N['main']()
if __name__=='__main__':unittest.main(verbosity=2)
