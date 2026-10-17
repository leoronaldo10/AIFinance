import unittest,runpy,pathlib,tempfile,tarfile,io,hashlib,contextlib,os
from unittest.mock import patch
R=pathlib.Path(__file__).parent
M=runpy.run_path(str(R/'bootstrap.py'));Operator=M['Operator'];Refused=M['Refused']
class Flow(Operator):
 def __init__(self,fail=None):self.calls=[];self.fail=fail
 def step(self,name):
  self.calls.append(name)
  if self.fail==name:raise Refused('synthetic_failure')
 def preflight(self):self.step('preflight')
 def prepare(self):self.step('prepare')
 def probe(self):self.step('probe')
 def backup(self):self.step('backup')
 def activate(self):self.step('activate')
 def run_once(self):self.step('run_once')
 def cleanup(self):self.step('cleanup')
class Bootstrap(unittest.TestCase):
 def test_preflight_failure_has_no_write_phase(self):
  f=Flow('preflight')
  with self.assertRaises(Refused):f.execute()
  self.assertEqual(f.calls,['preflight'])
 def test_every_postwrite_failure_cleans_up(self):
  order=['preflight','prepare','probe','backup','activate','run_once']
  for stage in order[1:]:
   f=Flow(stage)
   with self.subTest(stage=stage):
    with self.assertRaises(Refused):f.execute()
    self.assertEqual(f.calls,order[:order.index(stage)+1]+['cleanup'])
 def test_success_order(self):
  f=Flow();f.execute();self.assertEqual(f.calls,['preflight','prepare','probe','backup','activate','run_once','cleanup'])
 def test_admin_target_validation_no_value_output(self):
  fn=M['scrub_admin']
  for u in ['postgres://admin:synthetic@other:65439/fixture_db','postgres://admin:synthetic@127.0.0.1:5432/fixture_db','postgres://admin:synthetic@127.0.0.1:65439/other','postgres://admin:synthetic@127.0.0.1:65439/fixture_db?options=bad']:
   with self.assertRaises(Refused):fn(u)
  with contextlib.redirect_stdout(io.StringIO()) as out:e=fn('postgres://admin:synthetic@127.0.0.1:65439/fixture_db')
  self.assertEqual(out.getvalue(),'');self.assertEqual(e['PGDATABASE'],'fixture_db');self.assertEqual(e['PGPASSWORD'],'synthetic')
 def test_audit_blocks_all_dangerous_flags(self):
  ok={k:True for k in ['admin_is_superuser','role_absent','sequence_matches','application_readonly']}
  bad=['public_object_privileges','public_column_privileges','public_schema_create','public_definer_execute','custom_triggers','row_security','unsafe_defaults','unsafe_check_functions']
  ok.update({k:False for k in bad});M['audit_pass'](ok)
  for k in bad:
   d=dict(ok);d[k]=True
   with self.assertRaises(Refused):M['audit_pass'](d)
 def test_archive_rejects_traversal_secrets_symlink_parent(self):
  fn=M['artifact_members'];g=fn.__globals__
  for member,link,child in [('../escape',None,None),('.env',None,None),('safe','/etc/passwd',None),('safe','inside','safe/child')]:
   with tempfile.TemporaryDirectory() as d:
    p=pathlib.Path(d)/'fixture.tar'
    with tarfile.open(p,'w') as t:
     m=tarfile.TarInfo(member)
     if link:m.type=tarfile.SYMTYPE;m.linkname=link;t.addfile(m)
     else:m.size=1;t.addfile(m,io.BytesIO(b'x'))
     if child:
      m=tarfile.TarInfo(child);m.size=1;t.addfile(m,io.BytesIO(b'x'))
    with patch.dict(g,{'trusted':lambda p:None}):
     with self.assertRaises(Refused):fn(p,hashlib.sha256(p.read_bytes()).hexdigest())
 def test_new_files_exclusive_and_existing_untouched(self):
  fn=M['write_new'];g=fn.__globals__
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d)/'existing';p.write_bytes(b'original')
   with patch.dict(g,{'trusted':lambda p:None}):
    with self.assertRaises(FileExistsError):fn(p,b'replacement')
   self.assertEqual(p.read_bytes(),b'original')
 def test_dns_expiry_before_network_write(self):
  op=Operator(None);op.resolved_at=0
  with patch.dict(Operator.activate.__globals__,{'cmd':lambda *a,**k:self.fail('network command before expiry check')}):
   with self.assertRaises(Refused):op.activate()
   with self.assertRaises(Refused):op.run_once()
 def test_login_probe_requires_readonly_identity_success(self):
  import subprocess
  db=M['Database'].__new__(M['Database']);db.env={}
  g=db.login_probe.__func__.__globals__
  def fake(args,input,**kw):
   self.assertIn(b'BEGIN READ ONLY',input);self.assertEqual(kw['env']['PGUSER'],'aifinance_collect_once')
   return subprocess.CompletedProcess(args,0,b't\n',b'')
  with patch.dict(g,{'cmd':fake}):db.login_probe('synthetic')
  for code,out in [(1,b''),(0,b'f\n')]:
   with patch.dict(g,{'cmd':lambda *a,**k:subprocess.CompletedProcess([],code,out,b'')}):
    with self.assertRaises(Refused):db.login_probe('synthetic')
 def test_downstream_updates_and_deletes_fail(self):
  op=Operator(None)
  with self.assertRaises(Refused):op.verify_records({'receipts':{'hash1':1}},{'receipts':{'hash2':1}})
  with self.assertRaises(Refused):op.verify_records({'articles':{'id':{'hash':'a','valid':True}}},{'articles':{}})
 def test_cleanup_verification_failure_never_complete(self):
  import types
  for failure in ('unit','database','credential','nft'):
   with tempfile.TemporaryDirectory() as directory:
    root=pathlib.Path(directory);conf=root/'conf';conf.mkdir();state=root/'state';state.mkdir()
    db=types.SimpleNamespace(deactivate=lambda nonce:None,verify_disabled=lambda nonce:None,audit=lambda:{'application_readonly':True})
    if failure=='database':db.verify_disabled=lambda nonce:(_ for _ in ()).throw(Refused('database_owner_marker_mismatch'))
    op=Operator(db);op.state={'files':['/etc/systemd/system/aifinance-collect-once.service'],'role_attempted':True,'nonce':'a'*32,'network_attempted':True};op.save=lambda:None
    op.property=lambda unit,key:('1' if failure=='unit' else '0') if key=='MainPID' else 'inactive'
    import subprocess
    def fake(args,*a,**k):
     table={'nftables':[{'table':{'name':'aifinance_collect_once_v1','comment':'wrong'}}]} if failure=='nft' else {'nftables':[]}
     return subprocess.CompletedProcess(args,0,__import__('json').dumps(table).encode(),b'')
    if failure=='credential':(conf/'database.env').mkdir()
    with patch.dict(Operator.cleanup.__globals__,{'CONF':conf,'STATE':state,'cmd':fake}):
     with contextlib.redirect_stdout(io.StringIO()) as output:
      with self.assertRaises(Refused):op.cleanup()
     self.assertIn('"complete": false',output.getvalue());self.assertEqual(op.state['phase'],'cleanup_incomplete')
 def test_trusted_system_tool_symlink_and_untrusted_path(self):
  import types
  real=pathlib.Path.lstat
  def root_owned(p):
   st=real(p);return types.SimpleNamespace(st_uid=0,st_mode=st.st_mode)
  with patch.object(pathlib.Path,'lstat',root_owned):M['trusted_tool'](pathlib.Path('/usr/bin/python3'))
  with tempfile.TemporaryDirectory() as directory:
   p=pathlib.Path(directory)/'python';p.symlink_to('/usr/bin/python3')
   with self.assertRaises(Refused):M['trusted_tool'](p)
 def test_latch_write_access_is_only_dedicated_state_directory(self):
  unit=(R/'aifinance-collect-once.service').read_text()
  self.assertEqual([x for x in unit.splitlines() if x.startswith('ReadWritePaths=')],['ReadWritePaths=/var/lib/aifinance-collect-once'])
  self.assertIn('self.mkdir(STATE)',(R/'bootstrap.py').read_text())
  self.assertIn('def mkdir(self,p,mode=0o700',(R/'bootstrap.py').read_text())
if __name__=='__main__':unittest.main(verbosity=2)
