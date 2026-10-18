"""Real disposable PG17 TCP/SCRAM tests. No production endpoint or service access.
OS root ownership and systemd remain unit-tested; local fixture runs as current uid.
"""
import contextlib,io,json,os,pathlib,runpy,shutil,subprocess,tempfile,time,unittest
from unittest.mock import patch
R=pathlib.Path(__file__).resolve().parents[1]
H=runpy.run_path(str(R/'retry-hba.py'));T=runpy.run_path(str(R/'retry-once.py'))
BIN=pathlib.Path(os.environ['RETRY_TEST_PG_BIN']).resolve();SHARE=pathlib.Path(os.environ['RETRY_TEST_PG_SHARE']).resolve()
REAL=subprocess.run
class RetryTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.temp=tempfile.TemporaryDirectory(prefix='aifinance-retry-ci-');cls.root=pathlib.Path(cls.temp.name);cls.data=cls.root/'data';cls.socket=cls.root/'socket';cls.socket.mkdir();cls.port='56441'
  REAL([str(BIN/'initdb'),'-D',str(cls.data),'-L',str(SHARE),'-U','postgres','--auth-local=trust','--auth-host=scram-sha-256','--no-locale'],capture_output=True,check=True,timeout=30)
  cls.original=b'local all all trust\n';(cls.data/'pg_hba.conf').write_bytes(cls.original)
  REAL([str(BIN/'pg_ctl'),'-D',str(cls.data),'-l',str(cls.root/'server.log'),'-o',f'-h 127.0.0.1 -k {cls.socket} -p {cls.port}', '-w','start'],capture_output=True,check=True,timeout=30)
  cls.review=cls.root/'review';cfg=runpy.run_path(str(R/'configure.py'));cfg['render'](cls.review,cfg['bindings']('aifinance_preview',int(cls.port),'aifinance_app','fixture_deploy',2345))
  cls.m=runpy.run_path(str(cls.review/'bootstrap.py'))
  class DB:
   def sql(self,q,readonly=False):
    if readonly:q='BEGIN READ ONLY;'+q+';ROLLBACK;'
    p=REAL([str(BIN/'psql'),'-XwAtq','-v','ON_ERROR_STOP=1','-h',str(cls.socket),'-p',cls.port,'-U','postgres','-d',getattr(self,'database','postgres')],input=q.encode(),capture_output=True,timeout=15)
    if p.returncode:raise AssertionError('fixture admin SQL failed')
    return p.stdout.decode().strip()
  cls.admin=DB();cls.admin.sql('CREATE DATABASE aifinance_preview');cls.admin.database='aifinance_preview'
  cls.admin.sql((R/'tests/synthetic-schema.sql').read_text()+"ALTER TABLE sources ADD collect_only boolean NOT NULL DEFAULT false;ALTER TABLE articles ADD collect_only boolean NOT NULL DEFAULT false,ADD processing_state text DEFAULT 'new',ADD processing_queued_at timestamptz,ADD processing_retry_at timestamptz;CREATE ROLE aifinance_app NOLOGIN;GRANT SELECT ON sources,articles,article_revisions,article_discoveries,fetch_runs TO aifinance_app;INSERT INTO sources(id,name,kind) VALUES('fixture','fixture','rss');")
 @classmethod
 def tearDownClass(cls):
  REAL([str(BIN/'pg_ctl'),'-D',str(cls.data),'-m','fast','-w','stop'],capture_output=True,check=True,timeout=20);cls.temp.cleanup()
 def setUp(self):
  self.audit=pathlib.Path(tempfile.mkdtemp(dir=self.root));self.hba=H['TemporaryHBA'](self.admin,self.audit,os.getuid())
  self.path_patch=patch.dict(self.hba.inspect.__func__.__globals__,{'safe_path':lambda p,uid:None});self.path_patch.start();self.addCleanup(self.path_patch.stop)
  self.db=self.m['Database'].__new__(self.m['Database']);self.db.local_identity=None;self.db.env={};self.db.sql=self.admin.sql
 def tearDown(self):
  self.admin.sql("DO $$ BEGIN IF EXISTS(SELECT FROM pg_roles WHERE rolname='aifinance_collect_once') THEN ALTER ROLE aifinance_collect_once NOLOGIN PASSWORD NULL;DROP OWNED BY aifinance_collect_once;DROP ROLE aifinance_collect_once;END IF;END $$;")
  (self.data/'pg_hba.conf').write_bytes(self.original);self.hba.reload()
 def tcp(self,password,q="SELECT current_user",database='aifinance_preview',role='aifinance_collect_once'):
  env={'PATH':'/usr/bin:/bin','PGHOST':'127.0.0.1','PGPORT':self.port,'PGDATABASE':database,'PGUSER':role,'PGPASSWORD':password,'PGCONNECT_TIMEOUT':'3','PGPASSFILE':'/dev/null','LC_ALL':'C'}
  return REAL([str(BIN/'psql'),'-XwAtq','-v','ON_ERROR_STOP=1'],input=q.encode(),env=env,capture_output=True,timeout=10)
 def role(self):self.db.create_role('a'*32);self.db.activate('synthetic-password')
 def test_real_scram_hba_permissions_cleanup_restore(self):
  self.hba.inspect();self.role()
  p=self.tcp('synthetic-password');self.assertNotEqual(p.returncode,0);self.assertIn(b'no pg_hba.conf entry',p.stderr)
  self.hba.install()
  self.assertNotEqual(self.tcp('wrong-password').returncode,0)
  self.assertEqual(self.tcp('synthetic-password',"BEGIN READ ONLY;SELECT current_user='aifinance_collect_once' AND current_setting('transaction_read_only')='on';ROLLBACK;").stdout.strip(),b't')
  self.assertNotEqual(self.tcp('synthetic-password',database='postgres').returncode,0)
  self.assertNotEqual(self.tcp('synthetic-password',role='aifinance_app').returncode,0)
  self.assertEqual(self.tcp('synthetic-password',"INSERT INTO articles(id,source_id,identity_key,url,title,discovered_at,timeline_at,collect_only,processing_state) VALUES('fixture','fixture','fixture','https://example.invalid','fixture',now(),now(),true,'skipped');").returncode,0)
  for query in ("DELETE FROM articles","UPDATE sources SET enabled=true","CREATE TABLE forbidden(x int)"):
   self.assertNotEqual(self.tcp('synthetic-password',query).returncode,0)
  conf=self.audit/'conf';conf.mkdir();state=self.audit/'state';state.mkdir();op=self.m['Operator'](self.db);op.state={'nonce':'a'*32,'files':[],'role_attempted':True};op.save=lambda:None
  with patch.dict(op.cleanup.__func__.__globals__,{'CONF':conf,'STATE':state}),contextlib.redirect_stdout(io.StringIO()) as out:op.cleanup()
  self.assertIn('"complete": true',out.getvalue());self.db.verify_disabled('a'*32)
  self.assertNotEqual(self.tcp('synthetic-password').returncode,0);self.hba.restore();self.assertEqual((self.data/'pg_hba.conf').read_bytes(),self.original)
  # Restore really loaded: briefly enabling the fixture identity cannot connect without HBA.
  self.db.activate('synthetic-password');p=self.tcp('synthetic-password');self.assertIn(b'no pg_hba.conf entry',p.stderr)
 def test_real_probe_stdin_and_tcp_environment(self):
  self.hba.inspect();self.hba.install();self.role()
  db=self.m['Database'].__new__(self.m['Database']);db.local_identity=(os.getuid(),os.getgid());db.env={'PGHOST':str(self.socket)}
  def adapter(args,input,**kw):
   self.assertEqual(kw['env']['PGHOST'],'127.0.0.1');self.assertEqual(kw['env']['PGUSER'],'aifinance_collect_once');self.assertIn(b'BEGIN READ ONLY',input)
   return REAL([str(BIN/'psql')]+args[1:],input=input,env=kw['env'],capture_output=True,timeout=10)
  with patch.dict(db.login_probe.__func__.__globals__,{'cmd':adapter}):db.login_probe('synthetic-password')
  self.hba.restore()
 def test_concurrent_hba_preserved(self):
  self.hba.inspect();self.hba.install();p=self.data/'pg_hba.conf';p.write_bytes(p.read_bytes()+b'# another operator\n')
  with self.assertRaises(H['Refused']):self.hba.restore()
  self.assertTrue(p.read_bytes().endswith(b'# another operator\n'));self.assertTrue(self.hba.changed)
 def test_restore_after_reload_failure(self):
  self.hba.inspect();real=self.hba.reload;self.hba.reload=lambda:(_ for _ in ()).throw(H['Refused']('fixture_reload_failure'))
  with self.assertRaises(H['Refused']):self.hba.install()
  self.hba.reload=real;self.hba.restore();self.assertEqual((self.data/'pg_hba.conf').read_bytes(),self.original)
 def test_existing_hba_rule_refused(self):
  p=self.data/'pg_hba.conf';p.write_bytes(self.original+H['RULE']);self.hba.reload()
  with self.assertRaises(H['Refused']):self.hba.inspect()
 def test_invalid_hba_refused(self):
  p=self.data/'pg_hba.conf';p.write_bytes(self.original+b'not a valid rule\n')
  with self.assertRaises(H['Refused']):self.hba.inspect()
 def test_duplicate_attempt_directory_refused(self):
  p=self.audit/'retry-001';self.assertTrue(T['absent'](p));p.mkdir();self.assertFalse(T['absent'](p))
  with self.assertRaises(FileExistsError):p.mkdir()
 def test_hba_recovery_after_interruption(self):
  self.hba.inspect();self.hba.install();db=self.admin;db.local_identity=(os.getuid(),os.getgid())
  with patch.dict(T['load_hba_recovery'].__globals__,{'AUDIT':self.audit,'trusted_receipt':lambda p:None}):recovered=T['load_hba_recovery'](H,db)
  recovered.restore();self.assertEqual((self.data/'pg_hba.conf').read_bytes(),self.original)
 def test_matcher_refuses_broad_and_unknown(self):
  row={'type':'host','database':['all'],'user_name':['all'],'address':'127.0.0.1','netmask':'255.255.255.255','error':None}
  with self.assertRaises(H['Refused']):H['no_matching_rule']([row])
  row['address']='localhost'
  with self.assertRaises(H['Refused']):H['no_matching_rule']([row])
 def test_pending_configuration_edit_refused(self):
  p=self.data/'postgresql.conf';original=p.read_bytes();p.write_bytes(original+b'\n# pending change\n')
  try:
   with self.assertRaises(H['Refused']):self.hba.inspect()
  finally:p.write_bytes(original);self.hba.reload()
 def test_existing_role_regrant_and_revoke_real(self):
  self.role();self.db.deactivate('a'*32);self.db.verify_disabled('a'*32)
  with self.assertRaises(T['Refused']):T['regrant_existing'](self.db,self.review,'b'*32)
  T['regrant_existing'](self.db,self.review,'a'*32)
  self.assertEqual(self.admin.sql("SELECT NOT rolcanlogin FROM pg_roles WHERE rolname='aifinance_collect_once'"),'t')
  self.db.activate('synthetic-password');self.hba.inspect();self.hba.install()
  self.assertEqual(self.tcp('synthetic-password','SELECT id FROM sources').returncode,0)
  self.db.deactivate('a'*32);self.db.verify_disabled('a'*32);self.hba.restore()
 def test_attempt_claim_preserves_old_state_and_rejects_repeat(self):
  state=self.audit/'old';state.mkdir();old=state/'state.json';old.write_bytes(b'{"phase":"disabled"}')
  audit=state/'retry-001'
  with patch.dict(T['claim_attempt'].__globals__,{'AUDIT':audit,'STATE':state}):
   T['claim_attempt']({})
   with self.assertRaises(FileExistsError):T['claim_attempt']({})
  self.assertEqual(old.read_bytes(),(audit/'original-state.json').read_bytes());self.assertFalse((state/'consumed').exists());self.assertTrue((audit/'started').exists())
 def test_cleanup_attempts_hba_and_health_when_db_cleanup_fails(self):
  events=[]
  class Op:
   def cleanup(self):events.append('db');raise ValueError('fixture')
  class Hba:
   changed=True
   def restore(self):events.append('hba');self.changed=False
  with patch.dict(T['cleanup_all'].__globals__,{'AUDIT':self.audit,'website':lambda *a:events.append('health'),'emit':lambda *a,**k:None}):
   with self.assertRaises(T['Refused']):T['cleanup_all']({},Op(),Hba())
  self.assertEqual(events,['db','hba','health'])
 def test_never_started_guard_rejects_consumed_and_service_start(self):
  state=self.audit/'state';state.mkdir();(state/'state.json').write_text('{}');root=self.audit/'runtime';(root/'bin').mkdir(parents=True)
  for n in ('run.py','consume.py'):shutil.copyfile(self.review/n,root/'bin'/n);(root/'bin'/n).chmod(0o555)
  old={'phase':'disabled','role_attempted':True,'artifact_sha256':T['ARTIFACT_SHA'],'nonce':'a'*32}
  class Op:
   def property(self,u,k):return {'MainPID':'0','ActiveState':'inactive','ExecMainStartTimestampMonotonic':'7','ExecMainPID':'0'}[k]
  m={'trusted':lambda p:None,'ROOT':root,'CONF':self.audit/'conf','UNIT':'fixture'}
  with patch.dict(T['validate_never_started'].__globals__,{'STATE':state,'REVIEW':self.review}):
   (state/'consumed').write_text('do not remove')
   with self.assertRaisesRegex(T['Refused'],'collector_start_or_secret_evidence'):T['validate_never_started'](m,Op(),old)
   # Fixture only: separately test a different state directory with no latch.
   other=self.audit/'other-state';other.mkdir();(other/'state.json').write_text('{}')
   with patch.dict(T['validate_never_started'].__globals__,{'STATE':other}):
    with self.assertRaisesRegex(T['Refused'],'collector_previous_start_evidence'):T['validate_never_started'](m,Op(),old)
   self.assertEqual((state/'consumed').read_text(),'do not remove')
 def test_actual_retry_probe_and_sanitized_failure(self):
  self.role()
  def adapter(args,input,**kw):
   self.assertEqual(args[0],'/usr/lib/postgresql/17/bin/psql');self.assertEqual(kw['env']['PGPORT'],'55432');kw['env']['PGPORT']=self.port
   return REAL([str(BIN/'psql')]+args[1:],input=input,env=kw['env'],capture_output=True,timeout=10)
  m=dict(self.m,cmd=adapter)
  with contextlib.redirect_stdout(io.StringIO()) as out:
   with self.assertRaises(T['Refused']):T['probe_tcp'](m,'synthetic-password')
  self.assertIn('no_hba_entry',out.getvalue());self.assertNotIn('synthetic-password',out.getvalue())
  self.hba.inspect();self.hba.install()
  with contextlib.redirect_stdout(io.StringIO()) as out:T['probe_tcp'](m,'synthetic-password')
  self.assertIn('retry_tcp_scram_probe_passed',out.getvalue())
  with contextlib.redirect_stdout(io.StringIO()) as out:
   with self.assertRaises(T['Refused']):T['probe_tcp'](m,'wrong-password')
  self.assertIn('password_auth_failed',out.getvalue());self.assertNotIn('wrong-password',out.getvalue());self.hba.restore()
 def test_never_started_guard_accepts_only_clean_owned_fixture(self):
  self.role();self.db.deactivate('a'*32)
  state=self.audit/'old-state';state.mkdir();(state/'state.json').write_text('{}');(state/'before.dump').write_bytes(b'fixture backup')
  root=self.audit/'runtime';(root/'bin').mkdir(parents=True)
  for n in ('run.py','consume.py'):shutil.copyfile(self.review/n,root/'bin'/n);(root/'bin'/n).chmod(0o555)
  old={'phase':'disabled','role_attempted':True,'artifact_sha256':T['ARTIFACT_SHA'],'nonce':'a'*32,'backup_sha256':T['sha'](state/'before.dump'),'backup_bytes':14}
  db=self.db
  class Op:
   def __init__(self):self.db=db
   def property(self,u,k):return {'MainPID':'0','ActiveState':'inactive','ExecMainStartTimestampMonotonic':'0','ExecMainPID':'0','NRestarts':'0','UnitFileState':'static','LoadState':'not-found'}[k]
  m={'trusted':lambda p:None,'ROOT':root,'CONF':self.audit/'conf','UNIT':'fixture'}
  with patch.dict(T['validate_never_started'].__globals__,{'STATE':state,'REVIEW':self.review}):
   T['validate_never_started'](m,Op(),old)
   self.db.activate('synthetic-password')
   with self.assertRaises(self.m['Refused']):T['validate_never_started'](m,Op(),old)
 def test_new_included_configuration_file_detected_before_reload(self):
  p=self.data/'postgresql.conf';original=p.read_bytes();extra=self.data/'conf-extra';extra.mkdir(exist_ok=True)
  p.write_bytes(original+b"\ninclude_dir = 'conf-extra'\n");self.hba.reload();self.hba.inspect()
  added=extra/'new.conf';added.write_text("work_mem = '5MB'\n")
  try:
   with self.assertRaisesRegex(H['Refused'],'concurrent_configuration_file_set_change'):self.hba.install()
   self.assertEqual((self.data/'pg_hba.conf').read_bytes(),self.original)
  finally:added.unlink();p.write_bytes(original);self.hba.reload()
if __name__=='__main__':unittest.main(verbosity=2)
