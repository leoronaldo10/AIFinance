"""Real disposable PG SQL/dump tests; credential switching is separately unit-tested.
This runner is non-root: intercept only the OS uid/gid transition and fixed binary/socket
locations. All SQL, pg_dump output and pg_restore validation execute real PG tools.
"""
import contextlib,io,json,os,pathlib,runpy,subprocess,tempfile,unittest
from unittest.mock import patch
R=pathlib.Path(__file__).parent;BIN=pathlib.Path(os.environ['COLLECT_TEST_PSQL']).parent;SOCKET=os.environ['COLLECT_TEST_SOCKET'];PORT=os.environ['COLLECT_TEST_PORT'];ADMIN=os.environ['COLLECT_TEST_ADMIN'];NAME='socket_admin_fixture_ci'
REAL_RUN=subprocess.run
BASE=[str(BIN/'psql'),'-XwAtq','-v','ON_ERROR_STOP=1','-h',SOCKET,'-p',PORT,'-U',ADMIN]
def sql(q,db=NAME):
 p=REAL_RUN(BASE+['-d',db],input=q.encode(),capture_output=True,timeout=15)
 if p.returncode:raise AssertionError('fixture SQL failed')
 return p.stdout.decode().strip()
class SocketPostgres(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  assert ADMIN=='postgres','use a disposable cluster initialized with postgres admin'
  sql('CREATE DATABASE '+NAME,'postgres');sql((R/'synthetic-schema.sql').read_text()+"ALTER TABLE sources ADD collect_only boolean NOT NULL DEFAULT false;ALTER TABLE articles ADD collect_only boolean NOT NULL DEFAULT false,ADD processing_state text DEFAULT 'new',ADD processing_queued_at timestamptz,ADD processing_retry_at timestamptz;CREATE ROLE fixture_app NOLOGIN;GRANT SELECT ON sources,articles,article_revisions,article_discoveries,fetch_runs TO fixture_app;INSERT INTO sources(id,name,kind,enabled,participation_mode,collect_only) VALUES('collect-dynamics-finance','fixture','rss',false,'isolated',true);")
 @classmethod
 def tearDownClass(cls):
  sql('DROP DATABASE '+NAME,'postgres');sql('DROP ROLE IF EXISTS aifinance_collect_once;DROP ROLE fixture_app;','postgres')
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=pathlib.Path(self.tmp.name)
  for p in R.iterdir():
   if p.suffix in ('.py','.sql'):(self.root/p.name).write_text(p.read_text().replace('fixture_db',NAME).replace('65439',PORT))
  self.m=runpy.run_path(str(self.root/'bootstrap.py'));self.db=self.m['Database'].__new__(self.m['Database']);self.db.local_identity=(os.getuid(),os.getgid());self.db.socket=SOCKET;self.db.env=dict(self.m['ENV'],HOME='/nonexistent',PGHOST=SOCKET,PGPORT=PORT,PGDATABASE=NAME,PGUSER=ADMIN,PGPASSFILE='/dev/null',PGCONNECT_TIMEOUT='3');self.calls=[]
  def adapter(args,**kw):
   self.assertEqual((kw.pop('user'),kw.pop('group'),kw.pop('extra_groups')),(os.getuid(),os.getgid(),[]));self.assertNotIn('PGPASSWORD',kw['env']);self.assertEqual(kw['env']['PGPASSFILE'],'/dev/null');self.calls.append(pathlib.Path(args[0]).name)
   return REAL_RUN([str(BIN/pathlib.Path(args[0]).name)]+args[1:],**kw)
  self.addCleanup(patch.stopall);patch.dict(self.db.admin_process.__func__.__globals__,{'socket_endpoint':lambda *a:SOCKET}).start();patch.object(subprocess,'run',side_effect=adapter).start()
 def test_readonly_identity_and_write_rejection(self):
  self.db.verify_admin_identity();self.assertEqual(self.db.sql('SELECT current_user',True),'postgres')
  with self.assertRaises(self.m['Refused']):self.db.sql('CREATE TABLE must_not_exist(x int)',True)
  self.assertEqual(sql("SELECT to_regclass('must_not_exist') IS NULL"),'t')
 def test_grants_activation_revoke_and_cleanup(self):
  nonce='a'*32;self.db.create_role(nonce)
  self.db.activate('synthetic-test-password');self.assertEqual(sql("SELECT rolcanlogin FROM pg_roles WHERE rolname='aifinance_collect_once'"),'t')
  sql("SET ROLE aifinance_collect_once;INSERT INTO articles(id,source_id,identity_key,url,title,discovered_at,timeline_at,collect_only,processing_state) VALUES('fixture','collect-dynamics-finance','fixture','https://example.invalid/fixture','fixture',now(),now(),true,'skipped');")
  conf=self.root/'conf';conf.mkdir();state=self.root/'state';state.mkdir();op=self.m['Operator'](self.db);op.state={'files':[],'role_attempted':True,'nonce':nonce,'network_attempted':False,'admin_auth':self.db.auth_binding()};op.save=lambda:None
  with patch.dict(op.cleanup.__func__.__globals__,{'CONF':conf,'STATE':state}),contextlib.redirect_stdout(io.StringIO()) as output:op.cleanup();op.cleanup()
  self.assertIn('"complete": true',output.getvalue());self.db.verify_disabled(nonce)
  self.assertEqual(sql('SELECT count(*) FROM articles'),'1');self.assertEqual(sql("SELECT NOT has_any_column_privilege('fixture_app','articles','INSERT,UPDATE')"),'t')
  sql('DROP ROLE aifinance_collect_once')
 def test_actual_dump_uses_exclusive_fd_and_restore_list(self):
  state=self.root/'state';state.mkdir(mode=0o700);op=self.m['Operator'](self.db);op.state={};op.save=lambda:None
  def command(args,*a,**kw):
   self.assertEqual(args[0],'/usr/bin/pg_restore');p=REAL_RUN([str(BIN/'pg_restore')]+args[1:],capture_output=True,timeout=15);self.assertEqual(p.returncode,0);return p
  with patch.dict(op.backup.__func__.__globals__,{'STATE':state,'trusted':lambda p:None,'cmd':command}),patch.object(os,'fchown') as chown,contextlib.redirect_stdout(io.StringIO()):op.backup()
  chown.assert_called_once();self.assertEqual(chown.call_args.args[1:],(0,0));self.assertEqual((state/'before.dump').stat().st_mode&0o777,0o600);self.assertEqual((state/'before.dump').read_bytes()[:5],b'PGDMP');self.assertIn('pg_dump',self.calls)
  previous=(state/'before.dump').read_bytes()
  with patch.dict(op.backup.__func__.__globals__,{'STATE':state,'trusted':lambda p:None}):
   with self.assertRaises(FileExistsError):op.backup()
  self.assertEqual(previous,(state/'before.dump').read_bytes())
 def test_backup_symlink_is_not_followed(self):
  state=self.root/'state';state.mkdir();outside=self.root/'outside';outside.write_bytes(b'preserve');(state/'before.dump').symlink_to(outside);op=self.m['Operator'](self.db)
  with patch.dict(op.backup.__func__.__globals__,{'STATE':state,'trusted':lambda p:None}):
   with self.assertRaises(FileExistsError):op.backup()
  self.assertEqual(outside.read_bytes(),b'preserve');self.assertNotIn('pg_dump',self.calls)
if __name__=='__main__':unittest.main(verbosity=2)
