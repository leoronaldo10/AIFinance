import json,pathlib,subprocess,unittest,runpy,os
R=pathlib.Path(__file__).parent
BIN=os.environ['COLLECT_TEST_PSQL']
BASE=[BIN,'-XwAtq','-v','ON_ERROR_STOP=1','-h',os.environ['COLLECT_TEST_SOCKET'],'-p',os.environ['COLLECT_TEST_PORT'],'-U',os.environ['COLLECT_TEST_ADMIN']]
def sql(s,db='collector_fixture_ci',ok=True):
 p=subprocess.run(BASE+['-d',db],input=s,text=True,capture_output=True)
 if ok and p.returncode:raise AssertionError('synthetic SQL failed: '+p.stderr)
 return p
class Grants(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  sql('CREATE DATABASE collector_fixture_ci;',db='postgres')
  core=(R/'synthetic-schema.sql').read_text()
  sql(core+'''ALTER TABLE sources ADD collect_only boolean NOT NULL DEFAULT false;
  ALTER TABLE articles ADD collect_only boolean NOT NULL DEFAULT false,ADD processing_state text DEFAULT 'new',ADD processing_queued_at timestamptz,ADD processing_retry_at timestamptz;
  CREATE ROLE fixture_app NOLOGIN;GRANT SELECT ON sources,articles,article_revisions,article_discoveries,fetch_runs TO fixture_app;
  CREATE TABLE receipts(id int);
  INSERT INTO sources(id,name,kind,enabled,participation_mode,collect_only,site_fulltext) VALUES('collect-dynamics-finance','synthetic','rss',false,'isolated',true,false);''')
 @classmethod
 def tearDownClass(cls):
  sql('DROP DATABASE collector_fixture_ci;',db='postgres');sql('DROP ROLE IF EXISTS aifinance_collect_once;DROP ROLE fixture_app;',db='postgres')
 def audit(self):return json.loads(sql((R/'catalog-audit.sql').read_text()).stdout)
 def test_01_clean_preflight(self):
  a=self.audit();self.assertTrue(a['admin_is_superuser']);self.assertTrue(a['role_absent']);self.assertTrue(a['sequence_matches']);self.assertTrue(a['application_readonly'])
  for k in ['public_object_privileges','public_column_privileges','public_schema_create','public_definer_execute','custom_triggers','row_security','unsafe_defaults','unsafe_check_functions']:self.assertFalse(a[k],k)
  self.assertTrue(a['public_connect_temp'])
 def test_02_public_table_and_column_rejected(self):
  for grant,revoke,key in [('GRANT INSERT ON articles TO PUBLIC','REVOKE INSERT ON articles FROM PUBLIC','public_object_privileges'),('GRANT UPDATE(title) ON articles TO PUBLIC','REVOKE UPDATE(title) ON articles FROM PUBLIC','public_column_privileges')]:
   sql(grant);self.assertTrue(self.audit()[key]);sql(revoke);self.assertFalse(self.audit()[key])
 def test_03_trigger_and_definer_detected(self):
  sql("CREATE FUNCTION review_trigger() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RETURN NEW;END$$;CREATE TRIGGER review_t BEFORE INSERT ON articles FOR EACH ROW EXECUTE FUNCTION review_trigger();")
  self.assertTrue(self.audit()['custom_triggers']);sql('DROP TRIGGER review_t ON articles;DROP FUNCTION review_trigger();')
  sql('CREATE FUNCTION review_definer() RETURNS int LANGUAGE sql SECURITY DEFINER AS $$SELECT 1$$;')
  self.assertTrue(self.audit()['public_definer_execute']);sql('REVOKE EXECUTE ON FUNCTION review_definer() FROM PUBLIC;');self.assertFalse(self.audit()['public_definer_execute']);sql('DROP FUNCTION review_definer();')
 def test_035_custom_defaults_and_checks_detected(self):
  sql("CREATE FUNCTION review_default() RETURNS text LANGUAGE sql AS $$SELECT 'synthetic'::text$$;ALTER TABLE articles ALTER COLUMN author SET DEFAULT review_default();")
  self.assertTrue(self.audit()['unsafe_defaults']);sql('ALTER TABLE articles ALTER COLUMN author DROP DEFAULT;DROP FUNCTION review_default();');self.assertFalse(self.audit()['unsafe_defaults'])
  sql('CREATE FUNCTION review_check() RETURNS boolean LANGUAGE sql AS $$SELECT true$$;ALTER TABLE articles ADD CONSTRAINT review_check_constraint CHECK(review_check());')
  self.assertTrue(self.audit()['unsafe_check_functions']);sql('ALTER TABLE articles DROP CONSTRAINT review_check_constraint;DROP FUNCTION review_check();');self.assertFalse(self.audit()['unsafe_check_functions'])
 def test_04_grants_real_writes_and_denials(self):
  sql((R/'grants.sql').read_text().replace('fixture_db','collector_fixture_ci'))
  role='SET ROLE aifinance_collect_once;'
  sql(role+'''BEGIN;SELECT * FROM sources WHERE id='collect-dynamics-finance' FOR UPDATE;
  INSERT INTO articles(id,source_id,identity_key,url,title,discovered_at,timeline_at,collect_only,processing_state)
  VALUES('synthetic_1','collect-dynamics-finance','synthetic:1','https://example.invalid/1','synthetic',now(),now(),true,'skipped') ON CONFLICT(identity_key) DO NOTHING RETURNING id;
  SELECT id,source_id,collect_only,revision,content_hash,backfill,title,body_text,excerpt FROM articles WHERE identity_key='synthetic:1' FOR UPDATE;
  UPDATE articles SET collect_only=true,processing_state='skipped',processing_queued_at=NULL,processing_retry_at=NULL,author=coalesce(NULL,author),language=coalesce(NULL,language),body_html=coalesce(NULL,body_html),body_status=body_status,media=media,x_post=x_post,revision=revision+1,updated_at=now() WHERE id='synthetic_1' RETURNING revision;
  INSERT INTO article_revisions(article_id,revision,content_hash,title,body_text) VALUES('synthetic_1',1,'hash','synthetic','summary') ON CONFLICT DO NOTHING;
  INSERT INTO article_discoveries(article_id,source_id,via,discovered_at) VALUES('synthetic_1','collect-dynamics-finance','fetch',now()) ON CONFLICT DO NOTHING;
  UPDATE sources SET cursor='{}',last_fetch_at=now(),last_ok_at=now(),health='ok',fail_count=0,last_error=NULL,updated_at=now() WHERE id='collect-dynamics-finance';
  INSERT INTO fetch_runs(source_id,status,finished_at,found_count,new_count,error,detail) VALUES('collect-dynamics-finance','ok',now(),1,1,NULL,'{}');COMMIT;''')
  for q in ["UPDATE sources SET enabled=true","UPDATE sources SET config='{}'","UPDATE articles SET url='https://example.invalid/2'",'DELETE FROM articles','INSERT INTO receipts VALUES(1)','SELECT * FROM articles','CREATE TABLE public.unapproved(x int)']:
   self.assertNotEqual(sql(role+q,ok=False).returncode,0,q)
  self.assertTrue(self.audit()['application_readonly'])
 def test_05_revoke_twice_preserves_rows(self):
  revoke=(R/'revoke.sql').read_text().replace('fixture_db','collector_fixture_ci')
  sql(revoke);sql(revoke)
  self.assertEqual(sql('SELECT count(*) FROM articles').stdout.strip(),'1')
  self.assertEqual(sql("SELECT rolcanlogin FROM pg_roles WHERE rolname='aifinance_collect_once'").stdout.strip(),'f')
  self.assertNotEqual(sql("SET ROLE aifinance_collect_once;UPDATE sources SET health='ok'",ok=False).returncode,0)
  self.assertEqual(sql("SELECT has_sequence_privilege('aifinance_collect_once','fetch_runs_id_seq','USAGE')").stdout.strip(),'f')
 def test_06_real_activation_and_owned_cleanup_idempotency(self):
  sql('DROP ROLE aifinance_collect_once;')
  m=runpy.run_path(str(R/'bootstrap.py'));db=m['Database'].__new__(m['Database'])
  def adapter(text,readonly=False):
   text=text.replace('fixture_db','collector_fixture_ci')
   if readonly:text='BEGIN READ ONLY;'+text+';ROLLBACK;'
   return sql(text).stdout.strip()
  db.sql=adapter
  nonce='a'*32;db.create_role(nonce);self.assertTrue(db.role_owned(nonce));self.assertFalse(db.role_owned('b'*32))
  db.activate('synthetic_password_not_a_real_credential')
  self.assertEqual(sql("SELECT rolcanlogin AND rolpassword LIKE 'SCRAM-SHA-256$%' AND rolvaliduntil>now() AND rolvaliduntil<now()+interval '11 minutes' FROM pg_authid WHERE rolname='aifinance_collect_once'").stdout.strip(),'t')
  with self.assertRaises(m['Refused']):db.deactivate('b'*32)
  with self.assertRaises(m['Refused']):db.verify_disabled('b'*32)
  self.assertEqual(sql("SELECT rolcanlogin FROM pg_roles WHERE rolname='aifinance_collect_once'").stdout.strip(),'t')
  db.deactivate(nonce);db.verify_disabled(nonce);db.deactivate(nonce);db.verify_disabled(nonce)
  sql('GRANT UPDATE(title) ON articles TO aifinance_collect_once')
  with self.assertRaises(m['Refused']):db.verify_disabled(nonce)
  db.deactivate(nonce);db.verify_disabled(nonce)
  self.assertEqual(sql("SELECT NOT rolcanlogin AND rolpassword IS NULL FROM pg_authid WHERE rolname='aifinance_collect_once'").stdout.strip(),'t')
  self.assertEqual(sql('SELECT count(*) FROM articles').stdout.strip(),'1')
 def test_07_actual_record_validation(self):
  m=runpy.run_path(str(R/'bootstrap.py'));op=m['Operator'](None)
  snapshot=lambda:json.loads(sql((R/'record-snapshot.sql').read_text()).stdout)
  before=snapshot();sql("UPDATE articles SET body_text='short summary',excerpt='short',collect_only=true,processing_state='skipped' WHERE id='synthetic_1'")
  good=snapshot();op.verify_records(before,good)
  for update in ["collect_only=false","processing_state='new'","body_text=repeat('x',2001)","excerpt=repeat('x',2001)"]:
   sql('BEGIN;UPDATE articles SET '+update+" WHERE id='synthetic_1';COMMIT")
   with self.assertRaises(m['Refused']):op.verify_records(good,snapshot())
   sql("UPDATE articles SET body_text='short summary',excerpt='short',collect_only=true,processing_state='skipped' WHERE id='synthetic_1'")
  before=snapshot();sql("UPDATE article_revisions SET body_text=repeat('x',2001)")
  with self.assertRaises(m['Refused']):op.verify_records(before,snapshot())
  sql("UPDATE article_revisions SET body_text='summary'")
 def test_08_actual_readonly_login_probe_local_trust(self):
  from unittest.mock import patch
  m=runpy.run_path(str(R/'bootstrap.py'));db=m['Database'].__new__(m['Database'])
  db.env={'PATH':'/usr/bin:/bin','PGHOST':os.environ['COLLECT_TEST_SOCKET'],'PGPORT':os.environ['COLLECT_TEST_PORT'],'PGDATABASE':'collector_fixture_ci'}
  def adapter(args,input,**kw):
   args=[BIN]+args[1:];query=input.replace(b"current_database()='fixture_db'",b"current_database()='collector_fixture_ci'")
   return subprocess.run(args,input=query,env=kw['env'],capture_output=True,timeout=kw['timeout'])
  g=db.login_probe.__func__.__globals__
  with patch.dict(g,{'cmd':adapter}):
   with self.assertRaises(m['Refused']):db.login_probe('synthetic')
   sql('ALTER ROLE aifinance_collect_once LOGIN')
   db.login_probe('synthetic')
   sql('ALTER ROLE aifinance_collect_once NOLOGIN')
if __name__=='__main__':unittest.main(verbosity=2)
