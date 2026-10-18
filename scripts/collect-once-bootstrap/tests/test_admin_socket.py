import contextlib,io,json,os,pathlib,runpy,subprocess,tempfile,types,unittest
from unittest.mock import patch
R=pathlib.Path(__file__).parent;M=runpy.run_path(str(R/'bootstrap.py'));DB=M['Database']
def local():
 d=DB.__new__(DB);d.local_identity=(200,201);d.socket='/run/postgresql';d.env=dict(M['ENV'],HOME='/nonexistent',PGHOST=d.socket,PGPORT='65439',PGDATABASE='fixture_db',PGUSER='postgres',PGPASSFILE='/dev/null',PGCONNECT_TIMEOUT='3');return d
class SocketAdmin(unittest.TestCase):
 def test_explicit_mode_failure_never_prompts_or_falls_back(self):
  g=M['main'].__globals__
  with patch.object(g['os'],'geteuid',return_value=0),patch.object(g['sys'].stdin,'isatty',return_value=True),patch.object(g['sys'],'argv',['bootstrap.py','check','--admin-auth','local-socket','--admin-socket','/run/postgresql']),patch.object(DB,'local_socket',side_effect=M['Refused']('fixture_connection_failed')) as connect,patch.object(g['getpass'],'getpass') as prompt:
   with self.assertRaises(M['Refused']):M['main']()
  connect.assert_called_once();prompt.assert_not_called()
 def test_socket_cannot_be_supplied_to_uri_mode(self):
  g=M['main'].__globals__
  with patch.object(g['os'],'geteuid',return_value=0),patch.object(g['sys'].stdin,'isatty',return_value=True),patch.object(g['sys'],'argv',['bootstrap.py','check','--admin-socket','/run/postgresql']),patch.object(g['getpass'],'getpass') as prompt:
   with self.assertRaisesRegex(M['Refused'],'explicit_admin_auth'):M['main']()
  prompt.assert_not_called()
 def test_admin_process_drops_identity_and_clears_groups(self):
  d=local();g=d.admin_process.__func__.__globals__;result=subprocess.CompletedProcess([],0,b't',b'')
  with patch.dict(g,{'socket_endpoint':lambda *a:d.socket}),patch.object(g['subprocess'],'run',return_value=result) as run:
   self.assertEqual(d.sql('SELECT 1',True),'t')
  args=run.call_args;self.assertEqual(args.args[0][0],'/usr/lib/postgresql/17/bin/psql');k=args.kwargs
  self.assertEqual((k['user'],k['group'],k['extra_groups']),(200,201,[]));self.assertEqual(k['cwd'],'/');self.assertEqual(k['umask'],0o077);self.assertIn(b'BEGIN READ ONLY',k['input']);self.assertEqual(k['env']['PGPASSFILE'],'/dev/null');self.assertNotIn('PGPASSWORD',k['env']);self.assertIn('-XwAtq',args.args[0])
 def test_failure_does_not_retry_as_root(self):
  d=local();g=d.admin_process.__func__.__globals__
  with patch.dict(g,{'socket_endpoint':lambda *a:d.socket}),patch.object(g['subprocess'],'run',return_value=subprocess.CompletedProcess([],2,b'',b'synthetic hidden error')) as run:
   with self.assertRaisesRegex(M['Refused'],'database_operation_failed_details_suppressed'):d.sql('SELECT 1',True)
  self.assertEqual(run.call_count,1)
 def test_drop_permission_failure_does_not_retry(self):
  d=local();g=d.admin_process.__func__.__globals__
  with patch.dict(g,{'socket_endpoint':lambda *a:d.socket}),patch.object(g['subprocess'],'run',side_effect=PermissionError('synthetic')) as run:
   with self.assertRaisesRegex(M['Refused'],'admin_identity_drop_or_process_failed'):d.sql('SELECT 1',True)
  self.assertEqual(run.call_count,1)
 def test_collector_login_stays_tcp_and_dedicated(self):
  d=local();g=d.login_probe.__func__.__globals__
  with patch.dict(g,{'cmd':lambda args,input,**kw:subprocess.CompletedProcess([],0,b't',b'')}) as unused:
   calls=[]
   def capture(args,input,**kw):calls.append(kw);return subprocess.CompletedProcess([],0,b't',b'')
   with patch.dict(g,{'cmd':capture}):d.login_probe('synthetic')
  env=calls[0]['env'];self.assertEqual(env['PGHOST'],'127.0.0.1');self.assertEqual(env['PGUSER'],'aifinance_collect_once');self.assertEqual(env['PGPASSWORD'],'synthetic');self.assertNotIn('user',calls[0])
 def test_socket_directory_scope_refused(self):
  for p in ['/tmp','/','/run/postgresql/../other','relative']:
   with self.assertRaisesRegex(M['Refused'],'unapproved_admin_socket'):M['socket_endpoint'](p,200,201)
 def test_cleanup_mode_mismatch_stops_before_actions(self):
  with tempfile.TemporaryDirectory() as t:
   root=pathlib.Path(t);(root/'state.json').write_text(json.dumps({'admin_auth':{'mode':'uri'}}));g=M['main'].__globals__;d=local()
   with patch.dict(g,{'STATE':root,'trusted':lambda p:None}),patch.object(g['os'],'geteuid',return_value=0),patch.object(g['sys'].stdin,'isatty',return_value=True),patch.object(g['sys'],'argv',['bootstrap.py','cleanup','--admin-auth','local-socket','--admin-socket','/run/postgresql']),patch.object(DB,'local_socket',return_value=d),patch.object(M['Operator'],'cleanup') as cleanup:
    with self.assertRaisesRegex(M['Refused'],'cleanup_admin_auth_mismatch'):M['main']()
   cleanup.assert_not_called()
 def test_backup_uses_fd_no_password_and_readonly(self):
  d=local();g=d.admin_process.__func__.__globals__;out=io.BytesIO()
  with patch.dict(g,{'socket_endpoint':lambda *a:d.socket}),patch.object(g['subprocess'],'run',return_value=subprocess.CompletedProcess([],0,None,b'')) as run:d.admin_process(['/usr/bin/pg_dump','-w','-Fc'],output=out,timeout=120)
  self.assertIs(run.call_args.kwargs['stdout'],out);self.assertEqual(run.call_args.kwargs['env']['PGOPTIONS'],'-cdefault_transaction_read_only=on');self.assertEqual(run.call_args.kwargs['user'],200)
 def test_socket_endpoint_owner_type_and_permissions(self):
  import stat
  def check(change):
   def metadata(p):
    socket=p.name.startswith('.s.PGSQL.')
    values=dict(st_uid=200 if socket or str(p)=='/run/postgresql' else 0,st_gid=201 if str(p)=='/run/postgresql' else 0,st_mode=(stat.S_IFSOCK|0o777) if socket else (stat.S_IFDIR|0o755))
    if str(p)==change[0]:values.update(change[1])
    return types.SimpleNamespace(**values)
   with patch.object(pathlib.Path,'resolve',return_value=pathlib.Path('/run/postgresql')),patch.object(pathlib.Path,'lstat',autospec=True,side_effect=metadata):return M['socket_endpoint']('/var/run/postgresql',200,201)
  self.assertEqual(check(('',{})),'/run/postgresql')
  for change in [('/run/postgresql',{'st_mode':stat.S_IFDIR|0o777}),('/run/postgresql',{'st_uid':1234}),('/run/postgresql/.s.PGSQL.65439',{'st_uid':1234}),('/run/postgresql/.s.PGSQL.65439',{'st_mode':stat.S_IFREG|0o600})]:
   with self.assertRaises(M['Refused']):check(change)
 def test_local_constructor_does_not_inherit_credentials(self):
  g=DB.local_socket.__func__.__globals__
  with patch.object(g['os'],'geteuid',return_value=0),patch.object(g['pwd'],'getpwnam',return_value=types.SimpleNamespace(pw_uid=200,pw_gid=201)),patch.dict(g,{'socket_endpoint':lambda *a:'/run/postgresql','trusted_tool':lambda p:None}),patch.dict(os.environ,{'PGPASSWORD':'do-not-inherit','PGSERVICE':'do-not-inherit','PGHOST':'do-not-inherit'}):d=DB.local_socket('/var/run/postgresql')
  self.assertNotIn('PGPASSWORD',d.env);self.assertNotIn('PGSERVICE',d.env);self.assertEqual(d.env['PGHOST'],'/run/postgresql');self.assertEqual(d.env['HOME'],'/nonexistent');self.assertEqual(d.auth_binding()['mode'],'local-socket')
if __name__=='__main__':unittest.main(verbosity=2)
