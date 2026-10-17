import unittest,runpy,pathlib,json,re,ast
R=pathlib.Path(__file__).parent
class Review(unittest.TestCase):
 def test_insert_and_update_columns_match_reviewed_source(self):
  permissions=json.loads((R/'column-permissions.json').read_text())
  text='\n'.join((R/p).read_text() for p in ['reference-materials.ts','reference-collect-only.ts'])
  actual={}
  for table,cols in re.findall(r'INSERT INTO (\w+)\s*\(([^)]+)\)',text):actual.setdefault((table,'INSERT'),set()).update(c.strip() for c in cols.split(','))
  for table,body in re.findall(r'UPDATE (\w+) SET\s+(.*?)\s+WHERE',text,re.S):actual.setdefault((table,'UPDATE'),set()).update(re.findall(r'(?:^|,)\s*(\w+)\s*=',body))
  for (table,action),cols in actual.items():self.assertEqual(set(permissions[table][action]),cols,(table,action))
  for t,a in permissions.items():
   for op in a:
    if op in ('INSERT','UPDATE'):self.assertIn((t,op),actual)
 def test_read_side_columns(self):
  p=json.loads((R/'column-permissions.json').read_text())
  self.assertEqual(p['sources']['SELECT'],'*')
  self.assertTrue({'author','language','body_html','body_status','media','x_post','processing_state','revision','identity_key'}<=set(p['articles']['SELECT']))
 def test_no_broad_write_grants(self):
  sql=(R/'grants.sql').read_text()
  self.assertNotRegex(sql,r'GRANT (?:UPDATE|INSERT|ALL) ON')
  self.assertNotIn('TO fixture_app',sql)
  self.assertNotIn('GRANT DELETE',sql)
  self.assertEqual(sql.count('ON SEQUENCE'),1)
  self.assertIn('GRANT USAGE ON SEQUENCE public.fetch_runs_id_seq',sql)
  self.assertIn('NOLOGIN NOINHERIT NOSUPERUSER',sql)
 def test_cleanup_does_not_delete_material(self):
  sql=(R/'revoke.sql').read_text();self.assertNotRegex(sql,r'\b(?:DELETE|TRUNCATE|DROP|REASSIGN)\b');self.assertIn('NOLOGIN PASSWORD NULL',sql)
 def test_network_renderer_rejects_private_and_app_identity(self):
  f=runpy.run_path(str(R/'render-network.py'))['render']
  d={'uid':1500,'forbidden_uids':[0,2345,1001],'hosts':{h:['8.8.8.8'] for h in ['www.microsoft.com','www.journalofaccountancy.com','www.accountingtoday.com']}}
  v=f(d);self.assertIn('ip daddr 127.0.0.1 tcp dport 65439',v['nft']);self.assertIn('counter reject',v['nft']);self.assertNotIn('flush',v['nft']);self.assertEqual(v['nsswitch'],'hosts: files\n')
  d['uid']=2345
  with self.assertRaises(AssertionError):f(d)
  d['uid']=1500;d['hosts']['www.microsoft.com']=['127.0.0.1']
  with self.assertRaises(AssertionError):f(d)
 def test_counts_only_and_three_item_limit(self):
  f=runpy.run_path(str(R/'run.py'))['summary']
  rows=[dict(sourceId=s,found=20,processed=1,created=1,revised=0,reason='SECRET_BODY') for s in ['collect-dynamics-finance','collect-journal-accountancy','collect-accounting-today']]
  self.assertNotIn('SECRET_BODY',json.dumps(f(rows)))
  rows[0]['processed']=2
  with self.assertRaises(AssertionError):f(rows)
 def test_unit_limits_and_no_remote_grant(self):
  s=(R/'aifinance-collect-once.service').read_text()
  for v in ['User=aifinance-collect-once','MemoryMax=256M','TasksMax=32','TimeoutStartSec=120','Restart=no','KillMode=control-group','NoNewPrivileges=yes','ProtectSystem=strict','ReadWritePaths=/var/lib/aifinance-collect-once'] :self.assertIn(v,s)
  self.assertNotIn('\n[Install]',s);self.assertNotIn('sudo',s)
 def test_python_syntax_only_no_operator_execution(self):
  for p in R.glob('*.py'):ast.parse(p.read_text())
if __name__=='__main__':unittest.main(verbosity=2)
