"""New round's exact HBA marker and recovery on disposable local PG17 only."""
import contextlib,io,os,pathlib,runpy,unittest
from unittest.mock import patch
R=pathlib.Path(__file__).resolve().parents[1]
B=runpy.run_path(str(R/'tests/test_retry_hba.py'));N=runpy.run_path(str(R/'retry-002.py'));G=N['recover_hba'].__globals__
class Retry002PG(B['RetryTests']):
 def setUp(self):
  super().setUp();self.h=N['hba_module']();self.hba=self.h['TemporaryHBA'](self.admin,self.audit,os.getuid())
  base=self.h['TemporaryHBA'].__mro__[1];p=patch.dict(base.inspect.__globals__,safe_path=lambda *a:None);p.start();self.addCleanup(p.stop)
  p=patch.dict(G,AUDIT=self.audit,trusted=lambda p:None);p.start();self.addCleanup(p.stop);self.admin.local_identity=(os.getuid(),os.getgid())
 def test_002_real_scram_new_marker_recovery_and_revoke(self):
  self.hba.inspect();self.role();self.assertNotEqual(self.tcp('synthetic-password').returncode,0);self.hba.install()
  self.assertIn(b'retry-002 BEGIN',(self.data/'pg_hba.conf').read_bytes());self.assertNotIn(b'retry-001',(self.data/'pg_hba.conf').read_bytes())
  self.assertEqual(self.tcp('synthetic-password').returncode,0)
  self.assertNotEqual(self.tcp('synthetic-password',"UPDATE sources SET enabled=true").returncode,0)
  restored=N['recover_hba'](self.h,self.admin);restored.restore();self.assertEqual((self.data/'pg_hba.conf').read_bytes(),self.original)
  self.assertNotEqual(self.tcp('synthetic-password').returncode,0);self.db.deactivate('a'*32);self.db.verify_disabled('a'*32)
 def test_002_recovery_preserves_concurrent_hba_change(self):
  self.hba.inspect();self.hba.install();p=self.data/'pg_hba.conf';p.write_bytes(p.read_bytes()+b'# concurrent admin\n')
  recovered=N['recover_hba'](self.h,self.admin)
  with self.assertRaisesRegex(self.h['Refused'],'hba_concurrent_change_preserved'):recovered.restore()
  self.assertTrue(p.read_bytes().endswith(b'# concurrent admin\n'))
 def test_002_receipt_tamper_refused(self):
  self.hba.inspect();self.hba.install();p=self.audit/'hba.original';p.write_bytes(b'wrong original')
  with self.assertRaisesRegex(N['Refused'],'hba_recovery_receipt_changed'):N['recover_hba'](self.h,self.admin)
 def test_002_recovery_after_reload_failure(self):
  self.hba.inspect();reload_original=self.hba.reload;self.hba.reload=lambda:(_ for _ in ()).throw(RuntimeError('fixture'))
  try:
   with self.assertRaises(RuntimeError):self.hba.install()
  finally:self.hba.reload=reload_original
  recovered=N['recover_hba'](self.h,self.admin);recovered.restore();self.assertEqual((self.data/'pg_hba.conf').read_bytes(),self.original)
if __name__=='__main__':
 suite=unittest.TestSuite(Retry002PG(n) for n in unittest.defaultTestLoader.getTestCaseNames(Retry002PG) if n.startswith('test_002_'))
 result=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not result.wasSuccessful())
