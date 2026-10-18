import contextlib,io,pathlib,runpy,tempfile,unittest,hashlib
from unittest.mock import patch
R=pathlib.Path(__file__).resolve().parents[1];M=runpy.run_path(str(R/'upgrade-review.py'));C=runpy.run_path(str(R/'configure.py'))
class Upgrade(unittest.TestCase):
 def fixture(self,root):
  old=root/'old';C['render'](old,C['bindings']('fixture_db',65439,'fixture_app','fixture-deploy',2345));base=(R/'upgrade-base-bootstrap.py.txt').read_text()
  for k,v in C['bindings']('fixture_db',65439,'fixture_app','fixture-deploy',2345).items():base=base.replace(k,v)
  (old/'bootstrap.py').write_text(base);self.manifest(old);raw=b'synthetic-runtime';digest=hashlib.sha256(raw).hexdigest();(old/'collector-runtime.tar.gz').write_bytes(raw);(old/'RUNTIME.SHA256').write_text(digest+'  collector-runtime.tar.gz\n');return old,digest
 def manifest(self,root):
  names=[p.name[:-3] for p in (R/'templates').glob('*.in')];(root/'SHA256SUMS').write_text(''.join(hashlib.sha256((root/n).read_bytes()).hexdigest()+'  '+n+'\n' for n in sorted(names)))
 def test_sibling_preserves_old_and_only_changes_bootstrap_and_manifest(self):
  with tempfile.TemporaryDirectory() as t:
   root=pathlib.Path(t);old,d=self.fixture(root);before={p.name:p.read_bytes() for p in old.iterdir()};new=root/'new'
   with patch.dict(M['prepare'].__globals__,{'trusted':lambda p:None}),contextlib.redirect_stdout(io.StringIO()):M['prepare'](old,new,d)
   self.assertEqual(before,{p.name:p.read_bytes() for p in old.iterdir()});self.assertEqual({n for n in before if before[n]!=(new/n).read_bytes()},{'bootstrap.py','SHA256SUMS'})
 def test_modified_old_template_rejected_even_with_updated_manifest(self):
  with tempfile.TemporaryDirectory() as t:
   root=pathlib.Path(t);old,d=self.fixture(root);(old/'bootstrap.py').write_text((old/'bootstrap.py').read_text()+'\n# changed\n');self.manifest(old)
   with patch.dict(M['prepare'].__globals__,{'trusted':lambda p:None}):
    with self.assertRaisesRegex(M['Refused'],'old_bootstrap_not_exact'):M['prepare'](old,root/'new',d)
   self.assertFalse((root/'new').exists())
 def test_other_template_change_rejected_before_write(self):
  with tempfile.TemporaryDirectory() as t:
   root=pathlib.Path(t);old,d=self.fixture(root);(old/'grants.sql').write_text('changed');self.manifest(old)
   with patch.dict(M['prepare'].__globals__,{'trusted':lambda p:None}):
    with self.assertRaisesRegex(M['Refused'],'non_bootstrap_review_change'):M['prepare'](old,root/'new',d)
   self.assertFalse((root/'new').exists())
 def test_runtime_mismatch_rejected_before_write(self):
  with tempfile.TemporaryDirectory() as t:
   root=pathlib.Path(t);old,d=self.fixture(root)
   with patch.dict(M['prepare'].__globals__,{'trusted':lambda p:None}):
    with self.assertRaisesRegex(M['Refused'],'runtime_hash_mismatch'):M['prepare'](old,root/'new','0'*64)
   self.assertFalse((root/'new').exists())
if __name__=='__main__':unittest.main(verbosity=2)
