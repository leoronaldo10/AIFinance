import base64,hashlib,json,pathlib,runpy,tempfile,unittest
R=pathlib.Path(__file__).resolve().parents[1];B=runpy.run_path(str(R/'build-runtime.py'));C=runpy.run_path(str(R/'configure.py'))
class Build(unittest.TestCase):
 def test_private_bindings_reject_injection_and_invalid_scope(self):
  for args in [("bad';DROP",65439,'app','deploy',2345),('fixture',0,'app','deploy',2345),('fixture',65439,'app','root;sh',2345),('fixture',65439,'app','deploy',0)]:
   with self.assertRaises(ValueError):C['bindings'](*args)
 def test_reproducible_package_and_secret_file_exclusion(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d);src=root/'source';src.mkdir()
   for path in ['package.json','package-lock.json','scripts/collect-only.ts','industry/package.json','packages/backend/package.json','packages/backend/src/x.ts','packages/contracts/package.json','packages/contracts/src/x.ts','node_modules/pkg/package.json','node_modules/pkg/.env','packages/backend/node_modules/nested/package.json']:
    p=src/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('synthetic')
   a=root/'a.tgz';b=root/'b.tgz';ha=B['package'](src,a);hb=B['package'](src,b);self.assertEqual(ha,hb)
   import tarfile
   with tarfile.open(a) as tar:
    self.assertFalse(any('.env' in p.name for p in tar.getmembers()));self.assertIn('packages/backend/node_modules/nested/package.json',tar.getnames())
   (src/'node_modules/escape').symlink_to('/etc/passwd')
   with self.assertRaises(B['Refused']):B['package'](src,root/'bad.tgz')
 def test_dependency_integrity_and_tamper(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d);src=root/'source';(src/'node_modules').mkdir(parents=True);cache=root/'cache';raw=b'fixture tar bytes';h=hashlib.sha512(raw).digest();value=h.hex();path=cache/'_cacache/content-v2/sha512'/value[:2]/value[2:4]/value[4:];path.parent.mkdir(parents=True);path.write_bytes(raw)
   meta={'version':'1.0.0','integrity':'sha512-'+base64.b64encode(h).decode(),'resolved':'https://registry.npmjs.org/fixture/-/fixture-1.0.0.tgz'};data=json.dumps({'packages':{'node_modules/fixture':meta}})
   (src/'package-lock.json').write_text(data);(src/'node_modules/.package-lock.json').write_text(data);self.assertEqual(B['integrity'](src,cache),1);path.write_bytes(b'changed')
   with self.assertRaises(B['Refused']):B['integrity'](src,cache)
if __name__=='__main__':unittest.main(verbosity=2)
