import hashlib,json,pathlib,runpy,tempfile,unittest,tarfile,io
R=pathlib.Path(__file__).resolve().parents[1]
class Runtime(unittest.TestCase):
 def fixture(self):
  v=runpy.run_path(str(R/'templates/runtime_check.py.in'))
  packages={};files={};links={}
  for name in v['WORKSPACES']:
   alias='node_modules/@fixture/'+name.split('/')[-1]
   packages[name]={};packages[alias]={'link':True,'resolved':name};links[alias]=name
   files[name+'/package.json']=json.dumps({'name':alias[len('node_modules/'):]}).encode()
  for name,version in [('node_modules/dep','1'),('packages/backend/node_modules/dep','2')]:
   packages[name]={'version':version,'integrity':'sha512-fixture'};files[name+'/package.json']=json.dumps({'name':'dep','version':version}).encode()
  packages['packages/backend']['dependencies']={'dep':'2'}
  raw=json.dumps({'packages':packages}).encode();files['package-lock.json']=raw;files['node_modules/.package-lock.json']=raw
  v['verify'].__globals__['LOCK']=hashlib.sha256(raw).hexdigest()
  return v,files,links,packages
 def test_valid_nested_resolution(self):
  v,f,l,p=self.fixture();self.assertEqual(v['verify'](f.__getitem__,l.__getitem__)['external_packages'],2)
 def test_missing_nested_file_rejected(self):
  v,f,l,p=self.fixture();del f['packages/backend/node_modules/dep/package.json']
  with self.assertRaises((KeyError,ValueError)):v['verify'](f.__getitem__,l.__getitem__)
 def test_missing_nested_inventory_cannot_fall_back_to_root(self):
  v,f,l,p=self.fixture();del p['packages/backend/node_modules/dep'];f['node_modules/.package-lock.json']=json.dumps({'packages':p}).encode()
  with self.assertRaisesRegex(ValueError,'required_dependency'):v['verify'](f.__getitem__,l.__getitem__)
 def test_changed_workspace_alias_rejected(self):
  v,f,l,p=self.fixture();l['node_modules/@fixture/backend']='industry'
  with self.assertRaises(ValueError):v['verify'](f.__getitem__,l.__getitem__)
 def test_unsafe_archive_paths_and_duplicates_rejected(self):
  for names in [['../escape'],['x','x']]:
   v,_,_,_=self.fixture();raw=io.BytesIO()
   with tarfile.open(fileobj=raw,mode='w') as t:
    for name in names:t.addfile(tarfile.TarInfo(name),io.BytesIO())
   raw.seek(0)
   with tarfile.open(fileobj=raw) as t:
    with self.assertRaises(ValueError):v['verify_archive'](t)
if __name__=='__main__':unittest.main(verbosity=2)
