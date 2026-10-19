"""No downloads/sudo/ECS: actual file staging and controlled child-process fixtures."""
import contextlib,hashlib,io,os,pathlib,runpy,signal,tempfile,types,unittest
from unittest.mock import patch
R=pathlib.Path(__file__).resolve().parents[1];M=runpy.run_path(str(R/'retry-002-handoff.py'));G=M['root_flow'].__globals__
class Handoff(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=pathlib.Path(self.temp.name);self.base=self.root/'base';self.audit=self.root/'audit';self.calls=[];self.receipts=[]
  p=patch.dict(G,BASE=self.base,DEST=self.base/'helper',AUDIT=self.audit,ROOT_UID=os.getuid(),trusted=lambda p:None);p.start();self.addCleanup(p.stop)
 def flow(self,results,hook=None):
  calls=self.calls
  class Child:
   def __init__(child,args):calls.append(args[4]);child.rc=results[args[4]];child.signals=[]
   def wait(child):
    if hook:hook(child)
    return child.rc
   def poll(child):return None
   def send_signal(child,s):child.signals.append(s)
  with patch.object(M['subprocess'],'Popen',Child),patch.dict(G,receipt=lambda stage,rc:self.receipts.append((stage,rc))),contextlib.redirect_stdout(io.StringIO()):return M['root_flow']('a'*64)
 def test_success_runs_install_check_once_in_order(self):
  self.assertEqual(self.flow({'install':0,'check':0,'run':0}),0);self.assertEqual(self.calls,['install','check','run'])
 def test_install_failure_stops_before_check(self):
  self.assertEqual(self.flow({'install':7}),7);self.assertEqual(self.calls,['install'])
 def test_check_failure_stops_before_run(self):
  self.assertEqual(self.flow({'install':0,'check':9}),9);self.assertEqual(self.calls,['install','check'])
 def test_real_run_failure_code_preserved(self):
  self.assertEqual(self.flow({'install':0,'check':0,'run':23}),23);self.assertEqual(self.receipts[-1],('RUN_EXIT',23))
 def test_repeat_can_only_cleanup_and_status(self):
  self.audit.mkdir();self.assertEqual(self.flow({'cleanup':0,'status':0}),0);self.assertEqual(self.calls,['cleanup','status'])
 def test_failed_repeat_cleanup_stops(self):
  self.audit.mkdir();self.assertEqual(self.flow({'cleanup':11}),11);self.assertEqual(self.calls,['cleanup'])
 def test_disconnect_forwarded_and_prevents_next_stage(self):
  def hook(child):signal.getsignal(signal.SIGHUP)(signal.SIGHUP,None);self.assertEqual(child.signals,[signal.SIGHUP])
  self.assertEqual(self.flow({'install':-signal.SIGHUP},hook),129);self.assertEqual(self.calls,['install'])
 def source(self):
  src=self.root/'download';src.mkdir();payload={'retry-002.py':b'fixture','retry-002-handoff.py':(R/'retry-002-handoff.py').read_bytes()}
  for n,data in payload.items():(src/n).write_bytes(data)
  blob=''.join(M['digest'](v)+'  '+n+'\n' for n,v in payload.items()).encode();(src/'SHA256SUMS').write_bytes(blob);return src,M['digest'](blob)
 def test_root_stage_verifies_and_reuses_exact_helper(self):
  src,want=self.source();M['stage_helper'](src,want);M['stage_helper'](src,want)
  self.assertEqual((self.base/'helper/retry-002.py').read_bytes(),b'fixture')
 def test_root_hash_failure_writes_nothing(self):
  src,want=self.source();(src/'retry-002.py').write_bytes(b'changed')
  with self.assertRaisesRegex(M['Refused'],'root_download_hash_mismatch'):M['stage_helper'](src,want)
  self.assertFalse(self.base.exists())
 def test_partial_matching_stage_finishes(self):
  src,want=self.source();stage=self.base/'helper.staging';stage.mkdir(parents=True);(stage/'retry-002.py').write_bytes(b'fixture');M['stage_helper'](src,want)
  self.assertTrue((self.base/'helper/SHA256SUMS').is_file())
 def test_changed_or_extra_existing_helper_never_overwritten(self):
  src,want=self.source();M['stage_helper'](src,want);(self.base/'helper/retry-002.py').write_bytes(b'changed')
  with self.assertRaisesRegex(M['Refused'],'existing_helper_changed'):M['stage_helper'](src,want)
  self.assertEqual((self.base/'helper/retry-002.py').read_bytes(),b'changed')
 def test_manifest_traversal_duplicate_and_absolute_paths_rejected(self):
  for name in ('../outside','/root/out','retry-002.py\n'+'a'*64+' retry-002.py'):
   blob=('a'*64+'  '+name+'\n').encode()
   with self.assertRaises(M['Refused']):M['entries'](blob,M['digest'](blob))
 def test_durable_exit_receipts(self):
  self.base.mkdir();M['receipt']('RUN_EXIT',17);M['receipt']('HANDOFF_EXIT',17)
  self.assertIn('"exit_code": 17',(self.base/'handoff-results.jsonl').read_text());self.assertEqual((self.base/'handoff-results.jsonl').stat().st_mode&0o777,0o600)
if __name__=='__main__':unittest.main(verbosity=2)
