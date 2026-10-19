"""Production adapter tests; no systemd, network or database mutations."""
import contextlib,hashlib,io,pathlib,runpy,tempfile,time,types,unittest
from unittest.mock import patch
R=pathlib.Path(__file__).resolve().parents[1]
F=runpy.run_path(str(R/'tests/test_process_readiness.py'))
class Integration(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=pathlib.Path(self.tmp.name)
  cfg=runpy.run_path(str(R/'configure.py'));self.review=self.root/'review';cfg['render'](self.review,cfg['bindings']('fixture_db',65439,'fixture_app','fixture_deploy',2345))
  self.b=runpy.run_path(str(self.review/'bootstrap.py'));self.op=self.b['Operator'](None)
  fake=F['FakeOp']();self.sample=F['FakeSample'](fake,self.b['UNIT'],pathlib.Path('/usr/bin/python3'),self.root,lambda:None,lambda:None);self.sample.attach(F['snapshot']());self.sample.is_alive=False
  self.end=dict(F['snapshot'](),MainPID='0',ActiveState='active',SubState='exited',Result='success',ExecMainCode='1',ExecMainStatus='0',ControlGroup='')
 def wait(self,rows):
  self.calls=[]
  def properties(unit,keys,timeout):
   self.calls.append((unit,keys,timeout));return rows.pop(0)
  self.op.properties=properties
  self.op.wait_for_exit(self.b['UNIT'],self.sample,time.monotonic()+1)
 def test_two_complete_terminal_reads_accept_removed_exit_cgroup(self):
  self.wait([self.end,self.end]);self.assertEqual(len(self.calls),2)
  self.assertTrue(all('Result' in keys and 'InvocationID' in keys and timeout<=1 for _,keys,timeout in self.calls))
  self.assertEqual(sum(e['stage']=='process_exit_verified' for e in self.sample.op.events),2)
 def test_second_read_replacement_is_rejected(self):
  with self.assertRaisesRegex(F['M']['Refused'],'unit_execution_changed'):
   self.wait([self.end,dict(self.end,ExecMainPID='124')])
 def test_deadline_prevents_any_further_query(self):
  self.op.properties=lambda *a,**kw:self.fail('expired query')
  with self.assertRaisesRegex(self.b['Refused'],'process_exit_timeout'):
   self.op.wait_for_exit(self.b['UNIT'],self.sample,time.monotonic()-1)
 def test_probe_verifies_natural_exit_before_stop_and_close(self):
  events=[];self.sample.evidence={};self.sample.close=lambda:events.append('close')
  self.op.kernel_evidence=lambda unit:self.sample
  self.op.wait_for_exit=lambda *a:events.append('verified_exit')
  self.op.property=lambda *a:'0'
  with patch.dict(self.op.probe.__func__.__globals__,{'cmd':lambda a:events.append(a[1])}),contextlib.redirect_stdout(io.StringIO()):self.op.probe()
  self.assertEqual(events,['start','verified_exit','stop','close'])
 def test_probe_failed_exit_still_stops_and_closes(self):
  events=[];self.sample.close=lambda:events.append('close');self.op.kernel_evidence=lambda unit:self.sample;self.op.property=lambda *a:'0'
  def fail(*a):raise self.b['Refused']('exit_failed')
  self.op.wait_for_exit=fail
  with patch.dict(self.op.probe.__func__.__globals__,{'cmd':lambda a:events.append(a[1])}):
   with self.assertRaisesRegex(self.b['Refused'],'exit_failed'):self.op.probe()
  self.assertEqual(events,['start','stop','close'])
 def test_collector_receipt_is_scoped_to_verified_invocation(self):
  state=self.root/'state';state.mkdir();(state/'consumed').write_text('permanent fixture latch');self.op.resolved_at=time.monotonic();self.op.records=lambda:{};self.op.save=lambda:None;self.op.kernel_evidence=lambda unit:self.sample;self.op.wait_for_exit=lambda *a:None;self.op.property=lambda *a:'0';calls=[]
  def command(args):calls.append(args);return types.SimpleNamespace(stdout=b'')
  with patch.dict(self.op.run_once.__func__.__globals__,{'STATE':state,'cmd':command}):
   with self.assertRaisesRegex(self.b['Refused'],'sanitized_batch_receipt_missing'):self.op.run_once()
  self.assertIn('_SYSTEMD_INVOCATION_ID='+'a'*32,calls[-1]);self.assertEqual(calls[-2][1],'stop');self.assertEqual((state/'consumed').read_text(),'permanent fixture latch')
 def test_retry_evidence_directory_is_explicit_without_old_record_mutation(self):
  retry=runpy.run_path(str(R/'retry-once.py'));audit=self.root/'retry-001';audit.mkdir();marker=audit/'started';marker.write_bytes(b'old permanent marker')
  with patch.dict(retry['make_operator'].__globals__,{'AUDIT':audit}):
   op=retry['make_operator'](self.b,None);self.assertEqual(op.evidence_directory(),audit)
  self.assertEqual(marker.read_bytes(),b'old permanent marker');self.assertEqual(list(audit.iterdir()),[marker])
 def test_validated_v3_module_is_byte_identical(self):
  self.assertEqual(hashlib.sha256((R/'templates/process_readiness.py.in').read_bytes()).hexdigest(),'f5ca1ad6788ca4365118ab06ceac433509837239761c0a8ce1e99ad896a447d6')
if __name__=='__main__':unittest.main(verbosity=2)
