"""Systemd sequencing fixtures + real local pidfd/proc/exec tests, clearly separated."""
import contextlib,io,json,os,pathlib,runpy,select,subprocess,sys,tempfile,time,types,unittest
from unittest.mock import patch
R=pathlib.Path(__file__).resolve().parents[1]
M=runpy.run_path(str(R/'templates/process_readiness.py.in'))
STATUS='Uid:\t995\t995\t995\t995\nGid:\t996\t996\t996\t996\nNoNewPrivs:\t1\n'+''.join(k+':\t0000000000000000\n' for k in M['CAPS'])
def proc_stat(pid=123,ticks=900,state='S'):return str(pid)+' (name ) with spaces) '+state+' '+' '.join(['0']*18+[str(ticks)]+['0']*5)
def snapshot(**extra):return dict({'MainPID':'123','ExecMainPID':'123','ExecMainStartTimestampMonotonic':'100','InvocationID':'a'*32,'ControlGroup':'/fixture.service','ActiveState':'activating','SubState':'start'},**extra)
class FakeOp:
 def __init__(self,rows=None):self.state={'uid':995,'gid':996};self.rows=rows or [snapshot()];self.events=[]
 def properties(self,*a,**kw):return self.rows.pop(0) if len(self.rows)>1 else self.rows[0]
 def process_diagnostic(self,stage,values):self.events.append(dict(stage=stage,**values))
class FakeSample(M['ProcessSample']):
 status=STATUS;stat_text=proc_stat();exe_sequence=[True];is_alive=True
 def attach(self,s):self.pid=123;self.pidfd=999;self.procfd=None;self.ticks=900;self.initial=s;self.diagnostic.update(pid=123,start_ticks=900)
 def alive(self):return self.is_alive
 def read(self,name,limit=None):
  if name=='status':return self.status() if callable(self.status) else self.status
  return {'stat':self.stat_text,'cgroup':'0::/fixture.service\n'}[name]
 def executable_matches(self,allow_missing=True):return self.exe_sequence.pop(0) if len(self.exe_sequence)>1 else self.exe_sequence[0]
 def resolver_evidence(self):self.diagnostic['resolver_bindings_readonly']=True
 def close(self):self.closed=True
class SequencingTests(unittest.TestCase):
 def setUp(self):self.samples=[]
 def run_wait(self,op=None,status=STATUS,exe=None,stat_text=None,timeout=.02,verify=None):
  op=op or FakeOp()
  def factory(*a,**kw):
   s=FakeSample(*a,**kw);s.status=status;s.exe_sequence=list(exe or [True]);s.stat_text=stat_text or proc_stat();self.samples.append(s);return s
  with patch.dict(M['wait_for_process'].__globals__,{'ProcessSample':factory}),patch.object(M['select'],'select',return_value=([],[],[])):
   return M['wait_for_process'](op,'fixture-probe.service',pathlib.Path('/usr/bin/sleep'),pathlib.Path('/fixture'),lambda:None,verify or (lambda *a,**kw:{'memory_bytes':268435456}),timeout)
 def test_nonzero_pid_waits_for_exec_then_checks_policy(self):
  op=FakeOp();s=self.run_wait(op,exe=[False,False,True]);self.assertEqual(op.events[-1]['stage'],'process_readiness_passed');self.assertTrue(s.diagnostic['checks']['uid_matches']);s.close()
 def test_preexec_root_then_ready_dedicated_identity(self):
  statuses=iter([STATUS.replace('995','0'),STATUS,STATUS]);op=FakeOp();sample=self.run_wait(op,status=lambda:next(statuses),exe=[False,True]);self.assertEqual(op.events[-1]['uids'],[995]*4);sample.close()
 def test_exit_or_pid_reuse_during_cgroup_reads_is_not_accepted(self):
  for kind in ('exit','reuse'):
   def changed(*a,**kw):
    if kind=='exit':self.samples[-1].is_alive=False
    else:self.samples[-1].stat_text=proc_stat(ticks=901)
    return {}
   with self.assertRaises(M['Refused']):self.run_wait(verify=changed)
   self.assertTrue(self.samples[-1].closed)
 def test_preexec_root_identity_is_not_accepted(self):
  op=FakeOp()
  with self.assertRaisesRegex(M['Refused'],'process_exec_readiness_timeout'):self.run_wait(op,status=STATUS.replace('995','0'),exe=[False],timeout=.001)
  self.assertFalse(op.events[-1]['exec_matches']);self.assertEqual(op.events[-1]['uids'],[0]*4);self.assertTrue(self.samples[-1].closed)
 def test_postexec_bad_uid_gid_nnp_each_capability_refused(self):
  cases=[(STATUS.replace('995','0'),'uid_matches'),(STATUS.replace('996','0'),'gid_matches'),(STATUS.replace('NoNewPrivs:\t1','NoNewPrivs:\t0'),'no_new_privileges')]
  cases += [(STATUS.replace(k+':\t0000000000000000',k+':\t0000000000000001'),k.lower()+'_zero') for k in M['CAPS']]
  for status,key in cases:
   with self.subTest(check=key),self.assertRaisesRegex(M['Refused'],'process_'+key+'_failed'):self.run_wait(status=status)
   self.assertTrue(self.samples[-1].closed)
 def test_missing_and_duplicate_status_fields_fail_closed(self):
  with self.assertRaises(M['Refused']):self.run_wait(status=STATUS.replace('NoNewPrivs:\t1\n',''))
  with self.assertRaisesRegex(M['Refused'],'process_status_duplicate_field'):self.run_wait(status=STATUS+'Uid: 995 995 995 995\n')
 def test_changed_pid_invocation_and_exec_timestamp_refused(self):
  for changed,reason in [(snapshot(MainPID='124'),'process_unit_identity_changed'),(snapshot(InvocationID='b'*32),'unit_invocation_changed'),(snapshot(ExecMainStartTimestampMonotonic='101'),'unit_execution_changed')]:
   with self.subTest(reason=reason),self.assertRaisesRegex(M['Refused'],reason):self.run_wait(FakeOp([snapshot(),changed]))
 def test_same_pid_reuse_and_zombie_refused(self):
  for text,reason in [(proc_stat(ticks=901),'process_pid_reused'),(proc_stat(state='Z'),'process_exited_before_ready')]:
   with self.assertRaisesRegex(M['Refused'],reason):self.run_wait(stat_text=text)
 def test_unit_exits_without_ever_becoming_ready(self):
  op=FakeOp([snapshot(MainPID='0'),snapshot(MainPID='0',ActiveState='inactive')])
  with self.assertRaisesRegex(M['Refused'],'process_exited_before_ready'):self.run_wait(op)
 def test_stable_oneshot_activating_is_valid(self):self.run_wait(FakeOp([snapshot(ActiveState='activating')])).close()
 def test_cgroup_failure_is_not_retried_or_hidden(self):
  calls=[]
  def bad(*a,**kw):calls.append(1);raise M['Refused']('cgroup_memory_limit_mismatch')
  with self.assertRaisesRegex(M['Refused'],'cgroup_memory_limit_mismatch'):self.run_wait(verify=bad)
  self.assertEqual(calls,[1])
 def test_runtime_replacement_and_exit_checks(self):
  op=FakeOp();s=self.run_wait(op)
  with self.assertRaisesRegex(M['Refused'],'process_unit_identity_changed'):s.observe_running(snapshot(MainPID='124'))
  self.assertEqual(op.events[-1]['stage'],'process_runtime_failed')
  s.is_alive=False;s.observe_running(snapshot())
  s.observe_running(snapshot(MainPID='0',ActiveState='inactive',InvocationID=''))
  with self.assertRaises(M['Refused']):s.observe_running(snapshot(MainPID='0',ActiveState='inactive',ExecMainPID='124'))
  s.close()
 def test_unexpected_exception_is_sanitized(self):
  op=FakeOp()
  def bad(*a,**kw):raise OSError('SECRET_CONNECTION_VALUE')
  with self.assertRaisesRegex(M['Refused'],'process_evidence_unavailable'):self.run_wait(op,verify=bad)
  self.assertNotIn('SECRET',json.dumps(op.events));self.assertNotIn('environment',json.dumps(op.events));self.assertTrue(self.samples[-1].closed)
 def test_permission_timeout_and_exit_failures_have_safe_distinct_reasons(self):
  s=types.SimpleNamespace(pidfd=1,alive=lambda:False)
  for error,reason in [(PermissionError('SECRET'),'process_evidence_permission_denied'),(subprocess.TimeoutExpired(['SECRET'],1),'unit_evidence_query_timeout'),(FileNotFoundError('SECRET'),'process_exited_during_evidence')]:self.assertEqual(M['failure_reason'](s,error),reason)
 def test_proc_stat_comm_with_parentheses_does_not_shift_starttime(self):self.assertEqual(M['start_identity'](proc_stat(),123),900)
 def test_mount_identity_selects_visible_readonly_mount(self):
  text='10 1 0:1 / /etc/hosts rw - tmpfs x rw\n11 1 0:2 / /etc/hosts ro,nosuid - tmpfs x rw\n'
  M['mount_readonly'](text,11,'/etc/hosts')
  for mid,target in [(10,'/etc/hosts'),(12,'/etc/hosts'),(11,'/etc/nsswitch.conf')]:
   with self.assertRaises(M['Refused']):M['mount_readonly'](text,mid,target)
 def test_security_status_tabs_and_spaces(self):
  for text in (STATUS,STATUS.replace('\t',' ')):
   checks,values=M['security_status'](text,995,996);self.assertTrue(all(checks.values()))
 def exited(self,**extra):return snapshot(MainPID='0',ActiveState='active',SubState='exited',Result='success',ExecMainCode='1',ExecMainStatus='0',**extra)
 def test_retained_exit_requires_dead_original_pidfd_and_same_instance(self):
  op=FakeOp();s=self.run_wait(op)
  with self.assertRaisesRegex(M['Refused'],'unit_completion_not_observed'):s.verify_exit(self.exited())
  s.is_alive=False;s.verify_exit(self.exited());self.assertEqual(op.events[-1]['stage'],'process_exit_verified')
  self.assertFalse(op.events[-1]['unit_transition']['held_pidfd_alive'])
 def test_cleared_pid_or_start_stamp_never_becomes_success(self):
  for change in ({'ExecMainPID':'0'},{'ExecMainStartTimestampMonotonic':'0'},{'ExecMainPID':'0','ExecMainStartTimestampMonotonic':'0'}):
   op=FakeOp();s=self.run_wait(op);s.is_alive=False
   with self.assertRaisesRegex(M['Refused'],'unit_execution_changed'):s.verify_exit(self.exited(**change))
   transition=op.events[-1]['unit_transition'];self.assertEqual(transition['initial']['ExecMainPID'],'123')
   for key,value in change.items():self.assertEqual(transition['current'][key],value);self.assertIn(key,transition['changed_fields'])
 def test_reaping_window_still_rejects_changed_execution_identity(self):
  s=self.run_wait();s.is_alive=False
  with self.assertRaisesRegex(M['Refused'],'unit_execution_changed'):s.observe_running(snapshot(ExecMainPID='124'))
 def test_nonzero_signal_timeout_and_unretained_exit_rejected(self):
  changes=[{'Result':'exit-code','ExecMainStatus':'1'},{'Result':'signal','ExecMainCode':'2','ExecMainStatus':'15'},{'Result':'timeout'},{'ActiveState':'inactive','SubState':'dead'},{'InvocationID':''},{'InvocationID':'b'*32}]
  for change in changes:
   op=FakeOp();s=self.run_wait(op);s.is_alive=False;state=self.exited();state.update(change)
   with self.assertRaises(M['Refused']):s.verify_exit(state)
   self.assertNotEqual(op.events[-1]['stage'],'process_exit_verified')
 def test_restart_after_first_exit_observation_is_rejected(self):
  s=self.run_wait();s.is_alive=False;s.verify_exit(self.exited())
  with self.assertRaises(M['Refused']):s.verify_exit(self.exited(ExecMainPID='124',InvocationID='b'*32))
 def test_transition_log_redacts_unexpected_values_and_paths(self):
  op=FakeOp();s=self.run_wait(op)
  with self.assertRaises(M['Refused']):s.observe_running(snapshot(ExecMainPID='SECRET',ControlGroup='/SECRET',InvocationID='SECRET',ActiveState='SECRET'))
  data=json.dumps(op.events[-1]);self.assertNotIn('SECRET',data);self.assertIn('ExecMainPID',data)
 def test_previous_snapshot_and_observation_duration_are_recorded(self):
  op=FakeOp();s=self.run_wait(op);s.observe_running(snapshot());s.is_alive=False;s.verify_exit(self.exited())
  t=op.events[-1]['unit_transition'];self.assertEqual(t['previous']['MainPID'],'123');self.assertGreaterEqual(t['elapsed_ms'],0);self.assertGreaterEqual(t['since_last_observation_ms'],0)
 def test_exit_between_snapshot_and_proc_read_waits_for_verified_exit(self):
  op=FakeOp();s=self.run_wait(op);original=s.read
  def vanishes(name,limit=None):
   if name=='stat':s.is_alive=False;raise FileNotFoundError(2,'fixture disappearance')
   return original(name,limit)
  s.read=vanishes;s.observe_running(snapshot());self.assertTrue(s.diagnostic['unit_transition']['exit_observed_during_sample'])
  self.assertNotEqual(op.events[-1]['stage'],'process_exit_verified');s.verify_exit(self.exited());self.assertEqual(op.events[-1]['stage'],'process_exit_verified')
 def test_live_proc_failure_or_identity_mismatch_is_not_swallowed(self):
  s=self.run_wait();s.read=lambda *a,**kw:(_ for _ in ()).throw(FileNotFoundError(2,'fixture'))
  with self.assertRaises(M['Refused']):s.observe_running(snapshot())
  s=self.run_wait()
  def reused(*a,**kw):s.is_alive=False;return proc_stat(ticks=901)
  s.read=reused
  with self.assertRaisesRegex(M['Refused'],'process_pid_reused'):s.observe_running(snapshot())

class LinuxProcessTests(unittest.TestCase):
 def test_real_pidfd_natural_exit_with_retained_and_cleared_unit_fixtures(self):
  p=subprocess.Popen(['/usr/bin/sleep','.15']);op=FakeOp();sample=M['ProcessSample'](op,'fixture-probe.service',pathlib.Path('/usr/bin/sleep'),pathlib.Path('/unused'),lambda:None,lambda *a:None)
  initial=snapshot(MainPID=str(p.pid),ExecMainPID=str(p.pid))
  try:
   sample.attach(initial);self.assertTrue(sample.alive());self.assertEqual(p.wait(timeout=3),0);self.assertFalse(sample.alive())
   ended=dict(initial,MainPID='0',ActiveState='active',SubState='exited',Result='success',ExecMainStatus='0',ExecMainCode='1')
   with self.assertRaisesRegex(M['Refused'],'unit_execution_changed'):sample.verify_exit(dict(ended,ExecMainPID='0'))
   sample.verify_exit(ended);self.assertEqual(op.events[-1]['stage'],'process_exit_verified')
  finally:
   sample.close()
   if p.poll() is None:p.kill()
   p.wait()
 def test_real_pidfd_exec_transition_and_exit(self):
  # A blocked Python child then execs sleep: real exec transition, no systemd claim.
  p=subprocess.Popen([sys.executable,'-I','-B','-c','import os,sys; sys.stdout.write("ready\\n");sys.stdout.flush();sys.stdin.readline();os.execv("/usr/bin/sleep",["sleep","2"])'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
  sample=M['ProcessSample'](FakeOp(), 'fixture-probe.service',pathlib.Path('/usr/bin/sleep'),pathlib.Path('/unused'),lambda:None,lambda *a:{})
  try:
   self.assertEqual(p.stdout.readline().strip(),'ready');sample.attach(snapshot(MainPID=str(p.pid),ExecMainPID=str(p.pid)))
   self.assertFalse(sample.executable_matches());ticks=sample.ticks;p.stdin.write('go\n');p.stdin.flush();deadline=time.monotonic()+1
   while not sample.executable_matches() and time.monotonic()<deadline:select.select([sample.pidfd],[],[],.005)
   self.assertTrue(sample.executable_matches());self.assertEqual(M['start_identity'](sample.read('stat'),p.pid),ticks)
   p.terminate();p.wait(timeout=3);self.assertFalse(sample.alive())
  finally:sample.close();p.stdin.close();p.stdout.close();p.kill() if p.poll() is None else None;p.wait()
 def test_real_linux_status_with_no_new_privileges(self):
  p=subprocess.run([sys.executable,'-I','-B','-c','import ctypes,pathlib;assert ctypes.CDLL(None).prctl(38,1,0,0,0)==0;print(pathlib.Path("/proc/self/status").read_text())'],capture_output=True,text=True,check=True,timeout=5)
  checks,values=M['security_status'](p.stdout,os.getuid(),os.getgid());self.assertTrue(checks['uid_matches'] and checks['gid_matches'] and checks['no_new_privileges'] and checks['capeff_zero'])
  # Bounding-set drop needs privileges absent here; do not pretend full policy passed.
 def test_real_fdinfo_mount_identity(self):
  with open('/proc/self/root/etc/hosts','rb') as f:
   info=pathlib.Path('/proc/self/fdinfo/'+str(f.fileno())).read_text();mid=int(next(x.split(':')[1] for x in info.splitlines() if x.startswith('mnt_id:')))
   rows=[x.split() for x in pathlib.Path('/proc/self/mountinfo').read_text().splitlines() if x.split()[0]==str(mid)]
   self.assertEqual(len(rows),1)
   if rows[0][4]!='/etc/hosts':
    with self.assertRaises(M['Refused']):M['mount_readonly'](pathlib.Path('/proc/self/mountinfo').read_text(),mid,'/etc/hosts')
 def test_root_evidence_writer_uses_only_allowlisted_fields(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d);cfg=runpy.run_path(str(R/'configure.py'));cfg['render'](root/'review',cfg['bindings']('fixture_db',65439,'fixture_app','fixture_deploy',2345));b=runpy.run_path(str(root/'review/bootstrap.py'));op=b['Operator'](None)
   state=root/'state';state.mkdir();(state/'retry-001').mkdir()
   with patch.dict(op.process_diagnostic.__func__.__globals__,{'STATE':state,'trusted':lambda p:None}),contextlib.redirect_stdout(io.StringIO()):
    op.process_diagnostic('process_readiness_failed',{'role':'collector','reason':'process_uid_matches_failed','uids':[0]*4})
    with self.assertRaises(b['Refused']):op.process_diagnostic('process_readiness_failed',{'environment':'SECRET'})
   self.assertFalse((state/'retry-001/process-evidence.jsonl').exists());path=state/'process-evidence.jsonl';self.assertEqual(path.stat().st_mode&0o777,0o600);self.assertNotIn('SECRET',path.read_text())
 def test_probe_stops_itself_even_when_readiness_fails_without_database(self):
  with tempfile.TemporaryDirectory() as d:
   cfg=runpy.run_path(str(R/'configure.py'));review=pathlib.Path(d)/'review';cfg['render'](review,cfg['bindings']('fixture_db',65439,'fixture_app','fixture_deploy',2345));b=runpy.run_path(str(review/'bootstrap.py'));op=b['Operator'](None);events=[]
   def command(args,**kw):events.append(args[1]);return types.SimpleNamespace(stdout=b'')
   op.property=lambda *a:'0'
   def failure(unit):events.append('evidence');raise b['Refused']('fixture_failure')
   op.kernel_evidence=failure
   with patch.dict(op.probe.__func__.__globals__,{'cmd':command}):
    with self.assertRaises(b['Refused']):op.probe()
   self.assertEqual(events,['start','evidence','stop'])
 def test_formal_process_and_probe_both_call_shared_waiter(self):
  with tempfile.TemporaryDirectory() as d:
   cfg=runpy.run_path(str(R/'configure.py'));review=pathlib.Path(d)/'review';cfg['render'](review,cfg['bindings']('fixture_db',65439,'fixture_app','fixture_deploy',2345));b=runpy.run_path(str(review/'bootstrap.py'));op=b['Operator'](None);calls=[]
   def wait(*args,**kwargs):calls.append((args[1],str(args[2])));return 'sample'
   with patch.dict(op.kernel_evidence.__func__.__globals__,{'trusted_tool':lambda p:None}),patch.object(runpy,'run_path',return_value={'wait_for_process':wait}):
    self.assertEqual(op.kernel_evidence(b['PROBE']),'sample');self.assertEqual(op.kernel_evidence(b['UNIT']),'sample')
   self.assertEqual(calls,[(b['PROBE'],'/usr/bin/sleep'),(b['UNIT'],'/usr/bin/python3')])
if __name__=='__main__':unittest.main(verbosity=2)
