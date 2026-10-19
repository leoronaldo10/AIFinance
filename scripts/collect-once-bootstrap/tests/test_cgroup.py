import pathlib,runpy,tempfile,unittest
from unittest.mock import patch
R=pathlib.Path(__file__).parent
M=runpy.run_path(str(R/'bootstrap.py'));Refused=M['Refused']
class CgroupV2(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.root=pathlib.Path(self.tmp.name)/'cgroup';self.root.mkdir()
  (self.root/'cgroup.controllers').write_text('cpuset cpu io memory pids')
  self.cg='/custom.slice/collector.scope';self.group=self.root/self.cg[1:];self.group.mkdir(parents=True)
  self.defaults={'cgroup.procs':'123\n','memory.max':'268435456','pids.max':'32','cpu.max':'50000 100000','memory.current':'1024','memory.events':'low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n'}
  for n,v in self.defaults.items():(self.group/n).write_text(v)
 def mount(self,kind='cgroup2',root='/'):
  return '10 9 0:1 '+root+' '+str(self.root)+' rw - '+kind+' cgroup rw'
 def check(self):
  M['require_cgroup_v2'](self.root,self.mount())
  return M['verify_cgroup_v2'](self.root,self.cg,'123','0::'+self.cg+'\n')
 def test_correct_limits_non_guessed_unit_path(self):
  result=self.check();self.assertEqual(result['cpu_quota_percent'],50);self.assertEqual(result['memory_bytes'],268435456)
  (self.group/'cpu.max').write_text('10000 20000');self.check()
 def test_unlimited_memory_pids_cpu_rejected(self):
  for name,value in [('memory.max','max'),('pids.max','max'),('cpu.max','max 100000')]:
   with self.subTest(name=name):
    (self.group/name).write_text(value)
    with self.assertRaises(Refused):self.check()
    (self.group/name).write_text(self.defaults[name])
 def test_missing_controllers_rejected(self):
  for missing in ('memory','pids','cpu'):
   (self.root/'cgroup.controllers').write_text(' '.join(x for x in ('memory','pids','cpu') if x!=missing))
   with self.subTest(missing=missing):
    with self.assertRaisesRegex(Refused,'cgroup_controller_missing'):self.check()
 def test_path_escape_and_noncanonical_rejected(self):
  for cg in ('/../outside','/custom.slice/../collector','relative','/','/custom.slice//collector','/custom.slice/./collector'):
   with self.subTest(cg=cg):
    with self.assertRaises(Refused):M['verify_cgroup_v2'](self.root,cg,'123','0::'+cg)
 def test_symlink_escape_rejected(self):
  (self.root/'escape').symlink_to(self.group,target_is_directory=True)
  with self.assertRaisesRegex(Refused,'cgroup_path_unsafe'):M['verify_cgroup_v2'](self.root,'/escape','123','0::/escape')
 def test_missing_or_unreadable_files_rejected(self):
  (self.group/'memory.max').unlink()
  with self.assertRaisesRegex(Refused,'cgroup_file_unreadable'):self.check()
  (self.group/'memory.max').write_text('268435456')
  original=pathlib.Path.read_text
  def unreadable(p,*a,**kw):
   if p==self.group/'pids.max':raise PermissionError()
   return original(p,*a,**kw)
  with patch.object(pathlib.Path,'read_text',unreadable):
   with self.assertRaisesRegex(Refused,'cgroup_file_unreadable'):self.check()
 def test_wrong_cpu_quota_or_period_rejected(self):
  for value in ('100000 100000','25000 100000','0 100000','-1 100000','50000','50000 100000 extra','1 2'):
   (self.group/'cpu.max').write_text(value)
   with self.subTest(value=value):
    with self.assertRaises(Refused):self.check()
 def test_v1_other_or_subtree_mount_rejected(self):
  for mount in (self.mount('cgroup'),self.mount('tmpfs'),self.mount(root='/subtree'),''):
   with self.subTest(mount=mount):
    with self.assertRaises(Refused):M['require_cgroup_v2'](self.root,mount)
 def test_process_membership_and_unit_path_must_agree(self):
  for process in ('0::/another.slice/collector.scope','1:memory:'+self.cg,'0::'+self.cg+'\n1:cpu:/other'):
   with self.assertRaisesRegex(Refused,'process_unit_cgroup_mismatch'):M['verify_cgroup_v2'](self.root,self.cg,'123',process)
  (self.group/'cgroup.procs').write_text('456\n')
  with self.assertRaisesRegex(Refused,'cgroup_pid_missing'):self.check()
 def test_wrong_limits_or_memory_events_rejected(self):
  for name,value in [('memory.max','536870912'),('pids.max','64'),('memory.current','268435456'),('memory.events','max 1\noom 0\noom_kill 0'),('memory.events','max 0\noom 0')]:
   with self.subTest(name=name,value=value):
    (self.group/name).write_text(value)
    with self.assertRaises(Refused):self.check()
    (self.group/name).write_text(self.defaults[name])
 def test_unit_declared_cpu_and_memory_checked(self):
  op=M['Operator'](None)
  values={'DropInPaths':'','User':'aifinance-collect-once','Group':'aifinance-collect-once','MemoryMax':'268435456','TasksMax':'32','CPUQuotaPerSecUSec':'500ms','TimeoutStartUSec':'2min','NoNewPrivileges':'yes','KillMode':'control-group','ProtectSystem':'strict','RemainAfterExit':'yes'}
  def prop(unit,key):
   if key=='FragmentPath':return '/etc/systemd/system/'+unit
   if key=='ExecStart':return '{ argv[]='+('/usr/bin/sleep 30' if unit.endswith('-probe.service') else '/usr/bin/python3 -I -B /opt/aifinance-collect-once/bin/run.py')+' ; }'
   return values[key]
  op.property=prop;op.verify_units()
  for key,value in [('CPUQuotaPerSecUSec','infinity'),('CPUQuotaPerSecUSec','1s'),('MemoryMax','infinity')]:
   old=values[key];values[key]=value
   with self.assertRaisesRegex(Refused,'unit_safety_property_mismatch'):op.verify_units()
   values[key]=old
 def test_failed_limit_observations_are_sanitized(self):
  for value,expected in [('536870912','536870912'),('SECRET_VALUE',None)]:
   (self.group/'memory.max').write_text(value);observations={}
   with self.assertRaisesRegex(Refused,'cgroup_memory_limit_mismatch'):M['verify_cgroup_v2'](self.root,self.cg,'123','0::'+self.cg,observations=observations)
   self.assertEqual(observations,{'memory_max':expected})
if __name__=='__main__':unittest.main(verbosity=2)
