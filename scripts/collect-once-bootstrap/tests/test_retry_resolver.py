"""No external DNS/network: exercise real snapshot files and the approved renderer."""
import hashlib,json,os,pathlib,runpy,shutil,stat,subprocess,tempfile,types,unittest
from unittest.mock import patch
R=pathlib.Path(__file__).resolve().parents[1]
S=runpy.run_path(str(R/'retry-resolver.py'))
T=runpy.run_path(str(R/'retry-once.py'))
def overwrite(p,data):
 mode=stat.S_IMODE(p.stat().st_mode);p.chmod(mode|0o200);p.write_bytes(data.encode() if isinstance(data,str) else data);p.chmod(mode)
class ResolverTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=pathlib.Path(self.temp.name);self.conf=self.root/'conf';self.conf.mkdir();self.audit=self.root/'audit';self.audit.mkdir()
  cfg=runpy.run_path(str(R/'configure.py'));review=self.root/'review';cfg['render'](review,cfg['bindings']('aifinance_preview',55432,'aifinance_app','aifinance-deploy',2345));render=runpy.run_path(str(review/'render-network.py'))['render']
  self.old={'uid':2001,'gid':os.getgid(),'nonce':'a'*32};self.calls=[];self.answers={h:['8.8.8.8'] for h in S['HOSTS']}
  def command(args,input=None,**kw):
   self.calls.append((args,input))
   if args[0]=='/usr/bin/getent':return types.SimpleNamespace(stdout=(''.join(ip+' STREAM ignored-alias\n'+ip+' DGRAM\n' for ip in self.answers[args[2]])).encode())
   self.assertEqual(args,['/usr/sbin/nft','--check','--file','-']);return types.SimpleNamespace(stdout=b'')
  m={'CONF':self.conf,'TABLE':'aifinance_collect_once_v1','trusted':lambda p:None,'cmd':command}
  self.snap=S['ResolverSnapshot'](m,self.old,self.audit,render,[0,2345,2346]);patcher=patch.dict(self.snap.safe.__func__.__globals__,{'OWNER_UID':os.getuid()});patcher.start();self.addCleanup(patcher.stop)
  original=self.snap.network(self.answers);self.old['network_sha256']=S['digest'](original['nft'].encode())
  (self.conf/'hosts').write_text(original['hosts']);(self.conf/'nsswitch.conf').write_text(original['nsswitch'])
  for p in self.conf.iterdir():p.chmod(0o440)
  self.original=(self.conf/'hosts').read_bytes()
 def test_changed_public_addresses_are_pinned_and_old_snapshot_restored(self):
  self.snap.inspect();self.answers={h:['1.1.1.1','8.8.4.4'] for h in S['HOSTS']}
  started,hosts,net=self.snap.install()
  self.assertEqual(set(hosts),S['HOSTS']);self.assertEqual((self.conf/'hosts').read_text(),net['hosts']);self.assertNotEqual((self.conf/'hosts').read_bytes(),self.original)
  self.assertEqual(stat.S_IMODE((self.conf/'hosts').stat().st_mode),0o440)
  self.assertIn('ip daddr 1.1.1.1 tcp dport 443',net['nft']);self.assertIn('ip daddr 127.0.0.1 tcp dport 55432',net['nft']);self.assertNotIn('tcp dport 53',net['nft']);self.assertIn('meta skuid 2001 counter reject',net['nft'])
  self.snap.restore();self.assertEqual((self.conf/'hosts').read_bytes(),self.original);self.assertFalse(self.snap.changed)
 def test_order_and_duplicate_dns_answers_do_not_change_snapshot(self):
  self.snap.inspect();self.answers={h:['8.8.8.8','8.8.8.8'] for h in S['HOSTS']}
  with patch.object(self.snap,'replace',side_effect=AssertionError('unnecessary replacement')):self.snap.install();self.snap.restore()
  self.assertEqual((self.conf/'hosts').read_bytes(),self.original)
 def test_answer_order_canonicalized(self):
  self.snap.inspect();self.answers={h:['8.8.8.8','1.1.1.1'] for h in S['HOSTS']};a=self.snap.resolve()[2]
  self.answers={h:['1.1.1.1','8.8.8.8'] for h in S['HOSTS']};b=self.snap.resolve()[2];self.assertEqual(a,b)
 def test_private_reserved_ipv6_and_instruction_text_refused(self):
  self.snap.inspect()
  for ip in ('127.0.0.1','10.0.0.1','169.254.169.254','192.0.2.1','224.0.0.1','::1','2606:4700:4700::1111','execute-this-command'):
   self.answers={h:[ip] for h in S['HOSTS']}
   with self.assertRaises(S['Refused']):self.snap.install()
  self.assertEqual(list(self.audit.iterdir()),[]);self.assertEqual((self.conf/'hosts').read_bytes(),self.original)
 def test_empty_or_too_many_addresses_refused(self):
  self.snap.inspect()
  for addresses in ([],['8.8.8.'+str(i) for i in range(1,10)]):
   self.answers={h:addresses for h in S['HOSTS']}
   with self.assertRaises(S['Refused']):self.snap.install()
 def test_old_resolver_policy_and_receipt_are_not_silently_repaired(self):
  overwrite(self.conf/'nsswitch.conf','hosts: files dns\n')
  with self.assertRaisesRegex(S['Refused'],'old_nsswitch_policy_changed'):self.snap.inspect()
  overwrite(self.conf/'nsswitch.conf','hosts: files\n');overwrite(self.conf/'hosts',self.original.decode().replace('www.microsoft.com','unapproved.example'))
  with self.assertRaisesRegex(S['Refused'],'old_hosts_policy_changed'):self.snap.inspect()
  overwrite(self.conf/'hosts',self.original);self.old['network_sha256']='0'*64
  with self.assertRaisesRegex(S['Refused'],'old_resolver_receipt_mismatch'):self.snap.inspect()
 def test_concurrent_edit_is_preserved(self):
  self.snap.inspect();self.answers={h:['1.1.1.1'] for h in S['HOSTS']};self.snap.install();p=self.conf/'hosts';overwrite(p,p.read_bytes()+b'# concurrent change\n')
  with self.assertRaisesRegex(S['Refused'],'resolver_concurrent_change_preserved'):self.snap.restore()
  self.assertTrue(p.read_bytes().endswith(b'# concurrent change\n'))
 def test_recovery_restores_after_process_interruption(self):
  self.snap.inspect();self.answers={h:['1.1.1.1'] for h in S['HOSTS']};self.snap.install()
  other=S['ResolverSnapshot'](self.snap.m,self.old,self.audit,self.snap.render,self.snap.forbidden);other.recover(lambda p:None);other.restore();self.assertEqual((self.conf/'hosts').read_bytes(),self.original)
 def test_failed_replace_keeps_original_and_recovery_receipt(self):
  self.snap.inspect();self.answers={h:['1.1.1.1'] for h in S['HOSTS']}
  with patch.object(S['os'],'replace',side_effect=OSError('fixture rename failure')):
   with self.assertRaises(OSError):self.snap.install()
  self.assertEqual((self.conf/'hosts').read_bytes(),self.original);self.assertTrue((self.audit/'resolver-receipt.json').is_file());self.snap.restore();self.assertFalse(self.snap.changed)
 def test_recovery_rejects_widened_host_scope(self):
  self.snap.inspect();self.snap.install();p=self.audit/'resolver-receipt.json';data=json.loads(p.read_text());data['after']=data['after'].replace('www.microsoft.com','unapproved.example');data['after_sha256']=S['digest'](data['after'].encode());p.write_text(json.dumps(data))
  with self.assertRaises(S['Refused']):self.snap.recover(lambda p:None)
 def test_freshness_starts_before_first_dns_call(self):
  self.snap.inspect()
  with patch.object(S['time'],'monotonic',side_effect=[0,181]):
   with self.assertRaisesRegex(S['Refused'],'feed_resolution_expired'):self.snap.resolve()
 def test_resolution_is_refreshed_at_install_not_reused_from_preflight(self):
  self.snap.inspect();candidate=self.snap.resolve()[1];self.answers={h:['1.1.1.1'] for h in S['HOSTS']};installed=self.snap.install()[1]
  self.assertNotEqual(candidate,installed);self.assertTrue(all(v==['1.1.1.1'] for v in installed.values()));self.snap.restore()
 def test_readonly_inspect_and_resolve_do_not_create_audit_or_write_config(self):
  before=[(p.name,p.read_bytes(),p.stat().st_mtime_ns) for p in self.conf.iterdir()];self.snap.inspect();self.snap.resolve()
  self.assertEqual(before,[(p.name,p.read_bytes(),p.stat().st_mtime_ns) for p in self.conf.iterdir()]);self.assertEqual(list(self.audit.iterdir()),[])
 def test_symlink_and_wrong_mode_refused(self):
  p=self.conf/'hosts';p.chmod(0o644)
  with self.assertRaisesRegex(S['Refused'],'resolver_file_metadata_changed'):self.snap.inspect()
  p.unlink();p.symlink_to(self.conf/'nsswitch.conf')
  with self.assertRaises(S['Refused']):self.snap.inspect()
 def test_cleanup_still_restores_resolver_after_other_cleanup_failure(self):
  events=[]
  class Op:
   def cleanup(self):events.append('db');raise ValueError()
  class Hba:
   changed=True
   def restore(self):events.append('hba');raise ValueError()
  class Resolver:
   changed=True
   def restore(self):events.append('resolver');self.changed=False
  with patch.dict(T['cleanup_all'].__globals__,{'AUDIT':self.audit,'website':lambda *a:events.append('health'),'emit':lambda *a,**k:None}):
   with self.assertRaises(T['Refused']):T['cleanup_all']({},Op(),Hba(),Resolver())
  self.assertEqual(events,['db','hba','resolver','health'])
 def test_attempt_order_and_cleanup_on_every_failure(self):
  for fail in (None,'backup','resolve','probe','hba','activate','run'):
   events=[]
   def step(name):
    events.append(name)
    if fail==name:raise RuntimeError('fixture failure')
   class Resolver:
    def install(self):step('resolve');return 0,{'fixed-host':['8.8.8.8']},{'nft':'fixture','hosts':'fixture'}
   class Op:
    resolver=Resolver();state={}
    def backup(self):step('backup')
    def save(self):step('save')
    def probe(self):step('probe')
    def activate(self):step('activate')
    def run_once(self):step('run')
   class Hba:
    def install(self):step('hba')
   with patch.dict(T['execute_retry'].__globals__,{'emit':lambda *a,**k:None,'cleanup_all':lambda *a:events.append('cleanup')}),patch.object(T['signal'],'signal'):
    if fail is None:T['execute_retry']({},Op(),Hba())
    else:
     with self.assertRaises(RuntimeError):T['execute_retry']({},Op(),Hba())
   order=['backup','resolve','save','probe','hba','activate','run']
   self.assertEqual(events,(order if fail is None else order[:order.index(fail)+1])+['cleanup'])

class InstallerTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=pathlib.Path(self.temp.name);self.bin=self.root/'bin';self.bin.mkdir();self.fs=self.root/'fs';self.fs.mkdir()
  self.helper=self.fs/'root/aifinance-once-helper-retry-dns/helper';shutil.copytree(R,self.helper)
  self.manifest=hashlib.sha256((self.helper/'SHA256SUMS').read_bytes()).hexdigest();self.log=self.root/'calls'
  self.env=dict(os.environ,PATH=str(self.bin)+':/usr/bin:/bin',HOME=str(self.root),FIXTURE_FS=str(self.fs),FIXTURE_LOG=str(self.log))
  scripts={'id':'#!/bin/sh\nprintf "ecs-user\\n"\n','hostname':'#!/bin/sh\nprintf "iZ2zedybs3fftu1d9vnx39Z\\n"\n','sudo':"""#!/usr/bin/python3
import os,sys,subprocess
args=sys.argv[1:]
if args==['-v']:raise SystemExit(0)
args=[a.replace('/root/aifinance-',os.environ['FIXTURE_FS']+'/root/aifinance-').replace('/var/lib/aifinance-',os.environ['FIXTURE_FS']+'/var/lib/aifinance-') for a in args]
if args[0]=='/usr/bin/python3':
 assert args[1:3]==['-I','-B'] and args[4:]==['run','--approve-three-source-smoke','--exclusive-writer-window']
 with open(os.environ['FIXTURE_LOG'],'a') as f:f.write('run-called\\n')
 raise SystemExit(0)
raise SystemExit(subprocess.run(args).returncode)
"""}
  for name,text in scripts.items():p=self.bin/name;p.write_text(text);p.chmod(0o755)
 def invoke(self):return subprocess.run(['/bin/bash',str(R/'retry-install.sh'),'a'*40,self.manifest],env=self.env,capture_output=True,timeout=10)
 def test_complete_existing_helper_is_verified_and_reused(self):
  before={p.relative_to(self.helper).as_posix():p.read_bytes() for p in self.helper.rglob('*') if p.is_file()};p=self.invoke();self.assertEqual(p.returncode,0,p.stderr.decode());self.assertEqual(self.log.read_text(),'run-called\n');self.assertEqual(before,{p.relative_to(self.helper).as_posix():p.read_bytes() for p in self.helper.rglob('*') if p.is_file()})
 def test_existing_retry_latch_refuses_before_run(self):
  latch=self.fs/'var/lib/aifinance-collect-once/retry-001';latch.mkdir(parents=True);p=self.invoke();self.assertNotEqual(p.returncode,0);self.assertFalse(self.log.exists());self.assertTrue(latch.is_dir())
 def test_partial_helper_refuses_without_overwrite(self):
  (self.helper/'retry-once.py').unlink();p=self.invoke();self.assertNotEqual(p.returncode,0);self.assertFalse(self.log.exists());self.assertFalse((self.helper/'retry-once.py').exists())
if __name__=='__main__':unittest.main(verbosity=2)
