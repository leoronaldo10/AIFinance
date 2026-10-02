"""Only local fixtures and mocked host commands; Python 3.6 compatible."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SCRIPT=Path(__file__).resolve().parents[2]/'deploy/native/repair-egress-nft104.py'
spec=importlib.util.spec_from_file_location('repair',str(SCRIPT))
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

class RepairTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
  self.root=Path(self.temp.name)
  self.paths={'GUARD':self.root/'installed/egress-guard.py','RUNNER':self.root/'administrator/runner.sh',
              'INPUT':self.root/'input','BACKUP':self.root/'run/backup',
              'RECEIPT':self.root/'run/runtime/receipt.json','EVIDENCE':self.root/'run/evidence'}
  self.paths['GUARD_NEXT']=self.paths['GUARD'].with_name('.guard-next')
  self.paths['RUNNER_NEXT']=self.paths['RUNNER'].with_name('.runner-next')
  for name in ('GUARD','RUNNER','RECEIPT'): self.paths[name].parent.mkdir(parents=True,exist_ok=True)
  self.paths['INPUT'].mkdir(mode=0o700); self.paths['EVIDENCE'].mkdir(mode=0o700)
  self.content=(b'old guard\n',b'old runner\n',b'print("new guard")\n',b'#!/usr/bin/bash\ntrue\n')
  for path,raw in zip((self.paths['GUARD'],self.paths['RUNNER'],self.paths['INPUT']/'egress-guard.py',self.paths['INPUT']/'aifinance-egress-acceptance.sh'),self.content): path.write_bytes(raw)
  self.paths['RECEIPT'].write_text(json.dumps({'uid':989,'token':'a'*32})); self.paths['RECEIPT'].chmod(0o600)
  (self.paths['EVIDENCE']/'result.txt').write_text('probe_passed=false\napplication_accepted=false\ncleanup_failed=0\n'); (self.paths['EVIDENCE']/'result.txt').chmod(0o600)
  self.stack=contextlib.ExitStack(); self.addCleanup(self.stack.close)
  self.stack.enter_context(patch.multiple(m,**self.paths))
  for name,raw in zip(('OLD_GUARD','OLD_RUNNER','NEW_GUARD','NEW_RUNNER'),self.content): self.stack.enter_context(patch.object(m,name,hashlib.sha256(raw).hexdigest()))
  self.stack.enter_context(patch.object(m,'trusted',side_effect=lambda p,**k:Path(p)))
  self.idle=self.stack.enter_context(patch.object(m,'idle_conditions'))
  self.commands=[]; self.table=[{'table':{'family':'inet','name':m.TABLE,'handle':42}}]; self.guard_state='failed'; self.failure=None
  self.stack.enter_context(patch.object(m,'call',side_effect=self.command))
 def command(self,args):
  self.commands.append(args)
  if args[0]=='/usr/bin/bash': return ''
  if args[:3]==['/usr/sbin/nft','--json','--handle']: return json.dumps({'nftables':[{'metainfo':{'version':'1.0.4'}}]+self.table})
  if args[:3]==['/usr/sbin/nft','delete','table']:
   self.assertEqual(args,['/usr/sbin/nft','delete','table','inet','handle','42'])
   if self.failure=='delete': raise ValueError('delete_failed')
   self.table=[]; return ''
  if args[:3]==['/usr/sbin/nft','--json','list']: return json.dumps({'nftables':self.table})
  if args[0]=='/usr/bin/systemctl' and args[1]=='show': return 'LoadState=loaded\nActiveState='+self.guard_state+'\nMainPID=0\n'
  if args[:2]==['/usr/bin/systemctl','reset-failed']:
   self.assertEqual(args,['/usr/bin/systemctl','reset-failed',m.UNIT]); self.guard_state='inactive'; return ''
  raise AssertionError('Unexpected host action: '+str(args))
 def assert_no_mutation(self):
  self.assertFalse(m.BACKUP.exists()); self.assertEqual(m.GUARD.read_bytes(),self.content[0]); self.assertEqual(m.RUNNER.read_bytes(),self.content[1]); self.assertTrue(m.RECEIPT.exists()); self.assertTrue(m.EVIDENCE.exists()); self.assertFalse(any(a[1] in ('delete','reset-failed') for a in self.commands))
 def test_check_is_read_only(self):
  self.assertEqual(m.check(),self.content); self.assert_no_mutation()
 def test_success_preserves_receipt_evidence_and_old_files(self):
  m.apply(m.check())
  self.assertEqual(m.GUARD.read_bytes(),self.content[2]); self.assertEqual(m.RUNNER.read_bytes(),self.content[3]); self.assertEqual(self.guard_state,'inactive'); self.assertEqual(self.table,[])
  self.assertEqual((m.BACKUP/'egress-guard.py.before').read_bytes(),self.content[0]); self.assertEqual((m.BACKUP/'aifinance-egress-acceptance.sh.before').read_bytes(),self.content[1]); self.assertTrue((m.BACKUP/'receipt.before.json').exists()); self.assertTrue((m.BACKUP/'acceptance.before/result.txt').exists()); self.assertFalse(m.RECEIPT.exists()); self.assertFalse(m.EVIDENCE.exists())
  self.assertEqual(m.BACKUP.stat().st_mode & 0o777,0o700); self.assertEqual(m.GUARD.stat().st_mode & 0o777,0o644); self.assertEqual(m.RUNNER.stat().st_mode & 0o777,0o600)
  self.assertFalse(any('start' in a or 'stop' in a or 'enable' in a or 'restart' in a or 'flush' in a for a in self.commands))
 def test_table_rule_chain_or_handle_drift_refuses_before_backup(self):
  base=self.table
  for objects in (base+[{'rule':{}}],base+[{'chain':{}}],[{'table':{'family':'inet','name':m.TABLE,'handle':43}}]):
   self.table=objects
   with self.assertRaises(ValueError): m.check()
   self.assert_no_mutation()
 def test_recheck_rejects_rule_appearing_before_delete(self):
  content=m.check(); self.table.append({'chain':{}})
  with self.assertRaises(ValueError): m.apply(content)
  self.assertTrue(m.BACKUP.exists()); self.assertTrue(m.GUARD_NEXT.exists()); self.assertTrue(m.RECEIPT.exists()); self.assertFalse(any(a[1]=='delete' for a in self.commands))
 def test_hash_or_existing_backup_refuses(self):
  m.GUARD.write_bytes(b'changed')
  with self.assertRaises(ValueError): m.check()
  self.assertFalse(m.BACKUP.exists())
  m.GUARD.write_bytes(self.content[0]); m.BACKUP.mkdir()
  with self.assertRaises(ValueError): m.check()
  self.assertEqual(list(m.BACKUP.iterdir()),[])
 def test_receipt_uid_token_and_failed_cleanup_refuse(self):
  for receipt in ({'uid':990,'token':'a'*32},{'uid':989,'token':'wrong'},{'uid':989,'token':'a'*32,'extra':0}):
   m.RECEIPT.write_text(json.dumps(receipt))
   with self.assertRaises(ValueError): m.check()
   self.assert_no_mutation()
  m.RECEIPT.write_text(json.dumps({'uid':989,'token':'a'*32})); (m.EVIDENCE/'result.txt').write_text('probe_passed=false\napplication_accepted=false\ncleanup_failed=1\n')
  with self.assertRaises(ValueError): m.check()
  self.assert_no_mutation()
 def test_cross_filesystem_rename_refused(self):
  original=m.Path.stat
  def altered(path,*a,**k):
   result=original(path,*a,**k)
   if path==m.RECEIPT:
    values=list(result); values[2]=result.st_dev+1; return os.stat_result(values)
   return result
  with patch.object(m.Path,'stat',altered), self.assertRaises(ValueError): m.check()
  self.assert_no_mutation()
 def test_failed_delete_keeps_every_original_and_backup(self):
  self.failure='delete'
  with self.assertRaises(ValueError): m.apply(m.check())
  self.assertTrue(m.BACKUP.exists()); self.assertTrue(m.RECEIPT.exists()); self.assertTrue(m.EVIDENCE.exists()); self.assertEqual(m.GUARD.read_bytes(),self.content[0]); self.assertEqual(m.RUNNER.read_bytes(),self.content[1]); self.assertEqual(self.guard_state,'failed')
 def test_rename_failure_does_not_fallback_to_copy_delete(self):
  original=m.os.rename
  def rename(src,dst):
   if src==str(m.EVIDENCE): raise OSError('simulated evidence rename failure')
   return original(src,dst)
  with patch.object(m.os,'rename',side_effect=rename), self.assertRaises(OSError): m.apply(m.check())
  self.assertTrue((m.BACKUP/'receipt.before.json').exists()); self.assertTrue(m.EVIDENCE.exists()); self.assertEqual(m.GUARD.read_bytes(),self.content[0]); self.assertEqual(self.guard_state,'failed')
 def test_partial_file_pair_is_retained_and_not_retried(self):
  original=m.os.replace
  def replace(src,dst):
   if src==str(m.RUNNER_NEXT): raise OSError('simulated second replacement failure')
   return original(src,dst)
  with patch.object(m.os,'replace',side_effect=replace), self.assertRaises(OSError): m.apply(m.check())
  self.assertEqual(m.GUARD.read_bytes(),self.content[2]); self.assertEqual(m.RUNNER.read_bytes(),self.content[1]); self.assertTrue(m.RUNNER_NEXT.exists()); self.assertEqual(self.guard_state,'failed')
  with self.assertRaises(ValueError): m.check()
 def test_default_cli_never_calls_apply(self):
  previous=os.umask(0o022)
  try:
   with patch.object(m.os,'getuid',return_value=0),patch.object(m.os,'geteuid',return_value=0),patch.object(m,'apply') as apply,contextlib.redirect_stdout(io.StringIO()) as output:
    self.assertEqual(m.main([]),0); apply.assert_not_called(); self.assertFalse(json.loads(output.getvalue())['repair_applied'])
  finally: os.umask(previous)
 def test_nonroot_refused_before_check(self):
  with patch.object(m.os,'getuid',return_value=989),patch.object(m,'check') as check,contextlib.redirect_stdout(io.StringIO()): self.assertEqual(m.main([]),1)
  check.assert_not_called()

class BoundaryTests(unittest.TestCase):
 def test_real_command_wrapper_does_not_accept_partial_stdout(self):
  with patch.object(m,'trusted'),patch.object(m.subprocess,'run',return_value=SimpleNamespace(returncode=1,stdout='LoadState=not-found\n')) as run,self.assertRaises(ValueError): m.call(['/usr/bin/systemctl','show',m.UNIT])
  self.assertFalse(run.call_args[1]['shell']); self.assertEqual(run.call_args[1]['env'],m.ENV)
 def test_guard_state_uid_and_remaining_process_gates(self):
  account=SimpleNamespace(pw_uid=989,pw_name='aifinance')
  def state(unit):
   if unit==m.UNIT: return {'LoadState':'loaded','ActiveState':'failed','MainPID':'0'}
   if unit in m.PROBES: return {'LoadState':'not-found'}
   return {'LoadState':'loaded','ActiveState':'inactive','MainPID':'0'}
  with patch.object(m.pwd,'getpwnam',return_value=account),patch.object(m.pwd,'getpwall',return_value=[account]),patch.object(m.Path,'iterdir',return_value=[]),patch.object(m,'state',side_effect=state),patch.object(m,'call',return_value=''):
   m.idle_conditions()
   with patch.object(m,'state',return_value={'LoadState':'loaded','ActiveState':'active','MainPID':'99'}),self.assertRaises(ValueError): m.idle_conditions()
   with patch.object(m.Path,'iterdir',return_value=[Path('/proc/123')]),patch.object(m.Path,'read_text',return_value='Uid:\t0 0 989 0\n'),self.assertRaises(ValueError): m.idle_conditions()
   with patch.object(m.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=990)),self.assertRaises(ValueError): m.idle_conditions()
 def test_trusted_paths_reject_symlink_nonroot_or_writable(self):
  for mode,uid in ((stat.S_IFLNK|0o777,0),(stat.S_IFREG|0o644,989),(stat.S_IFREG|0o664,0)):
   with patch.object(m.Path,'lstat',return_value=SimpleNamespace(st_mode=mode,st_uid=uid)),self.assertRaises(ValueError): m.trusted(m.GUARD)

if __name__=='__main__': unittest.main(verbosity=2)
