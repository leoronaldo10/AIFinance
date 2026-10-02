"""Mocks only; transforms a private copy's binary paths, UID gate and evidence path."""
import json, os, pathlib, subprocess, sys, tempfile, unittest
SCRIPT=pathlib.Path(__file__).resolve().parents[2]/'deploy/native/accept-egress.sh'
FAKE=r'''#!PYTHON
import fcntl, json, os, pathlib, signal, subprocess, sys
name=pathlib.Path(sys.argv[0]).name; a=sys.argv[1:]
p=pathlib.Path(os.environ['FAKE_STATE']); lock=open(str(p)+'.lock','w'); fcntl.flock(lock,fcntl.LOCK_EX); s=json.loads(p.read_text()); scenario=s['scenario']
s['log'].append([name]+a)
def save(): p.write_text(json.dumps(s))
def out(x='',code=0):
 save()
 if x: print(x)
 raise SystemExit(code)
def unit_name():
 return next((v.split('=',1)[1] for v in a if v.startswith('--unit=')), None)
if name=='python3':
 if '/opt/aifinance/bin/egress-guard.py' in a:
  n=s.get('counter',0); out(json.dumps({'guard_loaded':True,'uid':1007,'table':'aifinance_preview_egress_v1','handle':11,'counters':{'a'*32+':deny-v4':{'packets':n,'bytes':n*40},'a'*32+':deny-v6':{'packets':0 if scenario=='counter-failure' else n,'bytes':n*60}}}))
 save(); fcntl.flock(lock,fcntl.LOCK_UN)
 if '-' in a:
  source=sys.stdin.read()
  if 'spec.loader.exec_module(g)' in source: print('1007 '+'a'*32); raise SystemExit(0)
  result=subprocess.run([REAL_PY]+a,input=source,universal_newlines=True); raise SystemExit(result.returncode)
 result=subprocess.run([REAL_PY]+a); raise SystemExit(result.returncode)
if name=='nft':
 tables=[]
 if scenario=='table-conflict': tables=[{'table':{'family':'inet','name':'aifinance_preview_probe'}}]
 out(json.dumps({'nftables':tables}))
if name=='ip':
 if 'add' in a:
  fam=6 if '-6' in a else 4
  if scenario=='address6-failure' and fam==6: out(code=1)
  s['addresses'].append(fam); out()
 if 'del' in a:
  fam=6 if '-6' in a else 4
  s['addresses'].remove(fam); out()
 if 'route' in a: out('default via 192.168.1.1 dev eth0' if '-4' in a else 'default via fe80::1 dev eth0')
 if 'to' in a:
  assert a[a.index('to')+1]=='2001:db8:ffff::254/128'
  s['dad_queries']=s.get('dad_queries',0)+1
  if scenario=='dad-query-failure': out('1: lo inet6 2001:db8:ffff::254/128 scope global',code=1)
  if scenario=='dad-address-missing': out()
  flags=' dadfailed' if scenario=='dad-failure' else (' tentative' if scenario=='dad-timeout' or (scenario=='dad-delayed' and s['dad_queries']<3) else '')
  out('1: lo inet6 2001:db8:ffff::254/128 scope global'+flags)
 lines=['1: lo inet 127.0.0.1/8 scope host lo']
 if 4 in s['addresses']: lines.append('1: lo inet 192.0.2.254/32 scope global lo')
 if 6 in s['addresses']: lines.append('1: lo inet6 2001:db8:ffff::254/128 scope global')
 out('\n'.join(lines))
if name=='ss':
 if any('8000' in x for x in a): out('LISTEN 0 128 127.0.0.1:8000 0.0.0.0:* users:(("old",pid=800,fd=3)) uid:1000 ino:9 sk:7')
 if scenario=='port-query-failure' and '-antup' in a: out(code=1)
 if scenario=='port-conflict' and '-antup' in a: out('LISTEN 0 128 0.0.0.0:48173 0.0.0.0:* users:(("other",pid=900,fd=3))')
 if s['units'].get('aifinance-isolation-listener.service',{}).get('active'):
  out('\n'.join('LISTEN 0 8 '+x+':48173 *:* users:(("python3",pid=123,fd=3))' for x in ['127.0.0.1','[::1]','192.0.2.254','[2001:db8:ffff::254]']))
 out()
if name=='systemctl':
 if '--version' in a: out('systemd 239')
 unit=next((v for v in a if v.endswith('.service')), '')
 if a[0]=='start':
  assert unit=='aifinance-preview-egress.service', a
  s['guard_attempted']=True
  if scenario=='guard-failure': out(code=1)
  s['guard_loaded']=True; out()
 if a[0]=='stop':
  assert unit.startswith('aifinance-isolation-'), a
  if scenario=='stop-failure' and 'listener' in unit: out(code=1)
  s['units'].pop(unit,None); out()
 if a[0]=='show':
  prop=next(v.split('=',1)[1] for v in a if v.startswith('--property='))
  if scenario=='partial-show-error' and unit=='aifinance-isolation-listener.service': out('not-found',code=1)
  u=s['units'].get(unit)
  isguard=unit=='aifinance-preview-egress.service'
  def field(k):
   if k=='LoadState': return 'loaded' if u or isguard or unit in ['firewalld.service','aifinance-preview-api.service','aifinance-preview-web.service'] else 'not-found'
   if k=='Description': return u['owner'] if u else ''
   if k=='ActiveState': return 'active' if (u and u.get('active')) or unit=='firewalld.service' or (isguard and s.get('guard_loaded')) else 'inactive'
   if k=='SubState': return 'running' if field('ActiveState')=='active' else 'dead'
   if k=='MainPID': return '123' if u and u.get('active') else ('800' if unit=='firewalld.service' else '0')
   if k=='FragmentPath': return '/etc/systemd/system/aifinance-preview-egress.service'
   if k=='DropInPaths': return ''
   if k=='NeedDaemonReload': return 'no'
   if k=='Result': return 'success'
   return ''
  out(field(prop) if '--value' in a else '\n'.join(k+'='+field(k) for k in prop.split(',')))
if name=='systemd-run':
 unit=unit_name(); owner=next(v.split('=',1)[1] for v in a if v.startswith('Description='))
 mode=a[a.index('/opt/aifinance/bin/isolation-probe.py')+1]
 s['units'][unit]={'active':mode=='serve','owner':owner}
 if mode=='serve': out()
 memory=int(a[a.index('--memory-limit-mib')+1]); uid=0 if mode=='control' else 1007
 if (scenario=='baseline-failure' and mode=='baseline') or (scenario=='guarded320-failure' and memory==320): out(code=1)
 if scenario=='term-after-guard' and memory==320:
  save(); os.kill(os.getppid(),signal.SIGTERM); out()
 if scenario=='foreign-owner' and mode=='control': s['units']['aifinance-isolation-listener.service']['owner']='foreign-administrator'
 if mode=='guarded': s['counter']=s.get('counter',0)+1
 result={'mode':mode,'expectations_matched':True,'memory':{'uid':uid,'memory.limit_in_bytes':memory*1024*1024},'network':[{'expectation_matched':True} for _ in range(4)]}
 # Successful transient units may be collected before cleanup.
 s['units'].pop(unit,None)
 out(json.dumps(result))
if name=='sleep': out()
if name=='journalctl': out('{"listeners_ready":true}')
raise SystemExit('unexpected mock command '+name+' '+str(a))
'''.replace('REAL_PY',repr(sys.executable)).replace('#!PYTHON','#!'+sys.executable)

class RunnerTests(unittest.TestCase):
 def run_case(self,scenario):
  with tempfile.TemporaryDirectory() as directory:
   root=pathlib.Path(directory); evidence=root/'evidence'; state=root/'state.json'; commands=root/'bin'; commands.mkdir()
   state.write_text(json.dumps({'scenario':scenario,'addresses':[],'units':{},'log':[]}))
   script=SCRIPT.read_text().replace('[[ $# == 0 && $EUID == 0 ]]','[[ $# == 0 ]]').replace('readonly EVIDENCE=/run/aifinance-egress-acceptance','readonly EVIDENCE='+str(evidence))
   for name,path in [('python3','/usr/bin/python3'),('systemctl','/usr/bin/systemctl'),('systemd-run','/usr/bin/systemd-run'),('journalctl','/usr/bin/journalctl'),('ss','/usr/sbin/ss'),('ip','/usr/sbin/ip'),('nft','/usr/sbin/nft'),('sleep','/usr/bin/sleep')]:
    tool=commands/name; tool.write_text(FAKE); tool.chmod(0o755); script=script.replace(path,str(tool))
   copy=root/'test-only.sh'; copy.write_text(script)
   result=subprocess.run(['/usr/bin/bash',str(copy)],env=dict(os.environ,FAKE_STATE=str(state)),stdout=subprocess.PIPE,stderr=subprocess.PIPE,universal_newlines=True,timeout=20)
   data=json.loads(state.read_text()); data['result_file']=(evidence/'result.txt').read_text() if (evidence/'result.txt').exists() else ''
   return result,data
 def test_success_keeps_guard_cleans_only_probe_addresses(self):
  r,s=self.run_case('success'); self.assertEqual(r.returncode,0,r.stdout+r.stderr); self.assertEqual(s['addresses'],[]); self.assertEqual(s['units'],{}); self.assertTrue(s['guard_loaded']); self.assertIn('probe_passed=true',s['result_file'])
 def test_baseline_failure_never_loads_guard(self):
  r,s=self.run_case('baseline-failure'); self.assertNotEqual(r.returncode,0); self.assertEqual(s['addresses'],[]); self.assertEqual(s['units'],{}); self.assertNotIn('guard_attempted',s)
 def test_delayed_dad_readiness_waits_without_disabling_ipv6(self):
  r,s=self.run_case('dad-delayed'); self.assertEqual(r.returncode,0,r.stdout+r.stderr); self.assertEqual(s['dad_queries'],3); self.assertTrue(s['guard_loaded']); self.assertEqual(sum(x[0]=='sleep' for x in s['log']),2)
 def test_persistent_tentative_stops_after_bounded_wait_before_services(self):
  r,s=self.run_case('dad-timeout'); self.assertNotEqual(r.returncode,0); self.assertEqual(s['dad_queries'],11); self.assertEqual(sum(x[0]=='sleep' for x in s['log']),10); self.assertEqual(s['addresses'],[]); self.assertEqual(s['units'],{}); self.assertNotIn('guard_attempted',s)
 def test_dad_failure_missing_address_or_query_error_never_starts_services(self):
  for scenario in ('dad-failure','dad-address-missing','dad-query-failure'):
   r,s=self.run_case(scenario); self.assertNotEqual(r.returncode,0,scenario); self.assertEqual(s['dad_queries'],1); self.assertEqual(s['addresses'],[]); self.assertEqual(s['units'],{}); self.assertNotIn('guard_attempted',s); self.assertFalse(any(x[0]=='sleep' for x in s['log']))
 def test_partial_address_failure_removes_only_first_address(self):
  r,s=self.run_case('address6-failure'); self.assertNotEqual(r.returncode,0); self.assertEqual(s['addresses'],[]); deletions=[x for x in s['log'] if x[0]=='ip' and 'del' in x]; self.assertEqual(len(deletions),1); self.assertIn('-4',deletions[0])
 def test_failed_guard_start_does_not_delete_guard_or_receipt(self):
  r,s=self.run_case('guard-failure'); self.assertNotEqual(r.returncode,0); self.assertEqual(s['addresses'],[]); self.assertTrue(s['guard_attempted']); self.assertFalse(any(x[0]=='systemctl' and x[1]=='stop' and 'aifinance-preview-egress.service' in x for x in s['log']))
 def test_later_probe_failure_keeps_guard_and_cleans_all_probes(self):
  r,s=self.run_case('guarded320-failure'); self.assertNotEqual(r.returncode,0); self.assertTrue(s['guard_loaded']); self.assertEqual(s['addresses'],[]); self.assertEqual(s['units'],{})
 def test_missing_v6_counter_cannot_pass(self):
  r,s=self.run_case('counter-failure'); self.assertNotEqual(r.returncode,0); self.assertEqual(s['addresses'],[]); self.assertTrue(s['guard_loaded']); self.assertIn('probe_passed=false',s['result_file'])
 def test_conflict_or_query_failure_never_changes_network(self):
  for scenario in ['table-conflict','port-conflict','port-query-failure','partial-show-error']:
   r,s=self.run_case(scenario); self.assertNotEqual(r.returncode,0,scenario); self.assertEqual(s['addresses'],[]); self.assertFalse(any(x[0]=='ip' and 'add' in x for x in s['log'])); self.assertNotIn('guard_attempted',s)
 def test_stop_failure_leaves_addresses_and_marks_not_passed(self):
  r,s=self.run_case('stop-failure'); self.assertNotEqual(r.returncode,0); self.assertEqual(s['addresses'],[4,6]); self.assertIn('cleanup_failed=1',s['result_file'])
 def test_term_after_guard_retains_guard_and_cleans_only_probes(self):
  r,s=self.run_case('term-after-guard'); self.assertNotEqual(r.returncode,0); self.assertTrue(s['guard_loaded']); self.assertEqual(s['addresses'],[]); self.assertEqual(s['units'],{}); self.assertIn('probe_passed=false',s['result_file'])
 def test_changed_unit_owner_refuses_stop_and_retains_addresses(self):
  r,s=self.run_case('foreign-owner'); self.assertNotEqual(r.returncode,0); self.assertTrue(s['guard_loaded']); self.assertEqual(s['addresses'],[4,6]); self.assertIn('cleanup_failed=1',s['result_file']); self.assertFalse(any(x[0]=='systemctl' and x[1]=='stop' and 'aifinance-isolation-listener.service' in x for x in s['log']))
 def test_no_dangerous_commands_in_deliverable(self):
  s=SCRIPT.read_text(); self.assertNotIn('nft flush',s); self.assertNotIn('reset-failed "',s); self.assertNotIn('systemctl enable',s); self.assertNotIn('systemctl restart',s); self.assertNotIn('initdb',s); self.assertNotIn('ExecStartPre=',s); self.assertNotIn('nodad',s); self.assertNotIn('sysctl',s)

if __name__=='__main__': unittest.main(verbosity=2)
