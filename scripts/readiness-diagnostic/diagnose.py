#!/usr/bin/python3
"""One detached, diagnosis-only session. No collector, database or recovery action."""
import argparse,hashlib,json,os,pwd,re,runpy,signal,stat,subprocess,sys,time
from pathlib import Path
ROOT=Path('/root/aifinance-readiness-diagnostic-v2');INPUT=Path('/run/aifinance-readiness-v2');UNITS=Path('/run/systemd/system')
CONTROLLER='aifinance-readiness-v2.service';SLEEP='aifinance-readiness-v2-sleep-probe.service';PYTHON='aifinance-readiness-v2-python.service';CHILDREN=(SLEEP,PYTHON)
SOURCE=Path('/etc/aifinance-collect-once');OLD=Path('/var/lib/aifinance-collect-once')
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C','HOME':'/root','SYSTEMD_PAGER':'cat','SYSTEMD_COLORS':'0'}
class Refused(Exception):
 def __init__(self,reason,evidence=None):super().__init__(reason);self.evidence=evidence or {}
def need(v,reason):
 if not v:raise Refused(reason)
def reason(e):return str(e) if type(e).__name__=='Refused' and re.fullmatch('[a-z_]{1,100}',str(e)) else 'diagnostic_operation_failed'
def trusted(p):
 for q in (p,*p.parents):
  st=q.lstat();need(st.st_uid==0 and not st.st_mode&0o022 and not stat.S_ISLNK(st.st_mode),'untrusted_diagnostic_path')
def digest(data):return hashlib.sha256(data).hexdigest()
def syncdir(p):
 fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
def exclusive(p,data,mode=0o600,gid=0):
 trusted(p.parent);fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
 with os.fdopen(fd,'wb') as f:os.fchown(f.fileno(),0,gid);os.fchmod(f.fileno(),mode);f.write(data);f.flush();os.fsync(f.fileno())
 syncdir(p.parent)
def save_report(report):
 p=ROOT/('report.next.'+str(os.getpid())+'.'+str(time.monotonic_ns()));exclusive(p,json.dumps(report,sort_keys=True).encode());os.replace(p,ROOT/'report.json');syncdir(ROOT)
def read_report():
 p=ROOT/'report.json'
 if not p.exists():return {'stage':'diagnostic_pending','final':False,'passed':False,'tests':[]}
 trusted(p);return json.loads(p.read_text())
def systemctl(args,timeout=5,ok=True):
 need(args and args[0] in ('show','start','stop','daemon-reload','--version'),'unapproved_diagnostic_command')
 if args[0] in ('start','stop'):need(all(a in (CONTROLLER,*CHILDREN,'--no-block') for a in args[1:]),'unapproved_diagnostic_unit')
 if args[0]=='show':need(len(args)>1 and args[1] in (CONTROLLER,*CHILDREN) and all(a=='--all' or a.startswith('--property=') for a in args[2:]),'unapproved_diagnostic_unit')
 p=subprocess.run(['/usr/bin/systemctl','--no-pager',*args],capture_output=True,env=ENV,timeout=timeout)
 need(len(p.stdout)<=131072 and len(p.stderr)<=131072,'diagnostic_output_limit')
 if ok:need(p.returncode==0,'diagnostic_systemctl_failed')
 return p

def props(unit,keys,timeout=5):
 evidence={'requested':list(keys),'missing':[],'reader':'systemctl_show'}
 try:p=systemctl(['show',unit,'--all']+['--property='+k for k in keys],timeout=timeout,ok=False)
 except subprocess.TimeoutExpired:raise Refused('unit_evidence_query_timeout',evidence) from None
 except OSError:raise Refused('unit_evidence_reader_unavailable',evidence) from None
 evidence['returncode']=p.returncode;values={}
 for line in p.stdout.decode().splitlines():
  if '=' in line:
   k,v=line.split('=',1)
   if k not in keys or k in values:raise Refused('invalid_unit_properties',evidence)
   values[k]=v
 evidence['missing']=sorted(set(keys)-set(values))
 if p.returncode!=0 and values.get('LoadState')!='not-found':raise Refused('diagnostic_systemctl_failed',evidence)
 if evidence['missing']:raise Refused('missing_unit_properties',evidence)
 return values

def busctl_preflight():
 p=Path('/usr/bin/busctl')
 try:st=p.lstat()
 except FileNotFoundError:raise Refused('busctl_missing') from None
 except OSError:raise Refused('busctl_metadata_unavailable') from None
 try:trusted(p)
 except Exception:raise Refused('busctl_untrusted_path') from None
 need(stat.S_ISREG(st.st_mode) and os.access(p,os.X_OK),'busctl_not_executable')

def typed_empty(unit,key):
 # systemctl suppresses empty structure arrays even with --all. Never infer empty
 # from missing text: require the real D-Bus type and explicit zero element count.
 signatures={'ExecStartPre':'a(sasbttttuii)','EnvironmentFiles':'a(sb)'}
 need(unit in CHILDREN and key in signatures,'unapproved_diagnostic_property')
 path='/org/freedesktop/systemd1/unit/'+''.join(c if c.isascii() and c.isalnum() else '_'+format(ord(c),'02x') for c in unit)
 evidence={'requested':[key],'reader':'busctl_typed','signature':signatures[key],'empty':False}
 try:
  busctl_preflight()
  p=subprocess.run(['/usr/bin/busctl','--system','--no-pager','--timeout=3','get-property','org.freedesktop.systemd1',path,'org.freedesktop.systemd1.Service',key],capture_output=True,env=ENV,timeout=4)
 except Refused as e:raise Refused(str(e),evidence) from None
 except subprocess.TimeoutExpired:raise Refused('typed_property_query_timeout',evidence) from None
 except PermissionError:raise Refused('busctl_execution_denied',evidence) from None
 except FileNotFoundError:raise Refused('busctl_missing',evidence) from None
 except OSError:raise Refused('busctl_execution_failed',evidence) from None
 evidence['returncode']=p.returncode
 if p.returncode!=0:raise Refused('typed_property_query_failed',evidence)
 if len(p.stdout)>131072 or len(p.stderr)>131072:raise Refused('diagnostic_output_limit',evidence)
 # No command arguments, environment-file paths or arbitrary output are logged.
 if p.stdout.strip()!=(signatures[key]+' 0').encode():raise Refused('typed_property_not_verified_empty',evidence)
 evidence['empty']=True;return evidence

def controller_text(manifest):
 return f'''[Unit]
Description=AIFinance diagnosis only, no collection
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -I -B {ROOT}/diagnose.py run --manifest-sha {manifest}
ExecStopPost=/usr/bin/python3 -I -B {ROOT}/diagnose.py cleanup --manifest-sha {manifest}
TimeoutStartSec=90
TimeoutStopSec=45
KillMode=control-group
Restart=no
PrivateNetwork=yes
RestrictAddressFamilies=AF_UNIX
InaccessiblePaths=-/run/postgresql -/var/run/postgresql -/etc/aifinance-preview.env
StandardOutput=null
StandardError=null
UMask=0077
'''
def child_text(unit):
 need(unit in CHILDREN,'unapproved_diagnostic_unit')
 command='/usr/bin/sleep 12' if unit==SLEEP else '/usr/bin/python3 -I -B -c "import time; time.sleep(12)"'
 return f'''[Unit]
Description=AIFinance inert identity and sandbox diagnostic
[Service]
Type=oneshot
User=aifinance-collect-once
Group=aifinance-collect-once
ExecStart=/usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C {command}
WorkingDirectory=/
TimeoutStartSec=20
TimeoutStopSec=3
KillMode=control-group
Restart=no
MemoryAccounting=yes
MemoryMax=256M
TasksMax=32
CPUQuota=50%
LimitNOFILE=512
LimitCORE=0
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
SupplementaryGroups=
PrivateNetwork=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
RestrictAddressFamilies=AF_UNIX AF_INET
BindReadOnlyPaths={INPUT}/hosts:/etc/hosts {INPUT}/nsswitch.conf:/etc/nsswitch.conf
InaccessiblePaths=-/etc/aifinance-collect-once -/var/lib/aifinance-collect-once -/opt/aifinance-collect-once -/opt/aifinance/staging -/opt/aifinance/releases -/opt/aifinance/switch -/etc/aifinance-preview.env -/run/postgresql -/var/run/postgresql -/run/nscd -/var/run/nscd
StandardOutput=null
StandardError=null
'''
def verify_bundle(manifest):
 need(os.geteuid()==0,'local_root_required');need(sys.version_info>=(3,9) and hasattr(os,'pidfd_open'),'python_pidfd_support_required');need(re.fullmatch('[a-f0-9]{64}',manifest),'manifest_digest_required');trusted(ROOT)
 p=ROOT/'DIAGNOSTIC.SHA256';trusted(p);need(digest(p.read_bytes())==manifest,'diagnostic_manifest_changed');names=[]
 for line in p.read_text().splitlines():
  h,n=line.split();need(n in ('diagnose.py','diagnose-install.sh','diagnostic_core.py','process_readiness.py') and n not in names,'diagnostic_manifest_scope');names.append(n);trusted(ROOT/n);need(digest((ROOT/n).read_bytes())==h,'diagnostic_file_changed')
 need(len(names)==4,'diagnostic_manifest_incomplete')

def guard_snapshot():
 result={}
 for name in ('state.json','retry-001/state.json','retry-001/started','consumed'):
  p=OLD/name
  if not p.exists() and not p.is_symlink():result[name]=None;continue
  trusted(p);st=p.stat();need(p.is_file() and st.st_size<=131072,'invalid_original_audit_file');result[name]=[digest(p.read_bytes()),st.st_ino,st.st_mtime_ns,st.st_mode,st.st_uid,st.st_gid]
 return result

def claim_session():
 exclusive(ROOT/'validation.started',b'diagnosis only; never collection or retry\n')
 exclusive(ROOT/'guards.json',json.dumps(guard_snapshot(),sort_keys=True).encode())
 exclusive(ROOT/'boot-id',Path('/proc/sys/kernel/random/boot_id').read_bytes())

def unit_available(unit):
 p=UNITS/unit;need(not p.exists() and not p.is_symlink(),'diagnostic_unit_file_collision')
 need(props(unit,('LoadState',))['LoadState']=='not-found','diagnostic_unit_collision')

def launch(manifest):
 need(os.uname().nodename=='iZ2zedybs3fftu1d9vnx39Z','wrong_diagnostic_host')
 if (ROOT/'validation.started').exists():
  report=read_report()
  if not report.get('final'):
   state=props(CONTROLLER,('ActiveState','LoadState'))
   if state['ActiveState'] in ('inactive','failed') or state['LoadState']=='not-found':
    if not (ROOT/'boot-id').exists() or (ROOT/'boot-id').read_bytes()!=Path('/proc/sys/kernel/random/boot_id').read_bytes():
     report.update(tests_passed=False,reason='diagnostic_interrupted_before_completion');save_report(report)
    cleanup(manifest)
  return
 p=UNITS/CONTROLLER;text=controller_text(manifest).encode()
 if p.exists():trusted(p);need(p.read_bytes()==text,'diagnostic_controller_collision')
 else:unit_available(CONTROLLER);exclusive(p,text,0o644)
 systemctl(['daemon-reload']);systemctl(['start','--no-block',CONTROLLER])

def prepare_children():
 need(Path('/proc/1/comm').read_text().strip()=='systemd','real_systemd_required')
 account=pwd.getpwnam('aifinance-collect-once');need(account.pw_uid>0 and account.pw_gid>0 and account.pw_shell=='/sbin/nologin','diagnostic_identity_changed')
 need(set(os.getgrouplist(account.pw_name,account.pw_gid))=={account.pw_gid},'unexpected_supplementary_groups')
 original=json.loads((OLD/'state.json').read_text());need((original['uid'],original['gid'])==(account.pw_uid,account.pw_gid),'original_identity_mismatch')
 for unit in CHILDREN:unit_available(unit)
 need(not INPUT.exists() and not INPUT.is_symlink(),'diagnostic_input_collision')
 data_by_name={}
 for name in ('hosts','nsswitch.conf'):
  p=SOURCE/name;trusted(p);st=p.stat();need(p.is_file() and st.st_size<=16384 and st.st_gid==account.pw_gid and stat.S_IMODE(st.st_mode)==0o440,'original_resolver_metadata_changed');data_by_name[name]=p.read_bytes()
 need(data_by_name['nsswitch.conf']==b'hosts: files\n','original_nsswitch_policy_changed')
 receipt={name:digest(data) for name,data in data_by_name.items()};exclusive(ROOT/'inputs.json',json.dumps(receipt).encode())
 INPUT.mkdir(mode=0o750);os.chown(INPUT,0,account.pw_gid);os.chmod(INPUT,0o750)
 exclusive(INPUT/'owner',digest((ROOT/'DIAGNOSTIC.SHA256').read_bytes()).encode())
 for name,data in data_by_name.items():exclusive(INPUT/name,data,0o440,account.pw_gid)
 for unit in CHILDREN:exclusive(UNITS/unit,child_text(unit).encode(),0o644)
 systemctl(['daemon-reload']);return account

class Adapter:
 def __init__(self,account,core):self.state={'uid':account.pw_uid,'gid':account.pw_gid};self.core=core;self.last={};self.query_failure={}
 def properties(self,unit,keys,timeout=2):
  need(unit in CHILDREN,'unapproved_diagnostic_unit')
  try:return props(unit,keys,timeout)
  except Refused as e:
   self.query_failure=e.evidence;self.last.update(stage='unit_property_query_failed',reason=reason(e),unit_query=e.evidence);raise
 def process_diagnostic(self,stage,values):
  allowed={'role','expected_uid','expected_gid','pid','start_ticks','uids','gids','no_new_privileges','capabilities_zero','checks','resolver_bindings_readonly','cgroup_verified','exec_matches','reason','cgroup','resolver_checks'}
  need(set(values)<=allowed,'diagnostic_fields_invalid');record=dict(values,stage=stage);record['role']='sleep_diagnostic' if values.get('role')=='resource_probe' else 'python_diagnostic'
  if self.query_failure:record['unit_query']=self.query_failure
  self.last=record
  fd=os.open(ROOT/'events.jsonl',os.O_WRONLY|os.O_CREAT|os.O_APPEND|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'w') as out:out.write(json.dumps(record,sort_keys=True)+'\n');out.flush();os.fsync(out.fileno())
 def verify_profile(self,unit):
  expected={'User':'aifinance-collect-once','Group':'aifinance-collect-once','Type':'oneshot','NoNewPrivileges':'yes','PrivateNetwork':'yes','MemoryMax':'268435456','TasksMax':'32','CPUQuotaPerSecUSec':'500ms','CapabilityBoundingSet':'','AmbientCapabilities':'','Restart':'no','KillMode':'control-group','ProtectSystem':'strict','DropInPaths':''}
  actual=self.properties(unit,tuple(expected))
  mismatched=[k for k in expected if actual[k]!=expected[k]]
  if mismatched:
   self.last.update(stage='unit_profile_failed',reason='diagnostic_unit_profile_mismatch',mismatched=mismatched);raise Refused('diagnostic_unit_profile_mismatch')
  for key in ('ExecStartPre','EnvironmentFiles'):
   try:typed_empty(unit,key)
   except Refused as e:
    self.last.update(stage='unit_profile_failed',reason=reason(e),unit_query=e.evidence);raise
 def test(self,unit,readiness):
  self.last={};self.query_failure={};self.verify_profile(unit);expected=Path('/usr/bin/sleep' if unit==SLEEP else '/usr/bin/python3');self.core['trusted_tool'](expected)
  sample=None
  try:
   systemctl(['start','--no-block',unit]);sample=readiness['wait_for_process'](self,unit,expected,INPUT,self.core['require_cgroup_v2'],self.core['verify_cgroup_v2'],timeout=5)
   need(os.stat('/proc/'+str(sample.pid)+'/ns/net').st_ino!=os.stat('/proc/1/ns/net').st_ino,'diagnostic_network_namespace_not_isolated')
   deadline=time.monotonic()+20
   while time.monotonic()<deadline:
    state=self.properties(unit,readiness['FIELDS']);sample.observe_running(state)
    if state['MainPID']=='0' and state['ActiveState'] in ('inactive','failed'):break
    time.sleep(.025)
   else:raise Refused('diagnostic_natural_exit_timeout')
   need(self.properties(unit,('Result','ExecMainStatus','ExecMainCode'))=={'Result':'success','ExecMainStatus':'0','ExecMainCode':'1'},'diagnostic_natural_exit_failed')
   return {'name':'sleep' if unit==SLEEP else 'python','readiness':True,'natural_exit':True,'network_isolated':True,'uid':self.state['uid'],'gid':self.state['gid'],'no_new_privileges':1,'capabilities_zero':True,'readonly_mounts':True,**sample.evidence}
  finally:
   try:systemctl(['stop',unit]);need(props(unit,('MainPID',))['MainPID']=='0','diagnostic_child_not_stopped')
   finally:
    if sample is not None:sample.close()

def cleanup(manifest,final=True):
 errors=[]
 for unit in CHILDREN:
  p=UNITS/unit
  try:
   load=props(unit,('LoadState',))['LoadState']
   if p.exists():
    trusted(p);need(p.read_bytes()==child_text(unit).encode(),'diagnostic_unit_changed')
    if load!='not-found':systemctl(['stop',unit]);need(props(unit,('MainPID',))['MainPID']=='0','diagnostic_child_not_stopped')
    p.unlink()
   elif load!='not-found':
    state=props(unit,('MainPID','ActiveState'));need(state['MainPID']=='0' and state['ActiveState'] in ('inactive','failed'),'unowned_diagnostic_process')
  except Exception:errors.append('child_cleanup_failed')
 if INPUT.exists() or INPUT.is_symlink():
  try:
   trusted(INPUT);trusted(INPUT/'owner');need((INPUT/'owner').read_text()==digest((ROOT/'DIAGNOSTIC.SHA256').read_bytes()),'diagnostic_input_owner_changed');receipt=json.loads((ROOT/'inputs.json').read_text());need(set(p.name for p in INPUT.iterdir())<=set(receipt)|{'owner'},'diagnostic_inputs_changed')
   for name,h in receipt.items():
    p=INPUT/name
    if p.exists():trusted(p);need(digest(p.read_bytes())==h,'diagnostic_input_changed');p.unlink()
   (INPUT/'owner').unlink();INPUT.rmdir()
  except Exception:errors.append('input_cleanup_failed')
 if final:
  p=UNITS/CONTROLLER
  try:
   if p.exists():trusted(p);need(p.read_bytes()==controller_text(manifest).encode(),'diagnostic_controller_changed');p.unlink()
  except Exception:errors.append('controller_cleanup_failed')
 try:systemctl(['daemon-reload'])
 except Exception:errors.append('diagnostic_reload_failed')
 try:need(guard_snapshot()==json.loads((ROOT/'guards.json').read_text()),'original_audit_changed')
 except Exception:errors.append('original_audit_changed')
 report=read_report();report.update(cleanup_complete=not errors,cleanup_errors=errors)
 if final:report.update(final=True,stage='diagnostic_finished',passed=bool(report.get('tests_passed')) and not errors)
 save_report(report)
 return not errors

def run(manifest):
 need(re.fullmatch('[a-f0-9]{32}',os.environ.get('INVOCATION_ID','')) is not None,'controller_invocation_required')
 identity=props(CONTROLLER,('MainPID','InvocationID'));need(identity=={'MainPID':str(os.getpid()),'InvocationID':os.environ['INVOCATION_ID']},'controller_identity_mismatch')
 claim_session();report={'stage':'diagnostic_running','final':False,'passed':False,'tests_passed':False,'tests':[]};save_report(report)
 def interrupted(*a):raise Refused('diagnostic_interrupted')
 signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
 adapter=None
 try:
  core=runpy.run_path(str(ROOT/'diagnostic_core.py'));readiness=runpy.run_path(str(ROOT/'process_readiness.py'))
  busctl_preflight();account=prepare_children();adapter=Adapter(account,core)
  for unit in CHILDREN:
   try:result=adapter.test(unit,readiness)
   except Exception as e:
    result={'name':'sleep' if unit==SLEEP else 'python','readiness':False,'reason':reason(e),'last_evidence':adapter.last}
    need(props(unit,('MainPID',))['MainPID']=='0','diagnostic_child_not_stopped')
   report['tests'].append(result);save_report(report)
  report['tests_passed']=all(t.get('natural_exit') for t in report['tests'])
 except Exception as e:
  report['reason']=reason(e)
  if adapter and adapter.last:report['last_evidence']=adapter.last
 finally:
  signal.signal(signal.SIGTERM,signal.SIG_IGN);signal.signal(signal.SIGINT,signal.SIG_IGN);save_report(report);cleanup(manifest,final=False)
 return bool(report['tests_passed'])

def status(quiet=False):
 report=read_report()
 if not report.get('final'):
  if not quiet:print(json.dumps({'stage':'diagnostic_pending','rerun_installer_retrieves_same_session':True}))
  return 2
 print(json.dumps(report,sort_keys=True));return 0 if report.get('passed') else 1

def main():
 p=argparse.ArgumentParser();p.add_argument('mode',choices=('launch','run','cleanup','status'));p.add_argument('--manifest-sha',required=True);p.add_argument('--quiet-pending',action='store_true');a=p.parse_args();verify_bundle(a.manifest_sha)
 if a.mode=='launch':launch(a.manifest_sha);print('{"stage":"diagnostic_session_submitted"}');return 0
 if a.mode=='run':
  try:return 0 if run(a.manifest_sha) else 1
  except Exception as e:
   report=read_report()
   if not report.get('final'):
    report.update(reason=reason(e),tests_passed=False)
    if isinstance(e,Refused) and e.evidence:report['unit_query']=e.evidence
    save_report(report)
   raise
 if a.mode=='cleanup':return 0 if cleanup(a.manifest_sha) else 1
 return status(a.quiet_pending)
if __name__=='__main__':
 try:sys.exit(main())
 except Exception as e:print(json.dumps({'stage':'diagnostic_stopped','reason':reason(e)}));sys.exit(1)
