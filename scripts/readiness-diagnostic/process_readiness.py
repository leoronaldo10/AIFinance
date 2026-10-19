"""Read-only process evidence. PID availability is not exec or sandbox readiness."""
import os,re,select,stat,time
from pathlib import Path
FIELDS=('MainPID','ExecMainPID','ExecMainStartTimestampMonotonic','InvocationID','ControlGroup','ActiveState','SubState')
CAPS=('CapInh','CapPrm','CapEff','CapBnd','CapAmb')
class Refused(Exception):pass
def need(value,reason):
 if not value:raise Refused(reason)
def start_identity(text,pid):
 end=text.rfind(')');need(end>0 and text.split(' ',1)[0]==str(pid),'process_stat_invalid')
 fields=text[end+2:].split();need(len(fields)>19 and fields[19].isdecimal(),'process_stat_invalid')
 need(fields[0] not in ('Z','X','x'),'process_exited_before_ready');return int(fields[19])
def security_status(text,uid,gid):
 values={}
 for line in text.splitlines():
  if ':' not in line:continue
  key,value=line.split(':',1)
  if key in ('Uid','Gid','NoNewPrivs',*CAPS):need(key not in values,'process_status_duplicate_field');values[key]=value.strip()
 def ids(key):
  parts=values.get(key,'').split();return list(map(int,parts)) if len(parts)==4 and all(v.isdecimal() for v in parts) else None
 uids,gids=ids('Uid'),ids('Gid');nnp=values.get('NoNewPrivs');caps={k:(int(values[k],16)==0 if re.fullmatch('[0-9a-fA-F]+',values.get(k,'')) else None) for k in CAPS}
 checks={'uid_matches':uids==[uid]*4,'gid_matches':gids==[gid]*4,'no_new_privileges':nnp=='1',**{k.lower()+'_zero':v is True for k,v in caps.items()}}
 return checks,{'uids':uids,'gids':gids,'no_new_privileges':int(nnp) if nnp in ('0','1') else None,'capabilities_zero':caps}
def mount_readonly(text,mount_id,target):
 rows=[line.split() for line in text.splitlines() if line.split() and line.split()[0]==str(mount_id)]
 need(len(rows)==1,'resolver_mount_missing_or_ambiguous');row=rows[0]
 need(len(row)>6 and '-' in row and row[4]==target,'resolver_mount_target_mismatch')
 need('ro' in row[5].split(','),'resolver_not_readonly')

def failure_reason(sample,error):
 if type(error).__name__=='Refused' and re.fullmatch('[a-z_]{1,100}',str(error)):return str(error)
 if isinstance(error,PermissionError):return 'process_evidence_permission_denied'
 if type(error).__name__=='TimeoutExpired':return 'unit_evidence_query_timeout'
 if sample.pidfd is not None:
  try:
   if not sample.alive():return 'process_exited_during_evidence'
  except OSError:pass
 return 'process_evidence_unavailable'

class ProcessSample:
 def __init__(self,op,unit,expected,conf,require_cgroup,verify_cgroup):
  self.op=op;self.unit=unit;self.expected=expected;self.conf=conf;self.require_cgroup=require_cgroup;self.verify_cgroup=verify_cgroup
  self.pidfd=None;self.procfd=None;self.pid=None;self.ticks=None;self.initial=None;self.evidence={};self.diagnostic={'role':'resource_probe' if unit.endswith('-probe.service') else 'collector','expected_uid':op.state['uid'],'expected_gid':op.state['gid']}
 def close(self):
  for key in ('procfd','pidfd'):
   fd=getattr(self,key)
   if fd is not None:os.close(fd);setattr(self,key,None)
 def __enter__(self):return self
 def __exit__(self,*unused):self.close()
 def alive(self):
  p=select.poll();p.register(self.pidfd,select.POLLIN);return not p.poll(0)
 def read(self,name,limit=131072):
  fd=os.open(name,os.O_RDONLY|os.O_CLOEXEC,dir_fd=self.procfd)
  with os.fdopen(fd,'rb') as f:data=f.read(limit+1)
  need(len(data)<=limit,'process_evidence_size_limit');return data.decode()
 def executable_matches(self):
  try:actual=os.stat('exe',dir_fd=self.procfd)
  except FileNotFoundError:return False
  expected=os.stat(self.expected)
  return (actual.st_dev,actual.st_ino)==(expected.st_dev,expected.st_ino)
 def attach(self,snapshot):
  need(hasattr(os,'pidfd_open'),'pidfd_required');self.pid=int(snapshot['MainPID']);self.diagnostic['pid']=self.pid
  self.pidfd=os.pidfd_open(self.pid,0);need(self.alive(),'process_exited_before_ready')
  self.procfd=os.open('/proc/'+str(self.pid),os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
  self.ticks=start_identity(self.read('stat'),self.pid);need(self.alive(),'process_exited_before_ready')
  need(re.fullmatch('[a-f0-9]{32}',snapshot['InvocationID']) is not None,'unit_invocation_missing')
  need(snapshot['ExecMainPID']==str(self.pid) and re.fullmatch('[1-9][0-9]*',snapshot['ExecMainStartTimestampMonotonic']) is not None,'unit_exec_identity_missing')
  self.initial=snapshot;self.diagnostic['start_ticks']=self.ticks
 def consistent(self,snapshot,completed=False):
  need(snapshot['ExecMainPID']==str(self.pid) and snapshot['ExecMainStartTimestampMonotonic']==self.initial['ExecMainStartTimestampMonotonic'],'unit_execution_changed')
  need(snapshot['InvocationID']==self.initial['InvocationID'] or (completed and snapshot['InvocationID']==''),'unit_invocation_changed')
  if completed:
   need(snapshot['MainPID']=='0' and not self.alive(),'unit_completion_not_observed');return
  need(snapshot['MainPID']==str(self.pid) and snapshot['ControlGroup']==self.initial['ControlGroup'],'process_unit_identity_changed')
  need(self.alive(),'process_exited_during_evidence')
  need(start_identity(self.read('stat'),self.pid)==self.ticks,'process_pid_reused')
 def check_security(self):
  checks,values=security_status(self.read('status'),self.op.state['uid'],self.op.state['gid']);self.diagnostic.update(values);self.diagnostic['checks']=checks
  for name,ok in checks.items():need(ok,'process_'+name+'_failed')
 def resolver_evidence(self):
  mounts=self.read('mountinfo',1048576);self.diagnostic['resolver_checks']={}
  for name in ('hosts','nsswitch.conf'):
   self.diagnostic['resolver_checks'][name]={'content_matches':None,'readonly_mount':None}
   fd=os.open('root/etc/'+name,os.O_RDONLY|os.O_CLOEXEC,dir_fd=self.procfd)
   with os.fdopen(fd,'rb') as f:
    data=f.read(16385);need(len(data)<=16384,'resolver_evidence_size_limit')
    info=Path('/proc/self/fdinfo/'+str(f.fileno())).read_text();ids=[s.split(':',1)[1].strip() for s in info.splitlines() if s.startswith('mnt_id:')]
    need(len(ids)==1 and ids[0].isdecimal(),'resolver_mount_id_missing')
    try:mount_readonly(mounts,int(ids[0]),'/etc/'+name)
    except Refused:self.diagnostic['resolver_checks'][name]['readonly_mount']=False;raise
    self.diagnostic['resolver_checks'][name]['readonly_mount']=True
   matches=data==(self.conf/name).read_bytes();self.diagnostic['resolver_checks'][name]['content_matches']=matches;need(matches,'resolver_binding_mismatch')
  self.diagnostic['resolver_bindings_readonly']=True
 def full_evidence(self,snapshot,deadline):
  self.consistent(snapshot);need(self.executable_matches(),'process_executable_changed');self.check_security();self.require_cgroup()
  group=self.initial['ControlGroup'];self.diagnostic['cgroup']={};self.evidence=self.verify_cgroup(Path('/sys/fs/cgroup'),group,str(self.pid),self.read('cgroup'),observations=self.diagnostic['cgroup'])
  self.diagnostic['cgroup_verified']=True;self.resolver_evidence()
  left=deadline-time.monotonic();need(left>0,'process_exec_readiness_timeout')
  self.consistent(self.op.properties(self.unit,FIELDS,timeout=min(2,left)));need(self.executable_matches(),'process_executable_changed');self.check_security()
  self.evidence.update(uid=self.op.state['uid'],gid=self.op.state['gid']);self.diagnostic['exec_matches']=True
 def _observe_running(self,snapshot):
  if snapshot['MainPID']=='0':
   self.consistent(snapshot,completed=True);return
  # An exited pidfd is terminal; never open or attach to a replacement PID.
  need(snapshot['MainPID']==str(self.pid),'process_unit_identity_changed')
  need(snapshot['InvocationID']==self.initial['InvocationID'],'unit_invocation_changed')
  if not self.alive():return  # systemd may not have reaped/cleared MainPID yet.
  self.consistent(snapshot);need(self.executable_matches(),'process_executable_changed');self.check_security()
 def observe_running(self,snapshot):
  try:self._observe_running(snapshot)
  except Exception as e:
   reason=failure_reason(self,e)
   self.record('process_runtime_failed',reason);raise Refused(reason) from None
 def wait(self,timeout):
  deadline=time.monotonic()+timeout;seen_start=False
  while True:
   left=deadline-time.monotonic();need(left>0,'process_exec_readiness_timeout')
   snapshot=self.op.properties(self.unit,FIELDS,timeout=min(2,left))
   need(snapshot['ActiveState']!='failed','unit_failed_before_ready')
   if snapshot['ActiveState']=='activating':seen_start=True
   if self.pid is None:
    need(re.fullmatch('[0-9]+',snapshot['MainPID']) is not None,'unit_main_pid_invalid')
    if snapshot['MainPID']!='0':self.attach(snapshot)
    else:need(not seen_start or snapshot['ActiveState']!='inactive','process_exited_before_ready')
   else:self.consistent(snapshot)
   if self.pid is not None:
    need(self.alive(),'process_exited_before_ready');matched=self.executable_matches();self.diagnostic['exec_matches']=matched
    if matched:
     self.full_evidence(snapshot,deadline);need(time.monotonic()<=deadline,'process_exec_readiness_timeout');return self
    checks,values=security_status(self.read('status'),self.op.state['uid'],self.op.state['gid']);self.diagnostic.update(values);self.diagnostic['checks']=checks
   # Condition polling only; no elapsed interval is treated as readiness evidence.
   remaining=max(0,min(.025,deadline-time.monotonic()))
   select.select([self.pidfd] if self.pidfd is not None else [],[],[],remaining)
 def record(self,stage,reason=None):
  record=dict(self.diagnostic)
  if reason is not None:record['reason']=reason
  self.op.process_diagnostic(stage,record)

def wait_for_process(op,unit,expected,conf,require_cgroup,verify_cgroup,timeout=5):
 sample=ProcessSample(op,unit,expected,conf,require_cgroup,verify_cgroup)
 try:
  sample.wait(timeout);sample.record('process_readiness_passed');return sample
 except Exception as e:
  reason=failure_reason(sample,e)
  try:sample.record('process_readiness_failed',reason)
  finally:sample.close()
  raise Refused(reason) from None
