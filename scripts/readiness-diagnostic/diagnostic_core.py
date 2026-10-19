"""Read-only diagnostic validators; no collector or database entry points."""
import os,re,stat
from pathlib import Path
class Refused(Exception):pass

def need(v,code):
 if not v:raise Refused(code)

def trusted(p):
 for q in (p,*p.parents):
  s=q.lstat();need(s.st_uid==0 and not s.st_mode&0o022 and not stat.S_ISLNK(s.st_mode),'untrusted_path')

def trusted_tool(p):
 # Distribution-managed executable symlinks are allowed only through root-owned, non-writable paths.
 current=p;seen=set()
 while current.is_symlink():
  need(current not in seen,'tool_symlink_cycle');seen.add(current)
  trusted(current.parent);st=current.lstat();need(st.st_uid==0,'untrusted_tool_symlink')
  target=Path(os.readlink(current));current=target if target.is_absolute() else current.parent/target
  current=Path(os.path.normpath(current))
 trusted(current);need(current.is_file() and os.access(current,os.X_OK),'tool_not_executable')

def cgroup_read(path):
 try:return path.read_text().strip()
 except (OSError,UnicodeError):raise Refused('cgroup_file_unreadable') from None

def require_cgroup_v2(root=Path('/sys/fs/cgroup'),mountinfo=None):
 if mountinfo is None:mountinfo=cgroup_read(Path('/proc/self/mountinfo'))
 matches=[]
 for line in mountinfo.splitlines():
  fields=line.split()
  if len(fields)>6 and fields[4]==str(root):
   need('-' in fields,'cgroup_mount_invalid');i=fields.index('-')
   need(i+1<len(fields),'cgroup_mount_invalid');matches.append((fields[3],fields[i+1]))
 need(len(matches)==1,'cgroup_mount_missing_or_ambiguous')
 need(matches[0][1]=='cgroup2','cgroup_v1_or_other_unsupported')
 need(matches[0][0]=='/','cgroup_subtree_mount_unsupported')
 need(root.resolve()==root and root.is_dir(),'cgroup_root_unsafe')
 need({'memory','pids','cpu'}<=set(cgroup_read(root/'cgroup.controllers').split()),'cgroup_controller_missing')

def verify_cgroup_v2(root,control_group,pid,process_cgroup,observations=None):
 # systemd's actual ControlGroup is the authority; never construct it from a unit name.
 need(bool(re.fullmatch(r'/(?:[A-Za-z0-9_.@:-]+/)*[A-Za-z0-9_.@:-]+',control_group)),'cgroup_path_invalid')
 parts=control_group[1:].split('/');need(all(x not in ('.','..') for x in parts),'cgroup_path_escape')
 group=root
 for part in parts:
  group=group/part
  try:need(stat.S_ISDIR(group.lstat().st_mode) and not group.is_symlink(),'cgroup_path_unsafe')
  except OSError:raise Refused('cgroup_path_unreadable') from None
 need(group.resolve()==group and root in group.parents,'cgroup_path_escape')
 need(process_cgroup.strip()=='0::'+control_group,'process_unit_cgroup_mismatch')
 need(pid in cgroup_read(group/'cgroup.procs').split(),'cgroup_pid_missing')
 def observed(name,value):
  if observations is not None:observations[name]=value
 memory=cgroup_read(group/'memory.max');observed('memory_max',memory if re.fullmatch(r'max|[0-9]{1,20}',memory) else None);need(memory=='268435456','cgroup_memory_limit_mismatch')
 pids=cgroup_read(group/'pids.max');observed('pids_max',pids if re.fullmatch(r'max|[0-9]{1,20}',pids) else None);need(pids=='32','cgroup_tasks_limit_mismatch')
 cpu=cgroup_read(group/'cpu.max').split();observed('cpu_max',cpu if len(cpu)==2 and all(re.fullmatch(r'max|[0-9]{1,20}',v) for v in cpu) else None)
 need(len(cpu)==2 and all(re.fullmatch(r'[1-9][0-9]*',x) for x in cpu),'cgroup_cpu_unlimited_or_invalid')
 quota,period=map(int,cpu);need(quota*2==period and 1000<=period<=1000000,'cgroup_cpu_quota_mismatch')
 current=cgroup_read(group/'memory.current');observed('memory_current',int(current) if re.fullmatch(r'[0-9]{1,20}',current) else None);need(current.isdecimal() and int(current)<268435456,'cgroup_memory_limit_hit')
 events={}
 for line in cgroup_read(group/'memory.events').splitlines():
  pair=line.split();need(len(pair)==2 and pair[1].isdecimal(),'cgroup_memory_events_invalid');events[pair[0]]=int(pair[1])
 observed('memory_events',{k:events.get(k) for k in ('max','oom','oom_kill')})
 need(all(events.get(k)==0 for k in ('max','oom','oom_kill')),'cgroup_memory_limit_hit')
 return {'cgroup_version':2,'memory_bytes':268435456,'tasks_max':32,'cpu_quota_percent':50}
