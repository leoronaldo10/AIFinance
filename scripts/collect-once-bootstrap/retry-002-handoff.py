#!/usr/bin/python3
"""Verified fixed-commit download and one-shot handoff. No credentials or generic commands."""
import argparse,hashlib,json,os,pwd,re,signal,stat,subprocess,sys,tempfile,time,urllib.request
from pathlib import Path
BASE=Path('/root/aifinance-once-helper-retry-002');DEST=BASE/'helper';AUDIT=Path('/var/lib/aifinance-collect-once/retry-002')
ROOT_UID=0
HOST='iZ2zedybs3fftu1d9vnx39Z';PREFIX='scripts/collect-once-bootstrap/'
class Refused(Exception):pass
def need(ok,reason):
 if not ok:raise Refused(reason)
def digest(data):return hashlib.sha256(data).hexdigest()
def emit(**values):
 try:print(json.dumps(values,sort_keys=True),flush=True)
 except OSError:pass  # Durable root result log remains readable after a disconnect.
def entries(data,want):
 need(digest(data)==want,'manifest_hash_mismatch');result={}
 for line in data.decode().splitlines():
  h,n=line.split();need(re.fullmatch('[a-f0-9]{64}',h) and re.fullmatch('[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*',n) and '..' not in Path(n).parts and n not in result,'unsafe_manifest')
  result[n]=h
 need(1<=len(result)<=150 and 'retry-002.py' in result and 'retry-002-handoff.py' in result,'invalid_manifest_file_set');return result
def readfile(p,limit=2097152):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb') as f:
  st=os.fstat(f.fileno());need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_size<=limit,'unsafe_download_file');data=f.read(limit+1)
 need(len(data)<=limit,'download_too_large');return data
def download(commit,want):
 root=Path(tempfile.mkdtemp(prefix='aifinance-retry002-download-',dir=Path.home()))
 def fetch(name):
  url='https://raw.githubusercontent.com/leoronaldo10/AIFinance/'+commit+'/'+PREFIX+name
  with urllib.request.urlopen(url,timeout=30) as response:data=response.read(2097153)
  need(len(data)<=2097152,'download_too_large');return data
 data=fetch('SHA256SUMS');files=entries(data,want);(root/'SHA256SUMS').write_bytes(data)
 for name,h in files.items():
  data=fetch(name);need(digest(data)==h,'download_hash_mismatch');p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
 need(digest(Path(__file__).read_bytes())==files['retry-002-handoff.py'],'launcher_not_in_approved_manifest')
 emit(stage='download_verified',files=len(files),commit=commit);return root

def trusted(p):
 for q in (p,*p.parents):
  st=q.lstat();need(st.st_uid==ROOT_UID and not st.st_mode&0o022 and not stat.S_ISLNK(st.st_mode),'untrusted_install_path')
def sync(p):
 fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
def write_new(p,data):
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
 sync(p.parent)
def stage_helper(source,want):
 data=readfile(source/'SHA256SUMS');files=entries(data,want)
 # Capture and hash bytes before any root write; user-owned downloads are never executed directly.
 payload={'SHA256SUMS':data}
 for n,h in files.items():
  blob=readfile(source/n);need(digest(blob)==h,'root_download_hash_mismatch');payload[n]=blob
 need(digest(Path(__file__).read_bytes())==files['retry-002-handoff.py'],'root_launcher_hash_mismatch')
 trusted(BASE.parent)
 if not BASE.exists():BASE.mkdir(mode=0o700);sync(BASE.parent)
 trusted(BASE)
 import fcntl
 fd=os.open(BASE/'install.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
 try:
  st=os.fstat(fd);need(st.st_uid==ROOT_UID and stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1,'unsafe_install_lock')
  try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:raise Refused('install_busy') from None
  stage=BASE/'helper.staging';target=DEST if DEST.exists() or DEST.is_symlink() else stage
  if not target.exists():target.mkdir(mode=0o700);sync(BASE)
  trusted(target)
  expected=set(payload);parents={str(p) for n in expected for p in Path(n).parents if str(p)!='.'}
  for p in target.rglob('*'):
   trusted(p);rel=p.relative_to(target).as_posix();need(rel in expected or (p.is_dir() and rel in parents),'unexpected_helper_file')
  for n,blob in payload.items():
   p=target/n
   if p.exists() or p.is_symlink():trusted(p);need(readfile(p)==blob,'existing_helper_changed')
   else:
    need(target==stage,'installed_helper_incomplete');p.parent.mkdir(parents=True,exist_ok=True,mode=0o700);trusted(p.parent);write_new(p,blob)
  if target==stage:
   need(not DEST.exists() and not DEST.is_symlink(),'helper_collision');os.rename(stage,DEST);sync(BASE)
 finally:os.close(fd)

def receipt(stage,rc):
 trusted(BASE);path=BASE/'handoff-results.jsonl';fd=os.open(path,os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as f:
  st=os.fstat(f.fileno());need(st.st_uid==ROOT_UID and stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1,'unsafe_handoff_log')
  f.write(json.dumps({'stage':stage,'exit_code':rc,'time_ns':time.time_ns()})+'\n');f.flush();os.fsync(f.fileno())
 emit(stage=stage,exit_code=rc)

def root_flow(want):
 child=None;interrupted=[]
 def relay(signum,frame):
  interrupted.append(signum)
  if child is not None and child.poll() is None:child.send_signal(signum)
 handlers={s:signal.signal(s,relay) for s in (signal.SIGHUP,signal.SIGINT,signal.SIGTERM)}
 def invoke(mode):
  nonlocal child
  if interrupted:return 128+interrupted[-1]
  args=['/usr/bin/python3','-I','-B',str(DEST/'retry-002.py'),mode,'--manifest-sha256',want]
  if mode=='run':args+=['--approve-retry-002-once','--exclusive-writer-window']
  child=subprocess.Popen(args);rc=child.wait();rc=rc if rc>=0 else 128-rc;receipt(mode.upper()+'_EXIT',rc);return rc
 try:
  # Repeat invocation can only clean up and show status, never install/check/run again.
  if AUDIT.exists() or AUDIT.is_symlink():
   emit(stage='existing_retry002_recovery_only',collection_will_not_restart=True)
   rc=invoke('cleanup')
   if rc:return rc
   return invoke('status')
  for mode in ('install','check','run'):
   rc=invoke(mode)
   if rc:return rc
  return 0
 finally:
  for s,handler in handlers.items():signal.signal(s,handler)

def main():
 p=argparse.ArgumentParser();p.add_argument('commit');p.add_argument('manifest');p.add_argument('--root-stage',type=Path);a=p.parse_args()
 need(re.fullmatch('[a-f0-9]{40}',a.commit) and re.fullmatch('[a-f0-9]{64}',a.manifest),'invalid_pins');need(os.uname().nodename==HOST and sys.stdin.isatty(),'expected_host_tty_required')
 if a.root_stage is not None:
  need(os.geteuid()==0,'root_required');stage_helper(a.root_stage,a.manifest);rc=root_flow(a.manifest);receipt('HANDOFF_EXIT',rc);return rc
 need(pwd.getpwuid(os.geteuid()).pw_name=='ecs-user','ecs_user_required');source=download(a.commit,a.manifest)
 # The outer shell hashes this launcher first. Root rechecks it against the pinned manifest.
 rc=subprocess.run(['/usr/bin/sudo','/usr/bin/python3','-I','-B',str(Path(__file__).resolve()),a.commit,a.manifest,'--root-stage',str(source)]).returncode
 rc=rc if rc>=0 else 128-rc;emit(stage='HANDOFF_EXIT',exit_code=rc);return rc
if __name__=='__main__':
 try:raise SystemExit(main())
 except Exception as e:
  emit(stage='HANDOFF_EXIT',exit_code=1,reason=str(e) if isinstance(e,Refused) else 'handoff_details_suppressed');raise SystemExit(1)
