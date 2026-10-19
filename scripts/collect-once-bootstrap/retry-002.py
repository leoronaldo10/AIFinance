#!/usr/bin/python3
"""Fixed retry-002 only. Offline package install, explicit one-shot run, recovery.
No download, generic round parameter, reset, automatic resume, or collector code edit.
"""
import argparse,contextlib,copy,fcntl,hashlib,json,os,pwd,re,runpy,signal,stat,sys,tempfile,time,types
from pathlib import Path
HERE=Path(__file__).resolve().parent
HELPER=Path('/root/aifinance-once-helper-retry-002/helper')
REVIEW=Path('/root/aifinance-once-review-retry-002')
OLD_REVIEW=Path('/root/aifinance-once-review-socket')
STATE=Path('/var/lib/aifinance-collect-once');AUDIT=STATE/'retry-002';PREVIOUS=STATE/'retry-001'
UNITS=Path('/etc/systemd/system')
BASE_SHA='91e81084533a452235e366c4b436c92581ba931b026adbb5929d4cb844c0edfc'
ARTIFACT_SHA='a88da42096a452d526e7cd53f6fdf26e6349cf1cd3d148428cefa9e73632656a'
ADDITION=b'\n# AIFinance approved retry-002 BEGIN\nhost aifinance_preview aifinance_collect_once 127.0.0.1/32 scram-sha-256\n# AIFinance approved retry-002 END\n'
class Refused(Exception):pass
def need(ok,reason):
 if not ok:raise Refused(reason)
def digest(data):return hashlib.sha256(data).hexdigest()
def sha(p):return digest(p.read_bytes())
def absent(p):return not p.exists() and not p.is_symlink()
def trusted(p):
 for q in (p,*p.parents):
  st=q.lstat();need(st.st_uid==0 and not st.st_mode&0o022 and not stat.S_ISLNK(st.st_mode),'untrusted_retry002_path')
def read(p):
 trusted(p);st=p.stat();need(stat.S_ISREG(st.st_mode) and st.st_nlink==1,'unsafe_retry002_file');return p.read_bytes()
def sync(p):
 fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
def exclusive(p,data):
 fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_WRONLY,0o600)
 with os.fdopen(fd,'wb') as out:out.write(data);out.flush();os.fsync(out.fileno())
 sync(p.parent)
def atomic(p,data,expected):
 need(read(p)==expected,'concurrent_file_change')
 st=p.stat();fd,name=tempfile.mkstemp(prefix='.retry002-',dir=p.parent)
 try:
  with os.fdopen(fd,'wb') as out:
   os.fchmod(out.fileno(),stat.S_IMODE(st.st_mode));os.fchown(out.fileno(),st.st_uid,st.st_gid);out.write(data);out.flush();os.fsync(out.fileno())
  need(read(p)==expected,'concurrent_file_change');os.replace(name,p);sync(p.parent)
 finally:
  if os.path.exists(name):os.unlink(name)
def save(p,data):
 blob=json.dumps(data,sort_keys=True).encode()
 if absent(p):exclusive(p,blob)
 else:atomic(p,blob,read(p))
@contextlib.contextmanager
def lock():
 trusted(STATE);p=STATE/'retry-002.lock';fd=os.open(p,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
 try:
  st=os.fstat(fd);need(st.st_uid==os.geteuid() and stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1,'unsafe_lock')
  try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:raise Refused('retry002_busy') from None
  yield
 finally:os.close(fd)
def manifest(root,want=None):
 data=read(root/'SHA256SUMS');need(want is None or digest(data)==want,'package_manifest_changed');entries={}
 for line in data.decode().splitlines():
  h,n=line.split();p=Path(n);need(re.fullmatch('[a-f0-9]{64}',h) and not p.is_absolute() and '..' not in p.parts and n not in entries,'invalid_package_manifest')
  need(sha_checked(root/n)==h,'package_file_changed');entries[n]=h
 return entries
def sha_checked(p):return digest(read(p))
def source_review():
 manifest(HERE);up=runpy.run_path(str(HERE/'upgrade-review.py'));cfg=runpy.run_path(str(HERE/'configure.py'))
 base=read(HERE/'retry-002-base-bootstrap.py.txt');need(digest(base)==BASE_SHA,'legacy_template_changed')
 entries=manifest(OLD_REVIEW);values=up['recover_bindings'](read(OLD_REVIEW/'bootstrap.py').decode(),base.decode())
 need(values['__DATABASE_NAME__']=='aifinance_preview' and values['__DATABASE_PORT__']=='55432' and values['__APPLICATION_ROLE__']=='aifinance_app' and values['__DEPLOY_USER__']=='aifinance-deploy','wrong_fixed_target')
 rendered=cfg['rendered_templates'](values);legacy={k:v for k,v in rendered.items() if k!='process_readiness.py'}
 text=base.decode()
 for k,v in values.items():text=text.replace(k,v)
 legacy['bootstrap.py']=text
 unit='aifinance-collect-once.service';need(rendered[unit].count('RemainAfterExit=yes\n')==1,'unit_template_changed');legacy[unit]=rendered[unit].replace('RemainAfterExit=yes\n','')
 need(set(entries)==set(legacy),'legacy_review_file_set_changed')
 for n,v in legacy.items():need(read(OLD_REVIEW/n)==v.encode(),'legacy_review_bytes_changed')
 need(sha_checked(OLD_REVIEW/'collector-runtime.tar.gz')==ARTIFACT_SHA,'runtime_changed')
 need(read(OLD_REVIEW/'RUNTIME.SHA256')== (ARTIFACT_SHA+'  collector-runtime.tar.gz\n').encode(),'runtime_receipt_changed')
 return values,rendered,legacy

def install():
 need(absent(AUDIT),'retry002_already_claimed');values,rendered,legacy=source_review()
 # Review-only installation; never edits units, DB, DNS, firewall, or old review.
 expected={n:v.encode() for n,v in rendered.items()}
 expected['SHA256SUMS']=''.join(digest(expected[n])+'  '+n+'\n' for n in sorted(expected)).encode()
 expected['collector-runtime.tar.gz']=read(OLD_REVIEW/'collector-runtime.tar.gz')
 expected['RUNTIME.SHA256']=(ARTIFACT_SHA+'  collector-runtime.tar.gz\n').encode()
 expected['INSTALL.json']=json.dumps({'round':'retry-002','helper_manifest':sha(HERE/'SHA256SUMS'),'old_review_manifest':sha(OLD_REVIEW/'SHA256SUMS'),'runtime':ARTIFACT_SHA},sort_keys=True).encode()
 stage=REVIEW.with_name(REVIEW.name+'.staging');dest=REVIEW if not absent(REVIEW) else stage
 if absent(dest):dest.mkdir(mode=0o700);sync(dest.parent)
 trusted(dest);need({p.name for p in dest.iterdir()}<=set(expected),'unexpected_install_file')
 for n,data in expected.items():
  p=dest/n
  if absent(p):need(dest==stage,'installed_review_incomplete');exclusive(p,data)
  else:need(read(p)==data,'partial_install_content_changed')
 if dest==stage:need(absent(REVIEW),'review_collision');os.rename(stage,REVIEW);sync(REVIEW.parent)
 verify_install();print(json.dumps({'stage':'retry002_installed','collection_started':False}))
def verify_install():
 values,rendered,legacy=source_review();entries=manifest(REVIEW)
 need(set(entries)==set(rendered),'new_review_file_set_changed')
 for n,v in rendered.items():need(read(REVIEW/n)==v.encode(),'new_review_bytes_changed')
 receipt=json.loads(read(REVIEW/'INSTALL.json'))
 need(receipt=={'round':'retry-002','helper_manifest':sha(HERE/'SHA256SUMS'),'old_review_manifest':sha(OLD_REVIEW/'SHA256SUMS'),'runtime':ARTIFACT_SHA},'install_receipt_changed')
 need(sha_checked(REVIEW/'collector-runtime.tar.gz')==ARTIFACT_SHA,'new_runtime_changed')
 return values,legacy

def history(old):
 need(json.loads(read(PREVIOUS/'original-state.json'))==old,'previous_original_state_changed')
 need(read(PREVIOUS/'started')==b'approved retry-001; never repeat\n','previous_claim_changed')
 prev=json.loads(read(PREVIOUS/'state.json'))
 need(prev.get('phase')=='disabled' and prev.get('nonce')==old.get('nonce') and prev.get('artifact_sha256')==ARTIFACT_SHA,'previous_not_cleaned')
 need(prev.get('network_attempted') is False and prev.get('network_owned') is False,'previous_activation_evidence')
 events=[json.loads(line) for line in read(PREVIOUS/'events.jsonl').splitlines()]
 need(any(e.get('stage')=='retry_stopped' and e.get('reason')=='probe_identity_or_capabilities' for e in events),'previous_failure_not_proven_prestart')
 need(not any(e.get('stage') in ('retry_tcp_scram_probe_passed','batch_completed','retry_finished') for e in events),'previous_collection_evidence')
 clean=sorted(PREVIOUS.glob('cleanup-*.json'));need(bool(clean),'previous_cleanup_receipt_missing')
 result=json.loads(read(clean[-1]));need(result.get('complete') is True and result.get('errors')==[],'previous_cleanup_incomplete')
 need(absent(PREVIOUS/'hba-receipt.json') and absent(PREVIOUS/'hba.original'),'previous_reached_hba')
 need(sha_checked(PREVIOUS/'before.dump')==prev.get('backup_sha256') and (PREVIOUS/'before.dump').stat().st_size==prev.get('backup_bytes'),'previous_backup_changed')
 # Pin all historical files; changed/added records during this round also fail.
 return tree_history()
def tree_history():
 result={}
 for root in (PREVIOUS,):
  trusted(root)
  for p in sorted(root.rglob('*')):
   trusted(p)
   if p.is_file():result[str(p)]=sha_checked(p)
 result[str(STATE/'state.json')]=sha_checked(STATE/'state.json')
 return result

def load():
 values,legacy=verify_install();m=runpy.run_path(str(REVIEW/'bootstrap.py'));r=runpy.run_path(str(HERE/'retry-once.py'));g=r['gates'].__globals__
 resolver=runpy.run_path(str(HERE/'retry-resolver.py'))
 g.update(REVIEW=REVIEW,AUDIT=AUDIT,STATE=STATE,VALUES=values,RESOLVER=resolver)
 db=m['Database'].local_socket('/var/run/postgresql');db.verify_admin_identity();old=json.loads(read(STATE/'state.json'))
 need(old.get('admin_auth')==db.auth_binding(),'original_auth_binding_changed')
 op=g['make_operator'](m,db)
 # Atomic state replacement tolerates stale interrupted tempfiles; fixed directory only.
 op.save=lambda:save(AUDIT/'state.json',op.state)
 return m,g,db,op,old,legacy

def unit_bytes(m,legacy):
 original=legacy[m['UNIT']];new=(REVIEW/m['UNIT']).read_text()
 def probe(s):return s.replace('ExecStartPre=+/usr/bin/python3 -I -B /opt/aifinance-collect-once/bin/consume.py\n','').replace('ExecStart=/usr/bin/python3 -I -B /opt/aifinance-collect-once/bin/run.py','ExecStart=/usr/bin/sleep 30\nPrivateNetwork=yes')
 return {m['UNIT']:(original.encode(),new.encode()),m['PROBE']:(probe(original).encode(),probe(new).encode())}
def preflight(m,g,op,old,legacy):
 pins=history(old);op.state=copy.deepcopy(old)
 # Run all original gates against original installed units/review before the claim.
 # New readiness code is not executed here. No guard is removed or broadened.
 oldmod=runpy.run_path(str(OLD_REVIEW/'bootstrap.py'));verify=op.verify_units
 op.verify_units=types.MethodType(oldmod['Operator'].verify_units,op);g['REVIEW']=OLD_REVIEW
 try:g['gates'](m,op,old)
 finally:g['REVIEW']=REVIEW;op.verify_units=verify
 if not absent(PREVIOUS/'resolver-receipt.json'):
  rec=json.loads(read(PREVIOUS/'resolver-receipt.json'));need(sha_checked(m['CONF']/'hosts')==rec['before_sha256'],'previous_resolver_not_restored')
 for n,(before,after) in unit_bytes(m,legacy).items():need(read(UNITS/n)==before,'original_unit_changed')
 return pins

def hba_module():
 h=runpy.run_path(str(HERE/'retry-hba.py'));base=h['TemporaryHBA']
 class HBA(base):
  def inspect(self):
   super().inspect();need(b'AIFinance approved retry-002' not in self.original,'existing_retry002_hba_marker');self.addition=ADDITION;self.modified=self.original+ADDITION
 h['TemporaryHBA']=HBA;return h

def recover_hba(h,db):
 obj=h['TemporaryHBA'](db,AUDIT,db.local_identity[0]);p=AUDIT/'hba-receipt.json'
 if absent(p):return obj
 data=json.loads(read(p));obj.original=read(AUDIT/'hba.original');obj.modified=obj.original+ADDITION
 need(digest(obj.original)==data['before_sha256'] and digest(obj.modified)==data['after_sha256'],'hba_recovery_receipt_changed')
 obj.path=Path(data['path']);need(str(obj.path)==db.sql('SHOW hba_file',True),'hba_target_changed')
 obj.st=types.SimpleNamespace(st_uid=data['uid'],st_gid=data['gid'],st_mode=data['mode']);obj.configs={k:tuple(v) for k,v in data['configs'].items()};obj.changed=True;return obj

def switch_units(m,legacy,restore=False):
 for n,(before,after) in unit_bytes(m,legacy).items():
  p=UNITS/n;current=read(p);need(current in (before,after),'concurrent_unit_change')
  desired=before if restore else after
  if current!=desired:atomic(p,desired,current)
 m['cmd'](['/usr/bin/systemctl','daemon-reload'])

def claim(old,pins):
 # Directory existence itself is permanent, even if killed during receipt writes.
 AUDIT.mkdir(mode=0o700);sync(STATE)
 exclusive(AUDIT/'original-state.json',read(STATE/'state.json'))
 exclusive(AUDIT/'history.json',json.dumps(pins,sort_keys=True).encode())
 exclusive(AUDIT/'started',b'approved retry-002; never repeat\n')
 state=copy.deepcopy(old);state.update(phase='retry002_claimed',network_attempted=False,network_owned=False)
 save(AUDIT/'state.json',state)
 exclusive(AUDIT/'claim-complete',b'retry-002\n')
 return state

def cleanup(m,g,db,op,old,legacy):
 need(read(AUDIT/'claim-complete')==b'retry-002\n' and read(AUDIT/'started')==b'approved retry-002; never repeat\n','claim_incomplete')
 state=json.loads(read(AUDIT/'state.json'));need(state.get('nonce')==old.get('nonce') and state.get('admin_auth')==db.auth_binding() and state.get('artifact_sha256')==ARTIFACT_SHA,'retry002_state_changed');op.state=state
 # Recover each reversible resource independently so one corrupt receipt cannot skip others.
 errors=[]
 def attempt(label,fn):
  try:fn()
  except Exception:errors.append(label)
 attempt('operator_cleanup_failed',op.cleanup)
 attempt('hba_restore_failed',lambda:recover_hba(hba_module(),db).restore())
 def resolver_restore():
  obj=g['make_resolver'](m,old);obj.recover(lambda p:read(p));obj.restore()
 attempt('resolver_restore_failed',resolver_restore)
 # Only restore unit files after both service processes have been stopped.
 def restore_units():
  for u in (m['UNIT'],m['PROBE']):need(op.property(u,'MainPID')=='0' and op.property(u,'ActiveState') in ('inactive','failed'),'unit_not_stopped')
  switch_units(m,legacy,True)
 attempt('unit_restore_failed',restore_units)
 attempt('website_health_failed',lambda:g['website'](m,op))
 attempt('history_changed',lambda:need(tree_history()==json.loads(read(AUDIT/'history.json')),'history_changed'))
 result={'complete':not errors,'errors':errors};exclusive(AUDIT/('cleanup-'+str(time.time_ns())+'.json'),json.dumps(result).encode())
 print(json.dumps(dict(stage='retry002_cleanup_finished',**result)));need(not errors,'retry002_cleanup_incomplete')

def execute(m,g,db,op,old,legacy,pins):
 need(tree_history()==pins,'history_changed_before_claim')
 need(absent(STATE/'consumed') and absent(STATE/'ready') and absent(m['CONF']/'database.env'),'collector_start_or_secret_evidence')
 op.state=claim(old,pins)
 def interrupted(*unused):raise Refused('retry002_interrupted')
 previous={s:signal.signal(s,interrupted) for s in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP)}
 try:
  switch_units(m,legacy);op.verify_units()
  h=hba_module()['TemporaryHBA'](db,AUDIT,db.local_identity[0]);h.inspect()
  op.backup();op.resolved_at,op.hosts,net=op.resolver.install();op.network=net['nft'];op.state['network_sha256']=digest(net['nft'].encode());op.save()
  op.probe();h.install()
  db.create_role=lambda nonce:g['regrant_existing'](db,REVIEW,nonce)
  db.login_probe=lambda password:g['probe_tcp'](m,password)
  op.activate();op.run_once();exclusive(AUDIT/'completed',b'collector completed; never repeat\n')
 finally:
  for s in previous:signal.signal(s,signal.SIG_IGN)
  try:cleanup(m,g,db,op,old,legacy)
  finally:
   for s,handler in previous.items():signal.signal(s,handler)

def parser():
 p=argparse.ArgumentParser();p.add_argument('mode',choices=['install','check','run','cleanup','status']);p.add_argument('--manifest-sha256',required=True);p.add_argument('--approve-retry-002-once',action='store_true');p.add_argument('--exclusive-writer-window',action='store_true');return p

def main():
 a=parser().parse_args();need(os.geteuid()==0 and sys.stdin.isatty(),'local_root_tty_required');need(os.uname().nodename=='iZ2zedybs3fftu1d9vnx39Z','wrong_host');need(HERE==HELPER,'fixed_helper_path_required')
 need(re.fullmatch('[a-f0-9]{64}',a.manifest_sha256),'invalid_manifest_hash');manifest(HERE,a.manifest_sha256)
 need(a.mode=='run' or not (a.approve_retry_002_once or a.exclusive_writer_window),'approval_flags_only_for_run')
 with lock():
  if a.mode=='install':install();return
  if a.mode=='status':
   print(json.dumps({'round':'retry-002','claimed':not absent(AUDIT),'claim_complete':not absent(AUDIT/'claim-complete'),'completed':not absent(AUDIT/'completed'),'may_repeat':False}));return
  if a.mode in ('run','check'):need(absent(AUDIT),'retry002_already_claimed_use_status_or_cleanup')
  if a.mode=='run':need(a.approve_retry_002_once and a.exclusive_writer_window,'explicit_retry002_scope_required')
  m,g,db,op,old,legacy=load()
  if a.mode=='cleanup':
   if absent(AUDIT):print(json.dumps({'stage':'retry002_no_attempt'}));return
   if absent(AUDIT/'claim-complete'):
    # No side effect can precede durable claim completion. Never fill in or rerun a partial claim.
    need(absent(AUDIT/'completed') and absent(AUDIT/'hba-receipt.json') and absent(AUDIT/'resolver-receipt.json'),'partial_claim_has_effects')
    print(json.dumps({'stage':'retry002_partial_claim_preserved','may_repeat':False,'effects_started':False}));return
   cleanup(m,g,db,op,old,legacy);return
  pins=preflight(m,g,op,old,legacy)
  hba_module()['TemporaryHBA'](db,AUDIT,db.local_identity[0]).inspect()
  if a.mode=='check':print(json.dumps({'stage':'retry002_preflight_passed','collection_started':False}));return
  execute(m,g,db,op,old,legacy,pins)
if __name__=='__main__':
 try:main()
 except Exception as e:
  print(json.dumps({'stage':'retry002_stopped','reason':str(e) if type(e).__name__=='Refused' else 'details_suppressed'}));sys.exit(1)
