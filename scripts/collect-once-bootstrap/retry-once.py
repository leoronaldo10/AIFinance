#!/usr/bin/env python3
"""One approved recovery of the exact pre-start failure. No generic resume/reset."""
import argparse,copy,hashlib,json,os,pwd,re,runpy,signal,stat,sys,tarfile,time,types
from pathlib import Path
HERE=Path(__file__).resolve().parent
REVIEW=Path('/root/aifinance-once-review-socket')
STATE=Path('/var/lib/aifinance-collect-once');AUDIT=STATE/'retry-001'
ARTIFACT_SHA='a88da42096a452d526e7cd53f6fdf26e6349cf1cd3d148428cefa9e73632656a'
class Refused(Exception):pass
def need(v,why):
 if not v:raise Refused(why)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def emit(stage,**values):
 line=json.dumps(dict(stage=stage,**values),sort_keys=True)
 print(line,flush=True)
 if globals().get('RECORD_EVENTS',False):
  fd=os.open(AUDIT/'events.jsonl',os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'a') as f:f.write(line+'\n');f.flush();os.fsync(f.fileno())
def exclusive(path,data):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
 syncdir(path.parent)
def syncdir(p):
 fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
def absent(p):return not p.exists() and not p.is_symlink()
def verify_helper():
 upgrade=runpy.run_path(str(HERE/'upgrade-review.py'));upgrade['manifest'](HERE);upgrade['manifest'](REVIEW)
 base=(HERE/'templates/bootstrap.py.in').read_text()
 values=upgrade['recover_bindings']((REVIEW/'bootstrap.py').read_text(),base)
 need(values['__DATABASE_NAME__']=='aifinance_preview' and values['__DATABASE_PORT__']=='55432' and values['__APPLICATION_ROLE__']=='aifinance_app' and values['__DEPLOY_USER__']=='aifinance-deploy','wrong_fixed_target')
 cfg=runpy.run_path(str(HERE/'configure.py'))
 expected=cfg['rendered_templates'](values)
 need(set(upgrade['manifest'](REVIEW))==set(expected),'old_review_file_set_changed')
 for name,text in expected.items():need((REVIEW/name).read_bytes()==text.encode(),'old_review_changed')
 return runpy.run_path(str(REVIEW/'bootstrap.py')),values

def validate_never_started(m,op,old):
 m['trusted'](STATE/'state.json')
 need(old.get('phase')=='disabled' and old.get('role_attempted') is True and old.get('artifact_sha256')==ARTIFACT_SHA,'old_attempt_not_cleaned')
 need(re.fullmatch('[a-f0-9]{32}',old.get('nonce','')) is not None,'old_nonce_invalid')
 need(absent(STATE/'consumed') and absent(STATE/'ready') and absent(m['CONF']/'database.env'),'collector_start_or_secret_evidence')
 for name in ('run.py','consume.py'):
  p=m['ROOT']/'bin'/name;m['trusted'](p);need(p.read_bytes()==(REVIEW/name).read_bytes() and stat.S_IMODE(p.stat().st_mode)==0o555,'installed_latch_or_runner_changed')
 need(op.property(m['UNIT'],'MainPID')=='0' and op.property(m['UNIT'],'ActiveState')=='inactive','collector_not_inactive')
 need(op.property(m['UNIT'],'ExecMainStartTimestampMonotonic')=='0' and op.property(m['UNIT'],'ExecMainPID')=='0','collector_previous_start_evidence')
 need(op.property(m['UNIT'],'NRestarts')=='0','collector_restart_evidence')
 need(op.property(m['UNIT'],'UnitFileState')=='static','collector_unit_enablement_changed')
 for name in ('aifinance-collect-once.timer','aifinance-collect-once-probe.timer'):
  need(op.property(name,'LoadState')=='not-found','unexpected_timer')
 need(op.db.role_owned(old['nonce']),'dedicated_role_owner_mismatch');op.db.verify_disabled(old['nonce'])
 need(op.db.sql("SELECT NOT rolsuper AND NOT rolinherit AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls AND rolconnlimit=1 AND NOT EXISTS(SELECT FROM pg_auth_members WHERE member=r.oid OR roleid=r.oid) FROM pg_roles r WHERE rolname='aifinance_collect_once'",True)=='t','dedicated_role_attributes_changed')
 backup=STATE/'before.dump';m['trusted'](backup)
 boot=int(next(line.split()[1] for line in Path('/proc/stat').read_text().splitlines() if line.startswith('btime ')));need(backup.stat().st_mtime>=boot,'original_attempt_before_current_boot')
 need(sha(backup)==old.get('backup_sha256') and backup.stat().st_size==old.get('backup_bytes'),'old_backup_changed')

def website(m,op):
 need(Path('/opt/aifinance/switch/current').resolve()==Path('/opt/aifinance/staging')/m['SHA'],'website_baseline_changed')
 for name in ('aifinance-api.service','aifinance-web.service'):need(op.property(name,'ActiveState')=='active','website_service_not_active')
 for port,path in [(3000,'/'),(3001,'/api/health')]:m['cmd'](['/usr/bin/curl','-q','--noproxy','*','--max-time','3','-fsS','-o','/dev/null',f'http://127.0.0.1:{port}{path}'],timeout=5)

def installed_snapshot(m):
 expected=set()
 with tarfile.open(REVIEW/'collector-runtime.tar.gz','r:*') as tar:
  for item in tar.getmembers():
   expected.add(item.name);p=m['REL']/item.name;st=p.lstat();need(st.st_uid==0,'snapshot_owner_changed')
   if item.issym():need(p.is_symlink() and os.readlink(p)==item.linkname,'snapshot_link_changed');continue
   m['trusted'](p)
   if item.isdir():need(p.is_dir() and stat.S_IMODE(st.st_mode)==0o555,'snapshot_directory_changed');continue
   need(p.is_file() and stat.S_IMODE(st.st_mode)==(0o555 if item.mode&0o111 else 0o444),'snapshot_mode_changed')
   with tar.extractfile(item) as f:data=f.read()
   if item.name=='packages/backend/src/sources/rss.ts':data=data.replace(b'const text = (bodyText || stripTags(summaryHtml)).slice(0, 20_000);',b'const text = stripTags(summaryHtml).slice(0, 2000);')
   need(hashlib.sha256(data).hexdigest()==sha(p),'snapshot_content_changed')
 actual=set()
 for root,dirs,files in os.walk(m['REL'],followlinks=False):
  for name in dirs+files:actual.add((Path(root)/name).relative_to(m['REL']).as_posix())
 # Tar can omit parent directory entries; all extras must be necessary directories.
 parents={str(p) for name in expected for p in Path(name).parents if str(p)!='.'}
 need(actual==expected|parents,'snapshot_extra_files')

def gates(m,op,old):
 validate_never_started(m,op,old);website(m,op);m['require_cgroup_v2']()
 for name in ('/usr/local/bin/node','/usr/bin/psql','/usr/bin/pg_dump','/usr/bin/pg_restore','/usr/bin/systemctl','/usr/bin/curl','/usr/bin/getent','/usr/sbin/nft'):m['trusted_tool'](Path(name))
 need(os.uname().machine=='x86_64','runtime_architecture_mismatch')
 version=m['cmd'](['/usr/local/bin/node','--version']).stdout.decode().strip();v=re.fullmatch(r'v([0-9]+)\.([0-9]+)\.([0-9]+)',version)
 need(v is not None and tuple(map(int,v.groups()))>=(24,11,0),'runtime_node_version_unsupported')
 op.verify_units()
 unit=(REVIEW/m['UNIT']).read_text()
 probe=unit.replace('ExecStartPre=+/usr/bin/python3 -I -B /opt/aifinance-collect-once/bin/consume.py\n','').replace('ExecStart=/usr/bin/python3 -I -B /opt/aifinance-collect-once/bin/run.py','ExecStart=/usr/bin/sleep 30\nPrivateNetwork=yes')
 need(set(old['files'])=={'/etc/systemd/system/'+m['UNIT'],'/etc/systemd/system/'+m['PROBE']},'unit_receipt_changed')
 for name,text in [(m['UNIT'],unit),(m['PROBE'],probe)]:
  p=Path('/etc/systemd/system')/name;m['trusted'](p);need(p.read_text()==text,'installed_unit_changed')
 account=pwd.getpwnam(m['USER']);need(account.pw_uid==old['uid'] and account.pw_gid==old['gid'] and account.pw_shell=='/sbin/nologin' and account.pw_dir=='/nonexistent','collector_os_identity_changed')
 need(account.pw_uid not in (0,int(VALUES['__APPLICATION_UID__']),pwd.getpwnam('aifinance-deploy').pw_uid),'unsafe_collector_uid')
 m['artifact_members'](REVIEW/'collector-runtime.tar.gz',ARTIFACT_SHA);installed_snapshot(m)
 audit=op.db.audit();need(audit['role_absent'] is False,'existing_dedicated_role_missing')
 need(all(audit.get(k) is True for k in ('admin_is_superuser','sequence_matches','application_readonly')) and all(audit.get(k) is False for k in ('public_object_privileges','public_column_privileges','public_schema_create','public_definer_execute','custom_triggers','row_security','unsafe_defaults','unsafe_check_functions')),'retry_catalog_precondition_failed')
 need(op.db.sql("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND backend_type='client backend' AND usename<>'aifinance_app'",True)=='0','other_database_clients_present')
 manifest=json.loads((REVIEW/'approval-manifest.json').read_text());op.feeds=manifest['feeds'];clauses=[]
 for row in op.feeds:
  sid=row['id'];url=row['config']['feedUrl'];need("'" not in sid+url,'invalid_feed')
  endpoint=m['urllib'].parse.urlsplit(url);need(endpoint.scheme=='https' and endpoint.hostname in RESOLVER['HOSTS'] and endpoint.port in (None,443) and not endpoint.username and not endpoint.password,'feed_host_scope_changed')
  clauses.append("(id='"+sid+"' AND kind='rss' AND NOT enabled AND collect_only AND participation_mode='isolated' AND NOT site_fulltext AND NOT syndicate_fulltext AND config=jsonb_build_object('feedUrl','"+url+"'))")
 need(len(clauses)==3 and op.db.sql('SELECT count(*) FROM sources WHERE '+' OR '.join(clauses),True)=='3','source_configuration_mismatch')
 op.before_counts=op.counts();op.before_audit=audit
 resolver=make_resolver(m,old);resolver.inspect();op.resolved_at,op.hosts,net=resolver.resolve();op.network=net['nft'];op.resolver=resolver
 tables=json.loads(m['cmd'](['/usr/sbin/nft','-j','list','tables']).stdout)
 need(not any(x.get('table',{}).get('name')==m['TABLE'] for x in tables['nftables']),'firewall_table_collision')
 m['cmd'](['/usr/sbin/nft','--check','--file','-'],op.network.encode())

def make_resolver(m,old):
 render=runpy.run_path(str(REVIEW/'render-network.py'))['render']
 return RESOLVER['ResolverSnapshot'](m,old,AUDIT,render,[0,int(VALUES['__APPLICATION_UID__']),pwd.getpwnam('aifinance-deploy').pw_uid])

def make_operator(m,db):
 class RetryOperator(m['Operator']):
  def save(self):
   tmp=AUDIT/'state.next';exclusive(tmp,json.dumps(self.state,sort_keys=True).encode());os.replace(tmp,AUDIT/'state.json');syncdir(AUDIT)
  def backup(self):
   size=int(self.db.sql('SELECT pg_database_size(current_database())',True));need(m['shutil'].disk_usage(AUDIT).free>=size*2+268435456,'insufficient_backup_space')
   path=AUDIT/'before.dump';fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
   with os.fdopen(fd,'wb') as out:
    p=self.db.admin_process(['/usr/bin/pg_dump','-w','-Fc'],timeout=120,output=out);out.flush();os.fsync(out.fileno())
   need(p.returncode==0,'retry_backup_failed');m['cmd'](['/usr/bin/pg_restore','--list',str(path)])
   self.state['backup_sha256']=sha(path);self.state['backup_bytes']=path.stat().st_size;self.save();emit('retry_backup_created',bytes=path.stat().st_size,restore_rehearsal=False)
 return RetryOperator(db,REVIEW/'collector-runtime.tar.gz',ARTIFACT_SHA)

def cleanup_all(m,op,hba,resolver=None):
 errors=[]
 try:op.cleanup()
 except Exception:errors.append('operator_cleanup_failed')
 try:hba.restore()
 except Exception:errors.append('hba_restore_failed')
 try:
  if resolver is not None:resolver.restore()
 except Exception:errors.append('resolver_restore_failed')
 try:website(m,op)
 except Exception:errors.append('website_health_failed')
 exclusive(AUDIT/('cleanup-'+str(time.time_ns())+'.json'),json.dumps({'complete':not errors,'errors':errors}).encode())
 emit('retry_cleanup_finished',complete=not errors,errors=errors,hba_restored=not hba.changed,resolver_restored=resolver is None or not resolver.changed)
 need(not errors,'retry_cleanup_requires_recovery')

def trusted_receipt(path):
 for q in (path,*path.parents):
  st=q.lstat();need(st.st_uid==0 and not st.st_mode&0o022 and not stat.S_ISLNK(st.st_mode),'untrusted_hba_recovery_receipt')

def load_hba_recovery(h,db):
 hba=h['TemporaryHBA'](db,AUDIT,db.local_identity[0]);receipt=AUDIT/'hba-receipt.json'
 if not receipt.exists() and not receipt.is_symlink():return hba
 for path in (receipt,AUDIT/'hba.original'):trusted_receipt(path)
 data=json.loads(receipt.read_text());hba.path=Path(data['path']);hba.original=(AUDIT/'hba.original').read_bytes()
 hba.modified=hba.original+b'\n# AIFinance approved retry-001 BEGIN\n'+h['RULE']+b'# AIFinance approved retry-001 END\n'
 need(h['digest'](hba.original)==data['before_sha256'] and h['digest'](hba.modified)==data['after_sha256'],'hba_recovery_receipt_changed')
 need(str(hba.path)==db.sql('SHOW hba_file',True),'hba_target_changed')
 hba.st=types.SimpleNamespace(st_uid=data['uid'],st_gid=data['gid'],st_mode=data['mode']);hba.configs={k:tuple(v) for k,v in data['configs'].items()};hba.changed=True;return hba

def claim_attempt(old):
 AUDIT.mkdir(mode=0o700);syncdir(STATE);exclusive(AUDIT/'original-state.json',(STATE/'state.json').read_bytes());exclusive(AUDIT/'started',b'approved retry-001; never repeat\n')

def regrant_existing(db,review,nonce):
 need(db.role_owned(nonce),'dedicated_role_owner_mismatch');db.verify_disabled(nonce)
 text=(review/'grants.sql').read_text();create='CREATE ROLE aifinance_collect_once NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 1;'
 need(text.count(create)==1,'grant_template_changed');db.sql(text.replace(create,''))

def probe_tcp(m,password):
 env=dict(m['ENV'],PGHOST='127.0.0.1',PGPORT='55432',PGDATABASE='aifinance_preview',PGUSER=m['ROLE'],PGPASSWORD=password,PGPASSFILE='/dev/null',PGCONNECT_TIMEOUT='3')
 query="BEGIN READ ONLY;SET LOCAL statement_timeout='5s';SELECT current_user='aifinance_collect_once' AND current_database()='aifinance_preview' AND current_setting('transaction_read_only')='on';ROLLBACK;"
 p=m['cmd'](['/usr/lib/postgresql/17/bin/psql','-XwAtq','-v','ON_ERROR_STOP=1','-P','pager=off'],query.encode(),env=env,timeout=10,ok=False)
 if p.returncode!=0 or p.stdout.strip()!=b't':
  category=next((v for k,v in ((b'no pg_hba.conf entry','no_hba_entry'),(b'password authentication failed','password_auth_failed'),(b'not permitted to log in','role_disabled'),(b'permission denied for database','database_access_denied')) if k in p.stderr),'other_or_invalid_result')
  emit('retry_login_probe_failed',exit_code=p.returncode,category=category,identity_readonly_ok=p.stdout.strip()==b't');raise Refused('dedicated_role_login_probe_failed')
 emit('retry_tcp_scram_probe_passed')

def execute_retry(m,op,hba):
 try:
  op.backup()
  op.resolved_at,op.hosts,net=op.resolver.install();op.network=net['nft'];op.state['network_sha256']=hashlib.sha256(op.network.encode()).hexdigest();op.save()
  emit('retry_resolver_pinned',hosts=3,public_ipv4_count=len({ip for ips in op.hosts.values() for ip in ips}),snapshot_sha256=hashlib.sha256(net['hosts'].encode()).hexdigest())
  op.probe();hba.install();op.activate();op.run_once()
 finally:
  signal.signal(signal.SIGTERM,signal.SIG_IGN);signal.signal(signal.SIGINT,signal.SIG_IGN)
  cleanup_all(m,op,hba,op.resolver)

def main():
 global VALUES,RECORD_EVENTS,RESOLVER
 p=argparse.ArgumentParser();p.add_argument('mode',choices=['check','run','cleanup']);p.add_argument('--approve-three-source-smoke',action='store_true');p.add_argument('--exclusive-writer-window',action='store_true');a=p.parse_args()
 need(os.geteuid()==0 and sys.stdin.isatty(),'local_root_tty_required')
 m,VALUES=verify_helper();RESOLVER=runpy.run_path(str(HERE/'retry-resolver.py'));h=runpy.run_path(str(HERE/'retry-hba.py'));db=m['Database'].local_socket('/var/run/postgresql');db.verify_admin_identity();op=make_operator(m,db)
 m['trusted'](STATE/'state.json');old=json.loads((STATE/'state.json').read_text());need(old.get('admin_auth')==db.auth_binding(),'original_auth_binding_changed')
 if a.mode=='cleanup':
  m['trusted'](AUDIT/'state.json');RECORD_EVENTS=True;op.state=json.loads((AUDIT/'state.json').read_text());need(op.state.get('nonce')==old.get('nonce') and op.state.get('admin_auth')==db.auth_binding(),'retry_receipt_mismatch')
  try:hba=load_hba_recovery(h,db)
  except Exception:
   class UnreadableHBA:
    changed=True
    def restore(self):raise Refused('hba_recovery_receipt_unreadable')
   hba=UnreadableHBA()
  try:
   resolver=make_resolver(m,old);resolver.recover(trusted_receipt)
  except Exception:
   class UnreadableResolver:
    changed=True
    def restore(self):raise Refused('resolver_recovery_receipt_unreadable')
   resolver=UnreadableResolver()
  cleanup_all(m,op,hba,resolver);return
 need(absent(AUDIT),'retry_already_attempted');op.state=copy.deepcopy(old);gates(m,op,old)
 hba=h['TemporaryHBA'](db,AUDIT,db.local_identity[0]);hba.inspect();emit('retry_preflight_passed',no_writes=True,never_started=True)
 if a.mode=='check':return
 need(a.approve_three_source_smoke and a.exclusive_writer_window,'explicit_retry_scope_required')
 # Exclusive mkdir is the permanent orchestration latch. Never remove or reset it.
 claim_attempt(old);RECORD_EVENTS=True
 op.state.update(phase='retry_prepared',network_attempted=False,network_owned=False);op.save()
 def interrupted(signum,frame):raise Refused('retry_interrupted')
 signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
 def regrant(nonce):regrant_existing(db,REVIEW,nonce)
 db.create_role=regrant
 db.login_probe=lambda password:probe_tcp(m,password)
 execute_retry(m,op,hba)
 need((STATE/'state.json').read_bytes()==(AUDIT/'original-state.json').read_bytes(),'original_receipt_changed')
 emit('retry_finished',complete=True)
if __name__=='__main__':
 try:main()
 except Exception as e:emit('retry_stopped',reason=str(e) if isinstance(e,Refused) or type(e).__name__=='Refused' else 'retry_failure_details_suppressed');sys.exit(1)
