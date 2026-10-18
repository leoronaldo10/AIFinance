"""Exact-target, temporary HBA change. No raw configuration or errors are emitted."""
import hashlib,ipaddress,json,os,stat,tempfile,time
from pathlib import Path
RULE=b'host aifinance_preview aifinance_collect_once 127.0.0.1/32 scram-sha-256\n'
class Refused(Exception):pass
def need(v,reason):
 if not v:raise Refused(reason)
def digest(data):return hashlib.sha256(data).hexdigest()
def safe_path(p,postgres_uid):
 for q in (p,*p.parents):
  st=q.lstat();need(not stat.S_ISLNK(st.st_mode) and st.st_uid in (0,postgres_uid) and not st.st_mode&0o022,'untrusted_hba_path')
 need(p.is_file() and p.stat().st_nlink==1,'unsafe_hba_file')
def no_matching_rule(rows):
 for r in rows:
  need(r['error'] is None,'hba_parse_error')
  if r['type']=='local':continue
  # Unknown patterns are refused rather than pretending to fully evaluate HBA.
  def possible(values,wanted):
   return any(v in (wanted,'all','sameuser','samerole','samegroup') or v.startswith(('/','@','+')) for v in values)
  if not possible(r['database'],'aifinance_preview') or not possible(r['user_name'],'aifinance_collect_once'):continue
  try:network=ipaddress.ip_network(r['address']+'/'+r['netmask'],strict=False)
  except (ValueError,TypeError):raise Refused('ambiguous_existing_hba_rule') from None
  need(ipaddress.ip_address('127.0.0.1') not in network,'existing_target_hba_rule_refused')
class TemporaryHBA:
 def __init__(self,db,audit,postgres_uid):
  self.db=db;self.audit=Path(audit);self.uid=postgres_uid;self.changed=False;self.path=None
 def rows(self):return json.loads(self.db.sql("SELECT coalesce(json_agg(row_to_json(t)),'[]'::json) FROM (SELECT type,database,user_name,address,netmask,auth_method,error FROM pg_hba_file_rules) t",True))
 def inspect(self):
  self.path=Path(self.db.sql('SHOW hba_file',True));safe_path(self.path,self.uid)
  self.original=self.path.read_bytes();self.st=self.path.stat();need(not os.listxattr(self.path),'hba_extended_attributes_require_review')
  # Preserve order; do not support unknown include graphs or continuation syntax.
  for line in self.original.decode().splitlines():
   s=line.strip()
   need(not s.startswith(('include ','include\t','include_if_exists','include_dir')) and not s.endswith('\\'),'hba_include_or_continuation_requires_review')
  no_matching_rule(self.rows())
  need(self.db.sql('SELECT NOT EXISTS(SELECT FROM pg_file_settings WHERE error IS NOT NULL) AND NOT EXISTS(SELECT FROM pg_settings WHERE pending_restart)',True)=='t','pending_or_invalid_server_configuration')
  files=self.config_paths()
  loaded=float(self.db.sql('SELECT extract(epoch FROM pg_conf_load_time())',True))
  self.configs={}
  for name in set(files):
   p=Path(name);safe_path(p,self.uid);st=p.stat();need(st.st_mtime<=loaded,'pending_configuration_edit');self.configs[name]=(digest(p.read_bytes()),st.st_ino,st.st_mtime_ns)
  self.addition=b'\n# AIFinance approved retry-001 BEGIN\n'+RULE+b'# AIFinance approved retry-001 END\n'
  need(b'AIFinance approved retry-001' not in self.original,'existing_retry_hba_marker')
  self.modified=self.original+self.addition
 def config_paths(self):
  files=json.loads(self.db.sql("SELECT json_agg(DISTINCT sourcefile) FROM pg_file_settings WHERE sourcefile IS NOT NULL",True)) or []
  files += [self.db.sql('SHOW config_file',True),self.db.sql('SHOW ident_file',True),str(self.path),str(Path(self.db.sql('SHOW data_directory',True))/'postgresql.auto.conf')]
  return set(files)
 def unchanged_configs(self,expect_hba):
  need(self.config_paths()==set(self.configs),'concurrent_configuration_file_set_change')
  need(self.db.sql('SELECT NOT EXISTS(SELECT FROM pg_file_settings WHERE error IS NOT NULL)',True)=='t','concurrent_configuration_parse_error')
  for name,old in self.configs.items():
   p=Path(name);safe_path(p,self.uid)
   if p==self.path:need(p.read_bytes()==expect_hba,'hba_concurrent_change')
   else:need((digest(p.read_bytes()),p.stat().st_ino,p.stat().st_mtime_ns)==old,'concurrent_server_configuration_change')
 def replace(self,expected,data):
  safe_path(self.path,self.uid);need(self.path.read_bytes()==expected,'hba_concurrent_change')
  fd,name=tempfile.mkstemp(prefix='.aifinance-hba-',dir=self.path.parent)
  try:
   with os.fdopen(fd,'wb') as f:
    os.fchown(f.fileno(),self.st.st_uid,self.st.st_gid);os.fchmod(f.fileno(),stat.S_IMODE(self.st.st_mode));f.write(data);f.flush();os.fsync(f.fileno())
   self.unchanged_configs(expected);os.replace(name,self.path)
   fd=os.open(self.path.parent,os.O_RDONLY|os.O_DIRECTORY)
   try:os.fsync(fd)
   finally:os.close(fd)
  finally:
   if os.path.exists(name):os.unlink(name)
 def reload(self):
  before=self.db.sql('SELECT pg_conf_load_time()::text',True)
  need(self.db.sql('SELECT pg_reload_conf()')=='t','hba_reload_signal_failed')
  for _ in range(40):
   if self.db.sql('SELECT pg_conf_load_time()::text',True)!=before:return
   time.sleep(.05)
  raise Refused('hba_reload_not_observed')
 def install(self):
  self.unchanged_configs(self.original)
  fd=os.open(self.audit/'hba.original',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb') as f:f.write(self.original);f.flush();os.fsync(f.fileno())
  receipt={'path':str(self.path),'before_sha256':digest(self.original),'after_sha256':digest(self.modified),'uid':self.st.st_uid,'gid':self.st.st_gid,'mode':stat.S_IMODE(self.st.st_mode),'configs':self.configs}
  with (self.audit/'hba-receipt.json').open('x') as f:os.fchmod(f.fileno(),0o600);json.dump(receipt,f);f.flush();os.fsync(f.fileno())
  fd=os.open(self.audit,os.O_RDONLY|os.O_DIRECTORY)
  try:os.fsync(fd)
  finally:os.close(fd)
  # Mark attempted before replace: interrupted/failed writes must never skip rollback.
  self.changed=True;self.replace(self.original,self.modified)
  rows=self.rows();need(all(r['error'] is None for r in rows),'new_hba_parse_error')
  r=rows[-1];need(r['type']=='host' and r['database']==['aifinance_preview'] and r['user_name']==['aifinance_collect_once'] and r['address']=='127.0.0.1' and r['netmask']=='255.255.255.255' and r['auth_method']=='scram-sha-256','new_hba_rule_mismatch')
  self.reload()
 def restore(self):
  if not self.changed:return
  current=self.path.read_bytes()
  need(current in (self.original,self.modified),'hba_concurrent_change_preserved')
  self.unchanged_configs(current)
  if current==self.modified:self.replace(self.modified,self.original)
  self.reload();need(self.path.read_bytes()==self.original and all(r['error'] is None for r in self.rows()),'hba_restore_not_verified');self.changed=False
