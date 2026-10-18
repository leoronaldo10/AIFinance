"""Fresh addresses for the same three HTTPS hosts; exact reversible hosts snapshot."""
import hashlib,ipaddress,json,os,stat,tempfile,time
from pathlib import Path
HOSTS={'www.microsoft.com','www.journalofaccountancy.com','www.accountingtoday.com'}
OWNER_UID=0
class Refused(Exception):pass
def need(v,reason):
 if not v:raise Refused(reason)
def digest(data):return hashlib.sha256(data).hexdigest()
def public_v4(value):
 try:ip=ipaddress.ip_address(value)
 except ValueError:raise Refused('invalid_resolver_address') from None
 need(ip.version==4 and ip.is_global and not ip.is_multicast and not ip.is_reserved,'unsafe_feed_resolution')
 return str(ip)
def mapping(data):
 need(len(data)<=16384,'resolver_snapshot_too_large');result={h:[] for h in HOSTS}
 for line in data.decode('ascii').splitlines():
  fields=line.split();need(len(fields)==2 and fields[1] in HOSTS,'old_hosts_policy_changed');result[fields[1]].append(public_v4(fields[0]))
 need(all(1<=len(v)<=8 and len(set(v))==len(v) for v in result.values()),'old_hosts_policy_changed')
 return {h:sorted(v) for h,v in result.items()}
def syncdir(p):
 fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
class ResolverSnapshot:
 def __init__(self,m,old,audit,render,forbidden_uids):
  self.m=m;self.old=old;self.audit=Path(audit);self.render=render;self.forbidden=forbidden_uids;self.path=m['CONF']/'hosts';self.changed=False
 def safe(self,p):
  self.m['trusted'](p);s=p.lstat()
  need(stat.S_ISREG(s.st_mode) and not p.is_symlink() and s.st_nlink==1 and s.st_uid==OWNER_UID and s.st_gid==self.old['gid'] and stat.S_IMODE(s.st_mode)==0o440 and not os.listxattr(p),'resolver_file_metadata_changed')
 def network(self,hosts):
  need(set(hosts)==HOSTS,'feed_host_scope_changed')
  net=self.render({'uid':self.old['uid'],'forbidden_uids':self.forbidden,'hosts':hosts})
  net['nft']=net['nft'].replace('create table inet '+self.m['TABLE'],'create table inet '+self.m['TABLE']+' { comment "aifinance-collect-once:'+self.old['nonce']+'"; }')
  return net
 def verify_old(self,data):
  net=self.network(mapping(data))
  need(net['hosts'].encode()==data,'old_hosts_not_canonical')
  need(digest(net['nft'].encode())==self.old.get('network_sha256'),'old_resolver_receipt_mismatch')
 def inspect(self):
  self.safe(self.path);self.safe(self.m['CONF']/'nsswitch.conf')
  need((self.m['CONF']/'nsswitch.conf').read_bytes()==b'hosts: files\n','old_nsswitch_policy_changed')
  self.original=self.path.read_bytes();self.verify_old(self.original)
 def resolve(self):
  started=time.monotonic();hosts={}
  for host in sorted(HOSTS):
   result=self.m['cmd'](['/usr/bin/getent','ahostsv4',host],timeout=6).stdout
   need(len(result)<=16384,'resolver_response_too_large')
   ips=sorted({public_v4(line.split()[0]) for line in result.decode('ascii').splitlines() if line.strip()})
   need(1<=len(ips)<=8,'unsafe_feed_resolution');hosts[host]=ips
  need(0<=time.monotonic()-started<=180,'feed_resolution_expired')
  return started,hosts,self.network(hosts)
 def verify_current(self,expected):
  self.safe(self.path);self.safe(self.m['CONF']/'nsswitch.conf')
  need((self.m['CONF']/'nsswitch.conf').read_bytes()==b'hosts: files\n','nsswitch_concurrent_change')
  need(self.path.read_bytes()==expected,'resolver_concurrent_change')
 def replace(self,expected,data):
  self.verify_current(expected);fd,name=tempfile.mkstemp(prefix='.aifinance-hosts-',dir=self.path.parent)
  try:
   with os.fdopen(fd,'wb') as out:
    os.fchown(out.fileno(),OWNER_UID,self.old['gid']);os.fchmod(out.fileno(),0o440);out.write(data);out.flush();os.fsync(out.fileno())
   self.verify_current(expected);os.replace(name,self.path);syncdir(self.path.parent)
  finally:
   if os.path.exists(name):os.unlink(name)
 def install(self):
  # Run AFTER backup, BEFORE resource probe/HBA/activation. No credential is active.
  started,hosts,net=self.resolve();self.modified=net['hosts'].encode();self.verify_current(self.original)
  self.m['cmd'](['/usr/sbin/nft','--check','--file','-'],net['nft'].encode())
  receipt={'before':self.original.decode('ascii'),'after':self.modified.decode('ascii'),'before_sha256':digest(self.original),'after_sha256':digest(self.modified)}
  fd=os.open(self.audit/'resolver-receipt.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'w') as out:json.dump(receipt,out);out.flush();os.fsync(out.fileno())
  syncdir(self.audit);self.changed=True
  if self.modified!=self.original:self.replace(self.original,self.modified)
  self.verify_current(self.modified)
  return started,hosts,net
 def restore(self):
  if not self.changed:return
  self.safe(self.path);current=self.path.read_bytes()
  need(current in (self.original,self.modified),'resolver_concurrent_change_preserved')
  if current!=self.original:self.replace(self.modified,self.original)
  self.verify_current(self.original);self.changed=False
 def recover(self,trusted):
  p=self.audit/'resolver-receipt.json'
  if not p.exists() and not p.is_symlink():return
  trusted(p);data=json.loads(p.read_text());self.original=data['before'].encode('ascii');self.modified=data['after'].encode('ascii')
  need(digest(self.original)==data['before_sha256'] and digest(self.modified)==data['after_sha256'],'resolver_recovery_hash_mismatch')
  self.verify_old(self.original);need(self.network(mapping(self.modified))['hosts'].encode()==self.modified,'resolver_recovery_scope_mismatch');self.changed=True
