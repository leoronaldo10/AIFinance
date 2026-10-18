#!/usr/bin/env python3
"""Create a verified sibling review; never edit the existing review or runtime."""
import argparse,hashlib,json,os,re,runpy,shutil,stat,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
OLD=Path('/root/aifinance-once-review');NEW=Path('/root/aifinance-once-review-socket')
BASE_TEMPLATE_SHA='0db3a5283009ddf6814dab38681a3d447b9abef7348b24e5f21af203f80185bd'
class Refused(Exception):pass
def need(v,reason):
 if not v:raise Refused(reason)
def digest(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for block in iter(lambda:f.read(1048576),b''):h.update(block)
 return h.hexdigest()
def trusted(p):
 for q in (p,*p.parents):
  st=q.lstat();need(st.st_uid==0 and not st.st_mode&0o022 and not stat.S_ISLNK(st.st_mode),'untrusted_review_path')
def manifest(root):
 trusted(root/'SHA256SUMS');entries={}
 for line in (root/'SHA256SUMS').read_text().splitlines():
  h,name=line.split();p=Path(name);need(not p.is_absolute() and '..' not in p.parts and name not in entries,'invalid_manifest')
  trusted(root/name);need((root/name).is_file() and digest(root/name)==h,'manifest_hash_mismatch');entries[name]=h
 return entries
def recover_bindings(text,base):
 patterns={'__DATABASE_NAME__':'[a-z_][a-z0-9_]{0,62}','__DATABASE_PORT__':'[0-9]{1,5}','__APPLICATION_ROLE__':'[a-z_][a-z0-9_]{0,62}','__DEPLOY_USER__':'[a-z_][a-z0-9_-]{0,31}','__APPLICATION_UID__':'[0-9]+'};seen=set();parts=[]
 for piece in re.split('('+ '|'.join(patterns)+')',base):
  if piece not in patterns:parts.append(re.escape(piece));continue
  name=piece.strip('_');parts.append('(?P='+name+')' if piece in seen else '(?P<'+name+'>'+patterns[piece]+')');seen.add(piece)
 match=re.fullmatch(''.join(parts),text);need(match is not None and seen==set(patterns),'old_bootstrap_not_exact_approved_template')
 return {key:match.group(key.strip('_')) for key in patterns}
def prepare(old,new,want):
 manifest(HERE);trusted(old);trusted(new.parent)
 need(not new.exists() and not new.is_symlink(),'new_review_must_be_absent')
 need(all(not p.exists() and not p.is_symlink() for p in map(Path,('/opt/aifinance-collect-once','/etc/aifinance-collect-once','/var/lib/aifinance-collect-once'))),'installation_already_started')
 entries=manifest(old);base=HERE/'upgrade-base-bootstrap.py.txt';need(digest(base)==BASE_TEMPLATE_SHA,'base_template_changed')
 values=recover_bindings((old/'bootstrap.py').read_text(),base.read_text())
 configure=runpy.run_path(str(HERE/'configure.py'));values=configure['bindings'](values['__DATABASE_NAME__'],int(values['__DATABASE_PORT__']),values['__APPLICATION_ROLE__'],values['__DEPLOY_USER__'],int(values['__APPLICATION_UID__']))
 rendered=configure['rendered_templates'](values);need(set(entries)==set(rendered),'unexpected_old_review_files')
 for name,text in rendered.items():
  if name!='bootstrap.py':need((old/name).read_bytes()==text.encode(),'non_bootstrap_review_change_refused')
 artifact=old/'collector-runtime.tar.gz';trusted(artifact);trusted(old/'RUNTIME.SHA256')
 need(artifact.is_file() and digest(artifact)==want and (old/'RUNTIME.SHA256').read_text()==want+'  collector-runtime.tar.gz\n','runtime_hash_mismatch')
 # All validation is complete before creating the sibling. Failure preserves partial evidence.
 new.mkdir(mode=0o700)
 for name,text in rendered.items():
  with (new/name).open('x') as f:f.write(text)
  (new/name).chmod(0o600)
 (new/'SHA256SUMS').write_text(''.join(digest(new/name)+'  '+name+'\n' for name in sorted(rendered)));(new/'SHA256SUMS').chmod(0o600)
 fd=os.open(new/'collector-runtime.tar.gz',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with artifact.open('rb') as source,os.fdopen(fd,'wb') as out:shutil.copyfileobj(source,out);out.flush();os.fsync(out.fileno())
 need(digest(new/'collector-runtime.tar.gz')==want,'copied_runtime_changed')
 (new/'RUNTIME.SHA256').write_text(want+'  collector-runtime.tar.gz\n');(new/'RUNTIME.SHA256').chmod(0o600);manifest(new)
 print(json.dumps({'stage':'sibling_review_prepared','old_review_unchanged':True,'runtime_sha256':want,'database_or_service_changes':False}))
def main():
 p=argparse.ArgumentParser();p.add_argument('--sha256',required=True);a=p.parse_args();need(os.geteuid()==0 and sys.stdin.isatty(),'root_local_tty_required');need(re.fullmatch('[a-f0-9]{64}',a.sha256),'invalid_runtime_hash');prepare(OLD,NEW,a.sha256)
if __name__=='__main__':
 try:main()
 except Exception as e:print(json.dumps({'stage':'upgrade_refused','reason':str(e) if isinstance(e,Refused) else type(e).__name__}));raise SystemExit(1)
