#!/usr/bin/env python3
"""Non-root fixed-source collector build. No application/lifecycle scripts or server access."""
import argparse,base64,gzip,hashlib,json,os,platform,re,shutil,subprocess,tarfile
from pathlib import Path
BASELINE='d57ba047369e666025347719caee1a4c642abe62'
LOCK='cb9821a67f7044e86c51ac5149fa0f7550511342b00560c4c593d4fc42bae503'
REPOSITORY='https://github.com/leoronaldo10/AIFinance.git'
HERE=Path(__file__).resolve().parent
class Refused(Exception):pass
def need(value,reason):
 if not value:raise Refused(reason)
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def verify_helper():
 for line in (HERE/'SHA256SUMS').read_text().splitlines():
  digest,name=line.split();p=HERE/name
  need(not Path(name).is_absolute() and '..' not in Path(name).parts and not p.is_symlink() and sha(p)==digest,'helper_checksum_mismatch')
def command(args,cwd,env,timeout=60):
 p=subprocess.run(args,cwd=cwd,env=env,capture_output=True,timeout=timeout)
 need(p.returncode==0,'build_command_failed_'+Path(args[0]).name)
 return p.stdout.decode().strip()
def integrity(source,cache):
 lock=json.loads((source/'package-lock.json').read_text())['packages'];installed=json.loads((source/'node_modules/.package-lock.json').read_text())['packages'];verified=0
 for path,meta in installed.items():
  if meta.get('link') or path in ('industry','packages/backend','packages/contracts'):continue
  expected=lock[path];need(meta['version']==expected['version'] and meta.get('integrity')==expected.get('integrity'),'installed_lock_mismatch')
  need(expected['resolved'].startswith('https://registry.npmjs.org/'),'nonofficial_registry')
  algorithm,digest=expected['integrity'].split('-',1);need(algorithm=='sha512','unsupported_integrity')
  value=base64.b64decode(digest,validate=True).hex();blob=cache/'_cacache/content-v2/sha512'/value[:2]/value[2:4]/value[4:]
  need(hashlib.sha512(blob.read_bytes()).hexdigest()==value,'dependency_integrity_mismatch');verified+=1
 return verified
def package(source,destination):
 roots=['package.json','package-lock.json','scripts/collect-only.ts','industry','packages/backend/package.json','packages/backend/src','packages/contracts/package.json','packages/contracts/src','node_modules'];paths=[]
 for name in roots:
  p=source/name;paths.append(p)
  if p.is_dir():
   for base,dirs,files in os.walk(p,followlinks=False):paths.extend(Path(base)/x for x in dirs+files)
 def allowed(p):return not any(x.startswith('.env') or x in ('.git','.data','.npmrc','.netrc','.aws','.ssh','.cache','__pycache__') for x in p.relative_to(source).parts)
 with destination.open('xb') as raw,gzip.GzipFile(fileobj=raw,mode='wb',filename='',mtime=0) as gz,tarfile.open(fileobj=gz,mode='w|',format=tarfile.PAX_FORMAT) as tar:
  for p in sorted(set(paths),key=lambda p:p.relative_to(source).as_posix()):
   if not allowed(p):continue
   info=tar.gettarinfo(str(p),arcname=p.relative_to(source).as_posix());need(not info.islnk(),'hardlink_refused');info.uid=info.gid=0;info.uname=info.gname='root';info.mtime=0;info.pax_headers={}
   if info.issym():
    need(not os.path.isabs(info.linkname) and source in p.resolve().parents,'symlink_escape');tar.addfile(info)
   elif info.isdir():info.mode=0o755;tar.addfile(info)
   else:
    need(info.isfile(),'special_file_refused');info.mode=0o755 if p.stat().st_mode&0o111 else 0o644
    with p.open('rb') as f:tar.addfile(info,f)
 return sha(destination)
def main():
 parser=argparse.ArgumentParser();parser.add_argument('--helper-commit',required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
 need(os.geteuid()!=0,'build_as_nonroot');need(platform.system()=='Linux' and platform.machine()=='x86_64','linux_x86_64_required');need(re.fullmatch('[a-f0-9]{40}',args.helper_commit),'full_helper_sha_required');verify_helper()
 env={k:v for k,v in os.environ.items() if k in ('PATH','HTTPS_PROXY','HTTP_PROXY','ALL_PROXY','NO_PROXY','https_proxy','http_proxy','all_proxy','no_proxy')};env.update(GIT_TERMINAL_PROMPT='0',GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null')
 git=['git','-c','core.hooksPath=/dev/null','-c','credential.helper=','-c','http.lowSpeedLimit=1024','-c','http.lowSpeedTime=20']
 need(command(git+['rev-parse','HEAD'],HERE,env)==args.helper_commit,'helper_commit_mismatch')
 need(not command(git+['status','--porcelain','--untracked-files=all','--',str(HERE)],HERE,env),'helper_worktree_not_clean')
 node=command(['node','--version'],HERE,env);m=re.fullmatch(r'v(\d+)\.(\d+)\.(\d+)',node);need(m and tuple(map(int,m.groups()))>=(24,11,0),'node_24_11_required')
 out=args.output.expanduser().absolute();need(out.parent.resolve()==out.parent and out.parent.stat().st_uid==os.getuid(),'output_parent_untrusted');need(not out.exists() and not out.is_symlink(),'new_build_directory_required');need(not str(out).startswith(('/opt/','/etc/','/var/')),'website_or_system_directory_refused');out.mkdir(mode=0o700)
 source=out/'source';source.mkdir();home=out/'npm-home';home.mkdir();cache=out/'npm-cache';cache.mkdir();env['HOME']=str(home);global_config=home/'empty-global-config';global_config.write_text('')
 command(git+['init','--quiet'],source,env)
 command(git+['fetch','--no-tags','--depth=1',REPOSITORY,BASELINE],source,env,90)
 need(command(git+['rev-parse','FETCH_HEAD'],source,env)==BASELINE,'baseline_mismatch');command(git+['checkout','--detach',BASELINE],source,env)
 need(sha(source/'package-lock.json')==LOCK,'lock_mismatch')
 env.update(NODE_USE_SYSTEM_CA='1',npm_config_userconfig='/dev/null',npm_config_globalconfig=str(global_config),npm_config_cache=str(cache),npm_config_registry='https://registry.npmjs.org',npm_config_fetch_retries='0',npm_config_fetch_timeout='30000',npm_config_audit='false',npm_config_fund='false',npm_config_strict_ssl='true')
 if Path('/etc/ssl/certs/ca-certificates.crt').is_file():env['npm_config_cafile']='/etc/ssl/certs/ca-certificates.crt'
 command(['npm','ci','--ignore-scripts','--omit=dev','--workspace=@aihot/backend','--include-workspace-root=false','--no-audit','--no-fund'],source,env,240)
 need(sha(source/'package-lock.json')==LOCK,'lock_changed');verified=integrity(source,cache)
 artifact=out/'collector-runtime.tar.gz';digest=package(source,artifact)
 result={'helper_commit':args.helper_commit,'source_commit':BASELINE,'lockfile_sha256':LOCK,'artifact_sha256':digest,'artifact_bytes':artifact.stat().st_size,'verified_dependency_tarballs':verified,'npm_ignore_scripts':True,'node':node,'runtime':'collector-only linux-x86_64'}
 (out/'build-result.json').write_text(json.dumps(result,indent=2)+'\n');(out/'RUNTIME.SHA256').write_text(digest+'  collector-runtime.tar.gz\n');print(json.dumps(result,indent=2))
if __name__=='__main__':
 try:main()
 except Exception as e:print(json.dumps({'status':'stopped','reason':str(e) if isinstance(e,Refused) else 'build_failed_details_suppressed'}));raise SystemExit(1)
