#!/usr/bin/env python3
"""Create an exclusive root-owned local review copy; no service, network or DB changes."""
import argparse,hashlib,json,os,pwd,re,shutil,stat,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
TARGET=Path('/root/aifinance-once-review')
BASELINE='d57ba047369e666025347719caee1a4c642abe62'
LOCK='cb9821a67f7044e86c51ac5149fa0f7550511342b00560c4c593d4fc42bae503'
# Only this published builder is compatible across configure-only revisions.
COMPATIBLE_BUILD_HELPER='0037375d52c49251f4be42e8de8be410b56f51ae'
BUILD_COMPONENT_HASHES={'build-runtime.py': 'd4d6b564b66ebeeb29eaa4da9cd3ed94410a3ca1cea0b64c6d79a179d4828c3a', 'runtime-probe.mjs': 'e2fc62e0b4e952c931854fecedc72dfa3a9d9de8910ce449506565d8aba03d8c', 'templates/runtime_check.py.in': '0740f4ebf8621a08c97ebe2279711c93f84345c694a590897059eec2b3012f77'}
STAGE='startup'
class Refused(ValueError):pass
def need(value,reason):
 if not value:raise Refused(reason)
def trusted(path):
 for p in (path,*path.parents):
  st=p.lstat();need(st.st_uid==0 and not st.st_mode&0o022 and not stat.S_ISLNK(st.st_mode),'untrusted_helper_path')
def bindings(database,port,application_role,deploy_user,application_uid):
 need(all(re.fullmatch('[a-z_][a-z0-9_]{0,62}',s) for s in (database,application_role)),'invalid_database_identifiers')
 need(re.fullmatch('[a-z_][a-z0-9_-]{0,31}',deploy_user),'invalid_os_account')
 need(type(port)==int and 1024<=port<=65535 and type(application_uid)==int and application_uid>0,'invalid_port_or_uid')
 return {'__DATABASE_NAME__':database,'__DATABASE_PORT__':str(port),'__APPLICATION_ROLE__':application_role,'__DEPLOY_USER__':deploy_user,'__APPLICATION_UID__':str(application_uid)}
def rendered_templates(values):
 rendered={}
 for p in sorted((HERE/'templates').glob('*.in')):
  text=p.read_text()
  for key,value in values.items():text=text.replace(key,value)
  need(not re.search('__[A-Z_]+__',text),'unresolved_template')
  rendered[p.name[:-3]]=text
 return rendered
def render(destination,values):
 rendered=rendered_templates(values)
 destination.mkdir(mode=0o700)
 for name,text in rendered.items():
  q=destination/name;q.write_text(text);q.chmod(0o600)
 (destination/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in sorted(destination.iterdir()) if p.is_file()))
def read_bindings():
 database=input('Approved existing database name (visible): ')
 need(re.fullmatch('[a-z_][a-z0-9_]{0,62}',database),'invalid_database_name')
 raw=input('Approved existing loopback database port (visible): ')
 try:port=int(raw)
 except ValueError:raise Refused('invalid_database_port') from None
 need(1024<=port<=65535,'invalid_database_port')
 app=input('Existing SELECT-only application database role (visible): ')
 need(re.fullmatch('[a-z_][a-z0-9_]{0,62}',app),'invalid_application_role')
 deploy=input('Existing restricted deploy OS account (visible): ')
 need(re.fullmatch('[a-z_][a-z0-9_-]{0,31}',deploy),'invalid_deploy_account')
 return database,port,app,deploy
def confirm_bindings(digest,database,port,app,deploy):
 print('Review non-secret configuration (no DB credentials are requested):')
 for name,value in [('artifact_sha256',digest),('database',database),('port',port),('application_role',app),('deploy_account',deploy)]:print(name+'='+str(value))
 need(input('Type CONFIRM to create the root review, or anything else to stop: ')=='CONFIRM','confirmation_cancelled')
def failure_message(e):
 reason=str(e) if isinstance(e,Refused) else ('input_ended' if isinstance(e,EOFError) else type(e).__name__)
 return 'Configuration refused at '+STAGE+': '+reason+'. No service/DB/firewall changes attempted. Preserve existing directories; do not bypass.'
def verify_build_helper(build_commit,helper_commit):
 need(build_commit==helper_commit or build_commit==COMPATIBLE_BUILD_HELPER,'incompatible_build_helper')
 if build_commit==COMPATIBLE_BUILD_HELPER:
  for name,digest in BUILD_COMPONENT_HASHES.items():
   p=HERE/name
   need(p.is_file() and not p.is_symlink() and hashlib.sha256(p.read_bytes()).hexdigest()==digest,'compatible_build_component_changed')
def main():
 global STAGE
 p=argparse.ArgumentParser();p.add_argument('--helper-commit',required=True);p.add_argument('--build-dir',type=Path,required=True);args=p.parse_args()
 STAGE='helper_validation'
 need(os.geteuid()==0 and sys.stdin.isatty(),'root_local_tty_required');need(re.fullmatch('[a-f0-9]{40}',args.helper_commit),'full_helper_sha_required');trusted(HERE)
 for line in (HERE/'SHA256SUMS').read_text().splitlines():
  digest,name=line.split();q=HERE/name;need('..' not in Path(name).parts and not Path(name).is_absolute(),'bad_manifest');trusted(q);need(hashlib.sha256(q.read_bytes()).hexdigest()==digest,'helper_hash_mismatch')
 STAGE='build_validation'
 build=args.build_dir.absolute();need(build.resolve()==build and build.is_dir(),'unsafe_build_path')
 need(build.stat().st_uid==int(os.environ.get('SUDO_UID','-1')) and build.stat().st_uid!=0,'build_owner_mismatch')
 artifact=build/'collector-runtime.tar.gz';receipt=build/'build-result.json'
 need(all(p.is_file() and not p.is_symlink() for p in (artifact,receipt)),'build_files_missing')
 result=json.loads(receipt.read_text());verify_build_helper(result['helper_commit'],args.helper_commit);need(result['source_commit']==BASELINE and result['lockfile_sha256']==LOCK and result['npm_ignore_scripts'] is True,'build_receipt_mismatch')
 need(result.get('runtime_verification',{}).get('probe',{}).get('real_http_module_loaded') is True and result['runtime_verification']['probe'].get('backend_undici_version')=='8.11.2' and result['runtime_verification'].get('required_edges_verified') is True,'runtime_verification_missing')
 STAGE='artifact_digest_input'
 digest=input('Paste the artifact SHA256 reported by your non-root build: ').strip();need(re.fullmatch('[a-f0-9]{64}',digest) and digest==result['artifact_sha256'],'artifact_digest_mismatch')
 need(hashlib.sha256(artifact.read_bytes()).hexdigest()==digest,'artifact_changed')
 STAGE='configuration_inputs'
 database,port,app,deploy=read_bindings()
 STAGE='deploy_account_lookup'
 pwd.getpwnam(deploy)
 users=[]
 for unit in ('aifinance-api.service','aifinance-web.service'):
  STAGE='service_user_'+unit
  value=subprocess.run(['/usr/bin/systemctl','show',unit,'-p','User','--value'],capture_output=True,text=True,timeout=5,check=True).stdout.strip();users.append(pwd.getpwnam(value).pw_uid)
 need(users[0]==users[1] and users[0]>0,'application_uid_ambiguous')
 STAGE='bindings_and_target_validation'
 values=bindings(database,port,app,deploy,users[0]);trusted(TARGET.parent);need(not TARGET.exists() and not TARGET.is_symlink(),'existing_review_refused');rendered_templates(values)
 STAGE='confirmation'
 print('Configuration helper: '+args.helper_commit+'; original build helper: '+result['helper_commit'])
 confirm_bindings(digest,database,port,app,deploy)
 STAGE='root_review_creation'
 render(TARGET,values)
 STAGE='artifact_copy'
 with artifact.open('rb') as source,(TARGET/'collector-runtime.tar.gz').open('xb') as out:shutil.copyfileobj(source,out)
 (TARGET/'collector-runtime.tar.gz').chmod(0o600);need(hashlib.sha256((TARGET/'collector-runtime.tar.gz').read_bytes()).hexdigest()==digest,'copied_artifact_changed')
 # Archive is separately checked by bootstrap; never put a large runtime into its flat helper checksum set.
 (TARGET/'RUNTIME.SHA256').write_text(digest+'  collector-runtime.tar.gz\n')
 print('Root review prepared. No services, DB permissions or firewall rules changed.')
 print('Run check first; if it fails, STOP. Do not run run after a failed check.')
 for mode,extra in [('check',''),('run',' --approve-three-source-smoke --exclusive-writer-window')]:print('/usr/bin/python3 -I -B '+str(TARGET/'bootstrap.py')+' '+mode+' --artifact '+str(TARGET/'collector-runtime.tar.gz')+' --sha256 '+digest+extra)
 print('Recovery only after an installation attempt: /usr/bin/python3 -I -B '+str(TARGET/'bootstrap.py')+' cleanup')
if __name__=='__main__':
 try:main()
 except Exception as e:print(failure_message(e));raise SystemExit(1)
