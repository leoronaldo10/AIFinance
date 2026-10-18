#!/usr/bin/env python3
"""Offline tests. Optional PostgreSQL tests require an explicitly supplied disposable cluster."""
import argparse,os,pathlib,runpy,shutil,subprocess,sys,tempfile
R=pathlib.Path(__file__).resolve().parent
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--postgres',action='store_true');a=p.parse_args()
 if a.postgres:
  for key in ('COLLECT_TEST_PSQL','COLLECT_TEST_SOCKET','COLLECT_TEST_PORT','COLLECT_TEST_ADMIN'):assert os.environ.get(key),key
 with tempfile.TemporaryDirectory(prefix='collect-helper-test-') as directory:
  dest=pathlib.Path(directory)/'review';m=runpy.run_path(str(R/'configure.py'));m['render'](dest,m['bindings']('fixture_db',65439,'fixture_app','fixture_deploy',2345))
  for name in ('test_review.py','test_bootstrap.py','test_cgroup.py','synthetic-schema.sql'):shutil.copyfile(R/'tests'/name,dest/name)
  repo=R.parents[1]
  for source,target in [('packages/backend/src/content/materials.ts','reference-materials.ts'),('packages/backend/src/sources/collect-only.ts','reference-collect-only.ts')]:shutil.copyfile(repo/source,dest/target)
  suites=['test_review.py','test_bootstrap.py','test_cgroup.py']
  if a.postgres:shutil.copyfile(R/'tests/test_postgres.py',dest/'test_postgres.py');suites.append('test_postgres.py')
  for name in suites:subprocess.run([sys.executable,'-I','-B',str(dest/name)],check=True,timeout=60)
 subprocess.run([sys.executable,'-I','-B',str(R/'tests/test_build.py')],check=True,timeout=30)

 subprocess.run([sys.executable,'-I','-B',str(R/'tests/test_runtime.py')],check=True,timeout=30)
