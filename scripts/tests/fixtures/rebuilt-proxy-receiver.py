#!/usr/bin/env python3
"""Test-only PTY gateway host: temporary filesystem, no network/systemd calls."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

repo=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('gateway',repo/'deploy/native/rebuilt-gateway.py')
g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)
root=Path(sys.argv[1]);policy=json.loads((root/'fixture-policy.json').read_text())
mode=sys.argv[2]
sys.argv=['rebuilt-gateway.py',*sys.argv[3:]]
g.ROOT=root

def restart():
    counter=root/'restarts'
    counter.write_text(str(int(counter.read_text())+1 if counter.exists() else 1))
    if mode=='interrupt-checking':raise g.Interrupted()

def run(argv,**kwargs):
    if argv[:3]!=['/usr/bin/python3','-I','-B'] or argv[3]!=str(root/'bin/extract-release.py'):
        raise AssertionError('real host command forbidden')
    result=subprocess.run([sys.executable,'-I','-B',str(repo/'deploy/native/extract-release.py'),*argv[4:]],capture_output=True,timeout=10)
    if result.returncode:raise g.Refused('fixture_extract_failed')
    return ''

with patch.object(g,'policy',return_value=policy),patch.object(g,'healthy',side_effect=lambda sha:g.current_sha(policy)==sha),\
     patch.object(g,'restart',side_effect=restart),patch.object(g,'services_idle'),patch.object(g,'trusted'),\
     patch.object(g,'run',side_effect=run),patch.object(g.pwd,'getpwuid') as user:
    user.return_value.pw_name='aifinance-deploy'
    try:
        result=g.main(terminal=True)
    except g.Interrupted:
        result={'ok':False,'reason':'operation_interrupted_query_status'}
    except g.Refused:
        result={'ok':False,'reason':'fixture_refused'}
    print(json.dumps(result),flush=True)
