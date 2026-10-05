#!/usr/bin/python3
"""Offline fixed-entry tests: no SSH, sudo or host commands."""
import ast
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import sys
import tempfile
import subprocess
import json
import unittest
from unittest.mock import patch

REPO=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('ops_gateway',str(REPO/'deploy/native/ops-gateway.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
ACTIONS=('diagnose','restart-preview','probe','recover-pre-seed','seed','run','disable','enable-hourly')

class GatewayTests(unittest.TestCase):
    def test_only_exact_approved_enums(self):
        self.assertEqual(m.OPS,ACTIONS)
        for action in ACTIONS:self.assertEqual(m.parse('ops-v1 '+action),['ops-v1',action])
        for bad in ('ops-v1','ops-v1 status','ops-v1 /bin/sh','ops-v1 diagnose x','ops-v1  diagnose',
                    ' ops-v1 diagnose','ops-v1 diagnose ','ops-v1\tdiagnose','ops-v1 diagnose\n',
                    'ops-v1 diagnose;id','ops-v1 $(id)','ops-v1 enable-hourly --accept-admin-view',
                    'ops-v1 run --scheduled','ops-v1 install','ops-v1 recover-pre-seed /tmp/x'):
            with self.assertRaises(ValueError):m.parse(bad)

    def test_exact_sudo_argv_and_rebuilt_environment_without_stdin(self):
        class NoInput:
            @property
            def buffer(self):raise AssertionError('ops must not consume uploaded input')
        for action in ACTIONS:
            source={'SSH_ORIGINAL_COMMAND':'ops-v1 '+action,'PYTHONPATH':'unsafe','SUDO_ASKPASS':'unsafe',
                    'LD_PRELOAD':'unsafe','AIFINANCE_ROOT':'/tmp/unsafe','HOME':'/tmp/unsafe'}
            with patch.dict(os.environ,source,clear=True),patch.object(m.os,'execve') as execute,patch.object(m.sys,'stdin',NoInput()):
                m.main()
                expected=['/usr/bin/sudo','-n','/usr/bin/python3','-I','-B','/opt/aifinance/bin/ops-broker.py',action]
                if action=='enable-hourly':expected+=['--accept-admin-view']
                execute.assert_called_once_with('/usr/bin/sudo',expected,{'PATH':'/usr/bin:/bin','HOME':'/var/lib/aifinance-deploy','LANG':'C.UTF-8'})

    def test_original_verbs_and_immutable_upload_survive(self):
        sha='a'*40;digest=hashlib.sha256(b'fixture').hexdigest()
        for command in ('verify','inspect','upload '+sha+' '+digest,'deploy '+sha+' '+digest,'rollback '+sha):
            self.assertEqual(m.parse(command),command.split(' '))
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'incoming').mkdir()
            m.upload(root,sha,digest,io.BytesIO(b'fixture'))
            self.assertEqual((root/'incoming'/(sha+'.tar.gz')).read_bytes(),b'fixture')
            with self.assertRaises(ValueError):m.upload(root,sha,digest,io.BytesIO(b'fixture'))
            with patch.object(m,'LIMIT',2),self.assertRaises(ValueError):m.upload(root,'b'*40,digest,io.BytesIO(b'fixture'))
            self.assertEqual(list((root/'incoming').glob('.upload-*')),[])

    def test_deployment_still_requires_native_ready(self):
        with tempfile.TemporaryDirectory() as d,patch.object(m,'ROOT',Path(d)),patch.dict(os.environ,{'SSH_ORIGINAL_COMMAND':'rollback '+'a'*40},clear=True),patch.object(m.os,'execve') as execute:
            with self.assertRaises(ValueError):m.main()
            execute.assert_not_called()

    def test_python36_and_workflow_boundary(self):
        ast.parse((REPO/'deploy/native/ops-gateway.py').read_text(),**({'feature_version':(3,6)} if sys.version_info>=(3,8) else {}))
        workflow=(REPO/'.github/workflows/deploy-preview.yml').read_text()
        self.assertIn("github.ref == 'refs/heads/release/aifinance-preview'",workflow)
        self.assertIn('environment: aifinance-preview',workflow)
        self.assertIn('contents: read',workflow)
        access=workflow.split('  access:',1)[1]
        self.assertNotIn('actions/checkout',access)
        self.assertNotIn('workflow_run:',workflow)
        self.assertIn("github.event_name == 'push' && 'verify'",access)
        self.assertIn("if: inputs.operation == 'build' || inputs.operation == 'stage' || inputs.operation == 'deploy'",workflow)
        self.assertIn('[[ -z "$REVISION" ]]',access)
        self.assertIn('StrictHostKeyChecking=yes',workflow)
        self.assertIn('ADMIN_VIEW_ACCEPTED',workflow)

    def test_install_manifest_pins_exact_final_sources(self):
        manifest=json.loads((REPO/'deploy/native/ops-files.json').read_text())
        self.assertEqual(set(manifest),{'schema','installer_sha256','broker_sha256','gateway_sha256','runner_sha256'})
        self.assertEqual(manifest['schema'],1)
        for name,key in (('install-ops.py','installer_sha256'),('ops-broker.py','broker_sha256'),('ops-gateway.py','gateway_sha256'),('collect-only-runner.py','runner_sha256')):
            self.assertEqual(hashlib.sha256((REPO/'deploy/native'/name).read_bytes()).hexdigest(),manifest[key])
        self.assertEqual(hashlib.sha256((REPO/'deploy/native/ssh-gateway.py').read_bytes()).hexdigest(),'d5f87fa494475c2686e9cc19bf3f00c06f9984205d6f840e52ad7ac9841ce6c6')

    def test_workflow_ops_shell_maps_only_enums_and_requires_hourly_acceptance(self):
        workflow=(REPO/'.github/workflows/deploy-preview.yml').read_text()
        lines=workflow.split('  access:',1)[1].split('        run: |\n',1)[1].splitlines()
        script='\n'.join(line[10:] if line.startswith('          ') else line for line in lines)+'\n'
        self.assertEqual(subprocess.run(['bash','-n'],input=script,universal_newlines=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE).returncode,0)
        with tempfile.TemporaryDirectory() as d:
            fake=Path(d)/'ssh';fake.write_text('#!/usr/bin/env python3\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\n');fake.chmod(0o755)
            env=dict(PATH=d+':'+os.environ['PATH'],SSH_HOST='example.invalid',SSH_PORT='22',SSH_KEY='public-test-key',SSH_KNOWN_HOSTS='public-test-host',REVISION='',ADMIN_VIEW_ACCEPTED='false')
            for action in ACTIONS:
                env.update(OPERATION='ops-'+action,ADMIN_VIEW_ACCEPTED='true' if action=='enable-hourly' else 'false')
                result=subprocess.run(['bash','-c',script],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,universal_newlines=True)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(json.loads(result.stdout)[-1],'ops-v1 '+action)
            for operation,revision,accepted in (('ops-diagnose;id','','false'),('ops-run --scheduled','','false'),('ops-diagnose','a'*40,'false'),('ops-enable-hourly','','false'),('ops-diagnose','','true')):
                env.update(OPERATION=operation,REVISION=revision,ADMIN_VIEW_ACCEPTED=accepted)
                result=subprocess.run(['bash','-c',script],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,universal_newlines=True)
                self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,'')

if __name__=='__main__':unittest.main()
