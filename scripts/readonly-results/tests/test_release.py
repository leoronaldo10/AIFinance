"""Offline release checks; reads only local files/git objects, never GitHub or ECS."""
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import unittest
from unittest.mock import patch
import hashlib

ROOT = Path(__file__).resolve().parents[3]
PACKAGE = ROOT / 'scripts/readonly-results'


class ReleaseTests(unittest.TestCase):
    def test_workflows_only_manual_and_reusable_full_pins(self):
        # BaseLoader avoids YAML 1.1's conversion of the key 'on' to boolean True.
        try: import yaml
        except ImportError: self.skipTest('PyYAML required for offline workflow validation')
        entry = yaml.load((ROOT / '.github/workflows/read-collection-results.yml').read_text(), Loader=yaml.BaseLoader)
        reusable = yaml.load((ROOT / '.github/workflows/read-results-reusable.yml').read_text(), Loader=yaml.BaseLoader)
        release = json.loads((PACKAGE / 'release.json').read_text())
        self.assertEqual(set(entry['on']), {'workflow_dispatch'})
        self.assertEqual(set(reusable['on']), {'workflow_call'})
        self.assertEqual(entry['permissions'], {})
        self.assertTrue(entry['jobs']['read']['uses'].endswith('@' + release['reusable_workflow_commit']))
        job = reusable['jobs']['read']; self.assertEqual(job['environment'], 'aifinance-readonly-results')
        self.assertEqual(job['permissions'], {'contents':'read', 'id-token':'write'})
        self.assertEqual(len(job['steps']), 3)
        for workflow in (entry, reusable):
            guard = workflow['jobs']['read']['if']
            self.assertIn("github.event_name == 'workflow_dispatch'", guard)
            self.assertIn("github.ref == 'refs/heads/main'", guard)
            self.assertIn("github.repository_id == '1396876434'", guard)
        checkout = job['steps'][0]
        self.assertRegex(checkout['uses'], r'^actions/checkout@[a-f0-9]{40}$')
        self.assertEqual(checkout['with']['ref'], release['reader_code_commit'])
        self.assertEqual(checkout['with']['persist-credentials'], 'false')
        self.assertEqual(job['steps'][1]['run'], 'python3 -I scripts/readonly-results/read_results.py --identity-preflight')
        self.assertEqual(job['steps'][1]['if'], 'inputs.identity_preflight')
        self.assertEqual(job['steps'][2]['run'], 'python3 -I scripts/readonly-results/read_results.py')
        self.assertEqual(job['steps'][2]['if'], '${{ !inputs.identity_preflight }}')
        self.assertEqual(entry['on']['workflow_dispatch']['inputs']['identity_preflight']['default'], 'true')
        self.assertEqual(entry['jobs']['read']['with']['expected_reusable_sha'], release['reusable_workflow_commit'])
        self.assertNotIn('env', job['steps'][1])
        self.assertEqual(job['env'], {'AIFINANCE_EXPECTED_REUSABLE_SHA': '${{ inputs.expected_reusable_sha }}'})

    def test_immutable_local_bytes_and_handoff_pins(self):
        if not (ROOT / '.git').exists(): self.skipTest('local git objects required')
        release = json.loads((PACKAGE / 'release.json').read_text())
        spec = importlib.util.spec_from_file_location('handoff', PACKAGE / 'install-release.py')
        handoff = importlib.util.module_from_spec(spec); spec.loader.exec_module(handoff)
        self.assertEqual(handoff.CODE_COMMIT, release['code_commit'])
        self.assertEqual(set(handoff.FILES), {'cloud_io.py','result_common.py','export_results.py','retry002.sql',
                                              'install_export.py','runtime-hashes.json','aifinance-export-retry002.service'})
        for name, digest in handoff.FILES.items():
            data = subprocess.check_output(['git','show',release['code_commit'] + ':scripts/readonly-results/' + name], cwd=ROOT)
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
        content = subprocess.check_output(['git','show',release['reusable_workflow_commit'] + ':.github/workflows/read-results-reusable.yml'], cwd=ROOT)
        self.assertEqual(content, (ROOT / '.github/workflows/read-results-reusable.yml').read_bytes())

    def test_trust_exact_repo_owner_environment_workflow(self):
        release = json.loads((PACKAGE / 'release.json').read_text())
        trust = json.loads((PACKAGE / 'policies/reader-trust.template.json').read_text())
        rule = trust['Statement'][0]
        self.assertEqual(rule['Action'], 'sts:AssumeRole')
        subject = rule['Condition']['StringEquals']['oidc:sub']
        self.assertEqual(subject, 'repo:leoronaldo10@311357003/AIFinance@1396876434:repository_id:1396876434:repository_owner_id:311357003:environment:aifinance-readonly-results:'
                         'job_workflow_ref:leoronaldo10/AIFinance/.github/workflows/read-results-reusable.yml@' + release['reusable_workflow_commit'])
        self.assertNotIn('*', subject)

    def test_template_trust_and_reader_agree(self):
        import sys
        sys.path.insert(0, str(PACKAGE))
        import read_results as reader
        from test_results import token, claims
        config = json.loads((PACKAGE / 'policies/github-sub-template.json').read_text())
        self.assertEqual(config, {'use_default': False, 'use_immutable_subject': True,
            'include_claim_keys': ['repo', 'repository_id', 'repository_owner_id', 'context', 'job_workflow_ref']})
        trust = json.loads((PACKAGE / 'policies/reader-trust.template.json').read_text())
        condition = trust['Statement'][0]['Condition']
        self.assertEqual(set(condition), {'StringEquals'})
        values = condition['StringEquals']
        self.assertEqual(set(values), {'oidc:iss', 'oidc:aud', 'oidc:sub'})
        data = claims()
        data['job_workflow_ref'] = 'leoronaldo10/AIFinance/.github/workflows/read-results-reusable.yml@' + json.loads((PACKAGE / 'release.json').read_text())['reusable_workflow_commit']
        data['sub'] = values['oidc:sub']
        data['iss'], data['aud'] = values['oidc:iss'], values['oidc:aud']
        self.assertEqual(reader.check_claims(token(data)), data)

    def test_handoff_hash_failure_never_calls_sudo(self):
        spec = importlib.util.spec_from_file_location('handoff', PACKAGE / 'install-release.py')
        handoff = importlib.util.module_from_spec(spec); spec.loader.exec_module(handoff)
        class Response:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, limit): return b'wrong bytes'
        class Opener:
            def open(self, *args, **kwargs): return Response()
        with patch.object(handoff.sys, 'argv', ['handoff','cn-beijing']), \
             patch.object(handoff.urllib.request, 'build_opener', return_value=Opener()), \
             patch.object(handoff.subprocess, 'run') as run, self.assertRaises(RuntimeError): handoff.main()
        run.assert_not_called()
