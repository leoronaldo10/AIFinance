"""Launcher/config regression tests; no accounts, credentials, sockets or services are changed."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('launcher', str(ROOT / 'deploy/native/run-preview.py'))
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)
# Deliberately public, fixed fixtures used only by tests.
CONFIG = ('DATABASE_URL=postgres://aifinance_preview:local-test-only@127.0.0.1:55432/aifinance_preview\n'
          'SITE_URL=http://127.0.0.1:3100\nADMIN_PASSWORD=local-test-password\n'
          'SESSION_SECRET=local-session-fixture-0123456789abcdef\n'
          'IMG_PROXY_SIGN_SECRET=local-image-fixture-0123456789abcdef')


class LauncherTests(unittest.TestCase):
    def test_only_exact_dedicated_database_is_allowed(self):
        for old, new in ((':55432/', ':5432/'), (':55432/', '/'), ('aifinance_preview:local-', 'postgres:local-'),
                         ('127.0.0.1:55432', 'localhost:55432'), ('127.0.0.1:55432', 'db.example.com:55432'),
                         ('/aifinance_preview\n', '/production\n'),
                         ('/aifinance_preview\n', '/aifinance_preview?host=elsewhere\n'),
                         ('/aifinance_preview\n', '/aifinance_preview#options\n')):
            with self.subTest(replacement=new), self.assertRaises(ValueError):
                launcher.environment(CONFIG.replace(old, new))
        self.assertEqual(launcher.environment(CONFIG)['DATABASE_POOL_MAX'], '3')

    def test_personal_loopback_or_valid_https_origin(self):
        for origin in ('http://127.0.0.1:3100', 'http://localhost:3100', 'https://preview.example.com', 'https://preview.example.com:8443/'):
            self.assertEqual(launcher.environment(CONFIG.replace('http://127.0.0.1:3100', origin))['SITE_URL'], origin)
        for origin in ('http://example.com', 'http://0.0.0.0:3100', 'http://127.0.0.1:3101',
                       'http://localhost:3100/evil', 'https://', 'https://user@example.com',
                       'https://example.com/path', 'https://example.com?x=1', 'https://example.com#fragment',
                       'https://example.com:bad', 'https://example.com:0'):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                launcher.environment(CONFIG.replace('http://127.0.0.1:3100', origin))

    def test_fresh_closed_environment(self):
        with patch.dict(os.environ, {'LLM_API_KEY': 'forbidden-fixture', 'NODE_OPTIONS': '--inspect', 'MODEL_CALLS_ENABLED': 'true'}):
            env = launcher.environment(CONFIG)
        for key in ('LLM_API_KEY', 'NODE_OPTIONS', 'HOME', 'PYTHONPATH'):
            self.assertNotIn(key, env)
        for key in ('COLLECT_ENABLED', 'MODEL_CALLS_ENABLED', 'FEISHU_INTERNAL_ENABLED', 'FEISHU_CONTENT_PUSH_ENABLED', 'INDEXNOW_SUBMIT_ENABLED'):
            self.assertEqual(env[key], 'false')
        self.assertEqual(env['PREVIEW_MODE'], 'true')
        self.assertEqual(env['API_HOST'], '127.0.0.1')
        self.assertEqual(env['WEB_HOST'], '127.0.0.1')
        self.assertEqual(env['TRUST_PROXY'], 'false')

    def test_unknown_duplicate_or_short_configuration_fails_closed(self):
        for text in (CONFIG + '\nMODEL_CALLS_ENABLED=true', CONFIG + '\nSITE_URL=https://example.com',
                     CONFIG.replace('local-test-password', 'short'), CONFIG.replace('local-session-fixture-0123456789abcdef', 'short'),
                     CONFIG.replace('SITE_URL=', 'SITE_URL= '), CONFIG + '\nLLM_API_KEY=value'):
            with self.assertRaises(ValueError):
                launcher.environment(text)

    def test_roles_use_dedicated_node_without_web_secrets(self):
        sha = 'a' * 40
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / 'releases' / sha
            release.mkdir(parents=True)
            (release / 'RELEASE_SHA').write_text(sha)
            (root / 'env').write_text(CONFIG)
            def mapped(value):
                if value == '/etc/aifinance-preview.env': return root / 'env'
                if value == '/opt/aifinance/state/current': return release
                if value == '/opt/aifinance/releases': return root / 'releases'
                return Path(value)
            for role, heap in (('api', '128'), ('web', '128')):
                with patch.object(launcher, 'Path', side_effect=mapped), patch.object(sys, 'argv', ['run-preview.py', role]), \
                        patch.object(launcher.os, 'chdir') as chdir, patch.object(launcher.os, 'execve') as execute:
                    launcher.main()
                    program, args, env = execute.call_args[0]
                    self.assertEqual(program, '/opt/aifinance/runtime/node/bin/node')
                    self.assertEqual(args[1], '--max-old-space-size=' + heap)
                    self.assertEqual(env['AIHOT_RELEASE'], sha)
                    chdir.assert_called_once_with(release)
                    for key in ('DATABASE_URL', 'ADMIN_PASSWORD', 'SESSION_SECRET', 'IMG_PROXY_SIGN_SECRET'):
                        self.assertEqual(key in env, role == 'api')

    def test_worker_role_is_never_launched(self):
        with patch.object(sys, 'argv', ['run-preview.py', 'worker']), patch.object(launcher.os, 'execve') as execute:
            with self.assertRaises(SystemExit): launcher.main()
            execute.assert_not_called()

    def test_units_use_cgroup_v1_compatible_limits_without_weakening_egress(self):
        for role, memory in (('api', '320M'), ('web', '256M')):
            text = (ROOT / ('deploy/native/aifinance-preview-' + role + '.service')).read_text()
            for expected in ('User=aifinance', 'MemoryAccounting=yes', 'MemoryLimit=' + memory, 'TasksMax=64',
                             'CPUQuota=50%', 'IPAddressDeny=any', 'IPAddressAllow=localhost',
                             'ExecStart=/usr/bin/python3 -I /opt/aifinance/bin/run-preview.py ' + role):
                self.assertIn(expected, text)
            for forbidden in ('MemoryHigh=', 'MemorySwapMax=', 'MemoryMax=', 'worker', '8000'):
                self.assertNotIn(forbidden, text)


if __name__ == '__main__':
    unittest.main()
