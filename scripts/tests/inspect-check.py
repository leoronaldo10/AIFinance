"""Diagnostic contract tests: synthetic processes/files only, no ECS or credential access."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, str(ROOT / 'deploy/native' / file))
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m


class Inspect(unittest.TestCase):
    def test_exact_gateway_command_before_native_ready_and_clean_environment(self):
        m = module('gateway_inspect', 'ssh-gateway.py')
        self.assertEqual(m.parse('inspect'), ['inspect'])
        for bad in ('inspect ', 'inspect\n', 'inspect;id', 'inspect /etc/shadow', 'inspect --help', '$(id)', 'inspect\x00'):
            with self.assertRaises(ValueError): m.parse(bad)
        before = os.umask(0o022)
        try:
            with patch.dict(os.environ, {'SSH_ORIGINAL_COMMAND': 'inspect', 'PYTHONPATH': '/caller', 'BASH_ENV': '/caller', 'SECRET': 'never-output'}, clear=True), patch.object(m.os, 'execve') as execute:
                m.main()
                args = execute.call_args[0]
                self.assertEqual(args[0], '/usr/bin/python3')
                self.assertEqual(args[1], ['/usr/bin/python3', '-I', '/opt/aifinance/bin/inspect-native.py'])
                self.assertEqual(args[2], {'PATH': '/usr/bin:/bin', 'HOME': '/var/lib/aifinance-deploy', 'LANG': 'C.UTF-8'})
        finally:
            os.umask(before)

    def test_upload_before_ready_is_data_only_and_deployment_still_refused(self):
        m = module('gateway_stage', 'ssh-gateway.py')
        content = b'fixed-public-fixture'
        sha, digest = 'a' * 40, hashlib.sha256(content).hexdigest()
        with tempfile.TemporaryDirectory() as d:
            m.ROOT = Path(d); (m.ROOT / 'incoming').mkdir(); (m.ROOT / 'shared').mkdir()
            before = os.umask(0o022)
            try:
                with patch.dict(os.environ, {'SSH_ORIGINAL_COMMAND': 'upload ' + sha + ' ' + digest}, clear=True), patch.object(m.sys, 'stdin', type('Input', (), {'buffer': io.BytesIO(content)})()), patch.object(m.os, 'execve') as execute, patch('sys.stdout', new_callable=io.StringIO):
                    m.main()
                    execute.assert_not_called()
                    self.assertEqual((m.ROOT / 'incoming' / (sha + '.tar.gz')).read_bytes(), content)
                for operation in ('deploy ' + sha + ' ' + digest, 'rollback ' + sha):
                    with patch.dict(os.environ, {'SSH_ORIGINAL_COMMAND': operation}, clear=True), patch.object(m.os, 'execve') as execute:
                        with self.assertRaises(ValueError): m.main()
                        execute.assert_not_called()
            finally:
                os.umask(before)

    def test_parsers_drop_urls_credentials_and_unapproved_fields(self):
        m = module('parse_inspect', 'inspect-native.py')
        secret = 'never-output-secret'
        modules = m.parse_modules('warning https://user:' + secret + '@host/\npostgresql 16 [e] server [d] ' + secret)
        packages = m.parse_packages('postgresql-server|16.8-1.al8|x86_64|alinux3-module\nPASSWORD=' + secret + '\npostgresql|10.1|x86_64|epel')
        units = m.parse_units('Id=aifinance-preview-api.service\nActiveState=active\nEnvironment=PASSWORD=' + secret + '\nExecStart=/etc/shadow\nMemoryMax=268435456')
        text = json.dumps([modules, packages, units])
        for bad in (secret, 'PASSWORD', 'Environment', 'ExecStart', 'https:', '/etc/shadow', 'epel'): self.assertNotIn(bad, text)
        self.assertEqual(modules[0]['stream'], '16')
        self.assertEqual(len(packages), 1)

    def test_symlinks_never_followed_or_read(self):
        m = module('paths_inspect', 'inspect-native.py')
        with tempfile.TemporaryDirectory() as d:
            base = Path(d); secret = base / 'secret'; secret.write_text('never-output-secret')
            link = base / 'link'; link.symlink_to(secret)
            with self.assertRaises(OSError): m.safe_read(link)
            parent = base / 'parent'; parent.symlink_to(base, target_is_directory=True)
            with self.assertRaises(ValueError): m.safe_read(parent / 'secret')
            m.ROOT = base / 'root'; m.ROOT.mkdir(); (m.ROOT / 'shared').mkdir(); (m.ROOT / 'state').mkdir()
            (m.ROOT / 'shared/native-ready').symlink_to(secret)
            (m.ROOT / 'state/current').symlink_to(secret)
            result = m.deployment()
            self.assertEqual(result['native-ready'], 'unexpected_type_or_owner')
            self.assertEqual(result['current_sha'], 'unexpected_target')
            self.assertNotIn('never-output-secret', json.dumps(result))

    def test_output_cap_timeout_no_stderr_or_environment_leak(self):
        m = module('bounded_inspect', 'inspect-native.py')
        with tempfile.TemporaryDirectory() as d:
            with patch.dict(os.environ, {'PRIVATE_TOKEN': 'never-output-secret'}):
                result = m.bounded([sys.executable, '-c', 'import os,sys; print(os.getenv("PRIVATE_TOKEN", "clean")); print("stderr-secret",file=sys.stderr)'], time.monotonic()+3, d)
            self.assertEqual(result, {'status': 'ok', 'text': 'clean\n'})
            result = m.bounded([sys.executable, '-c', 'import os; print(os.getcwd()); print(os.getenv("HOME"))'], time.monotonic()+3, d)
            self.assertEqual(result['text'], '/\n/\n')
            result = m.bounded([sys.executable, '-c', 'print("private"*100000)'], time.monotonic()+3, d)
            self.assertEqual(result, {'status': 'unavailable', 'reason': 'output_limit'})
            result = m.bounded([sys.executable, '-c', 'import time; time.sleep(3)'], time.monotonic()+0.05, d)
            self.assertEqual(result['reason'], 'timeout')
            self.assertNotIn('text', result)
            result = m.bounded(['/missing/command'], time.monotonic()-1, d)
            self.assertEqual(result['reason'], 'total_timeout')

    def test_config_ownership_and_fixed_dnf_config(self):
        m = module('config_inspect', 'inspect-native.py')
        with patch.object(Path, 'exists', return_value=True), patch.object(m, 'trusted_system_path', side_effect=ValueError):
            self.assertFalse(m.dnf_config_trusted())
        seen = []
        def record(args, deadline, temp):
            if args[0] == '/usr/bin/dnf':
                self.assertNotIn('--config=/dev/null', args)
                self.assertIn('--noplugins', args)
                self.assertIn('--setopt=reposdir=/etc/yum.repos.d', args)
                self.assertIn('--setopt=varsdir=/etc/dnf/vars,/etc/yum/vars', args)
                self.assertIn('--setopt=cachedir=/var/cache/dnf', args)
                seen.append(args)
            return {'status':'unavailable','reason':'fixture'}
        with patch.object(m, 'trusted_system_path'), patch.object(m, 'dnf_config_trusted', return_value=True), patch.object(m, 'bounded', side_effect=record):
            m.inspect()
        self.assertEqual(len(seen),2)

    def test_missing_privilege_cache_no_fallback_and_no_args(self):
        m = module('missing_inspect', 'inspect-native.py')
        seen = []
        def unavailable(args, *rest):
            seen.append(args)
            return {'status': 'unavailable', 'reason': 'permission_cache_or_command_failure'}
        with patch.object(m, 'safe_read', side_effect=PermissionError), patch.object(m, 'bounded', side_effect=unavailable), patch.object(m, 'deployment', return_value={'status': 'unavailable'}):
            out = m.inspect()
        self.assertEqual(out['modules']['status'], 'unavailable')
        for args in seen:
            self.assertNotIn('sudo', args)
            self.assertNotIn('journalctl', args)
            if args[0] == '/usr/bin/dnf':
                self.assertIn('-C', args); self.assertIn('--noplugins', args)
                self.assertFalse(any(x in args for x in ('install', 'enable', 'reset', 'switch-to', 'makecache')))
        with patch.object(sys, 'argv', ['inspect', 'arbitrary']), patch.object(m, 'inspect', side_effect=AssertionError):
            with self.assertRaises(SystemExit): m.main()
        with patch.object(sys, 'argv', ['inspect']), patch.object(m, 'inspect', return_value={'test': 'x'*70000}):
            with self.assertRaises(SystemExit): m.main()

    def test_one_time_update_preserves_backup_and_refuses_unknown_or_repeated_state(self):
        m = module('update_inspect_test', 'update-inspect.py')
        actual_lstat = Path.lstat
        def rootstat(p):
            data = list(actual_lstat(p)); data[4] = 0
            if p.is_dir() and p not in (m.BIN, m.SOURCE): data[0] &= ~0o022
            return os.stat_result(data)
        with tempfile.TemporaryDirectory() as d:
            base = Path(d); m.SOURCE = base / 'source'; m.SOURCE.mkdir(); m.BIN = base / 'bin'; m.BIN.mkdir()
            (m.SOURCE / 'ssh-gateway.py').write_bytes(b'reviewed-gateway')
            (m.SOURCE / 'inspect-native.py').write_bytes(b'reviewed-inspector')
            (m.BIN / 'ssh-gateway.py').write_bytes(b'old-gateway')
            m.OLD_GATEWAY = hashlib.sha256(b'old-gateway').hexdigest()
            g = m.sha(m.SOURCE / 'ssh-gateway.py'); i = m.sha(m.SOURCE / 'inspect-native.py')
            with patch.object(m.os, 'geteuid', return_value=0), patch.object(Path, 'lstat', rootstat):
                m.update(g,i)
                self.assertEqual(len(list(m.BIN.iterdir())),1)
                with self.assertRaises(ValueError): m.update('0'*64,i,True)
                self.assertEqual(len(list(m.BIN.iterdir())),1)
                m.update(g,i,True)
                self.assertEqual((m.BIN/'ssh-gateway.py.before-inspect-0d93245b.bak').read_bytes(),b'old-gateway')
                self.assertEqual((m.BIN/'ssh-gateway.py').read_bytes(),b'reviewed-gateway')
                with self.assertRaises(ValueError): m.update(g,i,True)
                m.restore(g,i)
                self.assertEqual((m.BIN/'ssh-gateway.py').read_bytes(),b'reviewed-gateway')
                m.restore(g,i,True)
                self.assertEqual((m.BIN/'ssh-gateway.py').read_bytes(),b'old-gateway')
                self.assertTrue((m.BIN/'inspect-native.py').exists())
                # Interrupted just before atomic replacement: old entry stays usable.
                (m.BIN/'inspect-native.py').unlink()
                (m.BIN/'ssh-gateway.py.before-inspect-0d93245b.bak').unlink()
                with patch.object(m.os, 'replace', side_effect=OSError('simulated interruption')):
                    with self.assertRaises(OSError): m.update(g,i,True)
                self.assertEqual((m.BIN/'ssh-gateway.py').read_bytes(),b'old-gateway')
                with self.assertRaises(ValueError): m.update(g,i,True)
                m.restore(g,i,True)
                (m.BIN/'ssh-gateway.py').write_bytes(b'unrecognized')
                with self.assertRaises(ValueError): m.restore(g,i,True)


if __name__ == '__main__': unittest.main()
