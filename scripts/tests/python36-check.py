"""Run in official Python 3.6.8 with networking disabled; never provision real accounts."""
import ast
import base64
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, str(ROOT / 'deploy/native' / filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class AccessCompatibility(unittest.TestCase):
    def test_all_native_python_syntax(self):
        for source in (ROOT / 'deploy/native').glob('*.py'):
            ast.parse(source.read_text())

    def test_bootstrap_preflight_real_subprocess_keyword_compatibility(self):
        boot = module('bootstrap_preflight', 'bootstrap-access.py')
        real_run, real_output, real_stat = subprocess.run, subprocess.check_output, Path.stat
        calls = []
        settings = 'permituserenvironment no\nforcecommand none\nauthorizedkeysfile .ssh/authorized_keys\nacceptenv LANG LC_*'
        def run(args, **kwargs):
            calls.append(args)
            self.assertEqual(args[0], '/usr/bin/systemctl')
            return real_run([sys.executable, '-c', 'print("not-found")'], **kwargs)
        def output(args, **kwargs):
            self.assertIn('-T', args)
            self.assertEqual(args[-2:], ['-C', 'user=aifinance-deploy,host=localhost,addr=127.0.0.1'])
            with patch.object(subprocess, 'run', real_run):
                return real_output([sys.executable, '-c', 'print(' + repr(settings) + ')'], **kwargs)
        def root_stat(p, *args, **kwargs):
            data = list(real_stat(p, *args, **kwargs))
            data[4] = 0
            return os.stat_result(data)
        with tempfile.TemporaryDirectory() as d:
            boot.ROOT, boot.HOME, boot.SUDO = [Path(d) / n for n in ('root', 'home', 'sudo')]
            with patch.object(boot.pwd, 'getpwnam', side_effect=KeyError), patch.object(boot.grp, 'getgrnam', side_effect=KeyError), patch.object(boot.shutil, 'which', side_effect=lambda x: '/usr/bin/' + x), patch.object(boot.subprocess, 'run', side_effect=run), patch.object(boot.subprocess, 'check_output', side_effect=output), patch.object(Path, 'stat', root_stat):
                boot.preflight(ROOT / 'deploy/native')
                self.assertEqual(len(calls), 2)
                base = 'permituserenvironment no\nforcecommand none\nauthorizedkeysfile .ssh/authorized_keys\n'
                actual = ('LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES '
                          'LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT LC_IDENTIFICATION '
                          'LC_ALL LANGUAGE XMODIFIERS').split()
                settings = base + '\n'.join('acceptenv ' + name for name in actual)
                boot.preflight(ROOT / 'deploy/native')
                for bad in ('PYTHONPATH', 'PYTHONHOME', 'LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_*',
                            'BASH_ENV', 'ENV', 'PATH', '*', 'L*', '*PATH', 'PYTHON*', '?NV',
                            'LANG*', 'XMODIFIERS*', 'LC_UNKNOWN', 'LOCPATH', 'GCONV_PATH'):
                    settings = base + 'acceptenv LANG ' + bad
                    with self.subTest(acceptenv=bad), self.assertRaises(ValueError):
                        boot.preflight(ROOT / 'deploy/native')
                settings = base.replace('permituserenvironment no', 'permituserenvironment yes') + 'acceptenv LANG'
                with self.assertRaises(ValueError):
                    boot.preflight(ROOT / 'deploy/native')
                settings = base.replace('forcecommand none', 'forcecommand internal-sftp') + 'acceptenv LANG'
                with self.assertRaises(ValueError):
                    boot.preflight(ROOT / 'deploy/native')
                previous_calls = len(calls)
                boot.ROOT.mkdir()
                with self.assertRaises(ValueError):
                    boot.preflight(ROOT / 'deploy/native')
                self.assertEqual(len(calls), previous_calls)

    def test_gateway_drops_client_locale_before_release(self):
        gate = module('gateway_locale', 'ssh-gateway.py')
        with tempfile.TemporaryDirectory() as d:
            gate.ROOT = Path(d)
            (gate.ROOT / 'shared').mkdir()
            (gate.ROOT / 'shared/native-ready').touch()
            client = {'SSH_ORIGINAL_COMMAND': 'rollback ' + 'a' * 40,
                      'LANG': 'invalid-locale', 'LC_ALL': 'invalid-locale',
                      'LANGUAGE': 'caller-choice', 'XMODIFIERS': '@im=caller-choice'}
            previous = os.umask(0o022)
            try:
                with patch.dict(os.environ, client, clear=True), patch.object(gate.os, 'execve') as execute:
                    gate.main()
                    self.assertEqual(execute.call_args[0][2], {
                        'PATH': '/usr/bin:/bin', 'HOME': '/var/lib/aifinance-deploy', 'LANG': 'C.UTF-8'})
            finally:
                os.umask(previous)

    def test_bootstrap_check_only_cannot_provision(self):
        boot = module('bootstrap_check', 'bootstrap-access.py')
        raw = struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32) + bytes(32)
        key = 'ssh-ed25519 ' + base64.b64encode(raw).decode()
        with tempfile.TemporaryDirectory() as d:
            public = Path(d) / 'fixture.pub'
            public.write_text(key)
            with patch.object(sys, 'argv', ['bootstrap', '--public-key', str(public)]), patch.object(boot.os, 'geteuid', return_value=0), patch.object(boot, 'preflight') as preflight, patch.object(boot, 'provision', side_effect=AssertionError('must not provision')), patch.object(boot.subprocess, 'run') as run, patch.object(boot.shutil, 'which', return_value='/usr/sbin/visudo'):
                previous = os.umask(0o022)
                try:
                    boot.main()
                finally:
                    os.umask(previous)
                self.assertEqual(preflight.call_count, 1)
                self.assertEqual(run.call_count, 1)
                self.assertEqual(run.call_args[0][0][0:3], ['/usr/sbin/visudo', '-c', '-f'])
        self.assertTrue(boot.authorized_key(boot.public_key(key)).startswith('restrict,command='))
        with self.assertRaises(ValueError):
            boot.public_key(key + '\n' + key)

    def test_gateway_paths_upload_and_limits(self):
        gate = module('gateway36', 'ssh-gateway.py')
        self.assertEqual(gate.parse('verify'), ['verify'])
        for bad in ('sh', 'verify;id', 'internal-sftp', 'verify\n'):
            with self.assertRaises(ValueError):
                gate.parse(bad)
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'incoming').mkdir()
            sha, data = 'a' * 40, b'archive'
            digest = hashlib.sha256(data).hexdigest()
            gate.upload(root, sha, digest, io.BytesIO(data))
            self.assertEqual((root / 'incoming' / (sha + '.tar.gz')).read_bytes(), data)
            with self.assertRaises(ValueError):
                gate.upload(root, sha, digest, io.BytesIO(data))
            gate.LIMIT = 4
            with self.assertRaises(ValueError):
                gate.upload(root, 'b' * 40, digest, io.BytesIO(data))
            self.assertEqual(list((root / 'incoming').glob('.upload-*')), [])

    def test_launcher_environment_and_exec_boundary(self):
        app = module('launcher36', 'run-preview.py')
        text = 'DATABASE_URL=postgres://aifinance_preview:local@127.0.0.1:55432/aifinance_preview\nSITE_URL=https://preview.example.com\nADMIN_PASSWORD=' + 'a' * 16 + '\nSESSION_SECRET=' + 'b' * 32 + '\nIMG_PROXY_SIGN_SECRET=' + 'c' * 32
        self.assertEqual(app.environment(text)['MODEL_CALLS_ENABLED'], 'false')
        with self.assertRaises(ValueError):
            app.environment(text + '\nLLM_API_KEY=not-real')
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            release = base / 'releases' / ('a' * 40)
            release.mkdir(parents=True)
            (release / 'RELEASE_SHA').write_text('a' * 40)
            (base / 'state').mkdir()
            (base / 'state/current').symlink_to(release)
            (base / 'env').write_text(text)
            def location(value):
                return base / 'env' if value == '/etc/aifinance-preview.env' else base / value.replace('/opt/aifinance/', '')
            previous = os.getcwd()
            try:
                with patch.object(app, 'Path', side_effect=location), patch.object(sys, 'argv', ['launcher', 'web']), patch.object(app.os, 'execve') as execute:
                    app.main()
                    env = execute.call_args[0][2]
                    self.assertNotIn('SESSION_SECRET', env)
                    self.assertNotIn('DATABASE_URL', env)
                    self.assertEqual(env['AIHOT_RELEASE'], 'a' * 40)
                    self.assertEqual(execute.call_args[0][0], '/opt/aifinance/runtime/node/bin/node')
                    self.assertEqual(execute.call_args[0][1], [app.NODE, '--max-old-space-size=128', 'apps/web/server.ts'])
            finally:
                os.chdir(previous)

    def test_release_standalone_python_extract_and_reject(self):
        script = (ROOT / 'deploy/native/release.sh').read_text()
        self.assertIn('python3 "$script_dir/extract-release.py" "$archive" "$stage"', script)
        extractor = ROOT / 'deploy/native/extract-release.py'
        ast.parse(extractor.read_text())
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            archive = base / 'release.tar.gz'
            for name, expected in [('safe.txt', 0), ('../escape', 1)]:
                stage = base / ('stage-' + str(expected))
                stage.mkdir(mode=0o700)
                with tarfile.open(str(archive), 'w:gz') as tf:
                    info = tarfile.TarInfo(name)
                    info.size = 4
                    tf.addfile(info, io.BytesIO(b'test'))
                result = subprocess.run([sys.executable, '-B', str(extractor), str(archive), str(stage)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertEqual(stage.stat().st_mode & 0o7777, 0o755 if expected == 0 else 0o700)
            self.assertFalse((base / 'escape').exists())
            self.assertEqual((base / 'stage-0/safe.txt').read_bytes(), b'test')


if __name__ == '__main__':
    print('Runtime:', sys.version, flush=True)
    unittest.main()
