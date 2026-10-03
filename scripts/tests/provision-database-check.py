"""Local files and mocked subprocesses only: no server, accounts, PG, or real secrets."""
import ast
import contextlib
import getpass
import grp
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import pwd
import stat
import signal
import subprocess
import time
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('provision_database', str(ROOT / 'deploy/native/provision-database.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
SPEC = (ROOT / 'deploy/native/aifinance-preview-db.service').read_bytes()
ADMIN = 'test-only-admin-password'
FAKES = ('a' * 64, 'b' * 64, 'c' * 64)


class Fixture(object):
    def __init__(self, path):
        self.path = path
        self.source = path / 'inputs'
        self.source.mkdir()
        (self.source / m.UNIT_NAME).write_bytes(SPEC)
        (self.source / 'provision-database.py').write_bytes(b'reviewed fixture')
        self.parent = path / 'pgsql'
        self.parent.mkdir()
        self.config = path / 'etc/config'
        self.config.parent.mkdir()
        self.run = path / 'run'
        self.run.mkdir()
        self.units = path / 'units'
        self.units.mkdir()
        self.pg = path / 'vendor'
        self.pg.mkdir()
        (self.pg / 'bin').mkdir()
        (self.pg / 'lib').mkdir()
        (self.pg / 'share/extension').mkdir(parents=True)
        for name in ('postgres', 'psql', 'initdb'):
            (self.pg / 'bin' / name).write_bytes(b'not an executable')
        (self.pg / 'lib/pg_trgm.so').touch()
        (self.pg / 'share/extension/pg_trgm.control').touch()
        self.paths = {'SOURCE': self.source, 'PG': self.pg, 'DATA': self.parent / 'preview',
                      'CONFIG': self.config, 'SOCKET': self.run / 'socket',
                      'ENV_FILE': self.config.parent / 'preview.env', 'UNIT': self.units / m.UNIT_NAME}

    def scope(self):
        stack = contextlib.ExitStack()
        for name, value in self.paths.items():
            stack.enter_context(patch.object(m, name, value))
        stack.enter_context(patch.object(m.os, 'fchown'))
        stack.enter_context(patch.object(m.os, 'chown'))
        stack.enter_context(patch.object(m.secrets, 'token_hex', side_effect=FAKES))
        return stack

    def command(self, args, **kw):
        if args[0].endswith('/initdb') and '--version' not in args:
            # Fake initdb leaves data to prove failure/retry never deletes it.
            (m.DATA / 'PG_VERSION').write_text('17\n')
        if args == [m.SYSTEMCTL, 'show', m.UNIT_NAME, '-p', 'FragmentPath', '--value']:
            return str(m.UNIT)
        if kw.get('capture'):
            return ''


def snapshot(path):
    return {str(p.relative_to(path)): p.read_bytes() for p in path.rglob('*') if p.is_file()}


class DatabaseProvisionTests(unittest.TestCase):
    def test_python36_syntax(self):
        text = (ROOT / 'deploy/native/provision-database.py').read_text()
        # Runtime 3.6 run is still a separate target verification.
        if sys.version_info >= (3, 8):
            ast.parse(text, feature_version=(3, 6))
        else:
            ast.parse(text)

    def test_plan_is_pure_no_password_random_process_or_preflight(self):
        with patch.object(m, 'preflight', side_effect=AssertionError), \
                patch.object(m, 'administrator_password', side_effect=AssertionError), \
                patch.object(m.secrets, 'token_hex', side_effect=AssertionError), \
                patch.object(m, 'run', side_effect=AssertionError), contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main(['plan']), 0)
            result = json.loads(out.getvalue())
            self.assertFalse(result['ready_for_deploy'])
            self.assertTrue(result['requires_explicit_approval'])
            self.assertEqual(result['postgres_uid_gid'], 26)

    def test_default_check_never_prompts_generates_or_writes(self):
        with patch.object(m, 'preflight', return_value=1234) as check, \
                patch.object(m, 'administrator_password', side_effect=AssertionError), \
                patch.object(m.secrets, 'token_hex', side_effect=AssertionError), \
                patch.object(m, 'initialize', side_effect=AssertionError), \
                patch.object(m.resource, 'setrlimit'), patch.object(m.os, 'umask'), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            m.main([])
            check.assert_called_once_with(None, None)
            self.assertFalse(json.loads(out.getvalue())['changed'])

    def test_existing_or_dangling_paths_refuse_without_generation_or_command(self):
        for key in ('DATA', 'CONFIG', 'SOCKET', 'ENV_FILE', 'UNIT'):
            for dangling in (False, True):
                with self.subTest(path=key, dangling=dangling), tempfile.TemporaryDirectory() as d:
                    f = Fixture(Path(d))
                    with f.scope(), patch.object(m, 'run', side_effect=AssertionError), \
                            patch.object(m.secrets, 'token_hex', side_effect=AssertionError):
                        target = getattr(m, key)
                        if dangling:
                            target.symlink_to(f.path / 'missing')
                        else:
                            target.write_bytes(b'preserve this')
                        before = snapshot(f.path)
                        with self.assertRaises(ValueError):
                            m.initialize(1234, ADMIN)
                        self.assertEqual(before, snapshot(f.path))
                        self.assertTrue(target.is_symlink() if dangling else target.exists())

    def test_fixed_configuration_hba_and_cgroup_v1_unit(self):
        conf = m.configuration()
        for text in ("listen_addresses = '127.0.0.1'", 'port = 55432', 'max_connections = 12',
                     "shared_buffers = '32MB'", "work_mem = '1MB'", "maintenance_work_mem = '16MB'",
                     "unix_socket_permissions = 0700", "password_encryption = 'scram-sha-256'",
                     "log_min_error_statement = 'panic'", "log_statement = 'none'",
                     'log_min_duration_statement = -1', 'log_min_duration_sample = -1',
                     'log_transaction_sample_rate = 0', 'log_parameter_max_length = 0',
                     'log_parameter_max_length_on_error = 0'):
            self.assertIn(text, conf)
        rows = m.HBA.splitlines()
        self.assertEqual(rows[:3], ['local all postgres peer', 'local all all reject',
                                   'host aifinance_preview aifinance_preview 127.0.0.1/32 scram-sha-256'])
        self.assertFalse(any('trust' in row or 'md5' in row for row in rows))
        unit = SPEC.decode()
        for text in ('User=postgres', 'Group=postgres', 'MemoryLimit=256M', 'MemoryAccounting=yes',
                     'RuntimeDirectoryMode=0700', 'CapabilityBoundingSet=', 'AmbientCapabilities=', 'Restart=no', 'LimitCORE=0', 'StandardOutput=null', 'StandardError=null',
                     'ExecStart=/usr/pgsql-17/bin/postgres -D /var/lib/pgsql/aifinance-preview',
                     'config_file=/etc/aifinance-preview-db/postgresql.conf', 'IPAddressDeny=any',
                     'IPAddressAllow=localhost', 'ProtectSystem=strict'):
            self.assertIn(text, unit)
        for bad in ('MemoryMax=', 'MemoryHigh=', 'EnvironmentFile=', '/17/data', 'postgresql-17.service', 'node ', 'sudo '):
            self.assertNotIn(bad, unit)

    def test_environment_matches_existing_launcher(self):
        text = m.environment(ADMIN, *FAKES)
        spec = importlib.util.spec_from_file_location('launcher_contract', str(ROOT / 'deploy/native/run-preview.py'))
        launcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(launcher)
        env = launcher.environment(text)
        self.assertEqual(env['ADMIN_PASSWORD'], ADMIN)
        self.assertEqual(env['DATABASE_POOL_MAX'], '3')
        self.assertEqual(env['MODEL_CALLS_ENABLED'], 'false')
        for bad in ('short', 'password\nwith-newline', 'has space password', 'unicode-password-好'):
            with self.assertRaises(ValueError):
                m.environment(bad, *FAKES)
        for bad in ('short', 'g' * 64, 'a' * 64 + "'\n"):
            with self.assertRaises(ValueError):
                m.environment(ADMIN, bad, FAKES[1], FAKES[2])

    def test_password_requires_tty_no_echo_fallback_or_argv(self):
        with patch.object(m.sys.stdin, 'isatty', return_value=False), \
                patch.object(m.getpass, 'getpass', side_effect=AssertionError):
            with self.assertRaises(ValueError):
                m.administrator_password()
        with patch.object(m.sys.stdin, 'isatty', return_value=True), patch.object(m.sys.stderr, 'isatty', return_value=True):
            with patch.object(m.getpass, 'getpass', side_effect=[ADMIN, ADMIN]):
                self.assertEqual(m.administrator_password(), ADMIN)
            with patch.object(m.getpass, 'getpass', side_effect=[ADMIN, 'mismatch']):
                with self.assertRaises(ValueError):
                    m.administrator_password()
            def warned(*args):
                m.warnings.warn('cannot disable echo', getpass.GetPassWarning)
                raise AssertionError('must not fall back')
            with patch.object(m.getpass, 'getpass', side_effect=warned):
                with self.assertRaises(getpass.GetPassWarning):
                    m.administrator_password()

    def test_process_boundary_clear_env_drop_uid_no_shell_and_suppressed_logs(self):
        completed = unittest.mock.Mock(returncode=0)
        completed.communicate.return_value = (b'1\n', None)
        with patch.dict(os.environ, {'PGPASSWORD': 'bad', 'LD_PRELOAD': 'bad', 'PYTHONPATH': 'bad', 'NODE_OPTIONS': 'bad'}), \
                patch.object(m.subprocess, 'Popen', return_value=completed) as process:
            self.assertEqual(m.psql('SELECT 1;\n', capture=True), '1')
        args, kw = process.call_args
        self.assertEqual(args[0][0], '/usr/pgsql-17/bin/psql')
        self.assertIn('--no-psqlrc', args[0])
        self.assertIn('--no-password', args[0])
        self.assertEqual(kw['env'], m.ENV)
        completed.communicate.assert_called_once_with(input=b'SELECT 1;\n', timeout=10)
        self.assertEqual(kw['stdin'], subprocess.PIPE)
        self.assertTrue(kw['start_new_session'])
        self.assertFalse(kw['shell'])
        self.assertIs(kw['preexec_fn'], m.as_postgres)
        self.assertEqual(kw['stderr'], subprocess.DEVNULL)
        with patch.object(m.os, 'setgroups') as groups, patch.object(m.os, 'setgid') as gid, \
                patch.object(m.os, 'setuid') as uid, patch.object(m.os, 'umask'):
            m.as_postgres()
            groups.assert_called_once_with([])
            gid.assert_called_once_with(26)
            uid.assert_called_once_with(26)

    def test_real_subprocess_stdin_and_python36_keywords(self):
        # Public fixture via a local Python child, never PostgreSQL or systemctl.
        args = [sys.executable, '-c', 'import sys; data=sys.stdin.buffer.read(); print(data.decode() if data else "empty")']
        self.assertEqual(m.run(args, data=b'public-fixture', capture=True), 'public-fixture')
        self.assertEqual(m.run(args, capture=True), 'empty')

    def test_timeout_kills_spawned_process_group_not_only_parent(self):
        with tempfile.TemporaryDirectory() as d:
            pidfile = Path(d) / 'child.pid'
            source = ('import subprocess,sys,time; '
                      'p=subprocess.Popen([sys.executable,"-c","import time; time.sleep(60)"]); '
                      'open(sys.argv[1],"w").write(str(p.pid)); time.sleep(60)')
            with self.assertRaises(subprocess.TimeoutExpired):
                m.run([sys.executable, '-c', source, str(pidfile)], timeout=0.3)
            self.assertTrue(pidfile.exists())
            status = Path('/proc') / pidfile.read_text() / 'status'
            for attempt in range(50):
                try:
                    exited = 'State:\tZ' in status.read_text()
                except (FileNotFoundError, ProcessLookupError):
                    exited = True  # Kernel may reap the process between observations.
                if exited:
                    break
                time.sleep(0.01)
            else:
                self.fail('bootstrap child remains running after parent timeout')

    def test_happy_path_only_new_db_unit_no_release_code(self):
        with tempfile.TemporaryDirectory() as d:
            f = Fixture(Path(d))
            with f.scope(), patch.object(m, 'run', side_effect=f.command) as run, \
                    patch.object(m, 'psql', side_effect=['1', None, None, 't', 't']) as sql:
                m.initialize(1234, ADMIN)
                self.assertEqual(m.ENV_FILE.read_text(), m.environment(ADMIN, *FAKES))
                self.assertEqual(stat.S_IMODE(m.ENV_FILE.stat().st_mode), 0o640)
                self.assertEqual(stat.S_IMODE(m.CONFIG.stat().st_mode), 0o750)
                self.assertEqual(stat.S_IMODE(m.DATA.stat().st_mode), 0o700)
                self.assertEqual(m.UNIT.read_bytes(), SPEC)
                commands = [call[0][0] for call in run.call_args_list]
                init = commands[0]
                self.assertEqual(init[0], str(m.PG / 'bin/initdb'))
                self.assertIn('--no-clean', init)
                self.assertIn('--auth-local=peer', init)
                self.assertIn('--auth-host=scram-sha-256', init)
                self.assertTrue(run.call_args_list[0][1]['postgres'])
                self.assertIn([m.SYSTEMCTL, 'start', m.UNIT_NAME], commands)
                self.assertNotIn([m.SYSTEMCTL, 'stop', m.UNIT_NAME], commands)
                self.assertNotIn('enable', repr(commands))
                for secret in (ADMIN,) + FAKES:
                    self.assertNotIn(secret, repr(run.call_args_list))
                self.assertIn("PASSWORD '" + FAKES[0] + "'", sql.call_args_list[1][0][0])
                self.assertIn('NOSUPERUSER', sql.call_args_list[1][0][0])
                self.assertIn('CREATE EXTENSION pg_trgm', sql.call_args_list[2][0][0])
                self.assertTrue(sql.call_args_list[4][0][0].startswith('\\connect \"postgresql://aifinance_preview:'))
                self.assertNotIn('native-ready', '\n'.join(snapshot(f.path)))
                self.assertNotIn('schema.sha256', '\n'.join(snapshot(f.path)))

    def test_failure_keeps_new_files_stops_only_new_unit_and_refuses_retry(self):
        for failure in ('initdb', 'start', 'sql', 'override'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as d:
                f = Fixture(Path(d))
                def command(args, **kw):
                    result = f.command(args, **kw)
                    if ((failure == 'initdb' and args[0].endswith('/initdb')) or
                            (failure == 'start' and args[1] == 'start')):
                        raise ValueError('fake failure')
                    if failure == 'override' and args[1:5] == ['show', m.UNIT_NAME, '-p', 'DropInPaths']:
                        return '/etc/systemd/system/service.d/unknown.conf'
                    return result
                with f.scope(), patch.object(m, 'run', side_effect=command) as run, \
                        patch.object(m, 'psql', side_effect=['1', ValueError('secret-bearing error never printed')]):
                    with self.assertRaises(ValueError):
                        m.initialize(1234, ADMIN)
                    self.assertEqual((m.DATA / 'PG_VERSION').read_text(), '17\n')
                    commands = [c[0][0] for c in run.call_args_list]
                    stops = [c for c in commands if len(c) > 1 and c[1] == 'stop']
                    self.assertEqual(stops, [] if failure == 'initdb' else [[m.SYSTEMCTL, 'stop', m.UNIT_NAME]])
                    if failure == 'override':
                        self.assertNotIn([m.SYSTEMCTL, 'start', m.UNIT_NAME], commands)
                    before = snapshot(f.path)
                    with self.assertRaises(ValueError):
                        m.initialize(1234, ADMIN)
                    self.assertEqual(snapshot(f.path), before)

    def test_hangup_and_terminate_after_start_stop_new_unit_preserve_files(self):
        for signum in (signal.SIGHUP, signal.SIGTERM):
            previous = signal.signal(signum, m.interrupted)
            try:
                with tempfile.TemporaryDirectory() as d:
                    f = Fixture(Path(d))
                    def receive_signal(*args, **kw):
                        os.kill(os.getpid(), signum)
                        raise AssertionError('signal was not converted to exception')
                    with f.scope(), patch.object(m, 'run', side_effect=f.command) as run, \
                            patch.object(m, 'psql', side_effect=receive_signal):
                        with self.assertRaises(InterruptedError):
                            m.initialize(1234, ADMIN)
                        self.assertEqual((m.DATA / 'PG_VERSION').read_text(), '17\n')
                        self.assertTrue(m.ENV_FILE.exists())
                        self.assertTrue(m.CONFIG.exists())
                        commands = [c[0][0] for c in run.call_args_list]
                        self.assertEqual(commands[-1], [m.SYSTEMCTL, 'stop', m.UNIT_NAME])
                        self.assertEqual(sum(c == [m.SYSTEMCTL, 'start', m.UNIT_NAME] for c in commands), 1)
            finally:
                signal.signal(signum, previous)

    def test_exclusive_write_preserves_existing_regular_and_symlink_targets(self):
        with tempfile.TemporaryDirectory() as d, patch.object(m.os, 'fchown') as owner:
            base = Path(d)
            target = base / 'env'
            m.write_new(target, b'fixed fixture', 0o640, 1234)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)
            self.assertEqual(owner.call_args[0][1:], (0, 1234))
            with self.assertRaises(OSError):
                m.write_new(target, b'replacement', 0o640, 1234)
            link = base / 'link'
            link.symlink_to(target)
            with self.assertRaises(OSError):
                m.write_new(link, b'replacement', 0o640, 1234)
            self.assertEqual(target.read_bytes(), b'fixed fixture')

    def test_protected_rejects_symlinks_wrong_owner_and_writable_ancestors(self):
        for invalid in ('symlink', 'owner', 'group-write'):
            def metadata(path):
                mode = stat.S_IFREG | 0o644 if path == Path('/root/trusted/script') else stat.S_IFDIR | 0o755
                uid = 0
                if path == Path('/root/trusted'):
                    if invalid == 'symlink': mode = stat.S_IFLNK | 0o777
                    elif invalid == 'owner': uid = 1000
                    else: mode |= 0o020
                return types.SimpleNamespace(st_mode=mode, st_uid=uid)
            with self.subTest(invalid=invalid), patch.object(Path, 'lstat', metadata):
                with self.assertRaises(ValueError):
                    m.protected(Path('/root/trusted/script'))

    def test_preflight_pins_version_existing_unit_port_and_fresh_path(self):
        for failure in (None, 'pin', 'version', 'unit', 'port', 'path'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as d:
                f = Fixture(Path(d))
                script_digest = hashlib.sha256((f.source / 'provision-database.py').read_bytes()).hexdigest()
                unit_digest = hashlib.sha256(SPEC).hexdigest()
                real_lstat = Path.lstat
                def metadata(path):
                    st = real_lstat(path)
                    if path == f.parent:
                        values = list(st)
                        values[4], values[5] = 26, 26
                        return os.stat_result(values)
                    return st
                def command(args, **kwargs):
                    if args[-1] == '--version':
                        return Path(args[0]).name + ' (PostgreSQL) ' + ('16.1' if failure == 'version' else '17.11')
                    return 'loaded' if failure == 'unit' else 'not-found'
                with f.scope(), patch.object(m, '__file__', str(f.source / 'provision-database.py')), \
                        patch.object(m, 'protected'), patch.object(m, 'accounts', return_value=1234), \
                        patch.object(m.os, 'getuid', return_value=0), patch.object(m.os, 'geteuid', return_value=0), \
                        patch.object(m.os, 'getegid', return_value=0), patch.object(Path, 'lstat', metadata), \
                        patch.object(m, 'run', side_effect=command), patch.object(m.socket, 'socket') as sock, \
                        patch.object(m.os, 'statvfs', return_value=types.SimpleNamespace(f_bavail=2048, f_frsize=1048576)), \
                        patch.object(m.secrets, 'token_hex', side_effect=AssertionError):
                    if failure == 'pin': unit_digest = '0' * 64
                    if failure == 'port': sock.return_value.__enter__.return_value.bind.side_effect = OSError('occupied')
                    if failure == 'path': m.DATA.mkdir()
                    before = snapshot(f.path)
                    if failure:
                        with self.assertRaises((ValueError, OSError)):
                            m.preflight(script_digest, unit_digest)
                    else:
                        self.assertEqual(m.preflight(script_digest, unit_digest), 1234)
                    self.assertEqual(before, snapshot(f.path))

    def test_apply_rechecks_after_hidden_prompt_and_does_not_print_secrets(self):
        with patch.object(m, 'preflight', return_value=1234) as check, \
                patch.object(m, 'administrator_password', return_value=ADMIN), \
                patch.object(m, 'initialize') as initialize, patch.object(m.resource, 'setrlimit'), \
                patch.object(m.signal, 'signal'), \
                patch.object(m.os, 'umask'), contextlib.redirect_stdout(io.StringIO()) as output:
            m.main(['apply', '--script-sha256', 'a' * 64, '--unit-sha256', 'b' * 64])
            self.assertEqual(check.call_count, 2)
            initialize.assert_called_once_with(1234, ADMIN)
            self.assertNotIn(ADMIN, output.getvalue())
            result = json.loads(output.getvalue())
            self.assertTrue(result['changed'])
            self.assertFalse(result['ready_for_deploy'])
            self.assertFalse(result['schema_migrated'])

    def test_account_contract_existing_postgres_26_and_distinct_app(self):
        users = {'postgres': types.SimpleNamespace(pw_uid=26, pw_gid=26, pw_name='postgres'),
                 'aifinance': types.SimpleNamespace(pw_uid=1234, pw_gid=1234, pw_name='aifinance')}
        groups = {'postgres': types.SimpleNamespace(gr_gid=26, gr_name='postgres'),
                  'aifinance': types.SimpleNamespace(gr_gid=1234, gr_name='aifinance')}
        with patch.object(m.pwd, 'getpwnam', side_effect=users.__getitem__), \
                patch.object(m.grp, 'getgrnam', side_effect=groups.__getitem__), \
                patch.object(m.pwd, 'getpwuid', return_value=users['postgres']), \
                patch.object(m.grp, 'getgrgid', return_value=groups['postgres']):
            self.assertEqual(m.accounts(), 1234)
            users['postgres'].pw_uid = 27
            with self.assertRaises(ValueError):
                m.accounts()


if __name__ == '__main__':
    unittest.main()
