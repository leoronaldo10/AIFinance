#!/usr/bin/python3
"""Offline installer adversarial/fault fixtures. No host units, nft, DB or sudo."""
import ast
import base64
from contextlib import ExitStack
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

REPO = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('install_ops', str(REPO / 'deploy/native/install-ops.py'))
m = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(m)
VERIFY_ACCESS = m.verify_access


def probe_receipt():
    return {'mode': 'probe', 'elapsed_seconds': 30.1, 'output': {}, 'samples': [{
        'properties': {'User': 'aifinance-collect', 'MainPID': '123', 'MemoryAccounting': 'yes',
                       'MemoryLimit': str(256 * 1024 ** 2), 'TasksMax': '32', 'TimeoutStartUSec': '2min'},
        'kernel': {'uid': 990, 'pid': 123, 'cgroup': '/system.slice/aifinance-collect-probe.service',
                   'memory.limit_in_bytes': 256 * 1024 ** 2, 'memory.usage_in_bytes': 2000,
                   'memory.max_usage_in_bytes': 3000, 'memory.failcnt': 0, 'pids.max': 32, 'pids.current': 1},
        'resolver': None}]}


class Fixture:
    def __enter__(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ops-install-fixture-')
        self.root = Path(self.temp.name)
        self.stack = ExitStack()
        self.meta = {}
        self.real_lstat = Path.lstat
        self.real_fstat = os.fstat
        mapping = {'ROOT': 'app', 'BIN': 'app/bin', 'STATE': 'var/lib/ops', 'COLLECT': 'var/lib/maintenance/collect-only',
                   'CONFIG': 'etc/collect', 'SUDO_DIR': 'etc/sudoers.d', 'SUDO_OLD': 'etc/sudoers.d/aifinance-preview',
                   'SUDO_NEW': 'etc/sudoers.d/aifinance-ops-v1', 'SUDO_NEXT': 'etc/sudoers.d/.ops.ops-v1.next',
                   'BROKER': 'app/bin/ops-broker.py', 'GATEWAY': 'app/bin/ssh-gateway.py', 'GATEWAY_NEXT': 'app/bin/.gateway.ops-v1.next',
                   'RUNNER_PATH': 'app/bin/collect-only-runner.py', 'RUNNER_NEXT': 'app/bin/.collect-only-runner.py.ops-v1.next',
                   'SYSTEM': 'etc/systemd/system'}
        for key, name in mapping.items():
            self.stack.enter_context(patch.object(m, key, self.root / name))
        for path in (m.BIN, m.ROOT / 'state', m.STATE.parent, m.COLLECT, m.CONFIG, m.SUDO_DIR, m.SYSTEM):
            path.mkdir(parents=True, exist_ok=True); path.chmod(0o755)
        m.COLLECT.chmod(0o700); m.CONFIG.chmod(0o750); m.SUDO_DIR.chmod(0o750)
        self.source = self.root / 'source'; self.source.mkdir(mode=0o700)
        self.stack.enter_context(patch.object(m, 'SOURCE_PATTERN', str(self.source)))
        self.stack.enter_context(patch.object(m, 'UNIT_DIRS', (self.root / 'etc/systemd/system', self.root / 'run/systemd/system')))
        # Only metadata views are mocked; O_NOFOLLOW/O_EXCL, hardlinks, locking,
        # writes, fsync, and final atomic replacement use the fixture filesystem.
        self.stack.enter_context(patch.object(m.Path, 'lstat', lambda path: self.lstat(path)))
        self.stack.enter_context(patch.object(m.os, 'fstat', self.fstat))
        self.stack.enter_context(patch.object(m.os, 'fchown'))
        self.stack.enter_context(patch.object(m.subprocess, 'run', side_effect=AssertionError('no real external commands in fixture')))
        self.validator = self.stack.enter_context(patch.object(m, 'validate_sudo'))
        self.access = self.stack.enter_context(patch.object(m, 'verify_access'))
        self.reload = self.stack.enter_context(patch.object(m, 'reload_units'))
        self.contents = {'install-ops.py': b'# installer\n', 'ops-broker.py': b'# broker\n', 'ops-gateway.py': b'# gateway ops-v1\n',
                         'collect-only-runner.py': b'# reviewed replacement runner\n'}
        self.manifest = dict(schema=1, installer_sha256=m.sha(self.contents['install-ops.py']),
                             broker_sha256=m.sha(self.contents['ops-broker.py']), gateway_sha256=m.sha(self.contents['ops-gateway.py']),
                             runner_sha256=m.sha(self.contents['collect-only-runner.py']))
        for name, content in self.contents.items():
            self.put(self.source / name, content)
        self.set_manifest(self.manifest)
        self.old = b'# reviewed old gateway\n'
        self.old_runner = b'# reviewed old runner\n'
        self.stack.enter_context(patch.object(m, 'OLD_GATEWAY', m.sha(self.old)))
        self.stack.enter_context(patch.object(m, 'OLD_RUNNER', m.sha(self.old_runner)))
        self.stack.enter_context(patch.object(m, 'NEW_RUNNER', m.sha(self.contents['collect-only-runner.py'])))
        self.put(m.GATEWAY, self.old, 0o755)
        self.put(m.RUNNER_PATH, self.old_runner, 0o755)
        self.put(m.SUDO_OLD, m.OLD_RULE, 0o440)
        self.put(m.ROOT / 'state/release.lock', b'preserve lock inode and contents', 0o644)
        self.put(m.CONFIG / 'database.env', b'DATABASE_URL=fixture-secret-do-not-print\n', 0o400)
        self.put(m.CONFIG / 'hosts', b'', 0o440)
        self.put(m.CONFIG / 'nsswitch.conf', b'hosts: files\n', 0o440)
        self.metadata(m.CONFIG, st_gid=990)
        for name in ('hosts', 'nsswitch.conf'):
            self.metadata(m.CONFIG / name, st_gid=990)
        for name, value in [('network.json', {'uid': 990, 'hosts': {}}), ('installed.json', {'uid': 990, 'release': m.APP}),
                            ('seed-attempt.json', {'release': m.APP, 'mode': 'seed', 'started': 42}),
                            ('probe.json', probe_receipt())]:
            self.put(m.COLLECT / name, json.dumps(value).encode())
        self.owner = SimpleNamespace(pw_uid=985, pw_gid=985)
        self.metadata(m.ROOT / 'state/release.lock', st_uid=985, st_gid=985)
        self.stack.enter_context(patch.object(m.pwd, 'getpwnam', return_value=self.owner))
        self.runner = SimpleNamespace(upgrade_gate=Mock(), validate_release=Mock(), account=Mock(return_value=SimpleNamespace(pw_uid=990, pw_gid=990)),
            database_url=Mock(), verify_units=Mock(), verify_network=Mock(), no_processes=Mock(),
            unit_name=lambda mode: 'aifinance-collect-' + mode + '.service', prop=Mock(side_effect=self.prop),
            unit_text=lambda mode: '[Unit]\nDescription=Fixture ' + mode + '\nRequires=aifinance-preview-db.service\nAfter=aifinance-preview-db.service\n[Service]\nExecStart=/usr/bin/true\n',
            release_lock=lambda: os.open(str(m.ROOT / 'state/release.lock'), os.O_RDONLY | os.O_NOFOLLOW))
        self.replacement = SimpleNamespace(unit_text=lambda mode: self.runner.unit_text(mode).replace('Requires=', 'Requisite='), verify_units=Mock())
        for mode in ('probe', 'check', 'seed', 'run'):
            self.put(m.SYSTEM / self.runner.unit_name(mode), self.runner.unit_text(mode).encode(), 0o644)
        return self

    def __exit__(self, *args):
        self.stack.close(); self.temp.cleanup()

    def metadata(self, path, **fields):
        st = self.real_lstat(path)
        self.meta[(st.st_dev, st.st_ino)] = fields

    def info(self, st, path=None):
        values = {name: getattr(st, name) for name in dir(st) if name.startswith('st_')}
        values.update(st_uid=0, st_gid=0)
        # The temporary fixture lives beneath /tmp, whose host permissions are
        # irrelevant to this simulated root-only installation tree.
        if path == Path('/tmp'):
            values['st_mode'] = stat.S_IFDIR | 0o755
        values.update(self.meta.get((st.st_dev, st.st_ino), {}))
        return SimpleNamespace(**values)

    def lstat(self, path):
        return self.info(self.real_lstat(path), path)

    def fstat(self, fd):
        return self.info(self.real_fstat(fd))

    def put(self, path, content, mode=0o600):
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists(): path.chmod(0o600)
        path.write_bytes(content); path.chmod(mode)

    def set_manifest(self, value):
        raw = json.dumps(value).encode()
        self.put(self.source / 'manifest.json', raw)
        self.pin = m.sha(raw)

    def prop(self, unit, name):
        if 'hourly' in unit:
            return {'LoadState': 'not-found', 'FragmentPath': '', 'DropInPaths': '', 'MainPID': '0'}[name]
        if name == 'ActiveState': return 'failed' if '-check.' in unit else 'inactive'
        if name == 'SubState': return 'failed' if '-check.' in unit else 'dead'
        if '-check.' in unit and name == 'ExecMainCode': return '2'
        if '-check.' in unit and name == 'ExecMainStatus': return '15'
        if '-check.' in unit and name == 'ExecMainStartTimestampMonotonic': return '10'
        if '-check.' in unit and name == 'ExecMainExitTimestampMonotonic': return '20'
        return '0'


class InstallerTests(unittest.TestCase):
    def test_python36_syntax_and_fixed_pins(self):
        source = (REPO / 'deploy/native/install-ops.py').read_text()
        ast.parse(source, **({'feature_version': (3, 6)} if sys.version_info >= (3, 8) else {}))
        self.assertEqual(m.OLD_RUNNER, 'ebc68aa6e7b3512e52735ab4114a81035c3da2f71a385d5192bb8e7825d9501d')
        self.assertEqual(m.NEW_RUNNER, m.sha((REPO / 'deploy/native/collect-only-runner.py').read_bytes()))
        self.assertEqual(m.UPGRADE, m.sha((REPO / 'deploy/native/collect-only-upgrade.py').read_bytes()))
        self.assertNotIn('shutil', source)

    def test_exact_sudo_arguments_no_arbitrary_execution(self):
        lines = m.sudo_rules().decode().splitlines()
        self.assertEqual(len(lines), 8)
        for action, line in zip(m.ACTIONS, lines):
            expected = 'aifinance-deploy ALL=(root) NOPASSWD: NOSETENV: /usr/bin/python3 -I -B /opt/aifinance/bin/ops-broker.py ' + action
            if action == 'enable-hourly': expected += ' --accept-admin-view'
            self.assertEqual(line, expected)
            for token in ('*', '?', '/bin/sh', '/bin/bash', 'install-ops.py', 'SETENV: '):
                if token == 'SETENV: ': self.assertNotIn(' NOPASSWD: SETENV:', line)
                else: self.assertNotIn(token, line)

    def test_visudo_exact_bounded_command_and_no_host_execution(self):
        with patch.object(m, 'trusted_executable') as trust, patch.object(m.subprocess, 'run') as run:
            m.validate_sudo(Path('/fixture/sudo-fragment'))
        trust.assert_called_once_with('/usr/sbin/visudo')
        self.assertEqual(run.call_args[0][0], ['/usr/sbin/visudo', '-c', '-f', '/fixture/sudo-fragment'])
        self.assertEqual(run.call_args[1]['timeout'], 10)
        self.assertEqual(run.call_args[1]['env'], m.ENV)
        self.assertIs(run.call_args[1]['check'], True)

    def test_reload_only_reloads_manager_and_never_starts_a_unit(self):
        with patch.object(m, 'trusted_executable'), patch.object(m.subprocess, 'run') as run:
            m.reload_units()
        self.assertEqual(run.call_args[0][0], ['/usr/bin/systemctl', 'daemon-reload'])
        self.assertEqual(run.call_args[1]['timeout'], 20)

    def test_only_database_requires_to_requisite_template_change_is_allowed(self):
        with Fixture() as f:
            old, new = m.replacement_units(f.runner, f.replacement)
            self.assertEqual(len(old), 4); self.assertEqual(len(new), 4)
            f.replacement.unit_text = lambda mode: f.runner.unit_text(mode).replace('Requires=', 'Requisite=') + 'Environment=UNREVIEWED=1\n'
            with self.assertRaisesRegex(ValueError, 'only_collector_database'): m.replacement_units(f.runner, f.replacement)
        with Fixture() as f:
            path = m.SYSTEM / f.runner.unit_name('run')
            f.put(path, b'[Unit]\nRequires=unreviewed.service\n', 0o644)
            with self.assertRaisesRegex(ValueError, 'original_collector_unit'): m.replacement_units(f.runner, f.replacement)
        with Fixture() as f:
            f.put(m.unit_stage(f.runner.unit_name('check')), b'unknown', 0o644)
            with self.assertRaisesRegex(ValueError, 'existing_or_partial'): m.replacement_units(f.runner, f.replacement)

    def test_access_capture_is_stream_bounded_and_kills_slow_child(self):
        # Harmless local Python children only; no host service or network tools.
        with patch.object(m, 'trusted_executable'):
            self.assertEqual(m.access_output([sys.executable, '-I', '-c', 'print("fixture")']), 'fixture\n')
            with self.assertRaisesRegex(ValueError, 'size_limit'):
                m.access_output([sys.executable, '-I', '-c', 'print("x" * 40000)'])
            with patch.object(m, 'ACCESS_TIMEOUT', .05):
                with self.assertRaisesRegex(ValueError, 'timeout'):
                    m.access_output([sys.executable, '-I', '-c', 'import time; time.sleep(5)'])

    def test_terminal_root_cannot_be_invoked_from_deploy_or_pipe(self):
        with patch.object(m.os, 'getuid', return_value=1000), patch.object(m.os, 'geteuid', return_value=1000):
            with self.assertRaisesRegex(ValueError, 'root_terminal'): m.terminal_root()
        flags = SimpleNamespace(isolated=1)
        with patch.object(m.os, 'getuid', return_value=0), patch.object(m.os, 'geteuid', return_value=0), \
                patch.object(m.sys, 'flags', flags), patch.object(m.sys, 'dont_write_bytecode', True), \
                patch.object(m.os, 'isatty', return_value=False), patch.dict(m.os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, 'root_terminal'): m.terminal_root()
        with patch.object(m.os, 'getuid', return_value=0), patch.object(m.os, 'geteuid', return_value=0), \
                patch.object(m.sys, 'flags', flags), patch.object(m.sys, 'dont_write_bytecode', True), \
                patch.object(m.os, 'isatty', return_value=True), patch.dict(m.os.environ, {'SUDO_USER': 'aifinance-deploy'}, clear=True):
            with self.assertRaisesRegex(ValueError, 'root_terminal'): m.terminal_root()

    def test_access_boundary_rejects_unlocked_password_and_environment_injection(self):
        with Fixture() as f:
            home = f.root / 'deploy-home'; home.mkdir(mode=0o755); (home / '.ssh').mkdir(mode=0o755)
            header = m.struct.pack('>I', 11) + b'ssh-ed25519' + m.struct.pack('>I', 32)
            key = base64.b64encode(header + b'x' * 32).decode()
            raw = ('restrict,command="/usr/bin/python3 -I /opt/aifinance/bin/ssh-gateway.py" ssh-ed25519 ' + key + ' aifinance-actions\n').encode()
            f.put(home / '.ssh/authorized_keys', raw, 0o644)
            f.owner.pw_shell = '/bin/sh'; f.owner.pw_dir = str(home); f.owner.pw_name = 'aifinance-deploy'
            m.pwd.getpwnam.side_effect = lambda name: f.owner if name == 'aifinance-deploy' else SimpleNamespace(pw_uid=990)
            f.stack.enter_context(patch.object(m.pwd, 'getpwall', return_value=[f.owner]))
            f.stack.enter_context(patch.object(m.grp, 'getgrnam', return_value=SimpleNamespace(gr_gid=f.owner.pw_gid)))
            settings = 'permituserenvironment no\nforcecommand none\nauthorizedkeyscommand none\nauthorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2\nacceptenv LANG LC_*\n'
            with patch.object(m, 'DEPLOY_HOME', home), patch.object(m, 'access_output', side_effect=['aifinance-deploy LK 2026-01-01', settings]):
                VERIFY_ACCESS()
            for password, conf in [('aifinance-deploy PS 2026-01-01', settings), ('aifinance-deploy LK', settings.replace('LANG LC_*', 'LANG PYTHONPATH')),
                                   ('aifinance-deploy LK', settings.replace('forcecommand none', 'forcecommand /bin/sh')),
                                   ('aifinance-deploy LK', settings.replace('authorizedkeyscommand none', 'authorizedkeyscommand /arbitrary'))]:
                with patch.object(m, 'DEPLOY_HOME', home), patch.object(m, 'access_output', side_effect=[password, conf]):
                    with self.assertRaises(ValueError): VERIFY_ACCESS()
            f.put(home / '.ssh/authorized_keys', raw.replace(b'restrict,', b''), 0o644)
            with patch.object(m, 'DEPLOY_HOME', home), patch.object(m, 'access_output') as outputs:
                with self.assertRaisesRegex(ValueError, 'forced_key'): VERIFY_ACCESS()
                outputs.assert_not_called()

    def test_deploy_identity_requires_exclusive_uid_and_original_named_group(self):
        deploy = SimpleNamespace(pw_name='aifinance-deploy', pw_uid=985, pw_gid=984, pw_shell='/bin/sh', pw_dir=str(m.DEPLOY_HOME))
        users = {'aifinance-deploy': deploy, 'aifinance': SimpleNamespace(pw_uid=991),
                 'postgres': SimpleNamespace(pw_uid=992), 'aifinance-collect': SimpleNamespace(pw_uid=993)}
        group = SimpleNamespace(gr_gid=984)
        with patch.object(m.pwd, 'getpwnam', side_effect=lambda name: users[name]), \
                patch.object(m.pwd, 'getpwall', return_value=[deploy]) as accounts, \
                patch.object(m.grp, 'getgrnam', return_value=group):
            self.assertIs(m.deploy_account(), deploy)
            for uid in (0, 991, 992, 993):
                deploy.pw_uid = uid
                with self.assertRaisesRegex(ValueError, 'deploy_identity'): m.deploy_account()
            deploy.pw_uid = 985
            for alias in (SimpleNamespace(pw_name='alias', pw_uid=985), SimpleNamespace(pw_name='aifinance-deploy', pw_uid=997)):
                accounts.return_value = [deploy, alias]
                with self.assertRaisesRegex(ValueError, 'exclusive_deploy_uid'): m.deploy_account()
            accounts.return_value = [deploy]; group.gr_gid = 983
            with self.assertRaisesRegex(ValueError, 'deploy_identity'): m.deploy_account()

    def test_probe_receipt_requires_real_successful_kernel_budgets(self):
        probe = probe_receipt(); m.validate_probe(probe, 990)
        for field, value in [('uid', 985), ('pids.max', 9999), ('memory.failcnt', 1), ('pid', True), ('memory.usage_in_bytes', 256 * 1024 ** 2)]:
            changed = probe_receipt(); changed['samples'][0]['kernel'][field] = value
            with self.assertRaises(ValueError): m.validate_probe(changed, 990)
        for elapsed in (0, -1, 121, float('nan'), True):
            changed = probe_receipt(); changed['elapsed_seconds'] = elapsed
            with self.assertRaises(ValueError): m.validate_probe(changed, 990)
        with self.assertRaises(ValueError): m.validate_probe({'mode': 'probe', 'samples': [{}], 'output': {}}, 990)

    def test_check_is_read_only_and_preserves_failed_attempt(self):
        with Fixture() as f:
            before = {str(p): p.read_bytes() for p in f.root.rglob('*') if p.is_file()}
            self.assertEqual(m.load_source(f.source, f.pin), (f.manifest, f.contents))
            with m.release_lock(f.runner):
                self.assertEqual(m.check_target(f.runner, f.replacement)['gateway'], f.old)
            after = {str(p): p.read_bytes() for p in f.root.rglob('*') if p.is_file()}
            self.assertEqual(before, after)
            self.assertFalse(m.STATE.exists())

    def test_manifest_rejects_wrong_hash_extra_missing_duplicate_and_types(self):
        with Fixture() as f:
            for value in (dict(f.manifest, surprise='x'), {'schema': 1}, dict(f.manifest, schema=True),
                          dict(f.manifest, schema=2), dict(f.manifest, broker_sha256='../arbitrary')):
                f.set_manifest(value)
                with self.assertRaises(ValueError): m.load_source(f.source, f.pin)
            raw = b'{"schema":1,"schema":1}'
            f.put(f.source / 'manifest.json', raw)
            with self.assertRaisesRegex(ValueError, 'duplicate'): m.load_source(f.source, m.sha(raw))
            f.set_manifest(f.manifest)
            with self.assertRaisesRegex(ValueError, 'manifest_hash'): m.load_source(f.source, '0' * 64)
            f.put(f.source / 'ops-broker.py', b'# tampered')
            with self.assertRaisesRegex(ValueError, 'source_hash'): m.load_source(f.source, f.pin)

    def test_source_exact_directory_owner_mode_symlink_and_extra_file(self):
        with Fixture() as f:
            f.source.chmod(0o755)
            with self.assertRaises(ValueError): m.load_source(f.source, f.pin)
            f.source.chmod(0o700)
            f.metadata(f.source, st_uid=123)
            with self.assertRaises(ValueError): m.load_source(f.source, f.pin)
            f.metadata(f.source, st_uid=0)
            f.put(f.source / 'extra.py', b'')
            with self.assertRaisesRegex(ValueError, 'exact_source'): m.load_source(f.source, f.pin)
            (f.source / 'extra.py').unlink()
            path = f.source / 'ops-broker.py'; path.unlink(); path.symlink_to(f.source / 'ops-gateway.py')
            with self.assertRaises(OSError): m.load_source(f.source, f.pin)

    def test_old_gateway_unknown_owner_mode_link_or_hash_rejected(self):
        with Fixture() as f:
            for metadata in ({'st_uid': 985}, {'st_gid': 990}):
                f.metadata(m.GATEWAY, **metadata)
                with self.assertRaises(ValueError): m.check_target(f.runner, f.replacement)
            f.metadata(m.GATEWAY)
            m.GATEWAY.chmod(0o775)
            with self.assertRaises(ValueError): m.check_target(f.runner, f.replacement)
            f.put(m.GATEWAY, b'# unknown', 0o755)
            with self.assertRaisesRegex(ValueError, 'gateway_hash'): m.check_target(f.runner, f.replacement)
            f.put(m.GATEWAY, f.old, 0o755)
            os.link(str(m.GATEWAY), str(f.root / 'hardlink'))
            with self.assertRaisesRegex(ValueError, 'unsafe_root_file'): m.check_target(f.runner, f.replacement)

    def test_parent_symlink_and_nonroot_parent_rejected(self):
        with Fixture() as f:
            f.metadata(m.BIN, st_uid=985)
            with self.assertRaises(ValueError): m.check_target(f.runner, f.replacement)
            f.metadata(m.BIN)
            alias = f.root / 'bin-link'; alias.symlink_to(m.BIN, target_is_directory=True)
            with self.assertRaises(ValueError): m.read_file(alias / 'ssh-gateway.py', 0o755)

    def test_existing_targets_and_stages_always_refuse(self):
        for key in ('STATE', 'BROKER', 'GATEWAY_NEXT', 'RUNNER_NEXT', 'SUDO_NEW', 'SUDO_NEXT'):
            with Fixture() as f:
                path = getattr(m, key); f.put(path, b'unknown')
                with self.assertRaisesRegex(ValueError, 'existing_or_partial'): m.check_target(f.runner, f.replacement)
                self.assertEqual(path.read_bytes(), b'unknown')
        with Fixture() as f:
            m.BROKER.symlink_to(f.root / 'absent')
            with self.assertRaises(ValueError): m.check_target(f.runner, f.replacement)

    def test_original_sudo_exact_content_and_preservation(self):
        with Fixture() as f:
            for content in (m.OLD_RULE + b'# comment\n', m.OLD_RULE.replace(b'restart', b'*'), m.OLD_RULE + b'root ALL=(ALL) ALL\n'):
                f.put(m.SUDO_OLD, content, 0o440)
                with self.assertRaisesRegex(ValueError, 'original_exact_sudo'): m.check_target(f.runner, f.replacement)
                self.assertEqual(m.SUDO_OLD.read_bytes(), content)

    def test_canonical_lock_contention_inode_and_metadata(self):
        with Fixture() as f:
            lock = m.ROOT / 'state/release.lock'; before = lock.read_bytes(); inode = lock.stat().st_ino
            with m.release_lock(f.runner):
                with self.assertRaises(BlockingIOError):
                    with m.release_lock(f.runner): pass
            self.assertEqual(lock.read_bytes(), before); self.assertEqual(lock.stat().st_ino, inode)
            f.metadata(lock, st_uid=0, st_gid=0)
            with self.assertRaisesRegex(ValueError, 'metadata'):
                with m.release_lock(f.runner): pass

    def test_untrusted_helper_is_never_imported(self):
        with Fixture() as f:
            marker = f.root / 'executed'
            code = ('open(%r,"w").write("bad")\n' % str(marker)).encode()
            f.put(m.BIN / 'collect-only-runner.py', code, 0o755)
            f.put(m.BIN / 'collect-only-upgrade.py', b'# helper', 0o755)
            with self.assertRaisesRegex(ValueError, 'helper_hash'): m.load_runner()
            self.assertFalse(marker.exists())

    def test_idle_identity_disabled_credentials_and_no_timer(self):
        with Fixture() as f:
            m.collector_state(f.runner)
            self.assertEqual(f.runner.database_url.call_args[0], ('DATABASE_URL=fixture-secret-do-not-print\n',))
            f.runner.account.return_value = SimpleNamespace(pw_uid=991, pw_gid=991)
            with self.assertRaises(ValueError): m.collector_state(f.runner)

            f.runner.account.return_value = SimpleNamespace(pw_uid=990, pw_gid=990)
            (m.CONFIG / 'database.env').chmod(0o440)
            with self.assertRaises(ValueError): m.collector_state(f.runner)
            (m.CONFIG / 'database.env').chmod(0o400)
            f.runner.prop.side_effect = lambda unit, key: '1' if key == 'MainPID' else f.prop(unit, key)
            with self.assertRaisesRegex(ValueError, 'idle'): m.collector_state(f.runner)
            f.runner.prop.side_effect = f.prop
            timer = m.UNIT_DIRS[0] / 'timers.target.wants/aifinance-collect-hourly.timer'
            timer.parent.mkdir(parents=True); timer.symlink_to(f.root / 'absent')
            with self.assertRaises(ValueError): m.collector_state(f.runner)

    def test_collector_existing_exclusive_gid_is_preserved(self):
        with Fixture() as f:
            f.runner.account.return_value = SimpleNamespace(pw_uid=990, pw_gid=991)
            for path in (m.CONFIG, m.CONFIG / 'hosts', m.CONFIG / 'nsswitch.conf'):
                f.metadata(path, st_gid=991)
            m.collector_state(f.runner)
            self.assertEqual(f.runner.verify_network.call_args[0][0].pw_gid, 991)

    def test_recovery_baseline_requires_original_monotonic_failure_evidence(self):
        with Fixture() as f:
            for start, end in [('0', '20'), ('10', '0'), ('20', '10'), ('10', 'secret-invalid-timestamp')]:
                f.runner.prop.side_effect = lambda unit, key: (
                    start if '-check.' in unit and key == 'ExecMainStartTimestampMonotonic' else
                    end if '-check.' in unit and key == 'ExecMainExitTimestampMonotonic' else f.prop(unit, key))
                with self.assertRaisesRegex(ValueError, 'original_check_timestamps'):
                    m.collector_state(f.runner)

    def test_started_seed_extra_network_or_run_evidence_refused(self):
        with Fixture() as f:
            f.runner.prop.side_effect = lambda unit, key: '20' if '-seed.' in unit and key == 'ExecMainStartTimestampMonotonic' else f.prop(unit, key)
            with self.assertRaisesRegex(ValueError, 'never'): m.collector_state(f.runner)
            f.runner.prop.side_effect = f.prop
            f.put(m.COLLECT / 'network.json', json.dumps({'uid': 990, 'hosts': {'unreviewed': ['1.1.1.1']}}).encode())
            with self.assertRaisesRegex(ValueError, 'db_only_network'): m.collector_state(f.runner)
            f.put(m.COLLECT / 'network.json', json.dumps({'uid': 990, 'hosts': {}}).encode())
            f.put(m.COLLECT / 'run-attempt.json', b'{}')
            with self.assertRaises(ValueError): m.collector_state(f.runner)

    def test_apply_success_atomic_gateway_last_and_no_side_effects(self):
        with Fixture() as f:
            seen = []
            real_replace = m.os.replace
            def replace(source, target):
                if Path(target) != m.GATEWAY:
                    seen.append(Path(target).name); real_replace(source, target); return
                self.assertTrue(m.BROKER.exists()); self.assertTrue(m.SUDO_NEW.exists())
                self.assertTrue((m.STATE / 'policy.json').exists())
                self.assertFalse((m.STATE / 'complete.json').exists())
                self.assertEqual(m.GATEWAY.read_bytes(), f.old)
                seen.append('gateway'); real_replace(source, target)
            with patch.object(m.os, 'replace', side_effect=replace):
                m.install(f.manifest, f.contents, m.check_target(f.runner, f.replacement))
            self.assertEqual(seen, ['collect-only-runner.py'] + sorted(f.runner.unit_name(mode) for mode in ('probe', 'check', 'seed', 'run')) + ['gateway'])
            f.reload.assert_called_once_with(); f.replacement.verify_units.assert_called_once_with()
            self.assertEqual(m.GATEWAY.read_bytes(), f.contents['ops-gateway.py'])
            self.assertEqual((m.STATE / 'ssh-gateway.before.py').read_bytes(), f.old)
            self.assertEqual((m.STATE / 'collect-only-runner.before.py').read_bytes(), f.old_runner)
            self.assertEqual(m.RUNNER_PATH.read_bytes(), f.contents['collect-only-runner.py'])
            for mode in ('probe', 'check', 'seed', 'run'):
                name = f.runner.unit_name(mode)
                self.assertEqual((m.STATE / (name + '.before')).read_bytes(), f.runner.unit_text(mode).encode())
                self.assertEqual((m.SYSTEM / name).read_bytes(), f.replacement.unit_text(mode).encode())
            self.assertEqual(m.SUDO_OLD.read_bytes(), m.OLD_RULE)
            self.assertEqual((m.CONFIG / 'database.env').stat().st_mode & 0o777, 0o400)
            self.assertEqual(json.loads((m.STATE / 'complete.json').read_text()),
                             {'schema': 1, 'status': 'complete', 'broker_sha256': f.manifest['broker_sha256'], 'app_release': m.APP})
            policy = json.loads((m.STATE / 'policy.json').read_text())
            self.assertEqual(set(policy), {'schema', 'broker_sha256', 'runner_sha256', 'upgrade_sha256', 'app_release', 'actions'})
            self.assertEqual(policy['actions'], list(m.ACTIONS))
            self.assertEqual(policy['runner_sha256'], f.manifest['runner_sha256'])
            baseline = json.loads((m.STATE / 'install.json').read_text())['recovery_baseline']
            db = (m.CONFIG / 'database.env').stat()
            self.assertEqual(baseline, {'attempt_sha256': m.sha((m.COLLECT / 'seed-attempt.json').read_bytes()),
                'attempt_started': 42, 'check_start_monotonic': '10', 'check_exit_monotonic': '20',
                'db_device': db.st_dev, 'db_inode': db.st_ino, 'collector_gid': 990})
            for path, mode in [(m.STATE, 0o700), (m.BROKER, 0o755), (m.SUDO_NEW, 0o440), (m.STATE / 'policy.json', 0o600)]:
                self.assertEqual(path.stat().st_mode & 0o777, mode)
            with self.assertRaises(ValueError): m.check_target(f.runner, f.replacement)

    def test_failed_sudo_validation_preserves_backup_and_old_gateway(self):
        with Fixture() as f:
            old = m.check_target(f.runner, f.replacement)
            f.validator.side_effect = subprocess.CalledProcessError(1, 'fixture-visudo')
            with self.assertRaises(subprocess.CalledProcessError): m.install(f.manifest, f.contents, old)
            self.assertEqual(m.GATEWAY.read_bytes(), f.old)
            self.assertTrue(m.SUDO_NEXT.exists()); self.assertFalse(m.SUDO_NEW.exists())
            self.assertTrue((m.STATE / 'ssh-gateway.before.py').exists())
            self.assertFalse((m.STATE / 'complete.json').exists())
            with self.assertRaises(ValueError): m.check_target(f.runner, f.replacement)

    def test_failure_after_publishing_sudo_still_has_no_write_gate(self):
        with Fixture() as f:
            old = m.check_target(f.runner, f.replacement)
            calls = [None, subprocess.CalledProcessError(1, 'fixture-visudo')]
            f.validator.side_effect = calls
            with self.assertRaises(subprocess.CalledProcessError): m.install(f.manifest, f.contents, old)
            self.assertTrue(m.SUDO_NEW.exists()); self.assertEqual(m.GATEWAY.read_bytes(), f.old)
            self.assertFalse((m.STATE / 'complete.json').exists())

    def test_reload_or_new_loaded_unit_failure_preserves_exact_backup_set(self):
        for operation in ('reload', 'verify'):
            with Fixture() as f:
                checked = m.check_target(f.runner, f.replacement)
                target = f.reload if operation == 'reload' else f.replacement.verify_units
                target.side_effect = ValueError('fixture loaded dependency verification failed')
                with self.assertRaises(ValueError): m.install(f.manifest, f.contents, checked)
                self.assertEqual(m.GATEWAY.read_bytes(), f.old)
                self.assertEqual((m.STATE / 'collect-only-runner.before.py').read_bytes(), f.old_runner)
                for name, old in checked['old_units'].items():
                    self.assertEqual((m.STATE / (name + '.before')).read_bytes(), old)
                    self.assertEqual((m.SYSTEM / name).read_bytes(), checked['new_units'][name])
                self.assertFalse(m.SUDO_NEW.exists()); self.assertFalse(m.BROKER.exists())
                self.assertFalse((m.STATE / 'complete.json').exists())

    def test_failure_each_runner_or_unit_switch_preserves_backups_and_closed_gateway(self):
        for fail_at in range(5):
            with Fixture() as f:
                checked = m.check_target(f.runner, f.replacement); original = m.replace_known; count = [0]
                def interrupt(stage, target, old, new, mode):
                    original(stage, target, old, new, mode)
                    point = count[0]; count[0] += 1
                    if point == fail_at:
                        raise OSError('fixture interrupted after known replacement')
                with patch.object(m, 'replace_known', side_effect=interrupt):
                    with self.assertRaises(OSError): m.install(f.manifest, f.contents, checked)
                self.assertEqual(m.GATEWAY.read_bytes(), f.old)
                self.assertEqual((m.STATE / 'collect-only-runner.before.py').read_bytes(), f.old_runner)
                for name, old in checked['old_units'].items():
                    self.assertEqual((m.STATE / (name + '.before')).read_bytes(), old)
                    self.assertIn((m.SYSTEM / name).read_bytes(), (old, checked['new_units'][name]))
                self.assertFalse(m.SUDO_NEW.exists()); self.assertFalse((m.STATE / 'complete.json').exists())
                f.reload.assert_not_called()

    def test_fault_each_exclusive_write_keeps_evidence_and_never_completes(self):
        names = ('install.json', 'ssh-gateway.before.py', 'collect-only-runner.before.py',
                 'aifinance-collect-probe.service.before', '10-backup.json', '.collect-only-runner.py.ops-v1.next',
                 '.aifinance-collect-probe.service.ops-v1.next', '15-runner-units.json', 'ops-broker.py', 'policy.json',
                 '20-broker-policy.json', '.ops.ops-v1.next', '30-sudo.json', '.gateway.ops-v1.next', '40-ready-to-switch.json', 'complete.json')
        for name in names:
            with Fixture() as f:
                old = m.check_target(f.runner, f.replacement); original = m.write_new
                def fail(path, content, mode):
                    if path.name == name:
                        original(path, b'partial-write-evidence', 0o600)
                        raise OSError('fixture write interrupted')
                    return original(path, content, mode)
                with patch.object(m, 'write_new', side_effect=fail):
                    with self.assertRaises(OSError): m.install(f.manifest, f.contents, old)
                if name != 'complete.json':
                    self.assertFalse((m.STATE / 'complete.json').exists())
                    self.assertEqual(m.GATEWAY.read_bytes(), f.old)
                else:
                    self.assertEqual((m.STATE / 'complete.json').read_bytes(), b'partial-write-evidence')
                    self.assertEqual(m.GATEWAY.read_bytes(), f.contents['ops-gateway.py'])
                self.assertTrue(m.STATE.exists())
                with self.assertRaises(ValueError): m.check_target(f.runner, f.replacement)

    def test_failure_after_gateway_switch_preserves_both_versions(self):
        with Fixture() as f:
            old = m.check_target(f.runner, f.replacement); real_replace = m.os.replace
            def interrupted(source, target):
                real_replace(source, target)
                if Path(target) == m.GATEWAY:
                    raise OSError('fixture interruption immediately after rename')
            with patch.object(m.os, 'replace', side_effect=interrupted):
                with self.assertRaises(OSError): m.install(f.manifest, f.contents, old)
            self.assertEqual(m.GATEWAY.read_bytes(), f.contents['ops-gateway.py'])
            self.assertEqual((m.STATE / 'ssh-gateway.before.py').read_bytes(), f.old)
            self.assertFalse((m.STATE / 'complete.json').exists())

    def test_exclusive_publish_refuses_unknown_new_file(self):
        with Fixture() as f:
            f.put(m.SUDO_NEXT, m.sudo_rules(), 0o440); f.put(m.SUDO_NEW, b'unknown', 0o440)
            with self.assertRaises(FileExistsError): m.publish_new(m.SUDO_NEXT, m.SUDO_NEW)
            self.assertEqual(m.SUDO_NEW.read_bytes(), b'unknown')


if __name__ == '__main__':
    unittest.main()
