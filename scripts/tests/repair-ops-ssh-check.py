#!/usr/bin/python3
"""Offline fixed SSH repair fixtures; no real sshd/systemctl or root filesystem writes."""
import ast
from contextlib import ExitStack
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

REPO = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


r = load('repair_ops_ssh', REPO / 'deploy/native/repair-ops-ssh.py')
fixtures = load('existing_install_fixtures', REPO / 'scripts/tests/install-ops-check.py')
CRYPTO = ['-oCiphers=aes256-gcm@openssh.com,aes256-ctr', '-oMACs=hmac-sha2-256-etm@openssh.com',
          '-oGSSAPIKexAlgorithms=gss-group14-sha256-,gss-nistp256-sha256-',
          '-oKexAlgorithms=curve25519-sha256,ecdh-sha2-nistp256',
          '-oHostKeyAlgorithms=ssh-ed25519,rsa-sha2-256', '-oPubkeyAcceptedKeyTypes=ssh-ed25519,rsa-sha2-256',
          '-oCASignatureAlgorithms=ssh-ed25519,rsa-sha2-256']


def argv_bytes(options):
    return ('\x00'.join(['/usr/sbin/sshd', '-D'] + options) + '\x00').encode()


class RepairFixture:
    def __enter__(self):
        self.stack = ExitStack(); self.f = self.stack.enter_context(fixtures.Fixture()); self.m = fixtures.m
        for key, name in [('CONFIG', 'etc/ssh/sshd_config'), ('CANDIDATE', 'etc/ssh/.repair.next'),
                          ('RESTORE', 'etc/ssh/.repair.restore'), ('EVIDENCE', 'var/lib/ssh-repair')]:
            self.stack.enter_context(patch.object(r, key, self.f.root / name))
        self.stack.enter_context(patch.object(r, 'SOURCE_PATTERN', str(self.f.source)))
        self.old = b'Port 22\nAuthorizedKeysCommand /usr/bin/ecs_config_instance_connect --uid %U\n'
        self.f.put(r.CONFIG, self.old, 0o600)
        self.session = self.stack.enter_context(patch.object(r, 'session', return_value=(100, '22', 100, 3, 4)))
        self.stack.enter_context(patch.object(self.m, 'terminal_root'))
        self.stack.enter_context(patch.object(self.m, 'deploy_account'))
        self.source_check = self.stack.enter_context(patch.object(self.m, 'load_source'))
        self.stack.enter_context(patch.object(self.m, 'load_runner', return_value=self.f.runner))
        self.ops = self.stack.enter_context(patch.object(self.m, 'main'))
        self.commands = []; self.reloads = 0; self.problem = None
        self.cmdline = b'/usr/sbin/sshd\x00-D\x00'
        original_read = self.m.read_file
        def read(path, *args, **kwargs):
            if str(path) in ('/proc/42/cmdline', '/proc/999/cmdline'):
                return self.cmdline
            return original_read(path, *args, **kwargs)
        self.stack.enter_context(patch.object(self.m, 'read_file', side_effect=read))
        self.stack.enter_context(patch.object(self.m, 'access_output', side_effect=self.output))
        self.before = {p.name: p.read_bytes() for p in self.f.source.iterdir()}
        return self

    def __exit__(self, *args):
        self.stack.close()

    def output(self, args):
        self.commands.append(args)
        if args[:3] == [self.m.CTL, 'reload', 'sshd.service']:
            self.reloads += 1
            if self.problem == 'title_counter':
                self.cmdline = b'sshd: /usr/sbin/sshd -D [listener] 7 of 10-100 startups\x00'
            if self.problem == 'crypto_changed':
                self.cmdline = self.cmdline.replace(b'-oCiphers=aes256-gcm@openssh.com,aes256-ctr', b'-oCiphers=aes128-ctr')
            if self.problem == 'flags_changed' and self.reloads == 1:
                self.cmdline += b'-e\x00'
            if self.problem == 'reload' and self.reloads == 1:
                raise ValueError('secret fixture stderr must never escape')
            if self.problem == 'ops_race' and self.reloads == 1:
                self.m.STATE.mkdir()
                raise ValueError('fixture_reload_failed')
            if self.problem == 'concurrent_after_write' and self.reloads == 1:
                r.CONFIG.write_bytes(b'unknown concurrent config\n')
                raise OSError('private fixture failure')
            return ''
        if args[:3] == [self.m.CTL, 'show', 'sshd.service']:
            pid = '999' if self.problem == 'pid' and self.reloads == 1 else '42'
            return 'ActiveState=active\nMainPID=' + pid + '\nExecMainStartTimestampMonotonic=123\nCanReload=yes\n'
        if args[:2] == [self.m.SSHD, '-t']:
            if self.problem == 'syntax' and '-f' in args:
                raise ValueError('untrusted SSH parser detail')
            return ''
        if args[:2] == [self.m.SSHD, '-T']:
            path = Path(args[args.index('-f') + 1]) if '-f' in args else r.CONFIG
            changed = r.MARKER in path.read_bytes()
            user = args[args.index('-C') + 1].split(',')[0][5:] if '-C' in args else None
            rows = ['port 22', 'forcecommand none', r.OLD_COMMAND]
            if changed and user == 'aifinance-deploy' and self.problem != 'deploy_conflict':
                rows[-1] = 'authorizedkeyscommand none'
            if changed and self.problem == user and user in ('root', 'aifinance-preview', 'aifinance'):
                rows[0] = 'port 23'
            if changed and self.problem == 'global' and user is None:
                rows[0] = 'port 23'
            if changed and user == 'aifinance-deploy' and self.problem == 'concurrent_before_write':
                r.CONFIG.write_bytes(b'unknown concurrent config\n')
            if changed and user == 'aifinance-deploy' and self.problem == 'same_bytes_new_inode':
                replacement = r.CONFIG.with_name('.concurrent')
                replacement.write_bytes(self.old); replacement.chmod(0o600)
                r.os.replace(str(replacement), str(r.CONFIG))
            return '\n'.join(rows)
        raise AssertionError('fixture rejected any unexpected external command')

    def run(self):
        return r.run(self.m, self.f.source)

    def assert_source_unchanged(self, case):
        case.assertEqual({p.name: p.read_bytes() for p in self.f.source.iterdir()}, self.before)


class RepairTests(unittest.TestCase):
    def test_python36_syntax_and_original_payload_pin(self):
        ast.parse((REPO / 'deploy/native/repair-ops-ssh.py').read_text(),
                  **({'feature_version': (3, 6)} if sys.version_info >= (3, 8) else {}))
        self.assertEqual(hashlib.sha256((REPO / 'deploy/native/install-ops.py').read_bytes()).hexdigest(), r.INSTALLER_SHA)
        self.assertEqual(hashlib.sha256((REPO / 'deploy/native/ops-files.json').read_bytes()).hexdigest(), r.MANIFEST_SHA)

    def test_success_preserves_inputs_and_uses_original_installer_check_then_apply(self):
        with RepairFixture() as f:
            result = f.run()
            self.assertFalse(result['failed']); self.assertTrue(result['ssh_restricted'])
            self.assertEqual(r.CONFIG.read_bytes(), f.old + r.APPEND)
            self.assertEqual((r.EVIDENCE / 'sshd_config.before').read_bytes(), f.old)
            self.assertEqual(f.reloads, 1)
            self.assertEqual([call[0][0][0] for call in f.ops.call_args_list], ['check', 'apply'])
            self.assertTrue(all(call[0][0][2] == str(f.f.source) for call in f.ops.call_args_list))
            self.assertTrue(all('restart' not in args for args in f.commands))
            f.assert_source_unchanged(self)

    def test_global_root_preview_or_deploy_conflict_never_changes_live_file(self):
        for problem in ('global', 'root', 'aifinance-preview', 'aifinance', 'deploy_conflict', 'syntax'):
            with RepairFixture() as f:
                f.problem = problem; result = f.run()
                self.assertTrue(result['failed']); self.assertEqual(r.CONFIG.read_bytes(), f.old)
                self.assertEqual(f.reloads, 0); f.ops.assert_not_called()
                self.assertIn(result['stage'], ('candidate_policy', 'candidate_syntax'))
                f.assert_source_unchanged(self)

    def test_existing_match_key_command_and_include_are_explicit_refusals(self):
        for suffix, reason in [(b'Match Address 10.*\nAuthorizedKeysCommand /different\n', 'earlier_match_key_command_requires_review'),
                               (b'Include /etc/ssh/sshd_config.d/*.conf\n', 'include_requires_separate_review')]:
            with RepairFixture() as f:
                original = f.old + suffix; r.CONFIG.write_bytes(original)
                result = f.run()
                self.assertEqual(result['reason'], reason); self.assertEqual(r.CONFIG.read_bytes(), original)
                self.assertFalse(r.EVIDENCE.exists()); f.ops.assert_not_called()

    def test_exact_disjoint_preview_none_block_preserves_target_style_config(self):
        with RepairFixture() as f:
            original = (f.old + b'AuthorizedKeysCommandUser nobody\nMatch User aifinance-preview\n'
                        b'    AuthorizedKeysCommand none\nMatch all\n')
            r.CONFIG.write_bytes(original)
            result = f.run()
            self.assertFalse(result['failed']); self.assertTrue(result['ssh_restricted'])
            self.assertEqual(r.CONFIG.read_bytes(), original + r.APPEND)
            self.assertEqual((r.EVIDENCE / 'sshd_config.before').read_bytes(), original)
            f.assert_source_unchanged(self)

    def test_preview_allowance_rejects_overlap_unknown_conditions_and_resets_each_match(self):
        selectors = ('User aifinance-deploy', 'User *', 'User aifinance-preview,aifinance-deploy',
                     'User !aifinance-preview', 'User aifinance-preview Group privileged',
                     'User aifinance-preview Address 127.0.0.1', 'Group aifinance-preview',
                     'User "aifinance-preview"', 'all')
        for selector in selectors:
            raw = ('Match ' + selector + '\n AuthorizedKeysCommand none\n').encode()
            with self.assertRaisesRegex(r.Refused, 'earlier_match_key_command_requires_review'):
                r.config_scope(raw)
        for suffix in (b' AuthorizedKeysCommand /different\n',
                       b' AuthorizedKeysCommand none extra\n',
                       b' AuthorizedKeysCommand none\nMatch all\n AuthorizedKeysCommand none\n'):
            with self.assertRaisesRegex(r.Refused, 'earlier_match_key_command_requires_review'):
                r.config_scope(b'Match User aifinance-preview\n' + suffix)

    def test_reload_failure_restores_known_config_without_leaking_error(self):
        with RepairFixture() as f:
            f.problem = 'reload'; result = f.run()
            self.assertTrue(result['failed']); self.assertEqual(result['stage'], 'sshd_reload')
            self.assertEqual(result['rollback'], 'restored'); self.assertFalse(result['ssh_restricted'])
            self.assertEqual(r.CONFIG.read_bytes(), f.old); self.assertEqual(f.reloads, 2)
            self.assertNotIn('secret', json.dumps(result)); f.ops.assert_not_called()
            f.assert_source_unchanged(self)

    def test_changed_config_or_inode_is_never_overwritten(self):
        for problem in ('concurrent_before_write', 'same_bytes_new_inode'):
            with RepairFixture() as f:
                f.problem = problem; result = f.run()
                self.assertEqual(result['reason'], 'concurrent_sshd_config_change')
                self.assertEqual(result['rollback'], 'not_needed'); self.assertEqual(f.reloads, 0)
                self.assertNotIn(r.MARKER, r.CONFIG.read_bytes()); f.ops.assert_not_called()

    def test_concurrent_edit_after_write_refuses_rollback_over_unknown_file(self):
        with RepairFixture() as f:
            f.problem = 'concurrent_after_write'; result = f.run()
            self.assertEqual(result['rollback'], 'rollback_refused_concurrent_change')
            self.assertIsNone(result['ssh_restricted'])
            self.assertEqual(r.CONFIG.read_bytes(), b'unknown concurrent config\n'); f.ops.assert_not_called()

    def test_daemon_identity_change_rolls_back_before_ops(self):
        with RepairFixture() as f:
            f.problem = 'pid'; result = f.run()
            self.assertEqual(result['reason'], 'daemon_or_operator_session_changed')
            self.assertEqual(result['rollback'], 'restored'); self.assertEqual(r.CONFIG.read_bytes(), f.old)
            f.ops.assert_not_called()

    def test_ops_check_or_apply_failure_keeps_verified_deploy_restriction(self):
        for stage in ('check', 'apply'):
            with RepairFixture() as f:
                def ops(args):
                    if args[0] == stage:
                        raise ValueError('private data must not be printed')
                f.ops.side_effect = ops; result = f.run()
                self.assertTrue(result['failed']); self.assertEqual(result['stage'], 'ops_' + stage)
                self.assertTrue(result['ssh_restricted']); self.assertEqual(result['rollback'], 'not_needed')
                self.assertEqual(r.CONFIG.read_bytes(), f.old + r.APPEND); self.assertEqual(f.reloads, 1)
                self.assertNotIn('private', json.dumps(result)); f.assert_source_unchanged(self)

    def test_specific_original_installer_reason_is_visible_without_raw_errors(self):
        with RepairFixture() as f:
            f.ops.side_effect = ValueError('existing_sshd_boundary_changed')
            result = f.run()
            self.assertEqual(result['reason'], 'existing_sshd_boundary_changed')
            self.assertEqual(result['stage'], 'ops_check'); self.assertTrue(result['ssh_restricted'])
        for secret in ('private_token_123', ['private_token_123'], {'key': 'private_token_123'}):
            with RepairFixture() as f:
                f.ops.side_effect = ValueError(secret)
                result = f.run()
                self.assertEqual(result['reason'], 'ops_check_failed')
                self.assertNotIn('private_token', json.dumps(result))

    def test_rollback_reacquires_lock_and_refuses_any_new_ops_state(self):
        with RepairFixture() as f:
            f.problem = 'ops_race'; result = f.run()
            self.assertEqual(result['rollback'], 'rollback_refused_ops_state')
            self.assertEqual(r.CONFIG.read_bytes(), f.old + r.APPEND); self.assertEqual(f.reloads, 1)
        with RepairFixture() as f:
            f.problem = 'reload'; original = f.m.release_lock
            with patch.object(f.m, 'release_lock', side_effect=[original(f.f.runner), BlockingIOError()]):
                result = f.run()
            self.assertEqual(result['rollback'], 'rollback_refused_lock_busy')
            self.assertEqual(r.CONFIG.read_bytes(), f.old + r.APPEND); self.assertEqual(f.reloads, 1)

    def test_daemon_requires_verified_default_config_invocation(self):
        for command in (b'/usr/sbin/sshd\x00-D\x00-o\x00AuthorizedKeysCommand=anything\x00',
                        b'/usr/sbin/sshd\x00-D\x00-f\x00/other/config\x00',
                        b'sshd: [listener] 0 of 10-100 startups\x00', b'/other/sshd\x00-D\x00'):
            with RepairFixture() as f:
                f.cmdline = command; result = f.run()
                self.assertIn(result['reason'], ('unverified_sshd_config_invocation', 'unverified_sshd_crypto_arguments'))
                self.assertEqual(r.CONFIG.read_bytes(), f.old); self.assertEqual(f.reloads, 0)
        with RepairFixture() as f:
            f.cmdline = b'sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups\x00'
            f.problem = 'title_counter'
            self.assertFalse(f.run()['failed'])

    def test_actual_seven_crypto_tokens_forward_unchanged_to_every_check_and_original_installer(self):
        # Vendor GSSAPI options are forwarded as evidence; this fixture never
        # drops them to fit a different local OpenSSH build.
        with RepairFixture() as f:
            f.cmdline = argv_bytes(CRYPTO)
            f.ops.side_effect = lambda args: f.m.access_output([f.m.SSHD, '-T', '-C',
                'user=aifinance-deploy,host=localhost,addr=127.0.0.1'])
            self.assertFalse(f.run()['failed'])
            commands = [args for args in f.commands if args[:2] in ([f.m.SSHD, '-t'], [f.m.SSHD, '-T'])]
            self.assertGreaterEqual(len(commands), 19)
            for args in commands:
                self.assertEqual([arg for arg in args if arg.startswith('-o')], CRYPTO)
            self.assertEqual(len([args for args in commands if args[1] == '-T' and '-f' not in args]), 2)
            f.assert_source_unchanged(self)
        with RepairFixture() as f:
            original_order = list(reversed(CRYPTO)); f.cmdline = argv_bytes(original_order); f.problem = 'reload'
            result = f.run(); self.assertEqual(result['rollback'], 'restored')
            for args in f.commands:
                if args[:2] in ([f.m.SSHD, '-t'], [f.m.SSHD, '-T']):
                    self.assertEqual([arg for arg in args if arg.startswith('-o')], original_order)

    def test_crypto_allowlist_rejects_auth_overrides_duplicates_partial_sets_and_malformed_values(self):
        bad = [CRYPTO + ['-oAuthorizedKeysCommand=none'], CRYPTO + ['-oForceCommand=anything'],
               CRYPTO + ['-oInclude=/unreviewed'], CRYPTO + [CRYPTO[0]], CRYPTO[:-1],
               CRYPTO + ['-f', '/unreviewed/config']]
        bad += [[first] + CRYPTO[1:] for first in ('-oCiphers=+aes256-ctr', '-oCiphers=-aes256-ctr',
                  '-oCiphers=aes256-ctr,-aes128-ctr', '-oCiphers=aes256-ctr,', '-oCiphers=aes256-ctr ssh-rsa',
                  '-oCiphers=aes256-ctr;bad', '-oCiphers=', '-oCiphers=aes256/ctr')]
        for options in bad:
            with RepairFixture() as f:
                f.cmdline = argv_bytes(options); result = f.run()
                self.assertEqual(result['reason'], 'unverified_sshd_crypto_arguments')
                self.assertEqual(r.CONFIG.read_bytes(), f.old); self.assertEqual(f.reloads, 0); f.ops.assert_not_called()

    def test_any_crypto_value_or_original_flag_change_after_reload_is_rejected(self):
        for problem in ('crypto_changed', 'flags_changed'):
            with RepairFixture() as f:
                f.cmdline = argv_bytes(CRYPTO); f.problem = problem; result = f.run()
                self.assertEqual(result['reason'], 'daemon_or_operator_session_changed')
                self.assertTrue(result['failed']); f.ops.assert_not_called()

    def test_selinux_label_preserved_for_candidate_and_rollback(self):
        with RepairFixture() as f:
            def identity(path):
                st = f.f.real_fstat(path) if isinstance(path, int) else f.f.real_lstat(Path(path))
                return st.st_dev, st.st_ino
            labels = {identity(r.CONFIG): {'security.selinux': b'system_u:object_r:sshd_config_t:s0\x00'}}
            def listattr(path, **kwargs): return list(labels.get(identity(path), {}))
            def getattribute(path, name, **kwargs): return labels[identity(path)][name]
            def setattribute(fd, name, value): labels.setdefault(identity(fd), {})[name] = value
            f.problem = 'reload'
            with patch.object(r.os, 'listxattr', side_effect=listattr), patch.object(r.os, 'getxattr', side_effect=getattribute), \
                    patch.object(r.os, 'setxattr', side_effect=setattribute):
                result = f.run()
                self.assertEqual(result['rollback'], 'restored')
                self.assertEqual(r.attributes(r.CONFIG), {'security.selinux': b'system_u:object_r:sshd_config_t:s0\x00'})
        with RepairFixture() as f:
            with patch.object(r.os, 'listxattr', return_value=['system.posix_acl_access']):
                result = f.run()
            self.assertEqual(result['reason'], 'unsupported_sshd_config_security_attributes')
            self.assertEqual(r.CONFIG.read_bytes(), f.old); self.assertEqual(f.reloads, 0)

    def test_prior_repair_or_ops_state_stops_without_changes(self):
        for which in ('repair', 'ops'):
            with RepairFixture() as f:
                path = r.EVIDENCE if which == 'repair' else f.m.STATE
                path.mkdir()
                result = f.run()
                self.assertTrue(result['failed']); self.assertEqual(result['stage'], 'preflight')
                self.assertEqual(r.CONFIG.read_bytes(), f.old); self.assertEqual(f.reloads, 0)

    def test_untrusted_bootstrap_bytes_never_execute(self):
        with RepairFixture() as f:
            marker = f.f.root / 'untrusted-executed'
            f.f.put(f.f.source / 'install-ops.py', ('open(%r,"w").write("bad")' % str(marker)).encode())
            with self.assertRaisesRegex(r.Refused, 'pinned_installer_mismatch'):
                r.installer(f.f.source)
            self.assertFalse(marker.exists())


if __name__ == '__main__':
    unittest.main()
