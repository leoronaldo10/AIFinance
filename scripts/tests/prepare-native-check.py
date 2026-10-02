"""Preparation gate contract tests. Synthetic inputs only; never install or start services."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('prepare_native', str(ROOT / 'deploy/native/prepare-native.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def host():
    return {'architecture': 'x86_64', 'python': [3, 6, 8],
            'os': {'ID': 'alinux', 'VERSION_ID': '3.2104'}, 'glibc': 'glibc 2.32',
            'memory_kib': {'MemAvailable': 1100000, 'SwapTotal': 4194304},
            'disk_available_bytes': 11 * 1024 ** 3, 'cgroup_v1_memory': True,
            'systemd_version': 239, 'ports': {'8000': ['other'], '3100': [], '3101': [], '55432': []},
            'units': {unit: 'not-found' for unit in m.UNITS},
            'dedicated_node': None, 'postgresql_candidates': [],
            'postgresql_absence_proven': False, 'existing_runtime_tree': False}


def fixture(base, major=17):
    def artifact(url):
        path = base / url.rsplit('/', 1)[1]
        path.write_bytes(b'synthetic-not-installable-' + path.name.encode())
        return {'path': str(path), 'url': url, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    version = '24.11.1'
    plan = {'format': 1, 'node_version': version,
            'node': artifact('https://nodejs.org/dist/v' + version + '/node-v' + version + '-linux-x64.tar.xz'),
            'postgresql_major': major, 'postgresql_rpms': []}
    for suffix in ('', '-libs', '-server', '-contrib'):
        name = 'postgresql' + str(major) + suffix + '-' + str(major) + '.6-1PGDG.rhel8.x86_64.rpm'
        plan['postgresql_rpms'].append(artifact('https://download.postgresql.org/pub/repos/yum/' + str(major) + '/redhat/rhel-8-x86_64/' + name))
    return plan


def save_plan(base, plan):
    path = base / 'reviewed-plan.json'
    path.write_text(json.dumps(plan))
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


class PrepareNative(unittest.TestCase):
    def test_check_only_never_calls_mutation_or_reports_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            before = list(Path(directory).iterdir())
            output = io.StringIO()
            with patch.object(m, 'snapshot', return_value=host()), patch.object(m.subprocess, 'run', side_effect=AssertionError('unexpected process')), patch.object(Path, 'mkdir', side_effect=AssertionError('write')), patch.object(Path, 'write_text', side_effect=AssertionError('write')), contextlib.redirect_stdout(output):
                self.assertEqual(m.main([]), 2)
            self.assertEqual(list(Path(directory).iterdir()), before)
            report = json.loads(output.getvalue())
            self.assertFalse(report['changed'])
            self.assertFalse(report['ready_for_deploy'])
            self.assertFalse(report['ready_for_apply'])
            self.assertEqual(report['host']['ports']['8000'], ['other'])
            self.assertEqual(report['provisional_memory_limit_mib'], {'database': 256, 'api': 320, 'web': 256})

    def test_apply_always_refuses_even_with_reviewed_inputs_and_perfect_host(self):
        events = []
        with patch.object(m, 'snapshot', side_effect=lambda: events.append('inspect') or host()), patch.object(m, 'verify_plan', side_effect=lambda *args: events.append('verify') or {'status': 'local_bytes_match_reviewed_pins_only'}), patch.object(m.subprocess, 'run', side_effect=AssertionError('mutation')), contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main(['--apply', '--plan', '/protected/plan.json', '--plan-sha256', 'a' * 64]), 3)
        self.assertEqual(events, ['inspect', 'verify'])
        report = json.loads(out.getvalue())
        self.assertEqual(report['mode'], 'apply-refused')
        self.assertFalse(report['changed'])
        self.assertIn('apply_not_implemented_no_host_changes_allowed', report['blockers'])

    def test_missing_or_invalid_plan_stops_before_apply(self):
        with patch.object(m, 'snapshot', side_effect=AssertionError('should reject arguments first')), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                m.main(['--apply', '--plan', '/protected/plan.json'])
        with patch.object(m, 'snapshot', return_value=host()), patch.object(m, 'verify_plan', side_effect=ValueError('bad_artifact')), patch.object(m, 'assess', side_effect=AssertionError('not checked')):
            with self.assertRaises(ValueError):
                m.main(['--apply', '--plan', '/protected/plan.json', '--plan-sha256', 'a' * 64])

    def test_artifact_bytes_verify_but_are_not_acceptance(self):
        for major in (16, 17):
            with self.subTest(major=major), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                path, digest = save_plan(base, fixture(base, major))
                # Only filesystem ownership is synthetic; all bytes/hashes/JSON are real.
                with patch.object(m, 'trusted', side_effect=lambda path: Path(path)), patch.object(m.os, 'fstat', side_effect=root_fstat):
                    report = m.verify_plan(path, digest)
                    self.assertFalse(report['dependency_closure_verified'])
                    self.assertFalse(report['trusted_vendor_signatures_checked'])
                    self.assertEqual(len(report['rpms']), 4)
                    self.assertEqual(report['postgresql_major'], major)

    def test_plan_and_artifact_digest_and_size_mismatches_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            plan = fixture(base)
            path, digest = save_plan(base, plan)
            with patch.object(m, 'trusted', side_effect=lambda path: Path(path)), patch.object(m.os, 'fstat', side_effect=root_fstat):
                with self.assertRaises(ValueError): m.verify_plan(path, '0' * 64)
                with self.assertRaises(ValueError): m.digest_file(path, 5)
                Path(plan['node']['path']).write_bytes(b'changed')
                with self.assertRaises(ValueError): m.verify_plan(path, digest)

    def test_no_url_options_moving_targets_or_mixed_packages(self):
        mutations = [
            lambda p: p['node'].update(url=p['node']['url'] + '?token=secret'),
            lambda p: p['node'].update(url=p['node']['url'].replace('nodejs.org', 'evil.example')),
            lambda p: p.update(node_version='22.20.0'),
            lambda p: p.update(postgresql_major=15),
            lambda p: p['postgresql_rpms'].pop(),
            lambda p: p['postgresql_rpms'].__setitem__(1, p['postgresql_rpms'][0]),
            lambda p: p.update(unapproved_command='dnf install'),
        ]
        for change in mutations:
            with tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                plan = fixture(base)
                change(plan)
                path, digest = save_plan(base, plan)
                with patch.object(m, 'trusted', side_effect=lambda path: Path(path)), patch.object(m.os, 'fstat', side_effect=root_fstat), self.assertRaises(ValueError):
                    m.verify_plan(path, digest)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            plan = fixture(base)
            item = plan['postgresql_rpms'][0]
            old = Path(item['path'])
            new = base / old.name.replace('17.6-', '17.7-')
            new.write_bytes(old.read_bytes())
            item.update(path=str(new), url=item['url'].replace('17.6-', '17.7-'))
            path, digest = save_plan(base, plan)
            with patch.object(m, 'trusted', side_effect=lambda path: Path(path)), patch.object(m.os, 'fstat', side_effect=root_fstat), self.assertRaises(ValueError):
                m.verify_plan(path, digest)
        with self.assertRaises(ValueError):
            m.unique_object([('format', 1), ('format', 1)])

    def test_symlinks_special_files_untrusted_owners_and_writable_ancestors_refused(self):
        def metadata(path):
            return os.stat_result((stat.S_IFREG | 0o644 if str(path) == '/inputs/plan' else stat.S_IFDIR | 0o755, 0, 0, 1, 0, 0, 1, 0, 0, 0))
        with patch.object(Path, 'lstat', autospec=True, side_effect=metadata):
            self.assertEqual(m.trusted('/inputs/plan'), Path('/inputs/plan'))
        for mode, uid, bad in ((stat.S_IFLNK | 0o777, 0, '/inputs/plan'), (stat.S_IFIFO | 0o600, 0, '/inputs/plan'), (stat.S_IFREG | 0o644, 1000, '/inputs/plan'), (stat.S_IFDIR | 0o777, 0, '/inputs')):
            def untrusted(path):
                values = list(metadata(path))
                if str(path) == bad:
                    values[0], values[4] = mode, uid
                return os.stat_result(values)
            with patch.object(Path, 'lstat', autospec=True, side_effect=untrusted), self.assertRaises(ValueError):
                m.trusted('/inputs/plan')
        with self.assertRaises(ValueError): m.trusted('relative/plan')

    def test_commands_are_fixed_read_only_and_clear_environment(self):
        def response(args, **kwargs):
            self.assertNotIn('SECRET', kwargs['env'])
            self.assertNotIn('LD_PRELOAD', kwargs['env'])
            self.assertEqual(kwargs['env'], m.ENV)
            self.assertIs(kwargs['stdin'], subprocess.DEVNULL)
            self.assertIs(kwargs['stderr'], subprocess.DEVNULL)
            self.assertFalse(kwargs['shell'])
            self.assertEqual(kwargs['cwd'], '/')
            self.assertEqual(kwargs['timeout'], 5)
            return subprocess.CompletedProcess(args, 0, 'systemd 239\n')
        with patch.dict(os.environ, {'SECRET': 'never-log', 'LD_PRELOAD': 'never-inherit'}), patch.object(m, 'trusted'), patch.object(m.subprocess, 'run', side_effect=response):
            self.assertEqual(m.command(['/usr/bin/systemctl', '--version']), 'systemd 239\n')
        with patch.object(m, 'trusted'), patch.object(m.subprocess, 'run', side_effect=subprocess.TimeoutExpired('fixed', 5)):
            self.assertIsNone(m.command(['/usr/bin/systemctl', '--version']))
        with patch.object(m, 'trusted', side_effect=ValueError), patch.object(m.subprocess, 'run', side_effect=AssertionError):
            self.assertIsNone(m.command(['/usr/bin/systemctl', '--version']))

    def test_snapshot_only_queries_fixed_metadata_and_candidates(self):
        seen = []
        def query(args):
            seen.append(args)
            if args == ['/usr/bin/systemctl', '--version']: return 'systemd 239\n'
            if args[0] == '/usr/bin/systemctl': return 'not-found\n'
            return None
        metadata = {'/etc/os-release': 'ID="alinux"\nVERSION_ID="3.2104"', '/proc/meminfo': 'MemAvailable: 1100000 kB\n',
                    '/proc/self/mountinfo': 'fixture - cgroup cgroup rw,memory\n', '/proc/net/tcp': 'header\n', '/proc/net/tcp6': 'header\n'}
        with patch.object(m, 'command', side_effect=query), patch.object(m, 'read_text', side_effect=lambda path: metadata[path]):
            report = m.snapshot()
        self.assertFalse(report['postgresql_absence_proven'])
        self.assertEqual(report['postgresql_candidates'], [])
        self.assertEqual(len(seen), 7)
        for args in seen:
            self.assertIn(args[-1], ('--version', '--value'))
            self.assertTrue(args[0].startswith('/'))
            self.assertFalse(any(token in args for token in ('dnf', 'sudo', 'install', 'restart', 'start', 'enable', 'initdb')))

    def test_busy_ports_existing_units_unknown_state_and_low_resources_block(self):
        h = host()
        h['ports']['55432'] = ['loopback']
        h['units'][m.UNITS[0]] = 'loaded'
        h['existing_runtime_tree'] = True
        h['memory_kib']['MemAvailable'] = 100000
        h['memory_kib']['SwapTotal'] = 100 * 1024 ** 3
        report = m.assess(h, None)
        for reason in ('dedicated_preview_port_occupied_do_not_stop_existing_listener', 'existing_or_unverifiable_preview_units_need_manual_reconciliation', 'existing_runtime_tree_do_not_overwrite', 'resource_review_required_minimum_headroom_not_observed'):
            self.assertIn(reason, report['blockers'])
        h['ports'] = None
        self.assertIn('listener_state_unavailable', m.assess(h, None)['blockers'])

    def test_node_24_minor_floor_and_kernel_listener_parser(self):
        for text in ('v22.20.0', 'v24.10.9', 'v25.0.0', 'v24.11.0-rc.1', 'v24.11.1\nsecret'):
            self.assertIsNone(m.parse_node(text))
        self.assertEqual(m.parse_node('v24.11.1\n'), '24.11.1')
        ports = m.parse_ports('head\n 0: 00000000:1F40 00000000:0000 0A\n 1: 0100007F:D888 00000000:0000 0A\n', 'head\n 0: 00000000000000000000000001000000:0C1C 00:00 0A\n')
        self.assertEqual(ports, {'8000': ['other'], '3100': ['loopback'], '3101': [], '55432': ['loopback']})


real_fstat = os.fstat


def root_fstat(fd):
    values = list(real_fstat(fd))
    values[4] = 0
    return os.stat_result(values)


if __name__ == '__main__':
    print('Runtime:', sys.version, flush=True)
    unittest.main()
