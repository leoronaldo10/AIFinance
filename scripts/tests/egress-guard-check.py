"""Local mocked checks only: never touch real nft, systemd, users or networking."""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('egress_guard', str(REPO / 'deploy/native/egress-guard.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
UID, TOKEN = 1007, 'a' * 32


def kernel_table():
    objects = copy.deepcopy(m.expected_objects(UID, TOKEN))
    for number, item in enumerate(objects, 11):
        value = next(iter(item.values()))
        value['handle'] = number
        for expr in value.get('expr', []):
            if 'counter' in expr:
                expr['counter'] = {'packets': 3, 'bytes': 180}
    return {'nftables': [{'metainfo': {'version': '1.0.4'}}] + objects}


class GuardTests(unittest.TestCase):
    def test_four_rules_match_only_explicit_app_uid(self):
        payload = m.rules(UID, TOKEN)
        self.assertTrue(payload.startswith('create table inet ' + m.TABLE + ' {'))
        self.assertEqual(payload.count('meta skuid 1007 '), 4)
        self.assertIn('ip daddr 127.0.0.0/8 counter accept', payload)
        self.assertIn('ip6 daddr ::1 counter accept', payload)
        self.assertIn('meta nfproto ipv4 counter reject with icmp type admin-prohibited', payload)
        self.assertIn('meta nfproto ipv6 counter reject with icmpv6 type admin-prohibited', payload)
        self.assertNotRegex(payload, r'flush|oif|iif|ct state|8000|26\b')
        self.assertIn('policy accept;', payload)

    def test_arbitrary_ids_and_injection_are_rejected(self):
        for uid in (0, -1, True, '1007', 4294967295):
            with self.assertRaises(ValueError):
                m.rules(uid, TOKEN)
        for token in ('x', TOKEN + '\nflush ruleset', 'a' * 33):
            with self.assertRaises(ValueError):
                m.rules(UID, token)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            m.main(['start', '--table', 'firewalld'])

    def test_getpwnam_resolves_actual_exclusive_uid(self):
        account = SimpleNamespace(pw_name='aifinance', pw_uid=UID)
        with patch.object(m.pwd, 'getpwnam', return_value=account) as get, \
                patch.object(m.pwd, 'getpwall', return_value=[account]):
            self.assertEqual(m.app_uid(), UID)
            get.assert_called_once_with('aifinance')
        for uid, names in ((0, ['aifinance']), (UID, ['aifinance', 'old-site'])):
            with patch.object(m.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=uid)), \
                    patch.object(m.pwd, 'getpwall', return_value=[SimpleNamespace(pw_uid=uid, pw_name=n) for n in names]), \
                    self.assertRaises(ValueError):
                m.app_uid()

    def test_table_list_failure_does_not_mean_absent(self):
        with patch.object(m, 'nft', side_effect=ValueError('query_failed')), self.assertRaises(ValueError):
            m.table_exists()
        for output in ({}, {'nftables': [{'weird': {}}]}, {'nftables': [{'table': {}}]}):
            with patch.object(m, 'nft', return_value=json.dumps(output)), self.assertRaises(ValueError):
                m.table_exists()
        for name, expected in ((m.TABLE, True), ('firewalld', False)):
            with patch.object(m, 'nft', return_value=json.dumps({'nftables': [{'table': {'family': 'inet', 'name': name}}]})):
                self.assertEqual(m.table_exists(), expected)

    def test_existing_table_is_never_merged_deleted_or_loaded(self):
        with patch.object(m, 'no_app_processes'), patch.object(m, 'table_exists', return_value=True), \
                patch.object(m, 'nft') as nft, self.assertRaises(ValueError):
            m.start(UID)
        nft.assert_not_called()

    def test_owned_table_requires_exact_semantics_and_order(self):
        with patch.object(m, 'nft', return_value=json.dumps(kernel_table())):
            handle, counters = m.inspect_table(UID, TOKEN)
        self.assertEqual(handle, 11)
        self.assertEqual(counters[TOKEN + ':deny-v6']['packets'], 3)
        mutations = []
        value = kernel_table(); value['nftables'][1]['table']['flags'] = ['dormant']; mutations.append(value)
        value = kernel_table(); value['nftables'][2]['chain']['hook'] = 'input'; mutations.append(value)
        value = kernel_table(); value['nftables'][2]['chain']['policy'] = 'drop'; mutations.append(value)
        value = kernel_table(); value['nftables'][3]['rule']['expr'][0]['match']['right'] = 26; mutations.append(value)
        value = kernel_table(); value['nftables'][3]['rule']['expr'][1]['match']['right'] = '0.0.0.0'; mutations.append(value)
        value = kernel_table(); value['nftables'][5]['rule']['expr'][-1] = {'accept': None}; mutations.append(value)
        value = kernel_table(); value['nftables'][5]['rule']['expr'].pop(0); mutations.append(value)
        value = kernel_table(); value['nftables'][5]['rule']['comment'] = 'not-ours'; mutations.append(value)
        value = kernel_table(); value['nftables'][3], value['nftables'][5] = value['nftables'][5], value['nftables'][3]; mutations.append(value)
        value = kernel_table(); value['nftables'].append(copy.deepcopy(value['nftables'][3])); mutations.append(value)
        value = kernel_table(); value['nftables'][6]['rule']['expr'][2]['counter']['packets'] = -1; mutations.append(value)
        value = kernel_table(); value['nftables'][1]['table'].pop('handle'); mutations.append(value)
        for value in mutations:
            with self.subTest(value=value), patch.object(m, 'nft', return_value=json.dumps(value)), self.assertRaises(ValueError):
                m.inspect_table(UID, TOKEN)

    def test_start_check_failure_does_not_create_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / 'receipt.json'
            with patch.object(m, 'RECEIPT', receipt), patch.object(m, 'no_app_processes'), \
                    patch.object(m, 'table_exists', return_value=False), \
                    patch.object(m, 'nft', side_effect=ValueError('check_failed')), self.assertRaises(ValueError):
                m.start(UID)
            self.assertFalse(receipt.exists())

    def test_start_apply_failure_retains_ownership_receipt_without_delete(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / 'receipt.json'
            with patch.object(m, 'RECEIPT', receipt), patch.object(m, 'no_app_processes'), \
                    patch.object(m, 'table_exists', return_value=False), \
                    patch.object(m, 'nft', side_effect=['', ValueError('apply_failed')]) as nft, self.assertRaises(ValueError):
                m.start(UID)
            self.assertEqual(json.loads(receipt.read_text())['uid'], UID)
            self.assertEqual(receipt.stat().st_mode & 0o777, 0o600)
            self.assertEqual([call[0][0] for call in nft.call_args_list], [['--check', '--file', '-'], ['--file', '-']])

    def test_start_applies_then_verifies_before_success(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(m, 'RECEIPT', Path(directory) / 'receipt.json'), \
                patch.object(m, 'no_app_processes'), patch.object(m, 'table_exists', return_value=False), \
                patch.object(m, 'nft', return_value='') as nft, patch.object(m, 'verify', return_value={'guard_loaded': True}) as verify:
            self.assertTrue(m.start(UID)['guard_loaded'])
            self.assertEqual(nft.call_count, 2)
            verify.assert_called_once_with(UID)

    def test_verify_rejects_uid_change_and_unavailable_kernel_table(self):
        with patch.object(m, 'read_receipt', return_value={'uid': 777, 'token': TOKEN}), \
                patch.object(m, 'inspect_table') as inspect, self.assertRaises(ValueError):
            m.verify(UID)
        inspect.assert_not_called()
        with patch.object(m, 'read_receipt', return_value={'uid': UID, 'token': TOKEN}), \
                patch.object(m, 'inspect_table', side_effect=ValueError('missing')), self.assertRaises(ValueError):
            m.verify(UID)

    def test_stop_refuses_if_any_app_uid_process_remains(self):
        with patch.object(m, 'no_app_processes', side_effect=ValueError('running')), \
                patch.object(m, 'table_exists') as exists, patch.object(m, 'nft') as nft, self.assertRaises(ValueError):
            m.stop(UID)
        exists.assert_not_called(); nft.assert_not_called()

    def test_stop_never_deletes_unknown_or_modified_table(self):
        for error in (FileNotFoundError('no receipt'), ValueError('tampered')):
            with patch.object(m, 'no_app_processes'), patch.object(m, 'table_exists', return_value=True), \
                    patch.object(m, 'read_receipt', side_effect=error), patch.object(m, 'nft') as nft, self.assertRaises(type(error)):
                m.stop(UID)
            nft.assert_not_called()
        with patch.object(m, 'no_app_processes'), patch.object(m, 'table_exists', return_value=True), \
                patch.object(m, 'read_receipt', return_value={'uid': UID, 'token': TOKEN}), \
                patch.object(m, 'inspect_table', side_effect=ValueError('modified')), patch.object(m, 'nft') as nft, self.assertRaises(ValueError):
            m.stop(UID)
        nft.assert_not_called()

    def test_stop_only_deletes_verified_table_handle(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / 'receipt.json'; receipt.write_text('fixture')
            with patch.object(m, 'RECEIPT', receipt), patch.object(m, 'no_app_processes'), \
                    patch.object(m, 'table_exists', side_effect=[True, False]), \
                    patch.object(m, 'read_receipt', return_value={'uid': UID, 'token': TOKEN}), \
                    patch.object(m, 'inspect_table', return_value=(11, {})), patch.object(m, 'nft') as nft:
                self.assertTrue(m.stop(UID)['guard_removed'])
            nft.assert_called_once_with(['delete', 'table', 'inet', 'handle', '11'])
            self.assertFalse(receipt.exists())

    def test_nonroot_refused_before_nft_or_privileged_files(self):
        with patch.object(m.os, 'getuid', return_value=UID), patch.object(m, 'trusted') as trusted, \
                patch.object(m, 'nft') as nft, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(m.main(['verify']), 1)
        trusted.assert_not_called(); nft.assert_not_called()

    def test_process_check_includes_saved_and_fs_uids(self):
        for uids, blocked in (('0 0 0 0', False), ('0 0 1007 0', True), ('0 0 0 1007', True)):
            with patch.object(m.Path, 'iterdir', return_value=[Path('/proc/123')]), \
                    patch.object(m.Path, 'read_text', return_value='Name:\tfixture\nUid:\t' + uids + '\n'):
                if blocked:
                    with self.assertRaises(ValueError): m.no_app_processes(UID)
                else:
                    m.no_app_processes(UID)

    def test_trusted_path_rejects_writable_nonroot_and_symlink(self):
        for mode, owner in ((stat.S_IFREG | 0o664, 0), (stat.S_IFREG | 0o644, UID), (stat.S_IFLNK | 0o777, 0)):
            with patch.object(m.Path, 'lstat', return_value=SimpleNamespace(st_mode=mode, st_uid=owner)), self.assertRaises(ValueError):
                m.trusted(m.SELF)

    def test_nft_wrapper_uses_fixed_binary_clean_env_and_no_shell(self):
        with patch.object(m, 'trusted'), patch.object(m.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout='{}')) as run:
            self.assertEqual(m.nft(['--json', 'list', 'tables']), '{}')
        call = run.call_args
        self.assertEqual(call[0][0], ['/usr/sbin/nft', '--json', 'list', 'tables'])
        self.assertEqual(call[1]['env'], m.ENV)
        self.assertFalse(call[1]['shell'])
        for result in (SimpleNamespace(returncode=1, stdout='{}'), SimpleNamespace(returncode=0, stdout='x' * 131073)):
            with patch.object(m, 'trusted'), patch.object(m.subprocess, 'run', return_value=result), self.assertRaises(ValueError):
                m.nft(['--json', 'list', 'tables'])

    def test_unit_dependencies_and_privilege_split(self):
        for role in ('api', 'web'):
            unit = (REPO / ('deploy/native/aifinance-preview-' + role + '.service')).read_text()
            self.assertIn('BindsTo=aifinance-preview-egress.service', unit)
            after = [line.split('=', 1)[1].split() for line in unit.splitlines() if line.startswith('After=')]
            self.assertIn('aifinance-preview-egress.service', sum(after, []))
            self.assertIn('ExecStartPre=+/usr/bin/python3 -I -B /opt/aifinance/bin/egress-guard.py verify', unit)
            self.assertIn('User=aifinance\n', unit)
            self.assertIn('CapabilityBoundingSet=\nAmbientCapabilities=\n', unit)
            self.assertNotIn('ExecStart=+', unit)
        unit = (REPO / 'deploy/native/aifinance-preview-egress.service').read_text()
        self.assertIn('Type=oneshot\n', unit)
        self.assertIn('RemainAfterExit=yes\n', unit)
        self.assertIn('RuntimeDirectoryPreserve=yes\n', unit)
        self.assertNotIn('ExecStopPost=', unit)
        self.assertIn('FOURTH auxiliary unit', unit)


if __name__ == '__main__':
    unittest.main()
