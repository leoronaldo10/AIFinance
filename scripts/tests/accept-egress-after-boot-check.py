"""Local mocks only; never run host nft/systemd, networking, or target operations.

Reviewed differences from accept-egress.sh: postboot evidence/owner name; absent
8000 before and after (no PID requirement); pager-safe systemctl calls; safe
line/status and 8000 cleanup diagnostics; corresponding comments/success text.
Everything else must remain byte-for-byte identical after those substitutions.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / 'deploy/native/accept-egress-after-boot.sh'
spec = importlib.util.spec_from_file_location('original_acceptance_tests', str(Path(__file__).with_name('accept-egress-check.py')))
original = importlib.util.module_from_spec(spec)
spec.loader.exec_module(original)


def replace_once(source, before, after):
    assert source.count(before) == 1, 'Reviewed source/fixture changed: ' + before
    return source.replace(before, after)


def local_command(name):
    path = shutil.which(name)
    if path is None:
        raise RuntimeError('Required local test command not found: ' + name)
    return path


def portable_test_utilities(script):
    # Debian Stretch is not usrmerged. Only the private mock copy uses local paths.
    for name in ('awk', 'sort', 'cmp', 'grep', 'mkdir', 'cat'):
        script = script.replace('/usr/bin/' + name, local_command(name))
    return script


# Reuse the reviewed command mocks and all their failure/cleanup scenarios.
FAKE = replace_once(original.FAKE,
    " if any('8000' in x for x in a): out('LISTEN 0 128 127.0.0.1:8000 0.0.0.0:* users:((\"old\",pid=800,fd=3)) uid:1000 ino:9 sk:7')",
    """ if any('8000' in x for x in a):
  s['port8000_queries']=s.get('port8000_queries',0)+1
  if scenario=='8000-query-failure': out(code=1)
  if scenario=='8000-cleanup-query-failure' and s.get('guard_loaded'): out(code=1)
  if scenario=='8000-occupied' or (scenario=='8000-changed' and s.get('guard_loaded')):
   out('LISTEN 0 128 127.0.0.1:8000 0.0.0.0:* users:(("unknown",pid=800,fd=3)) uid:1000 ino:9 sk:7')
  out()""")
FAKE = replace_once(FAKE, "{'packets':n,'bytes':n*40}",
                    "{'packets':n-1 if scenario=='counter-v4-stall-'+str(n) else n,'bytes':n*40}")
FAKE = replace_once(FAKE, "'packets':0 if scenario=='counter-failure' else n",
                    "'packets':0 if scenario=='counter-failure' else (n-1 if scenario=='counter-v6-stall-'+str(n) else n)")
FAKE = replace_once(FAKE,
    "  if 'spec.loader.exec_module(g)' in source: print('1007 '+'a'*32); raise SystemExit(0)",
    """  if 'spec.loader.exec_module(g)' in source:
   if scenario in ('existing-evidence','existing-receipt'):
    print('Existing acceptance directory or guard receipt',file=sys.stderr); raise SystemExit(1)
   print('1007 '+'a'*32); raise SystemExit(0)""")
FAKE = replace_once(FAKE, " if scenario=='table-conflict':",
                    " if scenario in ('table-conflict','guard-table-conflict'):")
FAKE = replace_once(FAKE, "'name':'aifinance_preview_probe'",
                    "'name':'aifinance_preview_egress_v1' if scenario=='guard-table-conflict' else 'aifinance_preview_probe'")
FAKE = replace_once(FAKE, "(isguard and s.get('guard_loaded'))",
                    "(isguard and (s.get('guard_loaded') or scenario=='guard-active'))")
FAKE = replace_once(FAKE, " # Successful transient units may be collected before cleanup.",
    """ if scenario=='wrong-memory-'+str(memory) and mode=='guarded': result['memory']['memory.limit_in_bytes']+=1
 if scenario=='wrong-uid' and mode=='guarded': result['memory']['uid']=0
 if scenario=='wrong-mode' and mode=='guarded': result['mode']='baseline'
 if scenario=='incomplete-network' and mode=='guarded': result['network'].pop()
 if scenario=='failed-network' and mode=='guarded': result['network'][0]['expectation_matched']=False
 if scenario=='failed-expectations' and mode=='guarded': result['expectations_matched']=False
 # Successful transient units may be collected before cleanup.""")


class RunnerTests(original.RunnerTests):
    def run_case(self, scenario):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, state, commands = root / 'evidence', root / 'state.json', root / 'bin'
            commands.mkdir()
            if scenario == 'existing-evidence':
                evidence.mkdir()
                (evidence / 'retained.txt').write_text('prior evidence\n')
            state.write_text(json.dumps({'scenario': scenario, 'addresses': [], 'units': {}, 'log': []}))
            script = SCRIPT.read_text().replace('[[ $# == 0 && $EUID == 0 ]]', '[[ $# == 0 ]]')
            script = replace_once(script, 'readonly EVIDENCE=/run/aifinance-egress-after-boot',
                                  'readonly EVIDENCE=' + str(evidence))
            for name, path in [('python3', '/usr/bin/python3'), ('systemctl', '/usr/bin/systemctl'),
                               ('systemd-run', '/usr/bin/systemd-run'), ('journalctl', '/usr/bin/journalctl'),
                               ('ss', '/usr/sbin/ss'), ('ip', '/usr/sbin/ip'), ('nft', '/usr/sbin/nft'),
                               ('sleep', '/usr/bin/sleep')]:
                tool = commands / name
                tool.write_text(FAKE)
                tool.chmod(0o755)
                script = script.replace(path, str(tool))
            script = portable_test_utilities(script)
            copy = root / 'test-only.sh'
            copy.write_text(script)
            result = subprocess.run([local_command('bash'), str(copy)], env=dict(os.environ, FAKE_STATE=str(state)),
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=20)
            data = json.loads(state.read_text())
            data['files'] = {p.name: p.read_text() for p in evidence.iterdir()} if evidence.exists() else {}
            data['result_file'] = data['files'].get('result.txt', '')
            return result, data

    def test_empty_8000_passes_complete_pinned_probe_sequence(self):
        result, state = self.run_case('success')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(state['files']['8000.before.txt'], '')
        self.assertEqual(state['files']['8000.after.txt'], '')
        self.assertIn('Port 8000 remains absent', result.stdout)
        sequence = []
        for command in state['log']:
            if command[0] == 'systemd-run':
                mode = command[command.index('/opt/aifinance/bin/isolation-probe.py') + 1]
                if mode != 'serve':
                    sequence.append((mode, command[command.index('--memory-limit-mib') + 1],
                                     next(arg for arg in command if arg.startswith('User='))))
            elif command[:2] == ['systemctl', 'start']:
                self.assertEqual(command, ['systemctl', 'start', '--no-pager', 'aifinance-preview-egress.service'])
                sequence.append('normal guard start')
            if command[0] == 'systemctl':
                self.assertIn('--no-pager', command)
        self.assertEqual(sequence, [('baseline', '64', 'User=aifinance'), 'normal guard start',
                                    ('guarded', '64', 'User=aifinance'), ('guarded', '320', 'User=aifinance'),
                                    ('guarded', '256', 'User=aifinance'), ('control', '64', 'User=root')])
        self.assertEqual(state['counter'], 3)
        self.assertEqual(state['addresses'], [])
        self.assertEqual(state['units'], {})
        self.assertTrue(state['guard_loaded'])

    def test_occupied_or_unreadable_8000_never_adds_addresses_or_starts_services(self):
        for scenario in ('8000-occupied', '8000-query-failure'):
            result, state = self.run_case(scenario)
            self.assertNotEqual(result.returncode, 0, scenario)
            self.assertNotIn('guard_attempted', state)
            self.assertFalse(any(c[0] == 'systemd-run' or (c[0] == 'ip' and 'add' in c) for c in state['log']))
            self.assertIn('Expected absent 8000 listener is occupied' if scenario == '8000-occupied'
                          else 'postboot acceptance command failed at line', result.stderr)

    def test_changed_or_unreadable_final_8000_fails_cleanup_retains_guard(self):
        for scenario in ('8000-changed', '8000-cleanup-query-failure'):
            result, state = self.run_case(scenario)
            self.assertNotEqual(result.returncode, 0, scenario)
            self.assertIn('Cleanup failed: ', result.stderr)
            self.assertIn('cleanup_failed=1', state['result_file'])
            self.assertIn('probe_passed=false', state['result_file'])
            self.assertEqual(state['addresses'], [])
            self.assertTrue(state['guard_loaded'])

    def test_each_family_counter_must_increase_for_every_guarded_budget(self):
        for family in (4, 6):
            for index, budget in enumerate((64, 320, 256), 1):
                scenario = 'counter-v%d-stall-%d' % (family, index)
                result, state = self.run_case(scenario)
                self.assertNotEqual(result.returncode, 0, scenario)
                self.assertIn('Missing per-family reject counter increase: guard.after%d:deny-v%d' % (budget, family),
                              result.stderr)
                self.assertIn('probe_passed=false', state['result_file'])

    def test_result_network_identity_and_each_memory_budget_still_fail_closed(self):
        for scenario in ('wrong-memory-64', 'wrong-memory-320', 'wrong-memory-256', 'wrong-uid', 'wrong-mode',
                         'incomplete-network', 'failed-network', 'failed-expectations'):
            result, state = self.run_case(scenario)
            self.assertNotEqual(result.returncode, 0, scenario)
            self.assertIn('probe_passed=false', state['result_file'])
            self.assertIn('Probe identity/result/memory mismatch' if scenario not in ('incomplete-network', 'failed-network')
                          else 'Incomplete network evidence', result.stderr)

    def test_existing_guard_or_evidence_fails_before_network_mutation(self):
        for scenario in ('guard-active', 'guard-table-conflict', 'existing-evidence', 'existing-receipt'):
            result, state = self.run_case(scenario)
            self.assertNotEqual(result.returncode, 0, scenario)
            self.assertNotIn('guard_attempted', state)
            self.assertFalse(any(c[0] == 'systemd-run' or (c[0] == 'ip' and 'add' in c) for c in state['log']))
            if scenario == 'existing-evidence':
                self.assertEqual(state['files'], {'retained.txt': 'prior evidence\n'})

    def test_command_failures_retain_safe_line_and_status_context(self):
        result, state = self.run_case('guard-failure')
        self.assertNotEqual(result.returncode, 0)
        self.assertRegex(result.stderr, r'postboot acceptance command failed at line [0-9]+ \(status 1\)')
        self.assertIn('guard.start.txt', state['files'])


class LocalPathTests(unittest.TestCase):
    def test_private_copy_uses_discovered_pre_usrmerge_paths(self):
        paths = {name: '/bin/' + name for name in ('bash', 'grep', 'mkdir', 'cat')}
        paths.update({name: '/usr/bin/' + name for name in ('awk', 'sort', 'cmp')})
        with patch.object(shutil, 'which', side_effect=paths.__getitem__):
            self.assertEqual(local_command('bash'), '/bin/bash')
            script = portable_test_utilities(SCRIPT.read_text())
        for name in ('grep', 'mkdir', 'cat'):
            self.assertNotIn('/usr/bin/' + name, script)
            self.assertIn('/bin/' + name, script)
        for name in ('awk', 'sort', 'cmp'):
            self.assertIn('/usr/bin/' + name, script)
        self.assertIn('#!/usr/bin/bash', SCRIPT.read_text())

    def test_missing_test_command_has_specific_failure(self):
        with patch.object(shutil, 'which', return_value=None):
            for name in ('bash', 'awk', 'sort', 'cmp', 'grep', 'mkdir', 'cat'):
                with self.assertRaisesRegex(RuntimeError, 'Required local test command not found: ' + name):
                    local_command(name)


class SourceContractTests(unittest.TestCase):
    def test_original_and_all_helper_pins_remain_unchanged(self):
        expected = {
            'accept-egress.sh': '3a72403f972bfd8b432394c375b225711d03bf5ee8acf453f0ecd09a9d329888',
            'egress-guard.py': '5c407c3916e1f44441f0a3962ea802d148084c281426ec0f809e9ad542913367',
            'isolation-probe.py': '46350936233416c282bd8941c063cdffb09bf138e5f4e29158afc236dfd8ac7e',
            'aifinance-preview-egress.service': 'e89d001be5bb1929553c1b219759a9f123da6484229af3264e954f072047773e',
        }
        for name, digest in expected.items():
            self.assertEqual(hashlib.sha256((REPO / 'deploy/native' / name).read_bytes()).hexdigest(), digest, name)
            if name != 'accept-egress.sh':
                self.assertIn(digest, SCRIPT.read_text())

    def test_only_documented_minimal_changes(self):
        source = SCRIPT.read_text().replace(' --no-pager', '').replace('aifinance-egress-after-boot', 'aifinance-egress-acceptance')
        # journalctl already used --no-pager in the original; restore it there.
        source = source.replace('journalctl -u "$unit" -n', 'journalctl -u "$unit" --no-pager -n')
        source = source.replace('journalctl -u "$LISTENER" -n', 'journalctl -u "$LISTENER" --no-pager -n')
        source = replace_once(source, '# One approved, bounded postboot run.', '# One approved, bounded acceptance run.')
        source = replace_once(source, '# Same pinned acceptance as accept-egress.sh; the approved 8000 state is absent.\n', '')
        source = replace_once(source, '# Retain the failing line/status without disclosing command arguments or environment.\n'
                              'trap \'rc=$?; echo "STOP: postboot acceptance command failed at line $LINENO (status $rc)" >&2\' ERR\n', '')
        source = replace_once(source, 'trap - EXIT INT TERM HUP ERR', 'trap - EXIT INT TERM HUP')
        source = replace_once(source,
            '  if ! port8000 >"$EVIDENCE/8000.after.txt"; then\n'
            "    echo 'Cleanup failed: cannot inspect 8000 listener state' >&2; cleanup_failed=1\n"
            '  fi\n'
            '  if [[ -s "$EVIDENCE/8000.after.txt" ]] || ! /usr/bin/cmp -s "$EVIDENCE/8000.before.txt" "$EVIDENCE/8000.after.txt"; then\n'
            "    echo 'Cleanup failed: 8000 must remain absent and unchanged' >&2; cleanup_failed=1\n"
            '  fi\n',
            '  port8000 >"$EVIDENCE/8000.after.txt" || cleanup_failed=1\n'
            '  /usr/bin/cmp -s "$EVIDENCE/8000.before.txt" "$EVIDENCE/8000.after.txt" || cleanup_failed=1\n')
        source = replace_once(source, 'Port 8000 remains absent;', 'Old 8000 socket/PID unchanged;')
        source = replace_once(source,
            '[[ ! -s "$EVIDENCE/8000.before.txt" ]] || fail \'Expected absent 8000 listener is occupied\'\n',
            '[[ -s "$EVIDENCE/8000.before.txt" ]] || fail \'Expected old 8000 listener is absent\'\n'
            '/usr/bin/grep -Eq \'pid=[0-9]+\' "$EVIDENCE/8000.before.txt" || fail \'Cannot identify old 8000 listener PID\'\n'
            'if /usr/bin/grep -Eq "(^|[[:space:]])uid:$APP_UID([[:space:]]|$)" "$EVIDENCE/8000.before.txt"; then fail \'Old 8000 socket belongs to app UID\'; fi\n')
        self.assertEqual(source, original.SCRIPT.read_text())


if __name__ == '__main__':
    unittest.main(verbosity=2)
