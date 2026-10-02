"""Local unit tests. No host networking/firewall/cgroup writes or target access."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('isolation_probe', str(REPO / 'deploy/native/isolation-probe.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
GOOD = {'connected': True, 'token_ok': True, 'error': None}
BLOCK = {'connected': False, 'token_ok': False, 'error': 'EACCES'}


class ProbeTests(unittest.TestCase):
    def test_fixed_targets_and_no_arbitrary_destination(self):
        self.assertEqual([x[1] for x in m.TARGETS], ['127.0.0.1', '::1', '192.0.2.254', '2001:db8:ffff::254'])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            m.main(['baseline', '--target', 'example.com'])

    def test_baseline_must_reach_every_target(self):
        with patch.object(m, 'connect_target', side_effect=[dict(GOOD), dict(GOOD), dict(BLOCK), dict(BLOCK)]):
            self.assertFalse(m.observe('baseline')[0])

    def test_all_network_unavailable_is_not_success(self):
        with patch.object(m, 'connect_target', side_effect=lambda *a: dict(BLOCK)):
            self.assertFalse(m.observe('guarded')[0])
            self.assertFalse(m.observe('control')[0])

    def test_each_family_needs_block_and_loopback_success(self):
        for values, expected in (([GOOD, GOOD, BLOCK, BLOCK], True), ([GOOD, GOOD, BLOCK, GOOD], False),
                                 ([GOOD, GOOD, GOOD, BLOCK], False), ([BLOCK, GOOD, BLOCK, BLOCK], False)):
            with patch.object(m, 'connect_target', side_effect=[dict(v) for v in values]):
                self.assertEqual(m.observe('guarded')[0], expected)

    def test_connected_socket_with_failed_reply_is_not_blocked(self):
        client = MagicMock()
        client.__enter__.return_value = client
        client.recv.side_effect = OSError(104, 'reset after connect')
        with patch.object(m.socket, 'socket', return_value=client):
            result = m.connect_target(m.socket.AF_INET, '192.0.2.254')
        self.assertTrue(result['connected'])
        self.assertFalse(result['token_ok'])

    def test_one_ready_batch_cannot_exceed_64_accepts(self):
        server = MagicMock()
        server.accept.return_value = (MagicMock(), ('127.0.0.1', 12345))
        key = SimpleNamespace(fileobj=server)
        ready = (key, m.selectors.EVENT_READ)
        selector = MagicMock()
        selector.__enter__.return_value = selector
        # Reach 63 accepts, then return a batch with four ready listeners.
        selector.select.side_effect = [[ready] * 4 for _ in range(15)] + [[ready] * 3, [ready] * 4]
        with patch.object(m.socket, 'socket', return_value=server), \
                patch.object(m.selectors, 'DefaultSelector', return_value=selector), \
                patch.object(m.time, 'monotonic', return_value=0), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(m.serve(), 64)
        self.assertEqual(server.accept.call_count, 64)

    def test_successful_pattern_does_not_accept_isolation(self):
        with patch.object(m.os, 'getuid', return_value=1001), patch.object(m.os, 'geteuid', return_value=1001), \
                patch.object(m.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=1001)), \
                patch.object(m, 'memory_evidence', return_value={'memory.limit_in_bytes': 67108864}), \
                patch.object(m, 'observe', return_value=(True, [])), contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main(['guarded']), 0)
        value = json.loads(out.getvalue())
        self.assertTrue(value['expectations_matched'])
        self.assertFalse(value['isolation_accepted'])
        self.assertFalse(value['ready_for_deploy'])

    def test_root_cannot_run_app_probe(self):
        with patch.object(m.os, 'getuid', return_value=0), patch.object(m.os, 'geteuid', return_value=0), \
                patch.object(m.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=1001)), \
                patch.object(m, 'memory_evidence', side_effect=AssertionError('must refuse first')), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(m.main(['guarded']), 1)

    def memory_fixture(self, mismatch=False, no_pid=False):
        base = '/sys/fs/cgroup/memory/system.slice/aifinance-isolation-probe.service/'
        values = {'/proc/self/cgroup': '7:memory:/system.slice/aifinance-isolation-probe.service\n',
                  '/proc/self/mountinfo': '29 21 0:26 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n',
                  base + 'cgroup.procs': '' if no_pid else '4321\n',
                  base + 'memory.limit_in_bytes': '999999' if mismatch else '67108864',
                  base + 'memory.usage_in_bytes': '10485760', base + 'memory.max_usage_in_bytes': '12582912',
                  base + 'memory.failcnt': '0'}
        return values

    def test_reads_real_controller_limit_and_pid(self):
        values = self.memory_fixture()
        with patch.object(m.Path, 'read_text', lambda p: values[str(p)]), \
                patch.object(m.Path, 'exists', return_value=False), patch.object(m.os, 'getpid', return_value=4321):
            self.assertEqual(m.memory_evidence(64)['memory.limit_in_bytes'], 67108864)
            self.assertFalse(m.memory_evidence(64)['pressure_or_oom_tested'])
        for options in ({'mismatch': True}, {'no_pid': True}):
            values = self.memory_fixture(**options)
            with patch.object(m.Path, 'read_text', lambda p: values[str(p)]), \
                    patch.object(m.Path, 'exists', return_value=False), patch.object(m.os, 'getpid', return_value=4321), \
                    self.assertRaises(ValueError):
                m.memory_evidence(64)

    def test_v2_or_root_cgroup_is_not_v1_proof(self):
        for value in ('0::/\n', '7:memory:/\n'):
            with patch.object(m.Path, 'read_text', return_value=value), self.assertRaises(ValueError):
                m.memory_evidence(64)


if __name__ == '__main__':
    unittest.main()
