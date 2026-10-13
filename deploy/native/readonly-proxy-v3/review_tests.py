"""Independent offline review: no real credentials, network, or live entrypoint."""
import ast
import json
from pathlib import Path
import shlex
import unittest
from unittest.mock import patch
import client as c
from test_client import output_text

class IndependentReview(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.network = patch('socket.create_connection', side_effect=AssertionError('network forbidden'))
        cls.dns = patch('socket.getaddrinfo', side_effect=AssertionError('DNS forbidden'))
        cls.network.start(); cls.dns.start()
    @classmethod
    def tearDownClass(cls):
        cls.network.stop(); cls.dns.stop()
    def test_exact_unchanged_scope(self):
        old = (Path(__file__).parent / 'baseline/client.py').read_text()
        new = (Path(__file__).parent / 'client.py').read_text()
        def nodes(source):
            return {n.name: ast.get_source_segment(source, n) for n in ast.parse(source).body if isinstance(n, (ast.ClassDef, ast.FunctionDef))}
        a,b=nodes(old),nodes(new)
        self.assertEqual(set(b)-set(a), {'agent_error_category'})
        self.assertEqual(set(a)-set(b), set())
        self.assertEqual([n for n in a if a[n]!=b[n]], ['Results'])
        self.assertEqual(old.split('def agent_error_category')[0].split('class Results:')[0], new.split('def agent_error_category')[0])
        self.assertFalse(c.LIVE_EXECUTION_ENABLED)
        self.assertEqual((len(c.COMMAND),len(c.fixed_command_line())),(454,499))
        self.assertEqual(shlex.split(c.fixed_command_line()), ['/bin/sh','-c',c.COMMAND])
    def test_known_unknown_codes_block_before_and_after_success(self):
        codes=['MalformedCommandLine','UserNotExists','ObtainUserIdentityFailed','ObtainUserInfoFailed','ShellCommandNotFound','ShellCommandPermissionDenied','HomeDirNotFound','HomeDirPermissionDenied','OpenPtyFailed','KeyExchangeFailed','UnknownError','SENSITIVE_UNKNOWN_CODE']
        for code in codes:
            error=('The session has terminated. '+code+': SENSITIVE_DYNAMIC_INFO\n').encode()
            for payload in [error+output_text().encode(),output_text().encode()+error]:
                r=c.Results(); r.feed(payload); r.finish()
                s=r.summary(); self.assertFalse(s['all_checks_passed']); self.assertTrue(s['output_problems'])
                self.assertNotIn('SENSITIVE',json.dumps(s))
    def test_utf8_every_byte_and_closed_tail(self):
        raw='The session has terminated. UserNotExists: User 秘密用户 does not exist.'.encode()
        for split in range(len(raw)+1):
            r=c.Results(); r.feed(raw[:split]); r.feed(raw[split:]); r.finish()
            self.assertEqual(r.summary()['output_problems'],['user_missing'])
            self.assertEqual(r.buffer,b'')
    def test_bad_bytes_and_controls_block_success(self):
        for bad in [b'\xff\n', b'\xe7\xa7', b'\x1b]0;SENSITIVE\x07\n', b'\x1bPSENSITIVE\x1b\\\n', b'a\bb\n',b'\0\n']:
            r=c.Results(); r.feed(output_text().encode()); r.feed(bad); r.finish()
            s=r.summary(); self.assertFalse(s['all_checks_passed']); self.assertTrue(s['output_problems'])
            self.assertNotIn('SENSITIVE',json.dumps(s))
    def test_total_bound_and_summary_fail_closed(self):
        r=c.Results(); r.feed(output_text().encode()); r.feed(b'x'*(131072-r.total_bytes))
        self.assertLessEqual(len(r.buffer),131072)
        with self.assertRaises(c.Stop): r.feed(b'x')
        self.assertEqual(r.buffer,b''); self.assertFalse(r.summary()['all_checks_passed'])
    def test_home_full_template_and_fallback(self):
        p='The session has terminated. HomeDirPermissionDenied: '
        cases={
            'Home directory /SENSITIVE lacks readable permissions: 300.':'home_owner_read_missing',
            'Home directory /SENSITIVE lacks executable permissions: 600.':'home_owner_exec_missing',
            'The home directory /SENSITIVE belongs to an incorrect user 1001.':'home_owner_mismatch',
            'An error occurred while obtaining the home directory /SENSITIVE permission. SENSITIVE.':'home_stat_failed',
        }
        for info,expected in cases.items():
            self.assertEqual(c.agent_error_category(p+info),expected)
            self.assertEqual(c.agent_error_category(p+info+' suffix'),'home_permission_failed')
            self.assertEqual(c.agent_error_category(p+'prefix '+info),'home_permission_failed')
        self.assertEqual(c.agent_error_category(p+'Home directory /SENSITIVE lacks readable permissions: 888.'),'home_permission_failed')
        template = 'Home directory /{} lacks readable permissions: 300.'
        bounded = template.format('x' * (4096 - len(template.format(''))))
        self.assertEqual(len(bounded), 4096)
        self.assertEqual(c.agent_error_category(p+bounded), 'home_owner_read_missing')
        with patch.object(c.re, 'fullmatch', side_effect=AssertionError('oversized Info reached regex')):
            self.assertEqual(c.agent_error_category(p+bounded+'x'), 'home_permission_failed')
            self.assertEqual(c.agent_error_category(p+' permission. '*10000), 'home_permission_failed')

if __name__=='__main__': unittest.main()
