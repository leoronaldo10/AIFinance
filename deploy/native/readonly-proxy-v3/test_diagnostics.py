"""Offline receive-path regression tests; all content below is synthetic.

Templates: aliyun/aliyun_assist_client commit
7f398b692b248dd91a64c8c2a98f476451ecb8e5,
agent/session/sessionresult/sessionresult.go. No historical payload is used.
"""
import contextlib
import io
import json
import time
import unittest
from unittest.mock import Mock, patch

import client as c
from test_client import frame, output_text


PREFIX = "The session has terminated. "
SECRET = "SYNTHETIC_PRIVATE_VALUE"
FIXTURES = (
    ("MalformedCommandLine", "Malformed commandLine `" + SECRET + "` can not be segmented correctly. synthetic failure.", "command_parse_failed"),
    ("UserNotExists", "User " + SECRET + " does not exist.", "user_missing"),
    ("ObtainUserIdentityFailed", "Failed to obtain identity of user " + SECRET + ": synthetic failure.", "user_identity_failed"),
    ("ObtainUserInfoFailed", "Failed to obtain user information of " + SECRET + ": synthetic failure.", "user_lookup_failed"),
    ("ShellCommandNotFound", "Look up shell command " + SECRET + " failed: synthetic failure.", "default_shell_lookup_failed"),
    ("ShellCommandPermissionDenied", "Shell command /" + SECRET + " lacks executable permissions: 600.", "default_shell_permission_failed"),
    ("ShellCommandPermissionDenied", "An error occurred while obtaining the shell command /" + SECRET + " permission. synthetic failure.", "default_shell_permission_failed"),
    ("HomeDirNotFound", "Home directory /" + SECRET + " is not found.", "home_missing"),
    ("HomeDirPermissionDenied", "Home directory /" + SECRET + " lacks readable permissions: 300.", "home_owner_read_missing"),
    ("HomeDirPermissionDenied", "Home directory /" + SECRET + " lacks executable permissions: 600.", "home_owner_exec_missing"),
    ("HomeDirPermissionDenied", "The home directory /" + SECRET + " belongs to an incorrect user 1001.", "home_owner_mismatch"),
    ("HomeDirPermissionDenied", "An error occurred while obtaining the home directory /" + SECRET + " permission. synthetic failure.", "home_stat_failed"),
    ("OpenPtyFailed", "An error occurred while starting the PTY. fork/exec /" + SECRET + ": permission denied.", "pty_or_process_start_failed"),
    ("KeyExchangeFailed", "An error occurred while exchanging key. " + SECRET + ".", "key_exchange_failed"),
    ("UnknownError", "Unknown error. " + SECRET + ".", "agent_unknown_error"),
)


class DiagnosticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.network = patch("socket.create_connection", side_effect=AssertionError("offline only"))
        cls.dns = patch("socket.getaddrinfo", side_effect=AssertionError("offline only"))
        cls.network.start()
        cls.dns.start()

    @classmethod
    def tearDownClass(cls):
        cls.dns.stop()
        cls.network.stop()

    def assert_problem(self, result, category):
        summary = result.summary()
        self.assertIn(category, summary["output_problems"])
        self.assertFalse(summary["all_checks_passed"])
        self.assertNotIn(SECRET, json.dumps(summary))

    def test_all_15_official_templates_every_byte_split_and_final_partial(self):
        self.assertEqual(len(FIXTURES), 15)
        for code, info, category in FIXTURES:
            raw = (PREFIX + code + ": " + info).encode()
            for ending in (b"", b"\n", b"\r\n"):
                data = raw + ending
                for split in range(len(data) + 1):
                    result = c.Results()
                    result.feed(data[:split])
                    result.feed(data[split:])
                    result.finish()
                    self.assertEqual(result.summary()["output_problems"], [category])
                    self.assert_problem(result, category)
                    self.assertEqual(result.buffer, b"")
                    self.assertEqual(result.values, {})

    def test_known_errors_block_fake_success_before_and_after_results(self):
        for code, info, category in FIXTURES:
            line = PREFIX + code + ": " + info + "\n"
            for text in (line + output_text(), output_text() + line):
                result = c.Results()
                result.feed(text.encode())
                result.finish()
                self.assertTrue(all(v["status"] == "pass" for v in result.summary()["checks"].values()))
                self.assert_problem(result, category)

    def test_error_during_result_sequence_does_not_advance_stage(self):
        lines = output_text().splitlines(keepends=True)
        for position in range(len(lines) + 1):
            result = c.Results()
            text = "".join(lines[:position]) + PREFIX + "UserNotExists: " + SECRET + "\n" + "".join(lines[position:])
            result.feed(text.encode())
            self.assertTrue(all(v["status"] == "pass" for v in result.summary()["checks"].values()))
            self.assert_problem(result, "user_missing")

    def test_unknown_codes_malformed_wrapper_never_echo_dynamic_data(self):
        for tail in (SECRET + ": " + SECRET, SECRET, "", " " * 3, "UserNotExistsSuffix: " + SECRET, "UserNotExists:" + SECRET):
            result = c.Results()
            result.feed((PREFIX + tail + "\n" + output_text()).encode())
            self.assert_problem(result, "agent_error_unknown_code")

    def test_home_templates_are_anchored_and_dynamic_values_never_returned(self):
        for _, info, category in FIXTURES[8:12]:
            self.assertEqual(c.agent_error_category(PREFIX + "HomeDirPermissionDenied: " + info), category)
            for malformed in ("unrelated " + info, info + " trailing", info[:-1]):
                self.assertEqual(c.agent_error_category(PREFIX + "HomeDirPermissionDenied: " + malformed), "home_permission_failed")
        for mode in ("800", "7777", SECRET):
            info = "Home directory /" + SECRET + " lacks readable permissions: " + mode + "."
            self.assertEqual(c.agent_error_category(PREFIX + "HomeDirPermissionDenied: " + info), "home_permission_failed")
        oversized = "An error occurred while obtaining the home directory /" + (" permission. " * 10000) + " permission. failure."
        self.assertEqual(c.agent_error_category(PREFIX + "HomeDirPermissionDenied: " + oversized), "home_permission_failed")

    def test_known_code_without_info_and_nonprefix_banner(self):
        self.assertEqual(c.agent_error_category(PREFIX + "UserNotExists"), "user_missing")
        self.assertIsNone(c.agent_error_category("Guide: " + PREFIX + "UserNotExists"))

    def test_multibyte_utf8_split_at_every_byte_is_not_replacement_decoded(self):
        data = (PREFIX + "HomeDirNotFound: Home directory /\u4e2d\U0001f642 is not found.\n").encode()
        for split in range(len(data) + 1):
            result = c.Results()
            result.feed(data[:split])
            result.feed(data[split:])
            result.finish()
            self.assertEqual(result.summary()["output_problems"], ["home_missing"])

    def test_invalid_and_truncated_utf8_are_redacted_and_block_success(self):
        for bad in (b"\xff", b"\xc0\xaf", b"\xed\xa0\x80", b"\xe4\xb8"):
            for data in (bad + b"\n" + output_text().encode(), output_text().encode() + bad):
                result = c.Results()
                result.feed(data)
                result.finish()
                self.assert_problem(result, "invalid_utf8")
                self.assertEqual(result.buffer, b"")

    def test_csi_fragmentation_and_unsupported_controls_fail_closed(self):
        data = ("\x1b[31m" + PREFIX + "UserNotExists: " + SECRET + "\x1b[0m\r\n").encode()
        result = c.Results()
        for byte in data:
            result.feed(bytes([byte]))
        self.assert_problem(result, "user_missing")
        for control in ("\x1b]0;" + SECRET + "\x07", "\x1bP" + SECRET + "\x1b\\", "\b", "\r", "\x00", "\x85", "\x9b", "\t"):
            result = c.Results()
            result.feed((SECRET + control + SECRET + "\n" + output_text()).encode())
            self.assert_problem(result, "unsupported_control_sequence")

    def test_output_bound_exact_limit_and_overflow_after_success(self):
        result = c.Results()
        result.feed(b"x" * 131072)
        self.assertEqual(len(result.buffer), 131072)
        with self.assertRaisesRegex(c.Stop, "^output_limit_exceeded$"):
            result.feed(b"x")
        self.assertEqual(result.buffer, b"")
        self.assert_problem(result, "output_limit_exceeded")
        result = c.Results()
        result.feed(output_text().encode())
        with self.assertRaises(c.Stop):
            result.feed(b"x" * 131072)
        self.assert_problem(result, "output_limit_exceeded")

    def test_unterminated_diagnostic_on_closed_no_send_no_reconnect(self):
        ws = Mock()
        diagnostic = (PREFIX + "OpenPtyFailed: " + SECRET).encode()
        ws.recv.side_effect = [frame(5, b"\x03"), frame(1, output_text().encode(), 1), frame(1, diagnostic, 2), frame(5, b"\x05")]
        manager = Mock()
        manager.__enter__ = Mock(return_value=ws)
        manager.__exit__ = Mock(return_value=False)
        with patch.object(c, "websocket_connect", return_value=manager) as connect, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(c.observe_session("SYNTHETIC_URL", "SYNTHETIC_TOKEN", None, time.monotonic() + 35), 1)
        connect.assert_called_once()
        ws.send.assert_not_called()
        manager.__exit__.assert_called_once()
        events = [json.loads(line) for line in output.getvalue().splitlines()]
        health = next(e for e in events if e["event"] == "health_results")
        self.assertFalse(health["all_checks_passed"])
        self.assertEqual(health["output_problems"], ["pty_or_process_start_failed"])
        self.assertIn('"remote_end": "channel_closed"', output.getvalue())
        self.assertNotIn("SYNTHETIC", output.getvalue())

    def test_all_reported_diagnostics_are_constant_not_payload_captures(self):
        result = c.Results()
        for code, info, _ in FIXTURES:
            result.feed((PREFIX + code + ": " + info + "\n").encode())
        result.feed((PREFIX + SECRET + ": https://synthetic.invalid/?token=" + SECRET + "\n").encode())
        summary = json.dumps(result.summary())
        for forbidden in (SECRET, "https://", "token=", "/dev/", "1001"):
            self.assertNotIn(forbidden, summary)
        self.assertFalse(result.summary()["all_checks_passed"])


if __name__ == "__main__":
    unittest.main()
