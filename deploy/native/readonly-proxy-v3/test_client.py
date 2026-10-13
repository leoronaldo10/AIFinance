"""Offline tests only. Network creation is blocked throughout this suite."""
import contextlib
import datetime as dt
import hashlib
import io
import json
import os
import ssl
import struct
import sys
import time
import unittest
from unittest.mock import Mock, patch
import urllib.parse

import client as c


def frame(kind, payload=b"", seq=0, channel=b"ch", instance=b"", version=b"1.02"):
    return (struct.pack("<I", kind) + version + bytes([len(channel)]) + channel +
            bytes([len(instance)]) + instance + struct.pack("<QIIHBB", 123, 0, seq,
                                                           len(payload), 0, 0) + payload)


def output_text():
    return ("uid=1001(aifinance-deploy) gid=1001(aifinance-deploy) groups=1001(aifinance-deploy)\n"
            + c.HOSTNAME + "\nactive\nactive\n" + c.RELEASE + "\nweb_http=200\napi_http=200\n")


class ClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.network = patch("socket.create_connection", side_effect=AssertionError("offline test attempted network"))
        cls.dns = patch("socket.getaddrinfo", side_effect=AssertionError("offline test attempted DNS"))
        cls.network.start()
        cls.dns.start()

    @classmethod
    def tearDownClass(cls):
        cls.network.stop()
        cls.dns.stop()

    def test_official_signature_vector(self):
        # Public Alibaba Cloud V3 vector, no real credentials.
        headers = {"host": "ecs.cn-shanghai.aliyuncs.com", "x-acs-action": "RunInstances",
                   "x-acs-version": "2014-05-26", "x-acs-date": "2023-10-26T10:22:32Z",
                   "x-acs-signature-nonce": "3156853299f313e23d1673dc12e1703d",
                   "x-acs-content-sha256": hashlib.sha256(b"").hexdigest()}
        query = "ImageId=win2019_1809_x64_dtc_zh-cn_40G_alibase_20230811.vhd&RegionId=cn-shanghai"
        result = c.authorization("POST", query, headers, "YourAccessKeyId", "YourAccessKeySecret")
        self.assertTrue(result.endswith("Signature=06563a9e1b43f5dfe96b81484da74bceab24a1d853912eee15083a6f0f3283c0"))

    def test_exact_request_scope(self):
        path, headers = c.make_request(("FAKE_ID", "FAKE_SECRET", "FAKE_STS"))
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
        self.assertEqual(set(query), {"RegionId", "InstanceId.1", "Username", "ConnectionType", "CommandLine", "ClientToken"})
        self.assertEqual(query["InstanceId.1"], ["i-2zedybs3fftu1d9vnx39"])
        self.assertEqual(query["Username"], ["aifinance-deploy"])
        self.assertEqual(query["CommandLine"], [c.fixed_command_line()])
        self.assertEqual(len(c.COMMAND), 454)
        self.assertTrue(c.COMMAND.startswith('test "$(id -un)" = aifinance-deploy || exit 10;'))
        self.assertTrue(c.COMMAND.endswith("; exit"))
        self.assertEqual(headers["x-acs-action"], "StartTerminalSession")
        self.assertEqual(headers["x-acs-security-token"], "FAKE_STS")
        self.assertIn("x-acs-security-token", headers["authorization"])
        self.assertNotIn("FAKE_", path)

    def test_encoding_roundtrip(self):
        query = c.canonical_query({"z": " +&/*~汉", "a": ""})
        self.assertEqual(query, "a=&z=%20%2B%26%2F%2A~%E6%B1%89")

    def test_proxy_required(self):
        with patch.object(c.urllib.request, "getproxies", return_value={}):
            with self.assertRaises(c.Stop):
                c.require_proxy()

    def test_explicit_proxy_overrides_bypass(self):
        with patch.object(c.urllib.request, "getproxies", return_value={"https": "http://proxy.invalid:8080", "no": "*"}):
            proxy = c.require_proxy()
            self.assertEqual(proxy.host, "proxy.invalid")
            self.assertEqual(proxy.port, 8080)

    def test_unsupported_proxy_rejected(self):
        for value in ("socks5://proxy.invalid", "https://proxy.invalid", "http://proxy.invalid/path", "http://proxy.invalid:99999"):
            with patch.object(c.urllib.request, "getproxies", return_value={"https": value}):
                with self.assertRaises(c.Stop):
                    c.require_proxy()

    def test_tls_verifies_host_and_certificate(self):
        ctx = c.tls_context()
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)

    def test_api_only_tunnels_fixed_host(self):
        proxy = c.Proxy("http://proxy.invalid:8080", "proxy.invalid", 8080, None)
        conn = c.api_connection(proxy, 12)
        self.assertEqual((conn.host, conn.port), ("proxy.invalid", 8080))
        self.assertEqual((conn._tunnel_host, conn._tunnel_port), (c.API_HOST, 443))
        conn.close()

    def test_validate_session_endpoint(self):
        body = {"SessionId": "s-test", "SecurityToken": "FAKE_SESSION_TOKEN",
                "WebSocketUrl": "wss://" + c.WSS_HOST + "/session?sessionId=s-test&token=FAKE_SESSION_TOKEN"}
        self.assertEqual(c.validate_session(body)[1], "s-test")
        for url in ("ws://" + c.WSS_HOST + "/session", "wss://other.invalid/session",
                    "wss://" + c.WSS_HOST + ":444/session", "wss://user@" + c.WSS_HOST + "/session",
                    body["WebSocketUrl"] + "#fragment", body["WebSocketUrl"].replace("token=", "different=")):
            with self.assertRaises(c.Stop):
                c.validate_session({**body, "WebSocketUrl": url})

    def test_query_duplicates_extras_and_controls_rejected(self):
        url = "wss://" + c.WSS_HOST + "/session?sessionId=s-test&token=FAKE_SESSION_TOKEN"
        body = {"SessionId": "s-test", "SecurityToken": "FAKE_SESSION_TOKEN"}
        for candidate in (url+"&token=", url+"&sessionId=", url+"&extra=1",
                          url+"&token=FAKE_SESSION_TOKEN", url+"&sessionId=s-test",
                          url+"\n", "\t"+url, url.replace("/session", "\\session")):
            with self.assertRaises(c.Stop):
                c.validate_session({**body, "WebSocketUrl": candidate})

    def test_api_rejection_single_attempt_and_redacted(self):
        conn = Mock()
        response = conn.getresponse.return_value
        response.status = 403
        response.read.return_value = json.dumps({"Code": "Forbidden.RAM", "RequestId": "req-safe",
                                                  "Message": "FAKE_STS https://sensitive.invalid/token"}).encode()
        captured = io.StringIO()
        with patch.object(c, "api_connection", return_value=conn), contextlib.redirect_stdout(captured):
            with self.assertRaises(c.Stop):
                c.start_one_session(None, ("FAKE_ID", "FAKE_SECRET", "FAKE_STS"))
        conn.request.assert_called_once()
        conn.close.assert_called_once()
        text = captured.getvalue()
        self.assertIn("Forbidden.RAM", text)
        self.assertIn("req-safe", text)
        self.assertNotIn("FAKE_", text)
        self.assertNotIn("https://", text)

    def test_api_success_secrets_stay_in_memory(self):
        conn = Mock()
        response = conn.getresponse.return_value
        response.status = 200
        response.read.return_value = json.dumps({"RequestId": "req-safe", "SessionId": "s-test",
           "SecurityToken": "FAKE_SESSION_TOKEN", "WebSocketUrl": "wss://" + c.WSS_HOST +
           "/session?sessionId=s-test&token=FAKE_SESSION_TOKEN"}).encode()
        captured = io.StringIO()
        with patch.object(c, "api_connection", return_value=conn), contextlib.redirect_stdout(captured):
            result = c.start_one_session(None, ("FAKE_ID", "FAKE_SECRET", "FAKE_STS"))
        self.assertEqual(result[1], "FAKE_SESSION_TOKEN")
        self.assertNotIn("FAKE_", captured.getvalue())
        self.assertNotIn("wss://", captured.getvalue())
        conn.request.assert_called_once()

    def test_bad_allocated_url_still_reports_safe_session_id(self):
        conn = Mock()
        response = conn.getresponse.return_value
        response.status = 200
        response.read.return_value = json.dumps({"RequestId": "req-safe", "SessionId": "s-cleanup",
            "SecurityToken": "FAKE_SESSION_TOKEN", "WebSocketUrl": "wss://unapproved.invalid/session"}).encode()
        captured = io.StringIO()
        with patch.object(c, "api_connection", return_value=conn), contextlib.redirect_stdout(captured):
            with self.assertRaises(c.Stop):
                c.start_one_session(None, ("FAKE_ID", "FAKE_SECRET", "FAKE_STS"))
        self.assertIn('"SessionId": "s-cleanup"', captured.getvalue())
        self.assertNotIn("FAKE_", captured.getvalue())
        self.assertNotIn("unapproved.invalid", captured.getvalue())

    def test_protocol_golden_wire_frame(self):
        # Independently specified 30-byte empty-ID header + 2-byte payload.
        raw = bytes.fromhex("01000000312e3032000001000000000000000000000001000000020000006869")
        msg = c.decode_frame(raw)
        self.assertEqual((msg.kind, msg.version, msg.channel, msg.instance), (1, "1.02", "", ""))
        self.assertEqual((msg.timestamp, msg.input_seq, msg.output_seq, msg.payload), (1, 0, 1, b"hi"))

    def test_protocol_malformed_and_foreign_rejected(self):
        valid = frame(1, b"hi", seq=1)
        samples = [b"", valid[:-1], valid + b"x", frame(1, instance=b"i-other"),
                   frame(99), frame(1, version=b"ABCD"), "text frame"]
        for raw in samples:
            with self.assertRaises(c.Stop):
                c.decode_frame(raw)

    def test_both_supported_versions_unchanged(self):
        for version in (b"1.01", b"1.02"):
            with self.subTest(version=version), contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(c.decode_frame(frame(1, version=version)).version, version.decode())
                self.assertEqual(out.getvalue(), "")

    def test_numeric_agent_versions_are_metadata(self):
        for version in (b"0.00", b"1.03", b"9.99"):
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(c.decode_frame(frame(1, version=version)).version, version.decode())
            self.assertEqual(out.getvalue(), "")

    def test_invalid_ascii_versions_redacted(self):
        for version in (b"ABCD", b"1.2x", b"12.3", b"1..2", b"1234", b"1.2\n", b"\x001.2", b"\x1b[0m"):
            with self.subTest(version=version), contextlib.redirect_stdout(io.StringIO()) as out:
                with self.assertRaisesRegex(c.Stop, "^unsupported_protocol_version$"):
                    c.decode_frame(frame(1, version=version))
            self.assertEqual(json.loads(out.getvalue()),
                             {"event": "protocol_version_rejected", "version_format": "invalid_or_redacted"})

    def test_non_ascii_and_truncated_versions_do_not_leak(self):
        samples = [frame(1, version=b"\xff.99"), bytes.fromhex("01000000312e30")]
        for raw in samples:
            with self.subTest(raw=raw), contextlib.redirect_stdout(io.StringIO()) as out:
                with self.assertRaises(c.Stop) as stopped:
                    c.decode_frame(raw)
            self.assertIn(str(stopped.exception), ("malformed_protocol_frame", "invalid_protocol_frame"))
            self.assertEqual(out.getvalue(), "")

    def test_version_diagnostic_excludes_identifiers_and_payload(self):
        raw = frame(1, b"FAKE_PAYLOAD_SECRET", channel=b"FAKE_CHANNEL_SECRET",
                    instance=b"FAKE_INSTANCE_SECRET", version=b"9.99")
        with contextlib.redirect_stdout(io.StringIO()) as out:
            with self.assertRaisesRegex(c.Stop, "^unexpected_protocol_instance$"):
                c.decode_frame(raw)
        self.assertEqual(out.getvalue(), "")
        self.assertNotIn("FAKE", out.getvalue())

    def test_nonempty_ids_fixed_wire_offsets(self):
        # Independent literal bytes: channel 'ch', instance is the fixed target;
        # timestamp 0x0102030405060708, input 0x0a0b0c0d, output 0x01020304.
        raw = bytes.fromhex(
            "01000000392e393902636816692d327a65647962733366667475316439766e783339"
            "08070605040302010d0c0b0a04030201020000006869")
        msg = c.decode_frame(raw)
        self.assertEqual((msg.kind, msg.version, msg.channel, msg.instance),
                         (1, "9.99", "ch", c.INSTANCE))
        self.assertEqual((msg.timestamp, msg.input_seq, msg.output_seq, msg.payload),
                         (0x0102030405060708, 0x0a0b0c0d, 0x01020304, b"hi"))

    def test_invalid_version_observation_stops_without_send_or_retry(self):
        ws = Mock()
        ws.recv.return_value = frame(1, b"FAKE_PAYLOAD_SECRET", version=b"ABCD")
        manager = Mock()
        manager.__enter__ = Mock(return_value=ws)
        manager.__exit__ = Mock(return_value=False)
        with patch.object(c, "websocket_connect", return_value=manager) as connect, contextlib.redirect_stdout(io.StringIO()) as out:
            with self.assertRaisesRegex(c.Stop, "^unsupported_protocol_version$"):
                c.observe_session("FAKE_URL", "FAKE_TOKEN", None, time.monotonic()+10)
        connect.assert_called_once()
        ws.recv.assert_called_once()
        ws.send.assert_not_called()
        manager.__exit__.assert_called_once()
        events = [json.loads(line) for line in out.getvalue().splitlines()]
        health = next(event for event in events if event["event"] == "health_results")
        self.assertFalse(health["all_checks_passed"])
        self.assertTrue(all(check["status"] == "not_observed" for check in health["checks"].values()))
        self.assertNotIn("FAKE", out.getvalue())

    def test_new_agent_version_completes_without_outbound_frames(self):
        ws = Mock()
        ws.recv.side_effect = [frame(5, b"\x03", version=b"9.99"),
                              frame(1, output_text().encode(), 1, version=b"9.99"),
                              frame(5, b"\x06", version=b"9.99")]
        manager = Mock()
        manager.__enter__ = Mock(return_value=ws)
        manager.__exit__ = Mock(return_value=False)
        with patch.object(c, "websocket_connect", return_value=manager) as connect, contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(c.observe_session("FAKE", "FAKE", None, time.monotonic()+35), 0)
        connect.assert_called_once()
        ws.send.assert_not_called()
        events = [json.loads(line) for line in out.getvalue().splitlines()]
        self.assertEqual([e for e in events if e["event"] == "agent_version"],
                         [{"event": "agent_version", "observed_version": "9.99"}])
        self.assertNotIn("FAKE", out.getvalue())
        self.assertTrue(all(0 < call.kwargs["timeout"] <= 30 for call in ws.recv.call_args_list))

    def test_new_version_does_not_bypass_structure_checks(self):
        valid = frame(1, b"hi", version=b"9.99", channel=b"", instance=b"")
        samples = [valid[:-1], valid+b"x", frame(99, version=b"9.99"),
                   frame(1, instance=b"foreign", version=b"9.99"),
                   valid[:26]+b"\x03\x00"+valid[28:],
                   valid[:28]+b"\x01"+valid[29:],
                   valid[:29]+b"\x01"+valid[30:],
                   b"x"*66076, valid[:8]+b"\xff"+valid[9:]]
        for raw in samples:
            with self.subTest(raw=raw[:8]), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(c.Stop):
                    c.decode_frame(raw)

    def test_new_version_output_limit_remains_enforced(self):
        results = c.Results()
        with self.assertRaisesRegex(c.Stop, "^output_limit_exceeded$"):
            results.feed(b"x" * 131073)

    def test_short_deadlines_and_expiration_protection(self):
        # Entire environment is fake; no injected credentials are read.
        fake = {key: "FAKE" for key in c.KEYS}
        with patch.dict(os.environ, fake, clear=True), patch.object(c, "LIVE_EXECUTION_ENABLED", True), patch.object(sys, "argv", ["client.py", "--run-one-session"]), patch.object(c.resource, "setrlimit"), patch.object(c.signal, "signal"), patch.object(c.signal, "setitimer") as timer, patch.object(c.logging, "disable"), patch.object(c.time, "monotonic", return_value=100), patch.object(c, "EXPIRATION", dt.datetime.max.replace(tzinfo=dt.timezone.utc)), patch.object(c, "require_proxy", return_value=None), patch.object(c, "start_one_session", return_value=("FAKE", "FAKE")), patch.object(c, "observe_session", return_value=0) as observe, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(c.main(), 0)
            observe.assert_called_once_with("FAKE", "FAKE", None, 135)
            self.assertEqual(timer.call_args_list[0].args, (c.signal.ITIMER_REAL, 40))
            self.assertEqual(timer.call_args_list[-1].args, (c.signal.ITIMER_REAL, 0))
        with patch.dict(os.environ, fake, clear=True), patch.object(c, "LIVE_EXECUTION_ENABLED", True), patch.object(sys, "argv", ["client.py", "--run-one-session"]), patch.object(c.resource, "setrlimit"), patch.object(c.signal, "signal"), patch.object(c.signal, "setitimer"), patch.object(c.logging, "disable"), patch.object(c, "EXPIRATION", dt.datetime.min.replace(tzinfo=dt.timezone.utc)), patch.object(c, "start_one_session") as start, contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(c.main(), 1)
            start.assert_not_called()
            self.assertIn("credential_expired_or_insufficient_remaining_lifetime", out.getvalue())

    def test_common_error_categories_redact_entire_lines(self):
        samples = {
            "command_not_found": ["bash: line 1: FAKE_SECRET: command not found", "/bin/sh: 1: FAKE_SECRET: not found"],
            "permission_denied": ["bash: /FAKE_SECRET: Permission denied", "curl: /FAKE_SECRET: Permission denied"],
            "shell_parsing_error": ["bash: -c: line 1: syntax error near unexpected token `FAKE_SECRET'", "/bin/sh: 1: Syntax error: FAKE_SECRET unexpected"],
        }
        for category, lines in samples.items():
            for line in lines:
                with self.subTest(category=category, line=line):
                    r = c.Results()
                    r.feed((line+"\n").encode())
                    summary = r.summary()
                    self.assertEqual(summary["output_problems"], [category])
                    self.assertFalse(summary["all_checks_passed"])
                    self.assertNotIn("FAKE", json.dumps(summary))
                    self.assertEqual(r.values, {})

    def test_error_phrase_in_banner_is_not_classified(self):
        for text in ("Welcome, Permission denied is an example", "Guide: command not found troubleshooting", "FAKE_SECRET", "bash: line 1: foo: command not found trailing text"):
            r = c.Results()
            r.feed((text+"\n").encode())
            self.assertEqual(r.summary()["output_problems"], [])
            self.assertFalse(r.summary()["all_checks_passed"])
            self.assertNotIn(text, json.dumps(r.summary()))

    def test_classified_error_blocks_success_even_with_all_results(self):
        for text in ("bash: foo: command not found", "sh: /fake: Permission denied", "sh: Syntax error: unexpected token"):
            r = c.Results()
            r.feed((text+"\n"+output_text()).encode())
            self.assertTrue(all(v["status"] == "pass" for v in r.summary()["checks"].values()))
            self.assertFalse(r.summary()["all_checks_passed"])

    def test_fragmented_error_and_partial_final_line_redacted(self):
        r = c.Results()
        for part in (b"bash: line 1: FAKE_", b"SECRET: command not ", b"found"):
            r.feed(part)
        r.finish()
        self.assertEqual(r.summary()["output_problems"], ["command_not_found"])
        self.assertNotIn("FAKE", json.dumps(r.summary()))

    def test_fixed_command_plaintext_transport_and_shell_syntax(self):
        import subprocess
        query = c.canonical_query(c.fixed_parameters())
        self.assertEqual(urllib.parse.parse_qs(query)["CommandLine"], [c.fixed_command_line()])
        self.assertLessEqual(len(c.COMMAND), 512)
        self.assertNotIn("\n", c.COMMAND)
        self.assertNotIn("\r", c.COMMAND)
        for shell in ("/bin/sh", "/bin/bash"):
            checked = subprocess.run([shell, "-n"], input=c.COMMAND, text=True,
                                     capture_output=True, env={"PATH": "/usr/bin:/bin"}, timeout=5)
            self.assertEqual(checked.returncode, 0)

    def test_shell_wrapper_exact_three_arguments(self):
        import shlex
        line = c.fixed_parameters()["CommandLine"]
        self.assertEqual(shlex.split(line), ["/bin/sh", "-c", c.COMMAND])
        self.assertEqual(len(line), 499)
        self.assertLessEqual(len(line.encode("ascii")), 512)
        self.assertEqual(c.COMMAND, shlex.split(line)[2])

    def test_shell_wrapper_limit_fails_before_api(self):
        with patch.object(c, "COMMAND", "x" * 513):
            with self.assertRaisesRegex(c.Stop, "^fixed_command_line_too_long$"):
                c.fixed_parameters()

    def test_shell_wrapper_query_roundtrip_preserves_argument(self):
        import shlex
        path, _ = c.make_request(("FAKE_ID", "FAKE_SECRET", "FAKE_STS"))
        line = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)["CommandLine"][0]
        self.assertEqual(shlex.split(line), ["/bin/sh", "-c", c.COMMAND])
        self.assertNotIn("FAKE", line)
        self.assertTrue(shlex.split(line)[2].startswith('test "$(id -un)" = aifinance-deploy || exit 10;'))
        self.assertTrue(shlex.split(line)[2].endswith('; exit'))

    def test_fragmented_health_output(self):
        results = c.Results()
        data = output_text().encode()
        for start in range(0, len(data), 7):
            results.feed(data[start:start+7])
        results.finish()
        self.assertTrue(results.summary()["all_checks_passed"])

    def test_identity_mismatch_stops(self):
        with self.assertRaises(c.Stop):
            c.Results().feed(b"uid=0(root) gid=0(root)\n")

    def test_missing_and_bad_results_not_passed(self):
        results = c.Results()
        results.feed(output_text().replace("active\n", "inactive\n", 1).replace("web_http=200", "web_http=503").encode())
        self.assertFalse(results.summary()["all_checks_passed"])
        self.assertFalse(c.Results().summary()["all_checks_passed"])

    def test_raw_banners_not_reported(self):
        results = c.Results()
        results.feed(b"PRIVATE_BANNER_SECRET\n")
        self.assertNotIn("PRIVATE", json.dumps(results.summary()))

    def test_mismatched_hostname_and_release_redacted(self):
        results = c.Results()
        results.feed(output_text().replace(c.HOSTNAME, "PRIVATE_BANNER_SECRET").replace(
            c.RELEASE, "/opt/aifinance/PRIVATE_PATH_SECRET").encode())
        summary = results.summary()
        self.assertFalse(summary["all_checks_passed"])
        self.assertNotIn("PRIVATE", json.dumps(summary))
        self.assertEqual(summary["checks"]["hostname"]["observed"], "[redacted_mismatch]")

    def test_curl_error_prevents_success(self):
        for data in (output_text()+"curl: (28) PRIVATE_ERROR\n",
                     output_text().replace("web_http=200", "curl: (28) PRIVATE_ERROR\nweb_http=200")):
            results = c.Results()
            results.feed(data.encode())
            self.assertFalse(results.summary()["all_checks_passed"])
            self.assertIn("curl_error", results.summary()["output_problems"])
            self.assertNotIn("PRIVATE", json.dumps(results.summary()))

    def test_http_duplicate_does_not_overwrite_failure(self):
        results = c.Results()
        results.feed(output_text().replace("web_http=200", "web_http=503\nweb_http=200").encode())
        summary = results.summary()
        self.assertFalse(summary["all_checks_passed"])
        self.assertEqual(summary["checks"]["web_http"]["observed"], "503")

    def test_missing_or_reordered_output_cannot_pass(self):
        variants = [output_text().replace("active\n", "", 1),
                    output_text().replace("active\nactive", "UNEXPECTED\nactive\nactive"),
                    output_text().replace("web_http=200\napi_http=200", "api_http=200\nweb_http=200")]
        for data in variants:
            results = c.Results()
            results.feed(data.encode())
            self.assertFalse(results.summary()["all_checks_passed"])

    def test_observe_complete_without_sending_or_reconnecting(self):
        ws = Mock()
        ws.recv.side_effect = [frame(5, b"\x03"), frame(1, output_text().encode(), 1), frame(5, b"\x06")]
        manager = Mock()
        manager.__enter__ = Mock(return_value=ws)
        manager.__exit__ = Mock(return_value=False)
        captured = io.StringIO()
        with patch.object(c, "websocket_connect", return_value=manager) as connect, contextlib.redirect_stdout(captured):
            result = c.observe_session("FAKE_URL", "FAKE_TOKEN", None, time.monotonic()+10)
        self.assertEqual(result, 0)
        connect.assert_called_once()
        ws.send.assert_not_called()
        self.assertIn('"remote_end": "process_exited"', captured.getvalue())
        self.assertNotIn("FAKE_", captured.getvalue())

    def test_empty_initial_control_does_not_lock_channel(self):
        ws = Mock()
        ws.recv.side_effect = [frame(5, b"\x00", channel=b""), frame(5, b"\x03"),
                              frame(1, output_text().encode(), 1), frame(5, b"\x06", channel=b"")]
        manager = Mock()
        manager.__enter__ = Mock(return_value=ws)
        manager.__exit__ = Mock(return_value=False)
        with patch.object(c, "websocket_connect", return_value=manager), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(c.observe_session("FAKE", "FAKE", None, time.monotonic()+10), 0)
        ws.send.assert_not_called()

    def test_output_requires_nonempty_consistent_channel(self):
        for frames in ([frame(1, b"unused", 1, channel=b"")],
                       [frame(5, b"\x03", channel=b"first"), frame(1, b"unused", 1, channel=b"other")]):
            ws = Mock()
            ws.recv.side_effect = frames
            manager = Mock()
            manager.__enter__ = Mock(return_value=ws)
            manager.__exit__ = Mock(return_value=False)
            with patch.object(c, "websocket_connect", return_value=manager), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(c.Stop):
                    c.observe_session("FAKE", "FAKE", None, time.monotonic()+10)
            ws.send.assert_not_called()

    def test_frozen_closes_immediately_without_reconnect_or_end_claim(self):
        ws = Mock()
        ws.recv.return_value = frame(5, b"\x08")
        manager = Mock()
        manager.__enter__ = Mock(return_value=ws)
        manager.__exit__ = Mock(return_value=False)
        captured = io.StringIO()
        with patch.object(c, "websocket_connect", return_value=manager) as connect, contextlib.redirect_stdout(captured):
            with self.assertRaisesRegex(c.Stop, "remote_channel_frozen_no_reconnect"):
                c.observe_session("FAKE", "FAKE", None, time.monotonic()+10)
        connect.assert_called_once()
        ws.recv.assert_called_once()
        ws.send.assert_not_called()
        manager.__exit__.assert_called_once()
        self.assertIn('"remote_end": "not_observed"', captured.getvalue())

    def test_sequence_gap_stops_without_retry(self):
        ws = Mock()
        ws.recv.return_value = frame(1, b"unused", 2)
        manager = Mock()
        manager.__enter__ = Mock(return_value=ws)
        manager.__exit__ = Mock(return_value=False)
        with patch.object(c, "websocket_connect", return_value=manager) as connect, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(c.Stop):
                c.observe_session("FAKE", "FAKE", None, time.monotonic()+10)
        connect.assert_called_once()
        ws.send.assert_not_called()

    def test_final_partial_identity_error_still_emits_evidence(self):
        ws = Mock()
        ws.recv.side_effect = [frame(1, b"uid=0(root) gid=0(root)", 1), frame(5, b"\x06")]
        manager = Mock()
        manager.__enter__ = Mock(return_value=ws)
        manager.__exit__ = Mock(return_value=False)
        captured = io.StringIO()
        with patch.object(c, "websocket_connect", return_value=manager), contextlib.redirect_stdout(captured):
            with self.assertRaises(c.Stop):
                c.observe_session("FAKE", "FAKE", None, time.monotonic()+10)
        events = [json.loads(line)["event"] for line in captured.getvalue().splitlines()]
        self.assertIn("health_results", events)
        self.assertIn("end_evidence", events)
        self.assertNotIn("root", captured.getvalue())

    def test_no_unbounded_receive(self):
        ws = Mock()
        manager = Mock()
        manager.__enter__ = Mock(return_value=ws)
        manager.__exit__ = Mock(return_value=False)
        with patch.object(c, "websocket_connect", return_value=manager), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(c.Stop):
                c.observe_session("FAKE", "FAKE", None, time.monotonic()-1)
        ws.recv.assert_not_called()

    def test_websocket_forces_proxy_and_safe_tls(self):
        import websockets.sync.client as library
        proxy = c.Proxy("http://proxy.invalid:8080", "proxy.invalid", 8080, None)
        with patch.object(library, "connect") as connect:
            c.websocket_connect("wss://"+c.WSS_HOST+"/session", proxy, "FAKE_TOKEN")
        kwargs = connect.call_args.kwargs
        self.assertEqual(kwargs["proxy"], proxy.url)
        self.assertEqual(kwargs["ssl"].verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(kwargs["ssl"].check_hostname)
        self.assertEqual(kwargs["additional_headers"], {"x-acs-session-token": "FAKE_TOKEN"})
        self.assertLessEqual(kwargs["open_timeout"], 12)

    def test_probe_has_no_token_or_auth_header(self):
        proxy = c.Proxy("http://proxy.invalid:8080", "proxy.invalid", 8080, None)
        manager = Mock()
        manager.__enter__ = Mock()
        manager.__exit__ = Mock(return_value=False)
        with patch.object(c, "websocket_connect", return_value=manager) as connect, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(c.probe(proxy), 0)
        connect.assert_called_once_with("wss://cn-beijing-axt.aliyuncs.com/session", proxy)

    def test_live_gate_does_not_read_or_send_credentials(self):
        self.assertFalse(c.LIVE_EXECUTION_ENABLED)
        with patch.object(sys, "argv", ["client.py", "--run-one-session"]), patch.object(c, "start_one_session") as start, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(c.main(), 2)
        start.assert_not_called()


if __name__ == "__main__":
    c.strip_cloud_credentials()
    unittest.main()
