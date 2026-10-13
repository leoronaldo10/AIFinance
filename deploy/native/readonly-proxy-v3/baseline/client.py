#!/usr/bin/env python3
"""One approved AIFinance check. No retries, files containing secrets, or direct I/O.

Protocol reference: aliyun/cloud-assistant-starter commit
0f100b8c84601e6a119d42bed0630aa8d64459f5, AxtMessage.ts / AxtSession.tsx.
API signature: Alibaba Cloud Request syntax and signature method V3.
Live execution remains locked pending independent review and parent go-ahead.
"""
import base64
import dataclasses
import datetime as dt
import hashlib
import hmac
import http.client
import json
import logging
import os
import re
import resource
import signal
import shlex
import ssl
import struct
import sys
import time
import urllib.parse
import urllib.request
import uuid

sys.dont_write_bytecode = True
LIVE_EXECUTION_ENABLED = False
REGION = "cn-beijing"
INSTANCE = "i-2zedybs3fftu1d9vnx39"
USERNAME = "aifinance-deploy"
API_HOST = "ecs.cn-beijing.aliyuncs.com"
WSS_HOST = "cn-beijing-axt.aliyuncs.com"
HOSTNAME = "iZ2zedybs3fftu1d9vnx39Z"
RELEASE = "/opt/aifinance/staging/d57ba047369e666025347719caee1a4c642abe62"
EXPIRATION = dt.datetime(2026, 10, 13, 12, 44, 25, tzinfo=dt.timezone.utc)
KEYS = ("ALIBABA_CLOUD_ACCESS_KEY_ID", "ALIBABA_CLOUD_ACCESS_KEY_SECRET",
        "ALIBABA_CLOUD_SECURITY_TOKEN")
COMMAND = '''test "$(id -un)" = aifinance-deploy || exit 10; id; hostname; systemctl is-active aifinance-api.service; systemctl is-active aifinance-web.service; readlink /opt/aifinance/switch/current; curl -q --noproxy '*' -sS -o /dev/null -w 'web_http=%{http_code}\\n' --connect-timeout 3 --max-time 10 http://127.0.0.1:3000/; curl -q --noproxy '*' -sS -o /dev/null -w 'api_http=%{http_code}\\n' --connect-timeout 3 --max-time 10 http://127.0.0.1:3001/api/health; exit'''
SAFE_FIELD = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")


class Stop(Exception):
    """Only internally chosen, non-sensitive reason strings."""


def emit(event, **fields):
    print(json.dumps({"event": event, **fields}, sort_keys=True), flush=True)


def strip_cloud_credentials():
    for key in KEYS:
        os.environ.pop(key, None)


@dataclasses.dataclass(repr=False)
class Proxy:
    url: str
    host: str
    port: int
    authorization: str | None


def require_proxy():
    # Explicit proxy URL overrides NO_PROXY. Never use a bypass/direct fallback.
    proxies = urllib.request.getproxies()
    value = proxies.get("wss") or proxies.get("https")
    if not value:
        raise Stop("environment_proxy_missing")
    try:
        part = urllib.parse.urlsplit(value)
        if part.scheme != "http" or not part.hostname or part.query or part.fragment:
            raise Stop("unsupported_environment_proxy")
        if part.path not in ("", "/"):
            raise Stop("unsupported_environment_proxy")
        port = part.port or 80
        if not 1 <= port <= 65535:
            raise Stop("unsupported_environment_proxy")
        auth = None
        if part.username is not None:
            if part.password is None:
                raise Stop("unsupported_environment_proxy")
            pair = (urllib.parse.unquote(part.username) + ":" +
                    urllib.parse.unquote(part.password)).encode()
            auth = "Basic " + base64.b64encode(pair).decode()
        return Proxy(value, part.hostname, port, auth)
    except (ValueError, UnicodeError):
        raise Stop("invalid_environment_proxy") from None


def tls_context():
    # Honor the system trust store; never disable host/certificate verification.
    return ssl.create_default_context()


def canonical_query(params):
    enc = lambda s: urllib.parse.quote(str(s), safe="-_.~")
    return "&".join(enc(k) + "=" + enc(v) for k, v in sorted(params.items()))


def authorization(method, query, headers, access_id, secret, body=b""):
    # Public V3 algorithm; signed material remains in memory, never logged.
    names = sorted(k for k in headers if k == "host" or k == "content-type"
                   or k.startswith("x-acs-"))
    signed = ";".join(names)
    canonical_headers = "".join(k + ":" + headers[k].strip() + "\n" for k in names)
    canonical = (method + "\n/\n" + query + "\n" + canonical_headers + "\n" +
                 signed + "\n" + hashlib.sha256(body).hexdigest())
    to_sign = "ACS3-HMAC-SHA256\n" + hashlib.sha256(canonical.encode()).hexdigest()
    signature = hmac.new(secret.encode(), to_sign.encode(), hashlib.sha256).hexdigest()
    return ("ACS3-HMAC-SHA256 Credential=" + access_id + ",SignedHeaders=" +
            signed + ",Signature=" + signature)


def fixed_command_line():
    # Agent shlex.Split executes argv directly; explicitly invoke one shell.
    # No caller-supplied command or shell options are accepted.
    command_line = "/bin/sh -c " + shlex.quote(COMMAND)
    if len(command_line) > 512:
        raise Stop("fixed_command_line_too_long")
    return command_line


def fixed_parameters():
    return {"RegionId": REGION, "InstanceId.1": INSTANCE, "Username": USERNAME,
            "ConnectionType": "Internet", "CommandLine": fixed_command_line(),
            "ClientToken": str(uuid.uuid4())}


def make_request(credentials):
    access_id, secret, sts = credentials
    query = canonical_query(fixed_parameters())
    headers = {
        "host": API_HOST, "x-acs-action": "StartTerminalSession",
        "x-acs-version": "2014-05-26",
        "x-acs-date": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "x-acs-signature-nonce": str(uuid.uuid4()),
        "x-acs-security-token": sts,
        "x-acs-content-sha256": hashlib.sha256(b"").hexdigest(),
        "accept": "application/json",
    }
    headers["authorization"] = authorization("POST", query, headers, access_id, secret)
    return "/?" + query, headers


def api_connection(proxy, timeout):
    # HTTPSConnection connects TCP to the proxy, CONNECTs the fixed API host,
    # then negotiates TLS with API_HOST. No request redirects or retries.
    conn = http.client.HTTPSConnection(proxy.host, proxy.port, timeout=timeout,
                                       context=tls_context())
    headers = {"Proxy-Authorization": proxy.authorization} if proxy.authorization else {}
    conn.set_tunnel(API_HOST, 443, headers=headers)
    return conn


def safe_api_fields(body):
    return {key: val for key in ("Code", "RequestId")
            if isinstance(val := body.get(key), str) and SAFE_FIELD.fullmatch(val)}


def validate_session(body):
    # Only the published, approved hostname can receive the session token.
    url = body.get("WebSocketUrl")
    sid = body.get("SessionId")
    token = body.get("SecurityToken")
    if not isinstance(url, str) or not isinstance(sid, str) or not SAFE_FIELD.fullmatch(sid):
        raise Stop("invalid_session_response")
    if not isinstance(token, str) or not token or "\r" in token or "\n" in token:
        raise Stop("invalid_session_response")
    try:
        if any(ord(char) <= 32 or ord(char) == 127 for char in url) or "\\" in url:
            raise Stop("invalid_session_response")
        part = urllib.parse.urlsplit(url)
        if (part.scheme != "wss" or part.hostname != WSS_HOST or
                part.port not in (None, 443) or part.username is not None or
                part.password is not None or part.fragment or part.path != "/session"):
            raise Stop("unapproved_websocket_endpoint")
        query = urllib.parse.parse_qs(part.query, strict_parsing=True,
                                     keep_blank_values=True, max_num_fields=4)
        if (set(query) != {"sessionId", "token"} or query.get("sessionId") != [sid]
                or query.get("token") != [token]):
            raise Stop("inconsistent_session_response")
    except ValueError:
        raise Stop("invalid_session_response") from None
    return url, sid, token


def start_one_session(proxy, credentials):
    path, headers = make_request(credentials)
    conn = api_connection(proxy, 12)
    # Once request() starts, receipt/execution is possible even on a lost response.
    emit("api_attempt", action="StartTerminalSession", fixed_command_may_execute=True)
    try:
        conn.request("POST", path, body=b"", headers=headers)
        response = conn.getresponse()
        raw = response.read(65537)
        if len(raw) > 65536:
            raise Stop("api_response_too_large")
        try:
            body = json.loads(raw)
        except (ValueError, UnicodeError):
            raise Stop("api_response_not_json") from None
        if not isinstance(body, dict):
            raise Stop("api_response_not_object")
        fields = safe_api_fields(body)
        emit("api_response", action="StartTerminalSession", http_status=response.status, **fields)
        if response.status != 200 or body.get("Code"):
            raise Stop("api_rejected")
        # Preserve the non-secret cleanup identifier even if URL validation fails.
        sid = body.get("SessionId")
        if isinstance(sid, str) and SAFE_FIELD.fullmatch(sid):
            emit("session_allocated", SessionId=sid, fixed_command_may_execute=True)
        url, sid, token = validate_session(body)
        return url, token
    finally:
        conn.close()


@dataclasses.dataclass(repr=False)
class Frame:
    kind: int
    version: str
    channel: str
    instance: str
    timestamp: int
    input_seq: int
    output_seq: int
    payload: bytes


def decode_frame(raw):
    # Exact little-endian layout in the pinned official AxtMessage.ts.
    if not isinstance(raw, bytes) or not 30 <= len(raw) <= 66075:
        raise Stop("invalid_protocol_frame")
    try:
        kind = struct.unpack_from("<I", raw)[0]
        version = raw[4:8].decode("ascii")
        pos = 8
        strings = []
        for _ in range(2):
            n = raw[pos]
            pos += 1
            if pos + n > len(raw):
                raise Stop("truncated_protocol_frame")
            strings.append(raw[pos:pos+n].decode("ascii"))
            pos += n
        timestamp, input_seq, output_seq, size, encoding, reserved = struct.unpack_from("<QIIHBB", raw, pos)
        pos += 20
        if size != len(raw) - pos or encoding != 0 or reserved != 0 or kind not in range(7):
            raise Stop("unsupported_protocol_frame")
        # Official inbound version is Agent metadata, not a layout selector.
        # Restrict diagnostic metadata to a four-character numeric version.
        if not re.fullmatch(r"[0-9]\.[0-9]{2}", version):
            emit("protocol_version_rejected", version_format="invalid_or_redacted")
            raise Stop("unsupported_protocol_version")
        if strings[1] not in ("", INSTANCE):
            raise Stop("unexpected_protocol_instance")
        return Frame(kind, version, *strings, timestamp, input_seq, output_seq, raw[pos:])
    except (struct.error, IndexError, UnicodeError):
        raise Stop("malformed_protocol_frame") from None


class Results:
    def __init__(self):
        self.buffer = ""
        self.values = {}
        self.other_lines = 0
        self.total_bytes = 0
        self.stage = 0
        self.problems = set()

    def feed(self, data):
        self.total_bytes += len(data)
        if self.total_bytes > 131072:
            raise Stop("output_limit_exceeded")
        # Never print raw terminal content, banners, prompts, or API payloads.
        self.buffer += data.decode("utf-8", "replace")
        while "\n" in self.buffer:
            line, self.buffer = self.buffer.split("\n", 1)
            self.line(line)

    def finish(self):
        if self.buffer:
            self.line(self.buffer)
            self.buffer = ""

    def line(self, value):
        line = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", value).strip("\r ")
        if not line:
            return
        curl_error = re.match(r"^curl: \((\d{1,3})\)", line)
        if curl_error:
            self.problems.add("curl_error")
            self.other_lines += 1
            return
        # Classify only anchored common error forms; never retain their text.
        shell_prefix = r"(?:/bin/)?(?:ba|da)?sh: (?:-c: )?(?:(?:line )?[0-9]+: )?"
        error_patterns = (
            ("command_not_found", r"(?:" + shell_prefix + r")?[A-Za-z0-9_./-]{1,128}: (?:command )?not found"),
            ("permission_denied", r"(?:" + shell_prefix + r")?[^\r\n]{1,256}: Permission denied"),
            ("shell_parsing_error", shell_prefix + r"(?:syntax error(?: near unexpected token [^\r\n]{1,80})?|Syntax error: [^\r\n]{1,80}|unexpected EOF while looking for matching [^\r\n]{1,16})"),
        )
        for category, pattern in error_patterns:
            if re.fullmatch(pattern, line):
                self.problems.add(category)
                self.other_lines += 1
                return
        identity = re.match(r"^uid=\d+\(([A-Za-z0-9_-]+)\) gid=\d+\(", line)
        if self.stage == 0 and identity:
            self.values["identity"] = USERNAME if identity.group(1) == USERNAME else "[redacted_mismatch]"
            self.stage = 1
            if identity.group(1) != USERNAME:
                self.problems.add("identity_mismatch")
                raise Stop("identity_mismatch")
            return
        if self.stage == 0:
            # Preamble is not evidence and is never copied into reported fields.
            self.other_lines += 1
            return
        if self.stage == 1:
            self.values["hostname"] = HOSTNAME if line == HOSTNAME else "[redacted_mismatch]"
            self.stage = 2
            return
        states = ("active", "inactive", "failed", "activating", "deactivating", "reloading", "maintenance", "unknown")
        if self.stage in (2, 3):
            self.values["api_service" if self.stage == 2 else "web_service"] = line if line in states else "[unexpected_output]"
            if line not in states:
                self.problems.add("unexpected_service_output")
            self.stage += 1
            return
        if self.stage == 4:
            self.values["release"] = RELEASE if line == RELEASE else "[redacted_mismatch]"
            self.stage = 5
            return
        if self.stage in (5, 6):
            label = "web" if self.stage == 5 else "api"
            match = re.fullmatch(label + r"_http=(\d{3})", line)
            if match:
                self.values[label + "_http"] = match.group(1)
            else:
                self.problems.add("unexpected_or_duplicate_http_output")
            self.stage += 1
            return
        if line not in ("exit", "logout"):
            self.other_lines += 1
            self.problems.add("unexpected_output_after_results")

    def summary(self):
        expected = {"identity": USERNAME, "hostname": HOSTNAME, "api_service": "active",
                    "web_service": "active", "release": RELEASE, "web_http": "200", "api_http": "200"}
        checks = {key: {"status": "not_observed" if key not in self.values else
                       "pass" if self.values[key] == wanted else "fail",
                       "observed": self.values.get(key)} for key, wanted in expected.items()}
        return {"checks": checks, "unreported_lines": self.other_lines,
                "output_problems": sorted(self.problems),
                "all_checks_passed": not self.problems and all(x["status"] == "pass" for x in checks.values())}


def websocket_connect(url, proxy, token=None):
    from websockets.sync.client import connect
    kwargs = {"proxy": proxy.url, "ssl": tls_context(), "open_timeout": 12,
              "close_timeout": 2, "ping_interval": None, "compression": None,
              "max_size": 66075, "max_queue": 8}
    if token is not None:
        kwargs["additional_headers"] = {"x-acs-session-token": token}
    # sync connect() performs one attempt; no iterator/reconnect API is used.
    return connect(url, **kwargs)


def observe_session(url, token, proxy, deadline):
    results = Results()
    remote_end = "not_observed"
    channel = None
    agent_version = None
    output_seq = 0
    last_output = time.monotonic()
    try:
        with websocket_connect(url, proxy, token) as ws:
            emit("websocket_connected")
            while True:
                remaining = min(deadline - time.monotonic(), 30 - (time.monotonic() - last_output))
                if remaining <= 0:
                    raise Stop("local_time_limit_remote_end_unknown")
                try:
                    raw = ws.recv(timeout=remaining)
                except TimeoutError:
                    raise Stop("idle_or_total_timeout_remote_end_unknown") from None
                frame = decode_frame(raw)
                # Official client learns channelId while it is still empty.
                # Empty control frames don't establish or change channel identity.
                if frame.channel:
                    if channel is None:
                        channel = frame.channel
                    elif frame.channel != channel:
                        raise Stop("unexpected_protocol_channel")
                elif frame.kind == 1:
                    raise Stop("output_channel_missing")
                if frame.kind == 1:
                    if agent_version is None:
                        agent_version = frame.version
                        emit("agent_version", observed_version=agent_version)
                    if frame.output_seq <= output_seq:
                        continue  # Ignore duplicate output; never duplicate commands.
                    if frame.output_seq != output_seq + 1:
                        raise Stop("output_sequence_gap_no_automatic_retry")
                    output_seq = frame.output_seq
                    last_output = time.monotonic()
                    results.feed(frame.payload)
                elif frame.kind == 5:
                    if not frame.payload:
                        raise Stop("empty_protocol_status")
                    state = frame.payload[0]
                    if state not in range(9):
                        raise Stop("unknown_protocol_status")
                    emit("remote_channel_state", state=state)
                    if state in (5, 6):
                        remote_end = "channel_closed" if state == 5 else "process_exited"
                        break
                    if state == 2:
                        raise Stop("remote_channel_aborted")
                    if state == 8:
                        raise Stop("remote_channel_frozen_no_reconnect")
                # No Input, Resize, Open, Close, Sync, or command replay is sent.
                # The single fixed CommandLine (including exit) was sent via API.
    finally:
        try:
            results.finish()
        finally:
            emit("health_results", **results.summary())
            emit("end_evidence", remote_end=remote_end,
                 cloud_session_revoked="not_verified", fixed_exit_executed="not_independently_verified")
    return 0 if results.summary()["all_checks_passed"] and remote_end != "not_observed" else 1


def probe(proxy):
    # No API, session ID, token, STS, terminal input, or response body is used.
    from websockets.exceptions import InvalidStatus, InvalidProxyStatus
    try:
        with websocket_connect("wss://" + WSS_HOST + "/session", proxy):
            emit("unauthenticated_probe", proxy_connect_and_tls=True, websocket_http_status=101)
    except InvalidProxyStatus as exc:
        emit("unauthenticated_probe", proxy_connect_and_tls=False,
             proxy_http_status=exc.response.status_code)
        return 1
    except InvalidStatus as exc:
        emit("unauthenticated_probe", proxy_connect_and_tls=True,
             websocket_http_status=exc.response.status_code)
        return 0
    return 0


def hard_deadline(_signal, _frame):
    os.write(1, b'{"event":"hard_40s_local_exit","remote_end":"unknown"}\n')
    os._exit(124)


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    logging.disable(logging.CRITICAL)
    args = sys.argv[1:]
    if args not in (["--probe"], ["--run-one-session"]):
        strip_cloud_credentials()
        emit("usage", modes=["--probe", "--run-one-session"], live_enabled=LIVE_EXECUTION_ENABLED)
        return 2
    if args == ["--run-one-session"] and not LIVE_EXECUTION_ENABLED:
        strip_cloud_credentials()
        emit("blocked", reason="awaiting_independent_review_and_parent_go_ahead")
        return 2
    signal.signal(signal.SIGALRM, hard_deadline)
    signal.setitimer(signal.ITIMER_REAL, 40)
    deadline = time.monotonic() + 35  # Reserve time for TLS close before hard limit.
    try:
        if args == ["--probe"]:
            strip_cloud_credentials()
            return probe(require_proxy())
        present = {key: bool(os.environ.get(key)) for key in KEYS}
        emit("credential_presence", **present)
        if not all(present.values()):
            raise Stop("credential_missing")
        if dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=40) >= EXPIRATION:
            raise Stop("credential_expired_or_insufficient_remaining_lifetime")
        proxy = require_proxy()
        credentials = tuple(os.environ.pop(key) for key in KEYS)
        url, token = start_one_session(proxy, credentials)
        del credentials
        return observe_session(url, token, proxy, deadline)
    except Stop as exc:
        emit("stopped", reason=exc.args[0])
        return 1
    except BaseException as exc:
        # Never stringify network/library exceptions: they can contain URLs/tokens.
        emit("stopped", error_type=type(exc).__name__, remote_end="unknown")
        return 1
    finally:
        strip_cloud_credentials()
        signal.setitimer(signal.ITIMER_REAL, 0)
        emit("local_client_finished", remote_revocation_confirmed=False)


if __name__ == "__main__":
    sys.exit(main())
