#!/usr/bin/env python3
"""Offline-only fixed gateway adapter. No credential lookup or live entry point.

Pinned official protocol and reviewed transport live in readonly-proxy-v3.
An injected test WebSocket is required; authorizing live transport is separate.
"""
import base64
import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import signal
import threading
import functools
import sys
import time
import uuid

_spec = importlib.util.spec_from_file_location('reviewed_readonly', Path(__file__).with_name('readonly-proxy-v3') / 'client.py')
reviewed = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = reviewed
_spec.loader.exec_module(reviewed)
Stop = reviewed.Stop
LIMIT = 128 * 1024 * 1024
GATEWAY = '/opt/aifinance/bin/rebuilt-gateway.py'
SHA = r'[0-9a-f]{40}'
DIGEST = r'[0-9a-f]{64}'
ID = r'[0-9a-f]{32}'
LIVE_EXECUTION_ENABLED = False


def command(action, *args):
    patterns = {'verify': '', 'status': '(?:' + ID + ')?', 'resume': ID,
                'upload': SHA + ' ' + DIGEST, 'artifact-status': SHA + ' ' + DIGEST,
                'deploy': SHA + ' ' + DIGEST + ' ' + ID,
                'rollback': SHA + ' ' + ID}
    if action not in patterns or any(not isinstance(a, str) for a in args):
        raise Stop('command_denied')
    arities = {'verify': (0,), 'status': (0,1), 'resume': (1,), 'upload': (2,),
               'artifact-status': (2,), 'deploy': (3,), 'rollback': (2,)}
    if len(args) not in arities[action] or any(not a or re.search(r'\s', a) for a in args):
        raise Stop('command_denied')
    tail = ' '.join(args)
    if not re.fullmatch(patterns[action], tail) or (not tail and args):
        raise Stop('command_denied')
    line = GATEWAY + ' --terminal rebuilt-v1 ' + action + (' ' + tail if tail else '')
    if len(line.encode('ascii')) > 512:
        raise Stop('command_limit')
    return line


def artifact(data, revision, digest, source):
    """Caller supplies reviewed build evidence; this is not provenance attestation."""
    command('upload', revision, digest)
    if (not isinstance(data, bytes) or not 0 < len(data) <= LIMIT or
            hashlib.sha256(data).hexdigest() != digest):
        raise Stop('artifact_digest_or_limit')
    expected = {'repository': 'leoronaldo10/AIFinance', 'revision': revision,
                'sha256': digest, 'checks_passed': True}
    if (not isinstance(source, dict) or any(source.get(k) != v for k, v in expected.items()) or
            not isinstance(source.get('build_run'), str) or
            not re.fullmatch(r'[1-9][0-9]{0,19}', source['build_run'])):
        raise Stop('build_evidence_required')
    return data


def signed_request(action, args, credentials, expiration, seconds):
    """Pure request builder, uses fresh explicitly supplied expiration, never sends."""
    line = command(action, *args)
    if (not isinstance(expiration, dt.datetime) or expiration.tzinfo is None or
            type(seconds) is not int or not 1 <= seconds <= 480 or
            (expiration - dt.datetime.now(dt.timezone.utc)).total_seconds() < seconds + 30):
        raise Stop('credential_window')
    if len(credentials) != 3 or any(not isinstance(v, str) or not v or '\r' in v or '\n' in v for v in credentials):
        raise Stop('credentials_invalid')
    query = reviewed.canonical_query({'RegionId': reviewed.REGION,
        'InstanceId.1': reviewed.INSTANCE, 'Username': reviewed.USERNAME,
        'ConnectionType': 'Internet', 'CommandLine': line, 'ClientToken': str(uuid.uuid4())})
    headers = {'host': reviewed.API_HOST, 'x-acs-action': 'StartTerminalSession',
        'x-acs-version': '2014-05-26',
        'x-acs-date': dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'x-acs-signature-nonce': str(uuid.uuid4()), 'x-acs-security-token': credentials[2],
        'x-acs-content-sha256': hashlib.sha256(b'').hexdigest(), 'accept': 'application/json'}
    headers['authorization'] = reviewed.authorization('POST', query, headers, *credentials[:2])
    return '/?' + query, headers


def connection_plan(action, args, credentials, expiration, seconds):
    """Validate the reviewed mandatory proxy/TLS and prepare, but do not send."""
    proxy = reviewed.require_proxy()
    tls = reviewed.tls_context()
    path, headers = signed_request(action, args, credentials, expiration, seconds)
    return proxy, tls, path, headers


def input_frame(channel, sequence, output_sequence, payload):
    # AxtMessage.ts: little endian, channel before instance; bounded ASCII payload <=1034
    if (not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', channel) or
            not 1 <= sequence <= 0xffffffff or not 0 <= output_sequence <= 0xffffffff or
            not isinstance(payload, bytes) or len(payload) > 1034):
        raise Stop('input_frame_invalid')
    name = channel.encode('ascii')
    return (struct.pack('<I', 0) + b'1.02' + bytes([len(name)]) + name + b'\0' +
            struct.pack('<QIIHBB', int(time.time()*1000), sequence, output_sequence,
                        len(payload), 0, 0) + payload)


def bounded(function):
    @functools.wraps(function)
    def call(*args, **kwargs):
        seconds = kwargs.get('seconds')
        if (type(seconds) is not int or not 1 <= seconds <= 480 or
                threading.current_thread() is not threading.main_thread() or
                signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0)):
            raise Stop('exclusive_deadline_required')
        previous = signal.getsignal(signal.SIGALRM)
        def expired(*_):
            raise Stop('timeout_query_status')
        signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, seconds)
        try:
            return function(*args, **kwargs)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
    return call


def valid_receipt(value, opid):
    fields = {'id','action','revision','digest','previous','phase','updated','fallback_allowed'}
    return (isinstance(value, dict) and set(value) == fields and isinstance(value['id'], str) and
        re.fullmatch(ID, value['id']) and value['id'] == opid and
        value['action'] in ('deploy','rollback') and
        all(isinstance(value[k], str) and re.fullmatch(SHA, value[k]) for k in ('revision','previous')) and
        isinstance(value['digest'], str) and
        ((value['action'] == 'rollback' and value['digest'] == '') or
         (value['action'] == 'deploy' and re.fullmatch(DIGEST, value['digest']))) and
        value['phase'] in ('prepared','switching','checking','rolling_back','succeeded','rolled_back','recovery_required') and
        type(value['updated']) is int and type(value['fallback_allowed']) is bool)


@bounded
def exchange(ws, action, args, *, seconds, data=None, source=None):
    """One mock session; caller starts the fixed command once. Never reconnect/replay.

    Exceptions mean result unknown: explicitly query status [ID] in a new session.
    No remote end/exit code is inferred from socket closure.
    """
    command(action, *args)
    if type(seconds) is not int or not 1 <= seconds <= 480:
        raise Stop('time_limit')
    if action == 'upload':
        artifact(data, args[0], args[1], source)
    elif data is not None or source is not None:
        raise Stop('unexpected_upload')
    deadline = time.monotonic() + seconds
    channel = None
    output_seq = input_seq = offset = expected_ack = 0
    ended = False
    pending = b''
    result = None
    sent_end = False
    while not ended:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise Stop('timeout_query_status')
        try:
            frame = reviewed.decode_frame(ws.recv(timeout=remaining))
        except Exception:
            raise Stop('connection_or_protocol_unknown_query_status') from None
        if frame.version != '1.02':
            raise Stop('unaccepted_agent_version')
        if frame.channel:
            if channel is not None and channel != frame.channel:
                raise Stop('channel_changed')
            channel = frame.channel
        if frame.kind == 5:
            if not frame.payload or frame.payload[0] not in (0, 1, 3, 4, 5, 6):
                raise Stop('status_unknown_query_status')
            ended = frame.payload[0] in (5, 6)
            continue
        if frame.kind != 1:
            raise Stop('unexpected_frame_no_replay')
        if not frame.channel or not channel or frame.input_seq > input_seq:
            raise Stop('sequence_invalid')
        if frame.output_seq <= output_seq:
            continue
        if frame.output_seq != output_seq + 1:
            raise Stop('output_gap_query_status')
        output_seq = frame.output_seq
        pending += frame.payload
        if len(pending) > 32768:
            raise Stop('output_limit')
        while b'\n' in pending:
            line, pending = pending.split(b'\n', 1)
            try:
                value = json.loads(line.rstrip(b'\r'))
            except (ValueError, UnicodeError):
                raise Stop('invalid_gateway_response') from None
            if not isinstance(value, dict) or result is not None:
                raise Stop('unexpected_gateway_response')
            if 'terminal' in value:
                if (action != 'upload' or sent_end or type(value.get('ack')) is not int or value !=
                        {'terminal': 'rebuilt-pty-v1', 'ack': expected_ack}):
                    raise Stop('upload_ack_invalid')
                if offset < len(data):
                    chunk = data[offset:offset+768]
                    offset += len(chunk)
                    expected_ack += 1
                    payload = ('%08d:' % expected_ack).encode() + base64.b64encode(chunk) + b'\n'
                else:
                    payload = b'.\n'
                    sent_end = True
                input_seq += 1
                try:
                    ws.send(input_frame(channel, input_seq, output_seq, payload))
                except Exception:
                    raise Stop('send_unknown_query_status') from None
            else:
                result = value
    if pending or result is None:
        raise Stop('missing_result_query_status')
    if result.get('ok') is False:
        raise Stop('gateway_refused')
    if action == 'upload':
        if not sent_end or result != {'uploaded': args[0], 'sha256': args[1]}:
            raise Stop('upload_result_mismatch')
    elif action in ('deploy', 'rollback', 'resume'):
        opid = args[-1]
        if (not valid_receipt(result, opid) or result.get('phase') not in
                ('succeeded', 'rolled_back', 'recovery_required') or
                (action != 'resume' and (result.get('revision') != args[0] or result.get('action') != action)) or
                (action == 'deploy' and result.get('digest') != args[1])):
            raise Stop('operation_result_mismatch')
    elif result.get('protocol') != 'rebuilt-v1':
        raise Stop('gateway_version_mismatch')
    elif action == 'artifact-status':
        if (set(result) != {'protocol','revision','sha256','present'} or
                result['revision'] != args[0] or result['sha256'] != args[1] or
                type(result['present']) is not bool):
            raise Stop('artifact_status_mismatch')
    elif action == 'verify':
        if result != {'protocol':'rebuilt-v1','access':True,'layout_verified':False}:
            raise Stop('verify_result_invalid')
    elif action == 'status':
        if set(result) != {'protocol','current','operation'}:
            raise Stop('status_receipt_invalid')
        record = result.get('operation')
        if (not isinstance(result.get('current'), str) or not re.fullmatch(SHA, result['current']) or
                (record is not None and (not isinstance(record, dict) or
                 not valid_receipt(record, args[0] if args else record.get('id')))) or
                (args and record is None)):
            raise Stop('status_receipt_invalid')
    return result


def connect_live(*args, **kwargs):
    # No switch, environment variable or CLI flag can enable this offline prototype.
    raise Stop('live_not_authorized')


if __name__ == '__main__':
    raise SystemExit('offline adapter only; live_not_authorized')
