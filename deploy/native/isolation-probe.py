#!/usr/bin/python3
"""Trusted, bounded probe only. Never installs a firewall or accepts a deployment."""
import argparse
import errno
import json
import os
from pathlib import Path
import pwd
import selectors
import socket
import time

PORT = 48173
TOKEN = b'aifinance-isolation-probe-v1\n'
TARGETS = ((socket.AF_INET, '127.0.0.1', True),
           (socket.AF_INET6, '::1', True),
           (socket.AF_INET, '192.0.2.254', False),
           (socket.AF_INET6, '2001:db8:ffff::254', False))


def memory_evidence(expected_mib):
    """Read this process's actual legacy controller; never trust unit text alone."""
    entries = [line.split(':', 2) for line in Path('/proc/self/cgroup').read_text().splitlines()]
    paths = [entry[2] for entry in entries if len(entry) == 3 and 'memory' in entry[1].split(',')]
    if len(paths) != 1 or paths[0] == '/' or '..' in paths[0].split('/'):
        raise ValueError('expected_nonroot_v1_memory_cgroup')
    mounts = []
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        left, separator, right = line.partition(' - ')
        if not separator:
            continue
        fields, tail = left.split(), right.split()
        if len(fields) >= 5 and len(tail) >= 3 and tail[0] == 'cgroup' and 'memory' in tail[2].split(','):
            mounts.append((fields[3], fields[4]))
    if len(mounts) != 1 or mounts[0][0] != '/' or '\\' in mounts[0][1]:
        raise ValueError('expected_single_standard_memory_mount')
    base = Path(mounts[0][1]) / paths[0].lstrip('/')
    if str(os.getpid()) not in (base / 'cgroup.procs').read_text().split():
        raise ValueError('pid_missing_from_memory_cgroup')
    values = {}
    for name in ('memory.limit_in_bytes', 'memory.usage_in_bytes', 'memory.max_usage_in_bytes', 'memory.failcnt'):
        values[name] = int((base / name).read_text().strip())
    if values['memory.limit_in_bytes'] != expected_mib * 1024 * 1024:
        raise ValueError('kernel_memory_limit_mismatch')
    for name in ('memory.memsw.limit_in_bytes', 'memory.memsw.usage_in_bytes'):
        path = base / name
        values[name] = int(path.read_text().strip()) if path.exists() else None
    values['cgroup'] = paths[0]
    values['mount'] = mounts[0][1]
    values['pid'] = os.getpid()
    values['uid'] = os.geteuid()
    values['pressure_or_oom_tested'] = False
    return values


def connect_target(family, address):
    """One literal-IP TCP attempt, no DNS/HTTP/TLS/user payload/proxy handling."""
    connected = False
    try:
        with socket.socket(family, socket.SOCK_STREAM) as client:
            client.settimeout(2)
            client.connect((address, PORT))
            connected = True
            received = b''
            while len(received) < len(TOKEN):
                part = client.recv(len(TOKEN) - len(received))
                if not part:
                    break
                received += part
            if received != TOKEN:
                return {'connected': True, 'token_ok': False, 'error': 'unexpected_probe_reply'}
            return {'connected': True, 'token_ok': True, 'error': None}
    except OSError as error:
        return {'connected': connected, 'token_ok': False,
                'error': errno.errorcode.get(error.errno, 'TIMEOUT_OR_SOCKET_ERROR')}


def observe(mode):
    results = []
    matched = True
    for family, address, loopback in TARGETS:
        value = connect_target(family, address)
        expect_success = mode != 'guarded' or loopback
        agrees = ((value['connected'] and value['token_ok']) if expect_success else not value['connected'])
        value.update({'address': address, 'family': 4 if family == socket.AF_INET else 6,
                      'loopback': loopback, 'expected_success': expect_success, 'expectation_matched': agrees})
        matched = matched and agrees
        results.append(value)
    return matched, results


def serve():
    """Four fixed listeners; close after 180 seconds or 64 accepts, whichever first."""
    sockets = []
    accepted = 0
    try:
        with selectors.DefaultSelector() as selector:
            for family, address, _ in TARGETS:
                server = socket.socket(family, socket.SOCK_STREAM)
                sockets.append(server)
                if family == socket.AF_INET6:
                    server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                # No SO_REUSEPORT or wildcard bind; a collision fails the whole probe.
                server.bind((address, PORT))
                server.listen(8)
                server.setblocking(False)
                selector.register(server, selectors.EVENT_READ)
            print(json.dumps({'listeners_ready': True, 'port': PORT, 'pid': os.getpid()}), flush=True)
            deadline = time.monotonic() + 180
            while time.monotonic() < deadline and accepted < 64:
                for key, _ in selector.select(min(1, max(0, deadline - time.monotonic()))):
                    if accepted >= 64 or time.monotonic() >= deadline:
                        break
                    try:
                        connection, _ = key.fileobj.accept()
                    except BlockingIOError:
                        continue
                    with connection:
                        connection.settimeout(0.5)
                        try:
                            connection.sendall(TOKEN)
                        except OSError:
                            pass
                    accepted += 1
    finally:
        for server in sockets:
            server.close()
    return accepted


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('serve', 'control', 'baseline', 'guarded'))
    parser.add_argument('--memory-limit-mib', type=int, choices=(64, 256, 320), default=64)
    args = parser.parse_args(argv)
    try:
        if args.mode in ('serve', 'control'):
            if os.getuid() != 0 or os.geteuid() != 0:
                raise ValueError('trusted_server_or_control_requires_root_service')
        else:
            expected_uid = pwd.getpwnam('aifinance').pw_uid
            if expected_uid == 0 or os.getuid() != expected_uid or os.geteuid() != expected_uid:
                raise ValueError('probe_requires_exact_nonroot_aifinance_uid')
        evidence = memory_evidence(args.memory_limit_mib)
        if args.mode == 'serve':
            print(json.dumps({'memory': evidence}), flush=True)
            print(json.dumps({'accepted_connections': serve()}), flush=True)
            return 0
        matched, results = observe(args.mode)
        print(json.dumps({'mode': args.mode, 'memory': evidence, 'network': results,
                          'expectations_matched': matched,
                          'isolation_accepted': False, 'ready_for_deploy': False,
                          'requires': 'reviewed baseline/control, per-family nft counter deltas, final unit checks'}), flush=True)
        return 0 if matched else 1
    except (ValueError, KeyError, OSError) as error:
        # Only fixed diagnostic class/message; never dump files, environment or credentials.
        print(json.dumps({'probe_failed': True, 'reason': str(error) if isinstance(error, ValueError)
                          else type(error).__name__, 'isolation_accepted': False, 'ready_for_deploy': False}), flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
