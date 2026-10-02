#!/usr/bin/python3
"""Read-only native preparation gate. Python 3.6.8+; no installer is enabled.

--apply is deliberately fail-closed until a reviewed target dependency transaction
and acceptance procedure exist. A successful checksum check is NOT acceptance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
from urllib.parse import urlsplit

ROOT = Path('/opt/aifinance')
NODE = ROOT / 'runtime/node/bin/node'
UNITS = tuple('aifinance-preview-' + role + '.service' for role in ('api', 'web', 'db'))
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/', 'LANG': 'C', 'LC_ALL': 'C'}
MAX_ARTIFACT = 512 * 1024 * 1024
CURRENT_GATES = [
    'postgresql_16_or_17_dependency_transaction_not_implemented_or_accepted',
    'dedicated_database_credentials_and_schema_not_provisioned_or_accepted',
    'target_runtime_native_modules_and_memory_not_accepted',
    'systemd_network_isolation_not_proven_on_target',
    'apply_not_implemented_no_host_changes_allowed',
]


def read_text(path, limit=65536):
    """Fixed system metadata only. Never environment, keys, logs, or process argv."""
    with Path(path).open('rb') as f:
        data = f.read(limit + 1)
    if len(data) > limit:
        raise ValueError('metadata_limit')
    return data.decode('utf-8', 'strict')


def trusted(path):
    """Reviewed input files and every ancestor must be root-owned, not writable.

    No symlinks or special files. Run checks after placing inputs in a protected
    administrator directory; a hash alone cannot make deployment-owned code safe.
    """
    path = Path(path)
    if not path.is_absolute():
        raise ValueError('absolute_input_path_required')
    for p in (path,) + tuple(path.parents):
        st = p.lstat()
        kind = stat.S_ISREG(st.st_mode) if p == path else stat.S_ISDIR(st.st_mode)
        if not kind or st.st_uid != 0 or st.st_mode & 0o022:
            raise ValueError('untrusted_input_path')
    return path


def digest_file(path, max_size=MAX_ARTIFACT):
    path = trusted(path)
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022 or st.st_size > max_size:
            raise ValueError('untrusted_or_oversize_input')
        digest = hashlib.sha256()
        total = 0
        while True:
            data = os.read(fd, 1024 * 1024)
            if not data:
                break
            total += len(data)
            if total > max_size:
                raise ValueError('input_limit')
            digest.update(data)
        return digest.hexdigest(), total
    finally:
        os.close(fd)


def command(args):
    """Fixed read-only executables; no shell, inherited credentials or PATH lookup."""
    try:
        # Permit normal vendor /bin -> /usr/bin symlinks only after resolving them.
        trusted(Path(args[0]).resolve())
        result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, universal_newlines=True,
                                env=ENV, cwd='/', timeout=5, shell=False)
        return result.stdout if result.returncode == 0 and len(result.stdout) <= 32768 else None
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def parse_node(text):
    match = re.fullmatch(r'v?(24)\.(\d+)\.(\d+)\s*', text or '')
    if not match or int(match.group(2)) < 11:
        return None
    return '.'.join(match.groups())


def parse_ports(text4, text6):
    result = {str(port): [] for port in (8000, 3100, 3101, 55432)}
    for text in (text4, text6):
        for line in text.splitlines()[1:]:
            columns = line.split()
            if len(columns) < 4 or columns[3] != '0A':
                continue
            host, port = columns[1].rsplit(':', 1)
            port = str(int(port, 16))
            if port in result:
                scope = 'loopback' if host in ('0100007F', '00000000000000000000000001000000') else 'other'
                result[port].append(scope)
    return result


def snapshot():
    report = {'architecture': platform.machine(), 'python': list(sys.version_info[:3])}
    try:
        values = dict(line.split('=', 1) for line in read_text('/etc/os-release').splitlines() if '=' in line)
        report['os'] = {key: values.get(key, '').strip('"') for key in ('ID', 'VERSION_ID')}
    except (OSError, ValueError):
        report['os'] = None
    try:
        value = os.confstr('CS_GNU_LIBC_VERSION')
        report['glibc'] = value if re.fullmatch(r'glibc [0-9]+\.[0-9]+', value or '') else None
    except (OSError, ValueError):
        report['glibc'] = None
    try:
        report['memory_kib'] = {k: int(v) for k, v in re.findall(
            r'^(MemTotal|MemAvailable|SwapTotal|SwapFree):\s+(\d+) kB$', read_text('/proc/meminfo'), re.M)}
        disk = os.statvfs('/opt')
        report['disk_available_bytes'] = disk.f_bavail * disk.f_frsize
    except (OSError, ValueError):
        report['memory_kib'] = None
        report['disk_available_bytes'] = None
    try:
        mounts = [line.split(' - ', 1)[1].split() for line in read_text('/proc/self/mountinfo').splitlines() if ' - ' in line]
        report['cgroup_v1_memory'] = any(len(row) >= 3 and row[0] == 'cgroup' and 'memory' in row[2].split(',') for row in mounts)
    except (OSError, ValueError):
        report['cgroup_v1_memory'] = None
    try:
        report['ports'] = parse_ports(read_text('/proc/net/tcp'), read_text('/proc/net/tcp6'))
    except (OSError, ValueError):
        report['ports'] = None
    version = command(['/usr/bin/systemctl', '--version'])
    match = re.match(r'systemd (\d+)\b', version or '')
    report['systemd_version'] = int(match.group(1)) if match else None
    report['units'] = {}
    for unit in UNITS:
        text = command(['/usr/bin/systemctl', 'show', unit, '-p', 'LoadState', '--value'])
        report['units'][unit] = text.strip() if text and text.strip() in ('loaded', 'not-found', 'masked', 'error') else 'unavailable'
    report['dedicated_node'] = parse_node(command([str(NODE), '--version']))
    report['postgresql_candidates'] = []
    for major in (16, 17):
        base = Path('/usr/pgsql-' + str(major))
        text = command([str(base / 'bin/postgres'), '--version'])
        match = re.fullmatch(r'postgres \(PostgreSQL\) (' + str(major) + r'\.[0-9]+)\s*', text or '')
        if match:
            try:
                trusted(base / 'share/extension/pg_trgm.control')
                trgm = 'present_not_loaded_or_tested'
            except (OSError, ValueError):
                trgm = 'unavailable'
            report['postgresql_candidates'].append({'version': match.group(1), 'pg_trgm': trgm})
    # Candidate paths are not an exhaustive installed-package inventory.
    report['postgresql_absence_proven'] = False
    report['existing_runtime_tree'] = (ROOT / 'runtime').exists() or (ROOT / 'runtime').is_symlink()
    return report


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate_plan_key')
        result[key] = value
    return result


def verify_artifact(item, url_pattern):
    if not isinstance(item, dict) or set(item) != {'path', 'url', 'sha256'}:
        raise ValueError('invalid_artifact_fields')
    if not all(isinstance(v, str) for v in item.values()):
        raise ValueError('invalid_artifact_values')
    if not re.fullmatch(r'[0-9a-f]{64}', item['sha256']):
        raise ValueError('invalid_artifact_digest')
    if not re.fullmatch(url_pattern, item['url']):
        raise ValueError('non_pinned_or_non_vendor_artifact_url')
    if Path(item['path']).name != Path(urlsplit(item['url']).path).name:
        raise ValueError('artifact_filename_mismatch')
    digest, size = digest_file(item['path'])
    if digest != item['sha256']:
        raise ValueError('artifact_digest_mismatch')
    return {'sha256': digest, 'bytes': size}


def verify_plan(path, expected):
    if not expected or not re.fullmatch(r'[0-9a-f]{64}', expected):
        raise ValueError('reviewed_plan_sha256_required')
    actual, _ = digest_file(path, 65536)
    if actual != expected:
        raise ValueError('reviewed_plan_digest_mismatch')
    text = read_text(path)
    if hashlib.sha256(text.encode('utf-8')).hexdigest() != expected:
        raise ValueError('reviewed_plan_changed_during_read')
    plan = json.loads(text, object_pairs_hook=unique_object)
    if not isinstance(plan, dict) or set(plan) != {'format', 'node_version', 'node', 'postgresql_major', 'postgresql_rpms'} or plan['format'] != 1:
        raise ValueError('invalid_plan_fields')
    version = plan['node_version']
    if not isinstance(version, str) or parse_node(version) != version:
        raise ValueError('node_24_11_or_newer_24x_required')
    node = verify_artifact(plan['node'], r'https://nodejs\.org/dist/v' + re.escape(version) +
                           r'/node-v' + re.escape(version) + r'-linux-x64\.tar\.xz')
    major = plan['postgresql_major']
    rpms = plan['postgresql_rpms']
    if type(major) is not int or major not in (16, 17) or not isinstance(rpms, list) or len(rpms) != 4:
        raise ValueError('postgresql_16_or_17_pinned_rpms_required')
    # Only the four PGDG packages are described; their complete dependency closure
    # and package signatures MUST be reviewed separately before any installation.
    names = ['postgresql' + str(major) + suffix for suffix in ('', '-libs', '-server', '-contrib')]
    found = set()
    builds = set()
    verified = []
    for item in rpms:
        if not isinstance(item, dict) or not isinstance(item.get('url'), str):
            raise ValueError('invalid_rpm_artifact')
        pattern = (r'https://download\.postgresql\.org/pub/repos/yum/' + str(major) +
                   r'/redhat/rhel-8-x86_64/(' + '|'.join(re.escape(n) for n in names) +
                   r')-(' + str(major) + r'\.[0-9]+-[A-Za-z0-9_+.]+)\.x86_64\.rpm')
        match = re.fullmatch(pattern, item['url'])
        if not match or match.group(1) in found:
            raise ValueError('invalid_or_duplicate_pgdg_rpm')
        found.add(match.group(1))
        builds.add(match.group(2))
        verified.append(verify_artifact(item, pattern))
    if found != set(names) or len(builds) != 1:
        raise ValueError('incomplete_pgdg_core_artifacts')
    return {'status': 'local_bytes_match_reviewed_pins_only', 'plan_sha256': actual,
            'node_version': version, 'node': node, 'postgresql_major': major, 'rpms': verified,
            'trusted_vendor_signatures_checked': False, 'dependency_closure_verified': False}


def assess(host, artifacts):
    blockers = list(CURRENT_GATES)
    if host['os'] != {'ID': 'alinux', 'VERSION_ID': '3.2104'} or host['architecture'] != 'x86_64':
        blockers.append('target_must_be_alinux_3_2104_x86_64')
    if host['glibc'] != 'glibc 2.32':
        blockers.append('target_glibc_2_32_profile_not_matched')
    if tuple(host['python']) < (3, 6, 8):
        blockers.append('system_python_3_6_8_or_newer_required_do_not_replace')
    if host['systemd_version'] is None or host['systemd_version'] < 239 or host['cgroup_v1_memory'] is not True:
        blockers.append('systemd_239_and_cgroup_v1_memory_controller_required')
    memory = host['memory_kib'] or {}
    if memory.get('MemAvailable', 0) < 1024 * 1024 or (host['disk_available_bytes'] or 0) < 4 * 1024 ** 3:
        blockers.append('resource_review_required_minimum_headroom_not_observed')
    if host['ports'] is None:
        blockers.append('listener_state_unavailable')
    elif any(host['ports'][str(port)] for port in (3100, 3101, 55432)):
        blockers.append('dedicated_preview_port_occupied_do_not_stop_existing_listener')
    if any(state != 'not-found' for state in host['units'].values()):
        blockers.append('existing_or_unverifiable_preview_units_need_manual_reconciliation')
    if host['existing_runtime_tree']:
        blockers.append('existing_runtime_tree_do_not_overwrite')
    if not host['dedicated_node']:
        blockers.append('dedicated_node_24_11_or_newer_24x_not_verified')
    if not artifacts:
        blockers.append('reviewed_immutable_local_runtime_artifacts_missing')
    return {'format': 1, 'mode': 'check', 'status': 'blocked', 'changed': False,
            'ready_for_apply': False, 'ready_for_deploy': False, 'host': host,
            'artifacts': artifacts, 'blockers': blockers,
            'preserve': ['existing_8000_listener', 'default_node_and_python', 'all_existing_databases',
                         'gateway_and_exact_two_service_sudo_rule'],
            'provisional_memory_limit_mib': {'database': 256, 'api': 320, 'web': 256}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, help='root-protected reviewed local artifact manifest; never downloaded')
    parser.add_argument('--plan-sha256', help='SHA256 of that manifest from the administrator review')
    parser.add_argument('--apply', action='store_true', help='request apply; currently ALWAYS refuses without mutation')
    args = parser.parse_args(argv)
    if bool(args.plan) != bool(args.plan_sha256):
        parser.error('--plan and --plan-sha256 must be supplied together')
    # Inspect before artifact validation or any apply decision. No installation path exists.
    host = snapshot()
    artifacts = verify_plan(args.plan, args.plan_sha256) if args.plan else None
    report = assess(host, artifacts)
    if args.apply:
        report['mode'] = 'apply-refused'
    print(json.dumps(report, sort_keys=True, ensure_ascii=True, indent=2))
    return 3 if args.apply else 2


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, TypeError, KeyError):
        # Do not echo input data, paths, command output, URLs, or parser exceptions.
        print('{"format":1,"status":"invalid_or_unreadable_input","changed":false,"ready_for_apply":false,"ready_for_deploy":false}')
        sys.exit(1)
