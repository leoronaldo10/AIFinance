#!/usr/bin/python3
"""Fixed, unprivileged, bounded diagnostic schema. No caller args, shell, secrets or logs."""
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path('/opt/aifinance')
MAX_BYTES = 16384
MAX_RESULT = 65536
TOTAL_SECONDS = 35
UNITS = ('aifinance-preview-api.service', 'aifinance-preview-web.service', 'aifinance-preview-db.service')


def trusted_system_path(path):
    """Allow vendor symlinks only when both original and resolved paths are trusted."""
    p = Path(path)
    for candidate in (p, p.resolve()):
        for node in (candidate,) + tuple(candidate.parents):
            st = node.lstat()
            if st.st_uid != 0 or (not stat.S_ISLNK(st.st_mode) and st.st_mode & 0o022):
                raise ValueError('untrusted system path')


def dnf_config_trusted():
    # Do not let repo files, variables or RPM macros come from deployment-owned paths.
    try:
        deadline = time.monotonic() + 1
        count = 0
        for name in ('/etc/dnf', '/etc/yum.repos.d', '/etc/yum/vars', '/etc/rpm', '/.rpmmacros', '/.rpmrc', '/.config/dnf'):
            root = Path(name)
            if not root.exists() and not root.is_symlink():
                continue
            trusted_system_path(root)
            for base, dirs, files in os.walk(str(root), followlinks=False):
                for leaf in dirs + files:
                    count += 1
                    if count > 512 or time.monotonic() > deadline:
                        raise ValueError('config inspection limit')
                    node = Path(base) / leaf
                    if node.is_symlink():
                        raise ValueError('symlink config')
                    trusted_system_path(node)
        return True
    except (OSError, ValueError):
        return False


def safe_read(path, limit=MAX_BYTES):
    # No symlink at any path component. Fixed callers only, never a requested path.
    path = Path(path)
    for parent in reversed(path.parents):
        if parent.is_symlink():
            raise ValueError('symlink parent')
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise ValueError('untrusted metadata path')
        data = os.read(fd, limit + 1)
        if len(data) > limit:
            raise ValueError('metadata too large')
        return data.decode('utf-8', 'replace')
    finally:
        os.close(fd)


def bounded(args, deadline, logdir):
    if time.monotonic() >= deadline:
        return {'status': 'unavailable', 'reason': 'total_timeout'}
    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'HOME': '/'}
    try:
        process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, env=env, cwd='/',
                                   shell=False, start_new_session=True)
    except OSError:
        return {'status': 'unavailable', 'reason': 'command_unavailable'}
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    chunks = bytearray()
    reason = None
    end = min(deadline, time.monotonic() + 5)
    try:
        while True:
            if time.monotonic() >= end:
                reason = 'timeout'; break
            events = selector.select(max(0, end - time.monotonic()))
            if not events:
                reason = 'timeout'; break
            block = os.read(process.stdout.fileno(), min(4096, MAX_BYTES + 1 - len(chunks)))
            if not block:
                break
            chunks.extend(block)
            if len(chunks) > MAX_BYTES:
                reason = 'output_limit'; break
        if reason:
            os.killpg(process.pid, signal.SIGKILL)
        try:
            rc = process.wait(timeout=max(0.01, end - time.monotonic()))
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL); process.wait(); reason = 'timeout'; rc = -1
    finally:
        selector.close(); process.stdout.close()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL); process.wait()
    if reason or rc != 0:
        return {'status': 'unavailable', 'reason': reason or 'permission_cache_or_command_failure'}
    return {'status': 'ok', 'text': chunks.decode('utf-8', 'replace')}


def parse_modules(text):
    rows = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] == 'postgresql' and re.fullmatch(r'[0-9][0-9.]{0,15}', fields[1]):
            rows.append({'name': 'postgresql', 'stream': fields[1],
                         'enabled': '[e]' in fields, 'default': '[d]' in fields, 'installed': '[i]' in fields})
    return rows[:64]


def parse_packages(text):
    rows = []
    for line in text.splitlines():
        fields = line.split('|')
        if len(fields) != 4:
            continue
        name, version, arch, repo = fields
        if (name in ('postgresql', 'postgresql-server', 'postgresql-contrib', 'postgresql-libs')
                and re.fullmatch(r'[0-9][A-Za-z0-9_.+:-]{0,127}', version)
                and arch in ('x86_64', 'noarch', 'aarch64')
                and repo in ('base', 'alinux3-module', 'alinux3-os', 'alinux3-plus', 'alinux3-powertools', 'alinux3-updates')):
            rows.append({'name': name, 'version': version, 'arch': arch, 'repo': repo})
    return rows[:128]


def parse_units(text):
    rows = []
    for block in text.split('\n\n'):
        values = dict(line.split('=', 1) for line in block.splitlines() if '=' in line)
        if values.get('Id') not in UNITS:
            continue
        row = {'id': values['Id']}
        for field in ('LoadState', 'ActiveState', 'SubState', 'Result'):
            if re.fullmatch('[a-z-]{1,32}', values.get(field, '')):
                row[field] = values[field]
        for field in ('MemoryCurrent', 'MemoryMax'):
            value = values.get(field, '')
            if re.fullmatch('[0-9]{1,20}|infinity', value): row[field] = value
        rows.append(row)
    return rows


def deployment():
    result = {}
    # Do not read any state contents, env, authorized_keys or logs, even when root-owned.
    for p in (ROOT, ROOT / 'shared', ROOT / 'state'):
        try:
            if p.is_symlink() or not p.is_dir():
                return {'status': 'unavailable', 'reason': 'unexpected_parent'}
        except OSError:
            return {'status': 'unavailable', 'reason': 'metadata_unavailable'}
    for name in ('native-ready', 'schema.sha256', 'first-prepare.json'):
        try:
            st = (ROOT / 'shared' / name).lstat()
            result[name] = 'regular' if stat.S_ISREG(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022 else 'unexpected_type_or_owner'
        except FileNotFoundError:
            result[name] = 'absent'
        except OSError:
            result[name] = 'unavailable'
    try:
        target = os.readlink(str(ROOT / 'state/current'))
        match = re.fullmatch(re.escape(str(ROOT / 'releases')) + r'/([a-f0-9]{40})', target)
        result['current_sha'] = match.group(1) if match else 'unexpected_target'
    except FileNotFoundError:
        result['current_sha'] = 'absent'
    except OSError:
        result['current_sha'] = 'unavailable'
    return result


def inspect():
    end = time.monotonic() + TOTAL_SECONDS
    report = {'schema': 1}
    try:
        text = safe_read('/etc/os-release')
        values = dict(line.split('=', 1) for line in text.splitlines() if '=' in line)
        report['os'] = {k: values[k].strip('"') for k in ('ID', 'VERSION_ID')
                        if re.fullmatch(r'"?[A-Za-z0-9_.-]{1,64}"?', values.get(k, ''))}
    except (OSError, ValueError): report['os'] = {'status': 'unavailable'}
    try:
        text = safe_read('/proc/meminfo')
        report['memory_kib'] = {k: int(v) for k, v in re.findall(r'^(MemTotal|MemAvailable|SwapTotal|SwapFree):\s+(\d+) kB$', text, re.M)}
    except (OSError, ValueError): report['memory_kib'] = {'status': 'unavailable'}
    try:
        # Fixed mount only, not any caller-supplied deployment path.
        st = os.statvfs('/opt')
        report['disk_bytes'] = {'available': st.f_bavail * st.f_frsize, 'total': st.f_blocks * st.f_frsize}
    except OSError: report['disk_bytes'] = {'status': 'unavailable'}
    report['deployment'] = deployment()
    with tempfile.TemporaryDirectory(prefix='aifinance-inspect-') as temp:
        # Ignore global dnf.conf options that can redirect to a user-writable config tree.
        dnf = ['/usr/bin/dnf', '-C', '--noplugins', '--config=/dev/null',
               '--setopt=reposdir=/etc/yum.repos.d',
               '--setopt=varsdir=/etc/dnf/vars,/etc/yum/vars',
               '--setopt=cachedir=/var/cache/dnf', '--setopt=persistdir=' + temp,
               '--setopt=logdir=' + temp]
        commands = {
            'modules': (dnf + ['module', 'list', '--all', 'postgresql'], parse_modules),
            'packages_unfiltered': (dnf + ['repoquery', '--available', '--disable-modular-filtering', '--qf',
                                         '%{name}|%{version}-%{release}|%{arch}|%{repoid}',
                                         'postgresql', 'postgresql-server', 'postgresql-contrib', 'postgresql-libs'], parse_packages),
            'services': (['/usr/bin/systemctl', 'show'] + list(UNITS) + ['-p', 'Id', '-p', 'LoadState', '-p', 'ActiveState', '-p', 'SubState', '-p', 'Result', '-p', 'MemoryCurrent', '-p', 'MemoryMax'], parse_units),
        }
        for name, (args, parser) in commands.items():
            try:
                trusted_system_path(args[0])
                if name in ('modules', 'packages_unfiltered') and not dnf_config_trusted():
                    raise ValueError('untrusted config')
            except (OSError, ValueError):
                report[name] = {'status': 'unavailable', 'reason': 'untrusted_or_missing_system_files'}
                continue
            result = bounded(args, end, temp)
            report[name] = {'status': 'ok', 'rows': parser(result['text']), 'absence_not_proven': True} if result['status'] == 'ok' else result
        result = bounded(['/usr/bin/systemctl', '--version'], end, temp)
        match = re.search(r'^systemd (\d+)', result.get('text', ''))
        report['systemd_version'] = int(match.group(1)) if match else 'unavailable'
        result = bounded(['/usr/bin/findmnt', '-rn', '-t', 'cgroup,cgroup2', '-o', 'FSTYPE'], end, temp)
        report['cgroup_mount_types'] = sorted(set(x for x in result.get('text', '').splitlines() if x in ('cgroup', 'cgroup2'))) if result['status'] == 'ok' else result
        result = bounded(['/usr/sbin/ss', '-H', '-ltn'], end, temp)
        if result['status'] != 'ok':
            report['ports'] = result
        else:
            report['ports'] = {str(p): [] for p in (22, 8000, 3100, 3101, 55432)}
            for line in result['text'].splitlines():
                fields = line.split()
                if len(fields) < 4: continue
                match = re.fullmatch(r'(.*):(22|8000|3100|3101|55432)', fields[3])
                if match:
                    host, port = match.groups()
                    kind = 'loopback' if host in ('127.0.0.1', '[::1]', '::1') else 'wildcard' if host in ('*', '0.0.0.0', '[::]', '::') else 'other'
                    report['ports'][port].append(kind)
    return report


def main():
    if len(sys.argv) != 1:
        raise SystemExit('No diagnostic arguments accepted')
    data = json.dumps(inspect(), ensure_ascii=True, sort_keys=True)
    if len(data.encode()) > MAX_RESULT:
        raise SystemExit('Diagnostic output limit')
    print(data)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError):
        print('{"schema":1,"status":"unavailable"}')
        sys.exit(1)
