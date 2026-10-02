#!/usr/bin/python3
"""First preview only. Root authorizes setup; all release code runs unprivileged.

No native-ready is written. Target isolation evidence must be accepted separately.
No existing release or database is replaced or deleted after a failure.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import resource
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, build_opener

ROOT = Path('/opt/aifinance')
BIN = ROOT / 'bin'
SYSTEMCTL = '/usr/bin/systemctl'
ENV = dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin', HOME='/', LANG='C', LC_ALL='C')
APP_UNITS = ['aifinance-preview-api.service', 'aifinance-preview-web.service']
DB_UNIT = 'aifinance-preview-db.service'
GUARD_UNIT = 'aifinance-preview-egress.service'
MAX_ARCHIVE = 128 * 1024 * 1024


def call(args, timeout=15, output=False):
    result = subprocess.run(args, env=ENV, cwd='/', stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE if output else subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=timeout, check=True)
    if output:
        if len(result.stdout) > 32768:
            raise ValueError('metadata_output_limit')
        return result.stdout.decode('utf-8', 'strict').strip()


def trusted(path):
    path = Path(path)
    for p in (path,) + tuple(path.parents):
        s = p.lstat()
        if s.st_uid != 0 or s.st_mode & 0o022 or not (stat.S_ISREG(s.st_mode) if p == path else stat.S_ISDIR(s.st_mode)):
            raise ValueError('untrusted_administrator_input')


def text_file(path, limit=32768):
    # Only release metadata. Reject symlink components, special files and huge data.
    for p in path.parents:
        if p.is_symlink():
            raise ValueError('metadata_symlink_parent')
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_size > limit:
            raise ValueError('metadata_not_small_regular_file')
        data = os.read(fd, limit + 1)
        if len(data) > limit:
            raise ValueError('metadata_size_limit')
        return data.decode('utf-8', 'strict')
    finally:
        os.close(fd)


def schema(release):
    manifest = text_file(release / 'schema.sha256')
    names = []
    for line in manifest.splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (database/migrations/[0-9]{4}_[a-z0-9_]+\.sql)', line)
        if not match or match.group(2) in names:
            raise ValueError('invalid_schema_manifest')
        name = match.group(2)
        raw = text_file(release / name, 1024 * 1024).encode('utf-8')
        if hashlib.sha256(raw).hexdigest() != match.group(1):
            raise ValueError('schema_fingerprint_mismatch')
        names.append(name)
    actual = sorted('database/migrations/' + p.name for p in (release / 'database/migrations').iterdir())
    if not names or sorted(names) != actual:
        raise ValueError('incomplete_schema_manifest')
    return manifest, [Path(name).name for name in names]


def stage(sha, digest):
    """Only the existing deploy identity may parse/extract an uploaded release."""
    if os.geteuid() != pwd.getpwnam('aifinance-deploy').pw_uid or os.geteuid() == 0:
        raise ValueError('stage_requires_deploy_identity')
    archive = ROOT / 'incoming' / (sha + '.tar.gz')
    release = ROOT / 'releases' / sha
    current = ROOT / 'state/current'
    if any(p.exists() or p.is_symlink() for p in (release, current, ROOT / 'state/.current-next')):
        raise ValueError('first_release_state_already_exists')
    fd = os.open(str(archive), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or not 0 < s.st_size <= MAX_ARCHIVE:
            raise ValueError('invalid_archive')
        h = hashlib.sha256()
        with os.fdopen(fd, 'rb') as f:
            fd = -1
            for part in iter(lambda: f.read(1024 * 1024), b''):
                h.update(part)
        if h.hexdigest() != digest:
            raise ValueError('archive_digest_mismatch')
    finally:
        if fd != -1:
            os.close(fd)
    temporary = Path(tempfile.mkdtemp(prefix='.first-', dir=str(ROOT / 'releases')))
    try:
        call(['/usr/bin/python3', '-I', '-B', str(BIN / 'extract-release.py'), str(archive), str(temporary)], 90)
        if text_file(temporary / 'RELEASE_SHA', 64).strip() != sha:
            raise ValueError('release_sha_mismatch')
        schema(temporary)
        if not (temporary / 'apps/web/build/server/index.js').is_file() or not (temporary / 'node_modules').is_dir():
            raise ValueError('production_build_missing')
        os.rename(str(temporary), str(release))
        # First installation has no previous release to restore. Preserve this
        # exact selection on later failures for administrator inspection.
        os.symlink(str(release), str(current))
    finally:
        if temporary.exists():
            shutil.rmtree(str(temporary))


def property_value(unit, name):
    return call([SYSTEMCTL, 'show', unit, '-p', name, '--value'], output=True)


def listeners():
    result = {str(port): [] for port in (8000, 3100, 3101, 55432)}
    for name in ('tcp', 'tcp6'):
        for line in Path('/proc/net/' + name).read_text().splitlines()[1:]:
            row = line.split()
            if len(row) < 10 or row[3] != '0A':
                continue
            address, port = row[1].split(':')
            key = str(int(port, 16))
            if key in result:
                result[key].append((address, row[9]))
    return {k: sorted(v) for k, v in result.items()}


def preflight():
    if os.geteuid() != 0:
        raise ValueError('administrator_terminal_required')
    for name in ('first-preview.py', 'run-preview.py', 'extract-release.py', 'egress-guard.py'):
        trusted(BIN / name)
    for p in (ROOT / 'state/current', ROOT / 'shared/native-ready', ROOT / 'shared/schema.sha256'):
        if p.exists() or p.is_symlink():
            raise ValueError('first_preview_only_existing_state')
    for unit in APP_UNITS:
        if property_value(unit, 'LoadState') != 'loaded' or property_value(unit, 'ActiveState') != 'inactive':
            raise ValueError('application_units_not_fresh_inactive')
    if property_value(DB_UNIT, 'ActiveState') != 'active' or property_value(GUARD_UNIT, 'ActiveState') != 'active':
        raise ValueError('database_and_egress_guard_must_be_active')
    call(['/usr/bin/python3', '-I', '-B', str(BIN / 'egress-guard.py'), 'verify'])
    before = listeners()
    if before['3100'] or before['3101'] or not before['55432'] or any(a != '0100007F' for a, _ in before['55432']):
        raise ValueError('unexpected_preview_listeners')
    available = re.search(r'^MemAvailable:\s+(\d+) kB$', Path('/proc/meminfo').read_text(), re.M)
    if not available or int(available.group(1)) < 700 * 1024:
        raise ValueError('first_start_memory_reserve_below_700_mib')
    return before['8000']


def setup_role(role):
    if role not in ('migrate', 'seed-topics'):
        raise ValueError('invalid_setup_role')
    unit = 'aifinance-preview-' + role
    if property_value(unit + '.service', 'LoadState') != 'not-found':
        raise ValueError('setup_unit_exists')
    props = ['User=aifinance', 'Group=aifinance', 'MemoryAccounting=yes', 'MemoryLimit=320M',
             'TasksMax=64', 'CPUQuota=50%', 'LimitNOFILE=4096', 'LimitCORE=0', 'UMask=0077',
             'RuntimeMaxSec=180', 'TimeoutStopSec=20', 'KillMode=control-group',
             'NoNewPrivileges=yes', 'CapabilityBoundingSet=', 'AmbientCapabilities=',
             'PrivateTmp=yes', 'ProtectSystem=strict', 'ProtectHome=yes',
             'ReadWritePaths=/opt/aifinance/shared/data', 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6',
             'StandardOutput=null', 'StandardError=null', 'BindsTo=' + GUARD_UNIT,
             'Requires=' + DB_UNIT, 'After=' + GUARD_UNIT + ' ' + DB_UNIT]
    args = ['/usr/bin/systemd-run', '--quiet', '--wait', '--collect', '--unit=' + unit]
    for prop in props:
        args += ['--property=' + prop]
    args += ['/usr/bin/python3', '-I', '-B', str(BIN / 'run-preview.py'), role]
    # v239 transient ExecStartPre does not accept the + prefix. Root verifies
    # immediately before launch; no firewall maintenance may overlap this run.
    call(['/usr/bin/python3', '-I', '-B', str(BIN / 'egress-guard.py'), 'verify'])
    try:
        call(args, 220)
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
        # The unique name was absent before this invocation. Stop only this setup.
        call([SYSTEMCTL, 'stop', unit + '.service'], 30)
        raise


def query(sql, app=False):
    if app:
        # Query app-owned objects through an actual nonsuperuser connection.
        # A malicious view must never run inside a postgres superuser session.
        trusted(Path('/etc/aifinance-preview.env'))
        spec = importlib.util.spec_from_file_location('preview_launcher', str(BIN / 'run-preview.py'))
        launcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(launcher)
        env = launcher.environment(text_file(Path('/etc/aifinance-preview.env'), 8192))
        password = urlsplit(env['DATABASE_URL']).password
        account = pwd.getpwnam('aifinance')
        def drop():
            os.setgroups([]); os.setgid(account.pw_gid); os.setuid(account.pw_uid)
        process = subprocess.Popen(['/usr/pgsql-17/bin/psql', '-X', '-w', '-A', '-t', '-v', 'ON_ERROR_STOP=1',
                                 '-h', '127.0.0.1', '-p', '55432', '-U', 'aifinance_preview',
                                 '-d', 'aifinance_preview', '-c', sql],
                                env=dict(ENV, PGPASSWORD=password), preexec_fn=drop, cwd='/',
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                start_new_session=True)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        chunks = bytearray()
        end = time.monotonic() + 15
        try:
            while True:
                if not selector.select(max(0, end - time.monotonic())):
                    raise ValueError('database_acceptance_timeout')
                part = os.read(process.stdout.fileno(), min(4096, 32769 - len(chunks)))
                if not part:
                    break
                chunks.extend(part)
                if len(chunks) > 32768:
                    raise ValueError('database_acceptance_output_limit')
            if process.wait(timeout=max(0.01, end - time.monotonic())) != 0:
                raise ValueError('database_acceptance_query_failed')
            return chunks.decode('utf-8', 'strict').strip()
        finally:
            selector.close(); process.stdout.close()
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL); process.wait()
    return call(['/usr/sbin/runuser', '-u', 'postgres', '--', '/usr/pgsql-17/bin/psql',
                 '-X', '-w', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-h', '/run/aifinance-preview-db',
                 '-p', '55432', '-d', 'aifinance_preview', '-c', sql], output=True)


def database_accepted(names):
    applied = query('SELECT pg_catalog.left(name::pg_catalog.text, 256) FROM public.schema_migrations ORDER BY name LIMIT 1000', app=True).splitlines()
    if applied != sorted(names):
        raise ValueError('database_migrations_mismatch')
    identity = query("SELECT current_database(), (SELECT extversion IS NOT NULL FROM pg_catalog.pg_extension WHERE extname='pg_trgm'), (SELECT NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls) AND rolcanlogin FROM pg_catalog.pg_roles WHERE rolname='aifinance_preview')")
    if identity != 'aifinance_preview|t|t':
        raise ValueError('database_identity_extension_role_failed')


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("health_redirect_refused")


def health(sha):
    opener = build_opener(ProxyHandler({}), NoRedirect())
    for unused in range(20):
        try:
            if all(property_value(u, 'ActiveState') == 'active' for u in APP_UNITS):
                with opener.open('http://127.0.0.1:3101/api/health', timeout=3) as r:
                    data = json.loads(r.read(8193).decode())
                if not isinstance(data, dict):
                    raise ValueError('health_object_required')
                with opener.open('http://127.0.0.1:3100/', timeout=3) as r:
                    web_ok = r.status == 200
                if data.get('ok') is True and data.get('release') == sha and web_ok:
                    return
        except (OSError, ValueError):
            pass
        time.sleep(2)
    raise ValueError('first_preview_health_failed')


def resource_evidence():
    """Actual running PID identity and kernel v1 memory limit, not unit text alone."""
    report = {}
    for role, budget, account in (('api', 320, 'aifinance'), ('web', 256, 'aifinance'), ('db', 256, 'postgres')):
        unit = 'aifinance-preview-' + role + '.service'
        pid = property_value(unit, 'MainPID')
        if not re.fullmatch(r'[1-9][0-9]{0,9}', pid):
            raise ValueError('service_main_pid_unavailable')
        status = Path('/proc/' + pid + '/status').read_text()
        values = dict(line.split(':', 1) for line in status.splitlines() if ':' in line)
        uid = pwd.getpwnam(account).pw_uid
        if (values.get('Uid', '').split() != [str(uid)] * 4 or
                values.get('NoNewPrivs', '').strip() != '1' or int(values.get('CapEff', '1').strip(), 16) != 0):
            raise ValueError('service_identity_or_privileges_unaccepted')
        groups = []
        for line in Path('/proc/' + pid + '/cgroup').read_text().splitlines():
            fields = line.split(':', 2)
            if len(fields) == 3 and 'memory' in fields[1].split(','):
                groups.append(fields[2])
        expected = '/system.slice/' + unit
        if groups != [expected]:
            raise ValueError('service_not_in_expected_v1_memory_cgroup')
        base = Path('/sys/fs/cgroup/memory') / expected.lstrip('/')
        if pid not in (base / 'cgroup.procs').read_text().split():
            raise ValueError('service_cgroup_membership_mismatch')
        kernel = {}
        for field in ('limit_in_bytes', 'usage_in_bytes', 'max_usage_in_bytes', 'failcnt'):
            raw = (base / ('memory.' + field)).read_text().strip()
            if not re.fullmatch(r'[0-9]{1,20}', raw):
                raise ValueError('invalid_kernel_memory_counter')
            kernel[field] = int(raw)
        if kernel['limit_in_bytes'] != budget * 1024 ** 2 or kernel['failcnt'] != 0:
            raise ValueError('memory_limit_not_enforced_or_hit_during_start')
        if property_value(unit, 'MainPID') != pid:
            raise ValueError('service_restarted_during_acceptance')
        report[role] = dict(kernel, pid=int(pid), uid=uid)
    return report


def activate(sha, digest):
    before = preflight()
    try:
        call(['/usr/sbin/runuser', '-u', 'aifinance-deploy', '--', '/usr/bin/python3', '-I', '-B',
              str(BIN / 'first-preview.py'), 'stage', sha, digest], 120)
        manifest, names = schema(ROOT / 'releases' / sha)
        # Fresh DB only. There must be no application tables before migration.
        if query("SELECT count(*) FROM pg_catalog.pg_tables WHERE schemaname='public'") != '0':
            raise ValueError('database_is_not_empty')
        setup_role('migrate')
        setup_role('seed-topics')
        database_accepted(names)
        call([SYSTEMCTL, 'start'] + APP_UNITS, 40)
        health(sha)
        after = listeners()
        if after['8000'] != before or any(not after[str(p)] or any(a != '0100007F' for a, _ in after[str(p)]) for p in (3100, 3101, 55432)):
            raise ValueError('listener_preservation_failed')
        evidence = resource_evidence()
        with (ROOT / 'shared/schema.sha256').open('x') as f:
            os.fchmod(f.fileno(), 0o644)
            f.write(manifest)
        print(json.dumps({'first_preview_healthy': True, 'release': sha, 'old_8000_listener_preserved': True,
                          'schema_verified': True, 'resources': evidence, 'pressure_and_reboot_accepted': False, 'native_ready_written': False, 'ready_for_deploy': False}))
    except (OSError, ValueError, subprocess.SubprocessError):
        # Only these newly provisioned preview services. Keep guard loaded and
        # preserve the selected release, env and PGDATA; no claimed rollback.
        try:
            call([SYSTEMCTL, 'stop'] + APP_UNITS + [DB_UNIT], 40)
        except (OSError, subprocess.SubprocessError):
            print('STOP_FAILED: administrator must stop the three preview units', file=sys.stderr)
        raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('operation', choices=('check', 'start', 'stage'))
    parser.add_argument('sha')
    parser.add_argument('archive_sha256')
    a = parser.parse_args()
    if not re.fullmatch(r'[0-9a-f]{40}', a.sha) or not re.fullmatch(r'[0-9a-f]{64}', a.archive_sha256):
        raise ValueError('exact_release_and_archive_hash_required')
    if a.operation == 'stage':
        stage(a.sha, a.archive_sha256)
    elif a.operation == 'start':
        activate(a.sha, a.archive_sha256)
    else:
        preflight()
        print('CHECK ONLY: first preview prerequisites passed; no release code executed')


if __name__ == '__main__':
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    def interrupted(signum, frame):
        raise ValueError('administrator_run_interrupted')
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupted)
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError):
        raise SystemExit('STOP: first preview incomplete; preserve new state and inspect; no rollback or native-ready claimed')
