#!/usr/bin/python3
"""One reviewed e6 -> d57 maintenance operation. Default check is read-only.

Run an administrator-owned installed copy with Python -I -B. Never marks native
ready, runs generic migrations, enables collection, or automatically rolls back.
"""
import argparse
import contextlib
import fcntl
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
from urllib.parse import urlsplit, unquote

ROOT = Path('/opt/aifinance')
BIN = ROOT / 'bin'
STATE = Path('/var/lib/aifinance-maintenance')
BACKUPS = Path('/var/backups/aifinance-collect-only')
RESTORES = Path('/var/lib/aifinance-restore')
ARTIFACTS = ROOT / 'maintenance-inputs'
PG = Path('/usr/pgsql-17/bin')
OLD = 'e6f84e81b17f1d916e9f5024769fe8af737b2315'
NEW = 'd57ba047369e666025347719caee1a4c642abe62'
OLD_SCHEMA = '33662b6612b0ce65eacd9c783e98da9b07835f90c03847b01430aec6ccfa85cb'
NEW_SCHEMA = '405672156ea4ef49bc9272d47f23de3a7208a8c80a9d2bee066e6d607152cafc'
MIGRATION = '0041_collect_only.sql'
MIGRATION_DIGEST = 'a71db6b66e9dfc862d60df2199e37e4baab13f1ba20056011984b33059b7ecef'
DB = 'aifinance_preview'
ENV_FILE = Path('/etc/aifinance-preview.env')
APP_UNITS = ['aifinance-preview-api.service', 'aifinance-preview-web.service']
CTL = '/usr/bin/systemctl'
ENV = dict(PATH='/usr/pgsql-17/bin:/usr/sbin:/usr/bin:/sbin:/bin', HOME='/', LANG='C', LC_ALL='C', TZ='UTC')
MAX_ARCHIVE = 128 * 1024 ** 2
UNIT_DIGESTS = {'aifinance-preview-api.service': 'a233ae654f3fc5c1c67c5b1cb3c0f7029428e7852afeea4934fa1ce4c54f70ed', 'aifinance-preview-web.service': 'b18f56c0461808d128786b74a425baf42c7a7abb6583a4828e531b7686468af6', 'aifinance-preview-db.service': '6f887ef4c0b7e753c2d80929963fabde5e630d9bbca7b298e24fa6cb4573a02a', 'aifinance-preview-egress.service': 'e89d001be5bb1929553c1b219759a9f123da6484229af3264e954f072047773e'}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def account(name):
    a = pwd.getpwnam(name)
    if a.pw_uid == 0:
        raise ValueError('unprivileged_identity_required')
    return a


def drop(name):
    a = account(name)
    def change():
        os.setgroups([]); os.setgid(a.pw_gid); os.setuid(a.pw_uid); os.umask(0o077)
    return change


def command(args, data=None, env=None, user=None, timeout=30, output=False, out_file=None):
    p = subprocess.Popen(args, env=ENV if env is None else env, cwd='/',
                         stdin=subprocess.PIPE, stdout=out_file if out_file is not None else subprocess.PIPE,
                         stderr=subprocess.DEVNULL, start_new_session=True,
                         preexec_fn=drop(user) if user else None)
    try:
        if data:
            p.stdin.write(data)
        p.stdin.close()
        raw = bytearray()
        if p.stdout is not None:
            select = selectors.DefaultSelector(); select.register(p.stdout, selectors.EVENT_READ)
            until = time.monotonic() + timeout
            try:
                while True:
                    if not select.select(max(0, until - time.monotonic())):
                        raise ValueError('fixed_command_timeout')
                    part = os.read(p.stdout.fileno(), 16384)
                    if not part:
                        break
                    raw.extend(part)
                    if len(raw) > 1024 * 1024:
                        raise ValueError('metadata_output_limit')
            finally:
                select.close(); p.stdout.close()
            timeout = max(0.01, until - time.monotonic())
        if p.wait(timeout=timeout) != 0:
            raise ValueError('fixed_command_failed')
        return raw.decode('utf-8').strip() if output else None
    except BaseException:
        if p.poll() is None:
            os.killpg(p.pid, signal.SIGKILL)
        p.wait()
        raise


def trusted(path, directory=False):
    for p in (path,) + tuple(path.parents):
        s = p.lstat()
        kind = stat.S_ISDIR if p != path or directory else stat.S_ISREG
        if not kind(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise ValueError('untrusted_administrator_path')


def helper(name):
    path = BIN / name
    trusted(path)
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), str(path))
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    return m


def small(path, limit=32768):
    for p in path.parents:
        if p.is_symlink():
            raise ValueError('symlink_parent')
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_size > limit:
            raise ValueError('regular_bounded_file_required')
        b = os.read(fd, limit + 1)
        if len(b) > limit:
            raise ValueError('file_size_limit')
        return b
    finally:
        os.close(fd)


def file_digest(path, maximum=None):
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as f:
        s = os.fstat(f.fileno())
        if not stat.S_ISREG(s.st_mode) or s.st_size <= 0 or (maximum and s.st_size > maximum):
            raise ValueError('invalid_file_size_or_type')
        h = hashlib.sha256()
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest(), s.st_size


def absent(path):
    if path.exists() or path.is_symlink():
        raise ValueError('existing_state_requires_review')


def prop(unit, key):
    return command([CTL, 'show', unit, '-p', key, '--value'], output=True)


def db_env():
    trusted(ENV_FILE)
    values = helper('run-preview.py').environment(small(ENV_FILE, 8192).decode())
    u = urlsplit(values['DATABASE_URL'])
    return dict(ENV, PGPASSWORD=unquote(u.password), PGCONNECT_TIMEOUT='5')


def psql(sql, database=DB, local=False, restore=None, output=True, timeout=20):
    args = [str(PG / 'psql'), '-X', '-w', '-q', '-A', '-t', '-v', 'ON_ERROR_STOP=1']
    if restore:
        args += ['-h', str(restore / 'socket'), '-p', '55433', '-U', DB, '-d', database]
        env, user = ENV, None
    elif local:
        args += ['-h', '/run/aifinance-preview-db', '-p', '55432', '-U', 'postgres', '-d', database]
        env, user = ENV, 'postgres'
    else:
        args += ['-h', '127.0.0.1', '-p', '55432', '-U', DB, '-d', database]
        env, user = db_env(), 'aifinance'
    return command(args, data=sql.encode(), env=env, user=user, timeout=timeout, output=output)


def identifier(value):
    if not re.fullmatch(r'[a-z_][a-z0-9_]{0,62}', value):
        raise ValueError('unexpected_database_identifier')
    return '"' + value + '"'


def snapshot(restore=None, content=True, legacy=False):
    # Query under the true application login, not a superuser SET ROLE session.
    query = lambda q: psql("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL statement_timeout='10s'; SET LOCAL timezone='UTC'; " + q + '; COMMIT;', restore=restore)
    names = query("SELECT n.nspname || '.' || c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('public','pgboss') AND c.relkind IN ('r','p') ORDER BY 1").splitlines()
    if not {'public.articles', 'public.sources', 'public.schema_migrations'}.issubset(names):
        raise ValueError('baseline_tables_missing')
    tables = {}
    for name in names:
        parts = name.split('.')
        if len(parts) != 2:
            raise ValueError('invalid_table_name')
        table = '.'.join(identifier(p) for p in parts)
        count = int(query('SELECT count(*) FROM ' + table))
        # Hash every row while bounding database work and client memory. The
        # aggregate is fixed-length; string_agg is deliberately not used.
        row = "(to_jsonb(t) - 'collect_only')" if legacy and name in ('public.articles', 'public.sources') else 'to_jsonb(t)'
        condition = " WHERE t.name <> '0041_collect_only.sql'" if legacy and name == 'public.schema_migrations' else ''
        hashes = query('SELECT md5(' + row + '::text) FROM ' + table + ' t' + condition + ' ORDER BY 1') if content else ''
        tables[name] = {'count': count, 'sha256': digest(hashes.encode()) if content else None}
    migrations = query('SELECT name FROM public.schema_migrations ORDER BY name').splitlines()
    catalog = query("SELECT json_build_object('schema',n.nspname,'table',c.relname,'owner',pg_catalog.pg_get_userbyid(c.relowner),'acl',c.relacl::text)::text FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('public','pgboss') AND c.relkind IN ('r','p','S','v') ORDER BY n.nspname,c.relname")
    extensions = query('SELECT extname || \'|\' || extversion || \'|\' || pg_catalog.pg_get_userbyid(extowner) FROM pg_catalog.pg_extension ORDER BY extname')
    return {'tables': tables, 'migrations': migrations, 'catalog': catalog, 'extensions': extensions, 'metadata': database_metadata(query)}


def database_metadata(query):
    # No pg_authid/rolpassword read. Unexpected role dependencies fail closed.
    role = query("SELECT rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolbypassrls,rolconnlimit,COALESCE(rolvaliduntil::text,''),COALESCE(rolconfig::text,'') FROM pg_catalog.pg_roles WHERE rolname='aifinance_preview'")
    if role != 'f|t|f|f|t|f|f|6||':
        raise ValueError('unexpected_application_role_attributes')
    memberships = query("SELECT count(*) FROM pg_catalog.pg_auth_members WHERE roleid=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname='aifinance_preview') OR member=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname='aifinance_preview')")
    if memberships != '0':
        raise ValueError('unexpected_application_role_memberships')
    ownership = query("SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('public','pgboss') AND pg_catalog.pg_get_userbyid(c.relowner) NOT IN ('aifinance_preview','postgres','pg_database_owner')")
    if ownership != '0':
        raise ValueError('unexpected_object_owner_dependency')
    schemas = query("SELECT nspname,pg_catalog.pg_get_userbyid(nspowner),COALESCE(nspacl::text,'') FROM pg_catalog.pg_namespace WHERE nspname IN ('public','pgboss') ORDER BY nspname")
    database = query("SELECT pg_catalog.pg_get_userbyid(datdba),pg_encoding_to_char(encoding),datcollate,datctype,COALESCE(datacl::text,'') FROM pg_catalog.pg_database WHERE datname=current_database()")
    sequence_names = query("SELECT n.nspname || '.' || c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('public','pgboss') AND c.relkind='S' ORDER BY 1").splitlines()
    sequences = {}
    for name in sequence_names:
        table = '.'.join(identifier(p) for p in name.split('.'))
        sequences[name] = query('SELECT last_value,is_called FROM ' + table)
    return {'role': role, 'memberships': memberships, 'schemas': schemas, 'database': database, 'sequences': sequences}


def compatible(before, after):
    if before != after:
        raise ValueError('restored_database_evidence_mismatch')


def exact_schema(release, expected):
    fp = helper('first-preview.py')
    manifest, names = fp.schema(release)
    if digest(manifest.encode()) != expected:
        raise ValueError('reviewed_schema_digest_mismatch')
    return manifest, sorted(names)


def archive_check(expected, path=None):
    if not re.fullmatch('[0-9a-f]{64}', expected or ''):
        raise ValueError('explicit_archive_sha256_required')
    actual, size = file_digest(path or ROOT / 'incoming' / (NEW + '.tar.gz'), MAX_ARCHIVE)
    if actual != expected:
        raise ValueError('archive_digest_mismatch')
    return size


def current_old():
    p = ROOT / 'state/current'
    if not p.is_symlink() or p.resolve(strict=True) != ROOT / 'releases' / OLD:
        raise ValueError('current_must_be_exact_reviewed_old_release')
    if small(p.resolve() / 'RELEASE_SHA', 64).decode().strip() != OLD:
        raise ValueError('old_release_metadata_mismatch')
    absent(ROOT / 'state/.current-next')
    absent(ROOT / 'shared/native-ready')


def quiet_database():
    for process in Path('/proc').iterdir():
        if not process.name.isdigit():
            continue
        try:
            status = (process / 'status').read_text()
        except FileNotFoundError:
            continue
        match = re.search(r'^Uid:\s+(\d+)', status, re.M)
        if match and int(match.group(1)) == 989:
            raise ValueError('unreviewed_app_uid_process_active')
    # Own maintenance connection is excluded. Never kill unrecognised sessions.
    n = psql("SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE datname='aifinance_preview' AND pid<>pg_backend_pid() AND backend_type='client backend'", local=True)
    if n != '0':
        raise ValueError('other_database_clients_active')
    # Queued/running workers and schedules are not adopted or stopped silently.
    units = command([CTL, 'list-units', '--all', '--no-legend', '--plain', '--no-pager', 'aifinance*'], output=True)
    allowed = set(APP_UNITS + ['aifinance-preview-db.service', 'aifinance-preview-egress.service'])
    for row in units.splitlines():
        fields = row.split()
        if len(fields) >= 4 and fields[0] not in allowed and fields[2] in ('active', 'activating', 'reloading'):
            raise ValueError('unreviewed_aifinance_writer_or_timer')


def backup_parent(create=False):
    parent = BACKUPS.parent
    if not parent.exists() and not parent.is_symlink():
        trusted(parent.parent, directory=True)
        if not create:
            return False
        parent.mkdir(mode=0o700)
        # Only the new directory is assigned root:root; existing paths are never repaired.
        fd = os.open(str(parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fchown(fd, 0, 0)
            os.fchmod(fd, 0o755)
        finally:
            os.close(fd)
    trusted(parent, directory=True)
    if stat.S_IMODE(parent.stat().st_mode) != 0o755 or parent.stat().st_gid != 0:
        raise ValueError('backup_parent_mode_mismatch')
    return True


def lock_info():
    deploy = account('aifinance-deploy')
    for parent in (ROOT, ROOT / 'state'):
        st = parent.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid not in (0, deploy.pw_uid) or stat.S_IMODE(st.st_mode) != 0o755:
            raise ValueError('release_lock_parent_mismatch')
    trusted(ROOT.parent, directory=True)
    path = ROOT / 'state/release.lock'
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != deploy.pw_uid or
            info.st_gid != deploy.pw_gid or stat.S_IMODE(info.st_mode) != 0o644):
        raise ValueError('existing_release_lock_owner_mode_mismatch')
    return info


def preflight(expected):
    if os.getuid() != 0 or os.geteuid() != 0:
        raise ValueError('root_administrator_required')
    if Path(__file__).absolute() != BIN / 'collect-only-upgrade.py':
        raise ValueError('installed_reviewed_helper_required')
    trusted(Path(__file__).absolute())
    for name in ('first-preview.py', 'extract-release.py', 'run-preview.py', 'egress-guard.py'):
        trusted(BIN / name)
    if account('aifinance').pw_uid != 989 or account('postgres').pw_uid != 26:
        raise ValueError('reviewed_server_accounts_required')
    for tool in ('psql','pg_dump','pg_restore','initdb','pg_ctl'):
        trusted(PG / tool)
        if command([str(PG / tool), '--version'], output=True) != tool + ' (PostgreSQL) 17.11':
            raise ValueError('reviewed_pg17_11_tools_required')
    current_old()
    absent(STATE / 'collect-only-upgrade.json')
    size = archive_check(expected)
    backup_parent_exists = backup_parent()
    lock_exists = lock_info() is not None
    manifest, names = exact_schema(ROOT / 'releases' / OLD, OLD_SCHEMA)
    if small(ROOT / 'shared/schema.sha256') != manifest.encode():
        raise ValueError('shared_schema_mismatch')
    for unit in APP_UNITS + ['aifinance-preview-db.service', 'aifinance-preview-egress.service']:
        if prop(unit, 'ActiveState') != 'active' or prop(unit, 'DropInPaths'):
            raise ValueError('reviewed_services_active_without_overrides_required')
        unit_path = Path('/etc/systemd/system') / unit
        trusted(unit_path)
        if prop(unit, 'FragmentPath') != str(unit_path) or digest(small(unit_path)) != UNIT_DIGESTS[unit]:
            raise ValueError('reviewed_unit_content_required')
    helper('first-preview.py').health(OLD)
    command(['/usr/bin/python3', '-I', '-B', str(BIN / 'egress-guard.py'), 'verify'])
    baseline = snapshot(content=False)
    if baseline['migrations'] != names:
        raise ValueError('migration_ledger_not_exact_old_manifest')
    if psql("SELECT count(*) FROM information_schema.columns WHERE table_schema='public' AND table_name IN ('articles','sources') AND column_name='collect_only'") != '0':
        raise ValueError('preexisting_collect_only_columns')
    database_size = int(psql("SELECT pg_catalog.pg_database_size(current_database())"))
    required = database_size * 4 + size * 4 + 1024 ** 3
    for path in (ROOT, Path('/var/lib'), Path('/var/backups')):
        existing = path if path.exists() else path.parent
        if shutil.disk_usage(str(existing)).free < required:
            raise ValueError('backup_restore_artifact_disk_reserve_insufficient')
    memory = re.search(r'^MemAvailable:\s+(\d+) kB$', Path('/proc/meminfo').read_text(), re.M)
    if not memory or int(memory.group(1)) < 700 * 1024:
        raise ValueError('maintenance_memory_reserve_insufficient')
    return {'old_release': OLD, 'release': NEW, 'archive_sha256': expected,
            'database_bytes': database_size, 'required_free_bytes': required,
            'migrations': names, 'native_ready_written': False, 'backup_parent_exists': backup_parent_exists,
            'release_lock_exists': lock_exists}


@contextlib.contextmanager
def release_lock(create=False):
    # Reuse the deploy account's inode, or create that very canonical lock with
    # its existing expected owner/mode. Never truncate, repair or replace one.
    info = lock_info()
    path = ROOT / 'state/release.lock'
    if info is None and not create:
        raise FileNotFoundError('canonical_release_lock_absent')
    if info is None:
        try:
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            info = lock_info()
            if info is None:
                raise ValueError('release_lock_creation_race')
            fd = os.open(str(path), os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        else:
            deploy = account('aifinance-deploy')
            os.fchown(fd, deploy.pw_uid, deploy.pw_gid)
            os.fchmod(fd, 0o644)
    else:
        fd = os.open(str(path), os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        actual = os.fstat(fd)
        expected = lock_info()
        if expected is None or (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
            raise ValueError('release_lock_replaced')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        expected = lock_info()
        if expected is None or (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
            raise ValueError('release_lock_replaced')
        yield
    finally:
        os.close(fd)


def write_new(path, data, mode=0o600):
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as f:
        f.write(data); f.flush(); os.fsync(f.fileno()); os.fchmod(f.fileno(), mode)


def protected_dir(path):
    if not path.exists():
        trusted(path.parent, directory=True); path.mkdir(mode=0o700)
    trusted(path, directory=True)
    if stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise ValueError('private_evidence_directory_required')


def stage(expected):
    if os.geteuid() != account('aifinance-deploy').pw_uid:
        raise ValueError('deploy_only_extraction')
    snapshot_archive = ARTIFACTS / (NEW + '.tar.gz')
    trusted(snapshot_archive)
    archive_check(expected, snapshot_archive)
    target = ROOT / 'releases' / NEW
    absent(target)
    temp = Path(tempfile.mkdtemp(prefix='.collect-stage-', dir=str(ROOT / 'releases')))
    try:
        command(['/usr/bin/python3', '-I', '-B', str(BIN / 'extract-release.py'), str(snapshot_archive), str(temp)], timeout=120)
        if small(temp / 'RELEASE_SHA', 64).decode().strip() != NEW:
            raise ValueError('release_metadata_mismatch')
        exact_schema(temp, NEW_SCHEMA)
        if not (temp / 'apps/web/build/server/index.js').is_file() or not (temp / 'node_modules').is_dir():
            raise ValueError('built_release_missing')
        os.rename(str(temp), str(target))
    finally:
        if temp.exists():
            shutil.rmtree(str(temp))


def snapshot_archive(expected):
    # A changing deploy-owned upload must never be reopened after digest check.
    # Snapshot once into administrator-only write storage, hash copied bytes,
    # then allow the unprivileged extractor to read this exact immutable file.
    if not ARTIFACTS.exists():
        trusted(ARTIFACTS.parent, directory=True); ARTIFACTS.mkdir(mode=0o755); ARTIFACTS.chmod(0o755)
    trusted(ARTIFACTS, directory=True)
    target = ARTIFACTS / (NEW + '.tar.gz')
    absent(target)
    source_fd = os.open(str(ROOT / 'incoming' / (NEW + '.tar.gz')), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(source_fd, 'rb') as source:
        st = os.fstat(source.fileno())
        if not stat.S_ISREG(st.st_mode) or not 0 < st.st_size <= MAX_ARCHIVE:
            raise ValueError('invalid_archive')
        fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(fd, 'wb') as out:
            h = hashlib.sha256(); total = 0
            for block in iter(lambda: source.read(1024 * 1024), b''):
                total += len(block)
                if total > MAX_ARCHIVE:
                    raise ValueError('archive_grew_during_copy')
                out.write(block); h.update(block)
            out.flush(); os.fsync(out.fileno())
            if h.hexdigest() != expected:
                raise ValueError('copied_archive_digest_mismatch')
            os.fchmod(out.fileno(), 0o444)
    return target


def seal_release(release):
    # Freeze each directory via its nofollow descriptor before inspecting its
    # children. Never path-based chmod/chown through deploy-writable symlinks.
    # The existing restricted deploy identity remains trusted for its parent
    # release-directory rename permission; gateway exposes no arbitrary rename.
    fd = os.open(str(release), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    def freeze(directory):
        os.fchown(directory, 0, 0); os.fchmod(directory, 0o555)
        for name in os.listdir(directory):
            st = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if stat.S_ISDIR(st.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                try:
                    freeze(child)
                finally:
                    os.close(child)
            elif stat.S_ISREG(st.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
                try:
                    actual = os.fstat(child)
                    if not stat.S_ISREG(actual.st_mode) or actual.st_nlink != 1:
                        raise ValueError('release_regular_file_or_hardlink')
                    os.fchown(child, 0, 0); os.fchmod(child, 0o555 if actual.st_mode & 0o111 else 0o444)
                finally:
                    os.close(child)
            elif stat.S_ISLNK(st.st_mode):
                os.chown(name, 0, 0, dir_fd=directory, follow_symlinks=False)
            else:
                raise ValueError('unexpected_release_file_type')
    try:
        freeze(fd)
    finally:
        os.close(fd)
    # The tree is now read-only and the reviewed extractor already rejected
    # escapes. Validate again after publication without following links to write.
    for base, dirs, files in os.walk(str(release), followlinks=False):
        for name in dirs + files:
            path = Path(base) / name
            if path.is_symlink():
                resolved = path.resolve(strict=True)
                if release not in resolved.parents and resolved != release:
                    raise ValueError('release_symlink_escape')


def resource_sample(unit, own_pid=None):
    pid = str(own_pid) if own_pid is not None else prop(unit, 'MainPID')
    if not re.fullmatch('[1-9][0-9]{0,9}', pid):
        raise ValueError('restore_pid_missing')
    values = dict(line.split(':', 1) for line in Path('/proc/' + pid + '/status').read_text().splitlines() if ':' in line)
    if values.get('Uid', '').split() != ['989'] * 4 or values.get('NoNewPrivs', '').strip() != '1' or int(values.get('CapEff', '1').strip(), 16) != 0:
        raise ValueError('restore_identity_or_privilege_mismatch')
    cgroups = {}
    for line in Path('/proc/' + pid + '/cgroup').read_text().splitlines():
        fields = line.split(':', 2)
        if len(fields) == 3:
            for control in fields[1].split(','):
                cgroups[control] = fields[2]
    expected = '/system.slice/' + unit
    if cgroups.get('memory') != expected or cgroups.get('pids') != expected:
        raise ValueError('restore_cgroup_v1_required')
    result = {'pid': int(pid), 'uid': 989}
    for control, limits in [('memory', {'memory.limit_in_bytes': 256 * 1024 ** 2, 'memory.failcnt': 0}), ('pids', {'pids.max': 32})]:
        base = Path('/sys/fs/cgroup') / control / expected.lstrip('/')
        if pid not in (base / 'cgroup.procs').read_text().split():
            raise ValueError('restore_kernel_membership_mismatch')
        for name, wanted in limits.items():
            got = int((base / name).read_text().strip())
            if got != wanted:
                raise ValueError('restore_kernel_limits_failed')
            result[name] = got
        current_name = 'memory.usage_in_bytes' if control == 'memory' else 'pids.current'
        current = int((base / current_name).read_text().strip())
        if current > (256 * 1024 ** 2 if control == 'memory' else 32):
            raise ValueError('restore_kernel_usage_exceeded')
        result[current_name] = current
    if own_pid is None and prop(unit, 'MainPID') != pid:
        raise ValueError('restore_pid_changed')
    base = Path('/sys/fs/cgroup/memory') / expected.lstrip('/')
    peak = int((base / 'memory.max_usage_in_bytes').read_text())
    if peak >= 256 * 1024 ** 2:
        raise ValueError('restore_peak_at_memory_limit')
    result['memory.max_usage_in_bytes'] = peak
    return result


def wait_restore(unit):
    end = time.monotonic() + 270
    evidence = None
    while time.monotonic() < end:
        state = prop(unit, 'ActiveState')
        if state == 'active' and prop(unit, 'SubState') == 'exited':
            if evidence is None or prop(unit, 'Result') != 'success' or prop(unit, 'ExecMainStatus') != '0':
                raise ValueError('restore_not_successfully_resource_verified')
            return evidence
        if state in ('active', 'activating'):
            try:
                evidence = resource_sample(unit)
            except (OSError, ValueError):
                if prop(unit, 'MainPID') != '0':
                    raise
            time.sleep(0.2)
            continue
        if state in ('inactive', 'failed'):
            if evidence is None or prop(unit, 'Result') != 'success' or prop(unit, 'ExecMainStatus') != '0':
                raise ValueError('restore_not_successfully_resource_verified')
            return evidence
        time.sleep(0.2)
    raise ValueError('restore_wait_timeout')


def migration_sql(release, old_names):
    raw = small(release / 'database/migrations' / MIGRATION, 16384)
    if digest(raw) != MIGRATION_DIGEST:
        raise ValueError('reviewed_0041_bytes_required')
    wanted = ','.join("'" + n + "'" for n in old_names)
    return ("BEGIN; SET LOCAL lock_timeout='5s'; SET LOCAL statement_timeout='60s';\n"
            "LOCK TABLE public.schema_migrations IN EXCLUSIVE MODE;\n"
            "DO $$ BEGIN IF (SELECT array_agg(name ORDER BY name) FROM public.schema_migrations) "
            "IS DISTINCT FROM ARRAY[" + wanted + "]::text[] THEN RAISE EXCEPTION 'ledger mismatch'; END IF; END $$;\n" +
            raw.decode() + "\nINSERT INTO public.schema_migrations(name) VALUES ('" + MIGRATION + "');\nCOMMIT;\n")


def restore_child(run):
    if not re.fullmatch('[0-9]{14}-[0-9a-f]{8}', run) or os.geteuid() != account('aifinance').pw_uid:
        raise ValueError('restore_child_identity_or_id')
    base = RESTORES / run
    if base.is_symlink() or base.stat().st_uid != os.geteuid() or stat.S_IMODE(base.stat().st_mode) != 0o700:
        raise ValueError('unsafe_restore_leaf')
    data, sock = base / 'data', base / 'socket'
    absent(data); absent(sock); sock.mkdir(mode=0o700)
    time.sleep(3)  # Parent must sample the actual constrained PID before work.
    args = [str(PG / 'initdb'), '-D', str(data), '-U', 'postgres', '--encoding=UTF8', '--locale=C', '--auth-local=trust', '--auth-host=reject', '--no-instructions']
    command(args, timeout=90)
    config = "listen_addresses=''\nport=55433\nunix_socket_directories='%s'\nunix_socket_permissions=0700\nshared_buffers='16MB'\nwork_mem='1MB'\nmaintenance_work_mem='16MB'\nmax_connections=6\nmax_worker_processes=0\nmax_parallel_workers=0\nautovacuum=off\njit=off\nfsync=on\nlog_statement='none'\nlog_min_error_statement=panic\n" % sock
    with (data / 'postgresql.conf').open('a') as f:
        f.write(config)
    started = False
    try:
        command([str(PG / 'pg_ctl'), '-D', str(data), '-l', str(base / 'server.log'), '-w', '-t', '30', 'start'], timeout=40)
        started = True
        command([str(PG / 'psql'), '-X', '-w', '-q', '-h', str(sock), '-p', '55433', '-U', 'postgres', '-d', 'postgres', '-v', 'ON_ERROR_STOP=1'], data=("CREATE ROLE aifinance_preview LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 6; CREATE DATABASE aifinance_preview OWNER aifinance_preview; REVOKE ALL ON DATABASE aifinance_preview FROM PUBLIC;").encode())
        # The only superuser restore is inside a new network/filesystem-confined
        # temporary cluster. It has no production credentials or socket access.
        command([str(PG / 'pg_restore'), '--exit-on-error', '-h', str(sock), '-p', '55433', '-U', 'postgres', '-d', DB, str(base / 'database.dump')], timeout=100)
        result = snapshot(restore=base)
    finally:
        if started:
            command([str(PG / 'pg_ctl'), '-D', str(data), '-w', '-t', '20', '-m', 'fast', 'stop'], timeout=25)
    # systemd239 prunes the cgroup at SERVICE_EXITED even with RemainAfterExit.
    # Capture terminal counters inside the still-live process after PG stopped.
    kernel = resource_sample('aifinance-collect-restore-' + run + '.service', own_pid=os.getpid())
    write_new(base / 'restore.json', json.dumps({'snapshot': result, 'resources': kernel}, sort_keys=True).encode())


def restore_backup(backup, run, before):
    if not RESTORES.exists():
        trusted(RESTORES.parent, directory=True); RESTORES.mkdir(mode=0o755); RESTORES.chmod(0o755)
    trusted(RESTORES, directory=True)
    leaf = RESTORES / run
    absent(leaf)
    leaf.mkdir(mode=0o700)
    a = account('aifinance')
    # The root-created leaf is the only path later cleaned up by this operation.
    with (leaf / 'database.dump').open('xb') as f, backup.open('rb') as source:
        shutil.copyfileobj(source, f); os.fchmod(f.fileno(), 0o600); os.fchown(f.fileno(), a.pw_uid, a.pw_gid)
    os.chown(str(leaf), a.pw_uid, a.pw_gid)
    unit = 'aifinance-collect-restore-' + run
    if prop(unit + '.service', 'LoadState') != 'not-found':
        raise ValueError('restore_unit_exists')
    props = ['User=aifinance', 'Group=aifinance', 'SupplementaryGroups=', 'PrivateNetwork=yes',
             'PrivateTmp=yes', 'NoNewPrivileges=yes', 'CapabilityBoundingSet=', 'AmbientCapabilities=',
             'ProtectSystem=strict', 'ProtectHome=yes', 'ReadWritePaths=' + str(leaf),
             'InaccessiblePaths=/etc/aifinance-preview.env /opt/aifinance/shared/data /run/aifinance-preview-db /var/lib/pgsql',
             'Type=oneshot', 'RemainAfterExit=yes', 'MemoryAccounting=yes', 'MemoryLimit=256M', 'TasksMax=32', 'TimeoutStartSec=240',
             'TimeoutStopSec=30', 'KillMode=control-group', 'LimitCORE=0', 'UMask=0077',
             'StandardOutput=null', 'StandardError=null', 'RestrictAddressFamilies=AF_UNIX']
    args = ['/usr/bin/systemd-run', '--quiet', '--no-block', '--unit=' + unit]
    args += ['--property=' + p for p in props]
    args += ['/usr/bin/python3', '-I', '-B', str(BIN / 'collect-only-upgrade.py'), 'restore-child', '--run-id', run]
    try:
        command(args, timeout=20)
        kernel = wait_restore(unit + '.service')
        receipt = json.loads(small(leaf / 'restore.json', 1024 * 1024).decode())
        result = receipt['snapshot']
        final_kernel = receipt['resources']
        if (final_kernel.get('uid') != 989 or final_kernel.get('memory.limit_in_bytes') != 256 * 1024 ** 2 or
                final_kernel.get('memory.failcnt') != 0 or final_kernel.get('pids.max') != 32 or
                not 0 <= final_kernel.get('memory.max_usage_in_bytes', -1) < 256 * 1024 ** 2):
            raise ValueError('final_restore_kernel_evidence_failed')
        compatible(before, result)
        # Read and validate the receipt before deleting only this invocation's leaf.
        if not shutil.rmtree.avoids_symlink_attacks:
            raise ValueError('safe_cleanup_unavailable')
        shutil.rmtree(str(leaf))
        return {'verified': True, 'target': 'isolated_unix_only_pg17', 'snapshot': result, 'unit': unit, 'resources': {'parent_sample': kernel, 'terminal_child': final_kernel}}
    finally:
        if prop(unit + '.service', 'LoadState') != 'not-found':
            command([CTL, 'stop', unit + '.service'], timeout=40)
        # Failed leaves remain for operator review; successful owned leaves are
        # cleaned only after verified evidence has been read into root memory.


def apply(expected):
    preflight(expected)  # No lock/directory creation before read-only checks pass.
    with release_lock(create=True):
        report = preflight(expected)
        snapshot_archive(expected)
        command(['/usr/sbin/runuser', '-u', 'aifinance-deploy', '--', '/usr/bin/python3', '-I', '-B', str(BIN / 'collect-only-upgrade.py'), 'stage', '--archive-sha256', expected], timeout=150)
        release = ROOT / 'releases' / NEW
        seal_release(release)
        manifest, names = exact_schema(release, NEW_SCHEMA)
        if names != sorted(report['migrations'] + [MIGRATION]):
            raise ValueError('only_0041_allowed')
        old_listener = helper('first-preview.py').listeners()['8000']
        backup_parent(create=True)
        protected_dir(STATE); protected_dir(BACKUPS)
        run = time.strftime('%Y%m%d%H%M%S', time.gmtime()) + '-' + os.urandom(4).hex()
        evidence = BACKUPS / run
        evidence.mkdir(mode=0o700)
        report.update(run_id=run, evidence=str(evidence), status='maintenance')
        write_new(evidence / 'before-schema.sha256', small(ROOT / 'shared/schema.sha256'))
        write_new(evidence / 'plan.json', json.dumps(report, sort_keys=True).encode())
        # Only the reviewed API/Web units are stopped; DB/egress/8000 remain.
        command([CTL, 'stop'] + APP_UNITS, timeout=45)
        try:
            quiet_database()
            before = snapshot()
            write_new(evidence / 'before.json', json.dumps(before, sort_keys=True).encode())
            backup = evidence / 'database.dump'
            with backup.open('xb') as f:
                os.fchmod(f.fileno(), 0o600)
                command([str(PG / 'pg_dump'), '-Fc', '--no-password', '-h', '127.0.0.1', '-p', '55432', '-U', DB, '-d', DB], env=db_env(), user='aifinance', timeout=120, out_file=f)
                f.flush(); os.fsync(f.fileno())
            backup_sha, backup_size = file_digest(backup)
            write_new(evidence / 'backup.json', json.dumps({'sha256': backup_sha, 'bytes': backup_size, 'path': str(backup), 'created_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}, sort_keys=True).encode())
            restored = restore_backup(backup, run, before)
            write_new(evidence / 'restore.json', json.dumps(restored, sort_keys=True).encode())
            quiet_database()
            compatible(before, snapshot())
            psql(migration_sql(release, report['migrations']), timeout=75)
            # Expected only additive flags plus one ledger row. Old contents must
            # match after removing the newly added false fields.
            after = snapshot(legacy=True)
            if after['migrations'] != names:
                raise ValueError('post_migration_ledger_mismatch')
            for name, old in before['tables'].items():
                expected_count = old['count'] + (1 if name == 'public.schema_migrations' else 0)
                if after['tables'].get(name, {}).get('count') != expected_count:
                    raise ValueError('post_migration_row_count_mismatch')
                if after['tables'].get(name, {}).get('sha256') != old['sha256']:
                    raise ValueError('preexisting_row_content_changed')
            check = psql("SELECT count(*) FROM information_schema.columns WHERE table_schema='public' AND table_name IN ('articles','sources') AND column_name='collect_only' AND data_type='boolean' AND is_nullable='NO' AND column_default='false'; SELECT count(*) FROM pg_catalog.pg_constraint WHERE conname='collect_only_source_isolation' AND conrelid='public.sources'::regclass AND convalidated; SELECT count(*) FROM articles WHERE collect_only; SELECT count(*) FROM sources WHERE collect_only")
            if check != '2\n1\n0\n0':
                raise ValueError('post_migration_quarantine_invariants')
            write_new(evidence / 'after.json', json.dumps(after, sort_keys=True).encode())
            current_old()
            if release.is_symlink() or release.stat().st_uid != 0 or stat.S_IMODE(release.stat().st_mode) != 0o555:
                raise ValueError('sealed_release_changed')
            exact_schema(release, NEW_SCHEMA)
            if small(release / 'RELEASE_SHA', 64).decode().strip() != NEW:
                raise ValueError('sealed_release_identity_changed')
            tmp = ROOT / 'state/.current-next'
            os.symlink(str(release), str(tmp)); os.replace(str(tmp), str(ROOT / 'state/current'))
            # Never modify OLD/schema.sha256 or write native-ready.
            replacement = ROOT / 'shared/.collect-schema-next'
            write_new(replacement, manifest.encode(), 0o644)
            os.replace(str(replacement), str(ROOT / 'shared/schema.sha256'))
            command([CTL, 'start'] + APP_UNITS, timeout=45)
            fp = helper('first-preview.py'); fp.health(NEW)
            command(['/usr/bin/python3', '-I', '-B', str(BIN / 'egress-guard.py'), 'verify'])
            if fp.listeners()['8000'] != old_listener:
                raise ValueError('old_8000_listener_changed')
            report.update(status='healthy', backup=str(backup), backup_sha256=backup_sha,
                          backup_bytes=backup_size, restore_verified=True, resources=fp.resource_evidence(),
                          collector_started=False, timer_enabled=False)
            write_new(STATE / 'collect-only-upgrade.json', json.dumps(report, sort_keys=True).encode())
            print(json.dumps(report, sort_keys=True))
        except BaseException:
            # Keep the additive schema and exact switch state for inspection.
            # A blind old-code rollback would discard collect-only safeguards.
            try:
                command([CTL, 'stop'] + APP_UNITS, timeout=45)
            finally:
                print('STOP: preview API/Web remain stopped; preserve backup and evidence; no automatic rollback', file=sys.stderr)
            raise


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('operation', choices=['check', 'apply', 'stage', 'restore-child'], nargs='?', default='check')
    p.add_argument('--archive-sha256')
    p.add_argument('--run-id')
    a = p.parse_args(argv)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0)); os.umask(0o077)
    if a.operation == 'stage':
        stage(a.archive_sha256)
    elif a.operation == 'restore-child':
        restore_child(a.run_id)
    elif a.operation == 'apply':
        apply(a.archive_sha256)
    else:
        result = preflight(a.archive_sha256); result.update(status='check_only', changed=False, readyForApply=False)
        print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    def interrupted(signum, frame):
        raise InterruptedError('interrupted')
    for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(sig, interrupted)
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        reason = str(error) if isinstance(error, ValueError) and re.fullmatch('[a-z][a-z0-9_]{0,100}', str(error)) else 'system_or_metadata_check_failed'
        print('STOP: ' + reason + '; preserve state and evidence; no automatic retry or rollback', file=sys.stderr)
        sys.exit(1)
