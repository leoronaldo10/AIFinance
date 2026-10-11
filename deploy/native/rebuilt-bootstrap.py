#!/usr/bin/python3
"""Root-run, same-version bootstrap only. Never invoked by the deployment gateway.

check/status are read-only. apply/rollback require separate server approval.
No shell, env-file contents, database operations, SSH or firewall changes.
"""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import signal
import stat
import sys
import tempfile

HERE = Path(__file__).resolve().parent
# Reuse bounded, quiet subprocess I/O and trusted-file checks. Installation must
# make this script and the adjacent gateway/manifest root-owned before invocation.
spec = importlib.util.spec_from_file_location('rebuilt_gateway', HERE / 'rebuilt-gateway.py')
g = importlib.util.module_from_spec(spec)
if __name__ == '__main__':
    dependency = HERE / 'rebuilt-gateway.py'
    for path in (dependency, *dependency.parents):
        info = path.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or not (
                stat.S_ISREG(info.st_mode) if path == dependency else stat.S_ISDIR(info.st_mode)):
            sys.exit('Untrusted bootstrap dependency; administrator installation required.')
spec.loader.exec_module(g)
ROOT = Path('/opt/aifinance')
OLD = ROOT / 'staging' / g.BASELINE
SWITCH = ROOT / 'switch'
CURRENT = SWITCH / 'current'
SYSTEM = Path('/etc/systemd/system')
STATE = Path('/var/lib/aifinance-bootstrap')
TX = STATE / 'rebuilt-v1'
LOCK = Path('/run/lock/aifinance-rebuilt-bootstrap.lock')
MANIFEST = HERE / 'rebuilt-baseline.sha256'
MANIFEST_DIGEST = '650d0f5269724371b564f49f2bbb313c65ef82df1ffdbde9985c177121373d5c'
NODE = Path('/usr/local/bin/node')
DROP = '90-rebuilt-bootstrap.conf'
ENTRIES = {'api': 'apps/api/src/main.ts', 'web': 'apps/web/server.ts'}
run = g.run
require = g.require
Refused = g.Refused


def drop(alias):
    return SYSTEM / (g.UNITS[alias] + '.d') / DROP


def content():
    return ('# Same-version bootstrap; inherited ExecStart and EnvironmentFile unchanged.\n'
            '[Service]\nWorkingDirectory=' + str(CURRENT) + '\n').encode()


def read(path, limit=16*1024*1024):
    # No symlinks/hardlinks and bounded regular files. Never called on .env.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit,
                'invalid_file')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(limit + 1)
        require(len(data) <= limit, 'file_too_large')
        return data
    finally:
        os.close(fd)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def absent(path):
    return not os.path.lexists(path)


def real(path):
    require(path.resolve(strict=True) == path, 'symlink_in_path')


def directory(path, mode=0o700):
    if absent(path):
        path.mkdir(mode=mode)
        if os.geteuid() == 0:
            os.chown(path, 0, 0)
        path.chmod(mode)
        g.sync_dir(path.parent)
    g.trusted(path, directory=True)
    require(path.stat().st_mode & 0o777 == mode, 'directory_mode')


def save(value):
    g.atomic(TX / 'state.json', value)


def write(path, data, mode=0o600):
    fd, temporary = tempfile.mkstemp(prefix='.bootstrap-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            if os.geteuid() == 0:
                os.fchown(stream.fileno(), 0, 0)
            os.fchmod(stream.fileno(), mode)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        g.sync_dir(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load():
    g.trusted(STATE, directory=True)
    g.trusted(TX, directory=True)
    g.trusted(TX / 'state.json')
    value = json.loads(read(TX / 'state.json', 65536))
    require(value.get('version') == 1 and value.get('baseline') == g.BASELINE,
            'invalid_receipt')
    return value


def policy_disabled():
    if not absent(g.POLICY):
        g.trusted(g.POLICY)
        require(json.loads(read(g.POLICY, 65536)).get('accepted') is False,
                'disable_deployment_policy_first')


def source_check():
    real(OLD)
    require(OLD.is_dir() and OLD.stat().st_uid == pwd.getpwnam('aifinance-deploy').pw_uid,
            'baseline_owner')
    require(read(OLD / 'RELEASE_SHA', 64).decode().strip() == g.BASELINE, 'baseline_identity')
    g.trusted(MANIFEST)
    raw = read(MANIFEST)
    require(digest(raw) == MANIFEST_DIGEST, 'source_manifest_changed')
    lines = raw.decode().splitlines()
    require(bool(lines), 'empty_source_manifest')
    seen = set()
    for line in lines:
        match = re.fullmatch(r'([0-9a-f]{64})  ([a-zA-Z0-9_./@+\[\]$()-]+)', line)
        require(match is not None, 'invalid_source_manifest')
        expected, name = match.groups()
        rel = Path(name)
        require(not rel.is_absolute() and '..' not in rel.parts and name not in seen,
                'invalid_source_path')
        seen.add(name)
        path = OLD / rel
        real(path)
        require(digest(read(path)) == expected, 'baseline_source_mismatch')
    migrations = OLD / 'database/migrations'
    real(migrations)
    require({str(p.relative_to(OLD)) for p in migrations.glob('*.sql')} ==
            {name for name in seen if name.startswith('database/migrations/') and name.endswith('.sql')},
            'baseline_migration_set_changed')
    actual = ''.join(digest(read(p)) + '  database/migrations/' + p.name + '\n'
                     for p in sorted(migrations.glob('*.sql'))).encode()
    require(actual and read(OLD / 'schema.sha256') == actual, 'baseline_schema_manifest')
    require((OLD / 'apps/web/build/server/index.js').is_file() and
            (OLD / 'node_modules').is_dir(), 'baseline_build_missing')
    for name in ('apps/web/build/server/index.js', 'node_modules'):
        require((OLD / name).resolve().is_relative_to(OLD), 'baseline_build_escape')
    # Metadata only: never read or copy the environment file.
    env = OLD / '.env'
    real(env)
    info = env.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
            info.st_uid in (0, OLD.stat().st_uid) and not info.st_mode & 0o007 and
            not info.st_mode & 0o022, 'environment_file_permissions')
    return digest(actual)


def properties(alias, switched=False):
    values = g.properties(g.UNITS[alias])
    require(values['User'] == 'aifinance-deploy', 'unit_user')
    require(values['WorkingDirectory'] == str(CURRENT if switched else OLD), 'unit_cwd')
    require(values['FragmentPath'] == str(SYSTEM / g.UNITS[alias]), 'unit_fragment')
    require(values['DropInPaths'] == (str(drop(alias)) if switched else ''), 'unit_dropins')
    require(values['EnvironmentFiles'] == str(OLD / '.env') + ' (ignore_errors=no)', 'unit_env_path')
    expected = str(NODE) + ' --experimental-strip-types ' + ENTRIES[alias]
    # systemctl's ExecStart also contains runtime timestamps; inspect only the
    # executable/argv fields and refuse multiple commands or extra arguments.
    pattern = r'\{ path=' + re.escape(str(NODE)) + r' ; argv\[\]=' + re.escape(expected) + r' ; ignore_errors=no ; [^{}]*\}'
    require(re.fullmatch(pattern, values['ExecStart']) is not None, 'unit_exec')
    g.trusted(Path(values['FragmentPath']))
    if switched:
        g.trusted(drop(alias))
    return digest(read(SYSTEM / g.UNITS[alias], 65536))


def idle():
    for unit in g.UNITS.values():
        require(run(['/usr/bin/systemctl', 'show', unit, '--property=Job', '--value']).strip()
                in ('', '0'), 'unit_job_pending')


def health():
    g.listeners()
    run(['/usr/bin/systemctl', 'is-active', '--quiet', *g.UNITS.values()])
    data = json.loads(run(['/usr/bin/curl', '--noproxy', '*', '--max-time', '3', '-fsS',
                          'http://127.0.0.1:3001/api/health'], limit=4096, timeout=5))
    require(isinstance(data, dict) and data.get('ok') is True and data.get('db') == 'ok'
            and data.get('release') in ('dev', g.BASELINE), 'baseline_health')
    run(['/usr/bin/curl', '--noproxy', '*', '--max-time', '3', '-fsS', '-o', '/dev/null',
         'http://127.0.0.1:3000/'], timeout=5)
    return data['release']


def wait_health(expected):
    import time
    for _ in range(20):
        try:
            require(health() == expected, 'release_response_changed')
            return
        except (Refused, ValueError):
            time.sleep(2)
    raise Refused('health_timeout')


def preflight():
    policy_disabled()
    g.trusted(ROOT, directory=True)
    g.trusted(SYSTEM, directory=True)
    g.trusted(NODE)
    require(run([str(NODE), '--version']).strip() == 'v24.21.0', 'node_changed')
    require(absent(SWITCH), 'switch_already_exists')
    for alias in ENTRIES:
        require(absent(drop(alias).parent), 'dropin_directory_exists')
    units = {alias: properties(alias) for alias in ENTRIES}
    schema = source_check()
    idle()
    return {'version': 1, 'baseline': g.BASELINE, 'phase': 'prepared',
            'units': units, 'schema': schema, 'health_release': health()}


def restore(record):
    policy_disabled()
    idle()  # Never race a restart left pending by a killed process.
    if not absent(SWITCH):
        g.trusted(SWITCH, directory=True)
    for alias in ENTRIES:
        require(digest(read(SYSTEM / g.UNITS[alias], 65536)) == record['units'][alias],
                'original_unit_changed')
        if not absent(drop(alias)):
            g.trusted(drop(alias))
            require(read(drop(alias)) == content(), 'dropin_changed')
        if not absent(drop(alias).parent):
            g.trusted(drop(alias).parent, directory=True)
            require(set(drop(alias).parent.iterdir()) <= {drop(alias)}, 'other_dropin_files')
    if not absent(CURRENT):
        require(CURRENT.is_symlink() and os.readlink(CURRENT) == str(OLD), 'current_changed')
    record['phase'] = 'restoring'
    save(record)
    for alias in ENTRIES:
        if not absent(drop(alias)):
            drop(alias).unlink()
            g.sync_dir(drop(alias).parent)
        if not absent(drop(alias).parent):
            # Refuse to delete other administrators' files.
            drop(alias).parent.rmdir()
            g.sync_dir(SYSTEM)
    run(['/usr/bin/systemctl', 'daemon-reload'])
    for alias in ENTRIES:
        require(properties(alias) == record['units'][alias], 'restored_unit_changed')
    run(['/usr/bin/systemctl', 'restart', *g.UNITS.values()], timeout=60)
    wait_health(record['health_release'])
    if not absent(CURRENT):
        CURRENT.unlink()
        g.sync_dir(SWITCH)
    if not absent(SWITCH):
        SWITCH.rmdir()
        g.sync_dir(ROOT)
    record['phase'] = 'rolled_back'
    save(record)


def apply():
    require(absent(TX), 'receipt_exists_use_status_or_rollback')
    record = preflight()
    directory(STATE)
    directory(TX)
    # Original units may contain inline secrets; local root-only evidence only.
    for alias in ENTRIES:
        write(TX / (alias + '.unit.backup'), read(SYSTEM / g.UNITS[alias], 65536))
    save(record)  # Durable intent before modifying the layout or units.
    try:
        directory(SWITCH, 0o755)
        CURRENT.symlink_to(OLD)
        if os.geteuid() == 0:
            os.chown(CURRENT, 0, 0, follow_symlinks=False)
        g.sync_dir(SWITCH)
        for alias in ENTRIES:
            directory(drop(alias).parent, 0o755)
            # Root-only ancestors and absent target were checked; no old drop-in is overwritten.
            require(absent(drop(alias)), 'dropin_exists')
            write(drop(alias), content(), 0o644)
        idle()
        run(['/usr/bin/systemctl', 'daemon-reload'])
        for alias in ENTRIES:
            require(properties(alias, True) == record['units'][alias], 'original_unit_changed')
        require(source_check() == record['schema'], 'baseline_changed')
        record['phase'] = 'restarting'
        save(record)
        run(['/usr/bin/systemctl', 'restart', *g.UNITS.values()], timeout=60)
        wait_health(record['health_release'])
        for alias in ENTRIES:
            require(properties(alias, True) == record['units'][alias], 'post_restart_unit_changed')
        record['phase'] = 'same_version_ready'
        save(record)
        return record
    except BaseException:
        try:
            restore(record)
        except BaseException:
            record['phase'] = 'recovery_required'
            save(record)
        raise Refused('bootstrap_failed_' + record['phase'])


def lock():
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == 0
                and info.st_mode & 0o777 == 0o600, 'untrusted_lock')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Refused('bootstrap_busy')
        return fd
    except BaseException:
        os.close(fd)
        raise


def main():
    require(len(sys.argv) == 2 and sys.argv[1] in ('check', 'apply', 'rollback', 'status'), 'usage')
    require(os.getuid() == 0 and os.geteuid() == 0, 'administrator_required')
    os.environ.clear()
    os.environ.update(g.ENV)
    os.umask(0o077)
    for path in (Path(__file__).resolve(), HERE / 'rebuilt-gateway.py', MANIFEST):
        g.trusted(path)
    action = sys.argv[1]
    if action == 'check':
        record = preflight()
    elif action == 'status':
        record = load()
    else:
        fd = lock()
        try:
            if action == 'apply':
                record = apply()
            else:
                record = load()
                if record['phase'] != 'rolled_back':
                    restore(record)
        finally:
            os.close(fd)
    # Only non-sensitive fields. dev is deliberately preserved in phase one.
    print(json.dumps({k: record[k] for k in ('baseline', 'phase', 'health_release')}))


def interrupted(signum, frame):
    raise Refused('interrupted')


if __name__ == '__main__':
    for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(sig, interrupted)
    try:
        main()
    except (Refused, OSError, ValueError, KeyError) as error:
        code = str(error) if isinstance(error, Refused) and re.fullmatch(r'[a-z0-9_]+', str(error)) else 'invalid_state_or_file'
        print('Bootstrap refused: ' + code + '; use root-only receipt and approved rollback.', file=sys.stderr)
        sys.exit(1)
