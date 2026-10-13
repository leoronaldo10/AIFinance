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
        try:
            info = path.lstat()
        except OSError as error:
            print(json.dumps({'error': 'bootstrap_dependency_unavailable', 'path': str(path),
                              'errno': error.errno}), file=sys.stderr)
            sys.exit(1)
        if info.st_uid != 0 or info.st_mode & 0o022 or not (
                stat.S_ISREG(info.st_mode) if path == dependency else stat.S_ISDIR(info.st_mode)):
            print(json.dumps({'error': 'bootstrap_dependency_untrusted', 'path': str(path),
                              'uid': info.st_uid, 'mode': oct(stat.S_IMODE(info.st_mode))}), file=sys.stderr)
            sys.exit(1)
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


class Diagnostic(Refused):
    def __init__(self, code, path=None, **metadata):
        super().__init__(code)
        self.details = {'error': code, **metadata}
        if path is not None:
            self.details['path'] = str(path)


def trusted(path, directory=False):
    # Preserve the gateway's trust rules; only improve the rejected-path report.
    try:
        g.trusted(path, directory=directory)
    except (Refused, OSError) as error:
        for candidate in (path, *path.parents):
            try:
                info = candidate.lstat()
            except OSError as missing:
                raise Diagnostic('trusted_path_unavailable', candidate, errno=missing.errno) from None
            is_dir = directory if candidate == path else True
            kind_ok = stat.S_ISDIR(info.st_mode) if is_dir else stat.S_ISREG(info.st_mode)
            if info.st_uid != 0 or info.st_mode & 0o022 or not kind_ok:
                raise Diagnostic('untrusted_path', candidate, uid=info.st_uid, gid=info.st_gid,
                                 mode=oct(stat.S_IMODE(info.st_mode)),
                                 expected='directory' if is_dir else 'regular_file') from None
        raise error


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
    trusted(path, directory=True)
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
    if absent(TX):
        raise Diagnostic('receipt_not_initialized', TX / 'state.json')
    trusted(STATE, directory=True)
    trusted(TX, directory=True)
    require(STATE.stat().st_mode & 0o777 == 0o700 and TX.stat().st_mode & 0o777 == 0o700,
            'state_directory_mode')
    if absent(TX / 'state.json'):
        raise Diagnostic('receipt_missing_in_existing_transaction', TX / 'state.json')
    trusted(TX / 'state.json')
    require((TX / 'state.json').stat().st_mode & 0o777 == 0o600, 'receipt_mode')
    try:
        value = json.loads(read(TX / 'state.json', 65536))
    except ValueError:
        raise Diagnostic('receipt_invalid_json', TX / 'state.json') from None
    require(isinstance(value, dict) and set(value) ==
            {'version', 'baseline', 'phase', 'units', 'schema', 'health_release'}, 'invalid_receipt_shape')
    require(value['version'] == 1 and value['baseline'] == g.BASELINE and
            value['phase'] in ('prepared', 'restarting', 'same_version_ready', 'restoring',
                               'rolled_back', 'recovery_required') and
            isinstance(value['units'], dict) and set(value['units']) == set(ENTRIES) and
            all(isinstance(v, str) and re.fullmatch(r'[0-9a-f]{64}', v) for v in value['units'].values()) and
            isinstance(value['schema'], str) and re.fullmatch(r'[0-9a-f]{64}', value['schema']) and
            value['health_release'] in ('dev', g.BASELINE),
            'invalid_receipt')
    return value


def state_parent():
    if not absent(STATE):
        trusted(STATE, directory=True)
        require(STATE.stat().st_mode & 0o777 == 0o700, 'state_directory_mode')


def status():
    state_parent()
    if not absent(TX):
        return load()
    require(absent(SWITCH) and all(absent(drop(a).parent) for a in ENTRIES),
            'layout_exists_without_receipt')
    require(absent(STATE) or not any(STATE.iterdir()), 'unknown_state_entries')
    # Observation only, not a fabricated or persisted deployment receipt.
    return {'phase': 'not_initialized', 'receipt_exists': False}


def policy_disabled():
    if not absent(g.POLICY):
        trusted(g.POLICY)
        try:
            value = json.loads(read(g.POLICY, 65536))
        except ValueError:
            raise Diagnostic('policy_invalid_json', g.POLICY) from None
        require(isinstance(value, dict), 'policy_invalid_shape')
        require(value.get('accepted') is False,
                'disable_deployment_policy_first')


def source_check():
    real(OLD)
    require(OLD.is_dir() and OLD.stat().st_uid == pwd.getpwnam('aifinance-deploy').pw_uid,
            'baseline_owner')
    require(read(OLD / 'RELEASE_SHA', 64).decode().strip() == g.BASELINE, 'baseline_identity')
    trusted(MANIFEST)
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


def home_compat(alias):
    path = drop(alias).parent / '90-home-compat.conf'
    if absent(path):
        return None
    trusted(path)
    require(read(path, 4096) == b'[Service]\nEnvironment="HOME=/opt/aifinance"\n',
            'home_compat_changed')
    return path


def properties(alias, switched=False):
    values = g.properties(g.UNITS[alias])
    require(values['User'] == 'aifinance-deploy', 'unit_user')
    require(values['WorkingDirectory'] == str(CURRENT if switched else OLD), 'unit_cwd')
    require(values['FragmentPath'] == str(SYSTEM / g.UNITS[alias]), 'unit_fragment')
    compat = home_compat(alias)
    expected_drops = ([drop(alias)] if switched else []) + ([compat] if compat else [])
    require(values['DropInPaths'].split() == [str(p) for p in sorted(expected_drops)], 'unit_dropins')
    require(values['EnvironmentFiles'] == str(OLD / '.env') + ' (ignore_errors=no)', 'unit_env_path')
    expected = str(NODE) + ' --experimental-strip-types ' + ENTRIES[alias]
    # systemctl's ExecStart also contains runtime timestamps; inspect only the
    # executable/argv fields and refuse multiple commands or extra arguments.
    pattern = r'\{ path=' + re.escape(str(NODE)) + r' ; argv\[\]=' + re.escape(expected) + r' ; ignore_errors=no ; [^{}]*\}'
    require(re.fullmatch(pattern, values['ExecStart']) is not None, 'unit_exec')
    trusted(Path(values['FragmentPath']))
    if switched:
        trusted(drop(alias))
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
    state_parent()
    trusted(ROOT, directory=True)
    trusted(SYSTEM, directory=True)
    trusted(NODE)
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
        trusted(SWITCH, directory=True)
    for alias in ENTRIES:
        require(digest(read(SYSTEM / g.UNITS[alias], 65536)) == record['units'][alias],
                'original_unit_changed')
        if not absent(drop(alias)):
            trusted(drop(alias))
            require(read(drop(alias)) == content(), 'dropin_changed')
        if not absent(drop(alias).parent):
            trusted(drop(alias).parent, directory=True)
            compat = home_compat(alias)
            require(set(drop(alias).parent.iterdir()) <= {drop(alias), compat}, 'other_dropin_files')
    if not absent(CURRENT):
        require(CURRENT.is_symlink() and os.readlink(CURRENT) == str(OLD), 'current_changed')
    record['phase'] = 'restoring'
    save(record)
    for alias in ENTRIES:
        if not absent(drop(alias)):
            drop(alias).unlink()
            g.sync_dir(drop(alias).parent)
        if not absent(drop(alias).parent) and home_compat(alias) is None:
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
    if not absent(TX):
        load()  # Distinguish a valid previous receipt from damaged partial state.
        raise Refused('receipt_exists_use_status_or_rollback')
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
        trusted(path)
    action = sys.argv[1]
    if action == 'check':
        record = preflight()
    elif action == 'status':
        record = status()
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
    print(json.dumps({k: record[k] for k in ('baseline', 'phase', 'health_release', 'receipt_exists')
                      if k in record}))


def interrupted(signum, frame):
    raise Refused('interrupted')


if __name__ == '__main__':
    for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(sig, interrupted)
    try:
        main()
    except (Refused, OSError, ValueError, KeyError) as error:
        if isinstance(error, Diagnostic):
            details = error.details
        elif isinstance(error, OSError):
            details = {'error': 'filesystem_error', 'errno': error.errno}
            if error.filename:
                details['path'] = str(error.filename)
        else:
            code = str(error) if isinstance(error, Refused) and re.fullmatch(r'[a-z0-9_]+', str(error)) else 'invalid_metadata'
            details = {'error': code}
        print(json.dumps(details), file=sys.stderr)
        sys.exit(1)
