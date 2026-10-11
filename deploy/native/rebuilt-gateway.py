#!/usr/bin/python3
"""Reviewed forced entry for the rebuilt Ubuntu host; install outside releases.

No provisioning, database connection, credential read, shell evaluation or arbitrary
service arguments. All deployment paths require a root-owned acceptance policy.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path('/opt/aifinance')
POLICY = Path('/etc/aifinance-rebuilt.json')
BASELINE = 'd57ba047369e666025347719caee1a4c642abe62'
UNITS = {'api': 'aifinance-api.service', 'web': 'aifinance-web.service'}
PROPERTIES = ('User', 'WorkingDirectory', 'ExecStart', 'FragmentPath', 'DropInPaths', 'EnvironmentFiles')
TERMINAL = ('succeeded', 'rolled_back', 'recovery_required')
PHASES = ('prepared', 'switching', 'checking', 'rolling_back') + TERMINAL
SHA = r'[0-9a-f]{40}'
DIGEST = r'[0-9a-f]{64}'
ID = r'[0-9a-f]{32}'
LIMIT = 128 * 1024 * 1024
ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': '/var/lib/aifinance-deploy'}


class Refused(Exception):
    pass


class Interrupted(BaseException):
    pass


def require(condition, reason):
    if not condition:
        raise Refused(reason)


def parse(command):
    patterns = (r'rebuilt-v1 (verify|inspect|status)',
                r'rebuilt-v1 (status|resume) ' + ID,
                r'rebuilt-v1 logs (api|web)',
                r'rebuilt-v1 upload ' + SHA + ' ' + DIGEST,
                r'rebuilt-v1 deploy ' + SHA + ' ' + DIGEST + ' ' + ID,
                r'rebuilt-v1 rollback ' + SHA + ' ' + ID)
    require(any(re.fullmatch(p, command) for p in patterns), 'command_denied')
    return command.split(' ')[1:]


def read(path, limit=32768):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= limit, 'invalid_metadata_file')
        data = source.read(limit + 1)
        require(len(data) <= limit, 'metadata_limit')
        return data


def document(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate_metadata_key')
            result[key] = value
        return result
    return json.loads(read(path), object_pairs_hook=unique)


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic(path, value):
    fd, name = tempfile.mkstemp(prefix='.receipt-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as output:
            json.dump(value, output, sort_keys=True)
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
        sync_dir(path.parent)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def trusted(path, directory=False):
    require(path.is_absolute() and '..' not in path.parts, 'trusted_path_not_absolute')
    info = path.lstat()
    require(info.st_uid == 0 and not info.st_mode & 0o022 and
            (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)), 'untrusted_policy_or_helper')
    for parent in path.parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'untrusted_parent')


def run(argv, limit=32768, timeout=15):
    # Output is bounded while reading, including failing commands. Never echo stderr.
    with open(os.devnull, 'wb') as error:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=error, env=ENV)
        import selectors
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        output = bytearray()
        end = time.monotonic() + timeout
        try:
            while True:
                remaining = end - time.monotonic()
                require(remaining > 0, 'command_timeout')
                require(selector.select(remaining), 'command_timeout')
                chunk = os.read(process.stdout.fileno(), min(4096, limit + 1 - len(output)))
                if not chunk:
                    break
                output.extend(chunk)
                require(len(output) <= limit, 'command_output_limit')
            try:
                code = process.wait(timeout=max(.01, end-time.monotonic()))
            except subprocess.TimeoutExpired:
                raise Refused('command_timeout')
            require(code == 0, 'command_failed')
            return output.decode('utf-8')
        finally:
            selector.close()
            if process.poll() is None:
                process.kill()
            process.wait()
            process.stdout.close()


def properties(unit):
    raw = run(['/usr/bin/systemctl', 'show', unit, '--no-pager',
               '--property=' + ','.join(PROPERTIES)])
    values = dict(line.split('=', 1) for line in raw.splitlines() if '=' in line)
    require(set(values) == set(PROPERTIES), 'unit_properties_missing')
    return values


def policy():
    trusted(POLICY)
    value = document(POLICY)
    require(set(value) == {'version', 'accepted', 'baseline', 'database', 'current_link',
                           'releases_dir', 'node', 'schema_sha256', 'units'}, 'policy_keys')
    require(value['version'] == 1 and value['accepted'] is True and value['baseline'] == BASELINE,
            'layout_not_accepted')
    require(value['database'] == {'host': '127.0.0.1', 'port': 55432, 'verified': True}, 'database_not_attested')
    for key in ('current_link', 'releases_dir'):
        p = Path(value[key])
        require(p.is_absolute() and p != ROOT and p.is_relative_to(ROOT) and '..' not in p.parts,
                'layout_path_invalid')
        require(p.parent.resolve() == p.parent, 'layout_parent_symlink')
    releases = Path(value['releases_dir'])
    require(releases.is_dir() and not releases.is_symlink(), 'releases_directory_missing')
    current = Path(value['current_link'])
    require(not current.is_relative_to(releases) and not releases.is_relative_to(current), 'layout_overlap')
    require(re.fullmatch(DIGEST, value['schema_sha256']) is not None, 'schema_not_attested')
    trusted(Path(value['node']))
    require(set(value['units']) == set(UNITS), 'unit_policy_missing')
    for alias, unit in UNITS.items():
        expected = value['units'][alias]
        require(set(expected) == set(PROPERTIES) and expected['User'] == 'aifinance-deploy', 'unit_policy_invalid')
        # Do not infer an indirect launcher's behavior. Unit cwd must use the approved switch link.
        require(expected['WorkingDirectory'] in (str(current), str(current / 'apps/web')),
                'unit_not_bound_to_switch')
        require(properties(unit) == expected, 'unit_changed_since_acceptance')
        trusted(Path(expected['FragmentPath']))
        for dropin in expected['DropInPaths'].split():
            trusted(Path(dropin))
    version = run([value['node'], '--version']).strip()
    require(re.fullmatch(r'v24\.[0-9]+\.[0-9]+', version) and
            int(version.split('.')[1]) >= 11, 'node_version')
    # Do not require live listeners here: status/logs and interrupted rollback must
    # remain available when an app is down. Health gates enforce them on release.
    return value


def state_dir():
    p = ROOT / 'state/rebuilt'
    require(p.is_dir() and not p.is_symlink() and p.resolve() == p, 'state_not_provisioned')
    require(stat.S_IMODE(p.stat().st_mode) == 0o700 and p.stat().st_uid == os.getuid(), 'state_permissions')
    return p


def lock(directory, shared=False):
    fd = os.open(directory / 'release.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600, 'invalid_lock_file')
        fcntl.flock(fd, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise Refused('operation_busy')
    except BaseException:
        os.close(fd)
        raise
    return fd


def upload(sha, digest, stream):
    incoming = ROOT / 'incoming'
    require(incoming.is_dir() and incoming.resolve() == incoming, 'incoming_not_provisioned')
    target = incoming / (sha + '.tar.gz')
    fd, temporary = tempfile.mkstemp(prefix='.upload-', dir=incoming)
    try:
        count = 0
        h = hashlib.sha256()
        with os.fdopen(fd, 'wb') as output:
            while True:
                chunk = stream.read(min(65536, LIMIT + 1 - count))
                if not chunk:
                    break
                count += len(chunk)
                require(count <= LIMIT, 'archive_limit')
                h.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        require(count > 0 and h.hexdigest() == digest, 'archive_digest')
        if target.exists() or target.is_symlink():
            require(file_digest(target) == digest, 'archive_conflict')
        else:
            os.link(temporary, target)
            sync_dir(incoming)
    finally:
        os.unlink(temporary)
    return {'uploaded': sha, 'sha256': digest}


def file_digest(path):
    h = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= LIMIT, 'archive_invalid')
        count = 0
        for chunk in iter(lambda: source.read(65536), b''):
            count += len(chunk)
            require(count <= LIMIT, 'archive_limit')
            h.update(chunk)
        after = os.fstat(source.fileno())
        require(count == info.st_size == after.st_size and info.st_mtime_ns == after.st_mtime_ns,
                'archive_changed_during_read')
    return h.hexdigest()


def release_path(p, sha):
    return ROOT / 'staging' / BASELINE if sha == BASELINE else Path(p['releases_dir']) / sha


def validate_release(p, sha):
    target = release_path(p, sha)
    require(target.resolve(strict=True) == target, 'release_path_invalid')
    require(read(target / 'RELEASE_SHA', 64).decode().strip() == sha, 'release_identity')
    manifest = read(target / 'schema.sha256')
    require(hashlib.sha256(manifest).hexdigest() == p['schema_sha256'], 'schema_changed')
    # Verify actual migration bytes, not just the upload's claimed manifest.
    migrations = target / 'database/migrations'
    require(migrations.is_dir() and migrations.resolve() == migrations, 'migration_directory_symlink')
    actual = ''.join(hashlib.sha256(read(f, 1024*1024)).hexdigest() + '  database/migrations/' + f.name + '\n'
                     for f in sorted(migrations.glob('*.sql'))).encode()
    require(actual and actual == manifest, 'migration_manifest_invalid')
    require((target / 'apps/web/build/server/index.js').is_file() and (target / 'node_modules').is_dir(),
            'release_build_missing')
    require(all((target / name).resolve().is_relative_to(target) for name in
                ('apps/web/build/server/index.js', 'node_modules')), 'release_build_escape')
    return target


def current_sha(p, allow_missing=False):
    link = Path(p['current_link'])
    require(link.is_symlink(), 'current_link_missing')
    target = link.resolve(strict=not allow_missing)
    sha = target.name
    require(re.fullmatch(SHA, sha) is not None and target == release_path(p, sha), 'current_layout_unknown')
    return sha


def listeners():
    found = {3000: [], 3001: [], 55432: []}
    for line in run(['/usr/bin/ss', '-H', '-ltn']).splitlines():
        fields = line.split()
        require(len(fields) >= 5, 'listener_metadata_invalid')
        host, _, port = fields[3].rpartition(':')
        if port.isdigit() and int(port) in found:
            found[int(port)].append(host)
    require(all(addresses == ['127.0.0.1'] for addresses in found.values()), 'loopback_boundary_changed')


def healthy(sha):
    for _ in range(20):
        try:
            listeners()
            run(['/usr/bin/systemctl', 'is-active', '--quiet', *UNITS.values()])
            data = json.loads(run(['/usr/bin/curl', '--noproxy', '*', '--max-time', '3', '-fsS',
                                   'http://127.0.0.1:3001/api/health'], limit=4096, timeout=5))
            require(isinstance(data, dict) and data.get('ok') is True and data.get('release') == sha,
                    'health_revision_mismatch')
            run(['/usr/bin/curl', '--noproxy', '*', '--max-time', '3', '-fsS', '-o', '/dev/null',
                 'http://127.0.0.1:3000/'], timeout=5)
            return True
        except (Refused, ValueError):
            time.sleep(2)
    return False


def switch(p, sha, opid, previous):
    link = Path(p['current_link'])
    require(link.parent.resolve() == link.parent and current_sha(p, allow_missing=True) in (previous, sha),
            'switch_layout_changed')
    pending = link.parent / ('.rebuilt-switch-' + opid)
    if pending.is_symlink():
        require(os.readlink(pending) == str(release_path(p, sha)), 'pending_switch_conflict')
    else:
        require(not pending.exists(), 'pending_switch_conflict')
        pending.symlink_to(release_path(p, sha))
    os.replace(pending, link)
    sync_dir(link.parent)


def restart():
    run(['/usr/bin/sudo', '-n', '/usr/bin/systemctl', 'restart', *UNITS.values()], timeout=45)


def services_idle():
    # A killed SSH process may leave a systemd job running after its flock closes.
    # Refuse a new/resumed mutation until those named jobs have finished.
    rows = run(['/usr/bin/systemctl', 'list-jobs', '--no-legend', '--no-pager', '--plain'])
    for line in rows.splitlines():
        fields = line.split()
        require(len(fields) == 4 and fields[0].isdigit(), 'job_metadata_invalid')
        require(fields[1] not in UNITS.values(), 'service_job_pending')


def receipt(directory, opid):
    value = document(directory / (opid + '.json'))
    require(set(value) == {'id', 'action', 'revision', 'digest', 'previous', 'phase', 'updated'} and
            value['id'] == opid and value['action'] in ('deploy', 'rollback') and
            re.fullmatch(SHA, value['revision']) and re.fullmatch(SHA, value['previous']) and
            ((value['action'] == 'rollback' and value['digest'] == '') or
             (value['action'] == 'deploy' and re.fullmatch(DIGEST, value['digest']))) and
            value['phase'] in PHASES and type(value['updated']) is int, 'receipt_invalid')
    return value


def active_id(directory):
    path = directory / 'active.json'
    if not path.exists() and not path.is_symlink():
        return None
    value = document(path)
    require(set(value) == {'id'} and re.fullmatch(ID, value['id']), 'active_receipt_invalid')
    return value['id']


def save(directory, record, phase):
    record.update(phase=phase, updated=int(time.time()))
    atomic(directory / (record['id'] + '.json'), record)


def publish(p, directory, action, sha, digest, opid):
    previous_id = active_id(directory)
    if previous_id and previous_id != opid:
        require(receipt(directory, previous_id)['phase'] in ('succeeded', 'rolled_back'), 'unfinished_operation')
    existing = directory / (opid + '.json')
    if existing.exists() or existing.is_symlink():
        record = receipt(directory, opid)
        require((record['action'], record['revision'], record['digest']) == (action, sha, digest), 'operation_id_conflict')
        if record['phase'] in TERMINAL:
            if record['phase'] == 'succeeded':
                require(current_sha(p) == sha, 'operation_superseded')
                validate_release(p, sha)
                require(healthy(sha), 'completed_release_unhealthy')
            return record
        require(current_sha(p, allow_missing=True) in (record['previous'], sha), 'interrupted_layout_changed')
    else:
        old = current_sha(p)
        validate_release(p, old)
        require(healthy(old), 'baseline_not_healthy')
        record = dict(id=opid, action=action, revision=sha, digest=digest, previous=old,
                      phase='prepared', updated=int(time.time()))
        save(directory, record, 'prepared')
    atomic(directory / 'active.json', {'id': opid})
    validate_release(p, record['previous'])
    target = release_path(p, sha)
    if record['phase'] == 'prepared':
        if action == 'deploy':
            archive = ROOT / 'incoming' / (sha + '.tar.gz')
            require(file_digest(archive) == digest, 'archive_digest')
            marker = directory / ('artifact-' + sha + '.json')
            require(not target.is_symlink(), 'release_path_invalid')
            if target.exists():
                require(document(marker) == {'sha256': digest}, 'existing_release_unverified')
            else:
                stage = Path(p['releases_dir']) / ('.rebuilt-stage-' + opid)
                require(not stage.exists() and not stage.is_symlink(), 'incomplete_stage_review_required')
                stage.mkdir(mode=0o700)
                helper = ROOT / 'bin/extract-release.py'
                trusted(helper)
                try:
                    run(['/usr/bin/python3', '-I', '-B', str(helper), str(archive), str(stage)], timeout=60)
                    os.rename(stage, target)
                    sync_dir(target.parent)
                    atomic(marker, {'sha256': digest})
                finally:
                    if stage.is_dir() and not stage.is_symlink():
                        shutil.rmtree(stage)
        validate_release(p, sha)
        save(directory, record, 'switching')
    if record['phase'] in ('switching', 'checking'):
        try:
            validate_release(p, sha)
        except (Refused, OSError):
            # A damaged/missing new release must not prevent restoring the verified old one.
            save(directory, record, 'rolling_back')
    if record['phase'] in ('switching', 'checking'):
        # A retry after a lost response checks the running SHA before another restart.
        if current_sha(p) == sha and healthy(sha):
            save(directory, record, 'succeeded')
            return record
        try:
            switch(p, sha, opid, record['previous'])
            save(directory, record, 'checking')
            restart()
            require(healthy(sha), 'new_release_unhealthy')
            save(directory, record, 'succeeded')
            return record
        except (Refused, OSError):
            save(directory, record, 'rolling_back')
    if record['phase'] == 'rolling_back':
        try:
            switch(p, record['previous'], opid, sha)
            restart()
            require(healthy(record['previous']), 'rollback_unhealthy')
            save(directory, record, 'rolled_back')
        except (Refused, OSError):
            save(directory, record, 'recovery_required')
    return record


def logs(alias):
    # Message text/identifiers are deliberately omitted: regex redaction cannot prove secrecy.
    raw = run(['/usr/bin/journalctl', '--quiet', '--no-pager', '--output=json', '--lines=50',
               '--output-fields=__REALTIME_TIMESTAMP,PRIORITY,_SYSTEMD_UNIT',
               '--since=-15min', '--unit=' + UNITS[alias]], limit=65536)
    rows = []
    for line in raw.splitlines():
        item = json.loads(line)
        require(isinstance(item, dict) and item.get('_SYSTEMD_UNIT') == UNITS[alias], 'journal_unit_mismatch')
        stamp, priority = item.get('__REALTIME_TIMESTAMP', ''), item.get('PRIORITY', '')
        require(isinstance(stamp, str) and re.fullmatch(r'[0-9]{1,20}', stamp) and
                isinstance(priority, str) and re.fullmatch(r'[0-7]', priority), 'journal_metadata_invalid')
        rows.append({'timestamp_us': stamp, 'priority': int(priority)})
    require(len(rows) <= 50, 'journal_limit')
    return {'service': alias, 'entries': rows, 'message_text': 'omitted',
            'visibility': 'current_account_only; empty does not prove no logs'}


def main():
    args = parse(os.environ.get('SSH_ORIGINAL_COMMAND', ''))
    os.environ.clear()
    os.environ.update(ENV)
    os.umask(0o077)
    require(os.getuid() != 0 and os.geteuid() == os.getuid() and
            pwd.getpwuid(os.getuid()).pw_name == 'aifinance-deploy', 'wrong_user')
    if args == ['verify']:
        return {'protocol': 'rebuilt-v1', 'access': True, 'layout_verified': False}
    p = policy()
    directory = state_dir()
    if args[0] == 'logs':
        return logs(args[1])
    fd = lock(directory, shared=args[0] in ('status', 'inspect'))
    try:
        if args[0] in ('status', 'inspect'):
            opid = args[1] if len(args) == 2 else active_id(directory)
            return {'protocol': 'rebuilt-v1', 'current': current_sha(p),
                    'operation': receipt(directory, opid) if opid else None}
        if args[0] == 'upload':
            return upload(args[1], args[2], sys.stdin.buffer)
        services_idle()
        if args[0] == 'resume':
            record = receipt(directory, args[1])
            return publish(p, directory, record['action'], record['revision'], record['digest'], record['id'])
        action, sha = args[:2]
        digest, opid = (args[2], args[3]) if action == 'deploy' else ('', args[2])
        return publish(p, directory, action, sha, digest, opid)
    finally:
        os.close(fd)


if __name__ == '__main__':
    def interrupted(*_):
        raise Interrupted()
    for signum in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupted)
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(Refused('operation_timeout')))
    signal.alarm(480)
    try:
        result = main()
        print(json.dumps(result, sort_keys=True))
        sys.exit(0 if result.get('phase', 'succeeded') == 'succeeded' else 1)
    except Refused as error:
        print(json.dumps({'ok': False, 'reason': str(error)}))
        sys.exit(1)
    except Interrupted:
        print('{"ok":false,"reason":"operation_interrupted_query_status"}')
        sys.exit(1)
    except Exception:
        print('{"ok":false,"reason":"operation_unavailable"}')
        sys.exit(1)
