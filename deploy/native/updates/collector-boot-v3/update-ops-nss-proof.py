#!/usr/bin/python3
"""One root-terminal NSS-proof update. No remote update verb or other host change.

Only the fixed runner, broker, policy and completion gate may change. Historical
installation/recovery records stay untouched. All backups and interrupted stages
are retained. Unknown changes keep the completion gate closed wherever its inode
is still known; they are never overwritten or reported as a successful rollback.
"""
import argparse
import base64
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import resource
import signal
import stat
import sys
import types

ROOT = Path('/opt/aifinance')
BIN = ROOT / 'bin'
OPS = Path('/var/lib/aifinance-ops')
COLLECT = Path('/var/lib/aifinance-maintenance/collect-only')
HISTORY = OPS / 'install.json'
UPDATE = OPS / 'nss-proof-v1-update'
PRIOR = OPS / 'collector-boot-v2'
PROC = Path('/proc')
TARGETS = {'runner': BIN / 'collect-only-runner.py', 'broker': BIN / 'ops-broker.py',
           'policy': OPS / 'policy.json', 'complete': OPS / 'complete.json'}
MODES = {'runner': 0o755, 'broker': 0o755, 'policy': 0o600, 'complete': 0o600}
OLD_RUNNER = '7555b956d26f93c2829683008a3f78f71e1e122d21f6c2fc25bcf3d222769cdf'
NEW_RUNNER = '95716db9e4c32be5555790147ff9b06a7ba8b916e26ade06b81d2cf79132fc35'
OLD_BROKER = '2620884dbba3acad9abc68db50ca2d09aa434b2d6f5e82f2ab28144228559fcc'
NEW_BROKER = '42adff178fdbbba3a352f958a48faee96a5e2ef96c2bfe1074c76285669f6d47'
UPGRADE = '9eb61d5b9357a31ed319202efd14ffedbc591aac1fe090179f719246971dfca5'
SOURCE_PATTERN = r'/root/aifinance-ops-nss-v1-[A-Za-z0-9]{12}'
SOURCE_FILES = {'update-ops-nss-proof.py', 'collect-only-runner.py', 'ops-broker.py', 'update-manifest.json'}
ENV = dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin', HOME='/', LANG='C', LC_ALL='C', TZ='UTC')


class Refused(ValueError):
    pass


def sha(data):
    return hashlib.sha256(data).hexdigest()


def trusted_dir(path, mode=None):
    if not path.is_absolute() or '..' in path.parts:
        raise Refused('unsafe_path')
    for item in (path,) + tuple(path.parents):
        info = item.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022 or
                item == path and mode is not None and stat.S_IMODE(info.st_mode) != mode):
            raise Refused('unsafe_directory')


def read(path, mode, maximum=1048576):
    trusted_dir(path.parent)
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno()); selected = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or info.st_nlink != 1 or
                stat.S_IMODE(info.st_mode) != mode or info.st_size > maximum or
                (info.st_dev, info.st_ino) != (selected.st_dev, selected.st_ino)):
            raise Refused('unsafe_file')
        data = stream.read(maximum + 1)
        if len(data) != info.st_size:
            raise Refused('file_changed_or_oversize')
        return data, (info.st_dev, info.st_ino)


def attrs(path):
    names = os.listxattr(str(path), follow_symlinks=False)
    if any(name != 'security.selinux' for name in names):
        raise Refused('unsupported_security_attributes')
    return {name: os.getxattr(str(path), name, follow_symlinks=False) for name in names}


def absent(path):
    try:
        path.lstat()
    except FileNotFoundError:
        return
    raise Refused('existing_update_or_stage')


def sync(path):
    fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path, data, mode=0o600, attributes=None):
    trusted_dir(path.parent)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        os.fchown(stream.fileno(), 0, 0)
        stream.write(data); stream.flush()
        for name, value in (attributes or {}).items():
            os.setxattr(stream.fileno(), name, value)
        os.fchmod(stream.fileno(), mode); os.fsync(stream.fileno())
    sync(path.parent)
    if attributes is not None and attrs(path) != attributes:
        raise Refused('security_attributes_not_preserved')
    return read(path, mode)[1]


def encoded(value):
    return (json.dumps(value, sort_keys=True) + '\n').encode('ascii')


def module(code, path, name):
    result = types.ModuleType(name); result.__file__ = str(path)
    exec(compile(code, str(path), 'exec'), result.__dict__)
    return result


def source_inputs(source, expected):
    if not re.fullmatch(SOURCE_PATTERN, str(source)) or not re.fullmatch(r'[0-9a-f]{64}', expected):
        raise Refused('fixed_source_and_manifest_pin_required')
    trusted_dir(source, 0o700)
    if {path.name for path in source.iterdir()} != SOURCE_FILES:
        raise Refused('exact_update_inputs_required')
    raw, _ = read(source / 'update-manifest.json', 0o600, 8192)
    if sha(raw) != expected:
        raise Refused('update_manifest_hash_mismatch')
    def unique(rows):
        out = {}
        for key, value in rows:
            if key in out:
                raise Refused('duplicate_manifest_key')
            out[key] = value
        return out
    manifest = json.loads(raw.decode('ascii'), object_pairs_hook=unique)
    if (not isinstance(manifest, dict) or set(manifest) != {'schema', 'updater_sha256', 'runner_sha256', 'broker_sha256'} or
            type(manifest['schema']) is not int or manifest['schema'] != 1 or
            manifest['runner_sha256'] != NEW_RUNNER or manifest['broker_sha256'] != NEW_BROKER):
        raise Refused('fixed_update_manifest_required')
    data = {}
    for key, name in (('updater', 'update-ops-nss-proof.py'), ('runner', 'collect-only-runner.py'), ('broker', 'ops-broker.py')):
        data[key] = read(source / name, 0o600, 262144)[0]
        if sha(data[key]) != manifest[key + '_sha256']:
            raise Refused('update_payload_hash_mismatch')
        compile(data[key], name, 'exec')
    return manifest, data


@contextlib.contextmanager
def lock(runner):
    fd = runner.release_lock()
    try:
        owner = pwd.getpwnam('aifinance-deploy'); info = os.fstat(fd)
        if (info.st_nlink != 1 or info.st_uid != owner.pw_uid or info.st_gid != owner.pw_gid or
                stat.S_IMODE(info.st_mode) != 0o644):
            raise Refused('canonical_lock_changed')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        selected = (ROOT / 'state/release.lock').lstat()
        if (info.st_dev, info.st_ino) != (selected.st_dev, selected.st_ino):
            raise Refused('canonical_lock_changed')
        yield
    finally:
        os.close(fd)


def no_controllers():
    scripts = [str(TARGETS[key]).encode() for key in ('runner', 'broker')]
    for entry in PROC.iterdir():
        if not entry.name.isdigit() or int(entry.name) == os.getpid():
            continue
        try:
            with (entry / 'status').open('rb') as stream:
                status = stream.read(65537)
            rows = [line.split()[1:] for line in status.splitlines() if line.startswith(b'Uid:')]
            if len(status) > 65536 or len(rows) != 1 or len(rows[0]) != 4:
                raise Refused('process_identity_unverifiable')
            if b'0' not in rows[0]:
                continue
            with (entry / 'cmdline').open('rb') as stream:
                command = stream.read(16385)
            if len(command) > 16384:
                raise Refused('process_command_unverifiable')
            if any(script in command for script in scripts):
                raise Refused('root_controller_in_flight')
        except (FileNotFoundError, ProcessLookupError):
            continue


def preconditions(b, runner, upgrade):
    worker = b.Broker(runner, upgrade); user = worker.base(); states = b.unit_states()
    worker.idle(user, states); worker.no_timer(states); worker.db_only_network(user); worker.probe_receipt(user)
    baseline = worker.recovery_baseline()
    for name in ('recovery.json', 'pre-seed-attempt-v1.json', 'recovery.json.next'):
        absent(OPS / name)
    for name in ('seed.json', 'run.json', 'run-attempt.json', 'hourly-approved.json', 'launch.json'):
        absent(COLLECT / name)
    raw = read(COLLECT / 'seed-attempt.json', 0o600, 4096)[0]
    attempt = json.loads(raw.decode(), object_pairs_hook=b.unique)
    if (set(attempt) != {'release', 'mode', 'started'} or attempt['release'] != b.RELEASE or attempt['mode'] != 'seed' or
            type(attempt['started']) is not int or sha(raw) != baseline['attempt_sha256'] or attempt['started'] != baseline['attempt_started']):
        raise Refused('original_attempt_baseline_changed')
    for key, value in (('ActiveState', 'failed'), ('Result', 'signal'), ('ExecMainCode', '2'), ('ExecMainStatus', '15'),
                       ('ExecMainStartTimestampMonotonic', baseline['check_start_monotonic']),
                       ('ExecMainExitTimestampMonotonic', baseline['check_exit_monotonic'])):
        if states['check'].get(key) != value:
            raise Refused('original_check_baseline_changed')
    for alias in ('seed', 'run'):
        if states[alias].get('ExecMainStartTimestampMonotonic') != '0' or worker.journal_metadata(alias, attempt['started']):
            raise Refused('collection_start_evidence_present')
    fd, info = worker.environment_fd(disabled=True)
    try:
        if (info.st_dev, info.st_ino, user.pw_gid) != (baseline['db_device'], baseline['db_inode'], baseline['collector_gid']):
            raise Refused('original_database_file_changed')
        runner.database_url(os.read(fd, 8193).decode('utf-8'))
    finally:
        os.close(fd)


def prepared(b, runner, upgrade, data):
    trusted_dir(OPS, 0o700); absent(UPDATE)
    old, identities, labels = {}, {}, {}
    for key, path in TARGETS.items():
        old[key], identities[key] = read(path, MODES[key]); labels[key] = attrs(path)
        absent(path.with_name('.' + path.name + '.nss-v1.next'))
        absent(path.with_name('.' + path.name + '.nss-v1.restore'))
    if sha(old['runner']) != OLD_RUNNER or sha(old['broker']) != OLD_BROKER:
        raise Refused('old_helper_set_changed')
    policy = b.policy(); b.installation_complete(policy)
    completion = {'schema': 1, 'status': 'complete', 'broker_sha256': OLD_BROKER, 'app_release': b.RELEASE}
    if old['policy'] != encoded(policy) or old['complete'] != encoded(completion):
        raise Refused('old_policy_or_completion_bytes_changed')
    expected = old['broker'].replace(('RUNNER_SHA = ' + repr(OLD_RUNNER)).encode(), ('RUNNER_SHA = ' + repr(NEW_RUNNER)).encode(), 1)
    if data['broker'] != expected:
        raise Refused('only_broker_runner_pin_change_allowed')
    new = {'runner': data['runner'], 'broker': data['broker']}
    new['policy'] = encoded(dict(policy, runner_sha256=NEW_RUNNER, broker_sha256=NEW_BROKER))
    new['complete'] = encoded(dict(completion, broker_sha256=NEW_BROKER))
    replacement = module(new['runner'], TARGETS['runner'], 'new_nss_runner')
    if any(runner.unit_text(mode) != replacement.unit_text(mode) for mode in ('probe', 'check', 'seed', 'run')) or runner.hourly_text() != replacement.hourly_text():
        raise Refused('unit_templates_must_not_change')
    preconditions(b, runner, upgrade)
    history, history_id = read(HISTORY, 0o600)
    return {'old': old, 'new': new, 'identities': identities, 'labels': labels, 'history': (history, history_id)}


def known(key, prepared, staged):
    path = TARGETS[key]
    try:
        value, identity = read(path, MODES[key])
    except FileNotFoundError:
        return key == 'complete'
    except (OSError, Refused):
        return False
    try:
        if attrs(path) != prepared['labels'][key]:
            return False
    except (OSError, Refused):
        return False
    old_identities = (prepared['identities'][key], prepared.get('restored', {}).get(key))
    return ((value == prepared['old'][key] and identity in old_identities) or
            (value == prepared['new'][key] and identity == staged[key]))


def withdraw_known(prepared, staged, name, required=False):
    path = TARGETS['complete']
    if not path.exists() and not path.is_symlink():
        if required:
            raise Refused('completion_gate_missing_before_withdrawal')
        return
    if not known('complete', prepared, staged):
        raise Refused('unknown_completion_gate')
    destination = UPDATE / name; absent(destination)
    os.rename(str(path), str(destination)); sync(OPS); sync(UPDATE)


def owns_first_withdrawal(change):
    path = UPDATE / 'complete.withheld'
    try:
        return (read(path, MODES['complete']) == (change['old']['complete'], change['identities']['complete']) and
                attrs(path) == change['labels']['complete'])
    except (OSError, Refused):
        return False


def apply(b, runner, upgrade, manifest, change):
    report = {'ok': False, 'stage': 'stage_files', 'rollback': 'not_needed', 'completion_gate': 'unverified'}
    staged, attempted, withdrawing = {}, False, False
    try:
        UPDATE.mkdir(mode=0o700); sync(OPS)
        write_new(UPDATE / 'manifest.json', encoded(manifest))
        for key, path in TARGETS.items():
            write_new(UPDATE / (key + '.before'), change['old'][key])
            temporary = path.with_name('.' + path.name + '.nss-v1.next')
            staged[key] = write_new(temporary, change['new'][key], MODES[key], change['labels'][key])
        plan = {'schema': 1, 'files': {key: {'old_sha256': sha(change['old'][key]), 'new_sha256': sha(change['new'][key]),
                    'mode': MODES[key], 'old_identity': list(change['identities'][key]), 'staged_identity': list(staged[key]),
                    'security_attributes': {name: base64.b64encode(value).decode('ascii') for name, value in change['labels'][key].items()}}
                    for key in TARGETS},
                'history_sha256': sha(change['history'][0]), 'history_identity': list(change['history'][1])}
        write_new(UPDATE / 'plan.json', encoded(plan))
        sync(UPDATE)
        try:
            unchanged = all(read(TARGETS[key], MODES[key]) == (change['old'][key], change['identities'][key]) and
                            attrs(TARGETS[key]) == change['labels'][key] for key in TARGETS)
        except (OSError, Refused):
            unchanged = False
        if not unchanged or read(HISTORY, 0o600) != change['history']:
            raise Refused('files_changed_before_gate_withdrawal')
        report['stage'] = 'withdraw_gate'
        withdrawing = True
        withdraw_known(change, staged, 'complete.withheld', required=True)
        attempted = owns_first_withdrawal(change)
        if not attempted:
            raise Refused('original_gate_withdrawal_unverified')
        report['completion_gate'] = 'withheld'
        no_controllers(); preconditions(b, runner, upgrade)
        for key in ('policy', 'runner', 'broker'):
            report['stage'] = 'replace_' + key
            if not all(known(name, change, staged) for name in TARGETS):
                raise Refused('unknown_concurrent_file_change')
            path = TARGETS[key]
            temporary = path.with_name('.' + path.name + '.nss-v1.next')
            if read(temporary, MODES[key]) != (change['new'][key], staged[key]) or attrs(temporary) != change['labels'][key]:
                raise Refused('staged_file_changed')
            os.replace(str(temporary), str(path)); sync(path.parent)
        report['stage'] = 'verify_new_set'
        new_broker = module(change['new']['broker'], TARGETS['broker'], 'new_nss_broker')
        new_runner = module(change['new']['runner'], TARGETS['runner'], 'new_nss_runner_verify')
        new_policy = new_broker.policy(); preconditions(new_broker, new_runner, upgrade)
        no_controllers()
        if read(HISTORY, 0o600) != change['history'] or not all(known(key, change, staged) for key in TARGETS):
            raise Refused('unknown_concurrent_file_change')
        for key in ('runner', 'broker', 'policy'):
            if read(TARGETS[key], MODES[key]) != (change['new'][key], staged[key]) or attrs(TARGETS[key]) != change['labels'][key]:
                raise Refused('new_set_not_coherent')
        report['stage'] = 'publish_completion'; path = TARGETS['complete']; absent(path)
        temporary = path.with_name('.' + path.name + '.nss-v1.next')
        if read(temporary, MODES['complete']) != (change['new']['complete'], staged['complete']) or attrs(temporary) != change['labels']['complete']:
            raise Refused('staged_file_changed')
        os.replace(str(temporary), str(path)); sync(path.parent)
        new_broker.installation_complete(new_policy)
        write_new(UPDATE / 'complete.json', encoded({'schema': 1, 'runner_sha256': NEW_RUNNER, 'broker_sha256': NEW_BROKER}))
        report.update(ok=True, stage='complete', completion_gate='new_verified')
    except BaseException as error:
        report['reason'] = error.args[0] if type(error) is Refused else b.reason(error)
        if withdrawing and not attempted:
            attempted = owns_first_withdrawal(change)
        if attempted:
            try:
                withdraw_known(change, staged, 'complete.after_failure')
                report['completion_gate'] = 'withheld'
                all_known = all(known(key, change, staged) for key in TARGETS)
                if not all_known or read(HISTORY, 0o600) != change['history']:
                    raise Refused('rollback_refused_unknown_change')
                no_controllers()
                restored = {}; change['restored'] = restored
                for key in ('policy', 'runner', 'broker'):
                    path = TARGETS[key]
                    if not known(key, change, staged):
                        raise Refused('rollback_refused_unknown_change')
                    temporary = path.with_name('.' + path.name + '.nss-v1.restore')
                    restored[key] = write_new(temporary, change['old'][key], MODES[key], change['labels'][key])
                    if not known(key, change, staged) or read(temporary, MODES[key]) != (change['old'][key], restored[key]):
                        raise Refused('rollback_refused_unknown_change')
                    os.replace(str(temporary), str(path)); sync(path.parent)
                b.policy(); preconditions(b, runner, upgrade); no_controllers()
                for key in restored:
                    if read(TARGETS[key], MODES[key]) != (change['old'][key], restored[key]) or attrs(TARGETS[key]) != change['labels'][key]:
                        raise Refused('rollback_refused_unknown_change')
                if read(HISTORY, 0o600) != change['history']:
                    raise Refused('rollback_refused_unknown_change')
                path = TARGETS['complete']; absent(path)
                temporary = path.with_name('.' + path.name + '.nss-v1.restore')
                restored['complete'] = write_new(temporary, change['old']['complete'], MODES['complete'], change['labels']['complete'])
                if not all(known(key, change, staged) for key in TARGETS) or read(temporary, MODES['complete']) != (change['old']['complete'], restored['complete']):
                    raise Refused('rollback_refused_unknown_change')
                os.replace(str(temporary), str(path)); sync(OPS); b.installation_complete(b.policy())
                report.update(rollback='old_set_verified', completion_gate='original_verified')
            except BaseException as rollback_error:
                report['rollback'] = rollback_error.args[0] if type(rollback_error) is Refused else b.reason(rollback_error)
                try:
                    withdraw_known(change, staged, 'complete.rollback_refused')
                    report['completion_gate'] = 'withheld'
                except BaseException:
                    report['completion_gate'] = 'unknown'
    return report


def withheld_evidence(change, missing=True):
    """Recheck real v2 evidence; an absent live gate has no old target inode."""
    evidence = change.get('withheld')
    fields = {'path', 'plan_path', 'plan_raw', 'plan_identity', 'raw', 'identity', 'labels'}
    if (not isinstance(evidence, dict) or set(evidence) != fields or
            evidence['path'] != PRIOR / 'helper-update/complete.withheld' or
            evidence['plan_path'] != PRIOR / 'helper-update/plan.json' or
            type(evidence['raw']) is not bytes or type(evidence['plan_raw']) is not bytes or
            any(type(evidence[key]) is not tuple or len(evidence[key]) != 2 or
                any(type(value) is not int or value < 0 for value in evidence[key])
                for key in ('identity', 'plan_identity')) or
            not isinstance(evidence['labels'], dict) or
            any(name != 'security.selinux' or type(value) is not bytes for name, value in evidence['labels'].items())):
        raise Refused('exact_withheld_evidence_required')
    trusted_dir(PRIOR, 0o700); trusted_dir(PRIOR / 'helper-update', 0o700)
    if (read(evidence['plan_path'], 0o600) != (evidence['plan_raw'], evidence['plan_identity']) or
            read(evidence['path'], 0o600) != (evidence['raw'], evidence['identity']) or
            attrs(evidence['path']) != evidence['labels']):
        raise Refused('withheld_evidence_changed')
    def unique(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise Refused('duplicate_withheld_plan_key')
            result[key] = value
        return result
    try:
        plan = json.loads(evidence['plan_raw'].decode('ascii'), object_pairs_hook=unique)
        complete = plan['files']['complete']
        expected = {name: base64.b64encode(value).decode('ascii') for name, value in evidence['labels'].items()}
        valid = (type(plan['schema']) is int and plan['schema'] == 1 and
                 set(complete) == {'old_sha256', 'new_sha256', 'mode', 'old_identity', 'staged_identity', 'security_attributes'} and
                 type(complete['mode']) is int and complete['mode'] == MODES['complete'] and
                 complete['old_sha256'] == sha(evidence['raw']) and
                 type(complete['old_identity']) is list and len(complete['old_identity']) == 2 and
                 all(type(value) is int for value in complete['old_identity']) and
                 complete['old_identity'] == list(evidence['identity']) and
                 complete['security_attributes'] == expected)
    except (KeyError, TypeError, ValueError, UnicodeError):
        raise Refused('withheld_plan_mismatch')
    if not valid:
        raise Refused('withheld_plan_mismatch')
    if missing:
        absent(TARGETS['complete'])
    return evidence


def known_withheld(key, change, staged):
    if key != 'complete':
        return known(key, change, staged)
    try:
        value, identity = read(TARGETS[key], MODES[key])
        return (value == change['new'][key] and identity == staged[key] and
                attrs(TARGETS[key]) == change['withheld']['labels'])
    except FileNotFoundError:
        return True
    except (OSError, Refused):
        return False


def withdraw_withheld(change, staged, name):
    path = TARGETS['complete']
    if not path.exists() and not path.is_symlink():
        return
    if not known_withheld('complete', change, staged):
        raise Refused('unknown_completion_gate')
    destination = UPDATE / name; absent(destination)
    os.rename(str(path), str(destination)); sync(OPS); sync(UPDATE)


def apply_withheld(b, runner, upgrade, manifest, change):
    """Continue the accepted failed-v2 transaction without reopening its old gate."""
    report = {'ok': False, 'stage': 'accept_withheld', 'rollback': 'not_needed', 'completion_gate': 'unverified'}
    helpers = ('policy', 'runner', 'broker'); staged = {key: None for key in TARGETS}; owned = False
    try:
        if (any(set(change[key]) != set(helpers) for key in ('old', 'identities', 'labels')) or
                set(change['new']) != set(TARGETS)):
            raise Refused('absent_completion_transaction_required')
        evidence = withheld_evidence(change)
        if (sha(change['old']['runner']) != OLD_RUNNER or sha(change['old']['broker']) != OLD_BROKER or
                change['old']['policy'] != encoded(b.policy())):
            raise Refused('old_helper_or_policy_set_changed')
        if not all(known_withheld(key, change, staged) for key in helpers) or read(HISTORY, 0o600) != change['history']:
            raise Refused('files_changed_before_continuation')
        owned = True; report['completion_gate'] = 'withheld'
        report['stage'] = 'stage_files'
        UPDATE.mkdir(mode=0o700); sync(UPDATE.parent)
        write_new(UPDATE / 'manifest.json', encoded(manifest))
        labels = dict(change['labels'], complete=evidence['labels'])
        for key, path in TARGETS.items():
            withheld_evidence(change)
            absent(path.with_name('.' + path.name + '.collector-v3.restore'))
            if key != 'complete':
                write_new(UPDATE / (key + '.before'), change['old'][key])
            temporary = path.with_name('.' + path.name + '.collector-v3.next')
            staged[key] = write_new(temporary, change['new'][key], MODES[key], labels[key])
        files = {key: {'new_sha256': sha(change['new'][key]), 'mode': MODES[key],
                      'staged_identity': list(staged[key]),
                      'security_attributes': {name: base64.b64encode(value).decode('ascii') for name, value in labels[key].items()}}
                 for key in TARGETS}
        for key in helpers:
            files[key].update(old_sha256=sha(change['old'][key]), old_identity=list(change['identities'][key]))
        files['complete']['initial_state'] = 'absent'
        plan = {'schema': 1, 'files': files, 'history_sha256': sha(change['history'][0]),
                'history_identity': list(change['history'][1]),
                'withheld': {'path': str(evidence['path']), 'sha256': sha(evidence['raw']), 'identity': list(evidence['identity']),
                             'plan_path': str(evidence['plan_path']), 'plan_sha256': sha(evidence['plan_raw']),
                             'plan_identity': list(evidence['plan_identity'])}}
        write_new(UPDATE / 'plan.json', encoded(plan)); sync(UPDATE)
        withheld_evidence(change)
        if not all(known_withheld(key, change, staged) for key in helpers) or read(HISTORY, 0o600) != change['history']:
            raise Refused('files_changed_before_continuation')
        report['stage'] = 'verify_withheld'; no_controllers(); preconditions(b, runner, upgrade)
        for key in helpers:
            report['stage'] = 'replace_' + key
            withheld_evidence(change)
            if not all(known_withheld(name, change, staged) for name in helpers):
                raise Refused('unknown_concurrent_file_change')
            path = TARGETS[key]; temporary = path.with_name('.' + path.name + '.collector-v3.next')
            if read(temporary, MODES[key]) != (change['new'][key], staged[key]) or attrs(temporary) != labels[key]:
                raise Refused('staged_file_changed')
            os.replace(str(temporary), str(path)); sync(path.parent)
        report['stage'] = 'verify_new_set'
        new_broker = module(change['new']['broker'], TARGETS['broker'], 'new_collector_v3_broker')
        new_runner = module(change['new']['runner'], TARGETS['runner'], 'new_collector_v3_runner')
        new_policy = new_broker.policy(); preconditions(new_broker, new_runner, upgrade); no_controllers()
        withheld_evidence(change)
        if read(HISTORY, 0o600) != change['history']:
            raise Refused('unknown_concurrent_file_change')
        for key in helpers:
            if read(TARGETS[key], MODES[key]) != (change['new'][key], staged[key]) or attrs(TARGETS[key]) != labels[key]:
                raise Refused('new_set_not_coherent')
        report['stage'] = 'publish_completion'; path = TARGETS['complete']; absent(path)
        temporary = path.with_name('.' + path.name + '.collector-v3.next')
        if read(temporary, MODES['complete']) != (change['new']['complete'], staged['complete']) or attrs(temporary) != labels['complete']:
            raise Refused('staged_file_changed')
        os.replace(str(temporary), str(path)); sync(path.parent)
        new_broker.installation_complete(new_policy)
        withheld_evidence(change, missing=False)
        if (any(read(TARGETS[key], MODES[key]) != (change['new'][key], staged[key]) or attrs(TARGETS[key]) != labels[key]
                for key in TARGETS) or read(HISTORY, 0o600) != change['history']):
            raise Refused('unknown_concurrent_file_change')
        write_new(UPDATE / 'complete.json', encoded({'schema': 1, 'runner_sha256': NEW_RUNNER, 'broker_sha256': NEW_BROKER}))
        withheld_evidence(change, missing=False)
        if (any(read(TARGETS[key], MODES[key]) != (change['new'][key], staged[key]) or attrs(TARGETS[key]) != labels[key]
                for key in TARGETS) or read(HISTORY, 0o600) != change['history']):
            raise Refused('unknown_concurrent_file_change')
        report.update(ok=True, stage='complete', completion_gate='new_verified')
    except BaseException as error:
        report['reason'] = error.args[0] if type(error) is Refused else b.reason(error)
        if owned:
            try:
                withdraw_withheld(change, staged, 'complete.after_failure'); report['completion_gate'] = 'withheld'
                withheld_evidence(change)
                if not all(known_withheld(key, change, staged) for key in helpers) or read(HISTORY, 0o600) != change['history']:
                    raise Refused('rollback_refused_unknown_change')
                no_controllers(); restored = {}; change['restored'] = restored
                for key in helpers:
                    withheld_evidence(change)
                    path = TARGETS[key]
                    if not known_withheld(key, change, staged):
                        raise Refused('rollback_refused_unknown_change')
                    temporary = path.with_name('.' + path.name + '.collector-v3.restore')
                    restored[key] = write_new(temporary, change['old'][key], MODES[key], change['labels'][key])
                    if not known_withheld(key, change, staged) or read(temporary, MODES[key]) != (change['old'][key], restored[key]):
                        raise Refused('rollback_refused_unknown_change')
                    os.replace(str(temporary), str(path)); sync(path.parent)
                b.policy(); no_controllers(); withheld_evidence(change)
                if (any(read(TARGETS[key], MODES[key]) != (change['old'][key], restored[key]) or
                        attrs(TARGETS[key]) != change['labels'][key] for key in helpers) or
                        read(HISTORY, 0o600) != change['history']):
                    raise Refused('rollback_refused_unknown_change')
                report.update(rollback='old_set_verified', completion_gate='withheld')
            except BaseException as rollback_error:
                report['rollback'] = rollback_error.args[0] if type(rollback_error) is Refused else b.reason(rollback_error)
                try:
                    withdraw_withheld(change, staged, 'complete.rollback_refused'); report['completion_gate'] = 'withheld'
                except BaseException:
                    report['completion_gate'] = 'unknown'
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('action', choices=('check', 'apply'))
    parser.add_argument('--source', type=Path, required=True); parser.add_argument('--manifest-sha256', required=True)
    args = parser.parse_args(argv)
    if (os.getuid() != 0 or os.geteuid() != 0 or not sys.flags.isolated or not sys.dont_write_bytecode or
            not os.isatty(0) or not os.isatty(1) or os.environ.get('SUDO_USER') or os.environ.get('SSH_ORIGINAL_COMMAND')):
        raise Refused('isolated_root_terminal_required')
    if Path(__file__).absolute() != args.source / 'update-ops-nss-proof.py':
        raise Refused('fixed_updater_entry_required')
    fd = os.open('/dev/tty', os.O_RDONLY | os.O_NOCTTY)
    try:
        if not os.isatty(fd):
            raise Refused('controlling_root_terminal_required')
    finally:
        os.close(fd)
    os.umask(0o077); resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.environ.clear(); os.environ.update(ENV)
    manifest, data = source_inputs(args.source, args.manifest_sha256)
    broker_code = read(TARGETS['broker'], 0o755)[0]; runner_code = read(TARGETS['runner'], 0o755)[0]
    upgrade_code = read(BIN / 'collect-only-upgrade.py', 0o755)[0]
    if (sha(broker_code), sha(runner_code), sha(upgrade_code)) != (OLD_BROKER, OLD_RUNNER, UPGRADE):
        raise Refused('fixed_old_helper_set_required')
    b = module(broker_code, TARGETS['broker'], 'old_nss_broker')
    runner = module(runner_code, TARGETS['runner'], 'old_nss_runner')
    upgrade = module(upgrade_code, BIN / 'collect-only-upgrade.py', 'approved_nss_upgrade')
    with lock(runner):
        try:
            change = prepared(b, runner, upgrade, data)
        except BaseException as error:
            result = {'ok': False, 'stage': 'preconditions',
                      'reason': error.args[0] if type(error) is Refused else b.reason(error)}
        else:
            result = apply(b, runner, upgrade, manifest, change) if args.action == 'apply' else {'ok': True, 'stage': 'check', 'changed': False}
    print(json.dumps(result, sort_keys=True)); return 0 if result['ok'] else 1


if __name__ == '__main__':
    def interrupted(signum, frame):
        raise Refused('updater_interrupted')
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupted)
    try:
        sys.exit(main())
    except BaseException as error:
        if isinstance(error, SystemExit):
            raise
        print(json.dumps({'ok': False, 'stage': 'preflight', 'reason': error.args[0] if type(error) is Refused else 'preflight_failed'}))
        sys.exit(1)
