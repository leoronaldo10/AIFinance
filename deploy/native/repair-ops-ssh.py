#!/usr/bin/python3
"""One approved deploy-account SSH restriction, then the unchanged pinned ops installer.

Run only in the existing root terminal with Python -I -B. Source inputs are never
modified. No SSH key, root login, preview-account policy, port, or service restart
is changed. Preserve the private repair directory and candidates on any failure.
"""
import argparse
import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import types

INSTALLER_SHA = '97886547a24e22554c3d744eeedf16cf3ea4731f55480c4a70cc4686a65c5f07'
MANIFEST_SHA = '4c495ac008117c3068d16a3b62e17ae0bfabcf1b554a1724089c81cffd5aac4e'
SOURCE_PATTERN = r'/root/aifinance-ops-v1-[A-Za-z0-9]{12}'
CONFIG = Path('/etc/ssh/sshd_config')
CANDIDATE = CONFIG.parent / '.sshd_config.aifinance-ops-repair.next'
RESTORE = CONFIG.parent / '.sshd_config.aifinance-ops-repair.restore'
EVIDENCE = Path('/var/lib/aifinance-ops-ssh-repair')
OLD_COMMAND = 'authorizedkeyscommand /usr/bin/ecs_config_instance_connect --uid %U'
MARKER = b'# AIFINANCE fixed deploy key boundary v1'
APPEND = b'\n' + MARKER + b'\nMatch all\nMatch User aifinance-deploy\n    AuthorizedKeysCommand none\nMatch all\n'
CONTEXTS = (None, 'root', 'aifinance-preview', 'aifinance', 'aifinance-deploy')
CRYPTO_OPTIONS = frozenset(('Ciphers', 'MACs', 'GSSAPIKexAlgorithms', 'KexAlgorithms',
                            'HostKeyAlgorithms', 'PubkeyAcceptedKeyTypes', 'CASignatureAlgorithms'))
# Closed literal codes from this repair and the exact pinned installer/old runner.
# Arbitrary exception strings, even lowercase strings resembling tokens, stay private.
KNOWN_REASONS = frozenset((
    'absolute_canonical_path_required absolute_trusted_path_required accepted_upgrade_required '
    'access_metadata_command_failed access_metadata_size_limit access_metadata_timeout '
    'active_reloadable_sshd_required active_root_controller_required actual_read_only_hosts_binding_required '
    'actual_systemd_budget_or_pid_mismatch application_code_requires_collector_uid '
    'approved_collector_identity_required batch_exceeds_three both_expected_v1_controllers_required '
    'bounded_child_output_limit bounded_child_timeout bounded_regular_file_required '
    'bounded_unique_address_list_required canonical_lock_inode_changed canonical_lock_metadata_changed '
    'collect_column_defaults_not_accepted collect_command_failed_no_automatic_retry collect_migration_missing '
    'collector_must_be_idle collector_name_resolution_modified collector_network_modified '
    'collector_process_identity_or_privileges collector_supplementary_or_shared_group_refused '
    'collector_unit_already_exists collector_unit_already_running command_output_limit '
    'concurrent_sshd_config_change controlling_terminal_required created_count_does_not_match_database '
    'current_must_be_accepted_collect_release daemon_or_operator_session_changed '
    'database_only_configuration_required dedicated_network_uid_required dedicated_no_login_collector_required '
    'deploy_policy_conflict_or_extra_change disabled_db_only_network_required duplicate_cgroup_controller '
    'duplicate_json_key earlier_match_key_command_requires_review exact_feed_hosts_required '
    'exact_manifest_schema_required exact_pinned_source_entry_required exact_source_files_required '
    'exclusive_collector_group_required exclusive_collector_uid_required exclusive_deploy_uid_required '
    'existing_deploy_identity_required existing_or_partial_collector_install_requires_review '
    'existing_or_partial_install_requires_review existing_release_lock_inode_required '
    'existing_repair_requires_review existing_sshd_boundary_changed explicit_admin_view_acceptance_required '
    'file_changed_while_reading file_size_limit first_batch_acceptance_required '
    'first_operation_already_attempted_requires_review fixed_authorized_keys_location_required '
    'fixed_feed_set_required fixed_installed_root_operator_entry_required fixed_release_required '
    'fixed_source_and_manifest_pin_required fixed_source_required forbidden_downstream_count_change '
    'gateway_switch_verification_failed hourly_acceptance_required hourly_unit_must_be_absent '
    'hourly_unit_override_or_content_mismatch hourly_units_must_not_preexist_install '
    'immutable_root_owned_release_required include_requires_separate_review '
    'installed_files_changed_before_gateway_switch installed_gateway_hash_mismatch installed_helper_hash_mismatch '
    'installer_interrupted invalid_batch_counts invalid_collect_mode invalid_kernel_counter '
    'invalid_operation_flags invalid_unprivileged_mode isolated_root_terminal_required '
    'kernel_budget_not_enforced_or_hit known_replacement_bytes_changed known_replacement_verification_failed '
    'loaded_collector_safety_property_mismatch loaded_exec_command_mismatch locked_deploy_password_required '
    'manifest_hash_mismatch migration_changed_during_collection network_handle_required network_uid_changed '
    'new_reviewed_gateway_required new_reviewed_runner_required old_runner_changed_before_install '
    'only_collector_database_requisite_change_allowed operator_interrupted original_check_timestamps_required '
    'original_collector_dependency_required original_collector_install_required original_collector_unit_changed '
    'original_exact_sudo_rule_required original_failed_attempt_required original_forced_key_boundary_required '
    'original_probe_resource_evidence_required original_probe_resource_limits_required '
    'original_valid_probe_receipt_required other_database_clients_present pid_changed_during_resource_sample '
    'pid_missing_from_kernel_cgroup pinned_installer_mismatch probe_already_recorded '
    'probe_must_only_execute_trusted_sleep protected_db_only_configuration_required '
    'protected_preview_environment_required public_ipv4_only read_only_snapshot_required release_symlink_escape '
    'required_exact_count_missing reviewed_collector_source_changed reviewed_pre_seed_failure_required '
    'reviewed_source_hash_mismatch reviewed_unit_or_dropin_mismatch revision_count_does_not_match_database '
    'rollback_refused_concurrent_change rollback_refused_ops_state rollback_verification_failed '
    'root_controller_identity_changed root_owned_nonwritable_path_required root_preview_or_global_policy_changed '
    'seed_or_run_must_never_have_started source_isolation_not_accepted '
    'sshd_config_security_attributes_not_preserved staging_link_changed stop_preview_api_and_web_for_first_batch '
    'successful_no_network_probe_required successful_seed_required three_seeded_sources_required '
    'timer_enable_not_verified trusted_system_executable_required unchanged_preview_database_required '
    'unexpected_batch_summary unexpected_collect_processing_state unexpected_collector_history_requires_review '
    'unexpected_existing_deploy_key_command unexpected_existing_release_parent unexpected_identity_process_exists '
    'unexpected_material_count_delta unexpected_network_object unexpected_sshd_config_mode '
    'unexpected_sudo_directory_mode unit_failed_timed_out_or_resource_evidence_missing '
    'unreadable_process_identity unsafe_installer_file unsafe_installer_parent unsafe_root_directory '
    'unsafe_root_file unsafe_sshd_environment_policy unsupported_sshd_config_security_attributes '
    'unverified_sshd_config_invocation unverified_sshd_crypto_arguments valid_original_ed25519_key_required validated_source_constraint_required '
).split())


class Refused(ValueError):
    pass


def installer(source):
    # Bootstrap trust before importing any code from the already downloaded SOURCE.
    if not re.fullmatch(SOURCE_PATTERN, str(source)):
        raise Refused('fixed_source_required')
    path = source / 'install-ops.py'
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022:
            raise Refused('unsafe_installer_parent')
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or info.st_nlink != 1 or
                stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 262144):
            raise Refused('unsafe_installer_file')
        code = stream.read(262145)
    if hashlib.sha256(code).hexdigest() != INSTALLER_SHA:
        raise Refused('pinned_installer_mismatch')
    module = types.ModuleType('approved_original_ops_installer'); module.__file__ = str(path)
    exec(compile(code, str(path), 'exec'), module.__dict__)
    module.terminal_root(); module.load_source(source, MANIFEST_SHA)
    return module


def effective(m, path, crypto=()):
    result = {}
    for user in CONTEXTS:
        args = [m.SSHD, '-T', '-f', str(path)] + list(crypto)
        if user:
            args += ['-C', 'user=' + user + ',host=localhost,addr=127.0.0.1']
        result[user] = m.access_output(args).splitlines()
    return result


def compare(before, after):
    for user in CONTEXTS:
        if user != 'aifinance-deploy':
            if before[user] != after[user]:
                raise Refused('root_preview_or_global_policy_changed')
            continue
        if before[user].count(OLD_COMMAND) != 1:
            raise Refused('unexpected_existing_deploy_key_command')
        expected = ['authorizedkeyscommand none' if line == OLD_COMMAND else line for line in before[user]]
        if after[user] != expected:
            raise Refused('deploy_policy_conflict_or_extra_change')


def config_scope(raw):
    matched, preview_only = False, False
    for line in raw.decode('utf-8', 'strict').splitlines():
        keyword = re.match(r'^\s*([A-Za-z][A-Za-z0-9]*)(?:\s|=|$)', line)
        if not keyword:
            continue
        key = keyword.group(1).lower()
        if key == 'include':
            raise Refused('include_requires_separate_review')
        if key == 'match':
            matched = True
            words = line.split()
            preview_only = (len(words) == 3 and words[0].lower() == 'match' and
                            words[1].lower() == 'user' and words[2] == 'aifinance-preview')
        if matched and key == 'authorizedkeyscommand':
            words = line.split()
            if not (preview_only and len(words) == 2 and words[0].lower() == 'authorizedkeyscommand' and words[1] == 'none'):
                raise Refused('earlier_match_key_command_requires_review')


def daemon(m):
    rows = m.access_output([m.CTL, 'show', 'sshd.service', '-p', 'ActiveState', '-p', 'MainPID',
                            '-p', 'ExecMainStartTimestampMonotonic', '-p', 'CanReload']).splitlines()
    data = dict(row.split('=', 1) for row in rows)
    if (set(data) != {'ActiveState', 'MainPID', 'ExecMainStartTimestampMonotonic', 'CanReload'} or
            data['ActiveState'] != 'active' or data['CanReload'] != 'yes' or
            not re.fullmatch(r'[1-9][0-9]*', data['MainPID']) or int(data['MainPID']) <= 1 or
            not re.fullmatch(r'[1-9][0-9]*', data['ExecMainStartTimestampMonotonic'])):
        raise Refused('active_reloadable_sshd_required')
    raw = m.read_file(Path('/proc') / data['MainPID'] / 'cmdline', maximum=16384)
    args = [part.decode('ascii', 'strict') for part in raw.rstrip(b'\0').split(b'\0')]
    if len(args) == 1:
        title = re.fullmatch(r'(?:sshd: )?(/usr/sbin/sshd(?: [^\x00]*)?) \[listener\] [0-9]+ of [0-9]+-[0-9]+ startups', args[0])
        if title:
            args = title.group(1).split(' ')
    if not args or args.pop(0) != m.SSHD or args.count('-D') != 1:
        raise Refused('unverified_sshd_config_invocation')
    flags = list(args)
    for flag in ('-D', '-e', '-q'):
        if args.count(flag) > 1:
            raise Refused('unverified_sshd_config_invocation')
        if flag in args:
            args.remove(flag)
    crypto, names = [], set()
    for arg in list(args):
        if not arg.startswith('-o'):
            continue
        match = re.fullmatch(r'-o([A-Za-z]+)=([A-Za-z0-9_@.][A-Za-z0-9_@.-]*(?:,[A-Za-z0-9_@.][A-Za-z0-9_@.-]*)*)', arg)
        if not match or match.group(1) not in CRYPTO_OPTIONS or match.group(1) in names:
            raise Refused('unverified_sshd_crypto_arguments')
        names.add(match.group(1)); crypto.append(arg); args.remove(arg)
    if crypto and (names != CRYPTO_OPTIONS or args):
        raise Refused('unverified_sshd_crypto_arguments')
    if args not in ([], ['-f', str(CONFIG)]):
        raise Refused('unverified_sshd_config_invocation')
    data['command'] = flags; data['crypto'] = crypto
    return data


def session():
    parent = os.getppid()
    ticks = Path('/proc/%d/stat' % parent).read_text().rsplit(') ', 1)[1].split()[19]
    tty = os.fstat(0)
    return parent, ticks, os.getsid(0), tty.st_dev, tty.st_ino


def attributes(path):
    names = os.listxattr(str(path), follow_symlinks=False)
    if any(name != 'security.selinux' for name in names):
        raise Refused('unsupported_sshd_config_security_attributes')
    return {name: os.getxattr(str(path), name, follow_symlinks=False) for name in names}


def stage_file(m, path, content, mode, gid, attrs):
    m.write_new(path, content, 0o600)
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fchown(fd, 0, gid)
        for name, value in attrs.items():
            os.setxattr(fd, name, value)
        os.fchmod(fd, mode); os.fsync(fd)
    finally:
        os.close(fd)
    m.sync_directory(path.parent)
    if attributes(path) != attrs:
        raise Refused('sshd_config_security_attributes_not_preserved')


def safe_reason(error, fallback):
    text = error.args[0] if isinstance(error, ValueError) and len(error.args) == 1 and type(error.args[0]) is str else ''
    return text if text in KNOWN_REASONS and re.fullmatch(r'[a-z][a-z0-9_]{0,95}', text) else fallback


def ops_absent(m):
    for path in (m.STATE, m.BROKER, m.SUDO_NEW, m.SUDO_NEXT, m.GATEWAY_NEXT, m.RUNNER_NEXT):
        try:
            m.absent(path)
        except ValueError:
            raise Refused('rollback_refused_ops_state')


def run(m, source):
    report = {'failed': True, 'stage': 'preflight', 'reason': 'preflight_failed',
              'ssh_restricted': False, 'rollback': 'not_needed', 'ops_started': False}
    attempted, verified, saved, published_identity = False, False, None, None
    try:
        m.terminal_root(); os.umask(0o077); m.load_source(source, MANIFEST_SHA); m.deploy_account()
        for path in (EVIDENCE, CANDIDATE, RESTORE):
            m.absent(path)
        ops_absent(m)
        m.safe_directory(EVIDENCE.parent); m.safe_directory(CONFIG.parent)
        info = CONFIG.lstat(); mode, gid = stat.S_IMODE(info.st_mode), info.st_gid
        if mode not in (0o600, 0o640, 0o644):
            raise Refused('unexpected_sshd_config_mode')
        old = m.read_file(CONFIG, mode, gid=gid)
        attrs = attributes(CONFIG)
        config_scope(old)
        if MARKER in old:
            raise Refused('existing_repair_requires_review')
        new = old + APPEND
        identity, terminal = daemon(m), session()
        crypto = identity['crypto']; before = effective(m, CONFIG, crypto)
        runner = m.load_runner()
        with m.release_lock(runner):
            ops_absent(m)
            EVIDENCE.mkdir(mode=0o700); m.sync_directory(EVIDENCE.parent)
            m.write_new(EVIDENCE / 'sshd_config.before', old, 0o600)
            m.write_new(EVIDENCE / 'sshd_config.restricted', new, 0o600)
            m.write_new(EVIDENCE / 'plan.json', json.dumps({'old_sha256': m.sha(old), 'new_sha256': m.sha(new),
                        'mode': mode, 'gid': gid, 'security_attributes': {name: base64.b64encode(value).decode('ascii') for name, value in attrs.items()},
                        'installer_sha256': INSTALLER_SHA, 'manifest_sha256': MANIFEST_SHA}).encode(), 0o600)
            saved = old, new, mode, gid, before, identity, terminal, attrs
            report['stage'] = 'candidate_syntax'
            stage_file(m, CANDIDATE, new, mode, gid, attrs)
            staged = CANDIDATE.lstat(); published_identity = staged.st_dev, staged.st_ino
            m.access_output([m.SSHD, '-t', '-f', str(CANDIDATE)] + crypto)
            report['stage'] = 'candidate_policy'
            compare(before, effective(m, CANDIDATE, crypto))
            report['stage'] = 'config_switch'
            live = CONFIG.lstat()
            if (m.read_file(CONFIG, mode, gid=gid) != old or
                    (live.st_dev, live.st_ino) != (info.st_dev, info.st_ino) or attributes(CONFIG) != attrs):
                raise Refused('concurrent_sshd_config_change')
            attempted = True
            os.replace(str(CANDIDATE), str(CONFIG)); m.sync_directory(CONFIG.parent)
            report['stage'] = 'live_syntax'
            m.access_output([m.SSHD, '-t'] + crypto)
            report['stage'] = 'sshd_reload'
            m.access_output([m.CTL, 'reload', 'sshd.service'])
            report['stage'] = 'live_policy'
            if m.read_file(CONFIG, mode, gid=gid) != new or attributes(CONFIG) != attrs:
                raise Refused('concurrent_sshd_config_change')
            compare(before, effective(m, CONFIG, crypto))
            if daemon(m) != identity or session() != terminal:
                raise Refused('daemon_or_operator_session_changed')
            verified = True; report['ssh_restricted'] = True
            m.write_new(EVIDENCE / 'ssh-verified.json', b'{"deploy_only_restriction_verified":true}\n', 0o600)
        # From this point, never reopen alternate deployment keys: an ops apply
        # may have published sudo or partially installed a privileged helper.
        report['ops_started'] = True
        m.write_new(EVIDENCE / 'ops-stage.json', b'{"keep_deploy_restriction_on_failure":true}\n', 0o600)
        for action in ('check', 'apply'):
            report['stage'] = 'ops_' + action
            original_output = m.access_output
            def active_policy_output(args):
                extra = crypto if args[:2] in ([m.SSHD, '-t'], [m.SSHD, '-T']) else []
                return original_output(args + extra)
            m.access_output = active_policy_output
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    m.main([action, '--source', str(source), '--manifest-sha256', MANIFEST_SHA])
            finally:
                m.access_output = original_output
        report.update(failed=False, stage='complete', reason='verified_repair_and_ops_install')
    except BaseException as error:
        report['reason'] = safe_reason(error, report['stage'] + '_failed')
        if isinstance(error, subprocess.CalledProcessError) and type(error.returncode) is int and isinstance(error.cmd, (tuple, list)) and error.cmd and error.cmd[0] in (m.SSHD, m.CTL):
            report.update(command=Path(error.cmd[0]).name, returncode=error.returncode)
        if attempted and not report['ops_started'] and saved:
            old, new, mode, gid, before, identity, terminal, attrs = saved
            try:
                with m.release_lock(runner):
                    ops_absent(m)
                    current = m.read_file(CONFIG, mode, gid=gid)
                    live = CONFIG.lstat()
                    expected_identity = published_identity if current == new else (info.st_dev, info.st_ino)
                    if current not in (old, new) or (live.st_dev, live.st_ino) != expected_identity or attributes(CONFIG) != attrs:
                        raise Refused('rollback_refused_concurrent_change')
                    if current == new:
                        stage_file(m, RESTORE, old, mode, gid, attrs)
                        m.access_output([m.SSHD, '-t', '-f', str(RESTORE)] + crypto)
                        live = CONFIG.lstat()
                        if (m.read_file(CONFIG, mode, gid=gid) != new or attributes(CONFIG) != attrs or
                                (live.st_dev, live.st_ino) != published_identity):
                            raise Refused('rollback_refused_concurrent_change')
                        os.replace(str(RESTORE), str(CONFIG)); m.sync_directory(CONFIG.parent)
                    m.access_output([m.SSHD, '-t'] + crypto); m.access_output([m.CTL, 'reload', 'sshd.service'])
                    if effective(m, CONFIG, crypto) != before or daemon(m) != identity or session() != terminal or attributes(CONFIG) != attrs:
                        raise Refused('rollback_verification_failed')
                    report.update(rollback='restored', ssh_restricted=False)
            except BlockingIOError:
                report.update(rollback='rollback_refused_lock_busy', ssh_restricted=None)
            except BaseException as rollback_error:
                report.update(rollback=safe_reason(rollback_error, 'rollback_failed'), ssh_restricted=None)
        elif verified:
            report['ssh_restricted'] = True
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--source', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = run(installer(args.source), args.source)
    except BaseException as error:
        result = {'failed': True, 'stage': 'source_validation', 'reason': safe_reason(error, 'source_validation_failed'),
                  'ssh_restricted': False, 'rollback': 'not_needed', 'ops_started': False}
    print(json.dumps(result, sort_keys=True))
    return 1 if result['failed'] else 0


if __name__ == '__main__':
    def interrupted(signum, frame):
        raise Refused('operator_interrupted')
    for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(number, interrupted)
    sys.exit(main())
