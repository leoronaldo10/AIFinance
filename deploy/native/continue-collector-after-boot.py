#!/usr/bin/python3
"""Continue only the reviewed pre-seed v2 failure, with its completion gate absent.

All previous evidence and staging files remain untouched. A read-only check
binds the exact validated state; apply requires that digest and creates one v3
attempt. This entry never seeds, runs collection, or enables a timer.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import sys
import types

RELEASE = 'd57ba047369e666025347719caee1a4c642abe62'
BOOT_PATTERN = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
SOURCE_PATTERN = r'/root/aifinance-collector-boot-v3-[A-Za-z0-9]{12}'
OPS = Path('/var/lib/aifinance-ops')
PRIOR = OPS / 'collector-boot-v2'
EVIDENCE = OPS / 'collector-boot-v3'
BIN = Path('/opt/aifinance/bin')
COLLECT = Path('/var/lib/aifinance-maintenance/collect-only')
UPGRADE_RECORD = Path('/var/lib/aifinance-maintenance/collect-only-upgrade.json')
CONFIG = Path('/etc/aifinance-collect')
TIMER_ROOTS = (Path('/run/systemd/system'), Path('/usr/lib/systemd/system'))
BASE_SHA = 'bdb93f1eac36518e5e29ffeea00bc18cbd708a9b31395f778dce03ce9a14d020'
WEBSITE_SHA = 'a484a7b35529e8101644e1dd382cb28b20a4d4142fab0d6c30b56dcbdc949dd7'
RUNNER_SHA = 'b1485bcac62972b2f2145c2ec6ad6163eb49c0e4f3a7e0eee1abdb1bbe98da0f'
UPDATER_SHA = 'e476a475faa40ecfd5dd4fb687ad5c3c6c0db16865502c497be7dfa3196d33cd'
BROKER_SHA = '646b2bf304dfb0534f330b386251bd46597201a72ed8ff8bb8882137ec659194'
FILES = {'continue-collector-after-boot.py', 'recover-collector-after-boot.py',
         'update-ops-nss-proof.py', 'recover-preview-after-boot.py',
         'collect-only-runner.py', 'ops-broker.py'}
ENV = dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin', HOME='/', LANG='C', LC_ALL='C', TZ='UTC')
PROOF = dict(database_ok=True, role_ok=True, role_safe=True, migration_ok=True,
             other_clients=0, sources=0, articles=0, discoveries=0, fetch_runs=0)
HELPER_FILES = {'manifest.json', 'plan.json', 'runner.before', 'broker.before',
                'policy.before', 'complete.before', 'complete.withheld'}
UNIT_FIELDS = ('ActiveState', 'SubState', 'Result', 'MainPID', 'ControlPID', 'ExecMainCode',
               'ExecMainStatus', 'ExecMainStartTimestampMonotonic', 'ExecMainExitTimestampMonotonic')


SAFE_REASON_CODES = frozenset("""collector_timer_file_present collector_unit_metadata_changed prior_helper_security_attributes_changed historical_downstream_counts_changed absent_completion_transaction_required acceptance_payload_digest_mismatch accepted_restore_required
actual_read_only_hosts_binding_required application_or_collector_process_present
apply_requires_checked_snapshot_digest archive_verification_failed boot_id_mismatch canonical_lock_changed
canonical_lock_owner_or_mode_mismatch canonical_lock_replaced canonical_manifest_required
checked_snapshot_digest_mismatch collection_start_evidence_present
collector_activation_or_environment_changed collector_database_file_identity_changed
collector_history_set_changed collector_history_size_changed collector_install_receipt_mismatch
collector_login_identity_changed collector_network_changed_before_restore collector_network_receipt_mismatch
collector_not_exact_reviewed_postboot_state collector_not_idle_after_boot
collector_table_must_be_absent_after_boot collector_timer_not_absent command_exit_nonzero
command_output_limit command_timeout completion_gate_missing_before_withdrawal
continuation_attempted_gate_stays_closed continuation_interrupted controller_payload_digest_mismatch
controller_source_changed controlling_root_terminal_required credential_file_metadata_mismatch
current_boot_website_completion_required current_probe_alias_changed current_probe_changed
current_receipt_changed_during_check current_release_mismatch database_auto_conf_startup_hook_refused
database_fd_unavailable database_fixed_configuration_mismatch database_free_space_below_one_gib
database_identity_changed_cleanup_refused database_path_identity_changed
database_read_only_role_or_ledger_identity_mismatch directory_owner_or_mode_mismatch
downstream_counts_changed duplicate_json_key duplicate_manifest_key duplicate_withheld_plan_key
effective_after_dependency_mismatch effective_binds_to_mismatch effective_command_mismatch
effective_resource_or_restart_mismatch effective_unit_identity_mismatch evidence_identity_changed
exact_downstream_counts_required exact_failed_v2_evidence_required exact_failed_v2_receipts_required
exact_failed_v2_unit_state_required exact_failed_v2_unit_timestamps_required
exact_reviewed_v2_failure_required exact_source_payloads_required exact_two_source_payloads_required
exact_update_inputs_required exact_withheld_evidence_required existing_database_migration_ledger_mismatch
existing_database_readiness_timeout existing_database_start_failed existing_pgdata_owner_mode_mismatch
existing_pgdata_version_mismatch existing_production_build_missing existing_update_or_stage
explicit_reviewed_boot_id_required failed_check_output_not_empty file_changed_during_read
file_changed_or_oversize file_owner_mode_or_size_mismatch files_changed_before_continuation
files_changed_before_gate_withdrawal filesystem_or_process_error fixed_collector_identity_required
fixed_command_failed fixed_controller_entry_required fixed_manifest_required fixed_old_helper_set_required
fixed_predecessor_pins_required fixed_source_and_manifest_pin_required
fixed_source_and_payload_digest_required fixed_update_manifest_required fixed_updater_entry_required
fresh_probe_receipt_changed guard_evidence_file_limit guard_evidence_total_limit historical_attempt_changed
historical_collection_start_present historical_downstream_counts_changed historical_network_not_db_only
historical_probe_receipt_mismatch historical_probe_resource_mismatch historical_probe_sample_mismatch
historical_receipt_changed historical_receipt_changed_before_archive historical_seed_attempt_mismatch
immutable_or_shared_schema_mismatch incomplete_unit_metadata installed_helper_digest_mismatch
installed_unit_digest_mismatch invalid_aifinance_unit_list invalid_nft_table_entry invalid_nft_table_list
invalid_unit_metadata isolated_root_entry_required isolated_root_terminal_required
job_relation_presence_unverified json_object_required maintenance_or_preview_database_process_present
manifest_digest_mismatch memory_reserve_below_700_mib new_set_not_coherent old_helper_or_policy_set_changed
old_helper_set_changed old_policy_bytes_changed old_policy_or_completion_bytes_changed
omitted_unit_array_not_verified_empty only_broker_runner_pin_change_allowed operation_refused
original_attempt_baseline_changed original_attempt_changed_before_rearm original_check_baseline_changed
original_database_file_changed original_database_identity_changed original_database_metadata_changed
original_gate_withdrawal_unverified original_install_history_changed original_probe_changed
original_v2_completion_stage_changed original_withheld_gate_changed pending_aifinance_job
persistent_ops_install_baseline_mismatch persistent_ops_policy_or_completion_mismatch
persistent_state_changed persistent_upgrade_acceptance_missing pgdata_parent_mismatch
port_8000_must_remain_absent postgresql_17_11_required preflight_failed preseed_check_not_empty
preseed_proof_changed preview_listener_already_present preview_listener_not_exact_ipv4_loopback
preview_unit_not_exact_postboot_state prior_archive_baseline_changed prior_archive_inventory_changed
prior_archive_oversize prior_archive_website_chain_changed prior_database_proof_changed
prior_helper_manifest_changed prior_install_history_changed prior_manifest_changed
prior_manifest_schema_changed prior_probe_check_order_changed prior_security_attributes_changed
prior_transaction_file_changed prior_transaction_plan_changed process_command_limit
process_command_unverifiable process_identity_unverifiable process_metadata_limit
protected_collector_resolver_changed real_guard_acceptance_not_passed receipt_changed_before_archive
recovery_attempted_gate_stays_closed recovery_callback_must_run_once recovery_interrupted
release_label_mismatch release_not_immutable release_not_root_owned release_parent_mismatch
release_symlink_escape reviewed_active_root_mount_required reviewed_boot_changed
rollback_refused_unknown_change root_controller_in_flight same_database_inode_required
security_attributes_not_preserved service_identity_mismatch source_payload_digest_mismatch
staged_file_changed unexpected_activation_or_environment_dependency unexpected_evidence_inventory
unexpected_loaded_service_hook unexpected_preview_or_collector_nft_table unexpected_website_hook
unit_changed_before_start unit_templates_must_not_change unknown_completion_gate
unknown_concurrent_file_change unknown_transaction_helper_set unreviewed_aifinance_service_active
unsafe_directory unsafe_file unsafe_path unsupported_security_attributes untrusted_directory_ancestor
update_manifest_hash_mismatch update_payload_hash_mismatch updater_interrupted validated_snapshot_changed
website_activation_or_environment_changed website_completion_changed website_evidence_listener_boundary
website_evidence_not_healthy website_helper_changed website_listener_boundary_changed
website_preserved_collector_history_changed website_preserved_database_metadata_changed
website_preserved_install_history_changed website_provenance_changed website_resource_boundary_changed
website_restore_unit_busy website_unit_changed website_unit_identity_changed website_unit_pid_changed
website_unit_state_changed website_writer_listener_remains withheld_evidence_changed withheld_plan_mismatch""".split())
SAFE_STAGE_CODES = frozenset(('current_website_helpers', 'archive', 'archive_then_rearm', 'check', 'complete', 'current_boot_and_gate', 'current_collector_receipts', 'current_collector_units', 'current_database_metadata', 'current_website_health', 'db_only_network', 'entry', 'fresh_no_network_probe', 'fresh_read_only_nss_check', 'preflight', 'prior_v2_archive', 'prior_v2_inventory', 'prior_v2_sql_and_probe', 'prior_v2_transaction', 'read_only_sql', 'ready', 'restore_same_database_permission', 'website_pause', 'website_restore'))
SAFE_ERROR_TYPES = frozenset(('OSError', 'FileNotFoundError', 'PermissionError', 'ProcessLookupError', 'BlockingIOError', 'IsADirectoryError', 'NotADirectoryError', 'UnicodeDecodeError', 'ValueError', 'TypeError', 'KeyError', 'SystemExit', 'InterruptedError', 'TimeoutError'))


class Refused(ValueError):
    pass


def require(value, reason):
    if not value:
        raise Refused(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(rows):
    result = {}
    for key, value in rows:
        require(key not in result, 'duplicate_json_key'); result[key] = value
    return result


def document(raw):
    value = json.loads(raw.decode('ascii'), object_pairs_hook=unique)
    require(isinstance(value, dict), 'json_object_required')
    return value


def trusted_dir(path, mode=None):
    require(path.is_absolute() and '..' not in path.parts, 'unsafe_path')
    for item in (path,) + tuple(path.parents):
        info = item.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and
                not info.st_mode & 0o022 and (item != path or mode is None or stat.S_IMODE(info.st_mode) == mode),
                'unsafe_directory')


def read(path, mode=0o600, maximum=1048576):
    trusted_dir(path.parent)
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno()); selected = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_nlink == 1 and
                stat.S_IMODE(info.st_mode) == mode and info.st_size <= maximum and
                (info.st_dev, info.st_ino) == (selected.st_dev, selected.st_ino), 'unsafe_file')
        raw = stream.read(maximum + 1)
        require(len(raw) == info.st_size, 'file_changed_or_oversize')
        return raw


def module(raw, path, name):
    value = types.ModuleType(name); value.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), value.__dict__)
    return value


def source_inputs(source, expected, boot_id):
    require(re.fullmatch(SOURCE_PATTERN, str(source)) and re.fullmatch('[0-9a-f]{64}', expected),
            'fixed_source_and_manifest_pin_required')
    trusted_dir(source, 0o700)
    require({p.name for p in source.iterdir()} == FILES | {'manifest.json'}, 'exact_source_payloads_required')
    raw = read(source / 'manifest.json', maximum=8192)
    require(sha(raw) == expected, 'manifest_digest_mismatch')
    manifest = document(raw)
    require(raw == (json.dumps(manifest, sort_keys=True) + '\n').encode('ascii'), 'canonical_manifest_required')
    require(set(manifest) == {'schema', 'boot_id', 'release', 'payloads', 'predecessor'} and
            type(manifest['schema']) is int and manifest['schema'] == 3 and manifest['boot_id'] == boot_id and
            manifest['release'] == RELEASE and isinstance(manifest['payloads'], dict) and
            set(manifest['payloads']) == FILES, 'fixed_manifest_required')
    prior = manifest['predecessor']
    require(isinstance(prior, dict) and set(prior) == {'manifest_sha256', 'failure_sha256', 'website_sha256'} and
            all(isinstance(v, str) and re.fullmatch('[0-9a-f]{64}', v) for v in prior.values()),
            'fixed_predecessor_pins_required')
    pins = {'recover-collector-after-boot.py': BASE_SHA, 'recover-preview-after-boot.py': WEBSITE_SHA,
            'update-ops-nss-proof.py': UPDATER_SHA, 'collect-only-runner.py': RUNNER_SHA, 'ops-broker.py': BROKER_SHA}
    data = {}
    for name in sorted(FILES):
        data[name] = read(source / name, maximum=262144); digest = sha(data[name])
        require(digest == manifest['payloads'][name] and (name not in pins or digest == pins[name]),
                'source_payload_digest_mismatch')
        compile(data[name], name, 'exec')
    return manifest, data


def make_recovery(base):
    class Continuation(base.Recovery):
        def __init__(self, updater, website, broker, runner, upgrade, manifest, data):
            super(Continuation, self).__init__(updater, website, broker, runner, upgrade)
            self.manifest = manifest; self.data = data
            self.manifest_sha = sha(self.u.encoded(manifest)); self.snapshot = None
            self.validator = module(data['ops-broker.py'], BIN / 'ops-broker.py', 'continuation_receipt_validator')
            self.u.UPDATE = EVIDENCE / 'helper-update'
            self.u.NEW_RUNNER = RUNNER_SHA; self.u.NEW_BROKER = BROKER_SHA

        def record(self, path, mode=0o600):
            raw, identity = self.u.read(path, mode)
            info = path.lstat()
            require(identity == (info.st_dev, info.st_ino), 'evidence_identity_changed')
            return dict(self.w.attributes(info), sha256=sha(raw), security_attributes={
                name: base64.b64encode(value).decode('ascii') for name, value in self.u.attrs(path).items()})

        def inventory(self, directory, names):
            trusted_dir(directory, 0o700)
            require({p.name for p in directory.iterdir()} == set(names), 'unexpected_evidence_inventory')
            return {name: self.record(directory / name) for name in sorted(names)}

        def prior_evidence(self, user, baseline, website):
            self.stage = 'prior_v2_inventory'
            trusted_dir(PRIOR, 0o700)
            require({p.name for p in PRIOR.iterdir()} ==
                    {'manifest.json', 'failure.json', 'sql-before.json', 'fresh-probe.json', 'archive', 'helper-update'},
                    'exact_failed_v2_evidence_required')
            pins = self.manifest['predecessor']; prior_manifest = read(PRIOR / 'manifest.json')
            require(sha(prior_manifest) == pins['manifest_sha256'], 'prior_manifest_changed')
            expected = dict(schema=2, boot_id=base.BOOT, release=RELEASE, payloads={
                'recover-collector-after-boot.py': BASE_SHA, 'update-ops-nss-proof.py': base.UPDATER_SHA,
                'recover-preview-after-boot.py': WEBSITE_SHA, 'collect-only-runner.py': base.RUNNER_SHA_V2,
                'ops-broker.py': base.BROKER_SHA_V2})
            require(document(prior_manifest) == expected, 'prior_manifest_schema_changed')
            failure = read(PRIOR / 'failure.json')
            require(sha(failure) == pins['failure_sha256'] and document(failure) == dict(
                stage='fresh_read_only_nss_check', automatic_retry=False, cleanup=dict(collector_stopped=True,
                database_read_revoked=True, collector_https_revoked=True, website_restored=False)),
                'exact_reviewed_v2_failure_required')
            self.stage = 'prior_v2_archive'
            archive = PRIOR / 'archive'; trusted_dir(archive, 0o700)
            names = {p.name for p in archive.iterdir()}
            required = {'installed.json', 'probe.json', 'seed-attempt.json', 'network.json', 'output.json'}
            require(required.issubset(names) and len(names) <= 128 and all(
                    name in required or re.fullmatch(r'probe-[0-9]+-[0-9a-f]{12}\.json', name) for name in names),
                    'prior_archive_inventory_changed')
            records = {name: read(archive / name) for name in names}
            require(sum(len(raw) for raw in records.values()) <= 8 * 1024 ** 2, 'prior_archive_oversize')
            for name, raw in records.items():
                require(website['preserved_after'].get(str(COLLECT / name), {}).get('sha256') == sha(raw),
                        'prior_archive_website_chain_changed')
            require(document(records['seed-attempt.json']) == dict(release=RELEASE, mode='seed', started=baseline['attempt_started']) and
                    sha(records['seed-attempt.json']) == baseline['attempt_sha256'] and
                    document(records['installed.json']) == dict(release=RELEASE, uid=user.pw_uid) and
                    document(records['network.json']) == dict(uid=user.pw_uid, hosts={}), 'prior_archive_baseline_changed')
            self.validator.boot_report(document(records['probe.json']), 'probe', user, self.r)
            self.stage = 'prior_v2_sql_and_probe'
            sql = document(read(PRIOR / 'sql-before.json'))
            require(set(sql) == {'proof', 'counts'} and sql['proof'] == PROOF and
                    all(type(sql['proof'][k]) is type(v) for k, v in PROOF.items()) and
                    set(sql['counts']) == set(base.COUNTS), 'prior_database_proof_changed')
            self.validator.boot_counts(sql['counts']); self.prior_counts = sql['counts']
            fresh = self.validator.boot_report(document(read(PRIOR / 'fresh-probe.json')), 'probe', user, self.r)
            self.stage = 'prior_v2_transaction'
            helper = PRIOR / 'helper-update'; helper_records = self.inventory(helper, HELPER_FILES)
            require(document(read(helper / 'manifest.json')) == expected, 'prior_helper_manifest_changed')
            policy = self.b.policy()
            complete = dict(schema=1, status='complete', broker_sha256=self.u.OLD_BROKER, app_release=RELEASE)
            old = {'runner': self.u.OLD_RUNNER, 'broker': self.u.OLD_BROKER,
                   'policy': sha(self.u.encoded(policy)), 'complete': sha(self.u.encoded(complete))}
            new = {'runner': base.RUNNER_SHA_V2, 'broker': base.BROKER_SHA_V2,
                   'policy': sha(self.u.encoded(dict(policy, runner_sha256=base.RUNNER_SHA_V2, broker_sha256=base.BROKER_SHA_V2))),
                   'complete': sha(self.u.encoded(dict(complete, broker_sha256=base.BROKER_SHA_V2)))}
            plan_raw, plan_identity = self.u.read(helper / 'plan.json', 0o600)
            plan = document(plan_raw)
            require(set(plan) == {'schema', 'files', 'history_sha256', 'history_identity'} and
                    type(plan['schema']) is int and plan['schema'] == 1 and isinstance(plan['files'], dict) and
                    set(plan['files']) == set(old), 'prior_transaction_plan_changed')
            history_raw, history_id = self.u.read(self.u.HISTORY, 0o600)
            require(plan['history_sha256'] == sha(history_raw) and plan['history_identity'] == list(history_id),
                    'prior_install_history_changed')
            for key in old:
                row = plan['files'][key]
                require(isinstance(row, dict) and set(row) == {'old_sha256', 'new_sha256', 'mode', 'old_identity',
                        'staged_identity', 'security_attributes'} and row['old_sha256'] == old[key] and
                        row['new_sha256'] == new[key] and type(row['mode']) is int and row['mode'] == self.u.MODES[key] and
                        all(isinstance(row[n], list) and len(row[n]) == 2 and all(type(v) is int and v > 0 for v in row[n])
                            for n in ('old_identity', 'staged_identity')) and isinstance(row['security_attributes'], dict) and
                        set(row['security_attributes']).issubset({'security.selinux'}) and
                        sha(read(helper / (key + '.before'))) == old[key], 'prior_transaction_file_changed')
                if key != 'complete':
                    require({n: base64.b64encode(v).decode('ascii') for n, v in self.u.attrs(self.u.TARGETS[key]).items()} ==
                            row['security_attributes'], 'prior_helper_security_attributes_changed')
                for value in row['security_attributes'].values():
                    require(isinstance(value, str) and base64.b64encode(base64.b64decode(value, validate=True)).decode('ascii') == value,
                            'prior_security_attributes_changed')
            withheld_raw, withheld_id = self.u.read(helper / 'complete.withheld', 0o600)
            labels = self.u.attrs(helper / 'complete.withheld')
            require(sha(withheld_raw) == old['complete'] and list(withheld_id) == plan['files']['complete']['old_identity'] and
                    {n: base64.b64encode(v).decode('ascii') for n, v in labels.items()} == plan['files']['complete']['security_attributes'],
                    'original_withheld_gate_changed')
            stage = OPS / '.complete.json.nss-v1.next'; stage_raw, stage_id = self.u.read(stage, 0o600)
            require(sha(stage_raw) == new['complete'] and list(stage_id) == plan['files']['complete']['staged_identity'] and
                    self.u.attrs(stage) == labels, 'original_v2_completion_stage_changed')
            self.withheld = dict(path=helper / 'complete.withheld', plan_path=helper / 'plan.json', plan_raw=plan_raw,
                                plan_identity=plan_identity, raw=withheld_raw, identity=withheld_id, labels=labels)
            inventory = {name: self.record(PRIOR / name) for name in ('manifest.json', 'failure.json', 'sql-before.json', 'fresh-probe.json')}
            inventory.update({'archive/' + name: self.record(archive / name) for name in names})
            inventory.update({'helper-update/' + name: row for name, row in helper_records.items()})
            return records, fresh, inventory

        def website_helpers(self):
            verified = {}
            for name, digest in self.w.HELPER_PINS.items():
                if name not in ('collect-only-runner.py', 'ops-broker.py'):
                    raw = self.w.read(BIN / name, maximum=262144)
                    require(sha(raw) == digest, 'website_helper_changed')
                    verified[name] = raw
            return verified

        def website_gate(self, healthy=True):
            self.website_helpers()
            return super(Continuation, self).website_gate(healthy)

        def collector_quiet(self, states):
            # The failed check is intentionally retained. The website helper's
            # postboot inactive-only rule cannot validate this continuation.
            for alias in ('probe', 'check', 'seed', 'run'):
                value = states[alias]
                expected_state = 'failed' if alias == 'check' else 'inactive'
                expected_substate = 'failed' if alias == 'check' else 'dead'
                require(value.get('LoadState') == 'loaded' and value.get('ActiveState') == expected_state and
                        value.get('SubState') == expected_substate and value.get('MainPID') == value.get('ControlPID') == '0' and
                        value.get('UnitFileState') in ('static', 'disabled'), 'collector_unit_metadata_changed')
            for name in ('aifinance-collect-hourly.service', 'aifinance-collect-hourly.timer'):
                keys = ('LoadState', 'ActiveState', 'SubState', 'FragmentPath', 'DropInPaths')
                value = self.w.properties(name, keys)
                require(value == dict(LoadState='not-found', ActiveState='inactive', SubState='dead',
                                      FragmentPath='', DropInPaths=''), 'collector_timer_not_absent')
                for root in (self.w.SYSTEM,) + TIMER_ROOTS:
                    for path in (root / name, root / (name + '.d'), root / 'timers.target.wants' / name):
                        self.w.absent(path, 'collector_timer_file_present')
            rows = self.w.command([self.w.CTL, 'list-units', '--all', '--plain', '--no-legend', '--no-pager', 'aifinance*'])
            for line in rows.splitlines():
                fields = line.split()
                require(len(fields) >= 4, 'invalid_aifinance_unit_list')
                require(fields[0] in self.w.UNITS or fields[2] not in ('active', 'activating', 'reloading', 'deactivating'),
                        'unreviewed_aifinance_service_active')

        def original_state(self, broker, runner):
            require(not self.started, 'continuation_attempted_gate_stays_closed')
            self.stage = 'current_boot_and_gate'
            base.boot(); self.u.no_controllers(); self.u.absent(self.u.TARGETS['complete'])
            self.stage = 'current_website_helpers'
            helpers = self.website_helpers()
            self.stage = 'current_collector_units'
            runner.upgrade_gate(); runner.validate_release(); runner.verify_units(); self.collector_units(runner)
            worker = broker.Broker(runner, self.upgrade); user = worker.identity()
            require(user.pw_uid == user.pw_gid == 986, 'fixed_collector_identity_required')
            gate = broker.document(UPGRADE_RECORD)
            require(gate.get('restore_verified') is True, 'accepted_restore_required')
            states = broker.unit_states(); worker.idle(user, states); worker.no_timer(states); worker.db_only_network(user)
            self.collector_quiet(states)
            unit_snapshot = {}
            for alias in ('probe', 'check', 'seed', 'run'):
                row = states[alias]; expected = dict(MainPID='0', ControlPID='0')
                if alias == 'check':
                    expected.update(ActiveState='failed', SubState='failed', Result='signal', ExecMainCode='2', ExecMainStatus='15')
                else:
                    expected.update(ActiveState='inactive', SubState='dead', Result='success', ExecMainCode='0', ExecMainStatus='0')
                require(all(row.get(k) == v for k, v in expected.items()), 'exact_failed_v2_unit_state_required')
                start = row.get('ExecMainStartTimestampMonotonic'); end = row.get('ExecMainExitTimestampMonotonic')
                require(isinstance(start, str) and isinstance(end, str) and start.isdigit() and end.isdigit() and
                        (0 < int(start) <= int(end) if alias == 'check' else start == end == '0'),
                        'exact_failed_v2_unit_timestamps_required')
                unit_snapshot[alias] = {k: row[k] for k in UNIT_FIELDS}
            for name in ('recovery.json', 'pre-seed-attempt-v1.json', 'recovery.json.next', 'nss-proof-v1-update'):
                self.u.absent(OPS / name)
            for key, path in self.u.TARGETS.items():
                if key != 'complete': self.u.absent(path.with_name('.' + path.name + '.nss-v1.next'))
                self.u.absent(path.with_name('.' + path.name + '.nss-v1.restore'))
            for name, expected in (('hosts', b''), ('nsswitch.conf', b'hosts: files\n')):
                require(self.w.read(CONFIG / name, maximum=8192, mode=0o440, uid=0, gid=986) == expected,
                        'protected_collector_resolver_changed')
            baseline = worker.recovery_baseline()
            evidence, website = self.website_evidence()
            require(evidence['sha256'] == self.manifest['predecessor']['website_sha256'], 'website_completion_changed')
            records, fresh, prior = self.prior_evidence(user, baseline, website)
            self.stage = 'current_collector_receipts'
            names = {p.name for p in COLLECT.iterdir()}
            extra = names - set(records)
            require(set(records).issubset(names) and len(extra) == 1 and all(
                    re.fullmatch(r'probe-[0-9]+-[0-9a-f]{12}\.json', n) for n in extra), 'exact_failed_v2_receipts_required')
            current = self.inventory(COLLECT, names); current_records = {n: read(COLLECT / n) for n in names}
            require(all(sha(raw) == current[name]['sha256'] for name, raw in current_records.items()), 'current_receipt_changed_during_check')
            for name, raw in records.items():
                if name == 'probe.json':
                    require(document(current_records[name]) == fresh, 'current_probe_alias_changed')
                elif name == 'output.json':
                    require(current_records[name] == b'', 'failed_check_output_not_empty')
                else:
                    require(current_records[name] == raw, 'historical_receipt_changed')
            require(document(current_records[next(iter(extra))]) == fresh, 'fresh_probe_receipt_changed')
            worker.probe_receipt(user)
            for alias in ('seed', 'run'):
                require(not worker.journal_metadata(alias, baseline['attempt_started']), 'collection_start_evidence_present')
            self.stage = 'current_database_metadata'
            fd, info = worker.environment_fd(disabled=True)
            try:
                require((info.st_dev, info.st_ino, user.pw_gid) == (baseline['db_device'], baseline['db_inode'], baseline['collector_gid']),
                        'original_database_identity_changed')
            finally:
                os.close(fd)
            metadata = self.w.metadata(CONFIG / 'database.env', 0, 0, 0o400, 8192)
            previous = website['preserved_after'].get(str(CONFIG / 'database.env'), {})
            require(set(previous) == set(metadata) and all(previous[k] == v for k, v in metadata.items() if k != 'ctime_ns') and
                    metadata['ctime_ns'] >= previous['ctime_ns'], 'original_database_metadata_changed')
            for path in (OPS / 'install.json', UPGRADE_RECORD):
                raw = read(path)
                require(website['preserved_after'].get(str(path)) == dict(self.w.attributes(path.lstat()), sha256=sha(raw)),
                        'original_install_history_changed')
            self.stage = 'current_website_health'
            self.fp = module(helpers['first-preview.py'], BIN / 'first-preview.py', 'verified_continuation_website')
            self.website_gate()
            snapshot = dict(schema=3, boot_id=base.BOOT, release=RELEASE, manifest_sha256=self.manifest_sha,
                prior=prior, current=current, database=metadata, units=unit_snapshot,
                helpers={k: self.record(self.u.TARGETS[k], self.u.MODES[k]) for k in ('runner', 'broker', 'policy')},
                history=self.record(self.u.HISTORY), legacy_stage=self.record(OPS / '.complete.json.nss-v1.next'),
                website={name: self.record(base.WEBSITE / name) for name in ('01-evidence_create.json', '05-complete.json')})
            if self.snapshot is not None:
                require(snapshot == self.snapshot, 'validated_snapshot_changed')
            self.snapshot = snapshot; self.current_records = current_records
            return user, baseline, records, evidence

        def preflight(self):
            self.u.absent(EVIDENCE); trusted_dir(OPS, 0o700)
            self.user, self.baseline, self.records, self.web_receipt = self.original_state(self.b, self.r)

        def prepared(self, data):
            self.u.absent(self.u.UPDATE)
            old, identities, labels = {}, {}, {}
            for key, path in self.u.TARGETS.items():
                self.u.absent(path.with_name('.' + path.name + '.collector-v3.next'))
                self.u.absent(path.with_name('.' + path.name + '.collector-v3.restore'))
                if key != 'complete':
                    old[key], identities[key] = self.u.read(path, self.u.MODES[key]); labels[key] = self.u.attrs(path)
            require(sha(old['runner']) == self.u.OLD_RUNNER and sha(old['broker']) == self.u.OLD_BROKER,
                    'old_helper_set_changed')
            self.u.absent(self.u.TARGETS['complete']); policy = self.b.policy()
            require(old['policy'] == self.u.encoded(policy), 'old_policy_bytes_changed')
            new = dict(runner=data['collect-only-runner.py'], broker=data['ops-broker.py'],
                policy=self.u.encoded(dict(policy, runner_sha256=RUNNER_SHA, broker_sha256=BROKER_SHA)),
                complete=self.u.encoded(dict(schema=1, status='complete', broker_sha256=BROKER_SHA, app_release=RELEASE)))
            replacement = module(new['runner'], self.u.TARGETS['runner'], 'continuation_template_runner')
            require(all(self.r.unit_text(mode) == replacement.unit_text(mode) for mode in ('probe', 'check', 'seed', 'run')) and
                    self.r.hourly_text() == replacement.hourly_text(), 'unit_templates_must_not_change')
            return dict(old=old, new=new, identities=identities, labels=labels,
                        history=self.u.read(self.u.HISTORY, 0o600), withheld=self.withheld)

        def archive(self):
            for name, values in (('archive', self.records), ('attempt-before', self.current_records)):
                destination = EVIDENCE / name; destination.mkdir(mode=0o700); self.u.sync(EVIDENCE)
                for filename, raw in sorted(values.items()):
                    source = PRIOR / 'archive' / filename if name == 'archive' else COLLECT / filename
                    require(read(source) == raw, 'receipt_changed_before_archive')
                    self.u.write_new(destination / filename, raw)
                    require(read(destination / filename) == raw, 'archive_verification_failed')
                self.u.sync(destination)

        def restore_network(self):
            # The reviewed failure already left exactly DB-only egress in place.
            self.worker.db_only_network(self.user)

        def restore_website(self):
            require(self.website_evidence()[0] == self.web_receipt, 'website_provenance_changed')
            self.website_gate(healthy=None)
            self.w.command([self.w.CTL, 'start', self.w.API, self.w.WEB], timeout=45)
            self.fp.health(RELEASE)
            self.website_gate()

        def cleanup(self):
            # Keep cleanup independent and report only fixed safe reason fields.
            result = {}
            actions = [
                ('collector_stopped', lambda: (self.r.command([self.r.CTL, 'stop', self.r.unit_name('probe'), self.r.unit_name('check')], timeout=15), self.r.no_processes(self.user.pw_uid))),
                ('database_read_revoked', self.revoke_database),
                ('collector_https_revoked', lambda: self.worker.db_only_network(self.user)),
                ('website_restored', self.restore_website if self.app_stop_attempted else lambda: None)]
            for label, action in actions:
                try:
                    action(); result[label] = True
                except BaseException as error:
                    result[label] = False; result[label + '_reason'] = safe_error(error, base, self)
            self.cleanup_result = result
            return result

        def revoke_database(self):
            require(self.db_fd is not None, 'database_fd_unavailable')
            info = os.fstat(self.db_fd); selected = (CONFIG / 'database.env').lstat()
            require((info.st_dev, info.st_ino) == (self.db_info.st_dev, self.db_info.st_ino) == (selected.st_dev, selected.st_ino),
                    'database_identity_changed_cleanup_refused')
            os.fchown(self.db_fd, 0, 0); os.fchmod(self.db_fd, 0o400); os.fsync(self.db_fd); self.same_database(True)

        def recover(self, broker, runner):
            self.started = True; self.b = broker; self.r = runner; self.worker = broker.Broker(runner, self.upgrade)
            try:
                self.db_fd, self.db_info = self.worker.environment_fd(disabled=True)
                self.stage = 'archive'; self.archive()
                self.stage = 'db_only_network'; self.restore_network()
                self.stage = 'website_pause'; self.website_gate(); self.app_stop_attempted = True
                self.w.command([self.w.CTL, 'stop', self.w.API, self.w.WEB], timeout=45)
                self.website_gate(healthy=False)
                runner.no_processes(runner.pwd.getpwnam('aifinance').pw_uid); runner.no_processes(self.user.pw_uid)
                self.stage = 'read_only_sql'; proof = self.worker.sql_proof(self.db_fd, self.user); before = self.counts()
                require(before == self.prior_counts, 'historical_downstream_counts_changed')
                self.u.write_new(EVIDENCE / 'sql-before.json', self.u.encoded(dict(proof=proof, counts=before)))
                self.stage = 'restore_same_database_permission'; self.same_database(True)
                os.fchown(self.db_fd, 0, self.user.pw_gid); os.fchmod(self.db_fd, 0o440); os.fsync(self.db_fd)
                self.same_database(False); runner.db_environment()
                self.stage = 'fresh_no_network_probe'; probe = runner.run_unit('probe', self.user)
                self.u.write_new(EVIDENCE / 'fresh-probe.json', self.u.encoded(probe))
                require(read(COLLECT / 'probe.json') == self.current_records['probe.json'], 'current_probe_changed')
                runner.replace_owned(COLLECT / 'probe.json', json.dumps(probe, sort_keys=True)); self.worker.probe_receipt(self.user)
                self.stage = 'fresh_read_only_nss_check'; check = runner.run_unit('check', self.user)
                runner.validate_snapshot(check['output']['result'], seeded=False)
                require(check['output']['result']['sources'] == [] and check['output']['result']['rawStates'] == [], 'preseed_check_not_empty')
                self.u.write_new(EVIDENCE / 'fresh-check.json', self.u.encoded(check)); runner.no_processes(self.user.pw_uid)
                require(self.worker.sql_proof(self.db_fd, self.user) == proof, 'preseed_proof_changed'); after = self.counts()
                require(before == after == check['output']['result']['counts'], 'downstream_counts_changed')
                self.u.write_new(EVIDENCE / 'sql-after.json', self.u.encoded(dict(proof=proof, counts=after)))
                self.stage = 'website_restore'; self.restore_website()
                self.worker.no_timer(broker.unit_states()); self.worker.db_only_network(self.user); self.same_database(False)
                self.stage = 'archive_then_rearm'; attempt = COLLECT / 'seed-attempt.json'
                require(read(attempt) == self.records['seed-attempt.json'] == read(EVIDENCE / 'archive/seed-attempt.json') ==
                        read(EVIDENCE / 'attempt-before/seed-attempt.json'), 'original_attempt_changed_before_rearm')
                attempt.unlink(); self.u.sync(COLLECT)
                continuation = dict(manifest_sha256=self.manifest_sha, snapshot_sha256=sha(self.u.encoded(self.snapshot)),
                    prior_evidence_sha256={n: v['sha256'] for n, v in self.snapshot['prior'].items()},
                    attempt_before_sha256={n: sha(raw) for n, raw in self.current_records.items()})
                index = dict(schema=3, status='ready', boot_id=base.BOOT, release=RELEASE, runner_sha256=RUNNER_SHA,
                    broker_sha256=BROKER_SHA, baseline=self.baseline, db_file_device=self.db_info.st_dev,
                    db_file_inode=self.db_info.st_ino, collector_gid=self.user.pw_gid, database_proof=proof,
                    counts_before=before, counts_after=after, archive_sha256={n: sha(raw) for n, raw in self.records.items()},
                    probe_sha256=sha(read(EVIDENCE / 'fresh-probe.json')), check_sha256=sha(read(EVIDENCE / 'fresh-check.json')),
                    website_evidence=self.web_receipt, listener_8000=[], continuation=continuation)
                self.u.write_new(EVIDENCE / 'ready.json', self.u.encoded(index)); self.worker.ready_recovery(self.user)
                self.stage = 'ready'
            except BaseException as error:
                self.failure_info = dict(stage=self.stage, **safe_error(error, base, self))
                handlers = [(sig, signal.signal(sig, signal.SIG_IGN)) for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)]
                try:
                    self.u.write_new(EVIDENCE / 'failure.json', self.u.encoded(dict(stage=self.stage, error=self.failure_info, cleanup=self.cleanup(), automatic_retry=False)))
                finally:
                    for sig, handler in handlers: signal.signal(sig, handler)
                raise

        def apply(self, manifest, change):
            EVIDENCE.mkdir(mode=0o700); self.u.sync(OPS)
            self.u.write_new(EVIDENCE / 'manifest.json', self.u.encoded(manifest))
            self.u.write_new(EVIDENCE / 'validated-snapshot.json', self.u.encoded(self.snapshot))
            try:
                result = self.u.apply_withheld(self.b, self.r, self.upgrade, manifest, change)
                if not result['ok'] and self.started and not self.cleanup_result:
                    handlers = [(sig, signal.signal(sig, signal.SIG_IGN)) for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)]
                    try:
                        self.cleanup()
                        self.u.write_new(EVIDENCE / 'failure.json', self.u.encoded(dict(stage='helper_transaction', cleanup=self.cleanup_result, automatic_retry=False)))
                    finally:
                        for sig, handler in handlers: signal.signal(sig, handler)
            finally:
                if self.db_fd is not None: os.close(self.db_fd); self.db_fd = None
            result.update(boot_id=base.BOOT, recovery_stage=self.stage, collection_started=False,
                          seed_run_started=False, timer_enabled=False, automatic_retry=False)
            if self.cleanup_result: result['cleanup'] = self.cleanup_result
            if self.failure_info: result['recovery_failure'] = self.failure_info
            return result
    return Continuation


def safe_error(error, base=None, recovery=None):
    if type(error) is Refused:
        result = {'reason': error.args[0]}
    elif base is not None:
        result = base.safe_error(error, recovery)
    elif isinstance(error, OSError):
        result = dict(reason='filesystem_or_process_error', error_type=type(error).__name__, errno=error.errno)
    else:
        result = dict(reason='preflight_failed', error_type=type(error).__name__)
    if result.get('reason') not in SAFE_REASON_CODES:
        result['reason'] = 'operation_refused'
    if 'error_type' in result and result['error_type'] not in SAFE_ERROR_TYPES:
        result['error_type'] = 'ValueError'
    detail = getattr(error, 'resolver_reason', None)
    if type(detail) is str and detail in ('mount_id_missing', 'mount_path_mismatch', 'mount_not_readonly',
                                         'inode_mismatch', 'content_mismatch', 'untrusted_path'):
        result['resolver_reason'] = detail
    return result


def checked_run(argv=None):
    """Checked entry for the CLI and a pinned root-terminal bootstrap."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('check', 'apply')); parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True); parser.add_argument('--expected-boot-id', required=True)
    parser.add_argument('--snapshot-sha256')
    args = parser.parse_args(argv)
    require(re.fullmatch(BOOT_PATTERN, args.expected_boot_id), 'explicit_reviewed_boot_id_required')
    require((args.action == 'check' and args.snapshot_sha256 is None) or
            (args.action == 'apply' and isinstance(args.snapshot_sha256, str) and re.fullmatch('[0-9a-f]{64}', args.snapshot_sha256)),
            'apply_requires_checked_snapshot_digest')
    require(os.getuid() == os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode and
            os.isatty(0) and os.isatty(1) and not os.environ.get('SUDO_USER') and not os.environ.get('SSH_ORIGINAL_COMMAND'),
            'isolated_root_terminal_required')
    require(Path(__file__).absolute() == args.source / 'continue-collector-after-boot.py', 'fixed_controller_entry_required')
    fd = os.open('/dev/tty', os.O_RDONLY | os.O_NOCTTY)
    try: require(os.isatty(fd), 'controlling_root_terminal_required')
    finally: os.close(fd)
    os.umask(0o077); resource.setrlimit(resource.RLIMIT_CORE, (0, 0)); os.environ.clear(); os.environ.update(ENV)
    manifest, data = source_inputs(args.source, args.manifest_sha256, args.expected_boot_id)
    require(sha(data['continue-collector-after-boot.py']) == sha(read(Path(__file__))), 'controller_source_changed')
    base = module(data['recover-collector-after-boot.py'], args.source / 'recover-collector-after-boot.py', 'approved_v2_controller')
    base.RUNNER_SHA_V2 = base.RUNNER_SHA; base.BROKER_SHA_V2 = base.BROKER_SHA
    base.RUNNER_SHA = RUNNER_SHA; base.BROKER_SHA = BROKER_SHA; base.EVIDENCE = EVIDENCE
    base.BOOT = args.expected_boot_id; base.WEBSITE = Path('/var/lib/aifinance-preview-recovery-' + base.BOOT)
    u = module(data['update-ops-nss-proof.py'], args.source / 'update-ops-nss-proof.py', 'continuation_updater')
    w = module(data['recover-preview-after-boot.py'], args.source / 'recover-preview-after-boot.py', 'approved_website_validator')
    old = {}
    for key, name, pin in (('broker', 'ops-broker.py', u.OLD_BROKER), ('runner', 'collect-only-runner.py', u.OLD_RUNNER),
                           ('upgrade', 'collect-only-upgrade.py', u.UPGRADE)):
        raw = read(BIN / name, 0o755, 262144); require(sha(raw) == pin, 'fixed_old_helper_set_required')
        old[key] = module(raw, BIN / name, 'approved_continuation_' + key)
    recovery = make_recovery(base)(u, w, old['broker'], old['runner'], old['upgrade'], manifest, data)
    try:
        with u.lock(old['runner']):
            recovery.preflight(); change = recovery.prepared(data)
            digest = sha(u.encoded(recovery.snapshot))
            if args.action == 'check':
                return dict(ok=True, stage='check', changed=False, boot_id=base.BOOT, snapshot_sha256=digest)
            require(digest == args.snapshot_sha256, 'checked_snapshot_digest_mismatch')
            return recovery.apply(manifest, change)
    except BaseException as error:
        return dict(ok=False, stage=recovery.stage, automatic_retry=False, **safe_error(error, base, recovery))


def interrupted(signum, frame):
    raise Refused('continuation_interrupted')


def run(argv=None):
    handlers = []
    try:
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            handlers.append((sig, signal.signal(sig, interrupted)))
        return checked_run(argv)
    except BaseException as error:
        return dict(ok=False, stage='entry', automatic_retry=False, **safe_error(error))
    finally:
        for sig, handler in reversed(handlers): signal.signal(sig, handler)


def main(argv=None):
    result = run(argv); print(json.dumps(result, sort_keys=True)); return 0 if result['ok'] else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except BaseException as error:
        if isinstance(error, SystemExit): raise
        print(json.dumps(dict(ok=False, stage='entry', automatic_retry=False, **safe_error(error)), sort_keys=True)); sys.exit(1)
