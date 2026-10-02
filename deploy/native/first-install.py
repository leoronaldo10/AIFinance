#!/usr/bin/python3
"""Small, separately approved first-install phase; Python 3.6.8+.

Only install the official pinned Node executable and license into a fresh fixed
path. No package manager, account, database, unit, secret, or acceptance writes.
Run an administrator-reviewed protected copy with /usr/bin/python3 -I -B.
"""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import resource
import stat
import struct
import subprocess
import sys
import tarfile

INPUTS = Path('/root/aifinance-native-inputs')
ROOT = Path('/opt/aifinance')
RUNTIME = ROOT / 'runtime'
NODE = RUNTIME / 'node'
PLAN = INPUTS / 'node-install.json'
GPGV = Path('/usr/bin/gpgv')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/', 'LANG': 'C', 'LC_ALL': 'C'}
MAX_ARCHIVE = 256 * 1024 ** 2
MAX_NODE = 256 * 1024 ** 2
MAX_EXPANDED = 512 * 1024 ** 2
HEX = r'[0-9a-f]{64}'


def resource_limits():
    # CLI only: cap XZ dictionary allocation, parser metadata, CPU and core dumps
    # before even the first archive header is parsed. Never raise inherited caps.
    for kind, soft, hard in ((resource.RLIMIT_AS, 128 * 1024 ** 2, 128 * 1024 ** 2),
                             (resource.RLIMIT_CPU, 30, 35),
                             (resource.RLIMIT_FSIZE, MAX_NODE + 1048576, MAX_NODE + 1048576),
                             (resource.RLIMIT_CORE, 0, 0)):
        current_soft, current_hard = resource.getrlimit(kind)
        if current_hard != resource.RLIM_INFINITY:
            hard = min(hard, current_hard)
        if current_soft != resource.RLIM_INFINITY:
            soft = min(soft, current_soft)
        resource.setrlimit(kind, (min(soft, hard), hard))


class BoundedTarInfo(tarfile.TarInfo):
    # tarfile otherwise allocates PAX/GNU header bodies before yielding members.
    def metadata_limit(self, archive):
        total = getattr(archive, '_first_install_metadata', 0) + self.size
        if not 0 <= self.size <= 65536 or total > 16 * 1024 ** 2:
            raise ValueError('archive_metadata_limit')
        archive._first_install_metadata = total

    def _proc_pax(self, archive):
        self.metadata_limit(archive)
        return super()._proc_pax(archive)

    def _proc_gnulong(self, archive):
        self.metadata_limit(archive)
        return super()._proc_gnulong(archive)

    def _proc_sparse(self, archive):
        raise ValueError('sparse_archive_members_forbidden')

    def _proc_gnusparse_00(self, *args):
        raise ValueError('pax_sparse_archive_members_forbidden')

    _proc_gnusparse_01 = _proc_gnusparse_00
    _proc_gnusparse_10 = _proc_gnusparse_00


def phases():
    return {
        'implemented': ['plan', 'check-node', 'apply-node'],
        'ready_for_deploy': False,
        'phases': [
            {'phase': 'node', 'depends_on': ['reviewed_official_signature_and_pins', 'explicit_node_install_approval'],
             'writes': [str(RUNTIME), str(NODE)], 'implemented': True,
             'acceptance': 'bytes_only_not_runtime_or_ABI_acceptance'},
            {'phase': 'postgresql-packages', 'depends_on': ['exact_target_dependency_transaction', 'explicit_package_transaction_approval'],
             'implemented': False, 'status': 'target_transaction_unknown_blocks_this_phase_only'},
            {'phase': 'database-env-units', 'depends_on': ['node', 'postgresql-packages', 'explicit_database_account_env_unit_approval'],
             'implemented': False, 'status': 'bounded_administrator_procedure_required'},
            {'phase': 'isolation-migration-acceptance', 'depends_on': ['database-env-units', 'actual_target_isolation_evidence', 'explicit_migration_approval'],
             'implemented': False, 'status': 'no_ready_or_schema_markers_before_real_acceptance'},
        ],
    }


def protected(path, directory=False):
    """No symlink components, root ownership, or group/other-writable paths."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('absolute_canonical_protected_path_required')
    for item in (path,) + tuple(path.parents):
        st = item.lstat()
        is_dir = directory or item != path
        if (not (stat.S_ISDIR(st.st_mode) if is_dir else stat.S_ISREG(st.st_mode))
                or st.st_uid != 0 or st.st_mode & 0o022):
            raise ValueError('unprotected_or_symlink_path')
    return path


@contextmanager
def verified_file(path, expected, limit):
    protected(path)
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as handle:
        st = os.fstat(handle.fileno())
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022
                or st.st_size > limit):
            raise ValueError('invalid_input_metadata_or_size')
        digest, count = hashlib.sha256(), 0
        while True:
            data = handle.read(1024 * 1024)
            if not data:
                break
            count += len(data)
            if count > limit:
                raise ValueError('input_size_limit')
            digest.update(data)
        if not re.fullmatch(HEX, expected or '') or digest.hexdigest() != expected:
            raise ValueError('input_pin_mismatch')
        handle.seek(0)
        yield handle


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate_plan_key')
        result[key] = value
    return result


def load_plan(expected):
    with verified_file(PLAN, expected, 16384) as handle:
        plan = json.loads(handle.read().decode('utf-8'), object_pairs_hook=unique)
    fields = {'format', 'operation', 'node_version', 'node_url', 'archive_sha256',
              'shasums_sha256', 'signature_sha256', 'keyring_sha256', 'signer_fingerprint'}
    if (not isinstance(plan, dict) or set(plan) != fields or type(plan['format']) is not int
            or plan['format'] != 1 or plan['operation'] != 'install-dedicated-node-runtime'):
        raise ValueError('invalid_node_plan_schema')
    version = plan['node_version']
    match = re.fullmatch(r'24\.([0-9]+)\.([0-9]+)', version) if isinstance(version, str) else None
    if (not match or int(match.group(1)) < 11 or
            any(str(int(x)) != x for x in match.groups())):
        raise ValueError('exact_node_24_11_or_newer_24x_required')
    filename = 'node-v' + version + '-linux-x64.tar.xz'
    if plan['node_url'] != 'https://nodejs.org/dist/v' + version + '/' + filename:
        raise ValueError('exact_official_node_url_required')
    for key in ('archive_sha256', 'shasums_sha256', 'signature_sha256', 'keyring_sha256'):
        if not isinstance(plan[key], str) or not re.fullmatch(HEX, plan[key]):
            raise ValueError('invalid_pin')
    if (not isinstance(plan['signer_fingerprint'], str) or
            not re.fullmatch(r'(?:[A-F0-9]{40}|[A-F0-9]{64})', plan['signer_fingerprint'])):
        raise ValueError('independently_reviewed_signer_fingerprint_required')
    return plan, filename


def verify_signature(plan, filename):
    """Only external command: local detached-signature verification. No downloads."""
    files = [('release-keys.gpg', 'keyring_sha256', 1024 * 1024),
             ('SHASUMS256.txt.sig', 'signature_sha256', 16384),
             ('SHASUMS256.txt', 'shasums_sha256', 131072)]
    for name, pin, limit in files:
        with verified_file(INPUTS / name, plan[pin], limit) as handle:
            if name == 'SHASUMS256.txt':
                sums = handle.read().decode('ascii')
    rows = []
    for line in sums.splitlines():
        match = re.fullmatch(r'([0-9a-f]{64}) [ *]([^\s]+)', line)
        if not match:
            raise ValueError('invalid_official_shasums_line')
        # Official manifests also contain win-x64/node.exe and other subpaths.
        # These names are comparison data only, never filesystem input paths.
        name = PurePosixPath(match.group(2))
        if (name.is_absolute() or '..' in name.parts or str(name) != match.group(2)
                or '\\' in match.group(2) or '\x00' in match.group(2)):
            raise ValueError('invalid_official_shasums_path')
        if match.group(2) == filename:
            rows.append(match.group(1))
    if rows != [plan['archive_sha256']]:
        raise ValueError('archive_pin_not_unique_in_signed_shasums')
    protected(GPGV.resolve(strict=True))
    args = [str(GPGV), '--homedir', str(INPUTS), '--keyring', str(INPUTS / 'release-keys.gpg'),
            '--status-fd', '1', '--', str(INPUTS / 'SHASUMS256.txt.sig'), str(INPUTS / 'SHASUMS256.txt')]
    try:
        result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, env=ENV, cwd='/', timeout=15,
                                universal_newlines=True, shell=False)
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError('official_signature_verification_unavailable')
    if result.returncode != 0 or len(result.stdout) > 32768:
        raise ValueError('official_signature_verification_failed')
    valid = []
    rejected = ('BADSIG', 'ERRSIG', 'EXPSIG', 'EXPKEYSIG', 'REVKEYSIG', 'KEYEXPIRED', 'SIGEXPIRED')
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == '[GNUPG:]':
            if parts[1] in rejected:
                raise ValueError('official_signature_rejected')
            if parts[1] == 'VALIDSIG' and len(parts) >= 11:
                if parts[9] not in ('8', '9', '10', '11') or parts[10] != '00':
                    raise ValueError('weak_or_unexpected_manifest_signature')
                # GnuPG emits the signing subkey first and (when present) primary key last.
                valid.append((parts[2], parts[11] if len(parts) == 12 else parts[2]))
    wanted = plan['signer_fingerprint']
    if not valid or any(wanted not in pair for pair in valid):
        raise ValueError('official_signer_does_not_match_reviewed_pin')


def target_preflight():
    if sys.version_info < (3, 6, 8) or platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise ValueError('supported_linux_x86_64_python_required')
    protected(ROOT, directory=True)
    # App UID is not root. Do not silently repair existing access/permissions.
    for directory in (ROOT,) + tuple(ROOT.parents):
        if not directory.stat().st_mode & 0o001:
            raise ValueError('existing_runtime_ancestors_not_service_traversable')
    if RUNTIME.exists() or RUNTIME.is_symlink():
        protected(RUNTIME, directory=True)
        if not RUNTIME.stat().st_mode & 0o001:
            raise ValueError('existing_runtime_not_service_traversable')
    # Existing, dangling, partial and interrupted installs are all preserved.
    if NODE.exists() or NODE.is_symlink():
        raise ValueError('existing_node_path_manual_reconciliation_required')
    disk = os.statvfs(str(ROOT))
    if disk.f_bavail * disk.f_frsize < MAX_NODE + 1024 ** 3:
        raise ValueError('insufficient_disk_reserve')


def inspect_archive(archive, version):
    """Inspect, then copy only two regular members; never tar.extract/extractall."""
    prefix = 'node-v' + version + '-linux-x64'
    wanted = {prefix + '/bin/node': None, prefix + '/LICENSE': None}
    seen, total, count = set(), 0, 0
    for member in archive:
        count += 1
        path = PurePosixPath(member.name)
        if (count > 50000 or path.is_absolute() or not path.parts or path.parts[0] != prefix
                or '..' in path.parts or '\\' in member.name or '\x00' in member.name
                or member.name.rstrip('/') != str(path) or member.name in seen):
            raise ValueError('unsafe_or_duplicate_archive_path')
        seen.add(member.name)
        total += member.size
        if member.size < 0 or total > MAX_EXPANDED:
            raise ValueError('archive_expansion_limit')
        if not (member.isdir() or member.isfile() or member.issym()):
            raise ValueError('unsupported_archive_member_type')
        if member.name in wanted:
            if not member.isfile() or member.issparse() or member.mode & 0o7000:
                raise ValueError('node_and_license_must_be_plain_files')
            wanted[member.name] = member
    node, license_file = wanted[prefix + '/bin/node'], wanted[prefix + '/LICENSE']
    if node is None or license_file is None or not 64 <= node.size <= MAX_NODE or not 1 <= license_file.size <= 1048576:
        raise ValueError('missing_or_invalid_node_and_license')
    with archive.extractfile(node) as handle:
        header = handle.read(64)
    if (header[:7] != b'\x7fELF\x02\x01\x01' or
            struct.unpack('<HH', header[16:20]) not in ((2, 62), (3, 62))):
        raise ValueError('x86_64_elf_required_not_an_ABI_acceptance')
    return node, license_file


def write_new(path, data, mode):
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
        os.fchmod(handle.fileno(), mode)


def install_node(archive, members, plan, plan_digest):
    """Called only after verification. Existing paths are never adopted or removed.

    A partial new directory is deliberately retained, private, for admin review.
    This is a first installation, not rollback or self-repair.
    """
    target_preflight()
    if not RUNTIME.exists():
        RUNTIME.mkdir(mode=0o755)
        RUNTIME.chmod(0o755)  # Administrator umask077 must not block the service UID.
    protected(RUNTIME, directory=True)
    NODE.mkdir(mode=0o700)  # Exclusive creation also arbitrates simultaneous attempts.
    (NODE / 'bin').mkdir(mode=0o700)
    for member, target, mode in ((members[0], NODE / 'bin/node', 0o755), (members[1], NODE / 'LICENSE', 0o644)):
        fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as out, archive.extractfile(member) as source:
            count = 0
            while True:
                data = source.read(1024 * 1024)
                if not data:
                    break
                count += len(data)
                if count > member.size:
                    raise ValueError('archive_member_changed')
                out.write(data)
            if count != member.size:
                raise ValueError('truncated_archive_member')
            out.flush()
            os.fsync(out.fileno())
            os.fchmod(out.fileno(), mode)
    receipt = {'format': 1, 'node_version': plan['node_version'], 'archive_sha256': plan['archive_sha256'],
               'plan_sha256': plan_digest, 'signer_fingerprint': plan['signer_fingerprint'],
               'runtime_or_ABI_accepted': False, 'ready_for_deploy': False}
    write_new(NODE / 'INSTALL.json', (json.dumps(receipt, sort_keys=True) + '\n').encode('ascii'), 0o644)
    (NODE / 'bin').chmod(0o755)
    NODE.chmod(0o755)  # Publish only after every byte and the non-acceptance receipt exist.


def run_node(expected, apply=False):
    if apply:
        if os.geteuid() != 0 or os.getegid() != 0:
            raise ValueError('administrator_root_context_required')
        protected(Path(__file__).absolute())
    target_preflight()
    plan, filename = load_plan(expected)
    verify_signature(plan, filename)
    with verified_file(INPUTS / filename, plan['archive_sha256'], MAX_ARCHIVE) as handle:
        with tarfile.open(fileobj=handle, mode='r:xz', tarinfo=BoundedTarInfo) as archive:
            members = inspect_archive(archive, plan['node_version'])
            if apply:
                install_node(archive, members, plan, expected)
    return {'phase': 'node', 'mode': 'apply-node' if apply else 'check-node', 'changed': apply,
            'node_bytes_installed': apply, 'node_version': plan['node_version'],
            'node_install_prerequisites_passed': True, 'explicit_administrator_approval_still_required': not apply,
            'trusted_signature_and_pins_verified': True, 'runtime_or_ABI_accepted': False,
            'ready_for_deploy': False, 'postgresql_transaction': 'unknown_not_a_node_phase_dependency'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('plan', 'check-node', 'apply-node'))
    parser.add_argument('--plan-sha256', help='independently reviewed digest of the fixed protected node-install.json')
    args = parser.parse_args(argv)
    if args.command == 'plan':
        if args.plan_sha256:
            parser.error('plan does not accept artifact pins')
        result = phases()
    else:
        if not re.fullmatch(HEX, args.plan_sha256 or ''):
            parser.error('node checks/apply require --plan-sha256 with a reviewed lowercase SHA256')
        result = run_node(args.plan_sha256, args.command == 'apply-node')
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        resource_limits()
        sys.exit(main())
    except (OSError, ValueError, tarfile.TarError, EOFError, MemoryError):
        # Do not print paths, raw verifier stderr, credentials, or input contents.
        print(json.dumps({'status': 'failed', 'ready_for_deploy': False,
                          'action': 'stop_and_review_preserved_paths_no_cleanup_or_service_changes'}))
        sys.exit(1)
