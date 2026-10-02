"""Filesystem and mocked-process contracts; never install on the host or run Node."""
import contextlib
import hashlib
import importlib.util
import io
import json
import lzma
import os
from pathlib import Path
import stat
import struct
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('first_install', str(REPO / 'deploy/native/first-install.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
REAL_FSTAT = os.fstat
SIGNER = 'A' * 40
VERSION = '24.11.1'
PREFIX = 'node-v' + VERSION + '-linux-x64'
FILENAME = PREFIX + '.tar.xz'
ELF = b'\x7fELF\x02\x01\x01' + b'\0' * 9 + struct.pack('<HH', 2, 62) + b'\0' * 128


def digest(data):
    return hashlib.sha256(data).hexdigest()


def root_fstat(fd):
    fields = list(REAL_FSTAT(fd))
    fields[4] = 0
    return os.stat_result(fields)


def image(base):
    return {str(p.relative_to(base)): (p.read_bytes() if p.is_file() else None, stat.S_IMODE(p.lstat().st_mode))
            for p in base.rglob('*') if not p.is_symlink()}


def valid_signature(args, **kwargs):
    return subprocess.CompletedProcess(args, 0,
        '[GNUPG:] VALIDSIG ' + SIGNER + ' 2026-01-01 1767225600 0 4 0 1 8 00 ' + SIGNER + '\n')


class Fixture(object):
    def __init__(self, base):
        self.base = base
        self.base.chmod(0o755)  # Fixture represents service-traversable protected ancestors.
        self.inputs = base / 'inputs'
        self.root = base / 'aifinance'
        self.inputs.mkdir(mode=0o700)
        self.root.mkdir(mode=0o755)
        self.db = base / 'database'
        self.db.mkdir()
        (self.db / 'data').write_bytes(b'preserve independent database')
        (self.root / 'shared').mkdir()
        (self.root / 'shared/schema.sha256').write_text('preserve existing schema record')
        self.gpgv = base / 'gpgv'
        self.gpgv.write_bytes(b'never executed')
        self.archive()

    def archive(self, extras=(), node_type=tarfile.REGTYPE, node=ELF):
        with tarfile.open(str(self.inputs / FILENAME), 'w:xz') as archive:
            for name, data, kind in ((PREFIX + '/bin/node', node, node_type),
                                     (PREFIX + '/LICENSE', b'Node license fixture', tarfile.REGTYPE)) + tuple(extras):
                item = tarfile.TarInfo(name)
                item.size = len(data) if kind == tarfile.REGTYPE else 0
                item.mode = 0o755 if name.endswith('/node') else 0o644
                item.type = kind
                if kind in (tarfile.LNKTYPE, tarfile.SYMTYPE):
                    item.linkname = '/unrelated/data'
                archive.addfile(item, io.BytesIO(data) if item.isfile() else None)
        self.pins()

    def pins(self):
        self.plan = {'format': 1, 'operation': 'install-dedicated-node-runtime',
                     'node_version': VERSION, 'node_url': 'https://nodejs.org/dist/v' + VERSION + '/' + FILENAME,
                     'archive_sha256': digest((self.inputs / FILENAME).read_bytes()), 'signer_fingerprint': SIGNER}
        values = [('SHASUMS256.txt', 'shasums_sha256', (self.plan['archive_sha256'] + '  ' + FILENAME + '\n').encode()),
                  ('SHASUMS256.txt.sig', 'signature_sha256', b'only mocked verifier accepts this'),
                  ('release-keys.gpg', 'keyring_sha256', b'synthetic public keyring')]
        for name, key, data in values:
            (self.inputs / name).write_bytes(data)
            self.plan[key] = digest(data)
        self.save()

    def save(self):
        data = json.dumps(self.plan, sort_keys=True).encode()
        (self.inputs / 'node-install.json').write_bytes(data)
        self.pin = digest(data)

    def trusted_fixture(self, path, directory=False):
        # Simulate root ownership only. Actual symlink/type/mode behavior is used.
        path = Path(path)
        if path == Path(m.__file__).absolute():
            return path
        for item in (path,) + tuple(path.parents):
            if item == self.base.parent:
                break
            info = item.lstat()
            is_dir = directory or item != path
            if (not (stat.S_ISDIR(info.st_mode) if is_dir else stat.S_ISREG(info.st_mode))
                    or info.st_mode & 0o022):
                raise ValueError('unprotected_fixture')
        return path

    @contextlib.contextmanager
    def active(self, verifier=valid_signature):
        with contextlib.ExitStack() as stack:
            for name, value in (('INPUTS', self.inputs), ('ROOT', self.root), ('RUNTIME', self.root / 'runtime'),
                                ('NODE', self.root / 'runtime/node'), ('PLAN', self.inputs / 'node-install.json'),
                                ('GPGV', self.gpgv)):
                stack.enter_context(patch.object(m, name, value))
            stack.enter_context(patch.object(m, 'protected', side_effect=self.trusted_fixture))
            stack.enter_context(patch.object(m.os, 'fstat', side_effect=root_fstat))
            stack.enter_context(patch.object(m.os, 'geteuid', return_value=0))
            stack.enter_context(patch.object(m.os, 'getegid', return_value=0))
            stack.enter_context(patch.object(m.platform, 'system', return_value='Linux'))
            stack.enter_context(patch.object(m.platform, 'machine', return_value='x86_64'))
            result = stack.enter_context(patch.object(m.subprocess, 'run', side_effect=verifier))
            yield result


class FirstInstall(unittest.TestCase):
    def test_plan_is_nonmutating_and_pg_block_is_independent(self):
        with patch.object(m, 'target_preflight', side_effect=AssertionError('host read')), patch.object(m.subprocess, 'run', side_effect=AssertionError('process')), contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main(['plan']), 0)
        value = json.loads(out.getvalue())
        node = value['phases'][0]
        self.assertTrue(node['implemented'])
        self.assertNotIn('exact_target_dependency_transaction', node['depends_on'])
        self.assertFalse(value['ready_for_deploy'])

    def test_check_verifies_real_bytes_without_any_filesystem_change(self):
        with tempfile.TemporaryDirectory() as directory:
            f = Fixture(Path(directory))
            before = image(f.base)
            with f.active(), patch.object(m, 'install_node', side_effect=AssertionError('write')):
                result = m.run_node(f.pin)
            self.assertEqual(image(f.base), before)
            self.assertTrue(result['node_install_prerequisites_passed'])
            self.assertFalse(result['ready_for_deploy'])
            self.assertFalse(result['changed'])

    def test_apply_creates_only_exact_runtime_files_and_preserves_data(self):
        with tempfile.TemporaryDirectory() as directory:
            f = Fixture(Path(directory))
            before = image(f.base)
            with f.active() as process:
                result = m.run_node(f.pin, True)
                self.assertEqual(process.call_count, 1)
                self.assertTrue(result['changed'])
                node = m.NODE
                self.assertEqual((node / 'bin/node').read_bytes(), ELF)
                self.assertEqual((node / 'LICENSE').read_bytes(), b'Node license fixture')
                self.assertEqual(set(str(p.relative_to(node)) for p in node.rglob('*')), {'bin', 'bin/node', 'LICENSE', 'INSTALL.json'})
                for path in (node, node / 'bin', node / 'bin/node'):
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o755)
                receipt = json.loads((node / 'INSTALL.json').read_text())
                self.assertFalse(receipt['ready_for_deploy'])
                self.assertFalse(receipt['runtime_or_ABI_accepted'])
            after = image(f.base)
            for key, value in before.items():
                self.assertEqual(after[key], value)
            self.assertFalse((f.root / 'shared/native-ready').exists())

    def test_root_umask_077_produces_service_traversable_new_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            f = Fixture(Path(directory))
            old = os.umask(0o077)
            try:
                with f.active():
                    m.run_node(f.pin, True)
            finally:
                os.umask(old)
            for path in (f.root / 'runtime', f.root / 'runtime/node', f.root / 'runtime/node/bin'):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o755)

    def test_existing_untraversable_root_or_runtime_is_not_modified(self):
        for kind in ('root', 'runtime'):
            with tempfile.TemporaryDirectory() as directory:
                f = Fixture(Path(directory))
                target = f.root if kind == 'root' else f.root / 'runtime'
                if kind == 'runtime':
                    target.mkdir()
                target.chmod(0o700)
                before = image(f.base)
                with f.active() as process, self.assertRaises(ValueError):
                    m.run_node(f.pin, True)
                self.assertFalse(process.called)
                self.assertEqual(image(f.base), before)

    def test_existing_complete_partial_or_symlink_install_never_adopted(self):
        for kind in ('complete', 'partial', 'symlink'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                f = Fixture(Path(directory))
                (f.root / 'runtime').mkdir()
                target = f.root / 'runtime/node'
                if kind == 'symlink':
                    target.symlink_to(f.db)
                else:
                    target.mkdir()
                    if kind == 'complete':
                        (target / 'keep').write_bytes(b'previous runtime')
                before = image(f.base)
                with f.active() as process, self.assertRaises(ValueError):
                    m.run_node(f.pin, True)
                self.assertFalse(process.called)
                self.assertEqual(image(f.base), before)
                if kind == 'symlink':
                    self.assertTrue(target.is_symlink())

    def test_existing_runtime_sibling_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            f = Fixture(Path(directory))
            (f.root / 'runtime').mkdir()
            sibling = f.root / 'runtime/other'
            sibling.write_bytes(b'do not replace')
            with f.active():
                m.run_node(f.pin, True)
            self.assertEqual(sibling.read_bytes(), b'do not replace')

    def test_signature_error_timeout_wrong_signer_and_weak_digest_stop_before_writes(self):
        statuses = [subprocess.CompletedProcess([], 1, ''),
                    subprocess.CompletedProcess([], 0, ''),
                    subprocess.CompletedProcess([], 0, '[GNUPG:] BADSIG abc\n'),
                    subprocess.CompletedProcess([], 0, valid_signature([]).stdout.replace(SIGNER, 'B' * 40)),
                    subprocess.CompletedProcess([], 0, valid_signature([]).stdout.replace(' 8 00 ', ' 2 00 ')),
                    subprocess.TimeoutExpired('gpgv', 15), OSError('missing gpgv')]
        for status in statuses:
            with self.subTest(status=str(status)), tempfile.TemporaryDirectory() as directory:
                f = Fixture(Path(directory))
                before = image(f.base)
                def verifier(*args, **kwargs):
                    if isinstance(status, Exception):
                        raise status
                    return status
                with f.active(verifier), self.assertRaises(ValueError):
                    m.run_node(f.pin, True)
                self.assertEqual(image(f.base), before)

    def test_fixed_signature_command_and_scrubbed_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            f = Fixture(Path(directory))
            with f.active() as process, patch.dict(os.environ, {'LD_PRELOAD': 'evil', 'NODE_OPTIONS': 'evil'}):
                m.run_node(f.pin)
                args, kwargs = process.call_args
                self.assertEqual(args[0], [str(f.gpgv), '--homedir', str(f.inputs), '--keyring',
                    str(f.inputs / 'release-keys.gpg'), '--status-fd', '1', '--',
                    str(f.inputs / 'SHASUMS256.txt.sig'), str(f.inputs / 'SHASUMS256.txt')])
                self.assertEqual(kwargs['env'], m.ENV)
                self.assertEqual(kwargs['timeout'], 15)
                self.assertEqual(kwargs['cwd'], '/')
                self.assertFalse(kwargs['shell'])
                self.assertIs(kwargs['stderr'], subprocess.DEVNULL)
                self.assertIs(kwargs['stdin'], subprocess.DEVNULL)

    def test_real_manifest_windows_subpaths_and_bad_or_duplicate_target_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            f = Fixture(Path(directory))
            target = f.plan['archive_sha256'] + '  ' + FILENAME + '\n'
            windows = ''.join('b' * 64 + '  ' + arch + '/' + name + '\n'
                              for arch in ('win-arm64', 'win-x64')
                              for name in ('node.exe', 'node.lib', 'node_pdb.7z', 'node_pdb.zip'))
            def manifest(text):
                data = text.encode('ascii')
                (f.inputs / 'SHASUMS256.txt').write_bytes(data)
                f.plan['shasums_sha256'] = digest(data)
                f.save()
            manifest(target + windows)
            before = image(f.base)
            with f.active():
                self.assertTrue(m.run_node(f.pin)['trusted_signature_and_pins_verified'])
            self.assertEqual(image(f.base), before)
            for extra in (target, 'c' * 64 + '  ' + FILENAME + '\n', 'malformed-row\n',
                          'c' * 64 + '  /absolute\n', 'c' * 64 + '  win-x64/../bad\n'):
                manifest(target + windows + extra)
                before = image(f.base)
                with f.active() as process, self.assertRaises(ValueError):
                    m.run_node(f.pin, True)
                self.assertFalse(process.called)
                self.assertEqual(image(f.base), before)

    def test_plan_rejects_hooks_extra_fields_wrong_url_version_and_duplicate_keys(self):
        changes = [('hook', '/bin/sh -c anything'), ('format', True), ('node_version', '24.011.1'),
                   ('node_version', '22.1.0'), ('node_url', 'https://evil.example/node.tar.xz'),
                   ('archive_sha256', 'A' * 64)]
        for key, value in changes:
            with self.subTest(key=key, value=value), tempfile.TemporaryDirectory() as directory:
                f = Fixture(Path(directory))
                f.plan[key] = value
                f.save()
                before = image(f.base)
                with f.active() as process, self.assertRaises(ValueError):
                    m.run_node(f.pin, True)
                self.assertFalse(process.called)
                self.assertEqual(image(f.base), before)
        with self.assertRaises(ValueError):
            m.unique([('format', 1), ('format', 1)])

    def test_mismatched_and_oversized_input_pins_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            f = Fixture(Path(directory))
            with f.active(), self.assertRaises(ValueError):
                m.run_node('0' * 64, True)
            with f.active(), self.assertRaises(ValueError):
                with m.verified_file(f.inputs / FILENAME, f.plan['archive_sha256'], 1):
                    pass
            (f.inputs / FILENAME).write_bytes(b'changed')
            before = image(f.base)
            with f.active(), self.assertRaises(ValueError):
                m.run_node(f.pin, True)
            self.assertEqual(image(f.base), before)

    def test_bad_archive_paths_hardlinks_duplicate_and_executable_rejected(self):
        variants = [((PREFIX + '/../escape', b'bad', tarfile.REGTYPE),),
                    (('/absolute', b'bad', tarfile.REGTYPE),),
                    ((PREFIX + '/hardlink', b'', tarfile.LNKTYPE),),
                    ((PREFIX + '/bin/node', ELF, tarfile.REGTYPE),)]
        for extras in variants:
            with tempfile.TemporaryDirectory() as directory:
                f = Fixture(Path(directory))
                f.archive(extras)
                before = image(f.base)
                with f.active(), self.assertRaises(ValueError):
                    m.run_node(f.pin, True)
                self.assertEqual(image(f.base), before)
        for node, kind in ((b'not an executable' * 8, tarfile.REGTYPE), (b'', tarfile.SYMTYPE)):
            with tempfile.TemporaryDirectory() as directory:
                f = Fixture(Path(directory))
                f.archive(node_type=kind, node=node)
                with f.active(), self.assertRaises(ValueError):
                    m.run_node(f.pin, True)
                self.assertFalse((f.root / 'runtime').exists())

    def test_huge_pax_and_gnu_metadata_rejected_before_body_read(self):
        for kind in (tarfile.XHDTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK):
            with tempfile.TemporaryDirectory() as directory:
                f = Fixture(Path(directory))
                header = tarfile.TarInfo('oversized-metadata')
                header.type, header.size = kind, 1000000000
                (f.inputs / FILENAME).write_bytes(lzma.compress(header.tobuf()))
                f.pins()
                with f.active(), self.assertRaisesRegex(ValueError, 'archive_metadata_limit'):
                    m.run_node(f.pin, True)
                self.assertFalse((f.root / 'runtime').exists())

    def test_pax_sparse_metadata_cannot_enter_sparse_decoder(self):
        with tempfile.TemporaryDirectory() as directory:
            f = Fixture(Path(directory))
            with tarfile.open(str(f.inputs / FILENAME), 'w:xz', format=tarfile.PAX_FORMAT) as archive:
                item = tarfile.TarInfo(PREFIX + '/bin/node')
                item.size = len(ELF)
                item.pax_headers = {'GNU.sparse.major': '1', 'GNU.sparse.minor': '0',
                                    'GNU.sparse.realsize': str(10 ** 12)}
                archive.addfile(item, io.BytesIO(ELF))
            f.pins()
            with f.active(), self.assertRaisesRegex(ValueError, 'pax_sparse_archive_members_forbidden'):
                m.run_node(f.pin, True)
            self.assertFalse((f.root / 'runtime').exists())

    def test_failure_retains_only_private_partial_tree_and_never_retries_over_it(self):
        with tempfile.TemporaryDirectory() as directory:
            f = Fixture(Path(directory))
            before = image(f.base)
            with f.active(), patch.object(m, 'write_new', side_effect=OSError('disk failure')), self.assertRaises(OSError):
                m.run_node(f.pin, True)
            target = f.root / 'runtime/node'
            self.assertTrue((target / 'bin/node').is_file())
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)
            self.assertFalse((target / 'INSTALL.json').exists())
            after = image(f.base)
            for key, value in before.items():
                self.assertEqual(after[key], value)
            with f.active() as process, self.assertRaises(ValueError):
                m.run_node(f.pin, True)
            self.assertFalse(process.called)

    def test_race_between_check_and_apply_preserves_newly_appeared_target(self):
        with tempfile.TemporaryDirectory() as directory:
            f = Fixture(Path(directory))
            real = m.install_node
            def competing_install(*args):
                target = f.root / 'runtime/node'
                target.mkdir(parents=True)
                (target / 'preserved').write_bytes(b'concurrent install')
                return real(*args)
            with f.active(), patch.object(m, 'install_node', side_effect=competing_install), self.assertRaises(ValueError):
                m.run_node(f.pin, True)
            self.assertEqual((f.root / 'runtime/node/preserved').read_bytes(), b'concurrent install')

    def test_root_and_protected_script_required_for_apply(self):
        with tempfile.TemporaryDirectory() as directory:
            f = Fixture(Path(directory))
            with f.active(), patch.object(m.os, 'geteuid', return_value=1000), self.assertRaises(ValueError):
                m.run_node(f.pin, True)
            self.assertFalse((f.root / 'runtime').exists())

    def test_protected_path_checks_real_structure_and_synthetic_owner(self):
        def metadata(path):
            return os.stat_result((stat.S_IFREG | 0o644 if str(path) == '/inputs/file' else stat.S_IFDIR | 0o755,
                                   0, 0, 1, 0, 0, 1, 0, 0, 0))
        with patch.object(Path, 'lstat', autospec=True, side_effect=metadata):
            self.assertEqual(m.protected('/inputs/file'), Path('/inputs/file'))
        for mode, uid, bad in ((stat.S_IFREG | 0o644, 1000, '/inputs/file'),
                               (stat.S_IFLNK | 0o777, 0, '/inputs/file'),
                               (stat.S_IFDIR | 0o777, 0, '/inputs'),
                               (stat.S_IFLNK | 0o777, 0, '/inputs')):
            def untrusted(path):
                data = list(metadata(path))
                if str(path) == bad:
                    data[0], data[4] = mode, uid
                return os.stat_result(data)
            with patch.object(Path, 'lstat', autospec=True, side_effect=untrusted), self.assertRaises(ValueError):
                m.protected('/inputs/file')
        for path in ('relative', '/inputs/../file'):
            with self.assertRaises(ValueError):
                m.protected(path)

    def test_symlink_input_or_parent_rejected_before_write(self):
        with tempfile.TemporaryDirectory() as directory:
            f = Fixture(Path(directory))
            real = f.inputs / 'real-plan'
            (f.inputs / 'node-install.json').rename(real)
            (f.inputs / 'node-install.json').symlink_to(real)
            with f.active(), self.assertRaises(ValueError):
                m.run_node(f.pin, True)
            self.assertFalse((f.root / 'runtime').exists())

    def test_parser_and_resource_caps_have_no_apply_escape(self):
        for args in (['apply-node'], ['apply-postgresql'], ['apply-node', '--plan-sha256', 'a' * 64, '--command', 'id']):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                m.main(args)
        with patch.object(m.resource, 'getrlimit', return_value=(m.resource.RLIM_INFINITY, m.resource.RLIM_INFINITY)), patch.object(m.resource, 'setrlimit') as setter:
            m.resource_limits()
            calls = dict((call[0][0], call[0][1]) for call in setter.call_args_list)
            self.assertEqual(calls[m.resource.RLIMIT_AS], (128 * 1024 ** 2,) * 2)
            self.assertEqual(calls[m.resource.RLIMIT_CPU], (30, 35))
            self.assertEqual(calls[m.resource.RLIMIT_CORE], (0, 0))
        with patch.object(m.resource, 'getrlimit', return_value=(16, 32)), patch.object(m.resource, 'setrlimit') as setter:
            m.resource_limits()
            self.assertTrue(all(call[0][1][0] <= 16 and call[0][1][1] <= 32 for call in setter.call_args_list))


if __name__ == '__main__':
    unittest.main()
