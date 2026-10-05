#!/usr/bin/python3
"""Original NSS and v3 resolver fixtures; no root, mounts, DB, DNS or live actions."""
import ast
from contextlib import ExitStack, contextmanager
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
SOURCE = REPO / 'deploy/native/updates/nss-proof-v1/collect-only-runner.py'
SPEC = importlib.util.spec_from_file_location('legacy_collector_fixtures', str(REPO / 'scripts/tests/collect-only-runner-check.py'))
legacy = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(legacy)
SPEC = importlib.util.spec_from_file_location('resolver_update_runner', str(SOURCE))
m = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(m)
# Run the same 29 legacy gates against the versioned payload, replacing only
# the obsolete literal-mount resolver fixture and adding canonical-proof cases.
legacy.m = m
HOSTS = legacy.HOSTS


@contextmanager
def resolver_fixture(link='authselect/nsswitch.conf'):
    # Real unprivileged openat/readlinkat/read/FD identities; only root ownership,
    # the RO mount and /proc mount metadata are simulated. No mounts or root use.
    with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
        base = Path(directory); root = base / 'child-root'; config = base / 'config'
        (root / 'etc/authselect').mkdir(parents=True); config.mkdir()
        (config / 'hosts').write_text(m.hosts_text(HOSTS))
        (config / 'nsswitch.conf').write_text('hosts: files\n')
        for name in ('hosts', 'nsswitch.conf'):
            (config / name).chmod(0o440)
        os.link(str(config / 'hosts'), str(root / 'etc/hosts'))
        canonical = '/etc/nsswitch.conf' if link is None else '/etc/authselect/nsswitch.conf'
        os.link(str(config / 'nsswitch.conf'), str(root) + canonical)
        if link is not None:
            (root / 'etc/nsswitch.conf').symlink_to(link)
        fixture = SimpleNamespace(root=root, config=config, readonly=True, ids=True,
                                  mounts='71 0 1:1 /source /etc/hosts ro - x x rw\n'
                                  '72 0 1:1 /source %s ro - x x rw\n' % canonical,
                                  nonroot=set(), fd_reads=[])
        original_open = os.open; original_fstat = os.fstat; original_read = m.read
        def open_file(path, flags, *args, **kwargs):
            if str(path) == '/proc/123/root': path = str(root)
            return original_open(path, flags, *args, **kwargs)
        def fstat(fd):
            info = original_fstat(fd)
            values = {name: getattr(info, name) for name in dir(info) if name.startswith('st_')}
            values['st_uid'] = 1000 if info.st_ino in fixture.nonroot else 0
            return SimpleNamespace(**values)
        def read(path, limit=131072):
            if str(path) == '/proc/123/mountinfo': return fixture.mounts
            if str(path).startswith('/proc/self/fdinfo/'):
                fd = int(path.name); fixture.fd_reads.append(original_fstat(fd).st_ino)
                which = '71' if original_fstat(fd).st_ino == (config / 'hosts').stat().st_ino else '72'
                return 'mnt_id:\t%s\n' % which if fixture.ids else 'pos:\t0\n'
            return original_read(path, limit)
        stack.enter_context(patch.object(m, 'CONFIG', config))
        stack.enter_context(patch.object(m, 'trusted'))
        stack.enter_context(patch.object(m.os, 'open', side_effect=open_file))
        stack.enter_context(patch.object(m.os, 'fstat', side_effect=fstat))
        stack.enter_context(patch.object(m.os, 'fstatvfs', side_effect=lambda fd: SimpleNamespace(f_flag=os.ST_RDONLY if fixture.readonly else 0)))
        stack.enter_context(patch.object(m, 'read', side_effect=read))
        yield fixture



class ResolverUpdateFixtures(legacy.CollectorFixtures):
    def test_python36_syntax_and_source_pins(self):
        ast.parse(SOURCE.read_text(), **({'feature_version': (3, 6)} if sys.version_info >= (3, 8) else {}))
        for path, digest in m.PINS.items():
            self.assertEqual(hashlib.sha256((REPO / path).read_bytes()).hexdigest(), digest)

    def test_actual_resolver_mounts_required_read_only(self):
        with resolver_fixture(None) as fixture:
            self.assertTrue(m.resolver_evidence(123)['hosts_only'])
            fixture.mounts = fixture.mounts.replace('/etc/hosts ro', '/etc/hosts rw')
            with self.assertRaises(ValueError): m.resolver_evidence(123)


    def test_resolver_relative_absolute_and_parent_symlinks_stay_in_child_root(self):
        for link in ('authselect/nsswitch.conf', '/etc/authselect/nsswitch.conf',
                     '../etc/authselect/nsswitch.conf'):
            with self.subTest(link=link), resolver_fixture(link) as fixture:
                self.assertTrue(m.resolver_evidence(123)['hosts_only'])
                self.assertEqual(len(fixture.fd_reads), 2)
                # The walker uses no privileged operation; this also runs in
                # the capability-dropped root Python 3.6 CI container.
                self.assertEqual(stat.S_IMODE((fixture.root / 'etc/nsswitch.conf').lstat().st_mode), 0o777)
                self.assertEqual(stat.S_IMODE((fixture.config / 'nsswitch.conf').stat().st_mode), 0o440)


    def test_resolver_inode_identity_required_not_just_same_bytes(self):
        with resolver_fixture() as fixture:
            path = fixture.root / 'etc/authselect/nsswitch.conf'
            path.unlink(); path.write_text('hosts: files\n'); path.chmod(0o440)
            with self.assertRaises(ValueError): m.resolver_evidence(123)


    def test_resolver_wrong_bytes_source_or_writable_file_rejected(self):
        for filename, content, mode in (('nsswitch.conf', 'hosts: files dns\n', 0o440),
                                        ('hosts', '', 0o460)):
            with self.subTest(filename=filename), resolver_fixture() as fixture:
                path = fixture.config / filename
                path.chmod(0o600); path.write_text(content); path.chmod(mode)
                with self.assertRaises(ValueError): m.resolver_evidence(123)
        with resolver_fixture() as fixture:
            # Simulate a tampered bound-file read even when metadata says same inode.
            original = os.read
            def changed(fd, count):
                data = original(fd, count)
                return b'hosts: dns\n' if len(fixture.fd_reads) == 2 else data
            with patch.object(m.os, 'read', side_effect=changed), self.assertRaises(ValueError):
                m.resolver_evidence(123)


    def test_resolver_mount_id_ro_and_canonical_path_are_all_required(self):
        mutations = (
            lambda f: setattr(f, 'readonly', False),
            lambda f: setattr(f, 'ids', False),
            lambda f: setattr(f, 'mounts', f.mounts.replace('72 ', '99 ')),
            lambda f: setattr(f, 'mounts', f.mounts + f.mounts.splitlines()[1] + '\n'),
            lambda f: setattr(f, 'mounts', f.mounts.replace('/etc/authselect/nsswitch.conf', '/etc/nsswitch.conf')),
            lambda f: setattr(f, 'mounts', f.mounts.replace(' ro ', ' ro,rw ')),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(case=index), resolver_fixture() as fixture:
                mutate(fixture)
                with self.assertRaises(ValueError): m.resolver_evidence(123)
        with resolver_fixture() as fixture:
            # A hidden lower RO mount must not prove that the actual FD is RO.
            fixture.mounts += '99 0 1:1 /source /etc/authselect/nsswitch.conf ro - x x rw\n'
            fixture.mounts = fixture.mounts.replace('72 0 1:1 /source /etc/authselect/nsswitch.conf ro',
                                                    '72 0 1:1 /source /etc/authselect/nsswitch.conf rw')
            with self.assertRaises(ValueError): m.resolver_evidence(123)


    def test_resolver_untrusted_symlink_directory_or_root_rejected(self):
        for relative in ('etc/nsswitch.conf', 'etc/authselect', ''):
            with self.subTest(relative=relative), resolver_fixture() as fixture:
                fixture.nonroot.add((fixture.root / relative).lstat().st_ino)
                with self.assertRaises(ValueError): m.resolver_evidence(123)
        for relative in ('etc', 'etc/authselect', ''):
            with self.subTest(relative=relative), resolver_fixture() as fixture:
                (fixture.root / relative).chmod(0o777)
                with self.assertRaises(ValueError): m.resolver_evidence(123)
        with resolver_fixture() as fixture:
            fixture.nonroot.add((fixture.config / 'nsswitch.conf').stat().st_ino)
            with self.assertRaises(ValueError): m.resolver_evidence(123)


    def test_resolver_loop_escape_proc_magic_and_nonregular_targets_rejected(self):
        for link in ('nsswitch.conf', '../../outside', '/proc/self/root/etc/nsswitch.conf', '/dev/null',
                     '/sys/nsswitch.conf', 'authselect', 'missing', './' * 260 + 'authselect/nsswitch.conf'):
            with self.subTest(link=link), resolver_fixture(link):
                with self.assertRaises((ValueError, FileNotFoundError)): m.resolver_evidence(123)
        with resolver_fixture() as fixture:
            path = fixture.root / 'etc/authselect/nsswitch.conf'; path.unlink(); os.mkfifo(str(path))
            with self.assertRaises(ValueError): m.resolver_evidence(123)


    def test_resolver_mountinfo_escaped_canonical_path(self):
        with resolver_fixture() as fixture:
            (fixture.root / 'etc/authselect').rename(str(fixture.root / 'etc/auth select'))
            path = fixture.root / 'etc/nsswitch.conf'; path.unlink(); path.symlink_to('auth select/nsswitch.conf')
            fixture.mounts = fixture.mounts.replace('/etc/authselect/', '/etc/auth\\040select/')
            self.assertTrue(m.resolver_evidence(123)['hosts_only'])


    def test_resolver_source_chain_is_checked_and_fds_close_on_failure(self):
        with resolver_fixture() as fixture:
            before = set(os.listdir('/proc/self/fd'))
            with patch.object(m, 'trusted', side_effect=ValueError('untrusted source')) as check:
                with self.assertRaises(ValueError): m.resolver_evidence(123)
                check.assert_called_once_with(fixture.config / 'hosts')
            self.assertEqual(set(os.listdir('/proc/self/fd')), before)
            fixture.readonly = False
            with self.assertRaises(ValueError): m.resolver_evidence(123)
            self.assertEqual(set(os.listdir('/proc/self/fd')), before)



class ResolverV3Fixtures(ResolverUpdateFixtures):
    @classmethod
    def setUpClass(cls):
        global m, SOURCE
        cls.original_runner, cls.original_source = m, SOURCE
        SOURCE = REPO / 'deploy/native/updates/collector-boot-v3/collect-only-runner.py'
        spec = importlib.util.spec_from_file_location('resolver_v3_runner', str(SOURCE))
        m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
        legacy.m = m

    @classmethod
    def tearDownClass(cls):
        global m, SOURCE
        m, SOURCE = cls.original_runner, cls.original_source
        legacy.m = m

    def assertResolverFailure(self, reason):
        with self.assertRaises(ValueError) as caught:
            m.resolver_evidence(123)
        self.assertEqual(str(caught.exception), 'actual_read_only_hosts_binding_required')
        self.assertEqual(caught.exception.resolver_reason, reason)

    def test_bounded_read_preserves_short_chunks_and_strict_size_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'metadata'
            content = ('first\n' + '\u00e9' * 30 + '\nlast\n').encode('utf-8')
            path.write_bytes(content)
            original = os.read
            with patch.object(m.os, 'read', side_effect=lambda fd, count: original(fd, min(count, 7))):
                self.assertEqual(m.read(path, len(content)), content.decode('utf-8'))
            # procfs reports st_size=0; the streamed byte limit still applies.
            original_stat = os.fstat
            with patch.object(m.os, 'read', side_effect=lambda fd, count: original(fd, min(count, 7))), \
                    patch.object(m.os, 'fstat', side_effect=lambda fd: SimpleNamespace(st_mode=original_stat(fd).st_mode, st_size=0)):
                with self.assertRaises(ValueError):
                    m.read(path, len(content) - 1)

    def test_resolver_mounts_after_short_read_boundary_are_verified(self):
        resolver_fixture_read = m.read
        with resolver_fixture() as fixture:
            path = fixture.root.parent / 'mountinfo'
            path.write_text(''.join('%d 0 1:1 / /unused%d ro - x x rw\n' % (n, n)
                                   for n in range(100, 400)) + fixture.mounts)
            inode = path.stat().st_ino
            original_read = os.read
            original_metadata_read = m.read
            def short_read(fd, count):
                return original_read(fd, min(count, 113) if os.fstat(fd).st_ino == inode else count)
            def metadata_read(selected, limit=131072):
                if str(selected) == '/proc/123/mountinfo':
                    return legacy_read(path, limit)
                return original_metadata_read(selected, limit)
            # Recover the real bounded reader, rather than fixture mount text.
            legacy_read = resolver_fixture_read
            with patch.object(m.os, 'read', side_effect=short_read), patch.object(m, 'read', side_effect=metadata_read):
                self.assertTrue(m.resolver_evidence(123)['hosts_only'])
                path.write_text(path.read_text().replace('/etc/hosts ro', '/etc/hosts rw'))
                with self.assertRaises(ValueError): m.resolver_evidence(123)

    def test_resolver_reasons_identify_required_mount_proofs(self):
        mutations = (
            ('mount_not_readonly', lambda f: setattr(f, 'readonly', False)),
            ('mount_id_missing', lambda f: setattr(f, 'ids', False)),
            ('mount_id_missing', lambda f: setattr(f, 'mounts', f.mounts.replace('72 ', '99 '))),
            ('mount_id_missing', lambda f: setattr(f, 'mounts', f.mounts + f.mounts.splitlines()[1] + '\n')),
            ('mount_path_mismatch', lambda f: setattr(f, 'mounts', f.mounts.replace('/etc/authselect/nsswitch.conf', '/private/path'))),
            ('mount_not_readonly', lambda f: setattr(f, 'mounts', f.mounts.replace(' ro ', ' ro,rw '))),
        )
        for reason, mutate in mutations:
            with self.subTest(reason=reason), resolver_fixture() as fixture:
                mutate(fixture)
                self.assertResolverFailure(reason)
        with resolver_fixture() as fixture:
            fixture.mounts += '99 0 1:1 /source /etc/authselect/nsswitch.conf ro - x x rw\n'
            fixture.mounts = fixture.mounts.replace('72 0 1:1 /source /etc/authselect/nsswitch.conf ro',
                                                    '72 0 1:1 /source /etc/authselect/nsswitch.conf rw')
            self.assertResolverFailure('mount_not_readonly')

    def test_resolver_reasons_identify_inode_content_and_trust_failures(self):
        with resolver_fixture() as fixture:
            path = fixture.root / 'etc/authselect/nsswitch.conf'
            path.unlink(); path.write_text('hosts: files\n'); path.chmod(0o440)
            self.assertResolverFailure('inode_mismatch')
        with resolver_fixture() as fixture:
            path = fixture.config / 'nsswitch.conf'
            path.chmod(0o600); path.write_text('hosts: files dns\n'); path.chmod(0o440)
            self.assertResolverFailure('content_mismatch')
        with resolver_fixture() as fixture:
            original = os.read
            def changed(fd, count):
                data = original(fd, count)
                return b'private changed content' if len(fixture.fd_reads) == 2 else data
            with patch.object(m.os, 'read', side_effect=changed):
                self.assertResolverFailure('content_mismatch')
        with resolver_fixture() as fixture:
            fixture.nonroot.add(fixture.root.stat().st_ino)
            self.assertResolverFailure('untrusted_path')
        with resolver_fixture('/proc/self/root/etc/nsswitch.conf'):
            self.assertResolverFailure('untrusted_path')

    def test_resolver_reason_never_contains_raw_exception_data(self):
        expected = {'mount_id_missing', 'mount_path_mismatch', 'mount_not_readonly',
                    'inode_mismatch', 'content_mismatch', 'untrusted_path'}
        self.assertEqual(set(m.RESOLVER_REASONS), expected)
        secret = '/private/path DATABASE_URL=postgres://private:secret@host/db raw-content'
        for reason in tuple(expected) + (secret, None, 7):
            error = m.resolver_failure(reason)
            self.assertEqual(str(error), 'actual_read_only_hosts_binding_required')
            self.assertEqual(error.resolver_reason, reason if reason in expected else 'untrusted_path')
            self.assertEqual(set(vars(error)), {'resolver_reason'})
        with resolver_fixture() as fixture:
            error = ValueError(secret); error.resolver_reason = secret
            with patch.object(m, 'trusted', side_effect=error):
                with self.assertRaises(ValueError) as caught:
                    m.resolver_evidence(123)
            self.assertIs(caught.exception, error)
            self.assertEqual(caught.exception.resolver_reason, 'untrusted_path')
        with patch.object(m.os, 'open', side_effect=OSError(secret)):
            with self.assertRaises(OSError) as caught:
                m.resolver_evidence(123)
        self.assertEqual(caught.exception.resolver_reason, 'untrusted_path')


if __name__ == '__main__': unittest.main()
