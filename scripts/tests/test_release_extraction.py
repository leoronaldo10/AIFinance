"""Release extraction security/mode tests, runnable with Python 3.6+."""
import importlib.util
import gzip
import io
import os
import pathlib
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


REPO = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('extract_release', str(REPO / 'deploy/native/extract-release.py'))
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)
EXTRACTOR = REPO / 'deploy/native/extract-release.py'
REQUIRE_CROSS_UID = '--require-cross-uid' in sys.argv
if REQUIRE_CROSS_UID:
    sys.argv.remove('--require-cross-uid')


def member(name, kind='file', mode=0o644, target='', data=b'payload'):
    item = tarfile.TarInfo(name)
    item.mode = mode
    # These metadata must never be applied by the extractor.
    item.uid = 12345
    item.gid = 23456
    item.mtime = 1
    item.pax_headers = {'SCHILY.xattr.user.test': 'untrusted'}
    item.type = {'file': tarfile.REGTYPE, 'dir': tarfile.DIRTYPE,
                 'link': tarfile.SYMTYPE, 'hardlink': tarfile.LNKTYPE,
                 'fifo': tarfile.FIFOTYPE, 'char': tarfile.CHRTYPE,
                 'block': tarfile.BLKTYPE}[kind]
    item.linkname = target
    item.size = len(data) if kind == 'file' else 0
    return item, data


class ReleaseExtractionTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='aifinance-extraction-')
        self.root = pathlib.Path(self.temporary.name)
        self.archive = self.root / 'release.tar.gz'
        self.stage = self.root / 'stage'
        self.stage.mkdir(mode=0o700)

    def tearDown(self):
        self.temporary.cleanup()

    def pack(self, members):
        with tarfile.open(str(self.archive), 'w:gz', format=tarfile.PAX_FORMAT) as archive:
            for item, data in members:
                archive.addfile(item, io.BytesIO(data) if item.isfile() else None)

    def extract(self, members):
        self.pack(members)
        release.extract_release(str(self.archive), str(self.stage))

    def rejected(self, members):
        self.pack(members)
        with self.assertRaises(ValueError):
            release.extract_release(str(self.archive), str(self.stage))
        self.assertEqual(list(self.stage.iterdir()), [], 'reject before extracting ANY member')
        self.assertEqual(stat.S_IMODE(self.stage.stat().st_mode), 0o700)

    def runtime_members(self):
        return [member('.', 'dir', 0o700), member('packages/app/bin/run', mode=0o4700,
                                                data=b'#!/bin/sh\nprintf "runtime-ok\\n"\n'),
                member('packages/app/config', mode=0o600),
                member('node_modules/app', 'link', target='../packages/app'),
                member('node_modules/.bin/run', 'link', target='../app/bin/run')]

    def cli(self, wrapper=None):
        command = [sys.executable, '-B', str(EXTRACTOR), str(self.archive), str(self.stage)]
        if wrapper is not None:
            command = [sys.executable, '-B', '-c', wrapper, str(EXTRACTOR), str(self.archive), str(self.stage)]
        return subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              universal_newlines=True, timeout=10)

    def assert_resource_refusal(self, result):
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, 'Release extraction refused: resource limit exceeded or unavailable\n')
        self.assertEqual(list(self.stage.iterdir()), [])
        self.assertEqual(stat.S_IMODE(self.stage.stat().st_mode), 0o700)

    def test_cli_enforces_limits_and_extracts_normal_release(self):
        self.pack(self.runtime_members())
        result = self.cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.stage / 'node_modules/app/config').read_bytes(), b'payload')
        self.assertEqual(stat.S_IMODE(self.stage.stat().st_mode), 0o755)

    def test_claimed_large_pax_and_gnu_headers_are_rejected_before_payload_read(self):
        for kind in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE,
                     tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK):
            with self.subTest(kind=kind):
                item = tarfile.TarInfo('do-not-echo-attacker-metadata')
                item.type, item.size = kind, 64 * 1024 ** 2
                with gzip.open(str(self.archive), 'wb') as archive:
                    archive.write(item.tobuf(format=tarfile.GNU_FORMAT))
                    archive.write(b'\x00' * 1024)
                self.assert_resource_refusal(self.cli())

    def test_compressed_pax_metadata_cannot_bypass_payload_or_member_limits(self):
        item, data = member('file', data=b'x')
        item.pax_headers = {'comment': 'x' * (1024 * 1024)}
        self.pack([(item, data)])
        with mock.patch.object(release, 'MAX_BYTES', 1), mock.patch.object(release, 'MAX_MEMBERS', 1):
            with self.assertRaises(release.ResourceLimitError):
                release.extract_release(str(self.archive), str(self.stage))
        self.assert_resource_refusal(self.cli())

    def test_memory_limit_contains_bomb_even_without_extension_guard(self):
        item = tarfile.TarInfo('do-not-echo-attacker-metadata')
        item.type, item.size = tarfile.GNUTYPE_LONGNAME, 64 * 1024 ** 2
        with gzip.open(str(self.archive), 'wb') as archive:
            archive.write(item.tobuf(format=tarfile.GNU_FORMAT))
            for _ in range(64):
                archive.write(b'x' * (1024 * 1024))
            archive.write(b'\x00' * 1024)
        # Lower the child-only cap and disable only the early header guard to
        # independently exercise RLIMIT_AS. Never limit the unittest process.
        wrapper = '''import importlib.util,sys
spec=importlib.util.spec_from_file_location('bounded',sys.argv[1])
module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
module.MAX_ADDRESS_SPACE=64*1024**2
module.MAX_HEADER_BYTES=80*1024**2
module.MAX_METADATA_BYTES=80*1024**2
sys.argv=sys.argv[1:]
module.main()
'''
        self.assert_resource_refusal(self.cli(wrapper))

    def test_unavailable_resource_limits_fail_before_opening_archive(self):
        self.pack(self.runtime_members())
        wrapper = '''import importlib.util,sys,resource
from unittest import mock
spec=importlib.util.spec_from_file_location('bounded',sys.argv[1])
module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
sys.argv=sys.argv[1:]
with mock.patch.object(resource,'setrlimit',side_effect=PermissionError), mock.patch.object(module.tarfile,'open',side_effect=AssertionError('archive must not open')):
    module.main()
'''
        self.assert_resource_refusal(self.cli(wrapper))

    def test_fixed_limits_only_lower_existing_process_limits(self):
        import resource
        calls = []
        with mock.patch.object(resource, 'getrlimit', return_value=(resource.RLIM_INFINITY, resource.RLIM_INFINITY)), mock.patch.object(resource, 'setrlimit', side_effect=lambda kind, value: calls.append((kind, value))), mock.patch.object(release.signal, 'signal'):
            release.enforce_resource_limits()
        self.assertIn((resource.RLIMIT_AS, (128 * 1024 ** 2, 128 * 1024 ** 2)), calls)
        self.assertIn((resource.RLIMIT_CPU, (30, 35)), calls)
        self.assertIn((resource.RLIMIT_FSIZE, (release.MAX_BYTES, release.MAX_BYTES)), calls)
        self.assertIn((resource.RLIMIT_CORE, (0, 0)), calls)
        calls = []
        with mock.patch.object(resource, 'getrlimit', return_value=(1, 2)), mock.patch.object(resource, 'setrlimit', side_effect=lambda kind, value: calls.append((kind, value))), mock.patch.object(release.signal, 'signal'):
            release.enforce_resource_limits()
        self.assertTrue(all(soft <= 1 and hard <= 2 for _, (soft, hard) in calls))

    def test_modes_are_deterministic_under_restrictive_umask(self):
        old_umask = os.umask(0o077)
        try:
            self.extract([member('.', 'dir', 0o700), member('private', 'dir', 0o000),
                          member('private/plain', mode=0o000), member('private/owner-only', mode=0o600),
                          member('private/executable', mode=0o710), member('private/world-writable', mode=0o666),
                          member('private/setid-executable', mode=0o6777)])
        finally:
            os.umask(old_umask)
        for name in ('', 'private'):
            self.assertEqual(stat.S_IMODE((self.stage / name).stat().st_mode), 0o755)
        for name in ('plain', 'owner-only', 'world-writable'):
            self.assertEqual(stat.S_IMODE((self.stage / 'private' / name).stat().st_mode), 0o644)
        for name in ('executable', 'setid-executable'):
            self.assertEqual(stat.S_IMODE((self.stage / 'private' / name).stat().st_mode), 0o755)
        file_stat = (self.stage / 'private/plain').stat()
        self.assertEqual(file_stat.st_uid, os.geteuid())
        self.assertNotEqual(file_stat.st_mtime, 1)
        if hasattr(os, 'listxattr'):
            self.assertNotIn('user.test', os.listxattr(str(self.stage / 'private/plain')))

    def test_internal_workspace_and_bin_links_work(self):
        self.extract(self.runtime_members())
        self.assertEqual((self.stage / 'node_modules/app/config').read_bytes(), b'payload')
        self.assertEqual(os.readlink(str(self.stage / 'node_modules/app')), '../packages/app')
        result = subprocess.run([str(self.stage / 'node_modules/.bin/run')], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, universal_newlines=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'runtime-ok\n')

    def test_actual_different_runtime_uid_reads_and_executes(self):
        self.extract(self.runtime_members())
        os.chmod(str(self.root), 0o755)
        uid = 65534 if os.geteuid() != 65534 else 65533

        def drop_identity():
            os.setgroups([])
            os.setgid(uid)
            os.setuid(uid)

        # No users, sudo policy, or persistent namespaces are created. On a host
        # with CAP_SETUID this really runs under a different kernel UID.
        try:
            probe = subprocess.run(['/usr/bin/id', '-u'], preexec_fn=drop_identity,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        except (PermissionError, subprocess.SubprocessError) as error:
            if REQUIRE_CROSS_UID:
                raise  # The dedicated CI invocation must exercise the UID boundary.
            self.skipTest('Cannot assume a different runtime UID in this environment: {}'.format(error))
        self.assertEqual(probe.returncode, 0, probe.stderr)
        self.assertEqual(int(probe.stdout.strip()), uid)
        reader = 'cat "$1/node_modules/app/config" && "$1/node_modules/.bin/run" && ! test -w "$1/packages/app/config"'
        result = subprocess.run(['/bin/sh', '-c', reader, 'reader', str(self.stage)],
                                preexec_fn=drop_identity, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'payloadruntime-ok\n')

    def test_traversal_and_absolute_paths_are_rejected(self):
        for name in ('../escaped', '/absolute', 'a/../../escaped', r'a\..\escaped'):
            with self.subTest(name=name):
                self.rejected([member('valid'), member(name)])

    def test_hard_links_and_special_files_are_rejected(self):
        for kind in ('hardlink', 'fifo', 'char', 'block'):
            with self.subTest(kind=kind):
                self.rejected([member('valid'), member('bad', kind, target='valid')])

    def test_escaping_links_are_rejected_even_through_a_chain(self):
        for target in ('/absolute', '../outside', 'directory/../../outside', r'..\outside'):
            with self.subTest(target=target):
                self.rejected([member('directory', 'dir'), member('bad', 'link', target=target)])
        self.rejected([member('shallow', 'link', target='.'),
                       member('bad', 'link', target='shallow/../outside')])

    def test_cycles_dangling_links_and_file_ancestors_are_rejected(self):
        self.rejected([member('a', 'link', target='b'), member('b', 'link', target='a')])
        self.rejected([member('a', 'link', target='missing')])
        self.rejected([member('file'), member('a', 'link', target='file/../file')])

    def test_archive_never_writes_through_a_symlink_in_either_member_order(self):
        parent = member('alias', 'link', target='directory')
        child = member('alias/file')
        for ordering in ([parent, child], [child, parent]):
            self.rejected([member('directory', 'dir')] + ordering)

    def test_duplicate_and_conflicting_paths_are_rejected(self):
        for members in ([member('./file'), member('file')],
                        [member('path'), member('path', 'dir')],
                        [member('path'), member('path/child')],
                        [member('path/child'), member('path')],
                        [member('.')]):
            with self.subTest(members=[item.name for item, _ in members]):
                self.rejected(members)

    def test_preexisting_contents_and_symlink_destination_are_rejected(self):
        self.pack([member('valid')])
        (self.stage / 'existing').write_text('keep me')
        with self.assertRaises(ValueError):
            release.extract_release(str(self.archive), str(self.stage))
        self.assertEqual((self.stage / 'existing').read_text(), 'keep me')
        link = self.root / 'link'
        link.symlink_to(self.stage, target_is_directory=True)
        with self.assertRaises(ValueError):
            release.extract_release(str(self.archive), str(link))

    def test_disk_reserve_size_and_member_limits_fail_before_writes(self):
        with mock.patch.object(release, 'MAX_BYTES', 1):
            self.rejected([member('too-large')])
        with mock.patch.object(release, 'MAX_MEMBERS', 1):
            self.rejected([member('first'), member('second')])
        with mock.patch.object(release.shutil, 'disk_usage', return_value=type('Usage', (), {'free': 0})()):
            self.rejected([member('valid')])


if __name__ == '__main__':
    unittest.main()
