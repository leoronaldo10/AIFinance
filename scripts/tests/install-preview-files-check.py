"""Only workspace files and fake systemctl; never modify the target host."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('install', str(REPO / 'deploy/native/install-preview-files.py'))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class Installation(unittest.TestCase):
    def fixture(self):
        directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        root = Path(directory.name); source = root / 'source'; source.mkdir(); binary = root / 'bin'; binary.mkdir(); system = root / 'system'; system.mkdir()
        manifest = {}
        for name in m.HELPERS + m.UNITS + ('install-preview-files.py',):
            content = ('reviewed-' + name).encode(); (source / name).write_bytes(content)
            manifest[name] = hashlib.sha256(content).hexdigest()
        old = {}
        for name in m.OLD:
            content = ('known-old-' + name).encode(); (binary / name).write_bytes(content)
            old[name] = hashlib.sha256(content).hexdigest()
        (source / 'preview-files.json').write_text(json.dumps(manifest))
        expected = hashlib.sha256((source / 'preview-files.json').read_bytes()).hexdigest()
        patches = [patch.object(m, 'SOURCE', source), patch.object(m, 'BIN', binary), patch.object(m, 'SYSTEM', system), patch.object(m, 'BACKUP', binary / 'backup'), patch.object(m, 'OLD', old), patch.object(m, '__file__', str(source / 'install-preview-files.py')), patch.object(m.os, 'getuid', return_value=0), patch.object(m.os, 'geteuid', return_value=0), patch.object(m, 'trusted'), patch.object(m.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=b'not-found\n'))]
        for p in patches: p.start(); self.addCleanup(p.stop)
        return source, binary, system, expected

    def test_check_has_no_filesystem_writes(self):
        source, binary, system, expected = self.fixture()
        before = {str(p): p.read_bytes() for p in source.parent.rglob('*') if p.is_file()}
        m.check(expected)
        self.assertEqual(before, {str(p): p.read_bytes() for p in source.parent.rglob('*') if p.is_file()})

    def test_exact_apply_preserves_old_and_never_starts_services(self):
        source, binary, system, expected = self.fixture()
        m.apply(expected)
        for name in m.HELPERS: self.assertEqual((binary / name).read_bytes(), (source / name).read_bytes())
        for name in m.OLD: self.assertEqual((binary / 'backup' / name).read_text(), 'known-old-' + name)
        for name in m.UNITS: self.assertEqual((system / name).read_bytes(), (source / name).read_bytes())
        calls = m.subprocess.run.call_args_list
        self.assertEqual(calls[-1][0][0], ['/usr/bin/systemctl', 'daemon-reload'])
        self.assertFalse(any(any(x in ('enable', 'start', 'restart', 'stop', 'initdb', 'nft') for x in c[0][0]) for c in calls))
        with self.assertRaises(ValueError): m.apply(expected)

    def test_unknown_existing_helper_stops_before_backup(self):
        source, binary, system, expected = self.fixture()
        (binary / 'run-preview.py').write_text('unknown')
        with self.assertRaises(ValueError): m.apply(expected)
        self.assertFalse((binary / 'backup').exists())
        self.assertFalse(list(system.iterdir()))

    def test_unknown_new_path_or_symlink_refused(self):
        source, binary, system, expected = self.fixture()
        (binary / 'egress-guard.py').symlink_to('/missing')
        with self.assertRaises(ValueError): m.apply(expected)
        self.assertFalse((binary / 'backup').exists())

    def test_source_or_manifest_hash_mismatch_refused(self):
        source, binary, system, expected = self.fixture()
        with self.assertRaises(ValueError): m.check('0' * 64)
        (source / 'ssh-gateway.py').write_text('unknown')
        with self.assertRaises(ValueError): m.apply(expected)
        self.assertFalse((binary / 'backup').exists())

    def test_late_failure_keeps_backup_and_gateway_last(self):
        source, binary, system, expected = self.fixture()
        real_write = m.write_file
        def fail(path, content, mode):
            if path.name == 'first-preview.py': raise OSError('fixture')
            return real_write(path, content, mode)
        with patch.object(m, 'write_file', side_effect=fail):
            with self.assertRaises(OSError): m.apply(expected)
        self.assertTrue((binary / 'backup').is_dir())
        self.assertEqual((binary / 'ssh-gateway.py').read_text(), 'known-old-ssh-gateway.py')
        with self.assertRaises(ValueError): m.apply(expected)

    def test_exact_original_target_names_are_pinned(self):
        self.assertEqual(set(m.OLD), {'release.sh', 'run-preview.py', 'ssh-gateway.py', 'inspect-native.py'})
        for digest in m.OLD.values(): self.assertRegex(digest, r'^[0-9a-f]{64}$')



if __name__ == '__main__': unittest.main()
