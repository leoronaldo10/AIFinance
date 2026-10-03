"""Offline checks. Fixture subprocesses only; no host provisioning or live DB."""
import ast
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('upgrade', str(REPO / 'deploy/native/collect-only-upgrade.py'))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class UpgradeSafety(unittest.TestCase):
    def test_python36_syntax(self):
        ast.parse((REPO / 'deploy/native/collect-only-upgrade.py').read_text())

    def test_exact_reviewed_schema_and_migration_pins(self):
        files = sorted((REPO / 'database/migrations').glob('*.sql'))
        def manifest(selected):
            return ''.join(hashlib.sha256(p.read_bytes()).hexdigest() + '  database/migrations/' + p.name + '\n' for p in selected)
        self.assertEqual(m.digest(manifest(files[:-1]).encode()), m.OLD_SCHEMA)
        self.assertEqual(m.digest(manifest(files).encode()), m.NEW_SCHEMA)
        self.assertEqual(m.digest(files[-1].read_bytes()), m.MIGRATION_DIGEST)
        self.assertEqual(files[-1].name, m.MIGRATION)

    def test_migration_is_one_transaction_with_ledger_guard_and_limits(self):
        names = ['0001_core.sql', '0040_topic_activation.sql']
        sql = m.migration_sql(REPO, names)
        self.assertTrue(sql.startswith('BEGIN;'))
        self.assertTrue(sql.endswith('COMMIT;\n'))
        for text in ["lock_timeout='5s'", "statement_timeout='60s'", 'LOCK TABLE public.schema_migrations', 'IS DISTINCT FROM ARRAY', "VALUES ('0041_collect_only.sql')"]:
            self.assertIn(text, sql)
        self.assertLess(sql.index('LOCK TABLE'), sql.index('ALTER TABLE'))
        self.assertLess(sql.index('ALTER TABLE'), sql.index('INSERT INTO'))
        for forbidden in ['publishArticle', 'migrate.ts', 'seed.ts', 'DELETE ', 'UPDATE ']:
            self.assertNotIn(forbidden, sql)

    def test_different_migration_bytes_rejected_before_sql(self):
        with patch.object(m, 'small', return_value=b'CREATE ROLE dangerous;'):
            with self.assertRaisesRegex(ValueError, '0041_bytes'):
                m.migration_sql(REPO, [])

    def test_current_requires_exact_old_and_no_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); root.chmod(0o755); (root / 'state').mkdir(); (root / 'state').chmod(0o755); (root / 'shared').mkdir(); old = root / 'releases' / m.OLD
            old.mkdir(parents=True); (old / 'RELEASE_SHA').write_text(m.OLD+'\n'); (root / 'state/current').symlink_to(old)
            with patch.object(m, 'ROOT', root):
                m.current_old()
                (root / 'shared/native-ready').touch()
                with self.assertRaises(ValueError): m.current_old()

    def test_no_symlink_file_or_escape_read(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory); (p / 'real').write_text('small'); (p / 'link').symlink_to(p / 'real')
            self.assertEqual(m.small(p / 'real'), b'small')
            with self.assertRaises(OSError): m.small(p / 'link')
            with self.assertRaises(ValueError): m.small(p / 'real', 2)

    def test_archive_full_sha_required_and_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / 'incoming').mkdir(); p = root / 'incoming' / (m.NEW+'.tar.gz'); p.write_bytes(b'fixture')
            with patch.object(m, 'ROOT', root):
                self.assertEqual(m.archive_check(m.digest(b'fixture')), 7)
                for value in [None, 'branch', 'A'*64, 'b'*64]:
                    with self.assertRaises(ValueError): m.archive_check(value)

    def test_command_bounds_output_and_drops_inherited_environment(self):
        self.assertEqual(m.command([sys.executable, '-c', 'print("fixture")'], output=True), 'fixture')
        with self.assertRaisesRegex(ValueError, 'output_limit'):
            m.command([sys.executable, '-c', 'print("x"*1100000)'], output=True)
        with patch.dict(os.environ, {'MODEL_API_KEY':'do-not-copy','PGPASSWORD':'do-not-copy'}):
            self.assertEqual(m.command([sys.executable, '-c', 'import os;print("MODEL_API_KEY" in os.environ or "PGPASSWORD" in os.environ)'], output=True), 'False')
        with self.assertRaises(ValueError): m.command([sys.executable, '-c', 'import time;time.sleep(10)'], timeout=.05)

    def test_true_app_authentication_not_set_role(self):
        with patch.object(m, 'db_env', return_value={'PGPASSWORD':'fixture'}), patch.object(m, 'command', return_value='1') as run:
            self.assertEqual(m.psql('SELECT 1'), '1')
            args = run.call_args[0][0]; opts = run.call_args[1]
            self.assertEqual(args[args.index('-U')+1], m.DB)
            self.assertEqual(opts['user'], 'aifinance')
            self.assertNotIn('fixture', repr(args))
            self.assertEqual(opts['data'], b'SELECT 1')

    def test_isolated_restore_authentication_has_no_production_secret(self):
        with patch.object(m, 'db_env', side_effect=AssertionError('not allowed')), patch.object(m, 'command', return_value='1') as run:
            m.psql('SELECT 1', restore=Path('/fixture'))
            self.assertEqual(run.call_args[1]['env'], m.ENV)
            self.assertIsNone(run.call_args[1]['user'])
            self.assertIn('/fixture/socket', run.call_args[0][0])

    def test_restore_evidence_mismatch_blocks(self):
        m.compatible({'tables':{'a':1}}, {'tables':{'a':1}})
        with self.assertRaisesRegex(ValueError, 'restored_database'):
            m.compatible({'tables':{'a':1}}, {'tables':{'a':2}})

    def test_existing_lock_inode_is_not_created_or_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); root.chmod(0o755); (root / 'state').mkdir(); (root / 'state').chmod(0o755)
            with patch.object(m, 'ROOT', root), patch.object(m, 'account', return_value=SimpleNamespace(pw_uid=os.getuid(),pw_gid=os.getgid())), patch.object(m,'trusted'):
                with self.assertRaises(FileNotFoundError):
                    with m.release_lock(): pass
                p = root / 'state/release.lock'; p.write_text('must not truncate'); p.chmod(0o644); ino = p.stat().st_ino
                with m.release_lock():
                    self.assertEqual(p.read_text(), 'must not truncate')
                self.assertEqual(ino, p.stat().st_ino)

    def test_attempting_second_lock_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); root.chmod(0o755); (root / 'state').mkdir(); (root / 'state').chmod(0o755); (root / 'state/release.lock').touch(); (root / 'state/release.lock').chmod(0o644)
            with patch.object(m, 'ROOT', root), patch.object(m, 'account', return_value=SimpleNamespace(pw_uid=os.getuid(),pw_gid=os.getgid())), patch.object(m,'trusted'):
                with m.release_lock():
                    with self.assertRaises(BlockingIOError):
                        with m.release_lock(): pass

    def test_absent_canonical_lock_created_only_for_apply_with_deploy_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);root.chmod(0o755);(root/'state').mkdir();(root/'state').chmod(0o755)
            user=SimpleNamespace(pw_uid=os.getuid(),pw_gid=os.getgid())
            with patch.object(m,'ROOT',root),patch.object(m,'account',return_value=user),patch.object(m,'trusted'):
                self.assertIsNone(m.lock_info());self.assertFalse((root/'state/release.lock').exists())
                previous=os.umask(0o077)
                try:
                    with m.release_lock(create=True):
                        path=root/'state/release.lock';st=path.stat()
                        self.assertEqual((st.st_uid,st.st_gid,st.st_mode & 0o777),(os.getuid(),os.getgid(),0o644))
                        first=st.st_ino
                finally:os.umask(previous)
                with m.release_lock(create=True):self.assertEqual((root/'state/release.lock').stat().st_ino,first)

    def test_existing_lock_symlink_and_wrong_mode_are_not_repaired(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);root.chmod(0o755);(root/'state').mkdir();(root/'state').chmod(0o755)
            path=root/'state/release.lock';path.write_text('preserve');path.chmod(0o600)
            with patch.object(m,'ROOT',root),patch.object(m,'account',return_value=SimpleNamespace(pw_uid=os.getuid(),pw_gid=os.getgid())),patch.object(m,'trusted'):
                with self.assertRaises(ValueError):
                    with m.release_lock(create=True):pass
                self.assertEqual(path.stat().st_mode & 0o777,0o600)
                path.unlink();path.symlink_to(root/'missing')
                with self.assertRaises(ValueError):
                    with m.release_lock(create=True):pass
                self.assertTrue(path.is_symlink())

    def test_absent_backup_parent_is_read_only_until_apply_and_umask_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);backups=base/'backups'/'aifinance-collect-only'
            real_stat=Path.stat
            def root_group(path,*args,**kwargs):
                values=list(real_stat(path,*args,**kwargs));values[5]=0;return os.stat_result(values)
            with patch.object(m,'BACKUPS',backups),patch.object(m,'trusted'),patch.object(m.os,'fchown'),patch.object(m.Path,'stat',root_group):
                self.assertFalse(m.backup_parent());self.assertFalse(backups.parent.exists())
                previous=os.umask(0o077)
                try:self.assertTrue(m.backup_parent(create=True))
                finally:os.umask(previous)
                self.assertEqual(backups.parent.stat().st_mode & 0o777,0o755)
                self.assertFalse(backups.exists())
                backups.parent.chmod(0o700)
                with self.assertRaises(ValueError):m.backup_parent(create=True)
                self.assertEqual(backups.parent.stat().st_mode & 0o777,0o700)

    def test_default_check_cannot_apply_stage_or_start(self):
        with patch.object(m, 'preflight', return_value={}) as preflight, patch.object(m, 'apply') as apply, patch.object(m, 'stage') as stage, patch.object(m, 'restore_child') as restore, patch('sys.stdout', new_callable=io.StringIO) as out:
            m.main(['--archive-sha256','f'*64])
            preflight.assert_called_once_with('f'*64); apply.assert_not_called(); stage.assert_not_called(); restore.assert_not_called()
            self.assertFalse(json.loads(out.getvalue())['changed'])
            self.assertFalse(json.loads(out.getvalue())['readyForApply'])

    def test_privileged_stage_is_refused_before_archive(self):
        with patch.object(m.os, 'geteuid', return_value=0), patch.object(m, 'account', return_value=SimpleNamespace(pw_uid=900)), patch.object(m, 'archive_check') as check:
            with self.assertRaises(ValueError): m.stage('f'*64)
            check.assert_not_called()

    def test_unknown_role_attributes_and_memberships_fail(self):
        for values in [['t|t|f|f|t|f|f|6||'], ['f|t|f|f|t|f|f|6||','1'], ['f|t|f|f|t|f|f|6||','0','1']]:
            with self.assertRaises(ValueError): m.database_metadata(iter(values).__next__ if False else lambda q, v=iter(values): next(v))

    def test_unit_digests_are_reviewed_templates(self):
        for name, digest in m.UNIT_DIGESTS.items():
            self.assertEqual(m.digest((REPO / 'deploy/native' / name).read_bytes()), digest)

    def test_new_write_cannot_overwrite_or_follow_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory)/'receipt'; m.write_new(p,b'first')
            with self.assertRaises(FileExistsError): m.write_new(p,b'second')
            self.assertEqual(p.read_bytes(),b'first')
            link=Path(directory)/'link';link.symlink_to(p)
            with self.assertRaises(FileExistsError):m.write_new(link,b'bad')

    def test_restore_completed_without_resource_sample_fails(self):
        with patch.object(m,'prop',return_value='inactive'):
            with self.assertRaisesRegex(ValueError,'resource_verified'):m.wait_restore('fixture.service')

    def test_root_snapshot_parent_traversable_under_private_umask(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root/'incoming').mkdir()
            (root/'incoming'/(m.NEW+'.tar.gz')).write_bytes(b'fixture')
            with patch.object(m,'ROOT',root), patch.object(m,'ARTIFACTS',root/'artifacts'), patch.object(m,'trusted'):
                previous = os.umask(0o077)
                try:
                    target = m.snapshot_archive(m.digest(b'fixture'))
                finally:
                    os.umask(previous)
                self.assertEqual((root/'artifacts').stat().st_mode & 0o777,0o755)
                self.assertEqual(target.stat().st_mode & 0o777,0o444)
                self.assertEqual(target.read_bytes(),b'fixture')
                with self.assertRaises(ValueError):m.snapshot_archive(m.digest(b'fixture'))

    def test_wrong_copied_archive_stays_unpublished(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'incoming').mkdir();(root/'incoming'/(m.NEW+'.tar.gz')).write_bytes(b'fixture')
            with patch.object(m,'ROOT',root),patch.object(m,'ARTIFACTS',root/'artifacts'),patch.object(m,'trusted'):
                with self.assertRaisesRegex(ValueError,'copied_archive_digest'):
                    m.snapshot_archive('0'*64)
                self.assertEqual((root/'artifacts'/(m.NEW+'.tar.gz')).stat().st_mode & 0o777,0o400)

    def test_seal_never_uses_path_chmod_or_follows_file_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);release=root/'release';release.mkdir();(release/'nested').mkdir();(release/'nested/file').write_text('x');(release/'link').symlink_to('nested/file')
            with patch.object(m.os,'fchown'),patch.object(m.os,'chown'),patch.object(m.Path,'chmod',side_effect=AssertionError('path chmod forbidden')):
                m.seal_release(release)
            self.assertEqual((release/'nested').stat().st_mode & 0o777,0o555)
            self.assertEqual((release/'nested/file').stat().st_mode & 0o777,0o444)
            # Restore fixture write permissions only for tempfile cleanup.
            os.chmod(str(release),0o700);os.chmod(str(release/'nested'),0o700)

    def test_service_exited_does_not_assume_cgroup_survives(self):
        states=iter(['activating','active'])
        def prop(unit,key):
            if key=='ActiveState':return next(states)
            return {'SubState':'exited','Result':'success','ExecMainStatus':'0'}[key]
        with patch.object(m,'prop',side_effect=prop),patch.object(m,'resource_sample',return_value={'sample':'actual'}),patch.object(m.time,'sleep'),patch.object(m.Path,'read_text',side_effect=AssertionError('pruned cgroup')):
            self.assertEqual(m.wait_restore('fixture.service'),{'sample':'actual'})

    def test_no_generic_migration_or_ready_write(self):
        source=(REPO / 'deploy/native/collect-only-upgrade.py').read_text()
        self.assertNotIn("'scripts/migrate.ts'",source)
        self.assertNotIn("'native-ready').open",source)
        self.assertNotIn("'rollback'",source)
        self.assertIn("'PrivateNetwork=yes'",source)
        self.assertIn("'RestrictAddressFamilies=AF_UNIX'",source)
        self.assertIn('InaccessiblePaths=/etc/aifinance-preview.env',source)


if __name__ == '__main__': unittest.main()
