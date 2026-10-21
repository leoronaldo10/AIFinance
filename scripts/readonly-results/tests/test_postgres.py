"""Disposable local PostgreSQL only. Set PG_BIN and PG_SHARE; never uses DATABASE_URL."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from result_common import SOURCES, validate

BIN = Path(os.environ.get('PG_BIN', '/nonexistent'))
SQL = (Path(__file__).resolve().parents[1] / 'retry002.sql').read_text()


@unittest.skipUnless((BIN / 'initdb').is_file(), 'PG_BIN required for disposable PostgreSQL integration')
class PostgresTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='aifinance-results-test-')
        cls.root = Path(cls.temp.name); cls.sock = cls.root / 'socket'; cls.sock.mkdir()
        cls.data = cls.root / 'data'
        def run(args):
            return subprocess.run(args, check=True, capture_output=True, timeout=30)
        cls.run_command = staticmethod(run)
        run([str(BIN / 'initdb'), '-D', str(cls.data), '-L', os.environ['PG_SHARE'],
             '-U', 'postgres', '--auth-local=trust', '--no-locale'])
        run([str(BIN / 'pg_ctl'), '-D', str(cls.data), '-l', str(cls.root / 'log'),
             '-o', '-h "" -k ' + str(cls.sock) + ' -p 56444', '-w', 'start'])
        cls.database = 'postgres'
        cls.sql('CREATE DATABASE aifinance_preview_test')
        cls.database = 'aifinance_preview_test'
        cls.sql("""CREATE TABLE sources(id text PRIMARY KEY,name text,enabled boolean DEFAULT false,
          collect_only boolean DEFAULT true,participation_mode text DEFAULT 'isolated');
          CREATE TABLE articles(id text,title text,source_id text,url text,published_at timestamptz,
          discovered_at timestamptz,created_at timestamptz,excerpt text,body_text text,
          collect_only boolean DEFAULT true,processing_state text DEFAULT 'skipped',revision int DEFAULT 1);
          CREATE TABLE fetch_runs(source_id text,started_at timestamptz,status text,new_count int,found_count int,detail jsonb);""")

    @classmethod
    def tearDownClass(cls):
        cls.run_command([str(BIN / 'pg_ctl'), '-D', str(cls.data), '-m', 'fast', '-w', 'stop'])
        cls.temp.cleanup()

    @classmethod
    def sql(cls, query):
        env = {'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'LANG': 'C.UTF-8',
               'PGPASSFILE': '/dev/null/aifinance-readonly.pgpass'}
        p = subprocess.run([str(BIN / 'psql'), '-XwqAt', '-h', str(cls.sock), '-p', '56444',
                            '-U', 'postgres', '-d', cls.database, '-v', 'ON_ERROR_STOP=1'],
                           input=query.encode(), capture_output=True, timeout=15, env=env)
        if p.returncode:
            raise RuntimeError('disposable fixture SQL failed: ' + p.stderr.decode())
        if p.stderr:
            raise AssertionError('unexpected local SQL warning')
        return p.stdout

    def setUp(self):
        self.sql('TRUNCATE articles,sources,fetch_runs;')
        for i, (source, hosts) in enumerate(SOURCES.items()):
            self.sql(f"""INSERT INTO sources(id,name) VALUES('{source}','Public source');
              INSERT INTO fetch_runs VALUES('{source}',to_timestamp(1700000100),'ok',1,
              {20 if source=='collect-journal-accountancy' else 10},
              '{{"collectOnly":true,"processed":1,"revised":0}}');
              INSERT INTO articles(id,title,source_id,url,discovered_at,created_at,excerpt,body_text)
              VALUES('round-{i}','Public title','{source}','https://{hosts[-1]}/article',
              to_timestamp(1700000101),to_timestamp(1700000100),'Public summary','password=must_not_export');""")

    def result(self):
        query = SQL.replace('__LOWER_EPOCH__', '1700000000').replace('__UPPER_EPOCH__', '1700000200')
        # Same fixed query, binding only the database guard to the disposable _test database.
        query = query.replace("current_database()='aifinance_preview'", "current_database()='aifinance_preview_test'")
        return json.loads(self.sql(query))

    def test_exact_batch_not_newest_and_no_body(self):
        self.sql("INSERT INTO articles SELECT 'later-'||id,title,source_id,url,published_at,discovered_at,to_timestamp(1700000300),excerpt,body_text,collect_only,processing_state,revision FROM articles")
        result = self.result(); validate(result)
        self.assertEqual({a['id'] for a in result['articles']}, {'round-0','round-1','round-2'})
        self.assertNotIn('must_not_export', json.dumps(result))

    def test_changed_article(self):
        self.sql("UPDATE articles SET revision=2 WHERE id='round-0'")
        self.assertEqual(self.result(), {'refused': True})

    def test_ambiguous_batch(self):
        self.sql('INSERT INTO fetch_runs SELECT source_id,to_timestamp(1700000150),status,new_count,found_count,detail FROM fetch_runs')
        self.assertEqual(self.result(), {'refused': True})

    def test_unexpected_fourth_article(self):
        self.sql("INSERT INTO articles SELECT 'extra',title,source_id,url,published_at,discovered_at,created_at,excerpt,body_text,collect_only,processing_state,2 FROM articles WHERE id='round-0'")
        self.assertEqual(self.result(), {'refused': True})

    def test_source_enabled_or_wrong_counts(self):
        self.sql('UPDATE sources SET enabled=true')
        self.assertEqual(self.result(), {'refused': True})
        self.sql('UPDATE sources SET enabled=false; UPDATE fetch_runs SET found_count=99')
        self.assertEqual(self.result(), {'refused': True})

    def test_missing_summary_allowed_oversize_refused(self):
        self.sql('UPDATE articles SET excerpt=NULL')
        self.assertEqual({a['summary'] for a in self.result()['articles']}, {''})
        self.sql("UPDATE articles SET excerpt=repeat('x',25000)")
        self.assertEqual(self.result(), {'refused': True})

    def test_transaction_blocks_writes_and_count_one(self):
        self.assertNotIn('count(*)', SQL)
        with self.assertRaises(RuntimeError): self.sql("BEGIN READ ONLY; INSERT INTO sources(id) VALUES('forbidden'); ROLLBACK;")
