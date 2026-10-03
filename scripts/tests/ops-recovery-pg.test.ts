// Real PostgreSQL 17 coverage of the broker's pre-seed proof. The fixed
// database/role may only be created inside the verified disposable CI service.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';

const container = process.env.UPGRADE_TEST_POSTGRES_CONTAINER;
const database = 'aifinance_preview';
const expected = { database_ok: true, role_ok: true, role_safe: true, migration_ok: true,
  other_clients: 0, sources: 0, articles: 0, discoveries: 0, fetch_runs: 0 };

// Capture the production method's payload, and also run its real result
// validation. This never reads a deployment environment file or runs psql.
const python = `
import importlib.util,json,sys,tempfile
from types import SimpleNamespace
spec=importlib.util.spec_from_file_location('broker','deploy/native/ops-broker.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
value=json.load(sys.stdin);captured={}
def capture(args,payload=None,**kwargs):
    captured.update(sql=payload,args=args,options=kwargs['env']['PGOPTIONS'])
    return json.dumps(value)
m.bounded_command=capture
broker=m.Broker.__new__(m.Broker)
broker.r=SimpleNamespace(database_url=lambda raw:raw.split('=',1)[1].strip())
with tempfile.TemporaryFile() as f:
    f.write(b'DATABASE_URL=postgres://aifinance_preview:ci-fixture@127.0.0.1:55432/aifinance_preview\\n');f.flush()
    try:
        captured['result']=broker.sql_proof(f.fileno(),SimpleNamespace(pw_uid=1000,pw_gid=1000))
        captured['accepted']=True
    except m.Refused as error:
        captured.update(accepted=False,reason=error.reason)
print(json.dumps(captured))
`;

function broker(result: unknown) {
  return JSON.parse(execFileSync('python3', ['-B', '-c', python], {
    input: JSON.stringify(result), encoding: 'utf8', timeout: 5_000,
  })) as { sql: string; args: string[]; options: string; accepted: boolean; reason?: string; result?: typeof expected };
}

test('broker recovery proves zero side effects using actual nonsuperuser PostgreSQL 17',
  { skip: !container, timeout: 120_000 }, () => {
    assert.match(container!, /^[a-f0-9]{12,64}$/);
    const connection = new URL(process.env.DATABASE_URL!);
    assert.equal(connection.protocol, 'postgres:');
    assert.equal(connection.hostname, '127.0.0.1');
    assert.equal(connection.port, '5432');
    assert.equal(connection.pathname, '/aihot_ci');
    assert.equal(connection.username, 'postgres');
    assert.equal(connection.search, '');
    assert.equal(connection.hash, '');
    // Ignore alternate Docker contexts/hosts and all inherited PostgreSQL env.
    const env = { PATH: process.env.PATH!, HOME: '/tmp', LANG: 'C', LC_ALL: 'C' };
    function docker(args: string[], input?: string) {
      return execFileSync('docker', args, { input, encoding: 'utf8', env,
        timeout: 30_000, maxBuffer: 16 * 1024 * 1024 }).trim();
    }
    const identity = JSON.parse(docker(['inspect', '--format',
      '{"id":{{json .Id}},"image":{{json .Config.Image}},"running":{{json .State.Running}},"ports":{{json .NetworkSettings.Ports}}}', container!]));
    assert.ok(identity.id.startsWith(container!));
    assert.equal(identity.image, 'postgres:17-alpine');
    assert.equal(identity.running, true);
    assert.ok(identity.ports['5432/tcp'].some((port: { HostPort: string }) => port.HostPort === '5432'));

    function query(sql: string, role = database, db = database, readOnly = false) {
      return docker(['exec', '-i', ...(readOnly ? ['--env', 'PGOPTIONS=-c default_transaction_read_only=on'] : []),
        container!, 'psql', '-X', '-w', '-q', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-U', role, '-d', db], sql);
    }
    const admin = (sql: string) => query(sql, 'postgres', 'aihot_ci');
    const server = JSON.parse(admin("SELECT json_build_object('database',current_database(),'role',current_user,'version',current_setting('server_version_num')::int)"));
    assert.equal(server.database, 'aihot_ci');
    assert.equal(server.role, 'postgres');
    assert.equal(Math.floor(server.version / 10000), 17);
    assert.equal(admin("SELECT count(*) FROM pg_database WHERE datname='aifinance_preview'"), '0', 'refuse an existing database');
    assert.equal(admin("SELECT count(*) FROM pg_roles WHERE rolname='aifinance_preview'"), '0', 'refuse an existing role');

    const captured = broker(expected);
    assert.equal(captured.accepted, true);
    assert.deepEqual(captured.result, expected);
    assert.equal(captured.options, '-c default_transaction_read_only=on');
    assert.deepEqual(captured.args, ['/usr/pgsql-17/bin/psql', '-X', '-w', '-q', '-A', '-t', '-v', 'ON_ERROR_STOP=1',
      '-h', '127.0.0.1', '-p', '55432', '-U', database, '-d', database]);
    const sql = captured.sql;
    let roleMade = false, databaseMade = false;
    try {
      admin('CREATE ROLE aifinance_preview LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS');
      roleMade = true;
      admin('CREATE DATABASE aifinance_preview OWNER aifinance_preview TEMPLATE template0');
      databaseMade = true;
      query('CREATE EXTENSION pg_trgm', 'postgres');
      assert.deepEqual(JSON.parse(query("SELECT json_build_array(current_database(),current_user)")), [database, database]);
      query('CREATE TABLE public.schema_migrations(name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())');
      const names = readdirSync('database/migrations').filter(name => name.endsWith('.sql') && name <= '0041_collect_only.sql').sort();
      assert.equal(names.length, 38);
      for (const name of names) {
        assert.match(name, /^\d{4}_[a-z0-9_]+\.sql$/);
        query(readFileSync(`database/migrations/${name}`, 'utf8') + `\nINSERT INTO public.schema_migrations(name) VALUES ('${name}');`);
      }
      query("INSERT INTO public.sources(id,name,kind,enabled,site_fulltext) VALUES ('untouched','Keep source','rss',false,false); " +
        "INSERT INTO public.articles(id,source_id,identity_key,url,title,discovered_at,timeline_at) VALUES ('untouched','untouched','untouched','https://example.invalid/item','Keep exact article',now(),now()); " +
        "INSERT INTO public.article_discoveries(article_id,source_id,via) VALUES ('untouched','untouched','fixture'); " +
        "INSERT INTO public.fetch_runs(source_id,status) VALUES ('untouched','ok');");

      // Snapshot every real table's rows, plus relation/column identities, not
      // just the proof's counts. Expected refusals must also leave them intact.
      const tables = JSON.parse(query("SELECT json_agg(tablename ORDER BY tablename) FROM pg_tables WHERE schemaname='public'")) as string[];
      for (const table of tables) assert.match(table, /^[a-z_][a-z0-9_]*$/);
      const rowsSql = tables.map(table => `SELECT '${table}' AS name, (SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb) FROM public.${table} t) AS rows`).join(' UNION ALL ');
      function snapshot() {
        return JSON.parse(query("SELECT jsonb_build_object('rows',(SELECT jsonb_object_agg(name,rows) FROM (" + rowsSql + ") t)," +
          "'relations',(SELECT jsonb_agg(to_jsonb(c) ORDER BY c.oid) FROM (SELECT c.oid,c.relname,c.relkind,c.relowner,c.relacl,c.relrowsecurity,c.relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public') c)," +
          "'columns',(SELECT jsonb_agg(to_jsonb(a) ORDER BY a.attrelid,a.attnum) FROM (SELECT a.attrelid,a.attnum,a.attname,a.atttypid,a.attnotnull,a.attidentity,a.attgenerated FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND a.attnum>0 AND NOT a.attisdropped) a))"));
      }
      function proof(overrides: Partial<typeof expected> = {}, prefix = '', role = database) {
        const before = snapshot();
        const result = JSON.parse(query(prefix + sql, role, database, !prefix));
        assert.deepEqual(result, { ...expected, ...overrides });
        const validated = broker(result);
        const accepted = Object.keys(overrides).length === 0;
        assert.equal(validated.accepted, accepted);
        if (!accepted) assert.equal(validated.reason, 'pre_seed_database_proof_failed');
        assert.deepEqual(snapshot(), before, 'proof must preserve all prior data and table definitions');
      }
      proof(); // Existing unrelated rows do not prevent recovery.
      const original = snapshot();

      query("UPDATE public.sources SET collect_only=true,participation_mode='isolated' WHERE id='untouched'");
      proof({ sources: 1 });
      query("UPDATE public.sources SET collect_only=false,participation_mode='editorial' WHERE id='untouched'");
      query("UPDATE public.articles SET collect_only=true WHERE id='untouched'");
      proof({ articles: 1 });
      query("UPDATE public.articles SET collect_only=false WHERE id='untouched'");

      const fixedIds = ['collect-dynamics-finance', 'collect-journal-accountancy', 'collect-accounting-today'];
      for (const id of fixedIds) {
        // Discoveries can survive without a corresponding fixed source row.
        query(`INSERT INTO public.article_discoveries(article_id,source_id,via) VALUES ('untouched','${id}','fixture')`);
        proof({ discoveries: 1 });
        query(`INSERT INTO public.sources(id,name,kind,enabled,site_fulltext) VALUES ('${id}','Fixed fixture','rss',false,false); ` +
          `INSERT INTO public.articles(id,source_id,identity_key,url,title,discovered_at,timeline_at) VALUES ('fixed-fixture','${id}','fixed-fixture','https://example.invalid/fixed','Fixed material',now(),now()); ` +
          `INSERT INTO public.fetch_runs(source_id,status) VALUES ('${id}','ok');`);
        proof({ sources: 1, articles: 1, discoveries: 1, fetch_runs: 1 });
        query("DELETE FROM public.articles WHERE id='fixed-fixture'; " +
          `DELETE FROM public.article_discoveries WHERE source_id='${id}'; DELETE FROM public.sources WHERE id='${id}';`);
      }
      assert.deepEqual(snapshot(), original);

      query('CREATE SCHEMA aifinance_preview');
      const guardedTables = ['schema_migrations', 'sources', 'articles', 'article_discoveries', 'fetch_runs'];
      for (const table of guardedTables) query(`CREATE TABLE aifinance_preview.${table} (LIKE public.${table} INCLUDING DEFAULTS)`);
      query("INSERT INTO aifinance_preview.schema_migrations(name) VALUES ('0041_collect_only.sql'); UPDATE public.articles SET collect_only=true WHERE id='untouched'");
      const shadows = guardedTables.map(table => `CREATE TEMP TABLE ${table} (LIKE public.${table} INCLUDING DEFAULTS);`).join(' ') +
        " INSERT INTO pg_temp.schema_migrations(name) VALUES ('0041_collect_only.sql'); SET search_path=aifinance_preview,public; ";
      proof({ articles: 1 }, shadows);
      query("UPDATE public.articles SET collect_only=false WHERE id='untouched'");

      const beforeWrite = snapshot();
      assert.match(sql, /COMMIT;$/);
      assert.throws(() => query(sql.replace(/COMMIT;$/, "UPDATE public.articles SET title='forbidden mutation'; COMMIT;"), database, database, true),
        /cannot execute UPDATE in a read-only transaction/);
      assert.deepEqual(snapshot(), beforeWrite);

      admin('ALTER ROLE aifinance_preview CREATEDB');
      try { proof({ role_safe: false }); } finally { admin('ALTER ROLE aifinance_preview NOCREATEDB'); }
      proof({ role_ok: false, role_safe: false }, '', 'postgres');

      query('ALTER TABLE public.fetch_runs OWNER TO postgres', 'postgres');
      try {
        assert.throws(() => query(sql, database, database, true), /unreviewed_relations/);
      } finally { query('ALTER TABLE public.fetch_runs OWNER TO aifinance_preview', 'postgres'); }
      // An owner with FORCE RLS must fail closed, never count hidden rows as zero.
      query("UPDATE public.articles SET collect_only=true WHERE id='untouched'; ALTER TABLE public.articles ENABLE ROW LEVEL SECURITY; ALTER TABLE public.articles FORCE ROW LEVEL SECURITY; CREATE POLICY hide_all ON public.articles USING (false)");
      try {
        assert.throws(() => query(sql, database, database, true), /row-level security policy/);
      } finally {
        query('ALTER TABLE public.articles NO FORCE ROW LEVEL SECURITY; ALTER TABLE public.articles DISABLE ROW LEVEL SECURITY; DROP POLICY hide_all ON public.articles');
        query("UPDATE public.articles SET collect_only=false WHERE id='untouched'");
      }
      proof();
      assert.deepEqual(snapshot(), original);
    } finally {
      // Only remove objects successfully created by this test. In particular,
      // an existing database/role fails before entering this cleanup scope.
      if (databaseMade) admin('DROP DATABASE aifinance_preview');
      if (roleMade) admin('DROP ROLE aifinance_preview');
    }
  });
