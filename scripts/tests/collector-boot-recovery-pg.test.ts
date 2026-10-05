// Execute the controller's captured SQL on real PostgreSQL 17, never a target
// deployment. Use the verified CI service, or create an exclusive local cluster.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import { createServer } from 'node:net';

const container = process.env.UPGRADE_TEST_POSTGRES_CONTAINER;
const localBin = process.env.COLLECTOR_BOOT_TEST_PG17_BIN;
const database = 'aifinance_preview';
const expectedProof = { database_ok: true, role_ok: true, role_safe: true, migration_ok: true,
  other_clients: 0, sources: 0, articles: 0, discoveries: 0, fetch_runs: 0 };
const countedTables = ['articles', 'article_revisions', 'analyses', 'receipts', 'editorial_overrides',
  'editorial_review_state', 'editorial_versions', 'editorial_exports', 'publications', 'deliveries',
  'grouping_decisions', 'pgboss.job'];
type Counts = Record<string, number | null>;
type Captured = { calls: { sql: string; args: string[]; options: string; dropsIdentity: boolean }[];
  accepted: boolean; reason?: string; result?: Counts | typeof expectedProof };

// Import and invoke the real production methods, replacing only subprocess
// execution. Fixture data is supplied through stdin; no deployment env is read.
const capturePython = `
import importlib.util,json,sys,tempfile
from types import SimpleNamespace
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
broker=module('broker','deploy/native/ops-broker.py')
boot=module('boot','deploy/native/recover-collector-after-boot.py')
request=json.load(sys.stdin);captured={'calls':[]}
def command(args,payload=None,**kwargs):
    captured['calls'].append(dict(sql=payload,args=args,options=kwargs['env']['PGOPTIONS'],dropsIdentity=callable(kwargs['drop'])))
    if request['mode']=='counts' and len(captured['calls'])==1:return request['present']
    return json.dumps(request['result'])
broker.bounded_command=command
runner=SimpleNamespace(database_url=lambda raw:raw.split('=',1)[1].strip())
user=SimpleNamespace(pw_uid=1000,pw_gid=1000)
with tempfile.TemporaryFile() as f:
    f.write(b'DATABASE_URL=postgres://aifinance_preview:local-fixture@127.0.0.1:55432/aifinance_preview\\n');f.flush()
    try:
        if request['mode']=='proof':
            worker=broker.Broker.__new__(broker.Broker);worker.r=runner
            captured['result']=worker.sql_proof(f.fileno(),user)
        else:
            recovery=boot.Recovery.__new__(boot.Recovery)
            recovery.b=broker;recovery.r=runner;recovery.user=user;recovery.db_fd=f.fileno()
            captured['result']=recovery.counts()
        captured['accepted']=True
    except (broker.Refused,boot.Refused) as error:
        captured.update(accepted=False,reason=getattr(error,'reason',str(error)))
print(json.dumps(captured))
`;

function capture(mode: 'proof' | 'counts', result: unknown, present = 'f'): Captured {
  return JSON.parse(execFileSync('python3', ['-B', '-c', capturePython], {
    input: JSON.stringify({ mode, result, present }), encoding: 'utf8', timeout: 5_000,
  }));
}

test('collector boot rearm SQL preserves all rows and refuses unsafe real PG17 sessions',
  { skip: !container && !localBin, timeout: 120_000 }, async t => {
    assert.ok(!(container && localBin), 'select exactly one disposable fixture');
    const cleanEnv = { PATH: process.env.PATH!, HOME: '/tmp', LANG: 'C', LC_ALL: 'C' };
    function command(binary: string, args: string[], input?: string, env = cleanEnv) {
      return execFileSync(binary, args, { input, env, encoding: 'utf8', timeout: 30_000,
        maxBuffer: 16 * 1024 * 1024, stdio: ['pipe', 'pipe', 'pipe'] }).trim();
    }
    let directory: string | undefined;
    let started = false, roleMade = false, databaseMade = false;
    let query: (sql: string, role?: string, db?: string, readOnly?: boolean) => string;
    let stop = () => {};
    const adminDatabase = container ? 'aihot_ci' : 'postgres';
    try {
      if (container) {
        assert.match(container, /^[a-f0-9]{12,64}$/);
        const connection = new URL(process.env.DATABASE_URL!);
        assert.equal(connection.protocol, 'postgres:');
        assert.equal(connection.hostname, '127.0.0.1');
        assert.equal(connection.port, '5432');
        assert.equal(connection.pathname, '/aihot_ci');
        assert.equal(connection.username, 'postgres');
        assert.equal(connection.search, '');
        assert.equal(connection.hash, '');
        const identity = JSON.parse(command('docker', ['inspect', '--format',
          '{"id":{{json .Id}},"image":{{json .Config.Image}},"running":{{json .State.Running}},"ports":{{json .NetworkSettings.Ports}}}', container]));
        assert.ok(identity.id.startsWith(container));
        assert.equal(identity.image, 'postgres:17-alpine');
        assert.equal(identity.running, true);
        assert.ok(identity.ports['5432/tcp'].some((port: { HostPort: string }) => port.HostPort === '5432'));
        query = (sql, role = database, db = database, readOnly = false) => command('docker', ['exec', '-i',
          ...(readOnly ? ['--env', 'PGOPTIONS=-c default_transaction_read_only=on'] : []), container,
          'psql', '-X', '-w', '-q', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-U', role, '-d', db], sql);
      } else {
        assert.ok(isAbsolute(localBin!), 'local binaries must have an explicit absolute path');
        const localEnv = { ...cleanEnv, ...(process.env.COLLECTOR_BOOT_TEST_PG17_LIB ?
          { LD_LIBRARY_PATH: process.env.COLLECTOR_BOOT_TEST_PG17_LIB } : {}) };
        assert.match(command(join(localBin!, 'postgres'), ['--version'], undefined, localEnv), /PostgreSQL\) 17\./);
        directory = mkdtempSync('/tmp/collector-boot-pg17-');
        const data = join(directory, 'data'), socket = join(directory, 'socket');
        mkdirSync(socket, { mode: 0o700 });
        // Some sandboxes prohibit Unix sockets. This explicit local-fixture
        // option binds only loopback, on a newly allocated ephemeral port.
        const tcp = process.env.COLLECTOR_BOOT_TEST_TCP === '1';
        let port = 55432;
        if (tcp) {
          const reservation = createServer();
          await new Promise<void>((resolve, reject) => { reservation.once('error', reject); reservation.listen(0, '127.0.0.1', resolve); });
          const address = reservation.address(); assert.ok(address && typeof address !== 'string'); port = address.port;
          await new Promise<void>((resolve, reject) => reservation.close(error => error ? reject(error) : resolve()));
        }
        const pg = (binary: string, args: string[], input?: string) => command(join(localBin!, binary), args, input, localEnv);
        pg('initdb', ['-D', data, '-U', 'postgres', '--encoding=UTF8', '--locale=C',
          '--auth-local=trust', tcp ? '--auth-host=trust' : '--auth-host=reject', '--no-instructions']);
        writeFileSync(join(data, 'postgresql.auto.conf'), `listen_addresses='${tcp ? '127.0.0.1' : ''}'\nport=${port}\n` +
          `unix_socket_directories='${tcp ? '' : socket}'\nunix_socket_permissions=0700\nshared_buffers='16MB'\nmax_connections=12\n`);
        stop = () => { pg('pg_ctl', ['-D', data, '-w', '-m', 'fast', 'stop']); started = false; };
        try {
          pg('pg_ctl', ['-D', data, '-l', join(directory, 'server.log'), '-w', 'start']); started = true;
        } catch (error) {
          try { pg('pg_ctl', ['-D', data, 'status']); started = true; } catch { /* Never started. */ }
          throw new Error(readFileSync(join(directory, 'server.log'), 'utf8'), { cause: error });
        }
        query = (sql, role = database, db = database, readOnly = false) => command(join(localBin!, 'psql'),
          ['-X', '-w', '-q', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-h', tcp ? '127.0.0.1' : socket, '-p', String(port), '-U', role, '-d', db],
          sql, { ...localEnv, ...(readOnly ? { PGOPTIONS: '-c default_transaction_read_only=on' } : {}) });
      }
      const admin = (sql: string) => query(sql, 'postgres', adminDatabase);
      const server = JSON.parse(admin("SELECT json_build_object('database',current_database(),'role',current_user,'version',current_setting('server_version_num')::int)"));
      assert.equal(server.database, adminDatabase);
      assert.equal(server.role, 'postgres');
      assert.equal(Math.floor(server.version / 10000), 17);
      assert.equal(admin("SELECT count(*) FROM pg_database WHERE datname='aifinance_preview'"), '0', 'refuse an existing database');
      assert.equal(admin("SELECT count(*) FROM pg_roles WHERE rolname='aifinance_preview'"), '0', 'refuse an existing role');
      admin('CREATE ROLE aifinance_preview LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'); roleMade = true;
      admin('CREATE DATABASE aifinance_preview OWNER aifinance_preview TEMPLATE template0'); databaseMade = true;
      query('CREATE EXTENSION pg_trgm', 'postgres');
      assert.deepEqual(JSON.parse(query("SELECT json_build_array(current_database(),current_user,(SELECT rolsuper FROM pg_roles WHERE rolname=current_user),current_setting('transaction_read_only'),(SELECT count(*) FROM pg_auth_members WHERE member=current_user::regrole))", database, database, true)),
        [database, database, false, 'on', 0]);
      query('CREATE TABLE public.schema_migrations(name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())');
      const migrations = readdirSync('database/migrations').filter(name => name.endsWith('.sql') && name <= '0041_collect_only.sql').sort();
      assert.equal(migrations.length, 38);
      for (const name of migrations) {
        assert.match(name, /^\d{4}_[a-z0-9_]+\.sql$/);
        query(readFileSync(`database/migrations/${name}`, 'utf8') + `\nINSERT INTO public.schema_migrations(name) VALUES ('${name}');`);
      }
      query(`
        INSERT INTO public.sources(id,name,kind,enabled,site_fulltext) VALUES ('untouched','Keep source','rss',false,false);
        INSERT INTO public.articles(id,source_id,identity_key,url,title,discovered_at,timeline_at)
          VALUES ('untouched','untouched','untouched','https://example.invalid/item','Keep exact article',now(),now());
        INSERT INTO public.article_discoveries(article_id,source_id,via) VALUES ('untouched','untouched','fixture');
        INSERT INTO public.fetch_runs(source_id,status) VALUES ('untouched','ok');
        INSERT INTO public.article_revisions(article_id,revision,title) VALUES ('untouched',1,'Keep revision');
        INSERT INTO public.analyses(article_id,input_revision,origin) VALUES ('untouched',1,'rule');
        INSERT INTO public.receipts(logical_key,service,purpose,status) VALUES ('untouched','fixture','preserve','completed');
        INSERT INTO public.editorial_overrides(article_id,fields) VALUES ('untouched','{"keep":true}');
        INSERT INTO public.editorial_review_state(article_id) VALUES ('untouched');
        INSERT INTO public.editorial_versions(article_id,version,copy,evidence,actor) VALUES ('untouched',1,'{}','{}','fixture');
        INSERT INTO public.editorial_exports(title,article_versions,html,markdown,actor) VALUES ('Keep export','[]','Keep HTML','Keep markdown','fixture');
        INSERT INTO public.publications(article_id,title,source_id,channel,url,discovered_at,timeline_at,sort_at)
          VALUES ('untouched','Keep publication','untouched','news','https://example.invalid/item',now(),now(),now());
        INSERT INTO public.notify_targets(key,purpose,kind) VALUES ('fixture','content','log');
        INSERT INTO public.deliveries(target_key,subject_kind,subject_id,dedupe_key,status) VALUES ('fixture','article','untouched','fixture','skipped');
        INSERT INTO public.grouping_decisions(article_id,verdict) VALUES ('untouched','Keep decision');
      `);

      function snapshot() {
        const relations = JSON.parse(query("SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY r.oid),'[]') FROM (SELECT c.oid,n.nspname,c.relname,c.relkind,c.relowner,c.relacl,c.relrowsecurity,c.relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('public','pgboss')) r", 'postgres')) as { oid: number; nspname: string; relname: string; relkind: string }[];
        const rowQueries = relations.filter(r => ['r', 'p', 'S'].includes(r.relkind)).map(relation => {
          assert.match(relation.nspname, /^(public|pgboss)$/); assert.match(relation.relname, /^[a-z_][a-z0-9_]*$/);
          const name = `${relation.nspname}.${relation.relname}`;
          const source = relation.relkind === 'S' ? `(SELECT last_value,log_cnt,is_called FROM ${name})` : name;
          return `SELECT '${name}' AS name,(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]') FROM ${source} t) AS rows`;
        });
        const rows = JSON.parse(query(`SELECT jsonb_object_agg(name,rows) FROM (${rowQueries.join(' UNION ALL ')}) t`, 'postgres')) as Record<string, unknown>;
        const columns = JSON.parse(query("SELECT jsonb_agg(to_jsonb(a) ORDER BY a.attrelid,a.attnum) FROM (SELECT a.attrelid,a.attnum,a.attname,a.atttypid,a.attnotnull,a.attidentity,a.attgenerated FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('public','pgboss') AND a.attnum>0 AND NOT a.attisdropped) a", 'postgres'));
        return { relations, columns, rows };
      }
      const proofCapture = capture('proof', expectedProof);
      assert.equal(proofCapture.accepted, true);
      assert.deepEqual(proofCapture.result, expectedProof, 'legacy broker proof fields stay unchanged');
      const proofSql = proofCapture.calls[0]!.sql;
      const expectedCounts: Counts = Object.fromEntries(countedTables.map(name => [name, name === 'pgboss.job' ? null : 1]));
      const countsCapture = capture('counts', Object.fromEntries(Object.entries(expectedCounts).filter(([key]) => key !== 'pgboss.job')));
      assert.equal(countsCapture.accepted, true); assert.deepEqual(countsCapture.result, expectedCounts);
      assert.equal(countsCapture.calls.length, 2);
      for (const call of [...proofCapture.calls, ...countsCapture.calls]) {
        assert.equal(call.options, '-c default_transaction_read_only=on'); assert.equal(call.dropsIdentity, true);
        assert.deepEqual(call.args, ['/usr/pgsql-17/bin/psql', '-X', '-w', '-q', '-A', '-t', '-v', 'ON_ERROR_STOP=1',
          '-h', '127.0.0.1', '-p', '55432', '-U', database, '-d', database]);
      }
      const countsSql = countsCapture.calls[1]!.sql;
      function prove(overrides: Partial<typeof expectedProof> = {}) {
        const before = snapshot();
        const value = JSON.parse(query(proofSql, database, database, true));
        assert.deepEqual(value, { ...expectedProof, ...overrides });
        const result = capture('proof', value);
        assert.equal(result.accepted, Object.keys(overrides).length === 0);
        if (!result.accepted) assert.equal(result.reason, 'pre_seed_database_proof_failed');
        assert.deepEqual(snapshot(), before, 'preseed proof preserves rows, sequences, and relations');
      }
      function count(sql = countsSql, expected = expectedCounts, prefix = '') {
        const before = snapshot();
        const present = query(countsCapture.calls[0]!.sql, database, database, true);
        const actual = JSON.parse(query(prefix + sql, database, database, !prefix));
        assert.deepEqual(capture('counts', actual, present).result, expected);
        assert.deepEqual(snapshot(), before, 'broad counts preserve rows, sequences, and relations');
      }
      function refuses(sql: string, error: RegExp, role = database, readOnly = true) {
        const before = snapshot();
        assert.throws(() => query(sql, role, database, readOnly), error);
        assert.deepEqual(snapshot(), before, 'refusal preserves every existing row and relation');
      }
      prove(); count();
      t.diagnostic('actual nonsuperuser app login; 38 migrations; all eleven broad counts contain preserved fixture data');
      const original = snapshot();
      query("UPDATE public.sources SET collect_only=true,participation_mode='isolated' WHERE id='untouched'");
      prove({ sources: 1 });
      query("UPDATE public.sources SET collect_only=false,participation_mode='editorial' WHERE id='untouched'; UPDATE public.articles SET collect_only=true WHERE id='untouched'");
      prove({ articles: 1 });
      query("UPDATE public.articles SET collect_only=false WHERE id='untouched'");
      for (const id of ['collect-dynamics-finance', 'collect-journal-accountancy', 'collect-accounting-today']) {
        query(`INSERT INTO public.article_discoveries(article_id,source_id,via) VALUES ('untouched','${id}','fixture')`);
        prove({ discoveries: 1 });
        query(`INSERT INTO public.sources(id,name,kind,enabled,site_fulltext) VALUES ('${id}','Fixed source','rss',false,false);
          INSERT INTO public.articles(id,source_id,identity_key,url,title,discovered_at,timeline_at) VALUES ('fixed','${id}','fixed','https://example.invalid/fixed','Fixed',now(),now());
          INSERT INTO public.fetch_runs(source_id,status) VALUES ('${id}','ok')`);
        prove({ sources: 1, articles: 1, discoveries: 1, fetch_runs: 1 });
        query(`DELETE FROM public.articles WHERE id='fixed'; DELETE FROM public.article_discoveries WHERE source_id='${id}'; DELETE FROM public.sources WHERE id='${id}'`);
      }
      // Fixture INSERTs advance sequences; all real proof invocations above
      // compare their own before/after snapshots, including sequence state.
      assert.deepEqual(snapshot().rows['public.articles'], original.rows['public.articles']);
      prove(); count();
      t.diagnostic('zero collector sources/articles/discoveries/fetch runs enforced for all three fixed source IDs');

      // A real inherited grant must fail even though legacy role_safe remains
      // true. Counts provides the extra boot-specific no-membership gate.
      admin('CREATE ROLE boot_fixture_parent NOLOGIN; CREATE ROLE boot_fixture_ancestor NOLOGIN; GRANT boot_fixture_ancestor TO boot_fixture_parent; GRANT boot_fixture_parent TO aifinance_preview');
      try { prove(); refuses(countsSql, /unreviewed_relations/); }
      finally { admin('REVOKE boot_fixture_parent FROM aifinance_preview; DROP ROLE boot_fixture_parent; DROP ROLE boot_fixture_ancestor'); }
      refuses(countsSql, /unreviewed_relations/, 'postgres');
      // Prove the explicit transaction-read-only gate in real PostgreSQL by
      // deliberately weakening only the BEGIN mode in this negative fixture.
      refuses(countsSql.replace('REPEATABLE READ READ ONLY', 'REPEATABLE READ READ WRITE'), /unreviewed_relations/, database, false);
      for (const sql of [proofSql, countsSql]) {
        assert.match(sql, /COMMIT;$/);
        refuses(sql.replace(/COMMIT;$/, "UPDATE public.articles SET title='forbidden'; COMMIT;"), /cannot execute UPDATE in a read-only transaction/);
      }

      // Present job rows are counted; absent job is represented by null.
      query("CREATE SCHEMA pgboss; CREATE TABLE pgboss.job(id integer PRIMARY KEY, data jsonb); INSERT INTO pgboss.job VALUES (1,'{\"preserve\":true}'),(2,'{}')");
      const withJob = { ...expectedCounts, 'pgboss.job': 2 };
      const jobSql = capture('counts', withJob, 't').calls[1]!.sql;
      count(jobSql, withJob);
      for (const name of ['public.receipts', 'pgboss.job']) {
        query(`ALTER TABLE ${name} OWNER TO postgres`, 'postgres');
        try { refuses(jobSql, /unreviewed_relations/); }
        finally { query(`ALTER TABLE ${name} OWNER TO aifinance_preview`, 'postgres'); }
        const [schema, table] = name.split('.');
        query(`ALTER TABLE ${name} RENAME TO ${table}_held; CREATE VIEW ${name} AS SELECT * FROM ${schema}.${table}_held`);
        try { refuses(jobSql, /unreviewed_relations/); }
        finally { query(`DROP VIEW ${name}; ALTER TABLE ${schema}.${table}_held RENAME TO ${table}`); }
        query(`ALTER TABLE ${name} ENABLE ROW LEVEL SECURITY; ALTER TABLE ${name} FORCE ROW LEVEL SECURITY; CREATE POLICY hide_all ON ${name} USING (false)`);
        try { refuses(jobSql, /row-level security policy/); }
        finally { query(`ALTER TABLE ${name} NO FORCE ROW LEVEL SECURITY; ALTER TABLE ${name} DISABLE ROW LEVEL SECURITY; DROP POLICY hide_all ON ${name}`); }
      }
      query('ALTER TABLE public.fetch_runs OWNER TO postgres', 'postgres');
      try { refuses(proofSql, /unreviewed_relations/); }
      finally { query('ALTER TABLE public.fetch_runs OWNER TO aifinance_preview', 'postgres'); }

      // Real role-named and temporary shadows cannot redirect qualified counts.
      query('CREATE SCHEMA aifinance_preview; CREATE TABLE aifinance_preview.articles (LIKE public.articles INCLUDING DEFAULTS)');
      count(jobSql, withJob, 'CREATE TEMP TABLE articles (LIKE public.articles INCLUDING DEFAULTS); SET search_path=aifinance_preview,public; ');
      prove(); count(jobSql, withJob);
      query('DROP TABLE pgboss.job');
      count();
      t.diagnostic('membership, writable transaction, wrong login, wrong owner, views, FORCE RLS, shadows and injected writes all fail closed; optional job present/absent paths pass');
    } finally {
      try {
        if (databaseMade) query!('DROP DATABASE aifinance_preview', 'postgres', adminDatabase);
        if (roleMade) query!('DROP ROLE aifinance_preview', 'postgres', adminDatabase);
      } finally {
        if (started) stop();
        if (directory && !started) rmSync(directory, { recursive: true });
      }
    }
  });
