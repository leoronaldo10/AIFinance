// Actual PG17 transaction + custom-format dump/restore test. CI-only Docker
// service; never accepts a server outside the fixed disposable CI database.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import postgres from 'postgres';

const container = process.env.UPGRADE_TEST_POSTGRES_CONTAINER;
test('reviewed 0041 is atomic, repeat-safe, and the pre-upgrade dump really restores', { skip: !container, timeout: 120_000 }, async () => {
  assert.match(container!, /^[a-f0-9]{12,64}$/);
  const connection = new URL(process.env.DATABASE_URL!);
  assert.equal(connection.hostname, '127.0.0.1');
  assert.equal(connection.port, '5432');
  assert.equal(connection.pathname, '/aihot_ci');
  const admin = postgres(connection.toString(), { max: 1 });
  const name = `aifinance_upgrade_${process.pid}_ci`;
  const restoredName = `aifinance_restore_${process.pid}_ci`;
  let db: ReturnType<typeof postgres> | undefined;
  let restored: ReturnType<typeof postgres> | undefined;
  let made = false, restoredMade = false;
  try {
    const [version] = await admin`SHOW server_version_num`;
    assert.equal(Math.floor(Number(version!.server_version_num) / 10000), 17);
    await admin.unsafe(`CREATE DATABASE ${name} TEMPLATE template0`); made = true;
    await admin.unsafe(`CREATE DATABASE ${restoredName} TEMPLATE template0`); restoredMade = true;
    const url = new URL(connection); url.pathname = `/${name}`;
    db = postgres(url.toString(), { max: 1 });
    await db`CREATE TABLE schema_migrations(name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`;
    const names = readdirSync('database/migrations').filter(n => n.endsWith('.sql') && n < '0041').sort();
    assert.equal(names.length, 37);
    for (const migration of names) {
      await db.unsafe(readFileSync(`database/migrations/${migration}`, 'utf8'));
      await db`INSERT INTO schema_migrations(name) VALUES (${migration})`;
    }
    await db`INSERT INTO sources(id,name,kind,enabled,site_fulltext) VALUES ('upgrade-fixture','Fixture','rss',false,false)`;
    await db`INSERT INTO articles(id,source_id,identity_key,url,title,discovered_at,timeline_at) VALUES ('upgrade-fixture','upgrade-fixture','upgrade-fixture','https://example.invalid/item','Keep exact original',now(),now())`;
    const before = await db`SELECT to_jsonb(a) AS row FROM public.articles a`;
    const beforeLedger = await db`SELECT * FROM public.schema_migrations ORDER BY name`;
    const dump = execFileSync('docker', ['exec', container!, 'pg_dump', '-Fc', '-U', 'postgres', '-d', name], { maxBuffer: 16 * 1024 * 1024, timeout: 30_000 });
    assert.ok(dump.length > 1000);
    execFileSync('docker', ['exec', '-i', container!, 'pg_restore', '--exit-on-error', '-U', 'postgres', '-d', restoredName], { input: dump, timeout: 30_000 });
    const restoreUrl = new URL(connection); restoreUrl.pathname = `/${restoredName}`;
    restored = postgres(restoreUrl.toString(), { max: 1 });
    assert.deepEqual(Array.from(await restored`SELECT to_jsonb(a) AS row FROM public.articles a`), Array.from(before));
    assert.deepEqual(Array.from(await restored`SELECT * FROM public.schema_migrations ORDER BY name`), Array.from(beforeLedger));
    // A role-named schema and implicit-first pg_temp must not redirect DDL.
    await db.unsafe('CREATE SCHEMA postgres; CREATE TABLE postgres.articles (LIKE public.articles INCLUDING DEFAULTS); CREATE TABLE postgres.sources (LIKE public.sources INCLUDING DEFAULTS); CREATE TEMP TABLE articles (LIKE public.articles INCLUDING DEFAULTS); CREATE TEMP TABLE sources (LIKE public.sources INCLUDING DEFAULTS); SET search_path=postgres,public');
    const python = "import importlib.util,json;from pathlib import Path;s=importlib.util.spec_from_file_location('u','deploy/native/collect-only-upgrade.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m);print(m.migration_sql(Path('.'),json.loads(__import__('sys').argv[1])))";
    const sql = execFileSync('python3', ['-B', '-c', python, JSON.stringify(names)], { encoding: 'utf8', timeout: 5_000 });
    // Force an error AFTER DDL, before ledger insertion; PostgreSQL must undo both.
    await assert.rejects(db.unsafe(sql.replace('INSERT INTO public.schema_migrations', 'SELECT 1/0; INSERT INTO public.schema_migrations')));
    await db.unsafe('ROLLBACK');
    assert.equal((await db`SELECT count(*)::int AS n FROM information_schema.columns WHERE table_schema='public' AND column_name='collect_only'`)[0]!.n, 0);
    assert.equal((await db`SELECT count(*)::int AS n FROM public.schema_migrations`)[0]!.n, 37);
    await db.unsafe(sql);
    assert.equal((await db`SELECT count(*)::int AS n FROM public.schema_migrations`)[0]!.n, 38);
    assert.deepEqual(Array.from(await db`SELECT to_jsonb(a)-'collect_only' AS row FROM public.articles a`), Array.from(before));
    assert.equal((await db`SELECT collect_only FROM public.articles`)[0]!.collect_only, false);
    assert.equal((await db`SELECT convalidated FROM pg_constraint WHERE conname='collect_only_source_isolation' AND conrelid='public.sources'::regclass`)[0]!.convalidated, true);
    assert.equal((await db`SELECT count(*)::int AS n FROM information_schema.columns WHERE column_name='collect_only' AND (table_schema='postgres' OR table_schema LIKE 'pg_temp_%')`)[0]!.n, 0);
    await assert.rejects(db.unsafe(sql));
    await db.unsafe('ROLLBACK');
    assert.equal((await db`SELECT count(*)::int AS n FROM public.schema_migrations`)[0]!.n, 38);
  } finally {
    await db?.end(); await restored?.end();
    if (restoredMade) await admin.unsafe(`DROP DATABASE ${restoredName}`);
    if (made) await admin.unsafe(`DROP DATABASE ${name}`);
    await admin.end();
  }
});
