// Read-only acceptance snapshot. No apply mode, migrations, workers or HTTP.
import postgres from 'postgres';

if (process.argv.slice(2).some(a => a !== '--check') || process.argv.length > 3 || !process.env.DATABASE_URL) {
  throw new Error('Usage: DATABASE_URL=<approved database> node scripts/collect-only-check.ts [--check]; no apply mode');
}
let db: ReturnType<typeof postgres> | undefined;
try {
  db = postgres(process.env.DATABASE_URL, { max: 1, connect_timeout: 5 });
  const snapshot = await db.begin('isolation level repeatable read read only', async tx => {
    await tx`SET LOCAL statement_timeout = '10s'`;
    const counts: Record<string, number | null> = {};
    for (const table of ['articles', 'article_revisions', 'pgboss.job', 'analyses', 'receipts',
      'editorial_overrides', 'editorial_review_state', 'editorial_versions', 'editorial_exports',
      'publications', 'deliveries', 'grouping_decisions']) {
      const [exists] = await tx`SELECT to_regclass(${table}) IS NOT NULL AS present`;
      counts[table] = exists!.present ? Number((await tx.unsafe(`SELECT count(*) AS n FROM ${table}`))[0]!.n) : null;
    }
    return {
      checkOnly: true, readyForApply: false,
      database: (await tx`SELECT current_database() AS name`)[0]!.name,
      migrations: (await tx`SELECT name FROM schema_migrations ORDER BY name`).map(r => r.name),
      columns: await tx`SELECT table_name,column_name,column_default,is_nullable FROM information_schema.columns
        WHERE table_schema='public' AND table_name IN ('articles','sources') AND column_name='collect_only' ORDER BY table_name`,
      constraints: await tx`SELECT conname,convalidated,pg_get_constraintdef(oid) AS definition FROM pg_constraint
        WHERE conrelid='sources'::regclass AND conname='collect_only_source_isolation'`,
      sources: await tx`SELECT id,kind,enabled,participation_mode,site_fulltext,syndicate_fulltext,
        to_jsonb(s)->>'collect_only' AS collect_only FROM sources s WHERE id IN
        ('collect-dynamics-finance','collect-journal-accountancy','collect-accounting-today') ORDER BY id`,
      rawStates: await tx`SELECT processing_state,count(*)::int AS count FROM articles a
        WHERE to_jsonb(a)->>'collect_only'='true' GROUP BY processing_state ORDER BY processing_state`,
      counts,
    };
  });
  console.log(JSON.stringify(snapshot, null, 2));
} catch {
  // Do not echo connection strings, database errors or credentials into acceptance logs.
  console.error('Collect-only check failed; no writes attempted. Verify approved connection/schema and timeout.');
  process.exitCode = 1;
} finally {
  try {
    await db?.end();
  } catch {
    console.error('Collect-only check connection cleanup failed.');
    process.exitCode = 1;
  }
}
