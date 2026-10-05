import { tag } from './setup.ts';
import assert from 'node:assert/strict';
import http from 'node:http';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { after, test } from 'node:test';
import { config } from '@aihot/backend/config';
import { sql, closeDb } from '@aihot/backend/db';
import { getBoss, stopBoss } from '@aihot/backend/jobs/queue';
import { queueProcessing, sweepUnprocessed, requeueFailed, processArticle } from '@aihot/backend/jobs/content';
import { collectSource, scheduleDueSources } from '@aihot/backend/sources/collect';
import { upsertMaterial } from '@aihot/backend/content/materials';
import { publishArticle, republishSource } from '@aihot/backend/publication/publish';
import { extractArticleBody } from '@aihot/backend/content/extract';
import { analyzeArticle } from '@aihot/backend/editorial/analyze';
import { groupArticle } from '@aihot/backend/events/group';
import { collectOnlyBatch } from '@aihot/backend/sources/collect-only';
import { guardedFetch } from '@aihot/backend/lib/http-fetch';
import { contentChain } from '@aihot/backend/admin/content';
import { buildApp } from '../apps/api/src/app.ts';

const T = tag();
config.modelCallsEnabled = false;
process.env.COLLECT_ENABLED = 'false';
process.env.EDITORIAL_AUTOMATIC_FIXTURES = 'false';
config.allowPrivateNetworkFetch = true;
let version = 1;
let collisionUrl = '';
let releaseSlow: (() => void) | null = null;
const hits: string[] = [];
const server = http.createServer((req, res) => {
  hits.push(req.url!);
  if (req.url === '/empty') { res.end('<rss><channel><title>Empty RSS</title></channel></rss>'); return; }
  if (req.url === '/slow') { releaseSlow = () => res.end('<rss><channel><title>Empty RSS</title></channel></rss>'); return; }
  if (req.url === '/large') { res.end('x'.repeat(2 * 1024 * 1024 + 1)); return; }
  if (req.url === '/collision') { res.end(`<rss><channel><item><title>Different feed title</title><link>${collisionUrl}?utm_source=fixture</link><description>Different feed summary</description></item></channel></rss>`); return; }
  if (req.url === '/port') { res.writeHead(302, { location: `http://127.0.0.1:${(server.address() as { port: number }).port + 1}/forbidden` }); res.end(); return; }
  if (req.url === '/scheme') { res.writeHead(302, { location: `https://${req.headers.host}/forbidden` }); res.end(); return; }
  if (req.url === '/credentials') { res.writeHead(302, { location: `http://user:secret@${req.headers.host}/forbidden` }); res.end(); return; }
  if (req.url === '/hop') { res.writeHead(302, { location: '/cross' }); res.end(); return; }
  if (req.url === '/cross') { res.writeHead(302, { location: 'http://localhost:1/forbidden' }); res.end(); return; }
  if (req.url === '/same') { res.writeHead(302, { location: '/rss0' }); res.end(); return; }
  if (req.url === '/forbidden') { res.writeHead(403); res.end(); return; }
  const entries = Array.from({ length: 5 }, (_, i) => `<item><title>Finance AI ${i} v${version}</title><link>https://example.org/${T}${req.url}/${i}</link><description><![CDATA[<p>Public RSS summary ${i}</p><img src="http://localhost:1/no-image" onerror="alert(1)"><script>alert(1)</script>]]></description><content:encoded><![CDATA[<p>Short public feed body ${i} v${version}</p>]]></content:encoded></item>`);
  res.writeHead(200, { 'content-type': 'application/rss+xml' });
  res.end(`<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/"><channel>${entries.join('')}${entries[0]}</channel></rss>`);
});
await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
const app = await buildApp();
after(async () => { await app.close(); await new Promise<void>(resolve => server.close(() => resolve())); await stopBoss(); await closeDb(); });
const ids = [0, 1, 2].map(i => `collect-only-${T}-${i}`);
async function seed(id: string, path: string) {
  await sql`INSERT INTO sources (id,name,kind,config,tier,enabled,participation_mode,site_fulltext,syndicate_fulltext,collect_only)
    VALUES (${id},'Collect-only RSS','rss',${sql.json({ feedUrl: base + path })},'T2',false,'isolated',false,false,true)`;
}
async function counts() {
  const tables = ['articles', 'article_revisions', 'pgboss.job', 'analyses', 'receipts', 'editorial_overrides', 'editorial_review_state', 'editorial_versions', 'editorial_exports', 'publications', 'deliveries', 'grouping_decisions'];
  return Object.fromEntries(await Promise.all(tables.map(async name => [name, Number((await sql.unsafe(`SELECT count(*) AS n FROM ${name}`))[0]!.n)])));
}

test('acceptance command is read-only and refuses apply', async () => {
  await getBoss();
  const before = await counts();
  const result = await promisify(execFile)(process.execPath, ['scripts/collect-only-check.ts'], { env: process.env });
  const report = JSON.parse(result.stdout);
  assert.equal(report.checkOnly, true);
  assert.equal(report.readyForApply, false);
  assert.ok(report.migrations.includes('0041_collect_only.sql'));
  assert.equal(report.columns.length, 2);
  assert.equal(report.constraints[0].convalidated, true);
  assert.deepEqual(report.counts, before);
  await assert.rejects(promisify(execFile)(process.execPath, ['scripts/collect-only-check.ts', '--apply'], { env: process.env }));
  await assert.rejects(promisify(execFile)(process.execPath, ['scripts/collect-only-check.ts'], {
    env: { ...process.env, DATABASE_URL: 'postgres://fixture-user:fixture-secret@127.0.0.1:bad/fixture' },
  }), (error: unknown) => {
    const output = error as { stderr: string; stdout: string };
    assert.match(output.stderr, /Collect-only check failed/);
    assert.doesNotMatch(output.stderr + output.stdout, /fixture-secret|fixture-user|postgres:\/\//);
    return true;
  });
  assert.deepEqual(await counts(), before);
});

test('real RSS → PG, three across entire batch, short text retained, duplicates/revisions, zero downstream writes', async () => {
  await getBoss(); // Creates queue tables only; never starts a worker.
  for (const [i, id] of ids.entries()) await seed(id, `/rss${i}`);
  assert.equal(config.editorialReviewRequired, true, "quarantine guards must run under production review policy");
  const before = await counts();
  const first = await collectOnlyBatch(ids, { queue: false });
  assert.equal(first.reduce((n, r) => n + r.processed, 0), 3);
  assert.equal(first.reduce((n, r) => n + r.created, 0), 3);
  assert.ok(first.every(r => r.found === 5), 'duplicate entries deduplicated before batching');
  const [article] = await sql`SELECT * FROM articles WHERE source_id=${ids[0]!}`;
  assert.equal(article!.body_text, 'Short public feed body 0 v1');
  assert.equal(article!.body_html, null);
  assert.deepEqual(article!.media, []);
  assert.ok(!article!.excerpt.includes('alert'));
  assert.equal(article!.processing_state, 'skipped');
  assert.equal(article!.collect_only, true);
  // Exercise more than the first three records, then cycle and deduplicate across repeated runs.
  for (let i = 0; i < 4; i++) await collectOnlyBatch(ids, { queue: false });
  const repeat = await collectOnlyBatch(ids, { queue: false });
  assert.equal(repeat.reduce((n, r) => n + r.created + r.revised, 0), 0);
  version = 2;
  const changed = await collectOnlyBatch(ids, { queue: false });
  assert.equal(changed.reduce((n, r) => n + r.revised, 0), 3);
  assert.equal(hits.length, 21, 'one RSS request per source per batch, no conditional retry');
  for (const id of ids) assert.equal((await collectSource(id, { force: true })).status, 'skipped');
  assert.equal((await counts())['pgboss.job'], before['pgboss.job']);
  await scheduleDueSources();
  assert.equal((await sql`SELECT id FROM pgboss.job WHERE data->>'sourceId' IN ${sql(ids)}`).length, 0);
  const afterSchedule = await counts();
  // Even a repair that mistakenly resets processing_state cannot remove durable quarantine.
  await sql`UPDATE articles SET created_at=now()-interval '10 minutes', processing_state='new' WHERE source_id IN ${sql(ids)}`;
  await sweepUnprocessed();
  await sql`UPDATE articles SET processing_state='failed', processing_error='collect-only-fixture-guard' WHERE source_id IN ${sql(ids)}`;
  await requeueFailed("collect-only-fixture-guard");
  assert.equal((await sql`SELECT 1 FROM articles WHERE source_id IN ${sql(ids)} AND processing_state <> 'failed'`).length, 0);
  await sql`UPDATE articles SET processing_state='skipped', processing_error=NULL WHERE source_id IN ${sql(ids)}`;
  assert.equal(await queueProcessing(article!.id, { step: 'analyze', attemptTag: 'manual' }), null);
  assert.equal(await queueProcessing(article!.id, { step: 'extract' }), null);
  assert.equal((await processArticle(article!.id)).state, 'skipped');
  assert.equal(await analyzeArticle(article!.id), null);
  assert.equal(await extractArticleBody(article!.id), 'skipped');
  assert.equal((await groupArticle(article!.id)).verdict, 'skipped');
  assert.equal(await publishArticle(article!.id), null);
  await republishSource(ids[0]!);
  assert.deepEqual(await counts(), afterSchedule);
  config.devAdmin = { displayName: 'Fixture admin' };
  for (const action of ['visibility', 'seo', 'override', 'detach', 'rerun']) {
    for (const step of action === 'rerun' ? ['group', 'extract', 'analyze'] : ['']) {
      const response = await app.inject({ method: 'POST', url: `/api/admin/content/${article!.id}/${action}`,
        headers: { 'x-csrf-token': 'dev', 'idempotency-key': 'fixture-request-0001' }, payload: { step, reason: 'fixture' } });
      assert.equal(response.statusCode, 409, action + step);
    }
  }
  assert.equal((await app.inject({ method: 'POST', url: `/api/admin/sources/${ids[0]}/fetch`, headers: { 'x-csrf-token': 'dev' }, payload: {} })).statusCode, 409);
  const [source] = await sql`SELECT updated_at FROM sources WHERE id=${ids[0]!}`;
  assert.equal((await app.inject({ method: 'PATCH', url: `/api/admin/sources/${ids[0]}`, headers: { 'x-csrf-token': 'dev' },
    payload: { patch: { name: 'Attempt republish' }, version: source!.updated_at.toISOString() } })).statusCode, 409);
  assert.equal((await app.inject({ method: 'POST', url: '/api/admin/sources/preview', headers: { 'x-csrf-token': 'dev' },
    payload: { id: ids[0], kind: 'rss', config: { feedUrl: base + '/rss0' }, collect_only: false } })).statusCode, 409);
  assert.deepEqual(await counts(), afterSchedule);
  const after = await counts();
  assert.equal(after.articles - before.articles, 15);
  assert.equal(after.article_revisions - before.article_revisions, 18);
  for (const key of Object.keys(before).filter(k => !['articles', 'article_revisions', 'pgboss.job'].includes(k))) assert.equal(after[key], before[key], key);
  assert.ok(hits.every(p => /^\/rss[012]$/.test(p)), 'only feed requests; no article, image or provider requests');
  config.devAdmin = null;
  assert.equal((await app.inject({ url: '/api/admin/content' })).statusCode, 401);
  assert.equal((await app.inject({ url: `/api/admin/content/${article!.id}` })).statusCode, 401);
  config.devAdmin = { displayName: 'Fixture admin' };
  const recent = await app.inject({ url: '/api/admin/content' });
  assert.equal(recent.statusCode, 200);
  assert.ok(recent.json().rows.some((r: { id: string }) => r.id === article!.id));
  assert.ok((await app.inject({ url: `/api/admin/content?q=${encodeURIComponent(T)}` })).json().rows.length <= 50);
  const detail = await app.inject({ url: `/api/admin/content/${article!.id}` });
  assert.equal(detail.statusCode, 200);
  assert.equal(detail.json().article.body_text, article!.body_text);
  await sql`UPDATE articles SET body_text=${'x'.repeat(21000)}, excerpt=${'y'.repeat(3000)} WHERE id=${article!.id}`;
  const bounded = await contentChain(article!.id);
  assert.equal(bounded!.article.body_text.length, 20000);
  assert.equal(bounded!.article.excerpt.length, 2000);
  assert.equal(bounded!.article.body_chars, 21000);
  config.devAdmin = null;
});

test('fail closed before HTTP for invalid source/config/valves and never follows cross-origin redirects', async () => {
  const before = hits.length;
  await assert.rejects(collectOnlyBatch([...ids, 'fourth'], { queue: false }), /1–3/);
  await assert.rejects(collectOnlyBatch([ids[0]!, ids[0]!], { queue: false }), /1–3/);
  await assert.rejects(collectOnlyBatch(ids, { queue: false, feedUrls: {} }), /allowlist/);
  await assert.rejects(sql`UPDATE sources SET enabled=true WHERE id=${ids[0]!}`, /collect_only_source_isolation/);
  await assert.rejects(sql`UPDATE sources SET participation_mode='editorial' WHERE id=${ids[0]!}`, /collect_only_source_isolation/);
  await sql`UPDATE sources SET participation_mode='isolated', config=config || '{"detail":{"maxFetches":1}}'::jsonb WHERE id=${ids[0]!}`;
  await assert.rejects(collectOnlyBatch(ids, { queue: false }), /feedUrl/);
  config.modelCallsEnabled = true;
  await assert.rejects(collectOnlyBatch(ids, { queue: false }), /MODEL_CALLS/);
  config.modelCallsEnabled = false;
  assert.equal(hits.length, before);
  await assert.rejects(guardedFetch(base + '/cross', { sameOriginRedirects: true }), /Cross-origin/);
  assert.equal(hits.at(-1), '/cross');
  for (const path of ['/port', '/scheme', '/hop']) await assert.rejects(guardedFetch(base + path, { sameOriginRedirects: true }), /Cross-origin/);
  await assert.rejects(guardedFetch(base + '/credentials', { sameOriginRedirects: true }), /credentials/);
  assert.equal((await guardedFetch(base + '/same', { sameOriginRedirects: true })).status, 200);
  const failed = `collect-failed-${T}`;
  await seed(failed, '/forbidden');
  const countsBefore = await counts();
  await assert.rejects(collectOnlyBatch([failed], { queue: false }), /HTTP 403/);
  assert.deepEqual(await counts(), countsBefore);
  assert.equal(hits.at(-1), '/forbidden');
  assert.match((await sql`SELECT last_error FROM sources WHERE id=${failed}`)[0]!.last_error, /403/);
  config.allowPrivateNetworkFetch = false;
  await assert.rejects(guardedFetch(base + '/ssrf', { sameOriginRedirects: true }), /Blocked/);
  assert.equal(hits.at(-1), '/forbidden', 'SSRF denied before connection');
});


test('empty feeds explain no candidates, byte limits fail closed, overlapping batches cannot fetch twice', async () => {
  config.allowPrivateNetworkFetch = true;
  const id = `collect-empty-${T}`;
  await seed(id, '/empty');
  const result = await collectOnlyBatch([id], { queue: false });
  assert.match(result[0]!.reason, /没有可用/);
  assert.equal(result[0]!.processed, 0);
  assert.match((await sql`SELECT detail FROM fetch_runs WHERE source_id=${id}`)[0]!.detail.reason, /没有可用/);
  await sql`UPDATE sources SET config=${sql.json({ feedUrl: base + '/large' })} WHERE id=${id}`;
  await assert.rejects(collectOnlyBatch([id], { queue: false }), /Response too large/);
  await sql`UPDATE sources SET config=${sql.json({ feedUrl: base.replace('http://', 'http://user:secret@') + '/rss0' })} WHERE id=${id}`;
  const beforeCredentials = hits.length;
  await assert.rejects(collectOnlyBatch([id], { queue: false }), /credentials/);
  assert.equal(hits.length, beforeCredentials);
  await sql`UPDATE sources SET config=${sql.json({ feedUrl: base + '/slow' })} WHERE id=${id}`;
  const running = collectOnlyBatch([id], { queue: false });
  while (!releaseSlow) await new Promise(resolve => setTimeout(resolve, 5));
  try { await assert.rejects(collectOnlyBatch([id], { queue: false }), /already running/); }
  finally { releaseSlow!(); }
  await running;
  assert.equal(hits.filter(h => h === '/slow').length, 1);
});

test('an existing analyzed/reviewed/public URL collision stays entirely unchanged, including tracking variants', async () => {
  const originalSource = `original-${T}`;
  await sql`INSERT INTO sources (id,name,kind,participation_mode) VALUES (${originalSource},'Existing editorial','external','editorial')`;
  collisionUrl = `https://example.org/existing-${T}`;
  const { articleId } = await upsertMaterial({ sourceId: originalSource, title: 'Existing title', url: collisionUrl, bodyText: 'Existing original body', raw: { existing: true }, via: 'import' });
  await sql`INSERT INTO analyses (article_id,input_revision,origin,title_zh,summary_zh,relevance) VALUES (${articleId},1,'replay','已有标题','已有摘要','pass')`;
  process.env.EDITORIAL_AUTOMATIC_FIXTURES = "true"; // Set up the pre-existing public fixture only.
  try { await publishArticle(articleId); } finally { process.env.EDITORIAL_AUTOMATIC_FIXTURES = "false"; }
  await sql`INSERT INTO editorial_review_state (article_id,current_version,published_version) VALUES (${articleId},1,1)`;
  await sql`INSERT INTO editorial_versions (article_id,version,copy,evidence,status,actor) VALUES (${articleId},1,'{}','{}','approved','fixture')`;
  const snapshot = async () => ({ article: (await sql`SELECT * FROM articles WHERE id=${articleId}`)[0],
    analyses: await sql`SELECT * FROM analyses WHERE article_id=${articleId}`,
    review: await sql`SELECT * FROM editorial_review_state WHERE article_id=${articleId}`,
    versions: await sql`SELECT * FROM editorial_versions WHERE article_id=${articleId}`,
    publication: await sql`SELECT * FROM publications WHERE article_id=${articleId}`,
    revisions: await sql`SELECT * FROM article_revisions WHERE article_id=${articleId}` });
  const before = await snapshot();
  assert.equal(before.publication[0]!.visibility, 'public');
  const id = `collect-collision-${T}`;
  await seed(id, '/collision');
  const result = await collectOnlyBatch([id], { queue: false });
  assert.equal(result[0]!.created + result[0]!.revised, 0);
  assert.deepEqual(await snapshot(), before);
  assert.equal((await sql`SELECT 1 FROM article_discoveries WHERE article_id=${articleId} AND source_id=${id}`).length, 1);
  assert.equal((await contentChain(articleId))!.article.collect_only, false);
  // The same-source legacy case must also never turn an existing reviewed article into raw material.
  await assert.rejects(upsertMaterial({ sourceId: originalSource, title: 'Different', url: collisionUrl, bodyText: 'Different', via: 'fetch', collectOnly: true }), /dedicated material entrance/);
  assert.deepEqual(await snapshot(), before);
});

test('fixed source registration rejects existing ID/config conflicts atomically and is otherwise idempotent', async () => {
  const id = 'collect-journal-accountancy';
  await sql`INSERT INTO sources (id,name,kind,config,participation_mode) VALUES (${id},'Existing active source','rss','{"feedUrl":"https://example.org/active"}','editorial')`;
  const before = (await sql`SELECT * FROM sources WHERE id=${id}`)[0];
  const run = () => promisify(execFile)(process.execPath, ['scripts/collect-only.ts', '--seed-only'], { env: { ...process.env, NODE_OPTIONS: '', MODEL_CALLS_ENABLED: 'false', COLLECT_ENABLED: 'false' } });
  await assert.rejects(run(), /Source ID conflict/);
  assert.deepEqual((await sql`SELECT * FROM sources WHERE id=${id}`)[0], before);
  assert.equal((await sql`SELECT 1 FROM sources WHERE id='collect-dynamics-finance'`).length, 0, 'earlier inserts roll back');
  await sql`DELETE FROM sources WHERE id=${id}`;
  await run();
  await run();
  assert.equal((await sql`SELECT 1 FROM sources WHERE id IN ('collect-dynamics-finance','collect-journal-accountancy','collect-accounting-today') AND collect_only AND NOT enabled AND participation_mode='isolated'`).length, 3);
  await sql`DELETE FROM sources WHERE id IN ('collect-dynamics-finance','collect-journal-accountancy','collect-accounting-today')`;
});


test('external ingest and untrusted material callers cannot write into dedicated RSS sources', async () => {
  const id = `collect-ingest-${T}`;
  await seed(id, '/rss0');
  const { articleId } = await upsertMaterial({ sourceId: id, title: 'Protected original', url: `https://example.org/ingest-guard-${T}`, via: 'fetch', collectOnly: true });
  const snapshot = async () => ({ source: (await sql`SELECT * FROM sources WHERE id=${id}`)[0],
    article: (await sql`SELECT * FROM articles WHERE id=${articleId}`)[0],
    events: (await sql`SELECT count(*) AS n FROM ingest_events`)[0]!.n,
    counts: await counts() });
  const before = await snapshot();
  const oldToken = process.env.INGEST_TOKEN;
  process.env.INGEST_TOKEN = 'fixture-ingest-token-0123456789';
  try {
    for (const url of [`https://example.org/new-ingest-${T}`, before.article!.url]) {
      const response: { statusCode: number } = await app.inject({ method: 'POST', url: '/api/ingest/items',
        headers: { authorization: `Bearer ${process.env.INGEST_TOKEN}` },
        payload: { sourceId: id, items: [{ title: 'Unauthorized replacement', url }] } });
      assert.equal(response.statusCode, 409);
      await assert.rejects(upsertMaterial({ sourceId: id, title: 'Unauthorized replacement', url, via: 'ingest' }), /dedicated material entrance/);
    }
  } finally {
    if (oldToken === undefined) delete process.env.INGEST_TOKEN;
    else process.env.INGEST_TOKEN = oldToken;
  }
  assert.deepEqual(await snapshot(), before, 'even source health, revisions, ingest logs and downstream jobs stay unchanged');
});


test('article quarantine remains authoritative if legacy data loses its source marker', async () => {
  const id = `collect-legacy-${T}`;
  await seed(id, '/rss0');
  const url = `https://example.org/legacy-marker-${T}`;
  const { articleId } = await upsertMaterial({ sourceId: id, title: 'Keep raw', url, bodyText: 'Original text', via: 'fetch', collectOnly: true });
  const [before] = await sql`SELECT * FROM articles WHERE id=${articleId}`;
  // Simulate a legacy/manual DB source migration; no admin endpoint can make this change.
  await sql`UPDATE sources SET collect_only=false WHERE id=${id}`;
  const result = await upsertMaterial({ sourceId: id, title: 'Ordinary overwrite', url, bodyText: 'Changed text', via: 'ingest' });
  assert.equal(result.created || result.revised, false);
  assert.deepEqual((await sql`SELECT * FROM articles WHERE id=${articleId}`)[0], before);
  assert.equal(await queueProcessing(articleId), null);
  assert.equal(await publishArticle(articleId), null);
});
