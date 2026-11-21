import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtemp, writeFile, chmod, symlink, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import Fastify from "fastify";
import { config } from "@aihot/backend/config";
import { COLLECTION_SOURCE_ID, COLLECTION_WORKER_UNIT, collectionEligibility, type CollectionOperations } from "@aihot/contracts/collection-operations";
import { parseWorkerObservation, readWorkerObservation } from "@aihot/backend/admin/worker-observation";
import { projectCollectionRun, readCollectionOperations } from "@aihot/backend/admin/collection-operations";
import { registerCollectionOperations } from "../apps/api/src/routes/admin-collection-operations.ts";
const NOW = Date.parse("2026-11-21T09:00:00Z");
const raw = { format: 1, unit: COLLECTION_WORKER_UNIT, observedAt: new Date(NOW).toISOString(), activeState: "active", loadState: "loaded", unitFileState: "enabled" };
const data = (): CollectionOperations => ({ observedAt: raw.observedAt, sourceState: "ok", source: { enabled: false, intervalMinutes: 30, nextFetchAt: "2026-11-22T09:00:00Z", lastFetchAt: null, lastOkAt: null }, worker: parseWorkerObservation(raw, NOW), runs: [] });

test("paused sources never show a next scheduled fetch; stale data cannot claim a current state", () => {
  const d = data();
  assert.deepEqual(collectionEligibility(d, NOW), { state: "paused", at: null });
  d.source!.enabled = true;
  assert.deepEqual(collectionEligibility(d, NOW), { state: "waiting", at: d.source!.nextFetchAt });
  d.source!.nextFetchAt = null;
  assert.equal(collectionEligibility(d, NOW).state, "eligible");
  assert.equal(collectionEligibility(d, NOW + 91_000).state, "unknown");
  d.source!.enabled = false;
  assert.equal(collectionEligibility(d, NOW + 91_000).state, "unknown");
  d.source!.enabled = true; d.worker.activeState = "failed";
  assert.equal(collectionEligibility(d, NOW).state, "worker_unavailable");
  d.worker = parseWorkerObservation({ ...raw, observedAt: "2026-11-21T08:00:00Z" }, NOW);
  assert.equal(collectionEligibility(d, NOW).state, "unknown");
});

test("worker observations distinguish stale, unknown, failed and malformed without returning extra fields", () => {
  assert.equal(parseWorkerObservation(raw, NOW).state, "fresh");
  assert.equal(parseWorkerObservation(raw, NOW + 91_000).state, "stale");
  assert.equal(parseWorkerObservation({ ...raw, activeState: "failed" }, NOW).activeState, "failed");
  for (const bad of [null, [], { ...raw, rawLog: "SECRET" }, { ...raw, unit: "other.service" }, { ...raw, activeState: "SECRET" }, { ...raw, observedAt: "invalid" }, { ...raw, observedAt: new Date(NOW + 6_000).toISOString() }]) {
    const got = parseWorkerObservation(bad, NOW); assert.equal(got.state, "invalid"); assert.ok(!JSON.stringify(got).includes("SECRET"));
  }
});

test("passive file reader rejects links, world-writable files, oversize, invalid JSON and directories", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "collection-observation-"));
  try {
    const file = path.join(dir, "status.json");
    assert.equal((await readWorkerObservation(NOW, file)).state, "missing");
    await writeFile(file, JSON.stringify(raw), { mode: 0o600 });
    assert.equal((await readWorkerObservation(NOW, file)).state, "fresh");
    await symlink(file, path.join(dir, "link"));
    assert.equal((await readWorkerObservation(NOW, path.join(dir, "link"))).activeState, "unknown");
    await chmod(file, 0o666); assert.equal((await readWorkerObservation(NOW, file)).state, "invalid");
    await chmod(file, 0o600); await writeFile(file, "x".repeat(5000)); assert.equal((await readWorkerObservation(NOW, file)).state, "invalid");
    await writeFile(file, "{"); assert.equal((await readWorkerObservation(NOW, file)).state, "invalid");
    assert.equal((await readWorkerObservation(NOW, dir)).state, "invalid");
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test("native run projections preserve successful zero-new runs and suppress arbitrary errors/details", () => {
  const row = { started_at: new Date(NOW - 1000), finished_at: new Date(NOW), status: "ok", found_count: 10, new_count: 0, error: "SECRET", detail: { token: "SECRET" }, error_category: null };
  assert.deepEqual(projectCollectionRun(row, NOW), { startedAt: new Date(NOW - 1000).toISOString(), finishedAt: raw.observedAt, outcome: "ok", foundCount: 10, newCount: 0, errorCategory: null });
  const failed = projectCollectionRun({ ...row, status: "failed", error_category: "network" }, NOW);
  assert.equal(failed.errorCategory, "network"); assert.ok(!JSON.stringify(failed).includes("SECRET"));
  assert.equal(projectCollectionRun({ ...row, status: "running", started_at: new Date(NOW - 31 * 60_000), finished_at: null }, NOW).outcome, "unknown");
  assert.equal(projectCollectionRun({ ...row, finished_at: null }, NOW).outcome, "unknown");
  assert.equal(projectCollectionRun({ ...row, started_at: new Date(NOW + 10_000) }, NOW).outcome, "unknown");
});

test("status adapter uses a fixed source with SELECT-only business reads in READ ONLY and no secret responses", async () => {
  const statements: Array<{ text: string; values: unknown[] }> = [];
  const tx = async (strings: TemplateStringsArray, ...values: unknown[]) => {
    const text = strings.join("?"); statements.push({ text, values });
    if (text.startsWith("SET LOCAL")) return [];
    if (text.includes("FROM sources")) return [{ enabled: false, interval_minutes: 30, next_fetch_at: raw.observedAt }];
    return [{ started_at: new Date(NOW - 1000), finished_at: new Date(NOW), status: "ok", found_count: 12, new_count: 0 }];
  };
  const database = { begin: async (mode: string, work: (tx: unknown) => Promise<unknown>) => { assert.equal(mode, "READ ONLY"); return work(tx); } } as unknown as NonNullable<Parameters<typeof readCollectionOperations>[0]>["database"];
  const got = await readCollectionOperations({ database, now: NOW, observe: async () => parseWorkerObservation(raw, NOW) });
  assert.equal(got.source?.enabled, false); assert.equal(got.runs[0].newCount, 0);
  assert.equal(statements.length, 3);
  for (const q of statements.slice(1)) {
    assert.ok(q.text.trim().startsWith("SELECT")); assert.deepEqual(q.values, [COLLECTION_SOURCE_ID]); assert.ok(!/INSERT|UPDATE|DELETE|pgboss|articles|publications/.test(q.text));
  }
  assert.ok(!statements[2].text.includes("error, detail"));
  const broken = { begin: async () => { throw new Error("postgres://SECRET@host/database"); } } as unknown as typeof database;
  const unavailable = await readCollectionOperations({ database: broken, now: NOW, observe: async () => parseWorkerObservation(raw, NOW) });
  assert.equal(unavailable.sourceState, "unavailable"); assert.equal(unavailable.source, null); assert.deepEqual(unavailable.runs, []); assert.ok(!JSON.stringify(unavailable).includes("SECRET"));
});

test("actual admin guard rejects anonymous/production stand-ins, exposes only guarded GET and does not call reader on write/public paths", async () => {
  const app = Fastify(); let reads = 0;
  registerCollectionOperations(app, async () => { reads++; return data(); });
  const before = { devAdmin: config.devAdmin, environmentName: config.environmentName };
  try {
    config.devAdmin = null;
    const denied = await app.inject({ url: "/api/admin/collection-operations" });
    assert.equal(denied.statusCode, 401); assert.equal(reads, 0); assert.equal(denied.headers["cache-control"], "no-store");
    config.devAdmin = { displayName: "Synthetic test principal" }; config.environmentName = "production";
    assert.equal((await app.inject({ url: "/api/admin/collection-operations" })).statusCode, 401); assert.equal(reads, 0);
    config.environmentName = "test";
    const ok = await app.inject({ url: "/api/admin/collection-operations" });
    assert.equal(ok.statusCode, 200); assert.equal(reads, 1); assert.equal(ok.headers["cache-control"], "no-store"); assert.equal(ok.headers["x-robots-tag"], "noindex, nofollow");
    const filter = await app.inject({ url: "/api/admin/collection-operations?source=unrelated" }); assert.equal(filter.statusCode, 400); assert.equal(reads, 1);
    for (const method of ["POST", "PUT", "PATCH", "DELETE"] as const) assert.equal((await app.inject({ method, url: "/api/admin/collection-operations" })).statusCode, 404);
    assert.equal((await app.inject({ url: "/api/collection-operations" })).statusCode, 404); assert.equal(reads, 1);
    const broken = Fastify();
    registerCollectionOperations(broken, async () => { throw new Error("SECRET backend diagnostic"); });
    const failure = await broken.inject({ url: "/api/admin/collection-operations" });
    assert.equal(failure.statusCode, 503); assert.ok(!failure.body.includes("SECRET"));
    assert.equal(failure.headers["cache-control"], "no-store"); await broken.close();
    const sources = await readFile(new URL("../apps/api/src/routes/admin-collection-operations.ts", import.meta.url), "utf8");
    assert.ok(!/child_process|exec\(|spawn\(|systemctl/.test(sources));
  } finally { Object.assign(config, before); await app.close(); }
});
