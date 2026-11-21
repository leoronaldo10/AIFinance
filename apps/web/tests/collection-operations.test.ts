// Real built SSR/router on loopback, synthetic read-only API; no browser or live host.
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import type { CollectionOperations } from "@aihot/contracts/collection-operations";
let web: ChildProcess, origin: string, logs = "", failing = false;
const calls: Array<{ method: string; url: string; cookie?: string }> = [];
const status: CollectionOperations = { observedAt: new Date().toISOString(), sourceState: "ok", source: { enabled: false, intervalMinutes: 30, nextFetchAt: "2099-01-01T00:00:00Z", lastFetchAt: null, lastOkAt: null }, worker: { state: "fresh", observedAt: new Date().toISOString(), activeState: "active", loadState: "loaded", unitFileState: "enabled" }, runs: [] };
const api = createServer((req, res) => {
  const url = new URL(req.url!, "http://api.local").pathname; calls.push({ method: req.method!, url, cookie: req.headers.cookie });
  res.setHeader("Content-Type", "application/json");
  if (req.method !== "GET") { res.statusCode = 405; return res.end('{}'); }
  if (url === "/api/site/meta") return res.end('{"changelogVersion":null}');
  if (req.headers.cookie !== "synthetic_admin=test") { res.statusCode = 401; return res.end('{"code":"unauthorized"}'); }
  if (url === "/api/admin/me") return res.end('{"name":"Synthetic administrator","csrf":"TEST","dev":false}');
  if (url === "/api/admin/nav-counts") return res.end('{}');
  if (url === "/api/admin/collection-operations") {
    if (failing) { res.statusCode = 503; return res.end('{"detail":"SECRET_BACKEND_ERROR"}'); }
    return res.end(JSON.stringify(status));
  }
  res.statusCode = 404; res.end('{}');
});
before(async () => {
  api.listen(0, "127.0.0.1"); await once(api, "listening");
  web = spawn(process.execPath, [fileURLToPath(new URL("../server.ts", import.meta.url))], { env: { ...process.env, WEB_PORT: "0", WEB_HOST: "127.0.0.1", API_BASE_URL: `http://127.0.0.1:${(api.address() as AddressInfo).port}`, COLLECT_ENABLED: "false", MODEL_CALLS_ENABLED: "false" }, stdio: ["ignore", "pipe", "pipe"] });
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("Local SSR startup failed")), 15000);
    web.on("exit", () => { clearTimeout(timer); reject(new Error("Local SSR exited")); });
    web.stderr!.on("data", c => { logs += String(c); });
    web.stdout!.on("data", c => { logs += String(c); const match = logs.match(/"msg":"web started","port":(\d+)/); if (match) { origin = `http://127.0.0.1:${match[1]}`; clearTimeout(timer); resolve(); } });
  });
});
after(async () => { if (web && web.exitCode === null) { web.kill("SIGTERM"); await once(web, "exit"); } api.closeAllConnections(); await new Promise<void>(resolve => api.close(() => resolve())); });
const get = () => fetch(`${origin}/admin/collection-operations`, { headers: { cookie: "synthetic_admin=test" }, redirect: "manual" });
test("anonymous SSR redirects to existing login and does not expose source observations", async () => {
  const r = await fetch(`${origin}/admin/collection-operations`, { redirect: "manual" });
  assert.equal(r.status, 302); assert.match(r.headers.get("location")!, /^\/admin\/login\?/); assert.ok(!(await r.text()).includes('intervalMinutes'));
});
test("authenticated SSR is no-store, Chinese, responsive, paused/no-runs and contains no write controls", async () => {
  const r = await get(), html = await r.text(); assert.equal(r.status, 200); assert.match(r.headers.get("cache-control")!, /(?:^|,\s*)no-store(?:,|$)/); assert.equal(r.headers.get("x-robots-tag"), "noindex, nofollow");
  for (const text of ["采集状态（只读）", "已暂停，没有下一次采集安排", "还没有该信源的抓取记录", "数据读取时间", "服务观测时间", "viewport", "md:grid-cols-2"]) assert.ok(html.includes(text), text);
  for (const text of ["立即采集", "预览抓取", "审核并发布", "下次可进入调度的时间："]) assert.ok(!html.includes(text), text);
  assert.ok(calls.filter(c => c.url === "/api/admin/collection-operations").some(c => c.cookie === "synthetic_admin=test")); assert.ok(calls.every(c => c.method === "GET"));
});
test("stale and unavailable observations are explicit; successful zero-new runs do not imply publication", async () => {
  status.observedAt = new Date(Date.now() - 100000).toISOString(); status.worker.state = "stale"; status.worker.observedAt = status.observedAt;
  status.runs = [{ startedAt: "2026-11-21T01:00:00Z", finishedAt: "2026-11-21T01:01:00Z", outcome: "ok", foundCount: 8, newCount: 0, errorCategory: null }];
  const html = await (await get()).text(); assert.ok(html.includes("观测已过期")); assert.ok(html.includes("页面数据已过期")); assert.ok(html.includes("抓取成功")); assert.ok(html.includes("不代表生成了草稿或已发布")); assert.ok(!html.includes("下次可进入调度的时间："));
  status.sourceState = "unavailable"; status.source = null; const unknown = await (await get()).text(); assert.ok(unknown.includes("当前状态未知")); assert.ok(unknown.includes("记录暂不可用"));
});
test("HTTP failure renders safe unknown state without backend text or prior green state", async () => {
  failing = true; const r = await get(), html = await r.text(); assert.equal(r.status, 503); assert.ok(html.includes("采集状态暂不可用")); assert.ok(!html.includes("SECRET_BACKEND_ERROR"));
});
