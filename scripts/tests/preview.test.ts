import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

const root = path.resolve(import.meta.dirname, "../..");
const runNode = (code: string, env: Record<string, string> = {}) => spawnSync(process.execPath, ["--input-type=module", "-e", code], {
  cwd: root, encoding: "utf8", env: { PATH: process.env.PATH, ...env }, timeout: 15000,
});

test("preview initialization isolates secrets, refuses model keys and does not overwrite either environment", () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), "preview-env-"));
  try {
    writeFileSync(path.join(dir, ".env"), "production-sentinel");
    const run = (...args: string[]) => spawnSync(process.execPath, [path.join(root, "scripts/init-env.ts"), "--preview", ...args], { cwd: dir, encoding: "utf8" });
    assert.notEqual(run("--llm-key", "not-a-real-key").status, 0);
    assert.equal(run().status, 0);
    const text = readFileSync(path.join(dir, ".env.preview"), "utf8");
    assert.match(text, /^ADMIN_PASSWORD=.{12,}$/m);
    assert.doesNotMatch(text, /LLM_|FEISHU_|COLLECT_ENABLED=true/);
    assert.equal(statSync(path.join(dir, ".env.preview")).mode & 0o777, 0o600);
    assert.notEqual(run().status, 0);
    assert.equal(readFileSync(path.join(dir, ".env.preview"), "utf8"), text);
    assert.equal(readFileSync(path.join(dir, ".env"), "utf8"), "production-sentinel");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("preview overrides enabled model and notification flags and blocks fetch before URL resolution", () => {
  const result = runNode(`
    import assert from 'node:assert/strict';
    import { config } from './packages/backend/src/config.ts';
    import { feishuInternalEnabled } from './packages/backend/src/notify/feishu.ts';
    import { guardedFetch } from './packages/backend/src/lib/http-fetch.ts';
    assert.equal(config.editorialReviewRequired, true);
    for (const value of [config.modelCallsEnabled, config.feishuContentPushEnabled, config.indexNowSubmitEnabled, feishuInternalEnabled()]) assert.equal(value, false);
    await assert.rejects(guardedFetch('not-even-a-url'), /disabled in isolated preview/);
  `, { NODE_ENV: "production", PREVIEW_MODE: "true", MODEL_CALLS_ENABLED: "true", FEISHU_CONTENT_PUSH_ENABLED: "true", FEISHU_INTERNAL_ENABLED: "true", INDEXNOW_SUBMIT_ENABLED: "true" });
  assert.equal(result.status, 0, result.stderr);
});

test("production model configuration keeps its existing opt-in/out semantics outside preview", () => {
  const result = runNode(`import assert from 'node:assert/strict'; import {config} from './packages/backend/src/config.ts'; assert.equal(config.previewMode,false); assert.equal(config.modelCallsEnabled,true);`, { MODEL_CALLS_ENABLED: "true" });
  assert.equal(result.status, 0, result.stderr);
});

test("worker refuses preview before starting queues or connecting to a database", () => {
  const result = runNode("await import('./apps/worker/src/main.ts')", { PREVIEW_MODE: "true" });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /worker must not run in isolated preview/);
});

test("resolved preview Compose excludes worker, external networks, credentials and production volumes", t => {
  const version = spawnSync("docker", ["compose", "version"], { encoding: "utf8" });
  if (version.status !== 0) return t.skip("Docker Compose is not installed");
  const result = spawnSync("docker", ["compose", "--env-file", "/dev/null", "-f", "docker-compose.preview.yml", "config", "--format", "json"], {
    cwd: root, encoding: "utf8", env: { PATH: process.env.PATH, PREVIEW_IMAGE: "review:test", SITE_URL: "http://localhost:3100", POSTGRES_PASSWORD: "preview-only", ADMIN_PASSWORD: "preview-admin-test", SESSION_SECRET: "preview-session-test", IMG_PROXY_SIGN_SECRET: "preview-image-test", LLM_API_KEY: "must-not-leak", FEISHU_INTERNAL_ENABLED: "true" },
  });
  assert.equal(result.status, 0, result.stderr);
  const compose = JSON.parse(result.stdout);
  assert.deepEqual(Object.keys(compose.services).sort(), ["api", "db", "setup", "web"]);
  assert.equal(compose.networks.isolated.internal, true);
  assert.doesNotMatch(result.stdout, /must-not-leak/);
  for (const service of Object.values(compose.services) as any[]) {
    assert.deepEqual(Object.keys(service.networks), ["isolated"]);
    assert.ok(!service.env_file && !service.build && !service.privileged && !service.network_mode);
  }
  for (const name of ["api", "setup"]) {
    const env = compose.services[name].environment;
    for (const key of ["COLLECT_ENABLED", "MODEL_CALLS_ENABLED", "FEISHU_CONTENT_PUSH_ENABLED", "FEISHU_INTERNAL_ENABLED", "INDEXNOW_SUBMIT_ENABLED"]) assert.equal(env[key], "false");
    assert.equal(env.PREVIEW_MODE, "true");
  }
  assert.equal(compose.services.web.ports[0].host_ip, "127.0.0.1");
  assert.ok(!compose.services.api.ports && !compose.services.db.ports);
  assert.deepEqual(Object.keys(compose.volumes).sort(), ["preview-data", "preview-db"]);
});
