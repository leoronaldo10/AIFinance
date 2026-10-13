import "./local-network-guard.ts";
import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import tls from "node:tls";
import { spawnSync } from "node:child_process";
import { test } from "node:test";

test("test TCP rejects public/private addresses and DNS names before connecting", () => {
  for (const host of ["203.0.113.1", "10.0.0.1", "example.invalid", "localhost", "2001:db8::1"]) {
    assert.throws(() => net.connect({ host, port: 443 }), /Test network isolation/);
    assert.throws(() => tls.connect({ host, port: 443 }), /Test network isolation/);
  }
});

test("local HTTP works but redirects cannot leave loopback", async () => {
  const server = http.createServer((req, res) => {
    if (req.url === "/redirect") {
      res.writeHead(302, { location: "http://example.invalid/" });
      res.end();
    } else res.end("local stub");
  });
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${(server.address() as net.AddressInfo).port}`;
  try {
    assert.equal(await (await fetch(url)).text(), "local stub");
    await assert.rejects(fetch(`${url}/redirect`), (error: any) =>
      /Test network isolation/.test(String(error.cause)));
  } finally {
    server.closeAllConnections();
    await new Promise<void>(resolve => server.close(() => resolve()));
  }
});

test("spawned Node processes inherit the loopback guard", () => {
  const child = spawnSync(process.execPath, ["--input-type=module", "-e", `
    import assert from 'node:assert/strict';
    import net from 'node:net';
    assert.throws(() => net.connect({host:'example.invalid',port:443}), /Test network isolation/);
  `], { encoding: "utf8", timeout: 10000 });
  assert.equal(child.status, 0, child.stderr);
});

test("fixture setup clears inherited provider credentials before enabling local model calls", () => {
  const child = spawnSync(process.execPath, ["--input-type=module", "-e", `
    import './tests/setup.ts';
    import assert from 'node:assert/strict';
    import {config} from './packages/backend/src/config.ts';
    assert.equal(config.modelCallsEnabled, true);
    assert.equal(process.env.DEEPSEEK_API_KEY, undefined);
    assert.equal(process.env.FEISHU_APP_SECRET, undefined);
    assert.equal(process.env.DEEPSEEK_BASE_URL, 'http://127.0.0.1:1/v1');
    assert.equal(config.credentialsDir, '/nonexistent-test-credentials');
    assert.equal(process.env.FEISHU_INTERNAL_ENABLED, 'false');
  `], {
    encoding: "utf8", timeout: 10000,
    env: { ...process.env, DATABASE_URL: "postgres://127.0.0.1/no_io_test",
      MODEL_CALLS_ENABLED: "false", DEEPSEEK_API_KEY: "inherited-fixture-sentinel",
      FEISHU_APP_SECRET: "inherited-fixture-sentinel", DEEPSEEK_BASE_URL: "https://example.invalid" },
  });
  assert.equal(child.status, 0, child.stderr);
});
