import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, symlinkSync, readlinkSync, rmSync, existsSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

const repo = path.resolve(import.meta.dirname, "../..");
const old = "a".repeat(40), next = "b".repeat(40);
function fixture() {
  const root = mkdtempSync(path.join(os.tmpdir(), "aifinance-release-"));
  for (const dir of ["releases", "incoming", "shared", "bin", "state"]) mkdirSync(path.join(root, dir));
  writeFileSync(path.join(root, "shared/native-ready"), "test fixture");
  writeFileSync(path.join(root, "shared/schema.sha256"), "schema-1\n");
  const make = (sha: string, schema = "schema-1\n") => {
    const dir = path.join(root, "releases", sha);
    mkdirSync(path.join(dir, "apps/web/build/server"), { recursive: true });
    mkdirSync(path.join(dir, "node_modules"));
    writeFileSync(path.join(dir, "apps/web/build/server/index.js"), "");
    writeFileSync(path.join(dir, "RELEASE_SHA"), sha);
    writeFileSync(path.join(dir, "schema.sha256"), schema);
    return dir;
  };
  make(old); symlinkSync(path.join(root, "releases", old), path.join(root, "state/current"));
  const stub = (name: string, body: string) => writeFileSync(path.join(root, "bin", name), "#!/usr/bin/env bash\n" + body, { mode: 0o755 });
  stub("systemctl", 'if [[ "$1" = show ]]; then echo loaded; fi\n');
  stub("sudo", 'printf "%s\\n" "$*" >> "$AIFINANCE_ROOT/restarts"\n');
  stub("node", 'exit 0\n');
  stub("sleep", 'exit 0\n');
  stub("curl", `sha=$(basename "$(readlink -f "$AIFINANCE_ROOT/state/current")")
if [[ -e "$AIFINANCE_ROOT/fail-new" && "$sha" = ${next} ]]; then exit 22; fi
printf '{"ok":true,"release":"%s"}\\n' "$sha"
`);
  // Replace only the fixed Node path; service and network commands are controlled PATH stubs.
  const script = path.join(root, "release.sh");
  writeFileSync(script, readFileSync(path.join(repo, "deploy/native/release.sh"), "utf8").replaceAll("/usr/local/bin/node", path.join(root, "bin/node")));
  const run = (...args: string[]) => spawnSync("bash", [script, ...args], { encoding: "utf8", timeout: 15000, env: { PATH: `${root}/bin:${process.env.PATH}`, AIFINANCE_ROOT: root } });
  const pack = () => {
    const dir = make(next);
    const archive = path.join(root, "incoming", `${next}.tar.gz`);
    assert.equal(spawnSync("tar", ["-czf", archive, "-C", dir, "."]).status, 0);
    rmSync(dir, { recursive: true });
    return createHash("sha256").update(readFileSync(archive)).digest("hex");
  };
  return { root, make, run, pack, clean: () => rmSync(root, { recursive: true, force: true }) };
}

test("deploy validates archive and switches only AIFinance services; explicit code rollback works", () => {
  const f = fixture();
  try {
    const result = f.run("deploy", next, f.pack());
    assert.equal(result.status, 0, result.stderr);
    assert.equal(readlinkSync(`${f.root}/state/current`), `${f.root}/releases/${next}`);
    assert.match(readFileSync(`${f.root}/restarts`, "utf8"), /^-n \/usr\/bin\/systemctl restart aifinance-preview-api.service aifinance-preview-web.service\n$/);
    assert.equal(f.run("rollback", old).status, 0);
    assert.equal(readlinkSync(`${f.root}/state/current`), `${f.root}/releases/${old}`);
  } finally { f.clean(); }
});

test("failed health check restores previous code and reports failure", () => {
  const f = fixture();
  try {
    f.make(next); writeFileSync(`${f.root}/fail-new`, "");
    const result = f.run("rollback", next);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Previous code restored/);
    assert.equal(readlinkSync(`${f.root}/state/current`), `${f.root}/releases/${old}`);
  } finally { f.clean(); }
});

test("schema mismatch and invalid revisions fail before any service restart", () => {
  const f = fixture();
  try {
    f.make(next, "different-schema");
    assert.notEqual(f.run("rollback", next).status, 0);
    assert.notEqual(f.run("rollback", "../../other-service").status, 0);
    assert.equal(existsSync(`${f.root}/restarts`), false);
    assert.equal(readlinkSync(`${f.root}/state/current`), `${f.root}/releases/${old}`);
  } finally { f.clean(); }
});

test("archive escape is rejected without switching code", () => {
  const f = fixture();
  try {
    const archive = `${f.root}/incoming/${next}.tar.gz`;
    const result = spawnSync("python3", ["-c", "import tarfile,sys; t=tarfile.open(sys.argv[1],'w:gz'); m=tarfile.TarInfo('../escaped'); m.size=0; t.addfile(m); t.close()", archive]);
    assert.equal(result.status, 0);
    const checksum = createHash("sha256").update(readFileSync(archive)).digest("hex");
    assert.notEqual(f.run("deploy", next, checksum).status, 0);
    assert.equal(existsSync(`${f.root}/restarts`), false);
    assert.equal(existsSync(`${f.root}/releases/escaped`), false);
  } finally { f.clean(); }
});

test("native launcher rejects external credentials/database and constructs a fresh closed environment", () => {
  const result = spawnSync("python3", ["-B", "-c", `
import importlib.util
spec=importlib.util.spec_from_file_location('preview', 'deploy/native/run-preview.py')
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
text='DATABASE_URL=postgres://preview:local@127.0.0.1:5432/aifinance_preview\\nSITE_URL=https://preview.example.com\\nADMIN_PASSWORD='+'a'*16+'\\nSESSION_SECRET='+'b'*32+'\\nIMG_PROXY_SIGN_SECRET='+'c'*32
out=m.environment(text)
assert out['MODEL_CALLS_ENABLED']=='false' and out['PREVIEW_MODE']=='true'
for bad in (text+'\\nLLM_API_KEY=no', text.replace('127.0.0.1','example.com'), text+'\\nMODEL_CALLS_ENABLED=true'):
    try: m.environment(bad)
    except ValueError: pass
    else: raise AssertionError('unsafe config accepted')
`], { cwd: repo, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
});
