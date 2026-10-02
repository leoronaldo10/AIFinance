import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, symlinkSync, readlinkSync, rmSync, existsSync, statSync, readdirSync } from "node:fs";
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
  writeFileSync(script, readFileSync(path.join(repo, "deploy/native/release.sh"), "utf8").replaceAll("/opt/aifinance/runtime/node/bin/node", path.join(root, "bin/node")));
  writeFileSync(path.join(root, "extract-release.py"), readFileSync(path.join(repo, "deploy/native/extract-release.py")));
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
    assert.equal(statSync(`${f.root}/releases/${next}`).mode & 0o7777, 0o755, "separate runtime UID can traverse release root");
    assert.equal(statSync(`${f.root}/releases/${next}/apps/web/build/server/index.js`).mode & 0o7777, 0o644);
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

test("first failed deploy reports no rollback and never silently widens restart-only sudo", () => {
  const f = fixture();
  try {
    rmSync(`${f.root}/state/current`);
    writeFileSync(`${f.root}/fail-new`, "");
    const result = f.run("deploy", next, f.pack());
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /no rollback performed; failed release remains current/);
    assert.match(result.stderr, /Restart-only sudo cannot stop these services/);
    assert.match(result.stderr, /separately approved provisioning permission change/);
    assert.doesNotMatch(result.stderr, /Previous code restored/);
    assert.equal(readlinkSync(`${f.root}/state/current`), `${f.root}/releases/${next}`);
    assert.equal(readFileSync(`${f.root}/restarts`, "utf8"), "-n /usr/bin/systemctl restart aifinance-preview-api.service aifinance-preview-web.service\n");
  } finally { f.clean(); }
});

test("release checks only the separately provisioned Node runtime", () => {
  const script = readFileSync(path.join(repo, "deploy/native/release.sh"), "utf8");
  assert.match(script, /\/opt\/aifinance\/runtime\/node\/bin\/node -e/);
  assert.doesNotMatch(script, /\/usr\/local\/bin\/node/);
});

test("stale switch symlink or real directory fails closed without touching its contents", () => {
  for (const staleKind of ["symlink", "directory"]) {
    const f = fixture();
    try {
      const pending = `${f.root}/state/.current-next`;
      if (staleKind === "symlink") symlinkSync(`${f.root}/releases/${old}`, pending);
      else mkdirSync(pending);
      writeFileSync(`${pending}/keep`, "operator-owned evidence");
      const result = f.run("deploy", next, f.pack());
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /Pending release switch exists; operator review required/);
      assert.equal(readFileSync(`${pending}/keep`, "utf8"), "operator-owned evidence");
      assert.equal(existsSync(`${f.root}/releases/${old}/${next}`), false);
      assert.equal(existsSync(`${f.root}/releases/${next}`), false);
      assert.equal(existsSync(`${f.root}/restarts`), false);
      assert.equal(readlinkSync(`${f.root}/state/current`), `${f.root}/releases/${old}`);
    } finally { f.clean(); }
  }
});

test("failure or termination before atomic switch preserves current and cleans only its own temporary link", () => {
  for (const interrupted of [false, true]) {
    const f = fixture();
    try {
      const failure = interrupted ? 'kill -TERM "$PPID"; exit 0' : "exit 73";
      writeFileSync(`${f.root}/bin/mv`, `#!/usr/bin/env bash\nif [[ "$1" = -Tf ]]; then ${failure}; fi\nexec /bin/mv "$@"\n`, { mode: 0o755 });
      const result = f.run("deploy", next, f.pack());
      assert.equal(result.status, interrupted ? 143 : 1, result.stderr);
      assert.equal(readlinkSync(`${f.root}/state/current`), `${f.root}/releases/${old}`);
      assert.equal(existsSync(`${f.root}/restarts`), false);
      assert.equal(readdirSync(`${f.root}/state`).includes(".current-next"), false);
      assert.equal(readdirSync(`${f.root}/releases`).some(name => name.startsWith(".stage-")), false);
    } finally { f.clean(); }
  }
});

test("health must match requested SHA even when switch falsely reports success", () => {
  const f = fixture();
  try {
    writeFileSync(`${f.root}/bin/mv`, '#!/usr/bin/env bash\nif [[ "$1" = -Tf ]]; then rm -- "${@: -2:1}"; exit 0; fi\nexec /bin/mv "$@"\n', { mode: 0o755 });
    const result = f.run("deploy", next, f.pack());
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /New release failed health check/);
    assert.doesNotMatch(result.stdout, /Active AIFinance release/);
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
    assert.equal(readdirSync(`${f.root}/releases`).some(name => name.startsWith(".stage-")), false);
  } finally { f.clean(); }
});

test("compressed metadata bomb is rejected and staged files cleaned before any service action", () => {
  const f = fixture();
  try {
    const archive = `${f.root}/incoming/${next}.tar.gz`;
    const packed = spawnSync("python3", ["-B", "-c", "import io,tarfile,sys; t=tarfile.open(sys.argv[1],'w:gz',format=tarfile.PAX_FORMAT); m=tarfile.TarInfo('do-not-echo-payload'); m.size=1; m.pax_headers={'comment':'x'*(1024*1024)}; t.addfile(m,io.BytesIO(b'x')); t.close()", archive]);
    assert.equal(packed.status, 0);
    const checksum = createHash("sha256").update(readFileSync(archive)).digest("hex");
    const result = f.run("deploy", next, checksum);
    assert.notEqual(result.status, 0);
    assert.equal(result.stderr, "Release extraction refused: resource limit exceeded or unavailable\n");
    assert.equal(existsSync(`${f.root}/restarts`), false);
    assert.equal(existsSync(`${f.root}/releases/${next}`), false);
    assert.equal(readlinkSync(`${f.root}/state/current`), `${f.root}/releases/${old}`);
    assert.equal(readdirSync(`${f.root}/releases`).some(name => name.startsWith(".stage-")), false);
  } finally { f.clean(); }
});

test("native launcher rejects external credentials/database and constructs a fresh closed environment", () => {
  const result = spawnSync("python3", ["-B", "-c", `
import importlib.util
spec=importlib.util.spec_from_file_location('preview', 'deploy/native/run-preview.py')
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
text='DATABASE_URL=postgres://aifinance_preview:local@127.0.0.1:55432/aifinance_preview\\nSITE_URL=https://preview.example.com\\nADMIN_PASSWORD='+'a'*16+'\\nSESSION_SECRET='+'b'*32+'\\nIMG_PROXY_SIGN_SECRET='+'c'*32
out=m.environment(text)
assert out['MODEL_CALLS_ENABLED']=='false' and out['PREVIEW_MODE']=='true'
for bad in (text+'\\nLLM_API_KEY=no', text.replace('127.0.0.1','example.com'), text+'\\nMODEL_CALLS_ENABLED=true'):
    try: m.environment(bad)
    except ValueError: pass
    else: raise AssertionError('unsafe config accepted')
`], { cwd: repo, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
});
