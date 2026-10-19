# Fixed Git build and one-shot collector bootstrap

This directory is an opt-in operator tool, not a deployment workflow. It neither changes a branch deployment policy nor grants remote/sudo access. The application baseline is exactly `d57ba047369e666025347719caee1a4c642abe62`; never build from moving main. Pin this helper to the full commit provided with its review. Existing files elsewhere in this repository describe older workflows; do not run their seed, migration, deploy or timer steps as part of this procedure.

## Approved boundary

One batch of the three existing public RSS feeds; disabled + isolated + collect_only; maximum three processed items, retained summary at most 2,000 characters. No article-page fetch, model calls, publication, migration, seed or timer. Dedicated OS and database identities, column-level grants, UID-only egress, 256 MiB / 32 tasks / 50% CPU / 120-second service limit. Website files and application-role permissions remain unchanged. A backup precedes activation; cleanup revokes only the new role and removes its credential/network rules while retaining data and audit artifacts.

Actual database names, ports, application roles and deployment identities are NOT supplied by this public directory. `configure.py` validates and binds them locally using a root TTY. Do not publish the resulting `/root/aifinance-once-review`, build caches, logs, credentials or DB backups. This local binding does not authorize a different server/database or broader access.

## 1. Obtain the reviewed helper as the existing non-root operator

Use a NEW directory in your home, outside all website directories. Set `HELPER_SHA` to the full reviewed helper commit supplied in the approval conversation, not a branch name. Each line is a separate command; stop on any error.

```sh
HELPER_SHA=<full-reviewed-helper-commit>
git init "$HOME/aifinance-collect-review"
git -C "$HOME/aifinance-collect-review" fetch --no-tags --depth=1 https://github.com/leoronaldo10/AIFinance.git "$HELPER_SHA"
git -C "$HOME/aifinance-collect-review" checkout --detach "$HELPER_SHA"
cd "$HOME/aifinance-collect-review/scripts/collect-once-bootstrap"
sha256sum -c SHA256SUMS
python3 -I -B test.py
```

No dependency installation is needed for these offline Python tests. Git/python3/node>=24.11/npm must already be installed; do not install tools globally or override a refusal. Commands fetching Git/npm have bounded timeouts inside the builder; a denied endpoint is not an invitation to use a mirror.

## 2. Build locally as NON-root

```sh
python3 -I -B build-runtime.py --helper-commit "$HELPER_SHA" --output "$HOME/aifinance-collect-build"
```

The output directory must be absent. This fetches the exact application commit into an isolated source tree, verifies lock SHA256 `cb9821a67f7044e86c51ac5149fa0f7550511342b00560c4c593d4fc42bae503`, and runs `npm ci --ignore-scripts --omit=dev --workspace=@aihot/backend --include-workspace-root=false` against the official npm registry. npm cache/home/config are isolated; existing website files and `.env` are not read. Lifecycle scripts remain disabled. Every installed external package tarball is checked against lockfile SHA-512 before packaging.

Review `build-result.json` and the printed artifact SHA256. It is the digest of YOUR locally generated `collector-runtime.tar.gz`; do not substitute a digest from another machine or this documentation. The archive is a collector runtime, not a full website build. Only the isolated build’s verified dependencies are packaged, including workspace-local `node_modules`. Native lifecycle scripts have not been needed for the collector tests; if anything requires them, stop and review that specific requirement instead of enabling all scripts.

## 2a. Repair an existing isolated build without reinstalling

Use the newly reviewed helper commit, not the earlier helper that omitted workspace-local dependencies. After obtaining that helper and running its checksum/tests, keep the existing build untouched and use a NEW output directory:

```sh
python3 -I -B build-runtime.py --helper-commit "$HELPER_SHA" --repack-existing "$HOME/aifinance-collect-build" --output "$HOME/aifinance-collect-repacked"
```

This mode runs no fetch, npm command, lifecycle script or installation. It requires the old build receipt, original archive, exact clean tracked source and existing npm cache. It checks cached tarball SHA-512 and installed file bytes, verifies the required dependency graph and workspace aliases, includes nested dependencies, and validates the extracted archive by loading the real HTTP and collector modules with network disabled. Missing cache/files, changed source or invalid dependencies stop the process; there is no automatic reinstall. Optional dependency counts can differ without weakening required-dependency checks.

Use `--build-dir "$HOME/aifinance-collect-repacked"` in step 3 and its newly printed digest. Older receipts without runtime validation are refused. Root preflight independently verifies the archive’s inventory and required dependencies; it does not execute the JavaScript probe as root. Do not overwrite existing root review directories or proceed to run after a failed check.

## 3. Copy only the fixed helper into a NEW root-owned review directory

The next actions require the existing operator's sudo, not the restricted deploy gateway. The first command creates a new directory and must fail if it already exists. Do not overwrite an earlier attempt.

```sh
sudo mkdir -m 0700 /root/aifinance-once-helper
git -C "$HOME/aifinance-collect-review" archive "$HELPER_SHA" scripts/collect-once-bootstrap | sudo tar -x -C /root/aifinance-once-helper --no-same-owner --no-same-permissions
sudo /usr/bin/python3 -I -B /root/aifinance-once-helper/scripts/collect-once-bootstrap/configure.py --helper-commit "$HELPER_SHA" --build-dir "$HOME/aifinance-collect-build"
```

The configure step verifies its SHA list, the fixed build receipt and the actual artifact hash, copies the artifact into an exclusive root directory, and asks locally for the approved existing database name/port/application role/restricted deploy OS account. These non-secret inputs are visible and validated individually. Review the artifact digest and all four fields, then type CONFIRM before any root review files are created. Database administrator credentials are not requested by configure; the later check/run prompt remains hidden. Refusals identify the stage and field or exception type without printing exception payloads. These are validated inputs, not arbitrary commands or paths. Existing API/Web systemd users must map to the same non-root UID; ambiguity stops. Configuration makes NO service, firewall or database changes. It prints concrete `check`, `run` and recovery commands with the newly computed artifact hash.

## 4. Root TTY: check, then one run, then verify cleanup

Enter `sudo -i` in the same server terminal. Run the printed **check** command first. At its hidden prompt, enter the ORIGINAL existing DB administrator URI, on the server only; do not put it in chat, arguments, shell history or files. It must match the locally bound loopback target. Unknown administrator authentication is a stop condition; no password guessing, pg_hba edits or credential reset.

**If check fails, STOP. Do not run `run`, change privileges, remove guards, or repair source rows automatically.** On success, establish the approved exclusive writer window and execute the printed `run` command once. It repeats preflight, creates new isolated identities/units, runs a no-network/no-DB resource probe, makes a protected custom-format DB backup, installs UID-only network rules and column grants, verifies the dedicated role's read-only login, consumes a single-use latch and runs the batch. Approval scope must already cover those changes.

Preflight requires unified cgroup v2 with memory/pids/cpu. It verifies unit `ControlGroup` against the process membership and checks real `memory.max`, `pids.max`, `cpu.max`; v1, missing controllers, unsafe/unreadable paths or wrong limits are refused. DNS snapshots expire after 180 seconds without refresh. Existing firewall tables remain untouched. Shared CDN IPs alone cannot enforce hostname/path isolation; immutable code and TLS checks also apply.

Success requires exit 0, a successful batch receipt and `cleanup_finished.complete=true`. Cleanup rechecks inactive/MainPID 0, NOLOGIN/password cleared, grants revoked, no remaining dedicated-role sessions, credential/ready removal and own nft table absence. Nonce mismatch reports incomplete. Failed check has no installation to clean; failed/interrupting installation must use the printed fixed recovery command:

```sh
/usr/bin/python3 -I -B /root/aifinance-once-review/bootstrap.py cleanup
```

Recovery again needs local root TTY and hidden original DB administrator authentication. Do not delete the consumed latch or rerun the batch automatically. Cleanup preserves collected material, source cursor/health changes, sequences, backup, audit/snapshot files and nologin identities; it is not a destructive data rollback. Login expiry alone does not terminate existing sessions. `pg_restore --list` is not a restore rehearsal. Return only sanitized stage/count/cleanup evidence, never credentials, source bodies or backups.

## Validation and limitations

`test.py` renders templates with synthetic targets and runs offline grant-shape/orchestration/cgroup/build tests. Optional `test.py --postgres` is ONLY for a disposable isolated test cluster: supply `COLLECT_TEST_PSQL`, `COLLECT_TEST_SOCKET`, `COLLECT_TEST_PORT`, `COLLECT_TEST_ADMIN`; it creates/drops `collector_fixture_ci` and fixture roles. Never point it at a real database cluster.

The fixed application collector and summary overlay were also tested with synthetic in-memory RSS and an isolated database under the dedicated grants: create, duplicate, revise, source rejection, <=3 processed, <=2000 summary, application role read-only. That is not target root/systemd/nft acceptance or current source reachability. No actual server evidence or private approval metadata is committed here. These changes add no CI workflow or auto-deployment and must not be merged into main as part of this task.

The standalone `tests/test_runtime_http.mjs <extracted-runtime>` integration test requires an isolated test process with `NODE_ENV=test`, `ALLOW_PRIVATE_NETWORK_FETCH=true` and all collection/model/publication flags disabled. It starts its own loopback HTTP fixture, permits socket connections only to that fixture, loads the real HTTP module (no mocks), and verifies fetch and response-size enforcement. These test-only network settings must never be applied to deployment configuration.

## Configure-only updates and existing runtimes

This configure revision explicitly accepts receipts from published build helper `0037375d52c49251f4be42e8de8be410b56f51ae` as well as its own helper commit. Compatibility is not a general SHA mismatch allowance: the previous builder, module probe, and shared dependency validator must retain their exact pinned SHA256 values. A changed component, any other older helper SHA, incorrect baseline/lock, missing runtime validation, or mismatched artifact hash is refused. Future changes to these build components require a separate compatibility review, not an automatic whitelist expansion.

The original `build-result.json` and its `helper_commit` remain unchanged; no receipt is rewritten or relabeled. Configure prints both the configuration helper SHA and original builder SHA. Reuse the existing validated runtime directly with `--build-dir`; no download of runtime dependencies, npm install, or repack is required. Root archive preflight and all runtime safety templates remain unchanged.

For an already staged older helper, retain it. Download/check out the newly approved full helper commit into a NEW non-root review directory, verify its tree and SHA256SUMS, then archive only this helper into a NEW root directory such as `/root/aifinance-once-helper-ux`. Invoke its configure with the NEW helper SHA and the EXISTING build directory. Do not reuse or overwrite `/root/aifinance-once-helper`. The final `/root/aifinance-once-review` must still be absent; if it exists, stop and inspect before any retry. Only visible inputs and the explicit CONFIRM step may create this final review. Keep later check/run separate.

## Explicit local-socket administrator mode (PostgreSQL 17)

When an operator has separately verified an existing passwordless local administrator connection, `bootstrap.py check|run|cleanup --admin-auth local-socket --admin-socket /var/run/postgresql` selects that connection explicitly. `/run/postgresql` is the canonical equivalent. The bound database and port come from the existing review, not new input. The existing postgres OS account and postgres database role are required, and a read-only identity query plus the existing superuser/catalog audit must pass. Success does not establish whether the server HBA method is peer or trust. No HBA change, password reset, new administrator, passfile lookup, or automatic fallback is performed.

The parent remains root for host operations. Only administrator psql and pg_dump children use the existing postgres UID/GID with supplementary groups cleared. PostgreSQL 17 binaries are fixed under `/usr/lib/postgresql/17/bin`, validated as trusted tools. The child environment is constructed from scratch with HOME=/nonexistent, an explicit socket/port/database/user, PGPASSFILE=/dev/null, and no password; `-w` disables password prompts. libpq may warn that /dev/null is not a regular password file; captured stderr is not printed. Credentials are not read from another file. URI mode remains the default and retains its hidden prompt. Neither mode falls back to the other on failure.

The dedicated collector login probe and collector service remain on loopback TCP with their own existing short-lived credential mechanism. SQL audits, grants, revoke, connection termination and administrator cleanup all use the selected administrator connection. Its non-secret binding is recorded in the root state; recovery must explicitly select the same mode/socket. A mode mismatch stops before cleanup actions.

Before backup, root verifies the state directory and creates before.dump with O_EXCL|O_NOFOLLOW, root ownership and mode 0600. The postgres child receives only the open stdout descriptor; it cannot traverse the root-only state directory and never receives the backup pathname. pg_dump runs with password prompting disabled and default_transaction_read_only=on. Failure stops activation; the existing finally-cleanup remains in force. The real dump is checked with pg_restore --list, which is not a production restore rehearsal.

### Preserve an already configured review

Stage the reviewed new helper in a NEW root directory, with its release manifest verified. Then run its `upgrade-review.py --sha256 <existing-runtime-digest>` from the existing operator's root TTY. This creates `/root/aifinance-once-review-socket`; it never edits `/root/aifinance-once-review`. No configuration inputs or rebuild are required. The updater verifies the old manifest, the exact previously approved bootstrap template and recovered bindings, every unchanged rendered template, and the existing runtime digest before any write. It refuses any existing installation or destination. The only changed review files are bootstrap.py and SHA256SUMS; the runtime is copied locally byte-for-byte. Do not overwrite a partial sibling after an error.

Publication and installation of this administrator-mode change require explicit approval. The update itself makes no DB, service, firewall, account or authentication changes. Run the new sibling's check separately with the explicit local-socket flags; run remains a separate approved action with the original batch/writer-window flags. Cleanup also needs these local-socket flags. Never run both reviews or restart a consumed batch.

### Validation limits

The local-socket suite executes real SQL, grants/revocation, pg_dump output and pg_restore listing against a disposable PostgreSQL cluster. The available test environment is non-root: tests intercept the OS identity-switch arguments and assert them separately; they do not claim a kernel-level root-to-postgres transition or root-owned dump was exercised locally. Production code always requests that transition and fails closed if it fails. File tests exercise exclusive creation, mode 0600, existing-file preservation and symlink refusal. Existing URI-path and safety suites remain required.

### Approved recovery of the pre-start TCP/HBA refusal (retry-001)

`retry-once.py` is a separate, exact-target local-root tool. It never changes the
old review, original runtime, original `state.json`, backup, or consumed latch.
Only `aifinance_preview:55432`, application role `aifinance_app`, deploy identity
`aifinance-deploy`, and runtime SHA256
`a88da42096a452d526e7cd53f6fdf26e6349cf1cd3d148428cefa9e73632656a` are accepted.
The sibling helper must be checksum-verified before execution. This recovery was
explicitly approved together with a temporary exact HBA rule and one retry.

`check` performs no writes. `run --approve-three-source-smoke
--exclusive-writer-window` repeats those gates and exclusively creates
`/var/lib/aifinance-collect-once/retry-001`, permanently consuming this recovery
attempt even on failure. `cleanup` only disables/verifies this same marked
attempt and restores its HBA change; it cannot start a batch. No automatic retry.

Required evidence: original attempt within the current boot, original phase disabled, verified backup and original role
marker, NOLOGIN/password NULL/revoked rights, no membership or privileged role
attributes, trusted unchanged runner/latch/unit and entire frozen runtime tree,
no consumed/ready/credential file, inactive static service with zero recorded
main-process start/PID/restarts, no timer. Missing or conflicting evidence stops
before mutation. The root-owned durable consumed latch is the principal
pre-start evidence; this does not attempt to defend against a root operator who
previously deleted or forged audit files. Never delete old state to pass a gate.
The old resolver bindings must be canonical, match the original network receipt,
and retain `hosts: files`. Only after that proof, fresh public IPv4 answers for
the same three approved HTTPS hosts may differ. Address order/duplicates are
canonicalized. The old resolver bytes and hashes are preserved in retry-001.

The existing OS/DB identity is reused only after ownership and safety checks.
The exact old grants are reapplied without CREATE ROLE, with a new short-lived
SCRAM password. A new backup is placed under retry-001; old backups are retained.
After the new backup, resolve again and pin one fresh snapshot to hosts and the
UID firewall, then perform the resource probe before activating credentials. The
180-second freshness clock starts before the first DNS request. Probe and batch
resource limits, three-source/three-item cap, and disabled source
flags remain unchanged. The installed systemd service/runner is not rewritten.

HBA: locate `SHOW hba_file`, require a trusted regular single-link file without
extended attributes; refuse includes/continuations, existing matching or ambiguous
rules, parse errors, pending restart or file changes newer than configuration
load. Snapshot config hashes; append only
`host aifinance_preview aifinance_collect_once 127.0.0.1/32 scram-sha-256` inside a
unique comment block. Preserve all old rule bytes/order, owner/group/mode, atomically
replace and fsync, validate parsed rule, reload (never restart), wait for reload
observation, then require the real TCP read-only identity probe. All operations
require an exclusive configuration-edit window as well as the DB writer window:
hash checks detect intervening changes but cannot prevent a non-cooperating root
writer racing the last compare and rename. No concurrent administrator edits.

Cleanup always attempts DB/session/credential/firewall/ready cleanup, HBA restore,
original resolver snapshot restore, and website baseline/HTTP health checks. HBA rollback restores original bytes only
when the current file is exactly original or exactly our addition; other changes
are preserved and reported for operator recovery. The role is disabled first.
`retry_cleanup_finished complete=true,hba_restored=true,resolver_restored=true`
is the overall receipt;
the old `cleanup_finished` alone is insufficient. Protected audit files contain
original HBA and hashes, old state copy, new backup/state, and sanitized retry events.
Raw client stderr/passwords are never persisted. `cleanup` can recover a completed
HBA receipt after interruption; unreadable/ambiguous receipts fail closed.

Test with an existing PostgreSQL 17 distribution (no software installation):
`RETRY_TEST_PG_BIN=/path/to/bin RETRY_TEST_PG_SHARE=/path/to/share python3 -I -B tests/test_retry_hba.py`.
It creates/stops a disposable cluster on 127.0.0.1:56441 and temporary Unix socket.
Tests cover real SCRAM correct/wrong credentials, absent HBA, other role/database
denial, column grants/forbidden writes, regrant/revoke, loaded HBA rollback,
concurrent edits, reload failure, interrupted HBA recovery and retry/start guards.
Root ownership/uid transitions and systemd kernel evidence cannot be integrated
locally under the non-root runner; production gates verify them before the batch.


### DNS-only recovery-helper revision

The published predecessor could stop at `feed_resolution_changed_requires_review`
before HBA inspection, retry-001 creation, credential generation, network writes,
or service start. No cleanup is needed for that preflight refusal. The installer
now starts from the exact checksum-verified predecessor helper and creates
`/root/aifinance-once-helper-retry-dns/helper`; the older helper is preserved. An
already complete new helper may be reused only after its full fixed manifest is
verified and retry-001 remains absent. A partial/mismatched helper or any retry-001
entry is a hard stop; nothing is deleted or reset. The retry ID remains retry-001.

Resolver changes touch only the dedicated `hosts` snapshot, with the same
root:collector ownership and 0440 mode. `nsswitch.conf`, the site, TLS behavior,
fixed URLs, source flags, service unit, and runtime are unchanged. Resolution uses
only the three exact hostnames and accepts 1–8 distinct globally routable,
non-multicast, non-reserved IPv4 addresses per host. No DNS egress is added to the
collector, no domain or subnet is added, and the UID firewall still rejects all
other traffic. The runner keeps default TLS certificate verification and existing
same-origin redirect restrictions. DNS output is parsed as address data only.

The original snapshot is checked against the original network SHA256, not just
against today's DNS. A receipt is fsynced before atomic replacement. Cleanup and
interrupted-attempt cleanup restore old bytes only if current content is exactly
our old or new snapshot; concurrent edits are preserved and reported. New DNS
results after pinning cannot widen the in-flight batch. A fresh address becoming
unavailable still causes a normal bounded failure, never a permissive fallback.

Offline resolver/cleanup tests (no external DNS):
`python3 -I -B tests/test_retry_resolver.py`.
The same-boot/no-start proof, consumed/retry latches, file integrity, 180-second
freshness and pending-server-configuration checks remain hard safety gates.


### Local-only v3 lifecycle integration — not a retry authorization

The process module is byte-identical to readiness-diagnostic v3 at commit
c36f4f215fce492bff11250c434d2a5a91829b6f (SHA256
f5ca1ad6788ca4365118ab06ceac433509837239761c0a8ce1e99ad896a447d6).
The user supplied successful ECS v3 sleep/Python readiness, natural-exit and
cleanup evidence. No repeat diagnostic is required by this preparation.

Both production adapters now use the held pidfd and stable execution identity,
UID/GID/capability/NNP, cgroup and read-only resolver checks. RemainAfterExit=yes
retains only unit metadata after the child naturally exits. Two bounded terminal
reads verify the original invocation, execution PID/start stamp, dead pidfd and
successful natural exit before stopping the unit. Running cgroup mismatch still
fails; an exited process may have no remaining cgroup. The isolated sleep probe
runs its existing 30 seconds to natural exit. Collector TimeoutStartSec=120,
runner deadline=105, memory=256MiB, CPU=50%, TasksMax=32 remain unchanged; the
130-second observer deadline does not extend execution permission.

Evidence uses an explicit per-operator directory, never directory-existence
routing into retry-001. Collector journal receipts are restricted to the verified
invocation. No diagnostic installer/controller, extra command, permission, or
network policy is imported. The runtime, consume.py and database policy are
unchanged. The existing retry-001 entry still refuses a used attempt; this patch
includes a separate fixed retry-002.py install/check/run/cleanup/status entry,
validated against the pinned legacy bootstrap template. See RETRY-002-PLAN.md for
installation, independent audit/lock/claim paths, recovery and exact pending
permissions. No new attempt is authorized merely by installing this package.

Local validation covers adapter sequencing, adverse transitions and real Linux
pidfd behavior, plus disposable PG17 and resolver regressions. Root/systemd
integration of the collection adapter and live database/feed reachability have
not been tested here; the successful inert v3 diagnostic does not establish them.

The approved distribution entry is retry-002-handoff.py: fixed commit and external
manifest pins, per-file verification before and after privilege elevation, atomic
helper staging, install/check/run with real exit codes. An existing retry-002
claim selects cleanup/status only; it never repeats collection. See the plan for
disconnect handling and durable root handoff-results.jsonl receipts.
