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

Review `build-result.json` and the printed artifact SHA256. It is the digest of YOUR locally generated `collector-runtime.tar.gz`; do not substitute a digest from another machine or this documentation. The archive is a collector runtime, not a full website build. No existing `node_modules` is copied. Native lifecycle scripts have not been needed for the collector tests; if anything requires them, stop and review that specific requirement instead of enabling all scripts.

## 3. Copy only the fixed helper into a NEW root-owned review directory

The next actions require the existing operator's sudo, not the restricted deploy gateway. The first command creates a new directory and must fail if it already exists. Do not overwrite an earlier attempt.

```sh
sudo mkdir -m 0700 /root/aifinance-once-helper
git -C "$HOME/aifinance-collect-review" archive "$HELPER_SHA" scripts/collect-once-bootstrap | sudo tar -x -C /root/aifinance-once-helper --no-same-owner --no-same-permissions
sudo /usr/bin/python3 -I -B /root/aifinance-once-helper/scripts/collect-once-bootstrap/configure.py --helper-commit "$HELPER_SHA" --build-dir "$HOME/aifinance-collect-build"
```

The configure step verifies its SHA list, the fixed build receipt and the actual artifact hash, copies the artifact into an exclusive root directory, and asks locally for the approved existing database name/port/application role/restricted deploy OS account. These are validated inputs, not arbitrary commands or paths. Existing API/Web systemd users must map to the same non-root UID; ambiguity stops. Configuration makes NO service, firewall or database changes. It prints concrete `check`, `run` and recovery commands with the newly computed artifact hash.

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
