# Fixed remote operations for the native preview

This optional entry replaces repeated administrator-terminal diagnostics with a small fixed command set. It must be explicitly approved and installed by an administrator. Possession of the source, a passing CI run, or staging an application artifact does not install it or authorize a server action.

The existing SSH key, forced command, GitHub Environment reviewers and release-branch restriction remain. The key-bearing Actions job never checks out project code. Every remote operation still requires the existing Environment approval. Neither arbitrary shell commands nor caller-selected paths, services, URLs or root scripts are accepted.

## Components and installation

- `ops-gateway.py` is the new, separately reviewed gateway source. The installer places it at the existing root-owned `ssh-gateway.py` entry. The legacy gateway source and first-preview manifests remain unchanged.
- `ops-broker.py` implements the fixed root actions, validates its root-only policy and pinned maintenance helpers, and serializes operations on the existing release lock.
- `install-ops.py` is a root-terminal-only installer. It has no remote verb or sudo permission. Its source directory contains exactly the four reviewed Python files and a pinned manifest.
- `ops-files.json` pins those four file contents. The operator command must also pin the manifest and the full reviewed Git commit. Use the prepared complete download/check/apply command; do not assemble unverified fragments or skip hashes.

The installer checks existing identities, forced-key restrictions, SSH environment settings, sudo policy, known application/helper versions, and the paused collector state before any persistent write. It then preserves root-only backups, installs the broker and private policy, replaces the exact reviewed runner and four idle collector units to use `Requisite=database` instead of `Requires=database`, reloads and verifies that configuration, validates eight exact sudo commands, and atomically switches the gateway last. `Requisite` refuses collection when the database is inactive instead of starting the database; the database and API/Web unit files remain unchanged. Its completion marker is written only after verification. It does not collect feeds, restore collector DB-file access, start services, change firewall rules, enable a timer or create `native-ready`.

A partial installation stops. Preserve its source bundle, private evidence and staging files. Do not rerun apply, delete evidence, or repair unknown permissions. Recovery must verify every affected file and the old gateway backup under the same lock, restore only the known gateway, runner and four collector unit files from their verified backups, reload only configuration, and archive only this installation's exact sudo fragment. It must first establish that no operation or timer can run during recovery. It must never erase an unknown file or grant broad sudo.

## Workflow operations

Use the existing `deploy-preview.yml` workflow on `release/aifinance-preview`. For every `ops-*` operation, leave `revision` empty. Build/stage/deploy/rollback keep their existing behavior and restrictions; ops do not build or execute uploaded code.

| Workflow operation | Fixed server action |
| --- | --- |
| `ops-diagnose` | Read bounded, sanitized service/check/receipt information. No raw application logs, environment contents or credentials are returned. |
| `ops-restart-preview` | Restore or restart only API/Web after checking the accepted application, original guard, reviewed units, database state and idle collector. An installed hourly timer must be disabled first. |
| `ops-probe` | Run the fixed isolated resource probe. It does not fetch RSS or write the database. |
| `ops-recover-pre-seed` | Recover one verified failure before the first seed: prove absence of effects through a quiet read-only database transaction, durably preserve the original attempt and recovery index, then restore only the original DB-only file's group-read permission. |
| `ops-seed` | Seed only the three fixed, disabled, isolated collect-only sources after a successful recovery. A new attempt is durable before work begins. |
| `ops-run` | Perform the first fixed-source batch, at most three processed items including revisions, with the existing content isolation and zero-downstream-change checks. |
| `ops-disable` | Stop the fixed collector/timer, revoke collector DB-file group read and its HTTPS access, preserving data and evidence. |
| `ops-enable-hourly` | Enable the fixed hourly schedule only after the successful first-batch receipt and explicit administrator-view acceptance. |

`admin_view_accepted` must be `true` only for `ops-enable-hourly`; that operation refuses `false`, and other operations reject `true`. An ordinary access approval does not silently assert that someone inspected the admin page.

Read-only diagnosis is the first action after installation. Recovery is not authorized by missing receipts alone: the installer and broker bind it to the same original failure instance, fixed code/application, trusted private records, idle identities, protected DB-only file and an independent database proof. Unknown, partial or already-attempted states stop for review. Existing failed attempts are preserved, not silently reset.

Failures report a fixed stage and reason code. After authorized mutations begin, cleanup reports collector shutdown and safe API/Web restoration separately; failure in either is not reported as success. The original database service, unrelated service and network boundary are not part of website recovery.

## Limits and continued review

Public workflow output is bounded JSON with allowlisted statuses, checks and counts. Detailed evidence stays in root-only server files. Host addresses, private paths, environment values, credentials and raw journal messages are excluded. Individual commands and operation lifetimes are bounded; existing collection memory, process and time limits remain.

This entry does not accept a new root helper through SSH upload, generalize database migrations, sign off `native-ready`, or certify load/reboot recovery. A new root-code fix still needs code review, exact hash approval and a fixed update procedure. An application upgrade retains the existing separate schema and deployment checks.

Offline fixtures, real Python 3.6 CI and disposable PostgreSQL tests verify code paths. Actual target resource enforcement and first-batch behavior must still be observed through the fixed entry before enabling the schedule.

## Existing cloud SSH key hooks

`repair-ops-ssh.py` is a separately reviewed, root-terminal-only repair for the known cloud SSH key lookup. It reuses the five unchanged, pinned installer inputs. It appends a restriction for `aifinance-deploy` only and accepts the candidate only when full effective global, root, and preview-account policies are unchanged and the deployment account differs solely in `AuthorizedKeysCommand none`. The exact disjoint `Match User aifinance-preview` block may retain `AuthorizedKeysCommand none`; other conditional key commands, conflicting policy, and unknown configuration layouts stop the repair. The original configuration and repair evidence remain private and are preserved.

The repair validates syntax before an atomic replacement, reloads the existing SSH daemon, then verifies its identity and effective policies. When the running daemon supplies the seven supported vendor cryptographic algorithm options, their original arguments are carried into every syntax and effective-policy check; other command-line policy overrides and duplicate options are refused. A failed SSH phase restores only a recognized configuration. Once SSH verification succeeds and ops installation starts, failure keeps the deployment-account restriction: a partial privileged ops installation must not regain alternate key access. The unchanged installer then checks and applies its original gates. Output includes a bounded stage and safe reason; preserve the evidence and do not retry a partial operation automatically.
