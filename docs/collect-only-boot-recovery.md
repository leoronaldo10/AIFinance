# Collector recovery after a fresh boot

This is a separately reviewed root-terminal recovery for an already installed collect-only release. The historical installation, attempt and probe records remain evidence of their original boot. A successful website-only recovery on the current boot must already exist. The controller does not seed sources, fetch feeds, publish content, create a timer, or add a remote operation.

## Inputs and scope

The administrator supplies `--expected-boot-id` privately. It must be a valid lowercase UUID, match the current kernel boot ID, and match the private manifest's `boot_id`. Public source code and tests contain no deployment boot ID or runtime records.

Place exactly these six files in a fresh, private, root-owned directory matching `/root/aifinance-collector-boot-v2-` plus twelve alphanumeric characters. Files are root:root `0600`; the directory is `0700`:

- `recover-collector-after-boot.py`, from `deploy/native/`
- `update-ops-nss-proof.py`, the unchanged held four-file updater
- `recover-preview-after-boot.py`, the unchanged website validator, used as a pinned library
- `collect-only-runner.py`, from `deploy/native/updates/nss-proof-v1/`
- `ops-broker.py`, from `deploy/native/updates/collector-boot-v2/`
- `manifest.json`, generated privately for this reviewed invocation

The manifest is an exact object with `schema: 2`, `boot_id`, `release`, and `payloads`. The payload map contains the five Python filenames above and their full SHA-256 hashes. The controller checks its own bytes against the externally supplied manifest digest and independently pins all four supporting payloads. The private manifest and target boot ID are not repository artifacts.

Invoke the controller using `python3 -I -B` from an interactive root terminal, with action `check` or `apply`, `--source`, `--manifest-sha256`, and `--expected-boot-id`. `check` is read-only and validates the complete static starting state. Any host-changing `apply` requires separate authorization for its concrete scope. Possession of the payload is not authorization.

## Preconditions

The original installed runner, broker, policy, completion record, upgrade acceptance and installation baseline must match. The original seed-attempt record must still match the historical baseline, with no evidence of a seed/run start. The four collector units must be in the reviewed inactive state after reboot, with no processes or timer, and their unit bytes and effective activation graph must match. The collector account is the existing fixed dedicated account.

The collector database file must retain its original device/inode, root:root ownership and `0400` mode. The old database-only network receipt, protected resolver files and historical output/probe records must be unchanged; the collector nftables table must be absent after reboot. The controller does not infer authorization from this absence.

The website proof must contain the current boot's matching `01-evidence_create.json` and `05-complete.json`, with equal preserved state, healthy website evidence and absent port 8000. The controller independently verifies current release, unit files, effective commands, dependencies, guard, loopback listeners and health. Missing metadata is not treated as proof of an empty systemd property; the existing typed D-Bus fallback handles empty arrays on systemd 239.

## Transaction and recovery

The unchanged NSS updater stages and backs up exactly the runner, broker, policy and completion gate. It preserves their modes, allowed security attributes and inode identities, withholds the completion gate, and rejects unknown concurrent changes. All work holds the canonical existing exclusive release lock and checks for other root controllers.

While the new coherent helper set is installed and the completion gate is still withheld, the boot recovery callback:

1. Durably archives all original collector receipts before any overwrite or rearming
2. Restores only the fixed collector database-only nftables table for the existing UID, preserving the old network receipt and protected resolver files
3. Stops only API and web, verifies that their processes are gone, and proves the pre-seed state through a real read-only database transaction under the application nonsuperuser
4. Checks regular relation ownership, absence of role memberships, enforced read-only mode and exact broad downstream counts
5. Restores collector read access on the same database-file inode to root:collector `0440`
6. Runs a fresh no-network probe and the real read-only checker, including actual cgroup and NSS mount evidence; checks zero collector source/raw state and unchanged downstream counts
7. Restores and verifies API and web, then removes the original attempt name only after verifying its durable archive
8. Writes a distinct schema-2 ready receipt and validates it before the updater publishes the new completion gate

The stable private directory is `/var/lib/aifinance-ops/collector-boot-v2`. It contains transaction backups, original archives, fresh probe/check results and proof records. It is not a fabricated legacy `recovery.json`. Because the directory remains present across reboots, a stale or partial attempt blocks legacy fallback and automatic retries.

On failure, the controller independently attempts to stop probe/check, revoke database read permission on the original inode, verify that collector HTTPS remains revoked, and restore the website using its already verified website provenance. Cleanup outcomes are explicit. Unknown inode, helper, network, guard or unit changes are never overwritten to claim success. Any attempted recovery prevents the updater from reopening the old completion gate. Evidence is retained for review.

## Later operations

The broker retains the same eight operations and all legacy recovery gates. With a v2 attempt directory present, relevant mutations require its valid current-boot receipt. The normal seed gate additionally verifies restored database-file identity and permissions. `diagnose` and `disable` remain available under their existing gates.

For v2 restart and failure cleanup, port 8000 must remain absent. Website restoration validates immutable v2 provenance without requiring collector-readable database credentials, so it can still run after failure cleanup revokes database access. A new unexpected port-8000 listener fails closed. Legacy installations without a v2 directory retain their original listener-preservation rule.

Seed, one bounded first batch and any later hourly acceptance remain separate authorized operations. Recovery success alone does not establish first-batch acceptance or host trust.

## Verification

Offline tests cover immutable legacy payloads/gates, source pins, stale and partial receipts, known/unknown four-file rollback, failure after ready/completion publication, database inode substitution, cleanup independence, current systemd dependency graphs and absent port 8000. A disposable PostgreSQL 17 integration test executes the exact production proof SQL and verifies read-only mutation rejection, membership/owner/view/RLS refusals and unchanged full row/sequence snapshots. CI runs fixed-database integration tests serially and includes the new offline suites in its actual Python 3.6.8 job.

Offline fixtures do not establish acceptance on the target kernel, systemd or NSS mount namespace. The real target probe/check and subsequent first-batch/admin acceptance remain required.

## Continuing the reviewed v2 pre-seed failure

`continue-collector-after-boot.py` is a separate root-terminal entry for the one reviewed failed-v2 state. The original controller, updater, NSS runner and v2 broker remain unchanged. The new runner, broker and updater are versioned under `deploy/native/updates/collector-boot-v3/`.

The continuation requires the old installed helper/policy set, a genuinely absent live completion gate, the original withheld completion inode and transaction plan, and the original unconsumed v2 completion stage. It rejects a v3 directory or stage from any earlier attempt. It does not recreate an old completion gate, modify v2 evidence, run a seed or collection batch, or enable the hourly timer.

The private source manifest has schema 3, the reviewed boot ID and release, hashes for exactly six Python payloads, and a `predecessor` object with `manifest_sha256`, `failure_sha256` and `website_sha256`. The payload names are `continue-collector-after-boot.py`, `recover-collector-after-boot.py`, `recover-preview-after-boot.py`, `update-ops-nss-proof.py`, `collect-only-runner.py` and `ops-broker.py`. The original controller and website helper are included unchanged; the updater, runner and broker come from the v3 directory. The manifest is canonical sorted JSON with a final newline. Runtime identifiers and private evidence hashes belong only in that private manifest.

Both actions require the exact `/root/aifinance-collector-boot-v3-<12 alphanumeric characters>` source directory, its manifest digest, the reviewed boot ID, root ownership and protected modes, isolated Python with bytecode disabled, and a real root terminal. `check` reads and validates the full previous evidence chain and current failed state, then returns `snapshot_sha256` without writing files. `apply` additionally requires that digest through `--snapshot-sha256`, recomputes the snapshot under the canonical release lock, and refuses any difference. The checked `run(argv)` entry supports a pinned in-process bootstrap while keeping the real terminal; it returns a sanitized result and installs/restores interruption handlers.

The exact current unit state includes an idle successful probe with no retained execution metadata (code/status/start/exit all zero), the failed SIGTERM check (code 2/status 15), and unstarted seed/run units. Durable v2 probe evidence independently proves the earlier probe. The original seed attempt, absence of seed/run receipts and journals, current refreshed probe alias, empty failed-check output, DB-only network, disabled database-file access and healthy website must all match their provenance. A metadata mismatch returns a fixed phase and safe reason rather than arbitrary command output.

The new attempt uses `collector-boot-v3` and `.collector-v3.*` helper stages. Its `archive` retains the original v2 archive, whose hashes still match the website recovery history. Its separate `attempt-before` archive preserves the current failed-v2 receipts before replacing the probe alias. A fresh real read-only SQL proof and counts equal to the prior proof precede restoring read permission. A new no-network probe, read-only NSS check, unchanged downstream counts, DB-only egress and a healthy website are required before the original attempt can be removed. Website restoration waits for bounded HTTP health before the final strict listener check.

The v3 ready receipt binds the private manifest, validated snapshot, both receipt generations, retained v2 failure/plan/withheld evidence, current boot and fresh checks. Any partial or failed v3 attempt blocks legacy fallback. Receipt provenance remains verifiable after database access is revoked, allowing guarded website restoration. Only a fully validated new receipt allows the updater to publish the new completion gate. On failure the updater restores only known runner/broker/policy files, keeps completion withheld and refuses to overwrite unknown changes. The controller retains the database descriptor through the entire transaction so a late publication failure can still revoke access.

The v3 runner reads bounded procfs files through EOF, including short reads. Resolver failures retain the existing refusal string and attach only an allowlisted reason: missing mount ID, wrong mount path, writable mount, inode mismatch, content mismatch or untrusted path. Failure evidence contains this safe reason and independent cleanup results without credential contents or arbitrary exception text.
