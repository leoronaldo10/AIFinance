# Restore the stopped native preview after a reboot

This is a one-time, administrator-reviewed recovery of the existing fixed collect-only application release. It re-establishes the application's UID network guard, tests that guard, and starts the existing PostgreSQL data directory followed by API and web. It does not establish that the underlying host is trustworthy.

The two inputs are `deploy/native/recover-preview-after-boot.py` and `deploy/native/accept-egress-after-boot.sh`. An administrator must verify their fixed hashes and place them in a private root-owned input directory. No existing installed helper is replaced and no remote action, SSH policy, sudo rule, or login credential is added. `check` is read-only; `apply` needs explicit approval for the concrete recovery and uses the same existing release lock.

## Required starting state

- The expected current boot and application release match the reviewed operation
- The existing four preview unit files, installed helpers and effective start commands match their pins; no unreviewed drop-ins or pending unit reload exists
- API, web, PostgreSQL and the application guard are stopped, and the application's and collector's UIDs have no processes
- The application guard's runtime receipt and both AIFinance nft tables are absent; existing unknown rules or receipts are never deleted or adopted
- The original port 8000 is currently absent and must remain absent; recovery does not start another application
- The existing PostgreSQL 17 data directory and fixed configuration are present, with no unreviewed startup configuration or recovery hooks
- Collector database access remains revoked, its timer remains absent, and its persistent installation, probe and failed-attempt evidence is preserved

Any mismatch stops before service or network changes. A failed or partial apply leaves its evidence for review; it must not be blindly repeated.

## Operation and side effects

The new acceptance shell preserves the original baseline, guarded and root-control probes, per-family reject-counter increases, loopback success and actual cgroup v1 memory-limit checks. Its intentional acceptance change is the port 8000 invariant: absent before and absent afterward. It uses its own evidence namespace, never deleting the original acceptance evidence.

The acceptance shell itself starts the normal guard unit after its baseline probes. Do not start the guard independently and then invoke this shell. Bounded tests temporarily add the two fixed documentation addresses to `lo` and use a fixed local test port; their ownership and absence checks, cleanup and guard-retention behavior remain in force. They do not reload firewalld or change the security group.

Only after guard acceptance succeeds does the controller start the existing database and then API/web. No `initdb`, database provisioning, migration, restore or collector operation runs. Database startup can write PostgreSQL's normal recovery/internal state. The unchanged API also writes its existing `settings` heartbeat at startup and periodically. This is therefore not a zero-write database operation; it does not collect articles or intentionally edit source/article records.

Final checks cover the fixed release, private health endpoints, loopback listeners, process identity and actual resource limits. Collector evidence and revoked access remain unchanged. Failure stops this invocation's API/web starts when necessary and preserves the guard, database data and evidence. It does not enable boot startup, hourly collection or `native-ready`, and does not claim pressure/OOM acceptance.

The historical collector recovery and NSS update paths depend on pre-reboot failed-unit metadata and are not part of this procedure. Successful website recovery does not make collection ready.

## Validation

The new tests use isolated simulated service/kernel fixtures and reject wrong inputs before mutation. They check ordered success, failed acceptance, failed service startup, evidence preservation and the unchanged collector boundary. They do not replace real acceptance on the target.

Run the dedicated Python tests and shell syntax check through `npm run test:deploy`. The existing CI job also runs them under actual Python 3.6.8 with networking disabled. Code review, those CI results, fixed artifact hashes and the exact expected boot identifier must be established before providing an administrator with the final command.
