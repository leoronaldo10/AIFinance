# Retry-002 private result channel

Exports only the already completed retry-002 batch's three public RSS items to:

`oss://backupforecs20261009/aifinance-public-results/retry-002/result-v1.json`

This operator-approved snapshot is independent of website publication. It does not enable the sources, publish site content, rerun collection, migrate the database, or create a scheduler. GitHub has no ECS, Cloud Assistant, terminal, database, or backup-reading permission.

## Files and fixed boundaries

- `export_results.py` executes one fixed read-only SQL transaction through the existing local PostgreSQL 17 socket, validates a public-field whitelist and uploads one private object. No runtime path/SQL/source/bucket/key arguments.
- `cloud_io.py` uses Python standard-library HTTPS, bounded responses, no redirects, OSS V4 header signatures and short-lived credentials. No dependency installation or credential files. GET and PUT use one compiled-in bucket/key; no list, delete, presigned URLs or general cloud client.
- `read_results.py` runs only in the approved GitHub context, exchanges GitHub OIDC for STS, reads that object, checks an independently supplied SHA256 and validates the whitelist again before printing public results.
- `install_export.py` installs root-owned fixed files and a non-enabled oneshot unit; it refuses existing target paths and does not start the unit. `install-release.py` in the final release automates verified download/install and the single start.
- `policies/` contains exact-object read/write policies, ECS trust and GitHub subject customization. `release.json` and the final reader trust contain the actual immutable code/workflow commits after publication.

The target host is `iZ2zedybs3fftu1d9vnx39Z`, instance `i-2zedybs3fftu1d9vnx39`, Beijing. The exporter refuses a different hostname, instance or region. Its IMDSv2-only role must be exactly `aifinance-results-writer`. Missing/different roles stop the run; no fallback to ambient AKs, no role replacement. Role policy composition still requires administrator review; a name alone does not prove least privilege.

## Public format and query

The result has schema version, fixed batch id, fixed matched status, export time and three articles. Each article contains only id, title, source id/name, public original URL, publication/collection time and stored RSS summary. No `body_text`, database dump, environment, credential, raw log or session data is selected. Titles/summaries are bounded; whitespace is normalized; credentials, JWTs and credential-bearing URLs are rejected. Pattern detection is an additional guard, not a proof that arbitrary text can never contain secrets. The primary boundary is fixed public source data and an explicit output whitelist. Maximum payload: 64 KiB.

The query uses the root-controlled retry-002 `before.dump` mtime and exact `completed` marker as bounds. It requires one matching three-source transaction, original expected fetch counts (10/10/20), three articles total, each still collect-only/revision1, and disabled/isolated sources. Ambiguity, changed records or an unexpected fourth row refuses upload. It uses `count(1)`, not a terminal-sensitive asterisk. No "latest three" fallback.

Local database access uses existing OS `postgres` peer authentication over `/run/postgresql/.s.PGSQL.55432`, database `aifinance_preview`, with cleared environment, `psql -Xw`, no password file, read-only transaction and query/lock timeouts. This is a privileged DB identity executing a fixed read-only query, not a SELECT-only DB role. The approved root oneshot owns the files, drops to OS postgres for psql, does not change HBA or DB grants, and exits. Failure does not read application secrets or repair authentication.

## Administrator setup (no secrets in chat)

The authenticated cloud GitHub CLI can administer GitHub settings after explicit approval; Alibaba administration remains separately gated. Complete the following once from authorized administrator sessions. Do not paste tokens, keys, headers or signed URLs into chat/logs.

1. In [OSS console](https://oss.console.aliyun.com/), select `backupforecs20261009`. Confirm the region, ownership, bucket policy, versioning, lifecycle and encryption. Keep existing backup rules untouched. The new object must remain private and not be made readable by another bucket policy. Do not grant `AliyunOSSReadOnlyAccess`, list permissions or wildcard backup paths. Standard storage and ordinary request/outbound-transfer charges apply; no acceleration/CDN/KMS service is added. A bucket that mandates KMS or blocks the selected endpoint requires review, not a silent policy change.
2. In [RAM console](https://ram.console.alibabacloud.com/), create the dedicated ECS service-trusted role `aifinance-results-writer` with only `policies/oss-writer-policy.json`. In [ECS console](https://ecs.console.alibabacloud.com/), select Beijing and the exact instance; inspect its attached RAM role first. ECS permits one role: **if any existing different role is attached, stop and report the conflict; do not replace it**. If none exists, attach the dedicated writer. The runtime requires IMDSv2 but does not change instance-wide metadata settings.
3. Create RAM OIDC provider `github-aifinance-readonly`: issuer `https://token.actions.githubusercontent.com`, client ID `sts.aliyuncs.com`; verify the issuer CA fingerprint in the console. Create `aifinance-results-reader` from the final `policies/reader-trust.template.json` after replacing only `<ACCOUNT_ID>`, and attach only `oss-reader-policy.json`. Trust uses exact `oidc:iss`, `oidc:aud`, `oidc:sub`. The subject includes actual repository ID `1396876434`, owner ID `311357003`, exact Environment and full reusable workflow SHA. The action is `sts:AssumeRole` in the trust document; the exchange API is AssumeRoleWithOIDC. Session request is 900 seconds.
4. In [repository Environments](https://github.com/leoronaldo10/AIFinance/settings/environments), create `aifinance-readonly-results` before running anything. Select only branch `main`, no tag rule; require reviewer `leoronaldo10`; disable administrator bypass. For this single-owner, public-result-only workflow, the owner may trigger and approve the job (leave Prevent self-review off); a separate reviewer can instead be selected if available. This is an explicit practical change from the earlier design's assumed second reviewer. No production deployment permission is attached to this Environment.
5. Save the repository's existing OIDC subject settings before changing them. Set the body in `policies/github-sub-template.json` via GitHub's [repository OIDC REST endpoint](https://docs.github.com/en/rest/actions/oidc#set-the-customization-template-for-an-oidc-subject-claim-for-a-repository), `PUT /repos/leoronaldo10/AIFinance/actions/oidc/customization/sub`. This is repository-wide: stop if another OIDC consumer requires the old format and coordinate its migration. Use the already authenticated cloud GitHub CLI after explicit approval; never create or send a token through chat.
6. Add Environment **variables** `AIFINANCE_ALIBABA_ACCOUNT_ID` (numeric account id), `AIFINANCE_OSS_REGION` (confirmed bucket region), and later `AIFINANCE_RESULTS_SHA256` (the export receipt hash). These are not credentials. No GitHub secret is required. Workflows request `id-token: write` only on the read job, pin reusable code/actions by commit, check main/manual event and repository identity, and never run PR code or restore untrusted caches.

## One host operation and first read

After the role and bucket checks, use the final release's verified `install-release.py` in an existing administrator session with the confirmed bucket region. It downloads only the pinned package files, checks every digest, installs without overwriting and starts `aifinance-export-retry002.service` once. No long SQL copy/paste and no package installation. Installation paths:

- `/opt/aifinance-results-retry002/` (four runtime files and their digest manifest)
- `/etc/aifinance-results-retry002.json` (nonsecret config, root0600)
- `/etc/systemd/system/aifinance-export-retry002.service` (no Install section/timer)

The successful receipt contains only `uploaded_private_retry002`, article count3 and SHA256. Save that independent SHA256 in the Environment variable before the read. On upload timeout, success is unknown; do not blindly rerun or widen permissions. `x-oss-forbid-overwrite` is sent, but OSS ignores it when bucket versioning is enabled/suspended; it is not WORM. The administrator should revoke this dedicated writer permission after the one successful export. Other processes that can reach IMDS can obtain the instance role; the role is not bound to the exporter Unix UID.

Then manually run **Read retry-002 public results** on main and approve the Environment job. The default-branch entry calls an immutable reusable workflow which checks out immutable reader code. Missing configuration refuses before requesting OIDC. After separate run approval, use the authenticated cloud GitHub CLI or [Actions](https://github.com/leoronaldo10/AIFinance/actions). Subsequent runs automatically obtain short STS; the operator need not issue recurring tokens.

**This repository is public.** The successfully validated three public items are deliberately printed in the workflow log and summary. OSS remains private; do not use a public repository artifact/log to store nonpublic results. A hash mismatch or schema refusal prints no result body. The returned status is collection/export status, not live ECS/API health.

## Validation and rollback

Offline tests: `python3 -m unittest discover -s scripts/readonly-results/tests -v`. Disposable PostgreSQL integration additionally uses `PG_BIN` and `PG_SHARE`; it starts its own Unix-socket cluster and `_test` database, never DATABASE_URL or ECS. Tests cover original-batch selection, changed/ambiguous rows, no body leakage, read-only writes, size/secret/URL rejection, fork/PR/claim failures, no-redirect behavior, role conflicts and official OSS V4 canonical/signature vectors. Runtime integration on the actual root/systemd host and the real OIDC/OSS exchange remain separate acceptance checks.

To revoke, remove object read/write permissions and disable the read workflow, then remove trust to stop new sessions. Removing trust alone is not instant revocation of previously issued STS. Cancel in-flight runs and review expiry. Delete only the result object if desired using an administrator; neither role receives DeleteObject. Detach only the dedicated newly attached writer after checking dependencies; never detach the old backup role. Remove only these installed exporter paths, daemon-reload, and restore prior GitHub OIDC settings after checking other consumers. No source, service, HBA or DB rollback is needed.

Future collection/update hooks and additional object keys are outside this release. Retry-002 remains its own snapshot.

## Official references

- [OSS exact-object RAM policies](https://www.alibabacloud.com/help/en/oss/user-guide/ram-policy/)
- [OSS V4 signing](https://www.alibabacloud.com/help/en/oss/developer-reference/recommend-to-use-signature-version-4)
- [PutObject ACL, encryption and overwrite behavior](https://www.alibabacloud.com/help/en/oss/developer-reference/putobject)
- [ECS instance roles and single-role limit](https://www.alibabacloud.com/help/en/ecs/user-guide/attach-an-instance-ram-role-to-an-ecs-instance)
- [GitHub OIDC claims](https://docs.github.com/en/actions/reference/security/oidc)
- [GitHub manual workflow registration](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow)

## Immutable-subject identity preflight (2026-10-21)

GitHub reports immutable subject mode for this repository. The template explicitly preserves `use_immutable_subject: true` and orders claims as repo, repository_id, repository_owner_id, context, job_workflow_ref. The reader and exact RAM trust include `repo:leoronaldo10@311357003/AIFinance@1396876434:` before the separately checked IDs, Environment and pinned reusable workflow. No legacy fallback or wildcard is accepted. Offline fixtures are not evidence of actual token issuance.

The manual entry defaults `identity_preflight` to true. Its pinned reusable workflow runs the reader with `--identity-preflight`: one GitHub token request, in-memory exact claim/subject/workflow SHA checks, boolean-only output, no token persistence, no STS exchange, no OSS operation, no ECS operation. This checks the authenticated GitHub token response locally, not Alibaba acceptance or independent JWT signature verification. The normal read step is mutually exclusive and requires an explicit false input plus the three real nonsecret variables. Environment approval is required for either mode and must be given by the human reviewer.

The entry hard-codes the same expected reusable SHA as its uses pin. Both preflight and real read require that exact job_workflow_ref and job_workflow_sha. `release.json` separates `reader_code_commit` from the original exporter `code_commit`; the exporter installer, pinned package, runtime hashes and host behavior remain unchanged.

Setup order: publish the reviewed immutable reader/workflow/caller chain; configure the main-only reviewed Environment and exact custom subject; manually dispatch identity_preflight=true and obtain human Environment approval; inspect boolean results. Only after success and separate approval, configure matching Alibaba trust and exact-object permissions using verified account/bucket/attached-role information, export once, enter the independent receipt digest and other variables, and run the actual reader. No preflight success implies Alibaba or ECS readiness. If any identity check fails, stop rather than widening trust or automatically rerunning.
