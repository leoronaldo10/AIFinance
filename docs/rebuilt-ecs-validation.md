# Rebuilt ECS deployment review

> 2026-10-13 更新：现场报告同版本 bootstrap 已验收，随后增加 root 管理的
> 90-home-compat.conf，固定只读代理连接也已验收；本轮未连接 ECS。备案仍 pending，
> 网站保持 localhost。下文原安装/接入状态是历史记录，当前本地发布准备、兼容性和
> 待批准步骤以 [受限发布准备](rebuilt-ecs-deploy.md) 为准；新代码尚未安装或推送。


Base: `14f53d08f35b37f4716009ed1b35f1c2318d5eaf` on
`release/aifinance-preview`. This change adds a separate, disabled-by-default
deployment protocol; it does not install anything on the server or migrate its layout.

## 2026-10-13 本地准备验证（未提交、未部署）

独立reviewer复查后修复两项恢复风险：非UTF8 RELEASE_SHA解码错误统一为Refused；
policy固定switch/current和releases路径以匹配launcher。当前网关43项、bootstrap/launcher
24项通过。下列41项及完整应用检查为修复前准备阶段记录，不冒充本轮重跑。

- 网关 41 项、bootstrap/启动入口 24 项通过；覆盖失效回退点、断线续作、批准撤销、
  SHA/摘要准入、旧回执拒绝、unit时间/PID归一化、配置摘要/HOME变化和真实SHA启动。
- 隔离root CLI通过：正确HOME drop-in保留，非root属主/错误内容在变更前拒绝。
  systemd/HTTP仍为替身，不是实际ECS回退验收。
- typecheck、preview 5项、旧deploy回归通过（历史跨UID解包项非root跳过1项）；
  Web构建和前端19项通过。
- 临时本地PostgreSQL 17迁移/seed、后端171/171、页面及机器出口smoke通过；
  临时应用进程已终止，数据库容器已停止并自动删除，不涉及生产数据。
- 本次不访问ECS、不读取生产秘密、不修改RAM/sudo/服务配置、不触发远端工作流。


## Local validation

- Rebuilt gateway: 31 tests passed using temporary releases, real restricted
  extraction, and mocked systemd/HTTP. These are not real ECS acceptance tests.
- Same-version bootstrap: 19 additional tests pass with temporary files and mocked
  systemd/HTTP. They cover unchanged env loading, source/SQL identity, minimal
  drop-ins, health failure rollback, interrupted installation, conflicts and locks.
  No bootstrap operation was run on ECS. See `rebuilt-bootstrap-runbook.md` for the
  exact separately approvable installation/restart/rollback scope.
- Full bootstrap CLI passes in an ephemeral network-disabled root container, using
  actual ownership/parent checks and load/save/main: absent initial state, first
  check/apply/status/rollback, missing/corrupt receipts and trust diagnostics.
  Only host commands are fixtures. The original c80f386 CLI also completed first
  apply, ruling out a load/save initialization deadlock. The server's precise
  check/apply failure still requires the new non-sensitive diagnostics.
- Typecheck, web build, 19 web tests and preview regression passed.
- Legacy deployment regression passed with the normal CI umask 022; the inherited
  restrictive-umask fixture failure is separate from this implementation.
- Fresh local PostgreSQL 17 migration, topics seed and site smoke passed.
- The initial disabled-model configuration produced the same 27 failures on the
  clean base and adapted code. Supplied CI failure text confirmed that local-model
  fixture tests were stopped by `MODEL_CALLS_ENABLED=false` before reaching stubs.
  The test fixture setup now enables models only behind the test TCP guard, clears
  inherited provider credentials and supplies local endpoint defaults. Service
  and workflow defaults remain disabled; negative valve tests remain intact.
- The complete backend suite passes 171/171, including four isolation regressions,
  with fresh PostgreSQL for this fix. Typecheck and rebuilt 31/31 pass again.
  No failure is skipped or converted into success. YAML, shell syntax and
  whitespace checks pass.

## Check workflow side effects

`Check` runs on pull requests (including drafts), main pushes and manual dispatch.
It has read-only repository permissions, no production secrets references, fresh
GitHub-hosted runners and a disposable local database. No deployment or worker is
started. Migrations and seeds operate on that disposable database only.

Provider fixtures bind to loopback and use dummy credentials. Feishu feedback tests
mock Feishu responses in-process. Some fixtures explicitly re-enable valves; for
example receipt tests restore the mutable model flag to true. A disabled default
alone is therefore not a universal network boundary.

The workflow now defaults all collection/model/notification valves to false,
uses a nonexistent credentials directory, and points every configured model and
collector base URL to loopback port 1. Tests needing providers override these with
their local stubs. `npm test` preloads a test-only TCP guard that rejects nonnumeric
hosts, nonloopback IPs and Unix socket paths before connecting. It covers Node TCP
requests from fetch/undici, redirects, and child Node processes inheriting
`NODE_OPTIONS`. Fixtures can enable model calls only in these guarded test
processes. Regression tests verify local HTTP, blocked public/private/name-based
connections, blocked redirects, child inheritance and credential cleanup.
The Docker smoke already uses preview mode, dummy credentials
and disabled valves; the Python 3.6 container uses `--network none`.
The Check regression step now includes `test:rebuilt`.

This is application-level isolation, not an OS egress sandbox. Package installation,
image pulls and GitHub actions still require network access. No claim is made that
the whole CI runner is offline or that arbitrary future test code cannot bypass
these defaults.

## Outstanding acceptance and publication gates

The actual ECS service definitions, paths, permissions, release SHA health response,
network channel and rollback have not been accepted. Shared application/deployment
UID means receipts are not a tamper-proof audit boundary. Uncertain interrupted
states fail closed and may need operator review.

A fix-branch push does not match the deployment or diagnostic push triggers.
The rebuilt workflow is manual-only. No workflow has been dispatched here.
External webhook inspection returned GitHub HTTP 403; no bypass or permission change
was attempted. The owner confirmed no external push-triggered deployment was
configured, and authorized the independent fix branch and draft PR #4. The first
Check run passed Docker/Python 3.6 and failed at backend fixtures; its log download
was denied and was not retried. The owner supplied failure text for diagnosis.
No merge, deployment or real service access is authorized by this report.
