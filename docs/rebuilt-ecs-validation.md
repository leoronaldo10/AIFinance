# Rebuilt ECS deployment review

Base: `14f53d08f35b37f4716009ed1b35f1c2318d5eaf` on
`release/aifinance-preview`. This change adds a separate, disabled-by-default
deployment protocol; it does not install anything on the server or migrate its layout.

## Local validation

- Rebuilt gateway: 31 tests passed using temporary releases, real restricted
  extraction, and mocked systemd/HTTP. These are not real ECS acceptance tests.
- Typecheck, web build, 19 web tests and preview regression passed.
- Legacy deployment regression passed with the normal CI umask 022; the inherited
  restrictive-umask fixture failure is separate from this implementation.
- Fresh local PostgreSQL 17 migration, topics seed and site smoke passed.
- Under disabled collection/model/integration valves, the clean base and adapted
  code each ran 167 backend tests: 140 passed and the same 27 failed. These are
  pre-existing failures under that configuration, not a green backend suite.
- Repeated after the Check defaults change: rebuilt 31/31, preview 5/5 and legacy
  deployment regressions passed; PostgreSQL migration/seed/smoke passed; backend
  remained 140/167 with exactly the same 27 failure names. YAML, embedded shell
  syntax, safety defaults and diff whitespace checks passed locally. GitHub CI
  itself has not run for this branch.

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
their local stubs. The Docker smoke already uses preview mode, dummy credentials
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
was attempted. Remote push and draft PR creation remain pending administrator
confirmation of external automation. No merge, deployment or real service access
is authorized by this report.
