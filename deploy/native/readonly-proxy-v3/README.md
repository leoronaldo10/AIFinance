# Reviewed readonly proxy v3 — adaptation source

This directory vendors the reviewed client and offline fixtures for subsequent
connection adaptation. It is not connected to a workflow or installed on a server.
Do not run its live or probe modes as part of adaptation or tests.
`LIVE_EXECUTION_ENABLED = False` remains unchanged. The historical, non-secret
Expiration `2026-10-13T12:44:25Z` remains protected by the expiration guard; it is
not a valid future credential grant. No credential values are included. Any future
live attempt requires separate authorization and the exact expiration of its
then-current credential batch, in a separate execution copy.

## Provenance and preserved behavior

- Library handoff v3: `aifinance-readonly-proxy-client-20261013-reviewed.zip`.
- Source ZIP SHA256: `236926188a6a5a84605a49519116147e39d3473e9f3aa4091f25edafa121dfa6`.
- Unmodified client SHA256: `e7ea1ac11e253c3e79d0166c1e9de9e1086b0ec1ca815bfdefb8ec924f2d077a`.
- `baseline/client.py` is the pre-diagnostic review baseline needed by the
  independent source-comparison test, also locked; it is not an alternate runner.

The fixed command is 454 ASCII characters; its explicit `/bin/sh -c` wrapper is
499 characters and three arguments. The target, session user, read-only checks,
proxy/TLS validation, bounded output, protocol checks, 40/35/30-second limits and
no-retry/no-reconnect behavior are unchanged. Only fixed diagnostic categories
are emitted for Agent errors; arbitrary payloads and dynamic error text are not.

## Offline tests

Use an existing Python 3.11+ environment with websockets 16.0. From this directory:

```sh
env -u ALIBABA_CLOUD_ACCESS_KEY_ID \
    -u ALIBABA_CLOUD_ACCESS_KEY_SECRET \
    -u ALIBABA_CLOUD_SECURITY_TOKEN \
    python3 -B -m unittest test_client test_diagnostics review_tests
sha256sum -c SHA256SUMS
```

The reviewed suite contains 70 tests: 52 original, 12 diagnostic regressions and
6 independent review tests. The suites block connection creation and DNS, mock
authentication/network entry points, and use synthetic fixtures. Local shell
checks parse syntax only. `verification/` additionally retains the original Go
shlex fixture/harness; it is not required by the 70 Python tests.

## Third-party references

Original reference files and license notices are retained byte-for-byte:

- `official/AxtMessage.ts`, `official/AxtSession.tsx`:
  [aliyun/cloud-assistant-starter](https://github.com/aliyun/cloud-assistant-starter/tree/0f100b8c84601e6a119d42bed0630aa8d64459f5),
  commit `0f100b8c84601e6a119d42bed0630aa8d64459f5`.
- `official/shell_unix.go`, `official/sessionresult.go`,
  `official/taskengine_session.go`:
  [aliyun/aliyun_assist_client](https://github.com/aliyun/aliyun_assist_client/tree/7f398b692b248dd91a64c8c2a98f476451ecb8e5),
  commit `7f398b692b248dd91a64c8c2a98f476451ecb8e5`.
- `verification/shlex/`: google/shlex commit
  `e7afc7fbc510` (`v0.0.0-20191202100458-e7afc7fbc510`),
  with its Apache-2.0 COPYING file.

This source-only import excludes archives, runtime output, session responses,
signed download URLs, environment files and credentials. It neither authorizes
nor implements deployment, merging, server installation or permission changes.
