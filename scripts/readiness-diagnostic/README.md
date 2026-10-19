# Independent readiness diagnosis

This package performs one diagnosis-only session on the approved host
`iZ2zedybs3fftu1d9vnx39Z`. It never starts the collector and never connects to a
database. It contains only standalone process/cgroup validators extracted from
the reviewed readiness repair, not the bootstrap, database or retry operators.
Existing collector tools, HBA, firewall, credentials and retry/consumed records
are not modified. No recovery entry is added to the old collector.

The fixed installer takes a 40-character commit and the SHA256 of
`DIAGNOSTIC.SHA256`. Use the separately pinned installer hash before execution.
It downloads only four scripts and their manifest from that exact commit,
rechecks the staged root-owned bytes and installs atomically under
`/root/aifinance-readiness-diagnostic-v1`. Existing matching installations are
reused; changed files or path collisions fail closed. No runtime is repacked,
no dependency is installed, and no existing download folder is reused.

A root-owned, detached systemd controller starts two sequential inert oneshot
units as the existing `aifinance-collect-once` account: `/usr/bin/sleep 12` and
`/usr/bin/python3 -I -B -c "import time; time.sleep(12)"`. Both have private
network namespaces, no inherited credentials, blocked site/collector/database
paths, zero capability sets, NoNewPrivileges, 256 MiB memory, 32 tasks and 50% CPU
limits. Copies of the existing hosts and files-only nsswitch configuration are
mounted read-only. There are no network or database operations in either child.

The root observer holds a pidfd and checks executable inode, all four UID/GID
fields, all five capability sets, NNP, process start ticks, systemd invocation,
actual cgroup membership/limits, and opened resolver-file mount IDs. A positive
MainPID alone is not readiness. Pre-exec identity is allowed to transition; the
expected final identity must be verified after exec. Capturing an intermediate
root state is timing-dependent and is not claimed as guaranteed evidence.
Both children must exit naturally with status zero. A readiness failure is
reported separately for each child; a child that cannot be stopped aborts the
session. Failures never trigger collection or automatic policy changes.

`ExecStopPost` cleans only exact owned diagnostic units and inputs after normal
completion or controller failure. Unexpected content is preserved and reported
as incomplete cleanup. Original state/retry/consumed sentinel contents and
metadata are compared before and after. The root-only bundle, session marker,
`report.json`, `events.jsonl`, and audit/input receipts remain for review.
Temporary download/staging directories are removed by installer exit traps.
A hard power loss or SIGKILL of the installer can leave a uniquely named staging
directory; it is never reused or treated as a valid installation.

SSH loss does not kill the controller. Repeating the same installer retrieves
the same session, or cleans its diagnostic resources if the controller has
already stopped. It does not repeat the two tests. Across a reboot, transient
units/inputs disappear and the next invocation reports interruption instead of
starting a new session. There is no supported reset or retry command.

Expected successful output is a JSON report with `stage=diagnostic_finished`,
`final=true`, `passed=true`, two tests with `readiness=true` and
`natural_exit=true`, `cleanup_complete=true`, `cleanup_errors=[]`, followed by
`DIAGNOSTIC_EXIT=0`. On failure, preserve the complete sanitized JSON and exit
code; do not change the old retry record or rerun collection.

Requirements: real systemd, unified cgroup v2, Linux pidfd support, Python 3.9+
at `/usr/bin/python3`, the existing dedicated account and original resolver
configuration. Missing requirements cause failure, not installation or upgrades.

Offline validation:

```sh
python3 -I -B -m unittest discover -s scripts/readiness-diagnostic/tests -p 'test_*.py' -v
bash -n scripts/readiness-diagnostic/diagnose-install.sh
```

Tests include real local Linux pidfd/exec/exit and proc parsing, and mocked
systemd lifecycle/ownership/failure fixtures. The development container has
non-systemd PID 1 and UID 1000; these tests do not establish real root/systemd
sandbox integration. That evidence must come from this diagnostic on ECS.
