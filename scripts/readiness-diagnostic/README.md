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
`/root/aifinance-readiness-diagnostic-v3`. Existing matching installations are
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

## Property-reader repair and independent v3 session

A real systemctl 257 client against a synthetic local D-Bus service reproduces
empty ExecStartPre and EnvironmentFiles arrays disappearing from show output,
even with --all. The original profile parser consequently rejected a valid
empty-array profile before either child was started. Upstream v239 and v257
source both have element-only printers for these structured arrays. The ECS
report did not retain missing names, so its exact missing set cannot be recovered.

The repair reads the other 14 profile properties with explicit --all, and
reads these two arrays with existing /usr/bin/busctl get-property on the system
bus. It requires the exact D-Bus signatures a(sasbttttuii) / a(sb) and an explicit
zero count. Missing properties, unknown types, nonempty arrays and bus failures
are never interpreted as empty. No software is installed. The existing busctl
executable and working system D-Bus are additional prerequisites, not assumed
to have been validated on ECS. Only names, type, empty/nonempty result and return
codes are retained; command contents, environment-file paths and raw stderr are
not reported. Scalar property errors now retain the exact missing-name list.

All property callers share this reader: controller identity, profile, process
readiness/exit, cleanup and reconnect. Empty InvocationID and ControlGroup remain
valid serialized strings only where the lifecycle checks already allow them;
unknown or absent scalar fields still fail. Existing PID/invocation/exit checks
are unchanged. A unit that gets unloaded before exit evidence is observed still
fails closed rather than fabricating successful completion.

The v3 installer and diagnostic use only `/root/aifinance-readiness-diagnostic-v3`,
`/run/aifinance-readiness-v3`, and `aifinance-readiness-v3*.service` resources.
The old v1 and v2 directories, reports, events and session marker are never overwritten,
renamed or removed. The v3 marker permits one new session only; reconnecting or
repeating the same command retrieves v3 results rather than repeating its tests.
The isolation policy, two inert commands, collector tools and retry records are
unchanged. There is no reset command or collection/recovery entry point.

Before any child setup, busctl is checked for existence, trusted ownership/path
and executable regular-file status. Missing, untrusted, nonexecutable, execution
denied, timeout and D-Bus query failures have distinct sanitized reason codes.
The fixed v3 installer verifies its own v3 manifest and uses a separate root-owned
staging directory before atomic installation. A matching existing v3 installation
is reused; changed bytes fail before launch. The old v1/v2 result is never used to
satisfy v3 status. Download/install failures do not launch diagnostic processes.

## Lifecycle evidence retained through verification

The original v2 report proves readiness but not the cause of the final identity
mismatch: it omitted before/after ExecMainPID and start-timestamp values. Local
fixtures reproduce the error when either field is cleared. Inactive-unit garbage
collection is a documented possible cause, not a confirmed ECS diagnosis.

The local repair sets RemainAfterExit=yes only on the two inert child units.
After natural process exit, the active/exited unit retains execution state until
the observer verifies it and stops the owned unit in its existing finally path.
No child process is kept alive to hold the state. The controller is unchanged.

The observer retains the original pidfd, PID, proc start ticks, executable and
invocation checks. Zeroed execution fields still fail. Success requires a dead
original pidfd, MainPID=0, the original ExecMainPID/start timestamp and nonempty
InvocationID, active/exited state, Result=success, ExecMainCode=1 and status=0.
Identity and exit results are read together and confirmed in a second bounded
query before cleanup. Replacement, restart, PID reuse, signal/timeout/nonzero
exit, missing metadata and an unexpectedly live pidfd cannot become success.
Even while waiting for systemd to reap an exited pidfd, execution identity must
remain stable. A rejected cleanup does not turn into a passed test.

Sanitized transition records retain initial/previous/current numeric identity
fields, invocation IDs, fixed-list state/result names, changed field names, pidfd
liveness, elapsed time and observation interval; cgroup paths and arbitrary
values are not logged. Readiness and exit_verified/natural_exit are separate
results, so later failure no longer erases readiness success.

The installer/session names are v3. Neither v1 nor v2 bundles, reports or session
markers are modified or used as the v3 result. Repeat invocation retrieves the
same v3 session without launching another pair of tests. After verification,
finally/ExecStopPost cleanup stops and removes only the exact v3 owned units and
inputs, while keeping the v3 report and evidence. Real root/systemd integration
must still be verified by running this fixed diagnostic on the approved host.
