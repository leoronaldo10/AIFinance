#!/usr/bin/env bash
# Read-only snapshot. Does not read .env, private keys, service Environment or process arguments.
set -u
printf 'Timestamp: '; date -u +%FT%TZ
id
uname -sm
cat /etc/os-release
printf '\nResources\n'
free -m
df -h / /opt 2>/dev/null
printf '\nRuntime and system libraries\n'
for cmd in node npm git systemctl psql docker podman nginx ssh; do command -v "$cmd" || true; done
node --version 2>/dev/null || true
getconf GNU_LIBC_VERSION 2>/dev/null || true
systemctl --version | head -1
printf '\nListening TCP sockets (no process command lines)\n'
ss -lnt
printf '\nAIFinance service state\n'
systemctl show aifinance-preview-api.service aifinance-preview-web.service -p Id -p LoadState -p ActiveState -p User -p MainPID
# Optional caller-supplied PID; do not infer ownership from a previous snapshot.
if [[ ${1:-} =~ ^[0-9]+$ ]]; then
  printf '\nRequested PID identity only\n'
  ps -p "$1" -o pid=,user=,comm= 2>/dev/null || true
fi
# Do not kill/restart any process discovered above.
