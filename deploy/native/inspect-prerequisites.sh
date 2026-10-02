#!/usr/bin/env bash
# Fixed read-only report for the existing administrator terminal; no gateway changes.
# No software installation, repo refresh, credentials, firewall writes or service changes.
set -uo pipefail

run() {
  local name=$1; shift
  printf '\n=== %s ===\n' "$name"
  env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LANG=C LC_ALL=C PYTHONDONTWRITEBYTECODE=1 timeout --kill-after=2s 12s "$@" 2>/dev/null | head -c 8193 > "$scratch/query.out"
  local result=${PIPESTATUS[0]}
  local bytes
  bytes=$(wc -c < "$scratch/query.out")
  head -c 8192 "$scratch/query.out"
  printf '\n[exit=%s; truncated=%s; errors withheld]\n' "$result" "$([[ $bytes -gt 8192 ]] && echo yes || echo no)"
}

# Report only structured package/module/repository fields and fixed error categories.
# Never return arbitrary DNF stderr, config values, repository names or URLs.
run_dnf() {
  local name=$1 kind=$2; shift 2
  printf '\n=== %s ===\n' "$name"
  local error_fd error_pid result
  exec {error_fd}> >(head -c 8193 > "$scratch/query.err")
  error_pid=$!
  env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LANG=C LC_ALL=C PYTHONDONTWRITEBYTECODE=1 timeout --kill-after=2s 12s "$@" 2>&$error_fd | head -c 8193 > "$scratch/query.out"
  result=${PIPESTATUS[0]}
  exec {error_fd}>&-
  wait "$error_pid" || true
  /usr/bin/python3 -I -B - "$kind" "$result" "$scratch/query.out" "$scratch/query.err" <<'DNF_REPORT'
import re
import sys

kind, result, out_path, err_path = sys.argv[1:]
with open(out_path, 'rb') as source:
    raw_out = source.read(8193)
with open(err_path, 'rb') as source:
    raw_err = source.read(8193)
# Match whole records; arbitrary text (including traceback/config contents) stays private.
package = r'postgresql(?:16|17)?(?:-(?:server|contrib|libs))?'
version = r'[0-9][A-Za-z0-9_.+~:^%-]{0,127}'
repo = r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}'
arch = r'(?:x86_64|noarch|i686|aarch64)'
kept, withheld, repository_header = [], False, False
lines = raw_out[:8192].decode('utf-8', 'replace').splitlines()
if len(raw_out) > 8192 and raw_out[8191:8192] != b'\n':
    lines = lines[:-1]  # Never turn a partial record into apparently complete evidence.
    withheld = True
for line in lines:
    line = line.strip()
    if not line:
        continue
    record = None
    if kind == 'repositories':
        if re.fullmatch(r'repo id\s+repo name', line):
            repository_header = True
            continue
        match = re.fullmatch('(' + repo + r')\s+.+', line) if repository_header else None
        if match and match.group(1).rstrip(':').lower() not in ('repo', 'last', 'no', 'error', 'warning'):
            record = 'repository_id=' + match.group(1)
    elif kind == 'packages':
        if re.fullmatch(package + r'\|' + version + r'\|' + arch + r'\|' + repo, line):
            record = line
    elif kind == 'list':
        match = re.fullmatch('(' + package + r')\.(' + arch + r')\s+(' + version + r')\s+(' + repo + ')', line)
        if match:
            record = '|'.join((match.group(1), match.group(3), match.group(2), match.group(4)))
    elif kind == 'modules':
        match = re.match(r'^postgresql\s+([0-9][A-Za-z0-9_.-]{0,31})((?:\s*\[[dei]\])*)\s+', line)
        if match:
            flags = ','.join(re.findall(r'\[([dei])\]', match.group(0))) or 'none'
            record = 'postgresql|stream=' + match.group(1) + '|flags=' + flags
    if record is not None:
        kept.append(record)
    else:
        withheld = True
for record in kept:
    print(record)
# Categorize the bounded stderr plus stdout: some DNF builds log errors on stdout.
text = (raw_err[:8192] + b'\n' + raw_out[:8192]).decode('utf-8', 'replace').lower()
patterns = (
    ('config_path_not_regular', r'config file [\'\"]?/dev/null[\'\"]? does not exist'),
    ('config_error', r'config error|parsing file .* failed|invalid configuration value|error parsing --setopt'),
    ('cache_unavailable', r'cache-only enabled but no cache|no cache for|cache.*(?:unavailable|not found)|failed to download metadata|no available modular metadata'),
    ('releasever_unknown', r'unable to detect release version'),
    ('module_platform_unknown', r'no valid platform|failed to detect.*platform|nothing provides module\(platform|module_platform_id'),
    ('unsupported_command_or_option', r'no such command|unrecognized arguments|unknown argument|unknown option|invalid choice|unknown repoquery tag'),
    ('permission_denied', r'permission denied|operation not permitted'),
    ('no_matching_packages_or_modules', r'no matching packages|no matching modules|unable to resolve argument|no match for argument'),
    ('repository_unavailable', r'unknown repo|no enabled repositories|there are no enabled repositories|failed loading repository'),
)
categories = [name for name, pattern in patterns if re.search(pattern, text)]
if result in ('124', '137'):
    categories.append('timeout_or_killed')
if raw_err and not categories:
    categories.append('unclassified_error_withheld')
print('[exit={}; stdout_truncated={}; stderr_truncated={}; stdout_other_withheld={}; stderr_categories={}; raw_stderr=withheld]'.format(
    result, 'yes' if len(raw_out) > 8192 else 'no', 'yes' if len(raw_err) > 8192 else 'no',
    'yes' if withheld else 'no', ','.join(categories) or 'none'))
DNF_REPORT
}

cached_dnf() {
  run cached-package-manager rpm -q dnf python3-dnf libdnf
  # DNF4 rejects --config=/dev/null because the explicit config must be a regular file.
  # Preserve the distro's configuration, vars, releasever, module platform and cache paths.
  # -C forbids cache refresh; disable plugins and optional DNS key checks to avoid network hooks.
  # Temporary persistdir omits module-failsafe state: these queries do NOT prove installability.
  local dnf=(dnf -C --noplugins --setopt=gpgkey_dns_verification=False "--setopt=persistdir=$scratch" "--setopt=logdir=$scratch")
  local packages=(postgresql postgresql-server postgresql-contrib postgresql-libs postgresql16 postgresql16-server postgresql16-contrib postgresql16-libs postgresql17 postgresql17-server postgresql17-contrib postgresql17-libs)
  run_dnf cached-repositories repositories "${dnf[@]}" repolist --enabled
  run_dnf cached-postgresql-list list "${dnf[@]}" list --available "${packages[@]}"
  run_dnf cached-postgresql-modules modules "${dnf[@]}" module list --all postgresql
  run_dnf cached-postgresql-packages packages "${dnf[@]}" repoquery --available --latest-limit=1 --disable-modular-filtering --qf '%{name}|%{version}-%{release}|%{arch}|%{repoid}' "${packages[@]}"
}

main() {
  export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C PYTHONDONTWRITEBYTECODE=1
  [[ $EUID = 0 && ( $# = 0 || ( $# = 1 && $1 = --dnf-only ) ) ]] || {
    echo 'Run this reviewed file in the existing root administrator terminal, optionally with --dnf-only'; return 2;
  }
  command -v timeout >/dev/null && [[ -x /usr/bin/python3 ]] || {
    echo 'Required timeout or /usr/bin/python3 is missing'; return 2;
  }
  umask 077
  scratch=$(mktemp -d /tmp/aifinance-prerequisites.XXXXXXXX) || return 2
  trap 'rm -rf -- "$scratch"' EXIT
  if [[ $# = 0 ]]; then
    run os cat /etc/os-release
    run kernel uname -r
    run architecture uname -m
    run glibc getconf GNU_LIBC_VERSION
    run systemd systemctl --version
    run installed-packages rpm -q glibc libstdc++ openssl-libs gnupg2 nodejs postgresql postgresql-libs postgresql-server postgresql-contrib postgresql16 postgresql16-libs postgresql16-server postgresql16-contrib postgresql17 postgresql17-libs postgresql17-server postgresql17-contrib
    run python-capabilities /usr/bin/python3 -I -B -c 'import sys, lzma, resource; print(sys.version.split()[0]); print("lzma/resource available")'
    run verifier-path bash -c 'command -v gpgv'
    run libstdcxx-symbols bash -c 'grep -aoE "GLIBCXX_[0-9]+\.[0-9]+\.[0-9]+" /usr/lib64/libstdc++.so.6 | sort -Vu | tail -5'
    run kernel-features grep -E '^(CONFIG_MEMCG|CONFIG_BPF|CONFIG_BPF_SYSCALL|CONFIG_CGROUP_BPF|CONFIG_CGROUPS)=' "/boot/config-$(uname -r)"
    if [[ -r /proc/config.gz ]]; then
      run proc-kernel-features bash -c 'gzip -dc /proc/config.gz | grep -E "^(CONFIG_MEMCG|CONFIG_BPF|CONFIG_BPF_SYSCALL|CONFIG_CGROUP_BPF|CONFIG_CGROUPS)="'
    fi
    run cgroup-mounts findmnt -n -t cgroup,cgroup2 -o TARGET,FSTYPE,OPTIONS
    run memory-controller cat /proc/cgroups
    run memory grep -E '^(MemTotal|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo
    run disk df -Pk /opt
    run selected-listeners bash -c 'ss -lnt | awk "NR==1 || /:(8000|3100|3101|55432)[[:space:]]/"'
    run preview-units systemctl show aifinance-preview-api.service aifinance-preview-web.service aifinance-preview-db.service -p Id -p LoadState -p ActiveState -p MemoryLimit -p MemoryCurrent
  fi
  cached_dnf
  if [[ $# = 0 ]]; then
    run iptables-version iptables --version
    run ip6tables-version ip6tables --version
    run nft-version nft --version
    run firewall-service systemctl show firewalld.service -p LoadState -p ActiveState
  fi
  printf '\nDONE: no installation, cache refresh, server configuration, service, firewall or SSH changes. Nonzero query exits, truncation or missing records mean UNKNOWN, not proven absence. Temporary DNF state and disabled plugins limit these cache-only observations; no installability claim. BPF flags do not prove actual unit egress denial.\n'
}

if [[ ${BASH_SOURCE[0]} = "$0" ]]; then
  main "$@"
fi
