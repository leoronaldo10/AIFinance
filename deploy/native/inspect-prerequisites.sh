#!/usr/bin/env bash
# Fixed read-only report for the existing administrator terminal; no gateway changes.
# No software installation, repo refresh, credentials, firewall writes or service changes.
set -uo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
[[ $# = 0 && $EUID = 0 ]] || { echo 'Run this reviewed file in the existing root administrator terminal, without arguments'; exit 2; }
command -v timeout >/dev/null || { echo 'Required timeout command is missing'; exit 2; }
scratch=$(mktemp -d /tmp/aifinance-prerequisites.XXXXXXXX) || exit 2
trap 'rm -rf -- "$scratch"' EXIT
run() {
  local name=$1; shift
  printf '\n=== %s ===\n' "$name"
  timeout --kill-after=2s 12s "$@" 2>/dev/null | head -c 8193 > "$scratch/query.out"
  local result=${PIPESTATUS[0]}
  local bytes
  bytes=$(wc -c < "$scratch/query.out")
  head -c 8192 "$scratch/query.out"
  printf '\n[exit=%s; truncated=%s; errors withheld]\n' "$result" "$([[ $bytes -gt 8192 ]] && echo yes || echo no)"
}
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
# -C forbids metadata download. All dnf scratch/log state is temporary; system cache is not refreshed.
dnf=(dnf -C --noplugins --config=/dev/null --setopt=reposdir=/etc/yum.repos.d --setopt=varsdir=/etc/dnf/vars,/etc/yum/vars --setopt=cachedir=/var/cache/dnf "--setopt=persistdir=$scratch" "--setopt=logdir=$scratch")
run cached-repositories "${dnf[@]}" repolist --enabled
run cached-postgresql-modules "${dnf[@]}" module list --all postgresql
run cached-postgresql-packages "${dnf[@]}" repoquery --available --latest-limit=1 --disable-modular-filtering --qf '%{name}|%{version}-%{release}|%{arch}|%{repoid}' postgresql-server postgresql-contrib postgresql-libs postgresql16-server postgresql16-contrib postgresql16-libs postgresql17-server postgresql17-contrib postgresql17-libs
run iptables-version iptables --version
run ip6tables-version ip6tables --version
run nft-version nft --version
run firewall-service systemctl show firewalld.service -p LoadState -p ActiveState
printf '\nDONE: no installation, cache refresh, server configuration, service, firewall or SSH changes. Nonzero query exits mean unavailable, not proven absence. BPF flags do not prove actual unit egress denial.\n'
