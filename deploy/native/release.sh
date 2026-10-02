#!/usr/bin/env bash
# Install a reviewed copy outside releases. Run as a dedicated deploy account, never root.
# That account may restart ONLY the two named services via separately approved sudo rules.
set -euo pipefail
umask 0022
root=${AIFINANCE_ROOT:-/opt/aifinance}
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
action=${1:?deploy or rollback}
sha=${2:?full commit SHA}
[[ $action = deploy || $action = rollback ]] || exit 2
[[ $sha =~ ^[0-9a-f]{40}$ && $root = /* ]] || exit 2
[[ $EUID != 0 ]] || { echo 'Run as dedicated deploy user, not root' >&2; exit 1; }
for cmd in flock curl python3 sudo systemctl; do command -v "$cmd" >/dev/null; done
[[ -d $root/state && -d $root/releases && -d $root/incoming && -f $root/shared/schema.sha256 && -f $root/shared/native-ready ]] || {
  echo 'Provisioning, schema approval and native isolation sign-off required' >&2; exit 1;
}
exec 9>"$root/state/release.lock"
flock -n 9 || { echo 'Another AIFinance deployment is active' >&2; exit 1; }
stage=''
switch_pending=''
cleanup() {
  if [[ -n $stage ]]; then rm -rf -- "$stage"; fi
  # Remove only the temporary symlink created by this invocation, never an
  # unknown pre-existing path or a directory an operator needs to investigate.
  if [[ -n $switch_pending && -L $root/state/.current-next &&
        $(readlink "$root/state/.current-next") = "$switch_pending" ]]; then
    rm -- "$root/state/.current-next"
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if [[ -e $root/state/.current-next || -L $root/state/.current-next ]]; then
  echo 'Pending release switch exists; operator review required before retrying' >&2; exit 1
fi
# Only these services may be touched. No daemon-reload, enable, kill, nginx or database commands.
units=(aifinance-preview-api.service aifinance-preview-web.service)
for unit in "${units[@]}"; do
  [[ $(systemctl show "$unit" -p LoadState --value) = loaded ]] || exit 1
done
if [[ -e $root/state/current && ! -L $root/state/current ]]; then echo 'current must be a release symlink' >&2; exit 1; fi
old=''
if [[ -L $root/state/current ]]; then old=$(readlink -f "$root/state/current"); fi
if [[ -n $old && $old != "$root/releases/"* ]]; then echo 'Unexpected current target' >&2; exit 1; fi
release="$root/releases/$sha"
if [[ $action = deploy ]]; then
  archive="$root/incoming/$sha.tar.gz"
  checksum=${3:?expected archive SHA256 required}
  [[ $checksum =~ ^[0-9a-f]{64}$ ]] || exit 2
  printf '%s  %s\n' "$checksum" "$archive" | sha256sum -c - >/dev/null
  [[ ! -e $release && ! -L $release ]] || { echo 'Release already exists; use rollback for an existing version' >&2; exit 1; }
  stage=$(mktemp -d "$root/releases/.stage-XXXXXXXX")
  # Reviewed, administrator-owned helper; never run extraction code from the upload.
  python3 "$script_dir/extract-release.py" "$archive" "$stage"
  [[ $(cat "$stage/RELEASE_SHA") = "$sha" ]] || exit 1
  [[ -f $stage/apps/web/build/server/index.js && -d $stage/node_modules ]] || exit 1
  mv "$stage" "$release"
  stage=''
fi
[[ -d $release && $(cat "$release/RELEASE_SHA") = "$sha" ]] || exit 1
# No migrations here. A separately approved migration/restore operation maintains this fingerprint.
cmp -s "$root/shared/schema.sha256" "$release/schema.sha256" || {
  echo 'Schema differs: separate migration/backup review required; no restart performed' >&2; exit 1;
}
if [[ -n $old && -d $old ]]; then
  cmp -s "$root/shared/schema.sha256" "$old/schema.sha256" || {
    echo 'Current release schema differs; automatic code rollback would be unsafe' >&2; exit 1;
  }
fi
/opt/aifinance/runtime/node/bin/node -e 'const [major, minor] = process.versions.node.split(".").map(Number); if (major !== 24 || minor < 11) process.exit(1)'
# Never execute uploaded JavaScript as the deploy account. Native dependencies are loaded by
# the confined app service; startup/health failure rolls the code back.
switch_to() {
  ln -sT -- "$1" "$root/state/.current-next" || return 1
  switch_pending=$1
  mv -Tf -- "$root/state/.current-next" "$root/state/current" || return 1
  switch_pending=''
}
restart() { sudo -n /usr/bin/systemctl restart "${units[@]}"; }
healthy() {
  local expected=${1:?expected release SHA required}
  for attempt in {1..20}; do
    if systemctl is-active --quiet "${units[0]}" && systemctl is-active --quiet "${units[1]}" &&
       curl --noproxy '*' --max-time 3 -fsS http://127.0.0.1:3101/api/health | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d.get("ok") is True and d.get("release")==sys.argv[1] else 1)' "$expected" &&
       curl --noproxy '*' --max-time 3 -fsS -o /dev/null http://127.0.0.1:3100/; then return 0; fi
    sleep 2
  done
  return 1
}
switch_to "$release"
if restart && healthy "$sha"; then
  printf 'Active AIFinance release: %s\n' "$sha"
else
  echo 'New release failed health check' >&2
  if [[ -n $old && -d $old && $old != "$release" ]]; then
    switch_to "$old"
    if restart && healthy "$(basename "$old")"; then echo 'Previous code restored; database was not changed' >&2
    else echo 'ROLLBACK HEALTH FAILED: operator intervention required' >&2; fi
  else
    echo 'No previous healthy version available; no rollback performed; failed release remains current' >&2
    echo 'Restart-only sudo cannot stop these services. Operator must stop the two AIFinance preview services; automatic stop requires a separately approved provisioning permission change' >&2
  fi
  exit 1
fi
