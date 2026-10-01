#!/usr/bin/env bash
# Install a reviewed copy outside releases. Run as a dedicated deploy account, never root.
# That account may restart ONLY the two named services via separately approved sudo rules.
set -euo pipefail
root=${AIFINANCE_ROOT:-/opt/aifinance}
action=${1:?deploy or rollback}
sha=${2:?full commit SHA}
[[ $action = deploy || $action = rollback ]] || exit 2
[[ $sha =~ ^[0-9a-f]{40}$ && $root = /* ]] || exit 2
[[ $EUID != 0 ]] || { echo 'Run as dedicated deploy user, not root' >&2; exit 1; }
for cmd in flock curl python3 sudo systemctl; do command -v "$cmd" >/dev/null; done
[[ -d $root/releases && -d $root/incoming && -f $root/shared/schema.sha256 && -f $root/shared/native-ready ]] || {
  echo 'Provisioning, schema approval and native isolation sign-off required' >&2; exit 1;
}
exec 9>"$root/release.lock"
flock -n 9 || { echo 'Another AIFinance deployment is active' >&2; exit 1; }
# Only these services may be touched. No daemon-reload, enable, kill, nginx or database commands.
units=(aifinance-preview-api.service aifinance-preview-web.service)
for unit in "${units[@]}"; do
  [[ $(systemctl show "$unit" -p LoadState --value) = loaded ]] || exit 1
done
if [[ -e $root/current && ! -L $root/current ]]; then echo 'current must be a release symlink' >&2; exit 1; fi
old=''
if [[ -L $root/current ]]; then old=$(readlink -f "$root/current"); fi
if [[ -n $old && $old != "$root/releases/"* ]]; then echo 'Unexpected current target' >&2; exit 1; fi
release="$root/releases/$sha"
if [[ $action = deploy ]]; then
  archive="$root/incoming/$sha.tar.gz"
  checksum=${3:?expected archive SHA256 required}
  [[ $checksum =~ ^[0-9a-f]{64}$ ]] || exit 2
  printf '%s  %s\n' "$checksum" "$archive" | sha256sum -c - >/dev/null
  [[ ! -e $release ]] || { echo 'Release already exists; use rollback for an existing version' >&2; exit 1; }
  stage=$(mktemp -d "$root/releases/.stage-XXXXXXXX")
  trap 'rm -rf "${stage:-}"' EXIT
  # Reject archive traversal and links escaping the release before extraction. No device/hard links.
  python3 - "$archive" "$stage" <<'PY'
import os, sys, tarfile, shutil
archive, dest = sys.argv[1:]
def inside(p): return os.path.commonpath([dest, os.path.realpath(p)]) == dest
with tarfile.open(archive) as tf:
    size = sum(m.size for m in tf.getmembers())
    if size > 2 * 1024**3 or shutil.disk_usage(dest).free < size + 1024**3:
        raise SystemExit('Insufficient disk reserve or oversized release')
    for m in tf:
        target = os.path.join(dest, m.name)
        if m.name.startswith('/') or '..' in m.name.split('/') or not inside(target):
            raise SystemExit('Unsafe archive path')
        if not (m.isfile() or m.isdir() or m.issym()): raise SystemExit('Unsafe archive type')
        if m.issym() and (os.path.isabs(m.linkname) or not inside(os.path.join(os.path.dirname(target), m.linkname))):
            raise SystemExit('Unsafe archive link')
        m.mode &= 0o777
        tf.extract(m, dest, set_attrs=False)
PY
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
/usr/local/bin/node -e 'const [major, minor] = process.versions.node.split(".").map(Number); if (major !== 24 || minor < 11) process.exit(1)'
# Exercise bundled native libraries on the target ABI before switching anything.
(cd "$release" && /usr/local/bin/node --input-type=module -e "await import('sharp'); await import('@resvg/resvg-js')")
switch_to() {
  ln -s "$1" "$root/.current-next"
  mv -Tf "$root/.current-next" "$root/current"
}
restart() { sudo -n /usr/bin/systemctl restart "${units[@]}"; }
healthy() {
  for attempt in {1..20}; do
    if systemctl is-active --quiet "${units[0]}" && systemctl is-active --quiet "${units[1]}" &&
       curl --noproxy '*' --max-time 3 -fsS http://127.0.0.1:3101/api/health | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d.get("ok") is True and d.get("release")==sys.argv[1] else 1)' "$(basename "$(readlink -f "$root/current")")" &&
       curl --noproxy '*' --max-time 3 -fsS -o /dev/null http://127.0.0.1:3100/; then return 0; fi
    sleep 2
  done
  return 1
}
switch_to "$release"
if restart && healthy; then
  printf 'Active AIFinance release: %s\n' "$sha"
else
  echo 'New release failed health check' >&2
  if [[ -n $old && -d $old && $old != "$release" ]]; then
    switch_to "$old"
    if restart && healthy; then echo 'Previous code restored; database was not changed' >&2
    else echo 'ROLLBACK HEALTH FAILED: operator intervention required' >&2; fi
  else
    echo 'No previous healthy version available; operator intervention required' >&2
  fi
  exit 1
fi
