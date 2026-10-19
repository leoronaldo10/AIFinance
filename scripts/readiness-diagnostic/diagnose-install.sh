#!/bin/bash
# Fixed diagnosis only. Repeating this command retrieves the SAME session.
set -euo pipefail
[[ $# == 2 && $1 =~ ^[a-f0-9]{40}$ && $2 =~ ^[a-f0-9]{64}$ ]]
[[ $(id -un) == ecs-user && $(hostname) == iZ2zedybs3fftu1d9vnx39Z ]]
COMMIT=$1
MANIFEST_SHA=$2
DEST=/root/aifinance-readiness-diagnostic-v1
FILES=(diagnose.py diagnose-install.sh diagnostic_core.py process_readiness.py DIAGNOSTIC.SHA256)
sudo -v
DOWNLOAD=
STAGE=
cleanup_downloads() {
 if [[ -n "$DOWNLOAD" ]]; then rm -rf -- "$DOWNLOAD"; fi
 if [[ -n "$STAGE" ]]; then sudo /bin/rm -rf -- "$STAGE"; fi
}
trap cleanup_downloads EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
sudo test ! -L "$DEST"
if ! sudo test -e "$DEST"; then
 DOWNLOAD=$(mktemp -d "$HOME/aifinance-diagnostic-download.XXXXXX")
 for f in "${FILES[@]}"; do
  curl --fail --silent --show-error --connect-timeout 10 --max-time 30 -H 'Accept: application/vnd.github.raw+json' "https://api.github.com/repos/leoronaldo10/AIFinance/contents/scripts/readiness-diagnostic/$f?ref=$COMMIT" -o "$DOWNLOAD/$f"
 done
 printf '%s  %s\n' "$MANIFEST_SHA" "$DOWNLOAD/DIAGNOSTIC.SHA256" | sha256sum -c -
 ( cd "$DOWNLOAD"; sha256sum --quiet -c DIAGNOSTIC.SHA256 )
 STAGE=$(sudo mktemp -d /root/aifinance-diagnostic-install.XXXXXX)
 for f in "${FILES[@]}"; do sudo install -o root -g root -m 0600 "$DOWNLOAD/$f" "$STAGE/$f"; done
 sudo /usr/bin/python3 -I -B -c 'import pathlib,hashlib,sys,os; p=pathlib.Path(sys.argv[1]); assert hashlib.sha256((p/"DIAGNOSTIC.SHA256").read_bytes()).hexdigest()==sys.argv[2]; rows=[line.split() for line in (p/"DIAGNOSTIC.SHA256").read_text().splitlines()]; assert all(hashlib.sha256((p/n).read_bytes()).hexdigest()==h for h,n in rows); target=pathlib.Path(sys.argv[3]); assert not target.exists() and not target.is_symlink(); os.rename(p,target)' "$STAGE" "$MANIFEST_SHA" "$DEST"
fi
sudo /bin/sh -c 'set -e; cd /root/aifinance-readiness-diagnostic-v1; printf "%s  DIAGNOSTIC.SHA256\n" "$1" | sha256sum -c -; sha256sum --quiet -c DIAGNOSTIC.SHA256' checked "$MANIFEST_SHA"
sudo /usr/bin/python3 -I -B "$DEST/diagnose.py" launch --manifest-sha "$MANIFEST_SHA"
for ((i=0; i<75; i++)); do
 set +e
 sudo /usr/bin/python3 -I -B "$DEST/diagnose.py" status --quiet-pending --manifest-sha "$MANIFEST_SHA"
 rc=$?
 set -e
 if [[ $rc != 2 ]]; then printf 'DIAGNOSTIC_EXIT=%s\n' "$rc"; exit "$rc"; fi
 sleep 2
done
printf '%s\n' 'Diagnostic still pending. Re-run this same command to retrieve it; it will not repeat the tests.'
exit 2
