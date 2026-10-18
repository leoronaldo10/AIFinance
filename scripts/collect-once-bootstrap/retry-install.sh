#!/bin/bash
# Download only fixed helper files, preserve prior helper/review/runtime and run once.
set -euo pipefail
[[ $# == 2 && $1 =~ ^[a-f0-9]{40}$ && $2 =~ ^[a-f0-9]{64}$ ]]
[[ $(id -un) == ecs-user && $(hostname) == iZ2zedybs3fftu1d9vnx39Z ]]
COMMIT=$1
MANIFEST_SHA=$2
BASE=/root/aifinance-once-helper-socket/scripts/collect-once-bootstrap
DEST=/root/aifinance-once-helper-retry
FILES=(README.md SHA256SUMS retry-once.py retry-hba.py retry-install.sh tests/test_retry_hba.py)
sudo -v
sudo test ! -e "$DEST"
sudo test ! -L "$DEST"
sudo test ! -e /var/lib/aifinance-collect-once/retry-001
sudo test ! -L /var/lib/aifinance-collect-once/retry-001
DOWNLOAD=$(mktemp -d "$HOME/aifinance-retry-download.XXXXXX")
mkdir "$DOWNLOAD/tests"
for f in "${FILES[@]}"; do
 curl --fail --silent --show-error --connect-timeout 10 --max-time 30 -H 'Accept: application/vnd.github.raw+json' "https://api.github.com/repos/leoronaldo10/AIFinance/contents/scripts/collect-once-bootstrap/$f?ref=$COMMIT" -o "$DOWNLOAD/$f"
done
printf '%s  %s\n' "$MANIFEST_SHA" "$DOWNLOAD/SHA256SUMS" | sha256sum -c -
sudo /bin/sh -c 'set -e; cd /root/aifinance-once-helper-socket/scripts/collect-once-bootstrap; printf "3635e8eb157386ccfee82800e438149d95272fa26773bf490f6e5a98db6ec554  SHA256SUMS\n" | sha256sum -c -; sha256sum --quiet -c SHA256SUMS'
sudo mkdir -m 0700 "$DEST"
sudo cp -a "$BASE" "$DEST/helper"
for f in "${FILES[@]}"; do sudo install -o root -g root -m 0644 "$DOWNLOAD/$f" "$DEST/helper/$f"; done
sudo /bin/sh -c 'set -e; cd /root/aifinance-once-helper-retry/helper; printf "%s  SHA256SUMS\n" "$1" | sha256sum -c -; sha256sum --quiet -c SHA256SUMS' checked-manifest "$MANIFEST_SHA"
set +e
sudo /usr/bin/python3 -I -B "$DEST/helper/retry-once.py" run --approve-three-source-smoke --exclusive-writer-window
rc=$?
printf 'RETRY_EXIT=%s\n' "$rc"
exit "$rc"
