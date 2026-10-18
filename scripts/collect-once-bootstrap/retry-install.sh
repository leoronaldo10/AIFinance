#!/bin/bash
# Download only fixed helper files, preserve prior helper/review/runtime and run once.
set -euo pipefail
[[ $# == 2 && $1 =~ ^[a-f0-9]{40}$ && $2 =~ ^[a-f0-9]{64}$ ]]
[[ $(id -un) == ecs-user && $(hostname) == iZ2zedybs3fftu1d9vnx39Z ]]
COMMIT=$1
MANIFEST_SHA=$2
BASE=/root/aifinance-once-helper-retry/helper
DEST=/root/aifinance-once-helper-retry-dns
FILES=(README.md SHA256SUMS retry-once.py retry-resolver.py retry-install.sh tests/test_retry_resolver.py)
sudo -v
sudo test ! -L "$DEST"
sudo test ! -e /var/lib/aifinance-collect-once/retry-001
sudo test ! -L /var/lib/aifinance-collect-once/retry-001
if ! sudo test -e "$DEST"; then
DOWNLOAD=$(mktemp -d "$HOME/aifinance-retry-download.XXXXXX")
mkdir "$DOWNLOAD/tests"
for f in "${FILES[@]}"; do
 curl --fail --silent --show-error --connect-timeout 10 --max-time 30 -H 'Accept: application/vnd.github.raw+json' "https://api.github.com/repos/leoronaldo10/AIFinance/contents/scripts/collect-once-bootstrap/$f?ref=$COMMIT" -o "$DOWNLOAD/$f"
done
printf '%s  %s\n' "$MANIFEST_SHA" "$DOWNLOAD/SHA256SUMS" | sha256sum -c -
sudo /bin/sh -c 'set -e; cd /root/aifinance-once-helper-retry/helper; printf "291dd19c2d49996b9816852a4c5b97e42800747cb5260006bcd595cba89a2d4b  SHA256SUMS\n" | sha256sum -c -; sha256sum --quiet -c SHA256SUMS'
sudo mkdir -m 0700 "$DEST"
sudo cp -a "$BASE" "$DEST/helper"
for f in "${FILES[@]}"; do sudo install -o root -g root -m 0644 "$DOWNLOAD/$f" "$DEST/helper/$f"; done
fi
sudo /bin/sh -c 'set -e; cd /root/aifinance-once-helper-retry-dns/helper; printf "%s  SHA256SUMS\n" "$1" | sha256sum -c -; sha256sum --quiet -c SHA256SUMS' checked-manifest "$MANIFEST_SHA"
set +e
sudo /usr/bin/python3 -I -B "$DEST/helper/retry-once.py" run --approve-three-source-smoke --exclusive-writer-window
rc=$?
printf 'RETRY_EXIT=%s\n' "$rc"
exit "$rc"
