#!/usr/bin/env bash
# Run on a Linux x86_64 builder AFTER tests/build. Never includes env files or runtime data.
set -euo pipefail
sha=${1:?full reviewed commit SHA required}
out=${2:?absolute output directory required}
[[ $sha =~ ^[0-9a-f]{40}$ && $out = /* ]] || exit 2
[[ $(git rev-parse HEAD) = "$sha" ]] || { echo 'Commit mismatch' >&2; exit 1; }
[[ -z $(git status --porcelain --untracked-files=normal) ]] || { echo 'Package only clean reviewed commits' >&2; exit 1; }
[[ -f apps/web/build/server/index.js ]] || exit 1
mkdir -p "$out"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
# git archive is an explicit tracked-source boundary; generated client/server assets are added separately.
git archive "$sha" | tar -x -C "$stage"
mkdir -p "$stage/apps/web/build"
cp -a apps/web/build/. "$stage/apps/web/build/"
# Keep production dependencies built/downloaded on the cloud builder, not on the small ECS.
cp -a node_modules "$stage/node_modules"
(cd "$stage" && npm prune --omit=dev --ignore-scripts --no-audit --no-fund)
(cd "$stage" && sha256sum database/migrations/*.sql > schema.sha256)
printf '%s\n' "$sha" > "$stage/RELEASE_SHA"
tar -czf "$out/$sha.tar.gz" -C "$stage" .
(cd "$out" && sha256sum "$sha.tar.gz" > "$sha.tar.gz.sha256")
