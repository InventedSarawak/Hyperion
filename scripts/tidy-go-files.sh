#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export GOCACHE="${GOCACHE:-$repo_root/.cache/go-build}"
mkdir -p "$GOCACHE"

for mod in apps/* packages/common packages/contracts packages/telemetry; do
  if [ -f "$mod/go.mod" ]; then
    echo "Tidying $mod"
    (cd "$mod" && go mod tidy)
  fi
done
