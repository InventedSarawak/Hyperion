#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export GOCACHE="${GOCACHE:-$repo_root/.cache/go-build}"
mkdir -p "$GOCACHE"

runner="${GO_TEST_RUNNER:-go test}"
if [[ "$runner" == richgo* ]] && ! command -v richgo >/dev/null 2>&1; then
  go_bin="$(go env GOBIN)"
  if [ -z "$go_bin" ]; then
    go_bin="$(go env GOPATH)/bin"
  fi
  runner="${runner/richgo/$go_bin\/richgo}"
fi

for mod in apps/* packages/common packages/contracts packages/telemetry; do
  if [ -f "$mod/go.mod" ]; then
    echo "Testing $mod"
    packages="$(cd "$mod" && go list ./... 2>/dev/null || true)"
    if [ -z "$packages" ]; then
      echo "Skipping $mod: no Go packages yet"
      continue
    fi

    (cd "$mod" && $runner ./...)
  fi
done
