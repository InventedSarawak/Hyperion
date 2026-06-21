#!/usr/bin/env bash
set -euo pipefail

for mod in apps/* packages/common packages/contracts packages/telemetry; do
  if [ -f "$mod/go.mod" ]; then
    echo "Tidying $mod"
    (cd "$mod" && go mod tidy)
  fi
done
