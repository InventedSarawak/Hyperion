#!/usr/bin/env bash
#
# Post a GraphQL query to the gateway.
#
#   ./scripts/graphql.sh '<query>' ['<variables json>']
#
# Everything a user does goes through nexus, so the task commands that used to
# call cortex over grpcurl come through here instead. The payload is built with
# python rather than string-concatenated in shell: a rule arrives as JSON, and
# nesting quotes through curl -d by hand is how the first attempt broke.
set -euo pipefail

endpoint="${HYPERION_GATEWAY_URL:-http://localhost:8080/graphql}"
query="${1:?usage: graphql.sh '<query>' ['<variables json>']}"
variables="${2:-{\}}"

python3 - "$query" "$variables" "$endpoint" <<'PY'
import json, sys, urllib.error, urllib.request

query, raw_variables, endpoint = sys.argv[1], sys.argv[2], sys.argv[3]

try:
    variables = json.loads(raw_variables) if raw_variables.strip() else {}
except json.JSONDecodeError as err:
    sys.exit(f"graphql: variables are not valid JSON: {err}")

body = json.dumps({"query": query, "variables": variables}).encode()
request = urllib.request.Request(endpoint, data=body,
                                 headers={"Content-Type": "application/json"})

try:
    with urllib.request.urlopen(request, timeout=30) as response:
        answer = json.load(response)
except urllib.error.URLError as err:
    sys.exit(f"graphql: {endpoint} is not answering: {err}")

print(json.dumps(answer, indent=2))

# A GraphQL error comes back with HTTP 200, so the exit code has to be set from
# the body or a failing query looks like a successful command.
if answer.get("errors"):
    sys.exit(1)
PY
