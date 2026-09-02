#!/usr/bin/env bash
#
# Start, stop and inspect the whole Hyperion stack.
#
#   ./scripts/system.sh up       infra + cortex (gRPC) + nexus (GraphQL)
#   ./scripts/system.sh down     stop services, then infra
#   ./scripts/system.sh status   what is running, with health checks
#   ./scripts/system.sh logs     tail the service logs
#
# Long-running Go services are started detached, with their PIDs tracked in
# .run/ so `down` can stop exactly what `up` started. Infra runs in Docker.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="$ROOT/.run"
COMPOSE="docker compose -f $ROOT/deploy/docker-compose.yml"

# Services run as detached Go binaries: name|module dir|package|port
SERVICES=(
  "cortex|$ROOT/apps/cortex|./cmd/server|50051"
  "nexus|$ROOT/apps/nexus|./cmd/server|8080"
)

mkdir -p "$RUN_DIR"

log() { printf '  %s\n' "$*"; }

# wait_for polls a command until it succeeds or the timeout expires.
wait_for() {
  local what="$1" timeout="$2"; shift 2
  local waited=0
  until "$@" >/dev/null 2>&1; do
    if (( waited >= timeout )); then
      log "TIMEOUT waiting for $what after ${timeout}s"
      return 1
    fi
    sleep 1; waited=$((waited + 1))
  done
  log "ready: $what (${waited}s)"
}

# port_holder prints the pid(s) listening on a TCP port, if any.
port_holder() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -ltnp "sport = :$port" 2>/dev/null | grep -oP 'pid=\K[0-9]+' | sort -u | tr '\n' ' ' | sed 's/ $//' || true
  else
    lsof -ti ":$port" -sTCP:LISTEN 2>/dev/null | tr '\n' ' ' | sed 's/ $//' || true
  fi
}

pid_of() {
  local name="$1" file="$RUN_DIR/$name.pid"
  [[ -f "$file" ]] || return 1
  local pid; pid="$(cat "$file")"
  kill -0 "$pid" 2>/dev/null || return 1
  printf '%s' "$pid"
}

up() {
  log "starting infrastructure (postgres, elasticsearch)..."
  $COMPOSE up -d

  wait_for "postgres" 60 docker exec hyperion-postgres pg_isready -U hyperion -d hyperion
  wait_for "elasticsearch" 120 curl -fsS http://localhost:9200/_cluster/health

  mkdir -p "$RUN_DIR/bin"

  for entry in "${SERVICES[@]}"; do
    IFS='|' read -r name dir pkg port <<< "$entry"

    if pid_of "$name" >/dev/null; then
      log "already running: $name (pid $(pid_of "$name"))"
      continue
    fi

    # An untracked process on our port would make the service die on bind.
    local holder
    holder="$(port_holder "$port")"
    if [[ -n "$holder" ]]; then
      log "ERROR: port $port already held by pid $holder (not started by us)"
      log "       run './scripts/system.sh down' to reclaim it, then retry"
      return 1
    fi

    # Build first: running the binary directly means the PID we record is the
    # real process, not a `go run` wrapper whose child outlives it.
    log "building $name..."
    ( cd "$dir" && go build -o "$RUN_DIR/bin/$name" "$pkg" )

    log "starting $name..."
    # setsid detaches into a new session so the service survives this script.
    setsid "$RUN_DIR/bin/$name" >"$RUN_DIR/$name.log" 2>&1 &
    echo $! >"$RUN_DIR/$name.pid"
  done

  wait_for "cortex gRPC :50051" 60 bash -c 'exec 3<>/dev/tcp/127.0.0.1/50051'
  wait_for "nexus HTTP :8080" 60 curl -fsS http://localhost:8080/healthz

  echo
  status
  echo
  log "GraphQL console: http://localhost:8080/playground"
  log "ingest data:     task ingest"
}

down() {
  for entry in "${SERVICES[@]}"; do
    IFS='|' read -r name _ _ port <<< "$entry"

    local pid
    if pid="$(pid_of "$name")"; then
      log "stopping $name (pid $pid)..."
      kill -TERM "$pid" 2>/dev/null || true
    fi
    rm -f "$RUN_DIR/$name.pid"

    # Reclaim the port regardless of who owns it: a crashed run, a manual
    # `go run`, or an orphan from a previous session would all block startup.
    local holder
    holder="$(port_holder "$port")"
    if [[ -n "$holder" ]]; then
      log "reclaiming port $port from pid $holder..."
      kill -TERM $holder 2>/dev/null || true
      sleep 1
      holder="$(port_holder "$port")"
      [[ -n "$holder" ]] && kill -KILL $holder 2>/dev/null || true
    fi
  done

  log "stopping infrastructure..."
  $COMPOSE down
  log "stopped."
}

status() {
  printf '  %-16s %-10s %s\n' "COMPONENT" "STATUS" "DETAIL"

  # Probe the services directly: Docker's health status lags its check interval,
  # so a container can be serving while still reported as "starting".
  if docker exec hyperion-postgres pg_isready -U hyperion -d hyperion >/dev/null 2>&1; then
    printf '  %-16s %-10s %s\n' "postgres" "UP" "accepting connections on :5432"
  else
    printf '  %-16s %-10s %s\n' "postgres" "DOWN" "not accepting connections"
  fi

  if curl -fsS http://localhost:9200/_cluster/health >/dev/null 2>&1; then
    local cluster
    cluster="$(curl -s http://localhost:9200/_cluster/health | sed -n 's/.*"status":"\([a-z]*\)".*/\1/p')"
    printf '  %-16s %-10s %s\n' "elasticsearch" "UP" "cluster ${cluster:-unknown} on :9200"
  else
    printf '  %-16s %-10s %s\n' "elasticsearch" "DOWN" "not responding on :9200"
  fi

  for entry in "${SERVICES[@]}"; do
    IFS='|' read -r name _ _ port <<< "$entry"
    local holder; holder="$(port_holder "$port")"

    if pid_of "$name" >/dev/null; then
      printf '  %-16s %-10s %s\n' "$name" "UP" "pid $(pid_of "$name") on :$port"
    elif [[ -n "$holder" ]]; then
      printf '  %-16s %-10s %s\n' "$name" "FOREIGN" "port :$port held by pid $holder (not ours)"
    else
      printf '  %-16s %-10s %s\n' "$name" "DOWN" "-"
    fi
  done

  local rows docs
  rows="$(docker exec hyperion-postgres psql -U hyperion -d hyperion -tAc \
    'SELECT count(*) FROM vulnerabilities;' 2>/dev/null || echo '-')"
  docs="$(curl -s http://localhost:9200/hyperion-vulnerabilities/_count 2>/dev/null \
    | sed -n 's/.*"count":\([0-9]*\).*/\1/p')"
  printf '  %-16s %-10s %s\n' "data" "-" "postgres rows=${rows:--} elasticsearch docs=${docs:--}"
}

logs() {
  local files=()
  for entry in "${SERVICES[@]}"; do
    IFS='|' read -r name _ _ _ <<< "$entry"
    [[ -f "$RUN_DIR/$name.log" ]] && files+=("$RUN_DIR/$name.log")
  done
  [[ ${#files[@]} -gt 0 ]] || { log "no logs yet; run: ./scripts/system.sh up"; return 0; }
  tail -n 40 -f "${files[@]}"
}

case "${1:-}" in
  up)     up ;;
  down)   down ;;
  status) status ;;
  logs)   logs ;;
  *)      echo "usage: $0 {up|down|status|logs}" >&2; exit 2 ;;
esac
