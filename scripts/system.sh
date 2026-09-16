#!/usr/bin/env bash
#
# Start, stop and inspect the whole Hyperion stack.
#
#   ./scripts/system.sh up       infra + cortex (gRPC) + nexus (GraphQL) + siphon (ingest)
#                                (HYPERION_INGEST=0 to skip siphon)
#   ./scripts/system.sh down     stop services, then infra
#   ./scripts/system.sh restart  rebuild and restart services + ingest; infra keeps running
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
  # Split across two statements on purpose: bash expands every word of a
  # `local a=$1 b=$a` line before assigning any of them, so `$name` there
  # would still be the *caller's* name, not this one.
  local name="$1"
  local file="$RUN_DIR/$name.pid"
  [[ -f "$file" ]] || return 1
  local pid; pid="$(cat "$file")"
  kill -0 "$pid" 2>/dev/null || return 1
  printf '%s' "$pid"
}

# --- continuous ingest -------------------------------------------------------
#
# siphon publishes to Kafka and cortex consumes the topic, so ingest is one
# ordinary process rather than a pipeline of two. It is kept out of SERVICES
# only because it binds no port, and every check there is written around one.
#
# The two halves are now independent: siphon keeps publishing while cortex is
# down, and cortex resumes from its last committed offset when it returns.
# Restarting either one no longer interrupts the other.

ingest_enabled() { [[ "${HYPERION_INGEST:-1}" == "1" ]]; }

start_ingest() {
  if ! ingest_enabled; then
    log "ingest loop disabled (HYPERION_INGEST=0)"
    return 0
  fi
  if pid_of ingest >/dev/null; then
    log "already running: ingest (pid $(pid_of ingest))"
    return 0
  fi

  log "building siphon..."
  ( cd "$ROOT/apps/siphon" && go build -o "$RUN_DIR/bin/siphon" ./cmd/worker )

  log "starting siphon (publishing to kafka)..."
  # Detached with its own stdio: a child holding this script's stdout open
  # would mean `./system.sh up | grep ...` never sees EOF and hangs.
  setsid "$RUN_DIR/bin/siphon" </dev/null >>"$RUN_DIR/ingest.log" 2>&1 &
  echo $! >"$RUN_DIR/ingest.pid"

  # Give it a moment to fail loudly (bad config, unreachable broker) rather
  # than reporting a PID that is already gone.
  sleep 2
  if pid_of ingest >/dev/null; then
    log "ready: siphon (pid $(pid_of ingest))"
  else
    log "WARNING: siphon exited immediately — see $RUN_DIR/ingest.log"
  fi
}

stop_ingest() {
  local pid
  pid="$(pid_of ingest)" || { rm -f "$RUN_DIR/ingest.pid"; return 0; }

  log "stopping siphon (pid $pid)..."
  # Negative PID signals the whole process group. siphon is one process now,
  # but a stale pid file from the old `siphon | cortex` pipeline names a group
  # of two, and this stops both.
  kill -TERM -"$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
  sleep 1
  kill -KILL -"$pid" 2>/dev/null || true
  rm -f "$RUN_DIR/ingest.pid"
}

up() {
  log "starting infrastructure (postgres, elasticsearch, neo4j, redis, kafka, console)..."
  $COMPOSE up -d

  wait_for "postgres" 60 docker exec hyperion-postgres pg_isready -U hyperion -d hyperion
  wait_for "elasticsearch" 120 curl -fsS http://localhost:9200/_cluster/health
  wait_for "neo4j" 120 docker exec hyperion-neo4j cypher-shell -u neo4j -p hyperion "RETURN 1"
  wait_for "redis" 60 docker exec hyperion-redis redis-cli ping
  # Listing topics proves the broker is answering API calls: cortex creates the
  # signal topic at startup and would fail against a port that merely listens.
  wait_for "kafka" 120 docker exec hyperion-kafka \
    /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list

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

  # Started last: siphon publishes as fast as the feeds allow, and there is no
  # point filling the topic before the consumer that drains it is up.
  start_ingest

  echo
  status
  echo
  log "GraphQL console: http://localhost:8080/playground"
  log "kafka console:   http://localhost:8081"
  log "ingest lag:      task topic:lag"
  log "what is on the topic: task topic:tail -- -limit 5"
}

down() {
  stop_services
  log "stopping infrastructure..."
  $COMPOSE down
  log "stopped."
}

# restart picks up code changes without touching the databases, so anything
# else writing to them — a backfill, a one-off scan — keeps running.
restart() {
  stop_services
  up
}

stop_services() {
  stop_ingest

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

  if docker exec hyperion-neo4j cypher-shell -u neo4j -p hyperion "RETURN 1" >/dev/null 2>&1; then
    printf '  %-16s %-10s %s\n' "neo4j" "UP" "bolt on :7687, browser on :7474"
  else
    printf '  %-16s %-10s %s\n' "neo4j" "DOWN" "not answering bolt on :7687"
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

  if docker exec hyperion-redis redis-cli ping >/dev/null 2>&1; then
    printf '  %-16s %-10s %s\n' "redis" "UP" "responding on :6379"
  else
    printf '  %-16s %-10s %s\n' "redis" "DOWN" "not responding on :6379"
  fi

  # Lag is the number that says whether ingest is keeping up: steady lag means
  # slow, lag climbing without bound means stopped. A group that has never
  # committed prints "-", which is not zero and must not be summed as if it were.
  if docker exec hyperion-kafka /opt/kafka/bin/kafka-topics.sh \
       --bootstrap-server localhost:9092 --list >/dev/null 2>&1; then
    local lag
    lag="$(docker exec hyperion-kafka /opt/kafka/bin/kafka-consumer-groups.sh \
      --bootstrap-server localhost:9092 --describe --group intel-indexer 2>/dev/null \
      | awk 'NR>1 && $6 ~ /^[0-9]+$/ {l+=$6; seen=1} END {print (seen ? l : "not committed yet")}')"
    printf '  %-16s %-10s %s\n' "kafka" "UP" "broker on :9092, ingest lag ${lag:-unknown}"
    if curl -fsS -o /dev/null http://localhost:8081/ 2>/dev/null; then
      printf '  %-16s %-10s %s\n' "kafka-console" "UP" "http://localhost:8081"
    else
      printf '  %-16s %-10s %s\n' "kafka-console" "DOWN" "not responding on :8081"
    fi
  else
    printf '  %-16s %-10s %s\n' "kafka" "DOWN" "not answering on :9092"
  fi

  if pid_of ingest >/dev/null; then
    printf '  %-16s %-10s %s\n' "siphon" "UP" "pid $(pid_of ingest), polling every ${SIPHON_POLL_INTERVAL:-10m}"
  elif ingest_enabled; then
    printf '  %-16s %-10s %s\n' "siphon" "DOWN" "-"
  else
    printf '  %-16s %-10s %s\n' "siphon" "OFF" "HYPERION_INGEST=0"
  fi

  local rows docs
  rows="$(docker exec hyperion-postgres psql -U hyperion -d hyperion -tAc \
    'SELECT count(*) FROM vulnerabilities;' 2>/dev/null || echo '-')"
  docs="$(curl -s http://localhost:9200/hyperion-vulnerabilities/_count 2>/dev/null \
    | sed -n 's/.*"count":\([0-9]*\).*/\1/p')"
  printf '  %-16s %-10s %s\n' "data" "-" "postgres rows=${rows:--} elasticsearch docs=${docs:--}"

  local nodes edges
  nodes="$(docker exec hyperion-neo4j cypher-shell -u neo4j -p hyperion --format plain \
    "MATCH (n) RETURN count(n);" 2>/dev/null | tail -1 || echo '-')"
  edges="$(docker exec hyperion-neo4j cypher-shell -u neo4j -p hyperion --format plain \
    "MATCH ()-[r]->() RETURN count(r);" 2>/dev/null | tail -1 || echo '-')"
  printf '  %-16s %-10s %s\n' "graph" "-" "neo4j nodes=${nodes:--} relationships=${edges:--}"
}

logs() {
  local files=()
  for entry in "${SERVICES[@]}"; do
    IFS='|' read -r name _ _ _ <<< "$entry"
    [[ -f "$RUN_DIR/$name.log" ]] && files+=("$RUN_DIR/$name.log")
  done
  [[ -f "$RUN_DIR/ingest.log" ]] && files+=("$RUN_DIR/ingest.log")
  [[ ${#files[@]} -gt 0 ]] || { log "no logs yet; run: ./scripts/system.sh up"; return 0; }
  tail -n 40 -f "${files[@]}"
}

case "${1:-}" in
  up)      up ;;
  down)    down ;;
  restart) restart ;;
  status)  status ;;
  logs)    logs ;;
  *)       echo "usage: $0 {up|down|restart|status|logs}" >&2; exit 2 ;;
esac
