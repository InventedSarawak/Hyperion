# Technical Debt & Corners Cut

An honest register of what Hyperion does **not** do yet, and why. Everything here
was a deliberate trade to keep momentum on the core threat engine — none of it is
an accident, but none of it should ship to production either.

Each entry records the shortcut, what it costs, and the roadmap version where it
should be paid off. Update this file whenever a corner is cut or repaid.

**Status legend:** 🔴 blocks production · 🟡 limits correctness/ops · 🟢 cosmetic

---

## 1. Deployment & Infrastructure

### 🔴 No Dockerfiles — Go services run as native host processes

`cortex` and `nexus` are compiled to `.run/bin/` and started with `setsid` by
`scripts/system.sh`. Only Postgres and Elasticsearch are containers.

- **Why:** a `go build` dev loop is ~1s; a Docker image rebuild per code change is not.
- **Cost:** the system lives in two places — `docker ps` shows only half of it.
  Services do not restart on crash, and they die on desktop logout (their parent is
  `systemd --user`) while the containers survive. This directly contradicts
  **AGENTS.md Rule 7** ("Code is not done until it runs inside a container").
- **Fix in v4:** multi-stage Dockerfiles per service, added to `docker-compose.yml`
  with `restart: unless-stopped`. Keep a bind-mount dev target so the fast loop survives.

### 🔴 `deploy/k8s/` and `deploy/terraform/` are empty directories

Both exist in the tree and are referenced by `docs/PROJECT-STRUCTURE.md`, but contain
no manifests, Helm charts, or `.tf` files whatsoever.

- **Why:** deployment is a v4 concern; there is nothing stable to deploy yet.
- **Cost:** the repo structure implies infra-as-code that does not exist. Anyone
  reading the tree would reasonably assume otherwise.
- **Fix in v4:** Helm chart per service, K3s locally, ArgoCD for GitOps. Terraform
  only once there is real cloud infra to describe — an empty `deploy/terraform/`
  should either be filled or deleted.

### 🟡 No CI pipeline

`.github/workflows/` is empty. Nothing runs tests, lint, or builds on push.

- **Why:** the husky pre-commit hook covers the same checks locally.
- **Cost:** the gate is bypassable (`--no-verify`) and only protects this machine.
  No build matrix, no image publishing, no protection on shared branches.
- **Fix in v4:** GitHub Actions running `task build:go`, `task test:go`, lint and
  typecheck; publish images on tag.

### 🟡 No restart policies or resource limits in compose

Containers have healthchecks but no `restart:` policy and no memory/CPU bounds
(beyond Elasticsearch's `ES_JAVA_OPTS` heap).

- **Cost:** a crashed container stays down; a runaway one can starve the host.
- **Fix in v4:** `restart: unless-stopped` plus `deploy.resources.limits`.

---

## 2. Data Flow & Correctness

### 🔴 Transport is a Unix pipe, not a message bus

`siphon | cortex` — siphon writes protojson to stdout, cortex reads stdin.

- **Why:** it proved the whole contract boundary end-to-end without standing up Kafka.
- **Cost:** no durability, no replay, no consumer groups, no backpressure. If cortex
  dies mid-stream those events are gone. Producer and consumer must run as a pair.
- **Fix in v3:** Kafka `raw-signals` topic. Only the publisher and consumer adapters
  change — the domain and use cases do not (this is the payoff of the hexagon).

### 🟡 Ingestion watermark is in-memory only

`scheduler.since` is a struct field. Restarting siphon resets it to
`now - SIPHON_LOOKBACK`.

- **Cost:** every restart re-fetches the whole lookback window, wasting rate-limit
  budget. Correctness is saved only because cortex upserts by CVE id — the duplicate
  work is invisible but real. A crash longer than the lookback window **loses signals**.
- **Fix in v3:** the `CheckpointStore` port already sketched in
  `docs/PROJECT-STRUCTURE.md`, backed by Redis or Postgres.

### 🟡 No dedupe store

`DedupeStore` is designed but not implemented. Deduplication happens implicitly at
the cortex upsert.

- **Cost:** siphon republishes unchanged signals on every poll; cortex does a
  read-modify-write per event regardless. Wasteful, and it will not scale to a real
  firehose.
- **Fix in v3:** Redis-backed `DedupeStore` keyed on the domain `SignalID`.

### 🟡 Single global lookback across sources of wildly different cadence

One `SIPHON_LOOKBACK` drives all ten sources. NVD/GitHub/Shodan publish hundreds of
signals a day; exploit-db, OSINT and package-feed publish a handful a _week_.

- **Cost:** at the 2h default, three sources return 0 essentially always — which
  looks like a broken adapter but is not. Verified against upstream: the data
  genuinely is not there.
- **Fix:** per-source lookback/interval in config. Small change, high clarity win.

### 🟡 Naive migration runner

`postgres.Migrate` executes every embedded `.sql` file in filename order on every
boot. Idempotency relies on `IF NOT EXISTS`.

- **Cost:** no version table, no down-migrations, no drift detection. A non-idempotent
  migration would corrupt state or fail the boot.
- **Fix in v2/v3:** adopt `goose` or `golang-migrate` with a schema-version table.

### 🟢 No Elasticsearch alias or reindex strategy

Documents are written straight to a fixed index name.

- **Cost:** a mapping change requires deleting and rebuilding the index with downtime.
- **Fix in v3:** write through an alias, reindex into a new concrete index, flip atomically.

---

## 3. Security

### 🔴 No authentication or authorization anywhere

The GraphQL endpoint and the gRPC API are both fully open. Anyone who can reach the
port can query everything.

- **Why:** Keycloak is scheduled for v4; auth would have blocked the v1 slice.
- **Fix in v4:** Keycloak OIDC, JWT validation at the nexus edge, per-tenant scoping.

### 🔴 gRPC runs in plaintext

`insecure.NewCredentials()` in
`apps/nexus/internal/adapters/outbound/grpc/intelligence_client.go`.

- **Cost:** fine while both ends are on localhost; unacceptable the moment the
  services are on separate hosts.
- **Fix in v4:** mTLS, or a service mesh handling transport security.

### 🟡 Elasticsearch security disabled

`xpack.security.enabled=false` in compose — no auth, no TLS on :9200.

- **Why:** removes credential setup from local dev.
- **Cost:** anything on the host can read/write the index. **Local dev only — never
  deploy this compose file.**
- **Fix in v4:** enable security, use real credentials from a secret store.

### 🟡 Default credentials committed in compose

`hyperion/hyperion` for Postgres, in the repo.

- **Cost:** harmless locally, catastrophic if the file were ever applied elsewhere.
- **Fix in v4:** secrets via environment/secret manager, never in the compose file.

### 🟡 Secrets sit in plaintext `.env`

API keys are read from an unencrypted, gitignored file.

- **Cost:** standard for local dev, but no rotation, no audit, no encryption at rest.
- **Fix in v4:** a secret manager (Vault / SOPS / cloud KMS) for anything deployed.
- **Known footgun:** godotenv strips a trailing `# comment` only when the line has a
  value. A blank setting written `KEY=   # hint` yields the _comment_ as the value —
  this produced a real GitHub 401. The loader now treats a leading `#` as unset, and
  `.env.sample` keeps hints on their own line. Do not reintroduce inline hints on
  blank lines.

---

## 4. Operability

### 🟡 No health endpoint on cortex

`nexus` serves `/healthz`; `cortex` and `siphon` serve nothing. `scripts/system.sh`
probes cortex by opening a TCP connection to :50051, which proves the port is bound
but not that the service is healthy.

- **Fix in v4:** gRPC health checking protocol on cortex; readiness that verifies
  Postgres and Elasticsearch.

### 🟡 No observability

No metrics, no tracing, no structured log aggregation. `packages/telemetry` is an
empty module.

- **Cost:** no visibility into rate-limit consumption, ingest lag, or query latency.
- **Fix in v6:** OpenTelemetry, Prometheus, Grafana, Loki, Tempo.

### 🟡 Ingest has no graceful shutdown

Ctrl-C during ingestion drops whatever is in flight. There is no transaction spanning
the store-and-index pair, so Postgres can hold a record that Elasticsearch does not.

- **Cost:** search results can silently lag storage after an abrupt stop.
- **Fix in v3:** drain on shutdown; a reconciliation job to reindex from Postgres.

### 🟢 Elasticsearch cluster runs yellow

Single-node with default replica settings, so replicas are unassignable.

- **Cost:** cosmetic locally; a genuine availability gap in any real deployment.
- **Fix in v4:** set `number_of_replicas: 0` for single-node, or run a real cluster.

---

## 5. Scope Deliberately Deferred

Not debt — planned roadmap work, listed so the gap between the docs and reality is explicit:

- **`ghost`** (CTF copilot, Ollama + Qdrant) — parked, v5.
- **`relic`** (Parquet archiver to MinIO) — stub, v4.
- **`deck`** (Bubble Tea TUI) — stub, v2.
- **`credits`** (Lago billing) — stub, v4.
- **`console`** (Next.js dashboard) — still the Turborepo starter page, v4.
- **Neo4j blast radius** — the platform's actual differentiator, v2.
