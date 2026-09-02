# Hyperion: The Ultimate CVE Intelligence Platform

## TODO v1: The Foundation (MVP)

> **Plan (decided 2026-08-22):** first vertical slice is **siphon → cortex → nexus**
> (NVD ingest → `SignalEvent` → cortex stores/indexes → `query { search }` via nexus).
> **Contracts-first:** define protobuf in `packages/contracts` and generate Go before wiring
> services. Keep **per-service `go.mod`**. `ghost` (exploit gen) is **parked** — not built yet.
> See `CURRENT_PROGRESS.md` for the live snapshot.

### Project Setup (Monorepo)

- [x] Initialize Git repository
- [x] Initialize Go Workspace (`go work init`) — 7 service modules + 3 Go packages wired in `go.work`
- [x] Setup `Taskfile.yml` for automation (build, run, test) — `task build:go` fixed (space-separated app list; `go build ./...` compile-check, no binaries until a real `func main` exists)
- [x] Setup `turbo.json` for build caching
- [x] Create directory structure (`apps/`, `packages/`, `deploy/`)
- [x] Scaffold Ginkgo test harnesses per service (smoke-level; `task test:go` passes)
- [x] Remove deprecated empty `api/` dir (contracts live in `packages/contracts`)
- [x] Configure `deploy/docker-compose.yml` — Postgres (host port 5433); `task infra:up`/`infra:down`
- [x] Add Elasticsearch to `deploy/docker-compose.yml` (8.15.3, security off for local dev)
- [x] Add `.env.sample` documenting env vars + formats for all 10 ingestion sources
- [x] Centralized namespaced config (`packages/common/config`): SERVICE.VAR -> SERVICE_VAR,
      typed getters, masked secrets, `.env` autoloading — used by siphon/cortex/nexus

### Domain Contracts (The "Law") — do this FIRST

- [x] Create `packages/contracts` module
- [x] Setup `buf.yaml` + `buf.gen.yaml` (managed mode, local plugins) and wire `task codegen`
- [x] Define `proto/hyperion/common/v1/vulnerability.proto` (shared normalized types)
- [x] Define `proto/hyperion/events/v1/signal_events.proto` (`SignalDiscovered`)
- [x] Define `proto/hyperion/intelligence/v1/intelligence_service.proto` (the `Search` RPC)
- [x] Generate Go into `packages/contracts/gen` and confirm services can import via `go.work` (verified from siphon)

### App: Ingestion Worker (`apps/siphon`)

- [x] **Domain:** `SourceSignal` model, `SourceKind` VO, `SignalDiscovered` event (+ dedupe identity)
- [x] **Ports:** `SourceClient`, `SignalPublisher` (outbound, defined in domain)
- [x] **Application:** `PollSource` use case (fetch → validate → publish), fully unit-tested with fakes
- [x] **Adapter (outbound):** NVD API 2.0 client (HTTP) → domain, httptest-tested
- [x] **Adapter (outbound):** publisher maps domain event → `events.v1.SignalDiscovered` proto → stdout (Kafka later)
- [x] **Adapter (inbound):** scheduler (ticker) drives `PollSource` on an interval
- [x] **Platform:** config + `cmd/worker/main.go` composition root — siphon runs end-to-end vs live NVD
- [x] **Rate limiting:** NVD paced to its documented limits (6s no key / 0.6s with key), pagination via startIndex/totalResults, 120-day window clamping, retry+backoff on 403/429/5xx
- [x] **Multi-source:** `PollSources` fans out over every active source; one failure doesn't stop the rest
- [x] **Source registry:** all 10 documented sources resolved at startup; inactive ones reported with a reason
- [x] **All 10 source adapters implemented:** NVD, GitHub Advisory, CISA KEV, Exploit-DB, MITRE,
      Vendor (Red Hat), OSINT RSS, Package feeds (OSV watchlist), Shodan CVEDB, GSD/OSV —
      each with fixture-backed tests and per-source rate limiting
- [x] **Shared adapter plumbing:** `sourcehttp` (pacing + bounded retry/backoff) and `cveid`
      (CVE/URL extraction) so transport concerns are written once
- [ ] Later: swap stdout publisher → Kafka (v3); add dedupe/checkpoint stores (Redis, v3)
- [ ] Note: siphon does NOT persist — it publishes; cortex owns storage (event-driven design)

### App: Intelligence Service (`apps/cortex`)

- [x] **Domain:** `Vulnerability` entity (+ `Merge` reconciliation), `VulnerabilityRepo` port
- [x] **Application:** `IngestSignal` use case (load → merge → upsert), unit-tested with fake repo
- [x] **Adapter (inbound):** consumer reads protojson `SignalDiscovered` (stdin) → cortex domain
- [x] **Adapter (outbound):** Postgres repo (pgx) + embedded migration; integration-tested vs real DB
- [x] **End-to-end:** `siphon | cortex` → Postgres verified (48 live NVD CVEs stored)
- [x] **Infrastructure:** Implement Elasticsearch Client (`SearchIndex` port + ES adapter + no-op fallback)
- [x] **Application:** Dual-write on ingest (Postgres = truth, ES = search); ES failure is non-fatal
- [x] **Application:** Implement `Search` use-case (full-text, paging, token validation)
- [x] **Infrastructure:** Expose gRPC `IntelligenceService.Search` server (+ reflection for grpcurl)

### Verification

- [x] Write Unit Tests with `Ginkgo` for the NVD parser (+ workflow, publisher, scheduler)
- [x] Manual Test: GraphQL query returns real ingested NVD data (verified end-to-end)

### App: API Gateway (`apps/nexus`)

- [x] **Domain/Ports:** `IntelligenceClient` port + view models
- [x] **Application:** `SearchVulnerabilities` use case
- [x] **Adapter (outbound):** gRPC client to cortex
- [x] **Adapter (inbound):** GraphQL schema + handler + browser playground (`/playground`)

---

## TODO v2: The Structure (Graph & TUI)

### Infrastructure Upgrade

- [ ] Add **Neo4j** to `docker-compose.yml`
- [ ] Add **gRPC** reflection to all services

### App: Intelligence Service (Upgrade)

- [ ] **Domain:** Add `Repository`, `Library`, `Author` entities
- [ ] **Infrastructure:** Implement `Neo4jRepository` (The Graph Adapter)
- [ ] **Application:** Implement `IngestDependency` command
  - Logic: `MERGE (r:Repo)-[:DEPENDS_ON]->(l:Lib)`
- [ ] **Query:** Add `FindBlastRadius` (Recursive graph traversal)

### App: TUI Dashboard (`apps/deck`)

- [ ] Initialize Bubble Tea project
- [ ] **Infrastructure:** Create gRPC Client adapter
- [ ] **UI:** Build `Model` (State) and `View` (Layout)
- [ ] **Feature:** "Live Feed" list (polling API for now)
- [ ] **Feature:** "Graph Explorer" (ASCII tree view of dependencies)

### App: Ingestion Worker (Upgrade)

- [ ] Add `GithubClient` adapter (Fetch `go.mod` / `package.json`)
- [ ] Parse dependencies and send to Intelligence Service

---

## Cross-cutting: Technical Debt

Registered in `docs/TECHNICAL-DEBT.md`. Highest-value items, roughly in order:

- [ ] **Per-source lookback/interval** — one global `SIPHON_LOOKBACK` makes three
      low-cadence sources return 0 at the 2h default (small change, high clarity)
- [ ] **Persist the ingestion watermark** — currently in-memory, so a restart refetches
      the whole window and a long outage loses signals
- [ ] Health endpoints on `cortex` and `siphon` (only `nexus` has one)
- [ ] Versioned migrations (`goose`/`golang-migrate`) instead of run-everything-idempotently
- [ ] Graceful shutdown for in-flight ingest (Postgres can end up ahead of Elasticsearch)
- [ ] Elasticsearch alias + reindex strategy for mapping changes

---

## TODO v3: The Nervous System (Streaming)

### Infrastructure Upgrade

- [ ] Add **Apache Kafka** & Zookeeper to `docker-compose.yml`
- [ ] Add **Redis** (for caching/deduplication)
- [ ] Create `packages/common/kafka` (Producer/Consumer wrappers)

### Refactor: Event-Driven Architecture

- [ ] **Ingestion Worker:** Stop writing to DB directly.
  - [ ] Create `KafkaProducer` adapter
  - [ ] Push events to topic `raw-signals`
- [ ] **Intelligence Service:**
  - [ ] Create `KafkaConsumer` adapter (Group: `intel-indexer`)
  - [ ] Process events: `Kafka -> Elastic/Neo4j`

### Feature: Real-Time Alerts

- [ ] **Domain:** Define `Subscription` entity (User rules)
- [ ] **Infrastructure:** Implement **Elasticsearch Percolator** (Reverse Search)
- [ ] **Application:** `MatchSignal` use-case
  - [ ] On new CVE -> Query Percolator -> Find affected Users
- [ ] **Infrastructure:** Redis Deduplication (Don't alert twice in 1 hour)

### Performance Testing

- [ ] Write a load test script (simulate 1k events/sec)
- [ ] Verify TUI updates instantly via gRPC streaming

---

## TODO v4: The Platform (SaaS)

### Data Lake Strategy

- [ ] Add **MinIO** to `docker-compose.yml`
- [ ] **App:** `apps/relic` (Lake Archiver)
  - [ ] Consume `raw-signals` topic
  - [ ] Buffer events and write `Parquet` files to MinIO
- [ ] **Analytics:** Integrate **DuckDB** to query Parquet files

### Monetization (Lago)

- [ ] Deploy **Lago** (Self-hosted billing) via Docker
- [ ] **App: API Gateway:**
  - [ ] Implement `RateLimitMiddleware` using Redis
  - [ ] Add `BillingHook` to report usage to Lago
- [ ] **Web Dashboard:** Build out `apps/console` (Next.js)
  - [ ] User Login (Keycloak)
  - [ ] Subscription Management UI

### DevOps (GitOps)

> Infra debt registered in `docs/TECHNICAL-DEBT.md`. `deploy/k8s/` and
> `deploy/terraform/` are currently **empty directories**.

- [ ] **Dockerfiles:** multi-stage build per Go service (repays AGENTS.md Rule 7 —
      services currently run natively via `scripts/system.sh`)
- [ ] Add the Go services to `docker-compose.yml` with `restart: unless-stopped`
- [ ] Add resource limits to all compose services
- [ ] **CI:** `.github/workflows/` is empty — add build + test + lint + typecheck
- [ ] Decide whether `deploy/terraform/` is real (fill it) or aspirational (delete it)
- [ ] Create `deploy/k8s/helm-chart`
- [ ] Setup local **K3s** cluster
- [ ] Install **ArgoCD** in K3s
- [ ] Create `Application` manifest to sync Git repo -> K3s

---

## TODO v5: The Endgame (AI Copilot)

### Infrastructure Upgrade

- [ ] Add **Ollama** (GPU/CPU mode) to `docker-compose.yml`
- [ ] Add **Qdrant** (Vector DB) to `docker-compose.yml`
- [ ] Pull `deepseek-coder` or `llama3` model

### App: CTF Copilot (`apps/ghost`)

- [ ] **Domain:** Define `Exploit` and `Target` entities
- [ ] **Infrastructure:**
  - [ ] `OllamaClient` adapter (Chat completion)
  - [ ] `QdrantRepository` adapter (Vector search)
- [ ] **Ingestion:** Scrape `Exploit-DB` and generate embeddings
  - [ ] Store Embeddings -> Qdrant
  - [ ] Store Raw Code -> MinIO

### Feature: RAG Pipeline

- [ ] Implement `GenerateExploit` use-case
  1. Receive User Query ("How to pawn CVE-2024-123?")
  2. Retrieve similar exploit code from Qdrant
  3. Construct Prompt with context
  4. Stream LLM response to TUI

### Final Polish

- [ ] Create "Sandbox" runner (execute generated script in Docker)
- [ ] Record Demo GIF (The "Money Shot")
- [ ] Update README with Architecture Diagrams

---

## TODO v6: Day-Two Operations (Observability & Reliability)

### Infrastructure Upgrade (The Telemetry Stack)

- [ ] Add **Prometheus** (Metrics) to `docker-compose.yml`
- [ ] Add **Grafana Loki** (Logs) & Promtail to `docker-compose.yml`
- [ ] Add **Grafana Tempo** (Traces) to `docker-compose.yml`
- [ ] Add **OpenTelemetry (OTel) Collector** to route telemetry data
- [ ] Add **Grafana UI** and provision default dashboards for Go services

### Application Instrumentation

- [ ] **Packages:** Build out `packages/telemetry` for shared OTel setup
- [ ] **Gateway & Services:** Implement OTel Go SDK libraries for distributed tracing
  - [ ] Propagate trace context across gRPC bounds
  - [ ] Propagate trace context across Kafka bounds (Producer/Consumer headers)
- [ ] **Metrics:** Expose `/metrics` endpoints in all Go services (or push to OTel)
  - [ ] Track Kafka lag, HTTP/gRPC request rates, error rates, and latencies

### Structured Logging

- [ ] **Packages:** Replace standard `fmt`/`log` with `log/slog` or `zap` across the monorepo
- [ ] Ensure all logs output in JSON format with trace/span IDs injected
- [ ] Route logs through Docker daemon or Promtail directly to Loki

### Reliability

- [ ] Add basic health checks (`/healthz`, `/readyz`) to all services
- [ ] Add graceful shutdown handling for Kafka consumers and HTTP/gRPC servers
