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
- [x] Configure `deploy/docker-compose.yml` — Postgres + Elasticsearch on default ports (5432/9200); `task up`/`task down`
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

## TODO v2: The Structure (Graph & TUI) — COMPLETE

> **Verified 2026-09-07** end to end on live data: 100 CVEs linked to 31 libraries,
> 3 scanned repositories, 912 `DEPENDS_ON` edges, and a real transitive answer —
> `eslint/eslint` is exposed to `CVE-2026-13676` at depth 2 via `npm:ajv` -> `npm:fast-uri`.

### Infrastructure Upgrade

- [x] Add **Neo4j** to `docker-compose.yml` — 5.26, bolt :7687, browser :7474,
      `cypher-shell` healthcheck; `scripts/system.sh` waits on it and reports node counts
- [x] Add **gRPC** reflection (done on cortex; add to future services as they gain gRPC)

### App: Intelligence Service (Upgrade)

- [x] **Domain:** `Repository`, `Library`, `Author` entities (+ `Dependency`,
      `RepositorySnapshot` aggregate, `PackageRef`/`Ecosystem` value objects)
- [x] **Infrastructure:** `Neo4jRepository` — the `DependencyGraph` adapter, with
      uniqueness constraints and a `noopgraph` fallback that **refuses** rather than
      returning an empty radius (an empty answer would read as "nothing is affected")
- [x] **Application:** `IngestDependency` command — `MERGE (r:Repository)-[:DEPENDS_ON]->(l:Library)`,
      whole snapshot in one transaction, idempotent on re-read
- [x] **Query:** `FindBlastRadius` (recursive `DEPENDS_ON*1..n` traversal, depth/result capped)
- [x] **Contracts:** `IngestDependencies` + `GetBlastRadius` RPCs; `common/v1/package.proto`
      and `common/v1/repository.proto`
- [x] **Linkage:** `(:Library)-[:AFFECTED_BY]->(:Vulnerability)` from GitHub Advisory and
      OSV affected-package data — without it the traversal has nothing to start from

### App: TUI Dashboard (`apps/deck`)

- [x] Initialize Bubble Tea project (`cmd/tui`, hexagonal like the services)
- [x] **Infrastructure:** gRPC client adapter (talks to cortex directly, not via nexus)
- [x] **UI:** `Model` (state), `Update` (keys/messages) and `View` (layout), lipgloss-styled
- [x] **Feature:** "Live Feed" list (polls on `DECK_REFRESH_INTERVAL`; streaming is v3)
- [x] **Feature:** "Graph Explorer" (ASCII tree view of the blast radius)

### App: Ingestion Worker (Upgrade)

- [x] Add repository adapter (`repos/githubrepo`) fetching `go.mod` / `package.json`
      via the GitHub contents API
- [x] Parse dependencies (`repos/manifest`, using `x/mod/modfile`) and send them to the
      Intelligence Service over gRPC (`ScanRepositories` workflow)

---

## Cross-cutting: Technical Debt

Registered in `docs/TECHNICAL-DEBT.md`. Highest-value items, roughly in order:

- [ ] **Per-source lookback/interval** — one global `SIPHON_LOOKBACK` makes three
      low-cadence sources return 0 at the 2h default (small change, high clarity).
      **v2 raised the stakes:** GitHub's _reviewed_ advisories are the only source of
      affected-package data, and only ~1 appears per 6h — so at the 2h default the
      dependency graph gains almost no linkage. Verified: a 30-day window yields 100
      reviewed advisories, all with packages.
- [ ] **Library-to-library edges only come from scanned repositories** — a `PUBLISHES`
      repo contributes its module's direct requirements, so transitivity reaches only as
      far as the watchlist. A real module graph (deps.dev / SBOM) would close this.
- [ ] **Persist the ingestion watermark** — currently in-memory, so a restart refetches
      the whole window and a long outage loses signals
- [ ] Health endpoints on `cortex` and `siphon` (only `nexus` has one)
- [ ] Versioned migrations (`goose`/`golang-migrate`) instead of run-everything-idempotently
- [ ] Graceful shutdown for in-flight ingest (Postgres can end up ahead of Elasticsearch)
- [ ] Elasticsearch alias + reindex strategy for mapping changes

---

## TODO v3: The Nervous System (Streaming)

### Infrastructure Upgrade

- [x] Add **Apache Kafka** to `docker-compose.yml` — 4.1.0 in **KRaft** mode, single
      node, healthchecked. (No ZooKeeper: it was removed in Kafka 4.0.)
- [x] Add **Redis** (for caching/deduplication) — landed with alerting, 2026-09-09
- [x] Create `packages/common/kafka` (Producer/Consumer wrappers) — franz-go, with a
      protobuf codec, group-free `Tail` for debugging, `EnsureTopic`, and lag reporting

### Refactor: Event-Driven Architecture

- [x] **Ingestion Worker:** publish to the broker instead of stdout
  - [x] Create `KafkaProducer` adapter (`adapters/outbound/publisher/kafka_publisher.go`)
  - [x] Push events to topic `hyperion.signals.v1`, keyed by finding id
  - [x] `SignalPublisher` port gained `Flush`, so a poll's watermark cannot advance past
        events the broker never acknowledged
- [x] **Intelligence Service:**
  - [x] Create `KafkaConsumer` adapter (Group: `intel-indexer`) — runs alongside the gRPC API
  - [x] Process events: `Kafka -> Postgres/Elastic/Neo4j`
- [x] **Make it the default (2026-09-17):** `task up` runs siphon and cortex as
      independent services over the broker. The pipe survives only where it is wanted —
      `task ingest` and `task backfill`, which opt out explicitly
- [x] **Repository scans publish `DependencyObserved` (2026-09-17):** topic
      `hyperion.dependencies.v1`, keyed by repository, consumed by cortex as group
      `intel-graph`. Verified by scanning with cortex stopped — the scan succeeded and
      cortex applied it on restart. The gRPC path remains as the no-broker fallback
- [x] **Redis `DedupeStore` (2026-09-17):** observations are fingerprinted by content and
      an unchanged one is not republished. One 3h NVD window re-read: 885 suppressed,
      25 published. A corrected score or a new affected package still publishes
- [x] **Dead-letter topic (2026-09-17):** exhausted records go to
      `hyperion.signals.v1.dlq` with the reason in headers and ingest continues; a run of
      ten consecutive failures still stops cortex rather than draining the topic.
      `task topic:dlq` reads it, `-replay` puts records back
- [x] **Persist siphon's ingestion watermark (2026-09-17):** `CheckpointStore` port +
      Redis adapter; the scheduler resumes from the stored watermark and only advances
      it on a successful poll. Restart re-fetch: 526 records -> 59

### Feature: Real-Time Alerts — DONE (2026-09-09)

> Built ahead of the Kafka refactor: alerting is the product step, and it works
> on the current transport. Only the consumer adapter changes when Kafka lands.

- [x] **Domain:** `Subscription` entity, `AlertRule` value object (with `Matches`
      as the authoritative specification), `Alert` entity with a deterministic id
- [x] **Infrastructure:** **Elasticsearch Percolator** (reverse search) — rules are
      stored as queries and a vulnerability is percolated against them; the query is
      built from the structured rule, never accepted as raw DSL
- [x] **Application:** `MatchSignal` use case
  - [x] On new CVE -> percolate -> load rule -> re-verify in the domain -> alert
- [x] **Infrastructure:** Redis deduplication (`SET NX EX`, one atomic round trip)
- [x] **Infrastructure:** Redis in `docker-compose.yml`
- [x] **API:** `hyperion.alerting.v1.AlertingService` — create/list/delete
      subscriptions, list alerts with their vulnerability resolved on read
- [x] Boot-time reindex, so a lost or rebuilt percolator index is repaired from
      Postgres rather than silently leaving every rule dead

### Technical debt taken into v3

Gathered from [`docs/TECHNICAL-DEBT.md`](docs/TECHNICAL-DEBT.md) on 2026-09-17: the open
entries that belong to v3's subject — how data flows through the backbone, and whether
what flows is right. Everything else stays where it is; the reasoning is below.

- [x] **A watermark per source, not one for all ten (2026-09-17)** (🟡 _Single global
      lookback_). Per-source interval, first window and watermark; the scheduler became a
      plain ticker. `vendor_advisory` fetches 13 records over 48h where 2h found none.
- [x] **Graceful shutdown for ingest (2026-09-17)** (🟡). The consumer finishes and
      commits the batch in hand within a 30s grace period instead of abandoning a record
      mid-write; rows carry `indexed_at` and a reconciler settles whatever drifted every
      5m. Verified live: 131 drifted rows repaired automatically.
- [ ] **Mark backfilled events as historical** (🟢 _A backfill can raise alerts for old
      findings_). A contract change, which makes it v3 work: `SignalDiscovered` gains a
      flag, and alerting skips it, so loading ten years of history stops firing ten years
      of alerts.
- [ ] **Versioned migrations, Postgres and Neo4j** (🟡 _Naive migration runner_ + 🟢
      _Neo4j migrations are implicit_). One piece of work: a schema-version table instead
      of re-running every file and relying on `IF NOT EXISTS`. Both stores have the same
      shortcut, and the doc already tags both for v3.
- [ ] **Elasticsearch alias and reindex strategy** (🟢). Write through an alias, reindex
      into a new concrete index, flip atomically — so a mapping change stops meaning
      delete-and-rebuild with downtime.
- [ ] **Triage malware rather than hiding it** (🟡 _Malware is ingested in full but only
      hidden_). ~220,000 `MAL-` records sit in the store costing index space, and a broad
      subscription rule can match them. The graph can already answer "does a tracked
      repository depend on this package?", which is the ranking that makes them useful
      instead of noise.

### Correctness fixes worth doing alongside

Not v3's subject, but each is small and each is a wrong answer today rather than a missing
feature:

- [ ] **Normalise NuGet (and RubyGems) package names** (🟡). A `.csproj` writing
      `newtonsoft.json` never reaches advisories filed under `Newtonsoft.Json`, so real
      exposure is silently missed.
- [ ] **Read `yarn.lock` and `packages.lock.json`** (🟢). The last two lockfile formats
      unread, so those versions stay ranges and their findings stay "possibly affected"
      instead of being settled outright.
- [ ] **Keep one description and score set per source** (🟡 _last-writer-wins_). Which
      description you read currently depends on which feed reported last.

### Deliberately left for v4 and later

Not gathered into v3, and why: **Dockerfiles, k8s/terraform, CI, restart policies and
resource limits** are deployment (v4). **Authentication, TLS, Kafka SASL, Elasticsearch
security, committed credentials and plaintext secrets** are the security pass (v4) and
should land together rather than piecemeal. **Health endpoints** (v4) and **metrics,
tracing and log aggregation** (v6) belong with their own stacks. **Library-to-library
edges reaching only as far as the watchlist** needs a real module graph (deps.dev or an
SBOM feed) — a data-source project, not a transport one. **Topics declared with the
infrastructure** waits for the same v4 work that containerises the services.

### Performance Testing

- [x] **Load test (2026-09-17):** `task loadtest` (`tests/load`) publishes synthetic
      findings at a target rate and consumes them back, on a throwaway topic it deletes
      afterwards. Measured on the dev laptop: **1,000/s sustained with 6ms mean latency**
      (18ms max), and **~9,200/s unpaced** — roughly 10x the roadmap's target. Those
      numbers are the broker and client; cortex's ingest is bounded by Postgres,
      Elasticsearch and Neo4j, and is measured by pointing it at the signal topic
- [x] **TUI updates instantly via gRPC streaming (2026-09-17):** cortex broadcasts each
      stored finding over `StreamFindings`, nexus relays it as SSE at `/stream`, deck
      subscribes and refreshes on arrival (debounced to 2s). Ingest never blocks on a
      watcher; the poll timer remains as the fallback

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
