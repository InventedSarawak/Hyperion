# Hyperion: The Ultimate CVE Intelligence Platform

## TODO v1: The Foundation (MVP)

### Project Setup (Monorepo)

- [ ] Initialize Git repository
- [ ] Initialize Go Workspace (`go work init`)
- [ ] Setup `Taskfile.yml` for automation (build, run, test)
- [ ] Setup `turbo.json` for build caching
- [ ] Create directory structure (`apps/`, `packages/`, `deploy/`)
- [ ] Configure `deploy/docker-compose.yml` (Postgres, Elasticsearch)

### Domain Contracts (The "Law")

- [ ] Create `packages/contracts`
- [ ] Define `ingestion/v1/signal.proto` (The data structure)
- [ ] Define `intelligence/v1/search.proto` (The API structure)
- [ ] Setup `buf.yaml` and generate Go structs

### App: Ingestion Worker (`apps/ingestion-worker`)

- [ ] **Infrastructure:** Implement NVD API Client (HTTP adapter)
- [ ] **Domain:** Define `Vulnerability` entity
- [ ] **Application:** Create Cron Job (ticker) to fetch CVEs every 10m
- [ ] **Infrastructure:** Implement `PostgresRepository` to save raw metadata

### App: Intelligence Service (`apps/intelligence-service`)

- [ ] **Infrastructure:** Implement Elasticsearch Client
- [ ] **Application:** Create `Indexer` service (Postgres -> Elastic sync)
- [ ] **Application:** Implement `Search` use-case (Full-text query)
- [ ] **Infrastructure:** Expose gRPC/GraphQL Server

### Verification

- [ ] Write Unit Tests with `Ginkgo` for the NVD parser
- [ ] Manual Test: Run `task dev` and query GraphQL Playground for "log4j"

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

### App: TUI Dashboard (`apps/tui-dashboard`)

- [ ] Initialize Bubble Tea project
- [ ] **Infrastructure:** Create gRPC Client adapter
- [ ] **UI:** Build `Model` (State) and `View` (Layout)
- [ ] **Feature:** "Live Feed" list (polling API for now)
- [ ] **Feature:** "Graph Explorer" (ASCII tree view of dependencies)

### App: Ingestion Worker (Upgrade)

- [ ] Add `GithubClient` adapter (Fetch `go.mod` / `package.json`)
- [ ] Parse dependencies and send to Intelligence Service

---

## TODO v3: The Nervous System (Streaming)

### Infrastructure Upgrade

- [ ] Add **Apache Kafka** & Zookeeper to `docker-compose.yml`
- [ ] Add **Redis** (for caching/deduplication)
- [ ] Create `packages/common-go/kafka` (Producer/Consumer wrappers)

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
- [ ] **New App:** `apps/lake-archiver`
  - [ ] Consume `raw-signals` topic
  - [ ] Buffer events and write `Parquet` files to MinIO
- [ ] **Analytics:** Integrate **DuckDB** to query Parquet files

### Monetization (Lago)

- [ ] Deploy **Lago** (Self-hosted billing) via Docker
- [ ] **App: API Gateway:**
  - [ ] Implement `RateLimitMiddleware` using Redis
  - [ ] Add `BillingHook` to report usage to Lago
- [ ] **Web Dashboard:** Create `apps/web-dashboard` (Next.js)
  - [ ] User Login (Keycloak)
  - [ ] Subscription Management UI

### DevOps (GitOps)

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

### App: CTF Copilot (`apps/ctf-copilot`)

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

- [ ] **Packages:** Create `packages/telemetry-go` for shared OTel setup
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
