# Hyperion Project Structure

## Project Root

```hyperion/
hyperion/
github.com/vedant/hyperion/
├── .github/workflows/          # CI/CD
├── docs/                       # Project Documentation
├── apps/
│   ├── nexus/                  # 🧠 Go: API Gateway (GraphQL/gRPC Entry)
│   │   ├── cmd/server/main.go
│   │   ├── internal/auth/      # JWT Validation
│   │   └── internal/graph/     # GraphQL Resolvers
│   ├── siphon/                 # 📡 Go: Ingestion (Fetches Data)
│   │   ├── cmd/worker/main.go
│   │   └── internal/adapters/  # NVD/GitHub Clients
│   ├── cortex/                 # 🔍 Go: Intelligence (Search & Graph Logic)
│   │   └── internal/domain/    # DDD Entities (Repo, CVE)
│   ├── ghost/                  # 🤖 Go: CTF Copilot (AI & Vectors)
│   │   └── internal/llm/       # Ollama Client
│   ├── relic/                  # 🗄️ Go: Lake Archiver (Parquet / MinIO)
│   │   └── cmd/archiver/main.go
│   ├── deck/                   # 📟 Go: Terminal UI (Bubble Tea)
│   │   └── cmd/tui/main.go
│   ├── credits/                # 💳️ Go: Credits & Subscription (Lago)
│   │   └── cmd/internal/main.go
│   └── console/                # 🌍 TS: Web Dashboard (Next.js SaaS)
│       ├── src/app/            # App Router (Pages)
│       ├── package.json        # NPM Config
│       └── next.config.js
├── packages/
│   ├── contracts/              # 📜 Protobufs (Shared Truth)
│   │   ├── ingestion/v1/
│   │   ├── intelligence/v1/
│   │   └── buf.yaml
│   ├── common/                 # 📦 Go: Shared Utils (Kafka, Errors)
│   ├── telemetry/              # 📊 Go: OTEL, Logger configurations
│   ├── sdk/                    # 📦 TS: Generated Axios Client
│   └── ui/                     # 🎨 TS: Shared React Components
├── deploy/                     # ☁️ Infrastructure
│   ├── docker-compose.yml
│   └── k8s/
├── scripts/                      # 🛠️ Scripts
├── go.work                     # 🔗 Go Workspace Config
├── turbo.json                  # 🚀 Build Orchestration
├── Taskfile.yml                # ⚡ Go Task Runner
└── package.json                # Root Node Config
```

## Microservice Template

```
apps/<service>/
├── cmd/
│   └── <binary>/main.go
├── internal/
│   ├── domain/
│   │   ├── model/
│   │   ├── valueobject/
│   │   ├── ports/
│   │   ├── events/
│   │   └── services/
│   ├── application/
│   │   ├── commands/
│   │   ├── queries/
│   │   └── workflows/
│   ├── adapters/
│   │   ├── inbound/
│   │   └── outbound/
│   └── platform/
│       ├── config/
│       ├── telemetry/
│       └── bootstrap/
├── migrations/
├── Dockerfile
└── go.mod
```

---

## Particular Microservice Setup (Potential)

### Nexus

```
apps/nexus/
├── cmd/server/main.go
└── internal/
    ├── domain/
    │   ├── model/view_models.go
    │   ├── ports/
    │   │   ├── intelligence_client.go
    │   │   ├── credits_client.go
    │   │   └── auth_verifier.go
    │   └── services/access_policy.go
    ├── application/
    │   ├── queries/search_vulnerabilities.go
    │   ├── queries/get_blast_radius.go
    │   └── commands/submit_webhook.go
    └── adapters/
        ├── inbound/graphql/
        ├── inbound/rest/
        └── outbound/grpc/
```

### Siphon

```
apps/siphon/
└── internal/
    ├── domain/
    │   ├── model/source_signal.go
    │   ├── model/ingestion_run.go
    │   ├── valueobject/source_kind.go
    │   ├── events/signal_discovered.go
    │   └── ports/
    │       ├── source_client.go
    │       ├── signal_publisher.go
    │       ├── dedupe_store.go
    │       └── checkpoint_store.go
    ├── application/
    │   ├── workflows/poll_source.go
    │   └── workflows/normalize_signal.go
    └── adapters/
        ├── inbound/scheduler/
        ├── outbound/sources/nvd/
        ├── outbound/sources/github_advisory/
        ├── outbound/sources/cisa_kev/
        ├── outbound/sources/exploitdb/
        ├── outbound/kafka/
        └── outbound/redis/
```

### Cortex

```
apps/cortex/
└── internal/
    ├── domain/
    │   ├── model/vulnerability.go
    │   ├── model/package.go
    │   ├── model/repository.go
    │   ├── model/advisory.go
    │   ├── model/alert_rule.go
    │   ├── valueobject/cve_id.go
    │   ├── valueobject/package_ref.go
    │   ├── services/blast_radius_calculator.go
    │   └── ports/
    │       ├── vulnerability_repo.go
    │       ├── search_index.go
    │       ├── dependency_graph.go
    │       ├── alert_rule_matcher.go
    │       └── event_publisher.go
    ├── application/
    │   ├── commands/ingest_signal.go
    │   ├── commands/upsert_dependency_graph.go
    │   ├── queries/search.go
    │   └── queries/calculate_blast_radius.go
    └── adapters/
        ├── inbound/kafka/
        ├── inbound/grpc/
        ├── outbound/postgres/
        ├── outbound/elasticsearch/
        ├── outbound/neo4j/
        ├── outbound/rabbitmq/
        └── outbound/kafka/
```

### Ghost

```
apps/ghost/
└── internal/
    ├── domain/
    │   ├── model/copilot_session.go
    │   ├── model/retrieved_artifact.go
    │   ├── model/prompt_context.go
    │   ├── valueobject/model_name.go
    │   └── ports/
    │       ├── vector_store.go
    │       ├── embedding_model.go
    │       ├── llm.go
    │       ├── artifact_repo.go
    │       └── stream_sink.go
    ├── application/
    │   ├── commands/generate_poc.go
    │   ├── commands/index_artifact.go
    │   └── queries/retrieve_context.go
    └── adapters/
        ├── inbound/grpc/
        ├── outbound/qdrant/
        ├── outbound/ollama/
        ├── outbound/minio/
        └── outbound/kafka/
```

### Relic

```
apps/relic/
└── internal/
    ├── domain/
    │   ├── model/archive_batch.go
    │   ├── model/raw_event.go
    │   ├── valueobject/object_key.go
    │   └── ports/
    │       ├── event_reader.go
    │       ├── object_store.go
    │       └── parquet_writer.go
    ├── application/
    │   ├── workflows/archive_topic_batch.go
    │   └── commands/compact_partition.go
    └── adapters/
        ├── inbound/kafka/
        ├── outbound/minio/
        └── outbound/parquet/
```

### Credits

```
apps/credits/
└── internal/
    ├── domain/
    │   ├── model/account.go
    │   ├── model/subscription.go
    │   ├── model/usage_event.go
    │   ├── valueobject/plan.go
    │   ├── services/entitlement_checker.go
    │   └── ports/
    │       ├── account_repo.go
    │       ├── usage_repo.go
    │       ├── billing_provider.go
    │       └── event_publisher.go
    ├── application/
    │   ├── commands/record_usage.go
    │   ├── commands/sync_subscription.go
    │   └── queries/check_entitlement.go
    └── adapters/
        ├── inbound/grpc/
        ├── inbound/webhooks/
        ├── outbound/postgres/
        ├── outbound/lago/
        ├── outbound/stripe/
        └── outbound/rabbitmq/
```

---

## Frontend Setups (Potential)

### Deck

```
apps/deck/
└── internal/
    ├── domain/
    │   ├── model/view_state.go
    │   └── ports/
    │       ├── intelligence_api.go
    │       └── copilot_api.go
    ├── application/
    │   ├── commands/run_search.go
    │   ├── commands/start_copilot_session.go
    │   └── queries/load_dashboard.go
    └── adapters/
        ├── inbound/tui/
        └── outbound/grpc/
```

### Console

```
apps/console/
├── app/
├── features/
│   ├── vulnerabilities/
│   ├── blast-radius/
│   ├── alerts/
│   ├── billing/
│   └── settings/
├── lib/
│   ├── api/
│   ├── auth/
│   └── formatting/
└── components/
```

---

## Contracts

```
packages/contracts/proto/
├── hyperion/events/v1/
│   ├── signal_events.proto
│   ├── intelligence_events.proto
│   └── billing_events.proto
├── hyperion/ingestion/v1/
│   └── ingestion_service.proto
├── hyperion/intelligence/v1/
│   └── intelligence_service.proto
├── hyperion/copilot/v1/
│   └── copilot_service.proto
├── hyperion/billing/v1/
│   └── credits_service.proto
└── hyperion/common/v1/
    ├── vulnerability.proto
    ├── package.proto
    └── tenant.proto
```