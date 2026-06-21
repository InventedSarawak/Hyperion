# Hyperion Project Structure

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
