# Hyperion Project Structure

```hyperion/
hyperion/
github.com/vedant/hyperion/
├── .github/workflows/          # CI/CD
├── apps/
│   ├── hermes-gateway/         # 🧠 Go: API Gateway (GraphQL/gRPC Entry)
│   │   ├── cmd/server/main.go
│   │   ├── internal/auth/      # JWT Validation
│   │   └── internal/graph/     # GraphQL Resolvers
│   ├── artemis-worker/         # 📡 Go: Ingestion (Fetches Data)
│   │   ├── cmd/worker/main.go
│   │   └── internal/adapters/  # NVD/GitHub Clients
│   ├── athena-service/         # 🔍 Go: Intelligence (Search & Graph Logic)
│   │   └── internal/domain/    # DDD Entities (Repo, CVE)
│   ├── prometheus-copilot/     # 🤖 Go: CTF Copilot (AI & Vectors)
│   │   └── internal/llm/       # Ollama Client
│   ├── oceanus-archiver/       # 🗄️ Go: Lake Archiver (Parquet / MinIO)
│   │   └── cmd/archiver/main.go
│   ├── pythia-tui/             # 📟 Go: Terminal UI (Bubble Tea)
│   │   └── cmd/tui/main.go
│   └── olympus-web/            # 🌍 TS: Web Dashboard (Next.js SaaS)
│       ├── src/app/            # App Router (Pages)
│       ├── package.json        # NPM Config
│       └── next.config.js
├── packages/
│   ├── contracts/              # 📜 Protobufs (Shared Truth)
│   │   ├── ingestion/v1/
│   │   ├── intelligence/v1/
│   │   └── buf.yaml
│   ├── common-go/              # 📦 Go: Shared Utils (Kafka, Errors)
│   ├── telemetry-go/           # 📊 Go: OTEL, Logger configurations
│   ├── api-sdk/                # 📦 TS: Generated Axios Client
│   └── ui-kit/                 # 🎨 TS: Shared React Components
├── deploy/                     # ☁️ Infrastructure
│   ├── docker-compose.yml
│   └── k8s/
├── tools/                      # 🛠️ Scripts
├── go.work                     # 🔗 Go Workspace Config
├── turbo.json                  # 🚀 Build Orchestration
├── Taskfile.yml                # ⚡ Go Task Runner
└── package.json                # Root Node Config
```
