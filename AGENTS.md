# AGENTS.md

## 1. Project Identity & Core Mission
**System Name:** Hyperion  
**Domain:** Enterprise-Grade, Event-Driven Cybersecurity & Threat Intelligence Platform.  
**Elevator Pitch:** Hyperion cuts through "Alert Fatigue" by mapping the software supply chain to determine vulnerability blast radiuses, analyzing pre-CVE heuristic chatter, and utilizing a local AI RAG pipeline to generate custom proof-of-concept exploit scripts. It processes millions of signals via an event-driven, polyglot architecture.

---

## 2. High-Level Architecture & Repository Structure
Hyperion is a Hybrid Monorepo orchestrated via **TurboRepo** and **Taskfile**, utilizing Go Workspaces (`go.work`). It strictly enforces **Domain-Driven Design (DDD)** and **Hexagonal Architecture** (Ports & Adapters).

### 2.1 Microservices (`/apps`)
* **`api-gateway` (Go):** The edge. Exposes GraphQL (reads) and REST (webhooks), routes gRPC traffic internally.
* **`ingestion-worker` (Go):** The scavenger. Polls NVD, GitHub, arXiv, Exploit-DB, and publishes `SignalEvents` to Kafka.
* **`intelligence-service` (Go):** The brain. Consumes Kafka streams, constructs dependency graphs (Neo4j), and builds full-text indexes (Elasticsearch).
* **`ctf-copilot` (Go):** The AI sidecar. Connects to the Vector DB and Local LLM for exploit generation.
* **`tui-dashboard` (Go):** Terminal UI built with Bubble Tea for CLI-native power users and hackers.
* **`web-dashboard` (TypeScript):** Next.js 14 SaaS dashboard for security managers and reporting.

### 2.2 Shared Packages (`/packages`)
* **`contracts`:** Protobuf definitions. **The absolute single source of truth** for all service-to-service communication.
* **`api-sdk`:** Auto-generated TypeScript Axios client derived from OpenAPI specs (generated via Protobuf).

---

## 3. Technology Stack & Polyglot Persistence

### 3.1 Backend & Transport
* **Language:** Go (Golang) for high-performance services; TypeScript for the web frontend.
* **Transport:** gRPC (internal service-to-service), GraphQL (external read operations), REST (webhooks/ingestion).
* **Message Brokers:** Apache Kafka (high-throughput firehose ingestion) & RabbitMQ (task queuing, notifications, alerts).

### 3.2 The Polyglot Data Layer
* **PostgreSQL:** Relational truth (Users, Tenants, Subscriptions, Billing).
* **Redis:** Ephemeral storage (High-speed cache, rate limiting, deduplication).
* **Elasticsearch:** Text search & Percolator (Reverse-search against user-defined alert rules).
* **Neo4j:** Graph DB. Crucial for mapping dependency trees and calculating vulnerability "blast radiuses" (Repo -> Library -> CVE).
* **Qdrant:** Vector DB. Stores semantic embeddings of CVE data and Exploit-DB scripts for the RAG pipeline.
* **MinIO:** S3-compatible Data Lake. Stores raw JSON/Parquet firehose data for infinite, cold retention.

### 3.3 AI & Offense (Local RAG)
* **Ollama:** Hosts local LLMs (DeepSeek-Coder / Llama 3) to ensure absolute data privacy and unfiltered exploit script generation.
* **LangChain (Go):** Orchestrates the pipeline: `Prompt -> Qdrant Context Retrieval -> Ollama Generation -> TUI Stream`.

---

## 4. DevOps, Orchestration & Environments
Hyperion leverages containerization and container orchestration to manage its complex web of microservices, ensuring absolute parity across all environments and enabling horizontal scaling based on event load.

### 4.1 Containerization (Docker)
* **Immutable Artifacts:** Every microservice and frontend application is containerized using optimized, multi-stage `Dockerfiles`.
* **Standardization:** Docker ensures that the Go runtime, dependencies, and environment variables behave identically on a developer's laptop, in the CI pipeline, and in production.

### 4.2 Orchestration & Scaling (Kubernetes)
* **Management:** Kubernetes (K8s) is the backbone of Hyperion's deployments, handling service discovery, load balancing, and self-healing for all microservices.
* **Auto-Scaling:** K8s Horizontal Pod Autoscalers (HPA) scale the `ingestion-worker` and `intelligence-service` dynamically based on CPU utilization or custom metrics (e.g., Kafka consumer group lag).
* **Stateful Workloads:** StatefulSets and Persistent Volumes (PVs) manage the underlying polyglot persistence layer (Postgres, Neo4j, Qdrant) within the cluster.

### 4.3 Environment Progression
* **Local / Dev:** Developers use `docker-compose` via `Taskfile` commands to spin up a lightweight, fully functional version of the infrastructure locally. Alternatively, `minikube` or `k3d` is used to test Kubernetes manifests and Helm charts directly.
* **Testing / CI:** Automated CI/CD pipelines build Docker images and deploy ephemeral K8s namespaces to run comprehensive integration and end-to-end (E2E) tests.
* **Production:** A multi-node Kubernetes cluster managed via GitOps (ArgoCD). Infrastructure as Code (IaC) ensures that the production state matches the Git repository exactly.

---

## 5. Core Workflows

1.  **The Intelligence Flow:**
    * `NVD/Source` -> `ingestion-worker` -> `Protobuf SignalEvent` -> `Kafka`.
    * `intelligence-service` consumes Kafka -> Travers Neo4j for affected repos -> Checks Elasticsearch Percolator for subscriber rules -> Queues alert in `RabbitMQ`.
2.  **The AI Exploit Flow (CTF Copilot):**
    * User query via `tui-dashboard` ("Exploit Apache Struts").
    * `ctf-copilot` vectorizes query -> Searches `Qdrant` for Python scripts from Exploit-DB.
    * Context injected into prompt -> `Ollama` generates PoC -> Streams back to terminal.
3.  **The Type-Safety Flow (Codegen):**
    * Update `.proto` in `packages/contracts`.
    * Run `task codegen` (uses `buf`).
    * Generates Go structs, gRPC stubs, and OpenAPI spec.
    * `openapi-generator` compiles the OpenAPI spec into a fully typed TypeScript SDK for Next.js.

---

## 6. Development Rules & Engineering Directives

* **Rule 1: Protobuf is Law.** Never manually write an API type definition in Go or TypeScript. All domain entities and service contracts must originate in `packages/contracts/*.proto`. Run `task codegen` to propagate changes.
* **Rule 2: Respect the Hexagon.** Business logic must remain isolated from transport and storage layers. Always define interfaces (Ports) in the domain layer and implement them (Adapters) in the infrastructure layer.
* **Rule 3: Asynchronous by Default.** If an operation does not require an immediate synchronous response to the user, publish it to Kafka or RabbitMQ. Do not block HTTP/gRPC threads.
* **Rule 4: Polyglot Discipline.** Do not force relational data into Neo4j, and do not try to do graph traversals in Postgres. Route data to its designated persistence layer based on its query pattern.
* **Rule 5: AI Must Remain Local.** Do not route sensitive internal architecture, vulnerability data, or explicit exploit requests to public OpenAI/Anthropic APIs. Always default to the local Ollama instance for the CTF Copilot.
* **Rule 6: Delegate the UI.** Do not build custom authentication screens or billing dashboards. Rely strictly on Keycloak for identity flows and Lago/Stripe for checkout and metering. Focus engineering cycles on the core threat engine.
* **Rule 7: Containerize Everything.** Code is not "done" until it runs seamlessly inside a Docker container and can be orchestrated via standard K8s manifests or Helm charts.