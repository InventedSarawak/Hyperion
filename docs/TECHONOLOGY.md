# TECHNOLOGY.md: The SignalFuse Stack

This document outlines the complete polyglot architecture of **SignalFuse Enterprise Edition**. Every technology selected is open-source, self-hostable, and serves a specific, isolated purpose in the event-driven intelligence pipeline.

## 🏗️ Entry & Interfaces

| Technology | Usage in SignalFuse | Target Version |
| :--- | :--- | :--- |
| **Go (Golang)** | The primary language for all backend microservices, workers, and CLIs. Chosen for high concurrency and performance. | **v1** |
| **Rust** | (Optional) Systems programming language reserved for specialized, ultra-low latency components (e.g., eBPF network hooks or isolated exploit execution sandboxes). | **v5** |
| **Bubble Tea** | The Terminal UI (TUI) framework. Provides the "Hacker Console" interface for fast, native interaction over SSH or local terminal. | **v2** |
| **Next.js** | Web dashboard framework. Used strictly for management features like billing, API key generation, and subscription toggles. | **v4** |
| **Nginx / Traefik** | Reverse proxy and load balancer. Handles SSL termination and routes traffic to the Gateway, Keycloak, or Web Dashboard. | **v4** |

## 🧠 Core Application Layer

| Technology | Usage in SignalFuse | Target Version |
| :--- | :--- | :--- |
| **GraphQL** | External-facing API queried by the Next.js dashboard and TUI. Aggregates data from multiple underlying microservices. | **v1** |
| **gRPC / Protobuf** | Internal communication protocol between Go microservices. Ensures strict type safety and minimal serialization latency. | **v2** |
| **Keycloak** | OpenID Connect (OIDC) identity provider. Handles user authentication, login flows, and issues JWTs for the API Gateway. | **v4** |

## 📨 Event & Message Bus

| Technology | Usage in SignalFuse | Target Version |
| :--- | :--- | :--- |
| **Apache Kafka** | High-throughput event stream. Acts as the main ingestion buffer for raw CVEs, GitHub commits, and NVD feeds. | **v3** |
| **RabbitMQ** | Task and job queue. Handles reliable delivery for asynchronous tasks like sending Slack/Email notifications or billing hooks. | **v3** |

## 💾 Polyglot Data & Storage

| Technology | Usage in SignalFuse | Target Version |
| :--- | :--- | :--- |
| **PostgreSQL** | Relational source of truth. Stores structured data: Users, Subscriptions, API Keys, and System Configs. | **v1** |
| **Elasticsearch** | Full-text search engine. Used for fuzzy matching vulnerability descriptions and reverse-searching (Percolator) user alert rules. | **v1** |
| **Neo4j** | Graph database. Maps the software supply chain (Repo -> Library -> CVE) to instantly calculate the dependency "blast radius." | **v2** |
| **Redis** | In-memory cache. Used for API rate-limiting, deduping alert notifications, and storing fast-access session states. | **v3** |
| **MinIO** | S3-compatible Data Lake. Archives the raw Kafka event firehose as Parquet files for long-term historical retention and auditing. | **v4** |
| **Qdrant** | Vector database. Stores semantic embeddings of Exploit-DB scripts and academic papers for the AI retrieval pipeline. | **v5** |

## 🤖 AI & Intelligence

| Technology | Usage in SignalFuse | Target Version |
| :--- | :--- | :--- |
| **Ollama** | Local LLM runner. Hosts privacy-preserving, uncensored models (DeepSeek-Coder / Llama 3) to generate custom CTF exploit scripts. | **v5** |

## ⚙️ Platform & Operations

| Technology | Usage in SignalFuse | Target Version |
| :--- | :--- | :--- |
| **Kubernetes (K8s) & Helm** | Container orchestration and package management. Manages the deployment, scaling, self-healing, and networking of the polyglot microservices. | **v4** |
| **ArgoCD & GitHub Actions** | CI/CD pipelines and GitOps workflow. GitHub Actions handles testing and Docker image builds; ArgoCD automatically syncs repository changes to the Kubernetes cluster. | **v4** |
| **Lago** | Self-hosted metered billing engine. Tracks API usage and alert generation to invoice premium users. | **v4** |
| **Prometheus & Grafana** | Metrics scraping and visualization. Monitors Kafka lag, HTTP request latency, and Go routine health. | **v4** |
| **OpenTelemetry & Jaeger** | Distributed tracing. Follows a single request across the GraphQL gateway, through gRPC services, and into the databases. | **v4** |

---

### 🚀 Implementation Roadmap Summary

* **v1 (The Foundation):** Go, PostgreSQL, Elasticsearch, GraphQL. *(Data scraping and basic search).*
* **v2 (The Structure):** Neo4j, gRPC, Bubble Tea. *(Dependency graphs and terminal interface).*
* **v3 (The Stream):** Kafka, RabbitMQ, Redis. *(Real-time event processing and notifications).*
* **v4 (The Platform):** Next.js, Nginx, Keycloak, MinIO, Lago, Kubernetes (K8s), Helm, ArgoCD, GitHub Actions, Observability. *(SaaS readiness, automated GitOps deployments, billing, and scale).*
* **v5 (The Endgame):** Ollama, Qdrant, Rust (optional). *(AI RAG pipeline, automated exploit generation, and low-latency system hooks).*