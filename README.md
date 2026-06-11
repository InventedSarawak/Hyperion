# Hyperion: The CVE Intelligence Platform

Hyperion is a simple, lightweight, and efficient TUI based CVE monitoring and analysis tool built with Go. It consists of two main applications: Artemis service that fetches CVE data from the NVD API and Athena Service that processes, indexes, and serves this data for querying. The project is structured as a monorepo, with shared domain contracts to ensure consistency across applications.

---

## project structure

```hyperion/
hyperion/
github.com/vedant/hyperion/
└── apps/
    ├── hermes-gateway/         # Go: API Gateway (GraphQL/gRPC Entry)
    ├── artemis-worker/         # Go: Ingestion (Fetches Data)
    ├── athena-service/         # Go: Intelligence (Search & Graph Logic)
    ├── prometheus-copilot/     # Go: CTF Copilot (AI & Vectors)
    ├── oceanus-archiver/       # Go: Lake Archiver (Parquet / MinIO)
    ├── pythia-tui/             # Go: Terminal UI (Bubble Tea)
    └── olympus-web/            # TS: Web Dashboard (Next.js SaaS)
```

## Progress

- [ ] v1: The Foundation (MVP)
- [ ] v2: The Structure (Graph & TUI)
- [ ] v3: The Nervous System (Streaming)
- [ ] v4: The Platform (SaaS)
- [ ] v5: The Endgame (AI Copilot)
- [ ] v6: Day-Two Operations (Observability & Reliability)
