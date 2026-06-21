# Hyperion: The CVE Intelligence Platform

Hyperion is a simple, lightweight, and efficient TUI based CVE monitoring and analysis tool built with Go. It consists of two main applications: Siphon service that fetches CVE data from the NVD API and Cortex Service that processes, indexes, and serves this data for querying. The project is structured as a monorepo, with shared domain contracts to ensure consistency across applications.

---

## project structure

```hyperion/
hyperion/
github.com/vedant/hyperion/
└── apps/
    ├── nexus/                  # Go: API Gateway (GraphQL/gRPC Entry)
    ├── siphon/                 # Go: Ingestion (Fetches Data)
    ├── cortex/                 # Go: Intelligence (Search & Graph Logic)
    ├── ghost/                  # Go: CTF Copilot (AI & Vectors)
    ├── relic/                  # Go: Lake Archiver (Parquet / MinIO)
    ├── deck/                   # Go: Terminal UI (Bubble Tea)
    ├── credits/                # Go: Billing & Credits (Lago)
    └── console/                # TS: Web Dashboard (Next.js SaaS)
```

## Progress

- [ ] v1: The Foundation (MVP)
- [ ] v2: The Structure (Graph & TUI)
- [ ] v3: The Nervous System (Streaming)
- [ ] v4: The Platform (SaaS)
- [ ] v5: The Endgame (AI Copilot)
- [ ] v6: Day-Two Operations (Observability & Reliability)
