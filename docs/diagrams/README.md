# System Diagrams

**`system-diagram.mermaid` is the canonical, up-to-date system diagram** and the single source
of truth. It is the most complete view (includes the observability/GitOps layer and DuckDB) and
uses service codenames. Render it with any Mermaid viewer (GitHub renders it inline).

> Earlier hand-drawn `.excalidraw` exports were removed in favor of the Mermaid source. If a
> polished visual is ever needed for the README/demo, generate it from this Mermaid.

## Service codenames (see `docs/PROJECT-STRUCTURE.md` for the full legend)

| Codename | Role                          |
| :------- | :---------------------------- |
| nexus    | API Gateway (GraphQL/gRPC)    |
| siphon   | Ingestion Worker              |
| cortex   | Intelligence (search/graph)   |
| ghost    | CTF Copilot (AI/RAG)          |
| relic    | Lake Archiver (Parquet/MinIO) |
| deck     | Terminal UI (Bubble Tea)      |
| credits  | Billing/Subscriptions (Lago)  |
| console  | Web Dashboard (Next.js)       |
