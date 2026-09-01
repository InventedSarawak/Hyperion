# Current Progress

A living snapshot of where Hyperion actually stands. Update the **Latest Update** section
before each commit; move superseded entries into the changelog at the bottom.

---

## Latest Update — 2026-08-30

### Overall status

**v1 is functionally complete for NVD.** The full slice runs end to end:
live NVD → siphon → cortex → Postgres + Elasticsearch → gRPC → nexus GraphQL.
Verified with real data: a GraphQL query returns actual ingested CVEs with scores.

### v1 stack (all working)

- **siphon** (ingestion): NVD adapter with **rate limiting to NVD's documented limits**
  (5 req/30s anonymous, 50 req/30s with key → paced 6s / 0.6s), **pagination**
  (startIndex/totalResults, 2000/page cap), **120-day window clamping**, and
  **retry with exponential backoff** on 403/429/5xx.
- **Source registry**: all **10 documented sources** are resolved at startup. Each is
  reported ACTIVE or inactive-with-reason ("adapter not implemented yet",
  "missing credential SIPHON_X", "disabled via configuration"). Only NVD has an
  adapter today; the other nine are wired for config and report cleanly.
  `PollSources` fans out across every active source; one failing source does not
  stop the others.
- **cortex** (intelligence): `SearchIndex` port + **Elasticsearch adapter** (fuzzy
  `multi_match` + `phrase_prefix` + exact-id term boost, so "log4j" finds "Log4j2"),
  a **no-op index fallback** so ingestion still works when ES is down, dual-write on
  ingest (Postgres = source of truth, ES failure is non-fatal), `Search` query use
  case with paging, and an inbound **gRPC server** implementing
  `IntelligenceService.Search` (+ reflection for grpcurl).
- **nexus** (gateway): `IntelligenceClient` port, gRPC client to cortex,
  **GraphQL** schema/handler at `POST /graphql` and a browser console at
  `GET /playground`.
- **Infra**: `deploy/docker-compose.yml` runs Postgres 17 (host **5433**) and
  Elasticsearch 8.15.3 (**9200**, security off — local dev only).
- **Config**: `.env.sample` documents env vars **and their formats** for all ten
  sources plus cortex/nexus, with per-source doc links, rate limits, and where to
  get each credential. `packages/common/env` loads `.env` from the repo root at
  startup (real env vars still win).

### Verified end-to-end (2026-08-30)

- siphon pulled live NVD CVEs and reported source status correctly.
- cortex ingested them into Postgres (65 rows) and Elasticsearch (16 docs indexed).
- `POST /graphql { search(term: "...") { hits { score vulnerability { cveId ... } } } }`
  returned real CVEs with CVSS scores and severities; paging token and the
  empty-term error path both behave.
- `task test:go` green; `task test:go:integration` green against real Postgres + ES.

### What does NOT work / is next

- **9 of 10 sources have no adapter yet** (NVD only). Config, enum, registry and
  status reporting are ready for them.
- Transport between siphon and cortex is still a **pipe**, not Kafka (v3).
- No auth on the GraphQL/gRPC endpoints yet (Keycloak is v4).
- `ghost`, `relic`, `deck`, `credits` remain stubs; `console` is still the starter page.

### Real-data run — 2026-09-01

Executed the full v1 stack against live NVD with a real API key:

- **siphon** pulled **1,906 real CVEs** (24h lookback) in ~47s using the authenticated
  rate limit, and reported 1 of 10 sources ACTIVE with reasons for the other nine.
- **cortex** ingested all 1,906 into Postgres **and** Elasticsearch with zero errors (~37s).
  Both stores agree exactly (1906 = 1906); spot-checked a CVE field-by-field in each.
- **Idempotency verified**: re-ingesting the same 1,906 events left the row count at
  1,906, preserved `first_seen_at`, and bumped `last_seen_at` — the domain `Merge` +
  upsert path is correct on real data.
- **Query path verified** end-to-end (nexus GraphQL → cortex gRPC → Elasticsearch):
  free-text search, exact-CVE lookup (ranks first at relevance 77.8 vs ~16 for text),
  fuzzy match on a typo ("kubernets" still finds Kubernetes CVEs), two-page pagination
  with no overlap, and the empty-term error path.
- **gRPC verified standalone** via grpcurl using server reflection.
- **Resilience verified**: with Elasticsearch stopped, cortex warned, disabled search,
  and kept ingesting to Postgres — then recovered when ES came back.
- Severity spread of the real corpus: 714 high, 638 medium, 263 critical, 178 low, 113 none.

**Bug found and fixed during this run:** the Postgres integration suite ran `TRUNCATE
vulnerabilities` against whatever database `CORTEX_TEST_DATABASE_URL` pointed at — it
destroyed 1,906 real dev rows. It now creates a **throwaway schema per run**
(`hyperion_test_<ts>`, dropped in cleanup), mirroring what the Elasticsearch suite
already did with throwaway indices. Verified: tests pass, real data survives, no
leftover schemas.

### How to run it

```bash
task infra:up                       # Postgres + Elasticsearch
cp .env.sample .env                 # add SIPHON_NVD_API_KEY for the higher rate limit
task ingest                         # siphon | cortex  (fetch + store + index)
task run:cortex                     # gRPC intelligence API on :50051
task run:nexus                      # GraphQL on :8080  → open /playground
```

---

## Changelog

- **2026-09-01** — Full-stack run on real data (1,906 live NVD CVEs) through ingest → store →
  index → gRPC → GraphQL; fixed a destructive Postgres integration test (now uses a
  throwaway schema).
- **2026-08-30** — v1 complete for NVD: NVD rate limiting/pagination/backoff, 10-source
  registry with active/inactive reporting, cortex Elasticsearch + gRPC search API,
  nexus GraphQL gateway + playground, `.env.sample` for all sources, `.env` loading.
- **2026-08-24** — Built `cortex` storage side: consumer + Postgres repo + migration; docker-compose
  Postgres (5433); `siphon | cortex` → Postgres verified with live NVD data.
- **2026-08-24** — Built `siphon` end-to-end as the first hexagonal slice (domain/ports/
  application/adapters/platform); runs vs live NVD, publishes protojson `SignalDiscovered`.
- **2026-08-22** — Contracts foundation: buf + `task codegen`, first 3 protos
  (common/events/intelligence v1), generated Go committed under `packages/contracts/gen`.
- **2026-08-22** — Clean-slate housekeeping: removed `api/`, fixed `task build:go`, dropped
  `.excalidraw` diagrams (Mermaid canonical). Repo now green on build + test.
- **2026-08-22** — Initial progress snapshot; doc/diagram/TODO reconciliation; first-slice plan set.
