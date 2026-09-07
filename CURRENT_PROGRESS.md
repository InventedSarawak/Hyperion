# Current Progress

A living snapshot of where Hyperion actually stands. Update the **Latest Update** section
before each commit; move superseded entries into the changelog at the bottom.

---

## Latest Update — 2026-09-02

### Overall status

**All 10 ingestion sources implemented and verified against live APIs.** v1 remains
complete; ingestion went from 1 source to 10, config moved to a centralized namespaced
system, and cross-source correlation now works end to end.

### All 10 source adapters (live-verified)

| #   | Source                        | Credential                       | Live yield (168h window)         |
| --- | ----------------------------- | -------------------------------- | -------------------------------- |
| 1   | NVD                           | optional key (have it)           | 300                              |
| 2   | GitHub Advisory               | optional token — **recommended** | quota-exhausted unauth           |
| 3   | CISA KEV                      | none                             | 5                                |
| 4   | Exploit-DB                    | none                             | 14                               |
| 5   | MITRE CVE List                | none                             | 11                               |
| 6   | Vendor (Red Hat)              | none                             | 200                              |
| 7   | OSINT (Full Disclosure)       | none                             | 16                               |
| 8   | Package feeds (OSV watchlist) | none                             | 0 (watchlist advisories are old) |
| 9   | Shodan **CVEDB**              | none — CVEDB is FREE             | 200                              |
| 10  | GSD / OSV                     | none                             | 2                                |

Only **GitHub** is worth obtaining a credential for; every other source works without one.
`api.shodan.io` (paid) is deliberately NOT used — the free CVEDB service provides the
EPSS/KEV enrichment instead.

### Centralized configuration

`packages/common/config` — one namespaced loader for all services: logical `SERVICE.VAR`
maps to env `SERVICE_VAR`, with typed getters (String/Secret/Int/Bool/Duration/List),
automatic `.env` discovery, and `Describe()` returning every resolved setting with
credentials masked. siphon/cortex/nexus all read through it; the old `packages/common/env`
is gone. `.env.sample` shrank 219 -> 92 lines, and is verified to match exactly the keys
the code reads (no undocumented or stale vars).

**Naming uses underscores, not a literal dot.** A dotted form (`SIPHON.NVD_API_KEY`) was
tried and reverted: Go and godotenv handle dots fine, but no POSIX shell can export one
(`export SIPHON.X=1` -> "not a valid identifier"), which makes one-off overrides
impossible. `.env` is now **read into a map rather than injected** into the process
environment, so precedence is explicit and correct: a real environment variable always
beats a `.env` entry.

### Bugs found and fixed by running against real APIs

- **Red Hat returns CVSS scores as JSON _strings_** ("7.8"); a `float64` DTO failed to
  decode. Added `sourcehttp.FlexFloat` (number | quoted-number | null) — now 200 records.
- **Shodan CVEDB sends `cvss_version` as a float** (4.0) and nulls most optional metrics;
  the int DTO failed. Same fix, plus CVSS v4 support.
- **Shodan `sort_by_epss` returns years-old CVEs**, so every record was filtered out by the
  recency window. Switched to server-side `start_date`/`end_date` — now 200 records.
- **Six sources had no protobuf enum value**, so their provenance silently decoded as
  UNSPECIFIED and was lost on the wire. Extended `events.v1.SourceKind` to all 10 and added
  a regression test asserting every domain kind maps to a distinct, non-zero enum value.
- **Exhausted rate-limit budgets were retried** with backoff, and each retry also waited the
  limiter — one throttled source stalled the whole poll for minutes. `sourcehttp` now
  detects `X-RateLimit-Remaining: 0` and fails fast with an actionable message.
- **NVD bulk pages exceeded the 60s HTTP timeout**; raised to 180s.

### Verified end-to-end (2026-09-02)

- One poll across all sources produced **748 events from 8 sources** with correct attribution.
- cortex ingested them: **2,671 rows in Postgres, 2,671 docs in Elasticsearch**.
- Provenance by source in Postgres: nvd 2277, vendor_advisory 200, shodan 200, exploit_db 14,
  osint 12, mitre 11, cisa_kev 5, gsd 2.
- **Cross-source correlation confirmed**: CVEs carry merged provenance such as
  `["nvd","cisa_kev"]`, `["nvd","vendor_advisory"]`, `["nvd","osint"]` — the domain `Merge`
  rule unioning sources for the same CVE.
- GraphQL over the real data: free-text search, exact CVE lookup, and paging all correct.
- `task test:go`: **32 packages green**.

### What does NOT work / is not built

Full register with reasons and fix-by version: **[docs/TECHNICAL-DEBT.md](docs/TECHNICAL-DEBT.md)**.
Headline gaps:

**Infrastructure — nothing is deployable yet**

- No `Dockerfile` for any Go service. `cortex`/`nexus` run as **native host processes**
  started with `setsid` by `scripts/system.sh`, so `docker ps` shows only Postgres and
  Elasticsearch. This contradicts AGENTS.md Rule 7 (now annotated there).
- `deploy/k8s/` and `deploy/terraform/` exist but are **empty directories** — no manifests,
  no Helm charts, no `.tf` files at all, despite being referenced in PROJECT-STRUCTURE.
- **No CI**: `.github/workflows/` is empty. The husky pre-commit hook is the only gate —
  local-only and bypassable with `--no-verify`.
- Compose has no `restart:` policy and no resource limits.
- Services die on desktop logout (parent is `systemd --user`) while containers survive,
  so you can end up with infra up and app services gone.

**Data flow**

- Transport is a **Unix pipe** (`siphon | cortex`), not Kafka — no durability, replay or
  backpressure (v3). Sources are polled sequentially, so a slow source delays later ones.
- The ingestion watermark is **in-memory only**: restarting siphon refetches the entire
  lookback window, and a crash longer than that window **loses signals** (v3).
- No dedupe or checkpoint stores — deduplication is implicit in the cortex upsert (v3).
- One global `SIPHON_LOOKBACK` for sources with very different cadences: at the 2h default,
  `exploit_db` / `osint` / `package_feed` return 0 essentially always. Verified against
  upstream — the data genuinely is not there, but per-source lookback is the real fix.
- Migration runner has no version table; idempotency rests on `IF NOT EXISTS`.
- Package feeds yield little until `SIPHON_PACKAGE_WATCHLIST` names packages you care about.

**Security — all v4, none of it started**

- **No authentication or authorization** on GraphQL or gRPC. Anyone who can reach the port
  can query everything.
- gRPC is **plaintext** (`insecure.NewCredentials()`).
- Elasticsearch security is disabled and default Postgres credentials are committed.
  `deploy/docker-compose.yml` is **local-dev only — never deploy it**.

**Operability**

- No health endpoint on `cortex` or `siphon` (only `nexus` has `/healthz`). The start script
  probes cortex by TCP connect, proving the port is bound, not that the service is healthy.
- No metrics, tracing or log aggregation; `packages/telemetry` is an empty module (v6).
- Ingest has no graceful shutdown — an abrupt stop can leave Postgres ahead of Elasticsearch.

**Still stubs:** `ghost` (v5), `relic` (v4), `credits` (v4), `deck` (v2); `console` is the
Turborepo starter page (v4). **Neo4j blast radius — the actual differentiator — is v2 and
not started.**

---

## Changelog

- **2026-09-02** — All 10 ingestion source adapters + centralized namespaced config
  (`packages/common/config`); `.env.sample` simplified 219->92 lines; extended
  `events.v1.SourceKind` to all 10 sources; fixed real-API decode bugs (Red Hat string
  scores, CVEDB float version), Shodan date-filtering, and rate-limit fail-fast.
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
