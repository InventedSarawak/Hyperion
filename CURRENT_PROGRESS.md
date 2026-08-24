# Current Progress

A living snapshot of where Hyperion actually stands. Update the **Latest Update** section
before each commit; move superseded entries into the changelog at the bottom.

---

## Latest Update — 2026-08-24

### Overall status

**Pre-v1, ingest → store pipeline works.** `siphon | cortex` runs end-to-end: live NVD →
protojson `SignalDiscovered` → cortex → **Postgres**. Data is durably saved. `nexus` (query
side) and Elasticsearch search are the remaining pieces to make it queryable.

### cortex — storage-owning consumer (NEW — done)

- Ports-and-adapters under `apps/cortex/internal/`:
  - domain: own `Vulnerability`/`CVSS`/`Severity` + `Merge` reconciliation rule (source union).
  - port (outbound): `VulnerabilityRepo` (Upsert/GetByCVE/Count).
  - application: `IngestSignal` (validate → load existing → `Merge` → upsert), fake-repo tested.
  - adapters: `inbound/consumer` (protojson `SignalDiscovered` → cortex domain; cortex's proto
    boundary), `outbound/postgres` (pgx repo, JSONB columns, embedded migration).
  - platform/config + `cmd/server/main.go` — connects Postgres, migrates, ingests from stdin.
- Infra: `deploy/docker-compose.yml` now runs **Postgres 17** on host port **5433** (5432 was
  taken locally). `task infra:up` / `task infra:down`.
- Verified: unit suites green; Postgres integration suite passes vs the real container (opt-in via
  `CORTEX_TEST_DATABASE_URL`, else skipped so `task test:go` stays green); ran
  `siphon | cortex` and confirmed 48 live CVEs landed in the `vulnerabilities` table.
- Transport is still a **pipe** (siphon stdout → cortex stdin), not Kafka (v3).

### siphon — first vertical-slice service (done, publishes to stdout)

- Full ports-and-adapters layout under `apps/siphon/internal/`:
  - domain: `SourceSignal`/`CVSS`/`Severity` (model), `SourceKind` (VO), `SignalDiscovered` (event
    with deterministic dedupe identity). Zero non-stdlib imports.
  - ports (outbound): `SourceClient`, `SignalPublisher`.
  - application: `PollSource` use case (fetch → validate → publish), unit-tested with fakes.
  - adapters: `outbound/sources/nvd` (NVD API 2.0 HTTP → domain, httptest-tested),
    `outbound/publisher` (domain → `events.v1.SignalDiscovered` proto → stdout; the ONLY place
    importing `gen/`), `inbound/scheduler` (ticker driving PollSource).
  - platform/config + `cmd/worker/main.go` composition root — siphon's first real `func main`.
- Verified: `go build/vet/test` green (nvd/publisher/scheduler/workflow suites); ran vs live NVD
  and emitted a real recent CVE as protojson.
- Monorepo note: `apps/siphon/go.mod` uses a `replace` → `../../packages/contracts` so `go mod tidy`
  resolves the local contracts module (cortex/nexus will need the same when they import contracts).
- Still stdout, not Kafka (roadmap v3); no dedupe/checkpoint stores yet.

### Contracts (done)

- `buf` installed (v1.72.0). `packages/contracts` has `buf.yaml` + `buf.gen.yaml` (managed mode,
  local `protoc-gen-go`/`protoc-gen-go-grpc` plugins). `task codegen` = `buf lint && buf generate && go mod tidy`.
- First 3 protos authored under `proto/hyperion/{common,events,intelligence}/v1`:
  `Vulnerability`/`Cvss`/`Severity`, `SignalDiscovered`/`SourceKind`, `IntelligenceService.Search`.
- Generated Go lands in `packages/contracts/gen/…`; import path
  `github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/…`.
- Verified: `buf lint` clean, contracts module builds, `apps/siphon` resolves the generated types
  via `go.work`, `task build:go` + `task test:go` green.
- Generated `gen/` is committed (so consumers build without needing buf).

### What actually works

- Monorepo wiring: `pnpm` + TurboRepo + Go workspace (`go.work`), app/package folders.
- 7 Go service modules (`nexus`, `siphon`, `cortex`, `ghost`, `relic`, `deck`, `credits`),
  each with a Ginkgo smoke-test harness. `task test:go` passes.
- `console` (Next.js) builds, lints, typechecks — but is still the Turborepo starter page.
- Shared packages present: `common`, `telemetry`, `contracts` (Go, go.mod only), `ui`,
  `sdk` (empty), `eslint-config`, `typescript-config`.
- ✅ `task build:go` now **compile-checks all 7 services** cleanly (`go build ./...` per module;
  no binaries yet since there's no `func main`).
- Green: `task build:go`, `task test:go`, `pnpm run lint`, `pnpm run check-types`, `pnpm run build` (frontend).

### What does NOT work / is empty

- No **query path** yet: data is stored but nothing serves it — needs cortex's gRPC
  `IntelligenceService.Search` + Elasticsearch index + `nexus` GraphQL.
- Transport is a **pipe**, not Kafka; siphon and cortex are run manually, not as long-lived services.
- `nexus`, `ghost`, `relic`, `deck`, `credits` are still empty stubs (no `func main`).
- `deploy/docker-compose.yml` has **Postgres only**; no Elasticsearch/Kafka/etc.; no `k8s`.

### Decisions made today

- **First vertical slice:** `siphon → cortex → nexus` (NVD ingest → `SignalEvent` → cortex
  store/index → `query { search(term:"log4j") }` via nexus).
- **Contracts-first:** define protobuf in `packages/contracts` and codegen with `buf` before
  wiring services (honors AGENTS.md Rule 1 "Protobuf is Law").
- **Module layout:** keep **per-service `go.mod`**; generated protobuf Go lives in
  `packages/contracts` and is imported by all services via `go.work`.
- **Architecture:** enforce hexagonal/DDD per `docs/PROJECT-STRUCTURE.md`. The domain layer
  imports no adapter/DB/broker/protobuf types directly; inbound adapters translate proto → domain.
- **`ghost` (exploit generation) parked** until later (roadmap v5) — don't design its ports out,
  but don't build it now.
- **Docs reconciled:** module path `vedant → inventedsarawak`; AGENTS.md switched to service
  codenames; TECHONOLOGY.md retitled to Hyperion, added DuckDB, moved observability to v6;
  added a codename legend to PROJECT-STRUCTURE.md.
- **Clean-slate housekeeping:** removed the deprecated empty `api/` dir; fixed `task build:go`
  (was broken); removed the hand-drawn `.excalidraw` diagrams — `system-diagram.mermaid` is now
  the sole canonical diagram.

### Next actions (immediate)

Two natural directions (user's call):

- **Close the query loop:** add cortex `SearchIndex` port + Elasticsearch adapter (or a Postgres
  `ILIKE` search first), a `Search` query use case, and the inbound gRPC `IntelligenceService.Search`
  server; then `nexus` GraphQL `search` → gRPC client → cortex.
- **Add more sources to siphon:** implement additional `SourceClient` adapters (CISA KEV, GitHub
  Advisory, …) — each is one new adapter; domain/use-case/publisher unchanged.

---

## Changelog

- **2026-08-24** — Built `cortex` storage side: consumer + Postgres repo + migration; docker-compose
  Postgres (5433); `siphon | cortex` → Postgres verified with live NVD data.
- **2026-08-24** — Built `siphon` end-to-end as the first hexagonal slice (domain/ports/
  application/adapters/platform); runs vs live NVD, publishes protojson `SignalDiscovered`.
- **2026-08-22** — Contracts foundation: buf + `task codegen`, first 3 protos
  (common/events/intelligence v1), generated Go committed under `packages/contracts/gen`.
- **2026-08-22** — Clean-slate housekeeping: removed `api/`, fixed `task build:go`, dropped
  `.excalidraw` diagrams (Mermaid canonical). Repo now green on build + test.
- **2026-08-22** — Initial progress snapshot; doc/diagram/TODO reconciliation; first-slice plan set.
