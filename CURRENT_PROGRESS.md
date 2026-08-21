# Current Progress

A living snapshot of where Hyperion actually stands. Update the **Latest Update** section
before each commit; move superseded entries into the changelog at the bottom.

---

## Latest Update — 2026-08-22

### Overall status

**Pre-v1, contracts foundation landed.** Monorepo wiring works and the protobuf contract layer
now exists + generates Go; services are still empty stubs otherwise.

### Contracts (NEW — done)

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

- All Go services are empty stubs (e.g. `apps/nexus/cmd/server/main.go` is just `package server`,
  no `func main`) — no runnable service binaries exist. Contracts exist but no service _uses_ them yet.
- `deploy/docker-compose.yml` is **empty (0 bytes)**; no real `k8s`/`terraform` manifests.

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

1. Begin `siphon`: domain (`SourceSignal`, `SourceKind`) + `SourceClient` port + NVD outbound
   adapter; map NVD JSON → domain → `SignalDiscovered` proto at the adapter boundary.
2. Decide the transport for the first slice (in-process/stdout first, Kafka later per roadmap).

---

## Changelog

- **2026-08-22** — Contracts foundation: buf + `task codegen`, first 3 protos
  (common/events/intelligence v1), generated Go committed under `packages/contracts/gen`.
- **2026-08-22** — Clean-slate housekeeping: removed `api/`, fixed `task build:go`, dropped
  `.excalidraw` diagrams (Mermaid canonical). Repo now green on build + test.
- **2026-08-22** — Initial progress snapshot; doc/diagram/TODO reconciliation; first-slice plan set.
