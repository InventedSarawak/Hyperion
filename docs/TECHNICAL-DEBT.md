# Technical Debt & Corners Cut

An honest register of what Hyperion does **not** do yet, and why. Everything here
was a deliberate trade to keep momentum on the core threat engine — none of it is
an accident, but none of it should ship to production either.

Each entry records the shortcut, what it costs, and the roadmap version where it
should be paid off. Update this file whenever a corner is cut or repaid.

**Status legend:** 🔴 blocks production · 🟡 limits correctness/ops · 🟢 cosmetic

---

## 1. Deployment & Infrastructure

### 🔴 No Dockerfiles — Go services run as native host processes

`cortex` and `nexus` are compiled to `.run/bin/` and started with `setsid` by
`scripts/system.sh`. Only Postgres and Elasticsearch are containers.

- **Why:** a `go build` dev loop is ~1s; a Docker image rebuild per code change is not.
- **Cost:** the system lives in two places — `docker ps` shows only half of it.
  Services do not restart on crash, and they die on desktop logout (their parent is
  `systemd --user`) while the containers survive. This directly contradicts
  **AGENTS.md Rule 7** ("Code is not done until it runs inside a container").
- **Fix in v4:** multi-stage Dockerfiles per service, added to `docker-compose.yml`
  with `restart: unless-stopped`. Keep a bind-mount dev target so the fast loop survives.

### 🔴 `deploy/k8s/` and `deploy/terraform/` are empty directories

Both exist in the tree and are referenced by `docs/PROJECT-STRUCTURE.md`, but contain
no manifests, Helm charts, or `.tf` files whatsoever.

- **Why:** deployment is a v4 concern; there is nothing stable to deploy yet.
- **Cost:** the repo structure implies infra-as-code that does not exist. Anyone
  reading the tree would reasonably assume otherwise.
- **Fix in v4:** Helm chart per service, K3s locally, ArgoCD for GitOps. Terraform
  only once there is real cloud infra to describe — an empty `deploy/terraform/`
  should either be filled or deleted.

### 🟢 Local infra assumes the default ports are free

`deploy/docker-compose.yml` binds Postgres to :5432, Elasticsearch to :9200 and
Neo4j to :7687 on the host.

- **Cost:** on a machine already running another project's database, `task up`
  fails to bind and the stack comes up half-started. This is real: v2 was
  verified against a throwaway Postgres on :55432 because an unrelated
  `ledgera-postgres-1` container held :5432.
- **Fix:** make the host ports configurable (`${HYPERION_POSTGRES_PORT:-5432}`
  in compose, matching the existing namespaced config), so the stack can move
  aside without editing a committed file.

### 🟡 No CI pipeline

`.github/workflows/` is empty. Nothing runs tests, lint, or builds on push.

- **Why:** the husky pre-commit hook covers the same checks locally.
- **Cost:** the gate is bypassable (`--no-verify`) and only protects this machine.
  No build matrix, no image publishing, no protection on shared branches.
- **Fix in v4:** GitHub Actions running `task build:go`, `task test:go`, lint and
  typecheck; publish images on tag.

### 🟡 No restart policies or resource limits in compose

Containers have healthchecks but no `restart:` policy and no memory/CPU bounds
(beyond Elasticsearch's `ES_JAVA_OPTS` heap).

- **Cost:** a crashed container stays down; a runaway one can starve the host.
- **Fix in v4:** `restart: unless-stopped` plus `deploy.resources.limits`.

---

## 2. Data Flow & Correctness

### 🟢 ~~Transport is a Unix pipe, not a message bus~~ — REPAID (v3, 2026-09-17)

Kafka is the transport: topic `hyperion.signals.v1`, 6 partitions, consumer group
`intel-indexer`, records keyed by finding id. `task up` runs siphon and cortex as
independent services over the broker; `scripts/system.sh` no longer builds a pipeline.
It cost exactly what the hexagon promised — one new outbound adapter in siphon, one
new inbound adapter in cortex, and no change to a domain type or a use case.

- **What the system gained:** durability (7-day retention), replay from the last
  committed offset, consumer groups, backpressure, and two services that no longer
  have to live and die together.
- **What remains of the pipe:** `task ingest` and `task backfill` still run
  `siphon | cortex` deliberately — one command that loads data and reports what it
  stored is genuinely the point there. They opt out explicitly.

### 🟢 ~~No dead-letter topic~~ — REPAID (v3, 2026-09-17)

A record that exhausts its retries is forwarded to `hyperion.signals.v1.dlq`
with the failure, origin partition/offset and attempt count in headers, and
committed past — so one poisonous record no longer blocks its partition.

- **The trap that was avoided:** a dead-letter queue on its own turns a
  database outage into a silent migration of the whole topic. The consumer
  therefore counts _consecutive_ dead-letters and stops after ten
  (`CORTEX_KAFKA_DLQ_MAX_CONSECUTIVE`): one bad record is a record, ten in a
  row is the world being broken. A success resets the count.
- **If the dead-letter topic itself is unreachable,** the consumer stops
  without committing, which is the only remaining way not to lose the record.
- **Draining it:** `task topic:dlq` reads it with reasons attached,
  `task topic:dlq -- -replay` republishes the records unchanged.
- **What remains:** nothing alerts on the topic being non-empty — it has to be
  looked at. A metric belongs in v6 with the rest of the telemetry.

### 🟢 Topics are created by the services that use them

`EnsureTopic` runs at startup in both siphon and cortex.

- **Why:** the alternative during development is broker auto-creation, which gives
  whatever partition count the broker defaults to — and partition count is the one
  setting that cannot be lowered later.
- **Cost:** topology is defined in application startup code rather than declared with
  the infrastructure, so it is invisible to anyone reading `deploy/`.
- **Fix in v4:** declare topics with the rest of the infrastructure, and drop the
  startup call.

### 🟢 ~~Ingestion watermark is in-memory only~~ — REPAID (v3, 2026-09-17)

The watermark is persisted to Redis (`hyperion:siphon:watermark:advisories`, no
expiry) through a `CheckpointStore` port, so a restart resumes where the last
successful poll finished. Measured on a restart with a 2h lookback: 526 records
re-fetched before, 59 after.

- **What it fixed:** an outage longer than the lookback window used to skip
  everything published in between, permanently. That gap is closed.
- **What remains:** one watermark for all ten sources, so a single slow source
  cannot be tracked separately — the same shape as the global-lookback entry
  below, and worth fixing together.
- **Degraded mode:** Redis unreachable is a warning, not a stop; siphon falls
  back to the in-memory watermark and keeps polling.

### 🟢 ~~No dedupe store~~ — REPAID (v3, 2026-09-17)

`DedupeStore` is implemented on Redis and applied in the poll workflow. Each
observation is fingerprinted (a digest of its content, not just its id) and an
identical one inside the window is not published again. Measured on one 3h NVD
window re-read from scratch: 885 suppressed, 25 published.

- **Why a content fingerprint:** the `SignalID` is source + id, so suppressing
  on it would drop _corrections_ — a score the advisory did not carry
  yesterday, a newly named affected package. Those must still be published.
- **New operational trap:** wiping cortex's databases no longer refills them
  from the next poll, because siphon remembers having published those records.
  Clear `hyperion:siphon:seen:*` or run a backfill. Documented in
  CURRENT-FUNCTIONALITIES 1.1 and `.env.sample`.
- **Fails open:** a store that errors publishes the observation anyway. A
  duplicate costs a merge that changes nothing; a suppressed signal is lost
  until the advisory is next amended.
- **Not applied to the backfill:** it is a one-off load of hundreds of
  thousands of records, and fingerprinting them all would fill Redis to no
  purpose.

### 🟢 ~~Single global lookback across sources of wildly different cadence~~ — REPAID (v3, 2026-09-17)

Each source now has its own interval, its own first window and its own
watermark (`hyperion:siphon:watermark:source:<name>`). Defaults run from 10m/2h
for NVD to 6h/14d for Exploit-DB and the package feeds; `SIPHON_<SOURCE>_INTERVAL`
and `_LOOKBACK` override one feed.

- **What it fixed:** at the old global 2h window three sources returned nothing
  essentially always. Measured after: `vendor_advisory` fetched 13 records over
  its 48h window where 2h found none, and dedupe suppressed the repeats so the
  wider window costs nothing downstream.
- **What it cost:** the scheduler stopped owning a watermark at all. It is a
  plain ticker now, and how far back to read is answered by the poller — which
  is the only thing that can answer it per source.
- **Migration:** `SIPHON_POLL_INTERVAL` and `SIPHON_LOOKBACK` still work and
  still override every source at once. They are commented out in `.env.sample`,
  because leaving them set silently flattens all ten feeds back to one cadence.

### 🟢 A re-keyed finding can alert a subscription once more

Findings are filed under a canonical id (CVE, else GHSA, else MAL) with every other id
as an alias; when a report links a GHSA-keyed record to its new CVE, the two merge and
the record moves to the CVE (see CURRENT-FUNCTIONALITIES 1.3).

- **Resolved (2026-09-12):** the old split — one advisory as two records, `GHSA-…` and
  `CVE-…` — is gone; existing alerts are moved to the new id in the same transaction.
- **Cost that remains:** an alert's id is derived from the subscription and the finding
  id, so after a re-key the same subscription can be alerted once more under the CVE.
- **Fix:** derive the alert id from the subscription and the finding's first-stored id,
  or dedupe on every id the finding carries.

### 🟢 Two lockfile formats are still unread

A version matters twice over: what a manifest allows ("^1.13.2") can only ever be judged
"possibly affected", while what a lockfile installs (1.13.2) settles it outright.

- **Resolved (2026-09-16):** `package-lock.json`, `pnpm-lock.yaml`, `Cargo.lock`,
  `poetry.lock`, `composer.lock` and `Gemfile.lock` are read alongside their manifests, and
  a locked version wins over a declared range. They also carry the transitive dependencies,
  where most exposure actually sits.
- **What remains:** `yarn.lock` (its own text format) and NuGet's `packages.lock.json` are
  not read, so those versions are still ranges. `go.mod` and pinned `==` requirements were
  already exact.

### 🟡 NuGet and RubyGems names must match the advisory's spelling

Library nodes are keyed by the package name as written. PyPI names are normalised on the
scanner's side (PEP 503, as advisories store them) and Packagist names are lower case, but
NuGet ids are case-insensitive and advisories store them with capitals (`Newtonsoft.Json`).

- **Cost:** a `.csproj` that writes `newtonsoft.json` does not reach the advisories for
  `Newtonsoft.Json`.
- **Fix:** normalise the key per registry in cortex (lower case for NuGet) and migrate the
  existing library nodes.

### 🟡 Descriptions and scores are last-writer-wins

`Merge` unions sources, references and affected packages, but for the description and
the score set the newest non-empty observation wins, whichever feed it came from.

- **Cost:** which description you read depends on which feed reported last — NVD's
  one-paragraph summary or GitHub's full Markdown write-up can replace each other on
  every poll. Nothing is lost that matters for matching, but the display wobbles.
- **Fix:** keep one description and score set per source and choose by source priority
  at read time.

### 🟡 Malware is ingested in full but only hidden, not triaged

OSV's malicious-package dataset (`MAL-…`) is ingested whole, as findings of kind
`malware`. deck leaves them out of the feed unless `m` is pressed; searching for an
exact id finds one either way.

- **Why:** a compromised package is the most urgent thing a dependency can be, and a
  `MAL-` id is often the only record it ever gets — skipping them made that invisible.
- **Cost:** npm alone has ~220,000 `MAL-` records, nearly all typosquats nobody installs.
  They cost storage and index space, and a subscription with a broad rule can match them.
- **Fix in v3:** rank malware by whether a tracked repository depends on the package —
  the graph can answer that — and alert only on those.

### 🟢 A backfill can raise alerts for old findings

The backfill publishes the same events as polling, so a subscription matching a
2017 advisory fires when the backfill replays it.

- **Cost:** a backfill run with subscriptions in place produces a burst of historical
  alerts. After a full reset (no subscriptions) it produces none.
- **Fix:** mark backfilled events as historical in the contract and skip alerting for them.

### 🟡 Naive migration runner

`postgres.Migrate` executes every embedded `.sql` file in filename order on every
boot. Idempotency relies on `IF NOT EXISTS`.

- **Cost:** no version table, no down-migrations, no drift detection. A non-idempotent
  migration would corrupt state or fail the boot.
- **Fix in v2/v3:** adopt `goose` or `golang-migrate` with a schema-version table.

### 🟢 No Elasticsearch alias or reindex strategy

Documents are written straight to a fixed index name.

- **Cost:** a mapping change requires deleting and rebuilding the index with downtime.
- **Fix in v3:** write through an alias, reindex into a new concrete index, flip atomically.

---

## 3. Dependency Graph & Supply Chain (v2)

### 🟢 ~~Dependency reporting is a synchronous gRPC call~~ — REPAID (v3, 2026-09-17)

siphon publishes `DependencyObserved` to `hyperion.dependencies.v1`, keyed by
repository full name; cortex consumes it as group `intel-graph` and writes the
graph edges. Verified by scanning with cortex stopped: the scan succeeded, and
cortex applied the observation when it came back.

- **What changed beyond the adapter:** the `DependencyPublisher` port used to
  return the number of edges cortex wrote, which only an RPC can answer. A port
  that promises what one of its adapters cannot deliver is not a port, so it now
  returns an error alone and the workflow reports what it _read_. That is the
  honest number for siphon to know.
- **Its own topic and group,** not the signal topic: a backlog of advisories
  must not hold up the supply-chain graph, and a consumer of one has no use for
  the other.
- **No dead-letter topic on this path,** deliberately. A manifest read that
  cannot be written is almost always the graph being unavailable — the case that
  should stop and be retried — and a later read of the same repository
  supersedes the one that failed.
- **The RPC remains** for callers that want the edge count synchronously, and as
  the fallback when the broker is unreachable.

### 🟡 Library-to-library edges reach only as far as the watchlist

`(:Library)-[:DEPENDS_ON]->(:Library)` edges are derived from scanned repositories
that publish a module: the module's direct requirements become its own edges.

- **Why:** it is the only transitive data a manifest actually contains, and it
  makes `DEPENDS_ON*1..n` genuinely recursive rather than decorative.
- **Cost:** transitivity stops at the edge of the watchlist. A repository
  depending on a library nobody scanned looks one hop deep, so a real blast
  radius can be **understated** — the failure mode that matters most here.
- **Fix in v3+:** ingest a real module graph (deps.dev, an SBOM feed, or
  `go mod graph` / lockfiles) instead of inferring it from what we happened to scan.

### 🟢 ~~Only _reviewed_ GitHub advisories carry package linkage~~ — MITIGATED

The advisory feed is dominated by `unreviewed` records — automated NVD imports with
`vulnerabilities: []` — and only about one reviewed advisory appears every 6 hours, so
polling alone builds almost no CVE-to-library linkage.

- **Repaid by the backfill (2026-09-11):** `task backfill` reads OSV's full
  per-ecosystem exports, where every record names its package and version range, so a
  fresh stack starts with ten years of linkage. Polling then only has to keep up.
- **What remains:** between backfills, new linkage still arrives only through reviewed
  GitHub advisories and the OSV package watchlist.

### 🟢 ~~The repository watchlist is manual~~ — REPAID

The watchlist is edited in the product (deck's Repositories tab, or the GraphQL
mutations): pick an owner, choose repositories, and they are scanned within 30s. It
lives in cortex; siphon polls it. `SIPHON_REPO_WATCHLIST` and `SIPHON_REPO_ORGS` are gone.

- **What remains:** one shared list — per-user and per-team watchlists arrive with
  auth in v4, and private repositories need a GitHub App installation rather than one
  personal token.

### 🟢 Two copies of "list an owner's repositories"

cortex (for the Repositories tab) and siphon (for one-off `task scan -- -orgs`) each
have a small GitHub listing adapter.

- **Why:** each belongs to its own service's hexagon; sharing an adapter across
  services would couple their release cycles for ~100 lines.
- **Cost:** a GitHub API change has to be fixed twice.
- **Fix:** retire siphon's `-orgs` flag once scripts use the watchlist instead.

### 🟢 Untracking keeps what a repository taught the graph about libraries

Removing a repository deletes it and its own edges, but library-to-library edges
learned from the module it published stay.

- **Why:** "ajv depends on fast-uri" stays true whether or not anyone tracks ajv, and
  removing it would silently shorten other repositories' transitive blast radius.
- **Cost:** those edges are no longer refreshed, so they can go stale.

### 🟢 The gateway adds a hop for the terminal client

`deck` → nexus (GraphQL/HTTP) → cortex (gRPC), where it used to call cortex
directly.

- **Why:** the edge is where authentication, rate limiting, per-tenant scoping
  and usage metering will live. A client that bypasses it bypasses all of them,
  and "the TUI is internal" stops being true the moment anyone runs it over SSH
  from a laptop.
- **Cost:** one extra network hop and a JSON encode/decode per query. Negligible
  against a human pressing keys; it would matter for a streaming firehose.
- **Escape hatch:** `DECK_TRANSPORT=grpc` keeps the direct path for debugging a
  cortex the gateway cannot reach.

### 🟢 Neo4j migrations are implicit

`EnsureSchema` creates uniqueness constraints idempotently on boot. There is no
version table and no way to evolve a constraint.

- **Cost:** the same shortcut as the Postgres migration runner, one layer over.
- **Fix in v3:** fold the graph schema into whatever versioned migration tool
  replaces the Postgres runner.

---

## 4. Security

### 🔴 No authentication or authorization anywhere

The GraphQL endpoint and the gRPC API are both fully open. Anyone who can reach the
port can query everything.

- **Why:** Keycloak is scheduled for v4; auth would have blocked the v1 slice.
- **Fix in v4:** Keycloak OIDC, JWT validation at the nexus edge, per-tenant scoping.

### 🔴 gRPC runs in plaintext

`insecure.NewCredentials()` in
`apps/nexus/internal/adapters/outbound/grpc/intelligence_client.go`.

- **Cost:** fine while both ends are on localhost; unacceptable the moment the
  services are on separate hosts.
- **Fix in v4:** mTLS, or a service mesh handling transport security.

### 🟡 Kafka runs plaintext with no authentication

The broker listens PLAINTEXT on 9092 with no SASL, no TLS and no ACLs, and runs as a
single node with replication factor 1.

- **Why:** same trade as Postgres and Elasticsearch below — local development only.
- **Cost:** anyone who can reach the port can read every advisory event or publish
  forged ones. A single broker also means no durability against losing that broker.
- **Fix in v4:** SASL/TLS and ACLs per service, and a replicated cluster.

The Kafka console on `:8081` inherits this: no login, and anyone who reaches it can read
every event on the topic. It is a development tool in the compose file, and must not be
exposed anywhere shared.

### 🟡 Elasticsearch security disabled

`xpack.security.enabled=false` in compose — no auth, no TLS on :9200.

- **Why:** removes credential setup from local dev.
- **Cost:** anything on the host can read/write the index. **Local dev only — never
  deploy this compose file.**
- **Fix in v4:** enable security, use real credentials from a secret store.

### 🟡 Default credentials committed in compose

`hyperion/hyperion` for Postgres and `neo4j/hyperion` for Neo4j, in the repo.

- **Cost:** harmless locally, catastrophic if the file were ever applied elsewhere.
- **Fix in v4:** secrets via environment/secret manager, never in the compose file.

### 🟡 Secrets sit in plaintext `.env`

API keys are read from an unencrypted, gitignored file.

- **Cost:** standard for local dev, but no rotation, no audit, no encryption at rest.
- **Fix in v4:** a secret manager (Vault / SOPS / cloud KMS) for anything deployed.
- **Known footgun:** godotenv strips a trailing `# comment` only when the line has a
  value. A blank setting written `KEY=   # hint` yields the _comment_ as the value —
  this produced a real GitHub 401. The loader now treats a leading `#` as unset, and
  `.env.sample` keeps hints on their own line. Do not reintroduce inline hints on
  blank lines.

---

## 5. Operability

### 🟡 No health endpoint on cortex

`nexus` serves `/healthz`; `cortex` and `siphon` serve nothing. `scripts/system.sh`
probes cortex by opening a TCP connection to :50051, which proves the port is bound
but not that the service is healthy.

- **Fix in v4:** gRPC health checking protocol on cortex; readiness that verifies
  Postgres and Elasticsearch.

### 🟡 No observability

No metrics, no tracing, no structured log aggregation. `packages/telemetry` is an
empty module.

- **Cost:** no visibility into rate-limit consumption, ingest lag, or query latency.
- **Fix in v6:** OpenTelemetry, Prometheus, Grafana, Loki, Tempo.

### 🟡 Ingest has no graceful shutdown

Ctrl-C during ingestion drops whatever is in flight. There is no transaction spanning
the store-and-index pair, so Postgres can hold a record that Elasticsearch does not.

- **Cost:** search results can silently lag storage after an abrupt stop.
- **Fix in v3:** drain on shutdown; a reconciliation job to reindex from Postgres.

### 🟢 Elasticsearch cluster runs yellow

Single-node with default replica settings, so replicas are unassignable.

- **Cost:** cosmetic locally; a genuine availability gap in any real deployment.
- **Fix in v4:** set `number_of_replicas: 0` for single-node, or run a real cluster.

---

## 6. Scope Deliberately Deferred

Not debt — planned roadmap work, listed so the gap between the docs and reality is explicit:

- **`ghost`** (CTF copilot, Ollama + Qdrant) — parked, v5.
- **`relic`** (Parquet archiver to MinIO) — stub, v4.
- **`credits`** (Lago billing) — stub, v4.
- **`console`** (Next.js dashboard) — still the Turborepo starter page, v4.
- ~~**`deck`** (Bubble Tea TUI)~~ — **built in v2**: live feed + graph explorer.
- ~~**Neo4j blast radius**~~ — **built in v2**, and verified against live data.
- ~~**Blast radius is not exposed through nexus.**~~ — **repaid**: the gateway
  serves a `blastRadius` query, and `deck` now routes through nexus by default
  (`DECK_TRANSPORT=grpc` still bypasses it for debugging). This matters because
  auth, rate limiting and metering all land at the edge in v4; a client that
  skips the gateway would skip all of them.
- ~~**gRPC streaming for the live feed**~~ — **built in v3**: cortex broadcasts each
  stored finding over `StreamFindings`, nexus relays it as SSE at `/stream`, and `deck`
  refreshes on arrival instead of on its timer. The timer stays as the fallback. What
  remains: nothing replays findings missed while disconnected, and the stream is
  unauthenticated like the rest of the API (v4).
