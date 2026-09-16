# Current Progress

A living snapshot of where Hyperion actually stands. Update the **Latest Update** section
before each commit; move superseded entries into the changelog at the bottom.

---

## Latest Update — 2026-09-17

### Overall status

**v3: Hyperion runs on an event backbone.** siphon publishes to Kafka and cortex consumes
it, with per-finding ordering, committed offsets and replay verified against a live
broker. `task up` now starts them as **independent services** — siphon keeps publishing
while cortex is down, and cortex resumes from its last committed offset when it returns.
The `siphon | cortex` pipe survives only where it is wanted: `task ingest` and
`task backfill`, which opt out explicitly.

### What landed

| Area           | What landed                                                                                                                                                                                                                                                                        |
| -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Infrastructure | **Kafka 4.1.0 in KRaft mode** in compose — single node, no ZooKeeper (removed in Kafka 4.0), healthchecked, three listeners so the host, other containers and the controller each reach it correctly; 5 MiB max record size, because a long advisory exceeds Kafka's 1 MiB default |
| Shared package | **`packages/common/kafka`** (franz-go): producer, consumer group, protobuf codec, `EnsureTopic`, group-free `Tail`, lag reporting. Only this package imports a Kafka client — services depend on its `Message`/`Handler` types                                                     |
| siphon         | `kafka_publisher.go` beside the stdout publisher, both behind `SignalPublisher`. Records keyed by **finding id**                                                                                                                                                                   |
| Port change    | `SignalPublisher` gained **`Flush`**: publishing is batched, so a poll must confirm durability before the scheduler advances its watermark, or a restart skips a window that was never published                                                                                   |
| cortex         | `KafkaHandler` reusing the stdin consumer's proto→domain mapping; runs **alongside** the gRPC API, and a consumer that gives up takes the server down with it                                                                                                                      |
| Tooling        | `topic:tail` (decodes records to protojson), `topic:lag`, `topic:describe`; `task up` starts siphon as its own service and reports ingest lag in `task status`                                                                                                                     |

### Verified end to end

Live NVD → siphon → Kafka → cortex → Postgres/Elasticsearch/Neo4j:

- **416 records** on `hyperion.signals.v1`, spread across all 6 partitions (52–82 each)
- cortex consumed all 416 as group `intel-indexer`; **lag 0 on every partition** afterwards,
  so a restart resumes rather than re-reads
- 16 specs in `packages/common/kafka`, 4 of them against the real broker: per-key
  ordering, commit-and-resume, poison-record skip, and failure-without-commit replay

Two real defects surfaced in that testing and were fixed: every poll must re-allow group
rebalancing or `Close` hangs forever, and lag read from a group that has not formed yet
reports nothing, which must not be read as "caught up".

**Then the switch itself was tested.** cortex was killed with `SIGKILL` before it had
committed anything (`CURRENT-OFFSET` still `-`); on restart it re-read the whole topic —
787 records, `ingested_this_run: 787` — and finished at `committed=787 end=787 LAG=0`.
The full stack was then torn down and brought back up on the broker: every component up,
lag 0, Postgres and Elasticsearch in agreement at 546,868, and a GraphQL query through
nexus returning findings with cross-source provenance (`["package_feed","nvd"]`) intact.

### Since then

- **Ingestion watermark persisted (2026-09-17).** A `CheckpointStore` port with a Redis
  adapter; the scheduler resumes from the stored watermark and advances it only on a
  successful poll. Restarting with a 2h lookback used to re-fetch 526 records; resuming
  from a 54-second-old watermark fetched 59. It also closes a real gap — an outage longer
  than the lookback used to skip everything published in between. Redis being unreachable
  is a warning, not a stop.

- **Observations deduplicated (2026-09-17).** A `DedupeStore` port on Redis, applied in
  the poll workflow: each observation is fingerprinted by **content** — id, title,
  description, scores, references, aliases, kind, dates, affected packages — and an
  identical one inside the window (24h) is not published again. One 3h NVD window re-read
  from scratch: 885 suppressed, 25 published. Keying on the `SignalID` alone would have
  suppressed corrections, which is why the digest covers content rather than identity.
  New trap, documented: wiping cortex's stores no longer refills them from the next poll —
  clear `hyperion:siphon:seen:*` or backfill.

- **Dead-letter topic (2026-09-17).** A record that exhausts its retries goes to
  `hyperion.signals.v1.dlq` — original bytes untouched, with the reason, origin
  partition/offset and attempt count in headers — and ingest continues past it. The trap
  avoided: a dead-letter queue alone turns a database outage into a silent migration of
  the whole topic, so the consumer counts **consecutive** dead-letters and stops after ten.
  A success resets the count; an unreachable dead-letter topic stops the consumer
  uncommitted. `task topic:dlq` reads it, `task topic:dlq -- -replay` puts records back
  (verified live: 3168 -> 3170 records on the signal topic after a replay).

- **Repository scans moved onto the bus (2026-09-17).** A new `DependencyObserved`
  contract, published to `hyperion.dependencies.v1` keyed by repository, consumed by
  cortex as group `intel-graph` — its own topic and group so a backlog of advisories
  cannot hold up the supply-chain graph. The `DependencyPublisher` port stopped returning
  "edges written", which only an RPC can answer; siphon now reports what it read.
  Verified by scanning `charmbracelet/bubbletea` with **cortex stopped**: the scan
  succeeded, and cortex wrote the edges when it came back. That scan would previously
  have failed outright.

- **Live feed, end to end (2026-09-17).** `StreamFindings` (server-streaming gRPC) on
  cortex, fed by an in-memory broadcaster that ingest notifies after each store; nexus
  relays it to HTTP clients as SSE at `GET /stream`; deck subscribes on start and
  refreshes on arrival. Three calls worth recording: **ingest never blocks on a watcher**
  (a full buffer drops updates instead), **deck refreshes rather than inserting the
  streamed record** (the query stays the single source of what the list shows), and the
  **feed goes through the gateway**, not straight from cortex, so it passes the same door
  as every other client. The port was split — `FindingStreamClient` separate from
  `IntelligenceClient` — so no existing caller or test stub had to implement a streaming
  method it never uses.

### What is deliberately not done

- Repository scans still call cortex over synchronous gRPC
- No dead-letter topic: a record that fails ingest past its retries halts the consumer
- No streaming to deck, no load test — both still open in v3

---

## v2 complete — 2026-09-07

### Overall status

**v2 is complete.** Hyperion now answers the question it was built for: _given a
vulnerability, which repositories does it actually reach?_ Neo4j holds the supply chain,
siphon reads real dependency manifests, and `deck` puts both in a terminal.

### What v2 added

| Area           | What landed                                                                                                                                                                                            |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Infrastructure | **Neo4j 5.26** in compose (bolt :7687, browser :7474), healthchecked; `system.sh` waits on it and reports node/relationship counts                                                                     |
| Contracts      | `common/v1/package.proto`, `common/v1/repository.proto`; `IngestDependencies` + `GetBlastRadius` RPCs; `Vulnerability.affected_packages`                                                               |
| cortex         | `Repository`/`Library`/`Author`/`Dependency` entities, `RepositorySnapshot` aggregate, `PackageRef`/`Ecosystem` VOs, `DependencyGraph` port, Neo4j adapter, `IngestDependency`, `CalculateBlastRadius` |
| siphon         | GitHub repository adapter (`go.mod` / `package.json` via the contents API), `manifest` parsers, `ScanRepositories` workflow, gRPC dependency publisher                                                 |
| deck           | Bubble Tea TUI — tabbed **Live Feed** (polling) and **Graph Explorer** (ASCII tree), gRPC client, 25 specs driving `Update`/`View` with no terminal                                                    |

### The graph

```
(:Author)-[:MAINTAINS]->(:Repository)-[:DEPENDS_ON {version, direct}]->(:Library)
(:Repository)-[:PUBLISHES]->(:Library)-[:DEPENDS_ON]->(:Library)
(:Library)-[:AFFECTED_BY {affected_version}]->(:Vulnerability)
```

Libraries are keyed on **ecosystem + name without a version**, so every dependant of a
package converges on one node and a single traversal finds them all; the pinned version
lives on the edge. A scanned repository that publishes a module contributes that module's
_direct_ requirements as library-to-library edges — which is what makes the
`DEPENDS_ON*1..n` traversal genuinely recursive rather than one hop deep.

### Verified end-to-end (2026-09-07, live data)

- Ingest of 30 days of GitHub Advisory + OSV: **100 vulnerabilities linked to 31
  libraries** via 134 `AFFECTED_BY` edges.
- Repository scan of `ajv-validator/ajv`, `eslint/eslint`, `fleetdm/fleet`:
  **651 dependency edges** written through the `IngestDependencies` RPC (44 / 88 / 519).
- Graph totals: 656 `Library`, 100 `Vulnerability`, 3 `Repository`, 3 `Author`;
  912 `DEPENDS_ON`, 134 `AFFECTED_BY`, 3 `PUBLISHES`, 3 `MAINTAINS`.
- **Real transitive blast radius** over gRPC — `CVE-2026-13676` in `npm:fast-uri`:
  - `ajv-validator/ajv` — depth 1, direct
  - `eslint/eslint` — depth 2, path `eslint/eslint → npm:ajv → npm:fast-uri`
  - `fleetdm/fleet` — reached through its own manifest
- `deck` renders the live feed against cortex with severity colouring and the
  graph explorer tree.
- Full suite: **39 packages green**, including the Postgres, Elasticsearch and Neo4j
  integration suites against real backends.

### Bugs and gaps found by running it for real

- **GitHub advisories carried no package data.** 42 of 43 advisories in a 6h window are
  `unreviewed` — automated NVD imports with `vulnerabilities: []`. Only _reviewed_
  advisories link a CVE to a library, and a recency-sorted window buries them. siphon now
  makes a second `type=reviewed` pass and dedupes: that feed is **100% package-bearing**.
- **Affected packages were never persisted.** The field reached the domain and the graph
  but not Postgres, so the cross-source union could not survive a restart. Added
  `affected_packages jsonb` (migration `0002`) with round-trip tests.
- **Unauthenticated pacing made tests crawl** — the GitHub suite took 241s once a second
  pass was added. `sourcehttp.WithRateLimit` now lets a test (or an operator tuning one
  source) override the adapter's default pacing; the suite is back to 0.3s.
- **`task up` cannot bind Postgres on this machine**: an unrelated project's container
  (`ledgera-postgres-1`) holds :5432. v2 was verified against a throwaway Postgres on
  :55432 rather than stopping someone else's database — see Technical Debt.

### What does NOT work / is not built

Full register with reasons and fix-by version: **[docs/TECHNICAL-DEBT.md](docs/TECHNICAL-DEBT.md)**.
Headline gaps after v2:

- **Transitivity reaches only as far as the watchlist.** Library-to-library edges come
  from scanned repositories that publish a module; a real module graph (deps.dev, SBOM)
  would close the rest.
- **The default 2h lookback yields almost no package linkage** (~1 reviewed advisory per
  6h). Per-source lookback is the fix; until then raise `SIPHON_LOOKBACK` to seed the graph.
- **siphon calls cortex synchronously** for dependencies — no bus yet (v3), and the
  advisory path is still a Unix pipe.
- **The repository watchlist is manual** — no discovery of what an org actually owns.
- **deck polls**; gRPC streaming is v3. Everything under Security and Operability below
  is unchanged from v1: no auth, plaintext gRPC, no Dockerfiles, no CI, no telemetry.

**Still stubs:** `ghost` (v5), `relic` (v4), `credits` (v4); `console` is the Turborepo
starter page (v4).

---

## Real-time alerts — 2026-09-09

The v3 feature that changes the product's character: from _"I query it"_ to _"it tells
me"_. Built ahead of the Kafka refactor, on the current transport — when Kafka lands only
the consumer adapter changes.

### How it works

**Reverse search.** A normal index stores documents and you search them with a query; the
Elasticsearch **percolator** stores _queries_ and you search it with a document, getting
back the queries that document satisfies. One pass over an incoming vulnerability finds
every interested subscriber, instead of replaying every rule as a separate search.

```
advisory ──▶ cortex ingest ──▶ percolate ──▶ candidate rules
                                   │
                     re-verify in the domain (the rule, not the index, is the authority)
                                   │
                     Redis SET NX EX (quiet for 1h)  ──▶  alert
```

### Design decisions worth recording

- **An empty rule is rejected, not treated as "everything".** Matching every advisory is
  the alert fatigue this platform exists to prevent, and trivially easy to create by accident.
- **The percolator is an index, not the definition of a match.** Every hit is re-checked
  against `AlertRule.Matches` in the domain, so a stale or over-broad index cannot invent
  an alert. A subscriber who stops trusting alerts is worse off than one who gets none.
- **Create rolls back if indexing fails.** A stored-but-unindexed subscription looks
  healthy in a listing and silently never fires — more dangerous than a visible failure.
- **Dedupe fails open.** Redis down means alerts fire without suppression; a duplicate is
  an annoyance, a suppressed alert is a missed vulnerability.
- **Alerts store the CVE id, not a copy of the advisory.** Records are corrected
  constantly; a frozen copy would drift from what it points at.
- **Unranked severity never clears a threshold.** "We don't know how bad this is" must not
  be promoted to "bad enough to wake you".
- **Boot-time reindex.** Postgres is the source of truth, so a lost percolator index is
  rebuilt rather than silently leaving every rule dead.

### Verified end-to-end (2026-09-09, live)

- Subscription created over gRPC for `npm:next`; a 7-year OSV backfill raised **57 alerts**
  with reasons (`affects npm:next`) and each alert's advisory resolved on read.
- Re-ingesting the same 56 advisories raised **0** — Redis suppression working.
- Flushing Redis and re-ingesting left the alert count **unchanged at 57** — deterministic
  ids prevent duplicates independently of suppression.
- **41 packages green**, including new Redis and percolator integration suites (18
  percolator specs against real Elasticsearch).

### What is still v3

Kafka and the Redis checkpoint. The transport is still a Unix pipe, and the ingestion
watermark is still in memory — a crash longer than the lookback window still loses
signals. Alerting sits on top of whatever the transport is, so that work is unaffected.

---

## Post-v2 hardening — 2026-09-08

Fixes and improvements taken before starting v3, all verified against the live stack.

### Bugs fixed

- **TUI frame corruption.** Advisory titles contain literal tabs and newlines
  (`CVE-2025-70290`: `"...U-Boot Filesystem\tParsing"`). A tab counts as one rune but
  renders as up to eight columns, so rows overflowed, wrapped, and desynchronised Bubble
  Tea's frame diff — leaving fragments of the previous frame on screen (`ParParsing`).
  Control characters are now flattened at the source and widths measured in **cells**, not
  runes. The selected and unselected row paths were also unified; they had drifted, which
  is why only some rows corrupted.
- **`pid_of` read the wrong PID file** — a latent bug in `scripts/system.sh` predating v2.
  `local name="$1" file="$RUN_DIR/$name.pid"` expands `$name` _before_ the local is
  assigned, so `file` used the caller's `name`. Invisible until a caller passed a name that
  differed from the loop variable.
- **Shodan CVEDB logged an error on every poll.** It answers an empty window with
  `404 {"detail":"No information available"}`; at a short lookback that is the normal case,
  not a failure. Now treated as an empty result.

### Improvements

- **Continuous ingest.** `task up` runs `siphon | cortex` detached in its own process
  group, polling on `SIPHON_POLL_INTERVAL`. `HYPERION_INGEST=0` skips it.
- **Repository discovery.** `SIPHON_REPO_ORGS=vercel` enumerates an owner's repositories
  instead of relying on a hand-written watchlist, skipping forks and archived repos and
  re-running each scan. Verified: one command discovered 20 repositories and wrote 611
  dependency edges, taking `CVE-2026-64646` (Next.js) from 1 exposed repository to 6.
- **Blast radius through the gateway.** nexus serves a `blastRadius` GraphQL query, and
  `deck` now routes through nexus by default rather than calling cortex directly — so it is
  subject to the edge policy that arrives in v4. `DECK_TRANSPORT=grpc` keeps the direct path.
- **Redesigned TUI**: ASCII banner on first load, rounded panels, an animated working
  indicator that stops when idle, and a search prompt pinned to the bottom.

### Package linkage, explained

The graph looked empty because **it genuinely was**: 0 of 2,683 stored CVEs carried package
linkage. NVD, Red Hat, Shodan, MITRE, CISA KEV and OSINT never name a package — only
GitHub's _reviewed_ advisories and OSV do.

The fix that scales is **OSV by package**, which is queried by package rather than by date,
so it returns a package's whole history and every record names its package. Verified:
`npm:next,npm:lodash,PyPI:django` over a 7-year window returned **225 advisories, 100%
package-bearing, reaching back to 2017**. NVD cannot do this — its API rejects ranges beyond
120 consecutive days.

**Current state:** 40 packages green; live stack carries 2,930 rows, 3,215 documents and a
graph of 1,386 nodes / 2,062 relationships.

---

## Superseded — 2026-09-02

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

- **2026-09-17** — v3: Kafka 4.1 (KRaft) in compose, `packages/common/kafka` (franz-go
  producer/consumer/codec/admin/tail), siphon Kafka publisher, cortex Kafka consumer
  group `intel-indexer`, `Flush` on the `SignalPublisher` port, topic tooling, and
  `task up` switched to run siphon and cortex as independent services over the broker.
  The pipe remains for `task ingest` / `task backfill`. Verified by SIGKILL-and-replay
  (787 records, lag 0) and a full stack restart.
- **2026-09-09** — Real-time alerts: `Subscription`/`AlertRule`/`Alert` domain,
  Elasticsearch percolator for reverse search, Redis deduplication, `AlertingService` gRPC
  API, and alert raising wired into ingest. Redis added to compose.
- **2026-09-08** — Post-v2 hardening: fixed TUI frame corruption from control characters in
  advisory titles, a latent `pid_of` bug in `system.sh`, and Shodan's empty-window 404s.
  Added continuous ingest (`task up`), GitHub org repository discovery, a `blastRadius`
  GraphQL query on nexus, and routed `deck` through the gateway. Redesigned the TUI.
- **2026-09-07** — **v2 complete**: Neo4j dependency graph, `Repository`/`Library`/`Author`
  entities, `IngestDependency` + `FindBlastRadius`, `IngestDependencies`/`GetBlastRadius`
  RPCs, siphon manifest scanner (`go.mod`/`package.json`) reporting over gRPC, CVE->package
  linkage from reviewed GitHub advisories and OSV, and the `deck` Bubble Tea TUI (live feed
  - ASCII graph explorer). Fixed: unreviewed-advisory blind spot, unpersisted affected
    packages, slow unauthenticated test pacing.
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
