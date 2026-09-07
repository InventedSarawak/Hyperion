# Runbook: Starting and Stopping Hyperion

How to bring the system up, load it with data, query it, and shut it down.

Everything here is verified against the stack as of **v2** (2026-09-08). For what is
implemented versus scaffolded, see [TECHNICAL-DEBT.md](./TECHNICAL-DEBT.md); for the live
snapshot, see [../CURRENT_PROGRESS.md](../CURRENT_PROGRESS.md).

> **Local development only.** `deploy/docker-compose.yml` runs with security disabled and
> credentials committed. Never apply it anywhere but your own machine.

---

## 1. Prerequisites

| Tool             | Why                                         | Check               |
| :--------------- | :------------------------------------------ | :------------------ |
| Docker + Compose | Postgres, Elasticsearch, Neo4j              | `docker ps`         |
| Go 1.26+         | every backend service                       | `go version`        |
| Task             | the command runner used throughout          | `task --list`       |
| `grpcurl`        | optional — querying cortex directly         | `grpcurl --version` |
| `buf`            | optional — only needed to regenerate protos | `buf --version`     |

Copy the environment file once and fill in what you have:

```bash
cp .env.sample .env
```

**Every source works without a credential.** Keys only raise rate limits. The one worth
setting is `SIPHON_GITHUB_TOKEN` (60 → 5,000 requests/hour), because both the advisory feed
and the repository scanner use it.

### Ports the stack binds

| Port    | Component                       |
| :------ | :------------------------------ |
| `5432`  | Postgres                        |
| `9200`  | Elasticsearch                   |
| `7687`  | Neo4j (bolt — the driver)       |
| `7474`  | Neo4j (browser UI)              |
| `50051` | cortex (gRPC)                   |
| `8080`  | nexus (GraphQL + `/playground`) |

If another project already holds one of these, `task up` fails to bind and the stack comes
up half-started — see [Troubleshooting](#7-troubleshooting).

---

## 2. Start the system

```bash
task up
```

That single command:

1. starts Postgres, Elasticsearch and Neo4j via Docker Compose;
2. **waits until each one actually answers** — Neo4j is probed with `cypher-shell`, not a
   port check, so "up" means Bolt will accept a session;
3. applies cortex's Postgres migrations;
4. builds and launches `cortex` (gRPC) and `nexus` (GraphQL) as detached host processes,
   recording their PIDs in `.run/` so `task down` stops exactly what it started;
5. prints a status table.

Expected output:

```
  ready: postgres (0s)
  ready: elasticsearch (10s)
  ready: neo4j (0s)
  ready: cortex gRPC :50051 (0s)
  ready: nexus HTTP :8080 (0s)
  ready: ingest loop (pid 497024)

  COMPONENT        STATUS     DETAIL
  postgres         UP         accepting connections on :5432
  elasticsearch    UP         cluster yellow on :9200
  neo4j            UP         bolt on :7687, browser on :7474
  cortex           UP         pid 303430 on :50051
  nexus            UP         pid 303519 on :8080
  ingest           UP         pid 497024, polling every 10m
  data             -          postgres rows=2671 elasticsearch docs=2964
  graph            -          neo4j nodes=788 relationships=1104
```

`task up` also starts a **continuous ingest loop** — `siphon | cortex` running detached, so
the system keeps pulling fresh advisories on `SIPHON_POLL_INTERVAL` (default 10m) without
you holding a terminal open. It is tracked as its own process group, so `task down` stops
both halves.

Skip it when you want a quiet stack:

```bash
HYPERION_INGEST=0 task up
```

`task up` does **not** start `deck` — it is an interactive terminal app, covered below.

### Inspecting a running system

```bash
task status     # health of every component, plus row / document / graph counts
task logs       # tail cortex and nexus logs together
```

Elasticsearch reporting `yellow` is expected on a single node — replicas cannot be
assigned. It is cosmetic locally.

---

## 3. Load data

Blast radius is a join between two independent halves. You need both.

### 3.1 Vulnerabilities (what is vulnerable)

`task up` already runs this continuously. Use `task ingest` when you want a **foreground**
run you can watch — for a one-off backfill, or to see errors as they happen:

```bash
task ingest
```

Pipes one siphon poll straight into cortex: `siphon | cortex`. Records land in Postgres
(source of truth), Elasticsearch (search) and — where an advisory names affected packages —
Neo4j as `(:Library)-[:AFFECTED_BY]->(:Vulnerability)`.

siphon polls on a timer and does not exit on its own, so **press Ctrl-C** once the counts
stop moving.

> **Want history, and packages?** The OSV watchlist is the best source of both: it is
> queried _by package_ rather than by date, so it returns a package's whole advisory
> history, and every record names its affected package. Verified: `npm:next,npm:lodash,
PyPI:django` over a 7-year window returned **225 advisories, 100% package-bearing,
> reaching back to 2017**.
>
> ```bash
> cd apps/siphon && SIPHON_LOOKBACK=61320h \
>   SIPHON_PACKAGE_WATCHLIST='npm:next,npm:lodash,PyPI:django' \
>   go run ./cmd/worker 2>/dev/null | \
>   (cd ../cortex && CORTEX_CONSUME_STDIN=true go run ./cmd/server)
> ```

> **Seed with a long lookback on first run.** The default `SIPHON_LOOKBACK=2h` yields
> almost no package linkage, because only GitHub's _reviewed_ advisories carry package data
> and roughly one appears every six hours. Without linkage, blast radius has nothing to
> traverse. One time:
>
> ```bash
> cd apps/siphon && SIPHON_LOOKBACK=720h go run ./cmd/worker 2>/dev/null | \
>   (cd ../cortex && CORTEX_CONSUME_STDIN=true go run ./cmd/server)
> ```
>
> A 30-day window yields ~100 reviewed advisories, all package-bearing.

To check which feeds are reachable without ingesting anything:

```bash
task sources:check
```

### 3.2 Dependencies (who depends on what)

```bash
task scan                                   # scans SIPHON_REPO_WATCHLIST, then exits
task scan -- -repos gin-gonic/gin,eslint/eslint   # ad-hoc, ignores the watchlist
```

Reads each repository's `go.mod` and `package.json` from GitHub, parses them, and reports
them to cortex over gRPC, which writes:

```
(:Author)-[:MAINTAINS]->(:Repository)-[:DEPENDS_ON {version, direct}]->(:Library)
(:Repository)-[:PUBLISHES]->(:Library)-[:DEPENDS_ON]->(:Library)
```

`task scan` runs once and exits non-zero if any repository failed, so it works as a cron or
CI step. It ignores `SIPHON_REPO_SCAN_ENABLED` — that flag only controls whether a
long-running `task run:siphon` _also_ scans in the background on its own interval.

Edit the default watchlist in `.env`:

```bash
SIPHON_REPO_WATCHLIST=gin-gonic/gin,ajv-validator/ajv,eslint/eslint
```

Each repository costs about three GitHub requests. Unauthenticated, you get 60 per hour.

---

## 4. The CLI (deck)

The terminal UI. It talks to cortex directly over gRPC — not through the nexus gateway —
because it is an operator's console on the internal network.

```bash
task run:deck
```

Requires cortex to be up (`task up` does that). Configure it in `.env` with
`DECK_CORTEX_GRPC_ADDR`, `DECK_FEED_QUERY`, `DECK_REFRESH_INTERVAL`.

It opens on the **Live Feed**: a list of findings refreshed on a timer (v2 polls; gRPC
streaming is v3). Select a finding and press `enter` to see its blast radius drawn as a
tree in the **Graph Explorer**.

### Keys

| Key                  | Action                                                      |
| :------------------- | :---------------------------------------------------------- |
| `↑` / `↓`, `k` / `j` | move the cursor                                             |
| `g` / `G`            | jump to the first / last finding                            |
| `enter`              | open the blast radius for the selected finding              |
| `tab`                | switch between the two views                                |
| `1` / `2`            | jump straight to Live Feed / Graph Explorer                 |
| `/`                  | edit the search query — `enter` to run it, `esc` to discard |
| `r`                  | refresh now                                                 |
| `q`, `ctrl+c`        | quit                                                        |

While `/` is active every key is text, so typing `j` searches for "j" rather than moving
the cursor.

What the Graph Explorer draws:

```
CVE-2026-13676
└── npm:fast-uri
    ├── ajv-validator/ajv  (direct)
    ├── eslint/eslint  (2 hops)
    │   └── eslint/eslint → npm:ajv → npm:fast-uri
    └── fleetdm/fleet  (3 hops)
        └── fleetdm/fleet → npm:eslint → npm:ajv → npm:fast-uri
```

If a CVE has no package linkage the tree says **"blast radius unknown"** rather than
showing zero repositories. That distinction is deliberate: an empty answer would read as
"nothing is affected", which is the most dangerous thing this system could tell you.

---

## 5. Other ways to query

**GraphQL** — browser console at <http://localhost:8080/playground>, or:

```bash
curl -s -X POST http://localhost:8080/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{ search(term:\"log4j\", pageSize:5){ hits{ score vulnerability{ cveId title } } } }"}'
```

**Blast radius over gRPC** (cortex has reflection enabled, so `grpcurl` needs no protos):

```bash
task blast -- CVE-2026-13676

grpcurl -plaintext localhost:50051 list                     # explore the API
grpcurl -plaintext -d '{"query":"log4j","page_size":5}' \
  localhost:50051 hyperion.intelligence.v1.IntelligenceService/Search
```

**Neo4j browser** — <http://localhost:7474>, user `neo4j`, password `hyperion`:

```cypher
MATCH (r:Repository)-[:DEPENDS_ON*1..3]->(l:Library)-[:AFFECTED_BY]->(v:Vulnerability)
RETURN r.full_name, l.name, v.cve_id LIMIT 25;
```

**Postgres**:

```bash
docker exec -it hyperion-postgres psql -U hyperion -d hyperion -c \
  'SELECT cve_id, sources FROM vulnerabilities LIMIT 5;'
```

---

## 6. Stop the system

```bash
task down
```

Stops cortex and nexus (reclaiming their ports even if a process was orphaned), then stops
and removes the containers. **Volumes are kept**, so your data survives.

To wipe the data as well:

```bash
task infra:down -- -v
```

That drops the Postgres, Elasticsearch and Neo4j volumes. Everything ingested is gone; the
schema is recreated on the next `task up`.

Individual services, when you want to run one in the foreground:

```bash
task run:cortex     # gRPC intelligence service
task run:nexus      # GraphQL gateway
task run:siphon     # ingestion worker (events to stdout, logs to stderr)
```

---

## 7. Troubleshooting

**`task up` fails to bind a port.** Another project is holding it. Find the owner and stop
it, or move the other project:

```bash
docker ps --filter "publish=5432"
ss -ltnp | grep 5432
```

Hyperion currently hardcodes its host ports in `deploy/docker-compose.yml`; making them
configurable is registered in [TECHNICAL-DEBT.md](./TECHNICAL-DEBT.md).

**Blast radius returns nothing.** Distinguish the two cases first — the response separates
`vulnerable_packages` from `repositories` precisely so you can:

- **No `vulnerable_packages`** → the CVE has no package linkage. Re-run ingestion with a
  long `SIPHON_LOOKBACK` (see §3.1); most sources never name a package.
- **Packages but no `repositories`** → nothing you have scanned depends on them. Add
  repositories to the watchlist and run `task scan`.
- **`UNAVAILABLE: dependency graph: no backend configured`** → cortex could not reach
  Neo4j. Check `task status` and `.run/cortex.log`.

**GitHub returns 401 or a rate-limit error.** Check `SIPHON_GITHUB_TOKEN`. Note the known
footgun: a blank setting written `KEY=   # hint` yields the _comment_ as the value. Keep
hints on their own line.

**Services vanished but containers are still up.** cortex and nexus are host processes
parented to `systemd --user`, so they die on desktop logout while the containers survive.
Run `task down && task up`. Containerising them is a v4 item.

**A source reports zero results.** Often correct rather than broken — `exploit_db`, `osint`
and `package_feed` publish a handful of records per _week_, so at a 2h lookback they
legitimately return nothing. Confirm with `task sources:check`.

---

## 8. Command reference

| Command                    | What it does                                        |
| :------------------------- | :-------------------------------------------------- |
| `task up`                  | infra + cortex + nexus, with health gates           |
| `task down`                | stop services, then infra (volumes kept)            |
| `task status`              | health, row/document/graph counts                   |
| `task logs`                | tail cortex + nexus                                 |
| `task ingest`              | one siphon poll piped into cortex (Ctrl-C to stop)  |
| `task scan`                | scan watched repositories into the graph, then exit |
| `task blast -- <CVE>`      | blast radius for one CVE (needs `grpcurl`)          |
| `task run:deck`            | the terminal UI                                     |
| `task sources:check`       | probe all ten ingestion sources and report          |
| `task infra:up` / `:down`  | containers only                                     |
| `task test:go`             | all Go tests                                        |
| `task test:go:integration` | including Postgres / Elasticsearch / Neo4j suites   |
| `task build:go`            | compile every Go service                            |
| `task codegen`             | regenerate Go from the protobuf contracts           |
