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
| `6379`  | Redis (alert deduplication)     |
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
task scan                                   # scans the configured targets, then exits
task scan -- -repos gin-gonic/gin,eslint/eslint   # ad-hoc repositories
task scan -- -orgs vercel                   # discover and scan everything an owner has
```

**Prefer organizations over a hand-written list.** A repository nobody listed is invisible
to blast radius, which makes exposure look smaller than it is — the one direction this
system must not be wrong in. `SIPHON_REPO_ORGS=vercel` discovers them instead, skipping
forks and archived repositories, capped by `SIPHON_REPO_ORG_LIMIT` (default 20) because
each repository costs about three API calls. Discovery re-runs on every scan, so
repositories created later are picked up automatically.

Verified: `task scan -- -orgs vercel` discovered 20 repositories and wrote 611 dependency
edges in one command, taking `CVE-2026-64646` (Next.js) from 1 exposed repository to 6.

Reads each repository's `go.mod` and `package.json` from GitHub, parses them, and reports
them to cortex over gRPC, which writes:

```
(:Author)-[:MAINTAINS]->(:Repository)-[:DEPENDS_ON {version, direct}]->(:Library)
(:Repository)-[:PUBLISHES]->(:Library)-[:DEPENDS_ON]->(:Library)
```

`task scan` runs once and exits non-zero if any repository failed, so it works as a cron or
CI step. It ignores `SIPHON_REPO_SCAN_ENABLED` — that flag only controls whether a
long-running `task run:siphon` _also_ scans in the background on its own interval.

Configure the default targets in `.env`:

```bash
SIPHON_REPO_WATCHLIST=gin-gonic/gin,ajv-validator/ajv,eslint/eslint
SIPHON_REPO_ORGS=vercel
SIPHON_REPO_ORG_LIMIT=20
```

Each repository costs about three GitHub requests. Unauthenticated, you get 60 per hour.

---

## 3.3 Alerts (who wants to hear about it)

Reverse search: instead of everyone polling for what they care about, a rule is stored
once and every incoming vulnerability is matched against every rule.

```bash
# watch a library
task subscribe -- '{"tenant":"acme","name":"Next.js watch",
  "rule":{"packages":[{"ecosystem":"ECOSYSTEM_NPM","name":"next"}]}}'

# watch by text and severity
task subscribe -- '{"tenant":"acme","name":"Critical log4j",
  "rule":{"term":"log4j","minSeverity":"SEVERITY_CRITICAL"}}'

task alerts        # what has matched so far
```

A rule's conditions are **AND-ed**, so each one narrows the match. A rule with no
conditions is rejected rather than treated as "everything" — matching every advisory ever
ingested is the alert fatigue this platform exists to prevent, and it is far too easy to
create by accident.

Alerts are raised on ingest, so they appear as data flows in. Two things stop them
repeating:

- **Redis suppression** — the same rule stays quiet about the same CVE for
  `CORTEX_ALERT_DEDUPE_WINDOW` (default 1h). Advisories are re-observed on every poll and
  corrected for weeks.
- **Deterministic alert ids** (`subscription:cve`) — even with suppression flushed, a
  re-observation refreshes the existing alert instead of stacking a new one.

If Redis is unreachable, alerting **fails open**: alerts still fire, just without
suppression. A duplicate alert is an annoyance; a suppressed one is a missed vulnerability.

Verified: a `npm:next` subscription against a 7-year OSV backfill raised **57 alerts**,
re-ingesting the same advisories raised **0**, and flushing Redis then re-ingesting left
the row count unchanged at 57.

---

## 4. The CLI (deck)

The terminal UI.

```bash
task run:deck
```

By default it talks to **nexus over GraphQL**, so it is subject to the same edge policy as
every other client — authentication, rate limiting and per-tenant scoping, once those land
in v4. Set `DECK_TRANSPORT=grpc` to bypass the gateway and query cortex directly; that is
for debugging a cortex the gateway cannot reach, not for everyday use.

Requires nexus and cortex to be up (`task up` does that). Configure it in `.env` with
`DECK_TRANSPORT`, `DECK_GATEWAY_URL`, `DECK_FEED_QUERY`, `DECK_REFRESH_INTERVAL`.

The layout is a banner on first load, a tab bar with a working indicator, a bordered
results panel, and a search prompt pinned to the bottom:

```
██╗  ██╗██╗   ██╗██████╗ ███████╗██████╗ ██╗ ██████╗ ███╗   ██╗
██║  ██║╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██║██╔═══██╗████╗  ██║
███████║ ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║██║   ██║██╔██╗ ██║
██╔══██║  ╚██╔╝  ██╔═══╝ ██╔══╝  ██╔══██╗██║██║   ██║██║╚██╗██║
██║  ██║   ██║   ██║     ███████╗██║  ██║██║╚██████╔╝██║ ╚████║
╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝

HYPERION  ▌ 1 Live Feed   2 Graph Explorer                    updated 04:37:09
╭──────────────────────────────────────────────────────────────────────────────╮
│ Findings  query "next" — 25 findings                                         │
│ ▸ CVE-2026-64646      HIGH      Next.js: Unbounded Server Action payload …   │
│   CVE-2025-57822      MEDIUM    Next.js Improper Middleware Redirect … SSRF  │
╰──────────────────────────────────────────────────────────────────────────────╯
╭──────────────────────────────────────────────────────────────────────────────╮
│ search: next                                                                 │
╰──────────────────────────────────────────────────────────────────────────────╯
  ↑/↓ move · enter blast radius · tab switch · / search · r refresh · q quit
```

The banner stays pinned at the top for the whole session; the list beneath it scrolls to
keep the cursor in view, and shows which part you are looking at (`25 findings · 2–25`).
In a terminal too small to hold the banner and a usable list (under 68 columns or 24 rows)
the banner steps aside — the tab bar still carries the name.

Everything is sized to the terminal on purpose: Bubble Tea keeps only the _last_
terminal-height lines of a frame that is too tall, so an overflowing list would silently
delete the top of the screen rather than scroll.

It opens on the **Live Feed**: a list of findings refreshed on a timer (v2 polls; gRPC
streaming is v3). Select a finding and press `enter` to see its blast radius drawn as a
tree in the **Graph Explorer**.

### Results and paging

With no search term, the feed is the **latest findings, newest first**. Type `/` and a
term for a **best-match** search; `s` flips that search to newest-first and back.

Results load a page at a time. Scrolling onto the last loaded row fetches the next page
automatically (or press `n`), and the title shows where you are:

```
latest findings — 75 of 6,771  ·  50–73  ·  ↓ more
```

Refreshes (every `DECK_REFRESH_INTERVAL`, or `r`) re-fetch everything already loaded and keep
the selection on the same finding, even when newer ones push it down the list.

### Keys

| Key                  | Action                                                      |
| :------------------- | :---------------------------------------------------------- |
| `↑` / `↓`, `k` / `j` | move the cursor                                             |
| `g` / `G`            | jump to the first / last finding (also `home` / `end`)      |
| `pgup` / `pgdn`      | page up / down (also `ctrl+u` / `ctrl+d`)                   |
| `n` (or `]`)         | load the next page of results                               |
| `s`                  | switch a search between best match and newest               |
| `enter`              | open the blast radius for the selected finding              |
|                      | in the Graph Explorer, the movement keys scroll the tree    |
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
