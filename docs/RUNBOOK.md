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
| `9092`  | Kafka (the signal topic)        |
| `8081`  | Kafka console (web UI)          |
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

1. starts Postgres, Elasticsearch, Neo4j, Redis and Kafka via Docker Compose;
2. **waits until each one actually answers** — Neo4j is probed with `cypher-shell` and
   Kafka by listing topics, not by a port check, so "up" means the thing will accept work;
3. applies cortex's Postgres migrations;
4. builds and launches `cortex` (gRPC + Kafka consumer), `nexus` (GraphQL) and `siphon`
   (ingest) as detached host processes, recording their PIDs in `.run/` so `task down`
   stops exactly what it started;
5. prints a status table.

Expected output:

```
  ready: postgres (0s)
  ready: elasticsearch (13s)
  ready: neo4j (0s)
  ready: redis (0s)
  ready: kafka (0s)
  ready: cortex gRPC :50051 (0s)
  ready: nexus HTTP :8080 (0s)
  ready: siphon (pid 1562946)

  COMPONENT        STATUS     DETAIL
  postgres         UP         accepting connections on :5432
  elasticsearch    UP         cluster yellow on :9200
  neo4j            UP         bolt on :7687, browser on :7474
  cortex           UP         pid 1562608 on :50051
  nexus            UP         pid 1562790 on :8080
  redis            UP         responding on :6379
  kafka            UP         broker on :9092, ingest lag 0
  siphon           UP         pid 1562946, polling every 10m
  data             -          postgres rows=546848 elasticsearch docs=546848
  graph            -          neo4j nodes=525776 relationships=287727
```

`task up` also starts **continuous ingestion**: siphon polls every
`SIPHON_POLL_INTERVAL` (default 10m) and publishes to the Kafka topic, and cortex consumes
that topic while it serves the API. They are **independent processes** — siphon keeps
publishing while cortex is down, and cortex resumes from its last committed offset when it
comes back. Nothing is lost in between, which is the whole reason the broker is there.

`ingest lag` in the status table is the number to watch: steady means ingest is merely
busy, climbing without bound means it has stopped.

Skip ingestion when you want a quiet stack:

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

### 3.1a History: `task backfill`

Polling only ever sees the last `SIPHON_LOOKBACK` (2h), and NVD refuses any window wider
than 120 days — so polling alone never reaches last year, let alone React2Shell
(December 2025). A **fresh stack needs one backfill**:

```bash
task backfill                                   # NVD + OSV exports, last 10 years
task backfill -- -backfill-from 2019-01-01      # a different start date
task backfill -- -backfill-sources osv          # just the package data (~15 min)
```

- **NVD** half: every CVE _published_ since the start date, in 120-day windows, four at a
  time. ~280,000 CVEs for ten years, about an hour (NVD takes ~40s per 2,000-record page).
- **OSV** half: the full exports for npm, PyPI, Go, Maven, crates.io, RubyGems, NuGet and
  Packagist (~300 MB). Every record names its package and version range — this is what
  gives blast radius something to traverse.

It exits when done. It is safe to run with the stack up, and `task restart` does not
interrupt it (only `task down` would, by stopping the databases).

To run it detached and watch it:

```bash
cd apps/siphon && go build -o ../../.run/bin/siphon ./cmd/worker && cd ../cortex && \
  go build -o ../../.run/bin/cortex ./cmd/server && cd ../.. && \
  setsid bash -c '.run/bin/siphon -backfill 2>>.run/backfill.log | \
    CORTEX_CONSUME_STDIN=true .run/bin/cortex >>.run/backfill-cortex.log 2>&1' </dev/null &
tail -f .run/backfill.log     # "backfill progress ... published=N" every 10,000
```

To check which feeds are reachable without ingesting anything:

```bash
task sources:check
```

### 3.2 Dependencies (who depends on what)

**Add repositories in the product, not in `.env`.** Open deck (`task run:deck`), press `4`
for the Repositories tab, then:

1. `a`, type a GitHub user or organization (`vercel`, `@torvalds`, or a pasted profile
   URL), `enter` — its repositories are listed, most recently pushed first;
2. `space` to select (it moves down as it goes), `a` to select every untracked one;
3. `enter` — they are tracked as **pending**, and siphon's scanner reads them within 30s.

The list refreshes itself until every scan finishes. `d` removes a repository (after a
`y / n`) — from the watchlist **and** from the graph. `s` re-scans one now.

The watchlist lives in cortex (Postgres); siphon polls it every
`SIPHON_REPO_WATCH_INTERVAL` (30s) and scans what is due — new ones at once, scanned ones
every `SIPHON_REPO_SCAN_INTERVAL` (6h), failed ones after `SIPHON_REPO_RETRY_INTERVAL`
(15m). The same operations are in GraphQL (`trackedRepositories`, `discoverRepositories`,
`trackRepositories`, `untrackRepository`).

Each scan lists the repository's files and reads every dependency file it recognises — Go,
npm, Python, Rust, Java and Gradle, Ruby, PHP, .NET, and Solidity through npm and git
submodules (CURRENT-FUNCTIONALITIES §1.4) — then writes:

```
(:Author)-[:MAINTAINS]->(:Repository)-[:DEPENDS_ON {version, direct}]->(:Library)
(:Repository)-[:PUBLISHES]->(:Library)-[:DEPENDS_ON]->(:Library)
```

Each repository costs two GitHub requests plus one per dependency file; unauthenticated you get 60 per hour,
so set `SIPHON_GITHUB_TOKEN` (scans) and `CORTEX_GITHUB_TOKEN` (the owner listing in the
Repositories tab — it can be the same token).

From a script:

```bash
task scan                                         # scan every tracked repository now
task scan -- -repos gin-gonic/gin,eslint/eslint   # ad-hoc, without tracking them
task scan -- -orgs vercel                         # an owner's repositories, without tracking
```

`task scan` exits non-zero if any repository failed, so it works as a cron or CI step.

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

Four tabs — `tab` / `shift+tab` cycle, `1`–`4` jump:

```
HYPERION  ▌ 1 Live Feed   2 Details   3 Graph Explorer   4 Repositories   updated 18:22:28
╭──────────────────────────────────────────────────────────────────────────────────────╮
│ Findings  query "react" · best match — 25 of 273  ·  ↓ more                          │
│ ▸ CVE-2021-41140      MEDIUM    Discourse-reactions is a plugin for the Discourse p… │
│   CVE-2018-6341       MEDIUM    React applications which rendered to HTML using the… │
╰──────────────────────────────────────────────────────────────────────────────────────╯
╭──────────────────────────────────────────────────────────────────────────────────────╮
│ search: react                                                                        │
╰──────────────────────────────────────────────────────────────────────────────────────╯
  ↑/↓ move · enter details · b blast radius · n more · s sort · / search · tab switch
```

| Tab              | Shows                                                                                                                                                     |
| :--------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1 Live Feed      | latest findings, or a search; **id · severity · title**, or the description when a record has no title (all of NVD)                                       |
| 2 Details        | the open finding in full: rating, dates, reporting feeds, every CVSS vector, affected packages with version ranges, the re-flowed description, references |
| 3 Graph Explorer | its blast radius, one tree per exposed repository                                                                                                         |
| 4 Repositories   | the watchlist, and adding / removing repositories (§3.2)                                                                                                  |

`enter` on a finding opens **Details** and starts its blast radius loading in the
background, so `enter` again (or `3`) shows the graph at once; `b` goes straight to the
graph; `esc` returns to the feed.

The banner stays pinned while there is room and steps aside in a small terminal; every
frame is sized to the terminal on purpose, because Bubble Tea keeps only the _last_
terminal-height lines of a frame that is too tall.

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

| Key                  | Where         | Action                                            |
| :------------------- | :------------ | :------------------------------------------------ |
| `↑` / `↓`, `k` / `j` | all           | move the cursor, or scroll Details and the graph  |
| `g` / `G`            | all           | first / last (also `home` / `end`)                |
| `pgup` / `pgdn`      | all           | page (also `ctrl+u` / `ctrl+d`)                   |
| `tab` / `shift+tab`  | all           | next / previous tab                               |
| `1`–`4`              | all           | jump to a tab                                     |
| `/`                  | all           | edit the search — `enter` runs it, `esc` discards |
| `n` (or `]`)         | Live Feed     | load the next page                                |
| `s`                  | Live Feed     | best match ⇄ newest                               |
| `enter`              | Live Feed     | open the finding in Details                       |
| `enter`, `b`         | Details       | its blast radius                                  |
| `b`                  | Live Feed     | straight to the blast radius                      |
| `esc`                | Details/Graph | back to the feed                                  |
| `a`                  | Repositories  | add from a GitHub user or org                     |
| `space` / `a`        | picker        | select one and move on / select all untracked     |
| `enter`              | picker        | track the selection                               |
| `d`, then `y`        | Repositories  | remove the selected repository                    |
| `s`                  | Repositories  | re-scan the selected repository                   |
| `r`                  | all           | refresh what the tab shows                        |
| `q`, `ctrl+c`        | all           | quit                                              |

While typing a search or an owner every key is text, so typing `j` searches for "j".

What the Graph Explorer draws — the repository first, then the path down to the finding:

```
vercel/commerce  (2 hops)
└── npm:next
    └── npm:react-server-dom-webpack
        └── CVE-2025-55182

not reached by any tracked repository
└── npm:react-server-dom-parcel
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

After changing Go code, restart the services without touching the databases:

```bash
task restart     # rebuild + restart cortex, nexus and the ingest loop; infra keeps running
```

Anything else writing to the databases — a backfill, a one-off scan — keeps running.

To stop everything:

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

- **No `vulnerable_packages`** → the CVE has no package linkage. Run the OSV backfill
  (`task backfill -- -backfill-sources osv`, §3.1a); NVD and most other feeds never name
  a package.
- **Packages but no `repositories`** → nothing you track depends on them. Add
  repositories in deck's Repositories tab (§3.2).
- **`UNAVAILABLE: dependency graph: no backend configured`** → cortex could not reach
  Neo4j. Check `task status` and `.run/cortex.log`.

**A search shows only CVE ids, no descriptions.** Fixed on 2026-09-11 — NVD records used
to carry their id as a placeholder title, which also overwrote real titles on merge. Data
ingested before then keeps the damage; `task down`, `task infra:down -- -v`, `task up`,
`task backfill` rebuilds it cleanly.

**A repository stays `failed` in the Repositories tab.** The error is on its row. Usually
a GitHub rate limit (set the tokens) or a private repository the token cannot read; it is
retried every 15 minutes, or press `s`.

**GitHub returns 401 or a rate-limit error.** Check `SIPHON_GITHUB_TOKEN` (scans) and
`CORTEX_GITHUB_TOKEN` (owner listing). Note the known
footgun: a blank setting written `KEY=   # hint` yields the _comment_ as the value. Keep
hints on their own line.

**Services vanished but containers are still up.** cortex and nexus are host processes
parented to `systemd --user`, so they die on desktop logout while the containers survive.
Run `task down && task up`. Containerising them is a v4 item.

**A source reports zero results.** Often correct rather than broken — `exploit_db`, `osint`
and `package_feed` publish a handful of records per _week_, so at a 2h lookback they
legitimately return nothing. Confirm with `task sources:check`.

---

## 7a. The event backbone

Two topics carry everything siphon observes:

| Topic                      | Carries                                                               | Consumer group  |
| :------------------------- | :-------------------------------------------------------------------- | :-------------- |
| `hyperion.signals.v1`      | advisories (`SignalDiscovered`), keyed by finding id                  | `intel-indexer` |
| `hyperion.dependencies.v1` | repository manifest reads (`DependencyObserved`), keyed by repository | `intel-graph`   |

They are separate so a backlog of advisories cannot hold up the supply-chain graph. `task up` runs both,
so there is nothing to turn on. To run them by hand, in two terminals:

```bash
task run:cortex          # consumes the topic, and serves the gRPC API
task run:siphon          # polls the feeds and publishes
```

### Measuring what it can carry

```bash
task loadtest                              # 10k findings at 1000/s
task loadtest -- -count 50000 -rate 0      # unpaced: find the ceiling
```

It uses a throwaway topic and deletes it afterwards, so it cannot touch the signal topic
or the databases. Measured on a dev laptop: **1,000/s sustained, 6ms mean latency** (18ms
max), and **~9,200/s unpaced**. High latency in an unpaced run is backlog, not slowness —
the producer is simply faster than the consumer.

That measures the broker and the client. To measure **cortex's ingest**, which is bounded
by Postgres, Elasticsearch and Neo4j rather than by Kafka, publish into the real topic and
watch it drain:

```bash
task loadtest -- -topic hyperion.signals.v1 -no-consume -count 5000
task topic:lag     # repeatedly, to watch cortex work through it
```

Note what that does: those synthetic findings are **really ingested**, under ids of the
form `CVE-9000-*`. Remove them afterwards, or do it on a stack you do not mind refilling.

### Watching findings arrive

```bash
curl -N http://localhost:8080/stream                 # every finding, as it lands
curl -N 'http://localhost:8080/stream?kind=malware'  # one kind only
```

`deck` subscribes to this on start, so its feed updates on arrival rather than on its
30-second timer. If the stream cannot connect, deck falls back to that timer and keeps
working — there is nothing to turn on and nothing that breaks when it is unavailable.

### In a browser

**<http://localhost:8081>** — the Kafka console, started with the rest of the
infrastructure. It shows topics, live messages, consumer groups and per-partition lag
without a single command.

```bash
task topic:ui     # opens it
```

Messages are **binary protobuf**, so the console is pointed at
`packages/contracts/proto` and decodes `hyperion.signals.v1` as
`hyperion.events.v1.SignalDiscovered` — you read events as JSON, straight from the
contracts, with no second copy to drift. If you add a topic carrying a different message
type, add a mapping to [`deploy/kafka-console.yaml`](../deploy/kafka-console.yaml) or its
records will show as base64.

The three views worth knowing:

| Where                                       | What it answers                                                           |
| :------------------------------------------ | :------------------------------------------------------------------------ |
| **Topics → hyperion.signals.v1 → Messages** | what is actually being published, decoded, newest first                   |
| **Consumer Groups → intel-indexer**         | is cortex attached, which partitions does it hold, how far behind is each |
| **Topics → … → Partitions**                 | whether records are spread evenly, or one key is hot                      |

It has **no authentication**, like everything else in the compose file. Local only.

### From the terminal

```bash
task topic:lag                           # per-partition lag for group intel-indexer
task topic:describe                      # partitions, leaders, settings
task topic:tail -- -limit 5 -from-start  # the events themselves, decoded to protojson
task topic:tail -- -keys                 # one line per record: key, partition, offset
```

**What to expect.** `task topic:lag` climbing means ingest is falling behind; climbing
without bound means it has stopped. Lag returning to 0 after a poll means everything
published has been stored _and committed_ — restarting cortex will not re-read it.

**Stopping cortex mid-batch is safe.** Offsets are committed only after the records they
cover are ingested, so the batch in flight is replayed on the next start. Duplicate
ingests merge to the same record, so the replay is invisible in the data. Verified by
killing cortex with `SIGKILL` before it had committed anything: on restart it re-read the
whole topic and finished at lag 0.

**When ingest sets a record aside.** `task topic:dlq` lists what failed, with the reason,
the attempt count and where it came from. An empty list is the healthy state, and the
command returns immediately when there is nothing there. `task topic:dlq -- -replay`
republishes them onto the signal topic unchanged, which is what to run after fixing
whatever rejected them. If cortex stopped with `records in a row could not be processed`,
that is the circuit breaker: something shared was broken, not the records — fix it and
restart, and nothing will have been lost.

**Which log is which.** `task logs` tails all three; individually,
`.run/cortex.log` is the **consumer** (group joins, ingest progress, retries, skipped
records), `.run/ingest.log` is **siphon** (per-source polls and what it published), and
`docker logs hyperion-kafka` is the **broker** (group coordination, rebalances). The lines
worth grepping:

```bash
grep 'consuming signals from kafka' .run/cortex.log                  # consumer attached?
grep -E 'retrying record|unprocessable|kafka ingest stopped' .run/cortex.log   # trouble
grep 'poll complete' .run/ingest.log | tail -3                       # is siphon publishing?
docker logs hyperion-kafka 2>&1 | grep 'group intel-indexer'         # rebalances
```

Note `.run/ingest.log` is appended to across runs, so older lines can predate the current
one — read the tail. And `ingest progress` only prints every 1000 findings, so a quiet
consumer log is not evidence of a stalled consumer; lag is.

**To bypass the broker entirely**, `task ingest` and `task backfill` still run
`siphon | cortex` as a pipe — one command, one self-contained report of what was stored.
They set `SIPHON_KAFKA_ENABLED=false` and `CORTEX_CONSUME_STDIN=true` themselves. The pipe
has no durability and no replay; it is for loading data on demand, not for running the
system.

**If ingest stops with an error**, cortex exits rather than skipping the record — a
database outage must not look like successful ingest. Fix the cause and restart; it
resumes at the last committed offset. A record that will not _decode_ is skipped and
logged instead, so one bad record cannot block the ones behind it.

---

## 8. Command reference

| Command                     | What it does                                         |
| :-------------------------- | :--------------------------------------------------- |
| `task up`                   | infra + cortex + nexus, with health gates            |
| `task down`                 | stop services, then infra (volumes kept)             |
| `task restart`              | rebuild + restart services; infra keeps running      |
| `task status`               | health, row/document/graph counts                    |
| `task logs`                 | tail cortex + nexus                                  |
| `task ingest`               | one siphon poll piped into cortex, bypassing Kafka   |
| `task backfill`             | load 10 years of NVD + OSV history, then exit        |
| `task scan`                 | scan every tracked repository now, then exit         |
| `task blast -- <CVE>`       | blast radius for one CVE (needs `grpcurl`)           |
| `task run:deck`             | the terminal UI                                      |
| `task sources:check`        | probe all ten ingestion sources and report           |
| `task run:siphon`           | ingestion worker, publishing to the signal topic     |
| `task run:cortex`           | intelligence service: consumes the topic, serves API |
| `task topic:tail`           | print the topic's events, decoded                    |
| `task topic:ui`             | open the Kafka console at :8081                      |
| `task topic:dlq`            | records ingest could not process, and why            |
| `task topic:dlq -- -replay` | put those records back on the signal topic           |
| `task topic:lag`            | how far behind ingest is, per partition              |
| `task topic:describe`       | the signal topic's partitions and settings           |
| `task infra:up` / `:down`   | containers only                                      |
| `task test:go`              | all Go tests                                         |
| `task test:go:integration`  | including Postgres / Elasticsearch / Neo4j / Kafka   |
| `task build:go`             | compile every Go service                             |
| `task codegen`              | regenerate Go from the protobuf contracts            |

## Watching ingest

Both halves of the pipe say what they are doing, and how much to say is a
setting rather than a rebuild.

| Setting                        | Default | Does                                                               |
| :----------------------------- | :------ | :----------------------------------------------------------------- |
| `CORTEX_INGEST_PROGRESS_EVERY` | 1000    | findings between cortex's `ingest progress` lines; 0 silences them |
| `CORTEX_LOG_LEVEL`             | info    | `debug` names every finding as it lands                            |
| `SIPHON_LOG_LEVEL`             | info    | `debug` names every signal as it is published                      |

At the default level a long run reports progress rather than going quiet:

```json
{
  "level": "INFO",
  "msg": "ingest progress",
  "ingested": 20000,
  "failed": 0,
  "per_second": 181,
  "latest": "CVE-2026-12345"
}
```

`failed` counts findings that could not be stored; the reasons are logged as
they happen, and a run that ends with any failures says so once more at the end.
`per_second` is the rate since the run began — useful for telling a slow
backfill from a stalled one.

To follow a single finding through, turn the level up for one run:

```bash
SIPHON_LOG_LEVEL=debug CORTEX_LOG_LEVEL=debug task ingest
```

That logs a line per signal published and a line per finding ingested, which is
far too much for a backfill of hundreds of thousands and exactly right when
something specific is missing.
