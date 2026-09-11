# Current Functionalities

Everything Hyperion can do **today**, one function at a time: what it does, how you use
it, and where it stops. This is a reference for the system as it stands, not a roadmap.
For what is planned see [TODO.md](../TODO.md); for what was cut and why see
[TECHNICAL-DEBT.md](TECHNICAL-DEBT.md); for how to start things see [RUNBOOK.md](RUNBOOK.md).

> **Kept current with every change**, like the changelog in
> [CURRENT_PROGRESS.md](../CURRENT_PROGRESS.md). If a function here is not what the code
> does, the document is wrong — fix it in the same change.
>
> Last updated: **2026-09-11**

---

## At a glance

```
  feeds ──▶ siphon ──(pipe: SignalDiscovered)──▶ cortex ──▶ Postgres   (store of record)
   (10)      │                                     │    ├──▶ Elasticsearch (search, alert percolator)
             │                                     │    ├──▶ Neo4j     (dependency graph)
             │  ◀──(gRPC: watchlist, scans)──────▶ │    └──▶ Redis     (alert dedupe)
             ▼                                     ▲
          GitHub (manifests)                       │ gRPC
                                                 nexus (GraphQL gateway) ◀── deck (terminal UI)
```

| Service | Role                                                   | State   |
| :------ | :----------------------------------------------------- | :------ |
| siphon  | Pulls vulnerability feeds and repository manifests     | working |
| cortex  | Stores, correlates, searches, graphs and alerts        | working |
| nexus   | GraphQL gateway in front of cortex                     | working |
| deck    | Terminal UI: feed, details, blast radius, repositories | working |
| ghost   | Local-AI CTF copilot                                   | stub    |
| relic   | Data-lake archiver                                     | stub    |
| credits | Billing                                                | stub    |
| console | Web dashboard                                          | stub    |

---

## 1. Ingestion (siphon)

### 1.1 Continuous polling

**What it does.** Every `SIPHON_POLL_INTERVAL` (default 10m) siphon asks each active
source for what changed in the last `SIPHON_LOOKBACK` (default 2h), turns each record into
a `SignalDiscovered` event and writes it to stdout, which is piped into cortex.

**How to use.** `task up` runs it for you, detached (`HYPERION_INGEST=0` skips it).
`task ingest` runs one pipeline in the foreground so you can watch it.

**The ten sources**

| #   | Source                  | What it contributes                                           | Credential                 |
| :-- | :---------------------- | :------------------------------------------------------------ | :------------------------- |
| 1   | NVD                     | Descriptions, CVSS v2/3/4 scores, references for every CVE    | optional key (faster)      |
| 2   | GitHub Advisory         | Titles, package + version ranges, **malware advisories**      | token strongly recommended |
| 3   | CISA KEV                | "Known exploited in the wild"                                 | none                       |
| 4   | Exploit-DB              | Public exploit exists                                         | none                       |
| 5   | MITRE CVE               | New ids before NVD analysis                                   | none                       |
| 6   | Vendor (Red Hat)        | Vendor severity and write-ups                                 | none                       |
| 7   | OSINT (Full Disclosure) | Mailing-list disclosures mentioning a CVE                     | none                       |
| 8   | Package feeds (OSV)     | Every advisory for the packages in `SIPHON_PACKAGE_WATCHLIST` | none                       |
| 9   | Shodan CVEDB (free)     | EPSS / KEV enrichment                                         | none                       |
| 10  | GSD (via OSV)           | Community CVE records                                         | none                       |

GitHub is read in **three passes** — everything, then `type=reviewed` (the only
advisories that name packages), then `type=malware` (compromised releases, which GitHub
never returns unless asked by name). Duplicates across passes are dropped.

**Limits.** The lookback is one global window; slow feeds (Exploit-DB, OSINT) return
nothing at 2h. The watermark is in memory, so a restart re-reads the lookback and a crash
longer than it loses records. NVD rejects windows over 120 days, so polling can never
reach history — that is what the backfill is for.

### 1.2 Backfill (history)

**What it does.** Loads years of history in one run, through the same pipe as polling:

- **NVD** — every CVE _published_ since the start date, walked in consecutive 120-day
  windows (NVD's maximum), four windows at a time. ~280,000 CVEs for ten years.
- **OSV exports** — OSV's full per-ecosystem archives for npm, PyPI, Go, Maven, crates.io,
  RubyGems, NuGet and Packagist. Every record names the package and version range it
  affects, which is what makes blast radius possible. React2Shell (CVE-2025-55182,
  `npm:react-server-dom-webpack`) arrives this way.

**How to use.**

```bash
task backfill                                            # both sources, last 10 years
task backfill -- -backfill-from 2019-01-01               # a different start date
task backfill -- -backfill-sources osv                   # just the package data
```

It exits when done (non-zero if a source could not be read in full). It can run while the
rest of the stack is up; `task restart` does not interrupt it.

**Limits.** The NVD half takes roughly an hour (NVD serves a 2,000-record page in ~40s);
the OSV half downloads ~300 MB. Records are published in the same event format as polling,
so a backfill can raise alerts for old findings if a subscription matches them.

### 1.3 Record identity

**What it does.** Keeps every id a finding is known by, and files it under one of them so
the same finding from different feeds lands on one record.

| Scheme                  | Issued by                    | Covers                                   |
| :---------------------- | :--------------------------- | :--------------------------------------- |
| `CVE-…`                 | CVE numbering authorities    | flaws in legitimate software, on request |
| `GHSA-…`                | GitHub                       | every GitHub advisory, including malware |
| `MAL-…`                 | OpenSSF malicious-packages   | malicious packages (never get a CVE)     |
| `PYSEC-…`, `GO-…`, etc. | ecosystem advisory databases | their own ecosystem                      |

The **canonical id** is the CVE, else the GHSA, else the MAL, else whatever id the finding
has; every other id is kept as an **alias**, and any of them finds the record. When a report
first links two ids — GitHub filed an advisory under its GHSA before a CVE existed, then OSV
reports the two together — the records **merge** and the finding moves to its CVE, taking its
first-seen time, alerts, search document and graph links with it.

Every finding also has a **kind**: `vulnerability` or `malware`. A finding is malware if any
feed says so or it carries a `MAL-` id, and it stays malware. OSV's malicious-package list is
ingested in full (it is the only record most malware ever gets); deck leaves it out of the
feed unless asked for (see 4.1).

Withdrawn OSV records are skipped.

### 1.4 Watchlist scanner (repositories)

**What it does.** Every `SIPHON_REPO_WATCH_INTERVAL` (default 30s) siphon reads the
watchlist from cortex and scans each repository that is due:

| State   | Due when                                                          |
| :------ | :---------------------------------------------------------------- |
| pending | immediately (just added, or re-queued)                            |
| scanned | its last scan is older than `SIPHON_REPO_SCAN_INTERVAL` (6h)      |
| failed  | its last attempt is older than `SIPHON_REPO_RETRY_INTERVAL` (15m) |

A scan reads the repository's `go.mod` and `package.json` from GitHub, parses direct and
indirect requirements (and the module the repository itself publishes), sends them to
cortex, and reports the outcome back to the watchlist — so a failure shows up in deck
with its reason.

**How to use.** Add repositories in deck's Repositories tab (§4.4). There is no
repository list in `.env` any more.

**Limits.** Only `go.mod` and `package.json` are understood (no lockfiles, no Python,
Java or Rust manifests yet). Each scan costs ~3 GitHub requests; without a token GitHub
allows 60 an hour.

### 1.5 One-off scans

```bash
task scan                                   # scan every tracked repository now
task scan -- -repos gin-gonic/gin,eslint/eslint   # scan named repositories (not tracked)
task scan -- -orgs vercel                   # scan an owner's repositories (not tracked)
```

Exits non-zero if anything failed, so it works from cron or CI.

### 1.6 Source health check

`task sources:check` probes every source once (default 24h window), prints which are
active, how many records each returned and why any failed, and exits non-zero if an active
source is broken. Publishes nothing.

---

## 2. Intelligence (cortex)

### 2.1 Ingest and correlation

**What it does.** Reads events from stdin and, per record: loads what is already stored,
**merges** the new observation into it, writes Postgres, re-indexes it in Elasticsearch,
links it to its packages in Neo4j, and matches it against alert rules. Records are
ingested on `CORTEX_INGEST_WORKERS` (default 8) parallel workers, sharded by id so one
record's observations are always merged in order. A write that loses a race — another worker filing the same finding under a different id, a deadlock, a serialization failure — is re-read and merged again, up to three attempts.

**Merge rules** (how two feeds' views of one finding combine):

| Field             | Rule                                                           |
| :---------------- | :------------------------------------------------------------- |
| title             | a real title wins; a title that only repeats the id is ignored |
| description       | the newest non-empty one wins                                  |
| scores            | the newest non-empty set wins                                  |
| references        | unioned, de-duplicated                                         |
| sources           | unioned — which feeds reported it                              |
| ids               | unioned; the canonical id is re-chosen from the union (1.3)    |
| kind              | malware if any feed says so, and it stays malware              |
| affected packages | unioned by package; the first version range seen is kept       |
| dates             | the newest non-empty wins                                      |

NVD has no title field, so an NVD-only record has an empty title and every view shows its
description instead.

### 2.2 Search

**What it does.** Full-text search over id, title, description and affected package
names, with typo tolerance ("log4shel"), partial words ("log4j" → "Log4j2"), exact-id
lookups by **any** of a finding's ids in any case (`ghsa-jfh8-…`, `mal-2026-2307`), and a flat bonus for records that _affect_ the library you named — so "next"
ranks Next.js advisories above text that merely contains the word.

Results can be limited to kinds of finding (`kinds: [VULNERABILITY]`); a term that is exactly
a finding's id finds it whatever its kind. Two orders: **best match** (ties broken newest-first) and **newest**. No term means the
live feed, newest first. Results page 25–200 at a time; totals are exact up to 10,000.

**How to use.** deck's feed (`/` to search, `s` to switch order), GraphQL `search`, or
gRPC `IntelligenceService/Search`.

**Limit.** Offset paging stops at the 10,000th result — narrow the query past that.

### 2.3 Finding details

**What it does.** Returns one finding in full from Postgres, the store of record —
including each affected package's **version range**, which search results leave out.

**How to use.** deck's Details tab, GraphQL `vulnerability(cveId:)`, or gRPC
`IntelligenceService/GetVulnerability`. Accepts any of a finding's ids — CVE, GHSA, MAL,
PYSEC, GO, … — and returns it under its canonical id with the rest as aliases.

### 2.4 Dependency graph and blast radius

**What it does.** Keeps the software supply chain as a graph:

```
(:Author)-[:MAINTAINS]->(:Repository)-[:DEPENDS_ON {version, direct}]->(:Library)
(:Repository)-[:PUBLISHES]->(:Library)-[:DEPENDS_ON]->(:Library)
(:Library)-[:AFFECTED_BY {affected_version}]->(:Vulnerability)
```

**Blast radius** answers _"which of my repositories does this finding reach, and how?"_:
it walks outwards from the libraries the finding affects, up to `max depth` hops
(default 3), and returns each exposed repository with the path to it and whether the
dependency is direct.

A finding with no package linkage returns "unknown", never "zero repositories" — the
distinction between _not affected_ and _never checked_ is the point.

**How to use.** deck's Graph Explorer, GraphQL `blastRadius`, `task blast -- CVE-…`. Any of a
finding's ids works (`GHSA-…`, `MAL-…`); the walk starts from its canonical id.

**Limits.** Transitive edges exist only for libraries published by a repository you
track; a dependency of a library nobody tracks looks one hop deep, so reach can be
understated.

### 2.5 Watchlist

**What it does.** The list of repositories blast radius can reach, stored in Postgres:

| Function | What it does                                                                                                                                              |
| :------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------- |
| list     | Every tracked repository with status, dependency count, last scan and last error                                                                          |
| discover | Lists a GitHub user's or organization's repositories (300 most recently pushed), marking the tracked ones                                                 |
| track    | Adds repositories as pending (accepts `owner/name` or a pasted GitHub URL); re-tracking re-queues a scan; a batch with any invalid name is rejected whole |
| untrack  | Removes the repository **and the edges its manifest contributed** from the graph, then from the list                                                      |
| report   | Records a scan's outcome (used by siphon)                                                                                                                 |

Names are case-insensitive, like GitHub's. Discovery uses `CORTEX_GITHUB_TOKEN` when set.

**How to use.** deck's Repositories tab; GraphQL `trackedRepositories`,
`discoverRepositories`, `trackRepositories`, `untrackRepository`; gRPC `WatchlistService`.

**Limits.** One shared list — no per-user or per-team lists until auth arrives (v4).
Libraries and library-to-library edges are kept on untrack, since other repositories and
advisories use them.

### 2.6 Real-time alerts

**What it does.** A subscription is a standing rule — free text, minimum severity,
packages, ecosystems, all AND-ed. Every ingested finding is matched against every rule at
once (Elasticsearch percolator), re-checked in the domain, de-duplicated in Redis for
`CORTEX_ALERT_DEDUPE_WINDOW` (1h), and stored as an alert.

**How to use.**

```bash
task subscribe -- '{"tenant":"acme","name":"Next.js watch","rule":{"packages":[{"ecosystem":"ECOSYSTEM_NPM","name":"next"}]}}'
task alerts
```

**Limits.** gRPC only — not yet in GraphQL or deck. Alerts are stored, not delivered
(no email, Slack or webhook yet). An empty rule is rejected.

### 2.7 Search reindex

`task reindex` rebuilds the Elasticsearch index from Postgres and removes documents
Postgres no longer has — after a mapping change, or to repair drift. The alert index is
rebuilt automatically at every cortex start.

---

## 3. Gateway (nexus)

GraphQL at `http://localhost:8080/graphql`, an interactive console at `/playground`, and
`/healthz`.

| Operation                                 | Kind     | Backed by     |
| :---------------------------------------- | :------- | :------------ |
| `search(term, sort, pageSize, pageToken)` | query    | §2.2          |
| `vulnerability(cveId)`                    | query    | §2.3          |
| `blastRadius(cveId, maxDepth, limit)`     | query    | §2.4          |
| `trackedRepositories`                     | query    | §2.5 list     |
| `discoverRepositories(owner, limit)`      | query    | §2.5 discover |
| `trackRepositories(fullNames)`            | mutation | §2.5 track    |
| `untrackRepository(fullName)`             | mutation | §2.5 untrack  |

Every `Vulnerability` carries `cveId, title, description, scores, references, publishedAt,
modifiedAt, sources, affectedPackages { package versionRange }`.

**Limits.** No authentication, rate limiting or tenancy yet (v4).

---

## 4. Terminal UI (deck)

`task run:deck`. Four tabs; `tab` / `shift+tab` cycle them, `1`–`4` jump, `q` quits.
It goes through nexus by default (`DECK_TRANSPORT=grpc` talks to cortex directly).

### 4.1 Live Feed (1)

The latest findings, newest first, refreshed every `DECK_REFRESH_INTERVAL` (30s). Each row
is **id · severity · headline**, where the headline is the title or, for records with none
(everything from NVD), the description. A malicious package shows **MALWARE** in place of a
severity. Malware is left out of the feed until `m` brings it in; searching for its exact
id (`MAL-…`, `GHSA-…`) finds it either way.

| Key                         | Does                                                              |
| :-------------------------- | :---------------------------------------------------------------- |
| `/`                         | search (every key is text until `enter` / `esc`)                  |
| `s`                         | switch a search between best match and newest                     |
| `m`                         | include malware in the feed, or leave it out again                |
| `↑↓` `jk` `g G` `pgup pgdn` | move; reaching the end loads the next page                        |
| `n`                         | load the next page now                                            |
| `enter`                     | open the finding in **Details** (blast radius starts loading too) |
| `b`                         | open the finding straight in the **Graph Explorer**               |
| `r`                         | refresh                                                           |

### 4.2 Details (2)

Everything known about the open finding: id and rating, title, a warning if it is a
malicious package, its other ids (aliases), published and modified dates, which feeds
reported it, every CVSS score with its vector, affected packages with
version ranges, the full description rendered from Markdown (headings, lists, code blocks and links, as GitHub advisories write them; plain NVD text re-flowed to the terminal), and every reference. It
shows the search result immediately and swaps in the full record when it arrives.

`↑↓` scroll · `enter` or `b` blast radius · `esc` back · `r` reload.

### 4.3 Graph Explorer (3)

The blast radius, one tree per exposed repository — repository first, then the path down
to the vulnerable package and the finding:

```
vercel/commerce  (2 hops)
└── npm:next
    └── npm:react-server-dom-webpack
        └── CVE-2025-55182

not reached by any tracked repository
└── npm:react-server-dom-parcel
```

`↑↓` scroll · `esc` back · `r` re-run the traversal.

### 4.4 Repositories (4)

The watchlist, with each repository's scan state, dependency count and last scan (and the
error, when a scan failed). While a scan is pending the list refreshes itself every 5s.

| Key     | Does                                                                   |
| :------ | :--------------------------------------------------------------------- |
| `a`     | add: type a GitHub user or org, `enter` lists its repositories         |
| `space` | (in the list) select / unselect and move down; tracked ones show `[✓]` |
| `a`     | (in the list) select every untracked repository, or clear them         |
| `enter` | (in the list) track the selection; scans begin within 30s              |
| `d`     | remove the selected repository — asks `y / n` first                    |
| `s`     | re-scan the selected repository now                                    |
| `r`     | reload the list                                                        |
| `esc`   | cancel adding                                                          |

### 4.5 Always

The logo stays pinned while there is room and steps aside in a small terminal; every frame
is sized to the terminal so nothing scrolls off the top; a spinner turns only while a
request is in flight.

---

## 5. Operating the stack

| Command                          | Does                                                                           |
| :------------------------------- | :----------------------------------------------------------------------------- |
| `task up`                        | Start Postgres, Elasticsearch, Neo4j, Redis, cortex, nexus and the ingest loop |
| `task down`                      | Stop everything, containers included                                           |
| `task restart`                   | Rebuild and restart cortex, nexus and ingest; databases keep running           |
| `task status`                    | What is up, with row, document, node and relationship counts                   |
| `task logs`                      | Tail the service logs                                                          |
| `task ingest`                    | One foreground `siphon \| cortex` pipeline                                     |
| `task backfill`                  | Load history (§1.2)                                                            |
| `task scan`                      | Scan tracked repositories now (§1.5)                                           |
| `task blast -- CVE-…`            | Blast radius over gRPC                                                         |
| `task reindex`                   | Rebuild the search index from Postgres                                         |
| `task subscribe` / `task alerts` | Create a subscription / list alerts                                            |
| `task sources:check`             | Probe every feed                                                               |
| `task test:go`                   | Unit tests                                                                     |
| `task test:go:integration`       | Unit tests plus Postgres, Elasticsearch, Neo4j and Redis suites                |
| `task codegen`                   | Regenerate Go from the protobuf contracts                                      |

Configuration lives in `.env` (documented key by key in `.env.sample`); a real environment
variable always overrides it.
