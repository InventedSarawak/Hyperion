# Current Functionalities

Everything Hyperion can do **today**, one function at a time: what it does, how you use
it, and where it stops. This is a reference for the system as it stands, not a roadmap.
For what is planned see [TODO.md](../TODO.md); for what was cut and why see
[TECHNICAL-DEBT.md](TECHNICAL-DEBT.md); for how to start things see [RUNBOOK.md](RUNBOOK.md).

> **Kept current with every change**, like the changelog in
> [CURRENT_PROGRESS.md](../CURRENT_PROGRESS.md). If a function here is not what the code
> does, the document is wrong — fix it in the same change.
>
> Last updated: **2026-09-17**

---

## At a glance

```
  feeds ──▶ siphon ──(SignalDiscovered)──▶ cortex ──▶ Postgres   (store of record)
   (10)      │        pipe  or  Kafka        │    ├──▶ Elasticsearch (search, alert percolator)
             │                               │    ├──▶ Neo4j     (dependency graph)
             │  ◀──(gRPC: watchlist, scans)──┤    └──▶ Redis     (alert dedupe)
             ▼                               ▲
          GitHub (manifests)                 │ gRPC
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
source for what changed since its **watermark**, turns each record into a
`SignalDiscovered` event and publishes it to the Kafka topic (1.7).

**Each source has its own cadence and its own watermark.** The ten feeds publish at rates
that differ by orders of magnitude, so one interval and one window cannot suit them all:

| Sources                   | Asked every | First window |
| :------------------------ | :---------- | :----------- |
| nvd, mitre                | 10m         | 2h           |
| github_advisory           | 15m         | 12h          |
| gsd, shodan               | 30m         | 24h          |
| cisa_kev, vendor_advisory | 1h          | 48h          |
| osint                     | 2h          | 7d           |
| exploitdb, package_feed   | 6h          | 14d          |

Override one feed with `SIPHON_<SOURCE>_INTERVAL` / `SIPHON_<SOURCE>_LOOKBACK`. Setting
`SIPHON_POLL_INTERVAL` or `SIPHON_LOOKBACK` overrides **every** source at once, which is
for a deliberate catch-up and little else — leave them unset for per-source cadence.

This is what makes the slow feeds work at all. At the old global 2h window, Exploit-DB,
OSINT and the package feeds returned nothing essentially always, which read as a broken
adapter and was not one. Measured after the change: `vendor_advisory` fetched 13 records
over its 48h window where 2h found none.

**The watermark** is how far one source has read. It advances only when that source's poll
succeeds — never past a window that failed — and is stored in Redis under
`hyperion:siphon:watermark:source:<name>`, without an expiry, so it survives a restart.
One key per source, so a fast feed can never drag a slow one's position past records it
never read. With nothing stored, a source falls back to its own first window.

That difference is large in practice: restarting with a 2h lookback re-fetched 526 records
where resuming from a 54-second-old watermark fetched 59. It also closes a real gap — an
outage longer than the lookback used to skip everything published in between, permanently.

Redis being unreachable is a warning, not a stop: siphon falls back to the in-memory
watermark and keeps polling. `SIPHON_CHECKPOINT_ENABLED=false` turns persistence off.

**Deduplication.** Even with a watermark, a window is re-read whenever a poll fails or a
feed re-reports an unchanged record, so most of what a poll finds is something it has
already published. Each observation is fingerprinted — a digest of its id, title,
description, scores, references, aliases, kind, dates and affected packages — and a
fingerprint already stored in Redis (`hyperion:siphon:seen:*`, default 24h) is not
published again. Measured against one 3h NVD window re-read from scratch: **885 suppressed,
25 published**.

The fingerprint covers content, not just identity, so a **correction is still published** —
a score the advisory did not carry yesterday, or a newly named affected package, changes
the fingerprint. Suppressing those would be worse than the duplicates it avoids. List order
is normalised first, so a feed returning the same references shuffled does not look new.

> **After wiping cortex's databases**, clear the fingerprints too
> (`redis-cli --scan --pattern 'hyperion:siphon:seen:*' | xargs redis-cli DEL`) or run
> `task backfill` — otherwise siphon will not republish what it has already sent, and the
> empty store stays empty until each advisory is next amended.

As with the watermark, a store that errors fails open: the observation is published.
`SIPHON_DEDUPE_ENABLED=false` turns suppression off entirely.

**How to use.** `task up` runs it for you, detached (`HYPERION_INGEST=0` skips it).
`task ingest` runs one poll in the foreground, piped into cortex, so you can watch it.

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

**Limits.** The lookback is one global window, and so is the watermark: slow feeds
(Exploit-DB, OSINT) return nothing at 2h, and one source falling behind cannot be tracked
separately from the rest. NVD rejects windows over 120 days, so polling can never reach
history — that is what the backfill is for.

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

**Stopping it early.** Ctrl+C is a supported way to end a run that is measured in hours.
Siphon reports how much it published and exits clean, and cortex drops whatever was still
queued behind its workers rather than failing each one against the cancelled context —
it logs one line saying how many were dropped. Everything already stored stays stored, and
re-running is safe: ingest merges, so a repeated finding costs time, not correctness.

> `task backfill` itself still reports `exit status 1` after a Ctrl+C. That is `go run`,
> which exits non-zero whenever the toolchain process is interrupted, whatever the program
> it launched did. The services underneath exited cleanly.

**Limits.** The NVD half takes roughly an hour (NVD serves a 2,000-record page in ~40s);
the OSV half downloads ~300 MB. Records are published in the same event format as polling,
so a backfill can raise alerts for old findings if a subscription matches them. An
interrupted run leaves a gap rather than a clean resumption point: the events queued when
it stopped are not stored, and the fix is to run the backfill again over that range.

**History is stored, not announced.** Events from a backfill carry a `historical` flag.
cortex stores them exactly as it stores polled events — that is what lets a backfilled
record and a polled one merge into each other — but skips alerting and the live feed for
them. Loading ten years of advisories is not ten years of news, and a subscription
matching them would otherwise fire thousands of times for findings long since fixed.

**Retracted findings are not stored.** A CVE id can be assigned and then disowned — a
duplicate, a dispute, or something that was never a vulnerability. NVD marks these
`vulnStatus: Rejected` and replaces the description with a "Rejected reason:" note, so
nothing else about the record says it is not a finding: it keeps its id, its dates and its
place in the feed, with no score and no severity.

siphon reads that status and marks the event `withdrawn`; cortex removes the finding from
Postgres, the search index and the graph rather than storing it. The retraction is
_published_ rather than silently skipped, because a CVE is often rejected **after** it was
stored — a consumer that only hears about live findings has no way to learn that one it
already holds has stopped being one.

`task purge:withdrawn` removes those stored before this check existed;
`task purge:withdrawn -- -dry-run` lists them without removing anything.

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

A scan lists the repository's whole file tree in one request, picks every dependency file
it recognises in any folder — so each service in a monorepo is read — and parses it:

| Ecosystem | Files read                                                                                                                                                                                                                                               |
| :-------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Go        | `go.mod` (the repository's own unpublished modules, wired in by `replace`, are left out)                                                                                                                                                                 |
| npm       | `package.json` (dependencies direct, devDependencies indirect)                                                                                                                                                                                           |
| Python    | `requirements*.txt`, `pyproject.toml` (PEP 621, dependency groups, Poetry), `Pipfile`                                                                                                                                                                    |
| Rust      | `Cargo.toml`, including workspace and per-target tables                                                                                                                                                                                                  |
| Java      | `pom.xml`, `build.gradle` / `build.gradle.kts` (Android too), `libs.versions.toml`                                                                                                                                                                       |
| Ruby      | `Gemfile.lock` (exact versions), else `Gemfile`                                                                                                                                                                                                          |
| PHP       | `composer.json`                                                                                                                                                                                                                                          |
| .NET      | `.csproj` / `.fsproj` / `.vbproj`, `Directory.Packages.props`, `packages.config`                                                                                                                                                                         |
| Solidity  | `package.json` (Hardhat); git submodules (Foundry), read at the pinned commit — e.g. `@openzeppelin/contracts 5.5.0`; Soldeer entries in `foundry.toml`                                                                                                  |
| Lockfiles | `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` (v1 and Berry), `Cargo.lock`, `poetry.lock`, `composer.lock`, `Gemfile.lock`, `packages.lock.json` — read alongside the manifest; their exact versions win, and they bring in transitive dependencies |

Solidity libraries are recorded as the npm packages advisories name them by. Folders of
installed or generated code — `node_modules`, `vendor`, `.venv`, `dist`, `build`, `target`,
test fixtures, `examples` — are skipped, and at most 60 files are read per repository,
shallowest first. An empty repository scans as having nothing to read. Every dependency is
recorded with the file it came from and sent to cortex, and the outcome is reported back to
the watchlist, so a failure shows up in deck with its reason.

**How to use.** Add repositories in deck's Repositories tab (§4.4). There is no
repository list in `.env` any more.

**Limits.** A version held in a Gradle variable or a parent pom is unknown. RubyGems names
must match the advisory's spelling — gem ids are case-sensitive by specification, so
folding them would merge packages the registry says are different (NuGet, Packagist and
PyPI names are normalized). A Solidity library copied in as plain files, rather than a
submodule or package, is not seen. A scan costs two GitHub requests plus one per file and
per submodule; without a token GitHub allows 60 an hour.

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

### 1.7 Transport: the event backbone

**What it does.** Published events reach cortex over Kafka. A pipe remains for loading
data on demand. Both are adapters behind siphon's `SignalPublisher` port, and the workflow
that produces the events cannot tell which is in use.

|             | **Kafka** (default)                                                            | **Pipe**                                                                                            |
| :---------- | :----------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------- |
| Turn on     | nothing — it is the default                                                    | `SIPHON_KAFKA_ENABLED=false` + `CORTEX_CONSUME_STDIN=true`, which `task ingest`/`task backfill` set |
| Shape       | topic `hyperion.signals.v1`, 6 partitions                                      | `siphon \| cortex`, one pair of processes                                                           |
| Durability  | records are retained 7 days and replayed from the last committed offset        | none: if cortex dies mid-stream those events are gone                                               |
| Parallelism | one consumer goroutine per partition, across however many cortex processes run | `CORTEX_INGEST_WORKERS` inside one process                                                          |
| Coupling    | independent: either can restart without the other noticing                     | both halves live and die together                                                                   |
| Use it for  | the running system                                                             | `task ingest`, `task backfill`, running the chain in one command                                    |

**How you use it.** `task up` runs both halves, so there is nothing to turn on. To watch
it, or to drive either half by hand:

```bash
task topic:ui                 # the Kafka console at localhost:8081, in a browser
task topic:lag                # how far behind ingest is, per partition
task topic:tail -- -limit 5   # what is actually on the topic, decoded
task topic:describe           # partitions, leaders, settings
task run:siphon               # the publisher
task run:cortex               # the consumer, and the gRPC API
```

**When a record cannot be ingested.** Two different failures, answered differently:

| Failure                                              | What happens                                                                                                                                                          |
| :--------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The record will not **decode**                       | skipped, logged, committed past — retrying cannot change the answer                                                                                                   |
| The record will not **ingest** (Postgres refuses it) | retried 5 times with doubling backoff, then set aside on `hyperion.signals.v1.dlq` and committed past, so nothing behind it on that partition is blocked              |
| **Ten** records in a row are set aside               | cortex stops. That many consecutive failures is the database being down, not the records, and draining the topic into a dead-letter queue would be a silent migration |
| The dead-letter topic itself is unreachable          | cortex stops, uncommitted — the only remaining way not to lose the record                                                                                             |

```bash
task topic:dlq              # what failed, and why (empty is healthy)
task topic:dlq -- -replay   # put them back on the signal topic, unchanged
```

A dead-lettered record keeps its original bytes exactly, with the reason, the origin
partition and offset, the attempt count and the time in headers — so replaying it is
publishing the same record again, not reconstructing it.

**What it guarantees.**

- **Per-finding order.** A record's key is the finding id, so every report of one CVE —
  from any feed — lands on one partition and is merged by one consumer in arrival order.
  This is the same rule the pipe enforces with worker sharding, one level lower.
- **Nothing is lost on a crash.** Offsets are committed only after the records they cover
  have been ingested. A cortex that dies mid-batch replays that batch on restart.
- **A poll is not "done" until the broker has it.** Publishing is batched and
  asynchronous, so the poll flushes before its watermark advances — otherwise a restart
  would skip a window that was never actually published.
- **A record that cannot be decoded is skipped**, logged, and committed past, so one bad
  record cannot wedge every record behind it. A record that fails to _ingest_ is retried
  and then **stops the consumer** rather than being dropped: a database outage must not
  look like successful ingest.

**Seeing it.** The Kafka console (Redpanda Console) runs at **localhost:8081** with the
rest of the infrastructure, reading `packages/contracts/proto` so records render as
decoded JSON rather than base64. Topics, live messages, consumer-group membership and
per-partition lag, without a command. No authentication — local only.

**A second topic.** Repository manifest reads are published to
`hyperion.dependencies.v1` as `DependencyObserved`, keyed by repository full name, and
consumed by cortex as group `intel-graph`. Separate from the signal topic on purpose: a
backlog of advisories must not hold up the supply-chain graph. A scan therefore no longer
fails because cortex is restarting — verified by scanning with cortex stopped, then
watching it apply the observation on restart. If the broker is unreachable, scans fall
back to the gRPC call.

**Where it stops.** There is no dead-letter topic, so a record that fails
ingest permanently halts the consumer until someone intervenes. One broker, no
replication, no authentication: local development only.

---

## 2. Intelligence (cortex)

### 2.1 Ingest and correlation

**What it does.** Reads events from the pipe or the signal topic (1.7) and, per record: loads what is already stored,
**merges** the new observation into it, writes Postgres, re-indexes it in Elasticsearch,
links it to its packages in Neo4j, and matches it against alert rules. Records are
ingested on `CORTEX_INGEST_WORKERS` (default 8) parallel workers, sharded by id so one
record's observations are always merged in order; over Kafka that sharding is the
partition key instead, one goroutine per partition. A write that loses a race — another worker filing the same finding under a different id, a deadlock, a serialization failure — is re-read and merged again, up to three attempts.

**When the stores disagree.** Postgres is the truth; Elasticsearch and Neo4j are derived
from it. An index write that fails does not fail the ingest — losing the finding would be
worse than it being briefly unsearchable — so the row is left marked as behind
(`indexed_at` older than `last_seen_at`) and a reconciler settles it within
`CORTEX_RECONCILE_INTERVAL` (5m). Only rows known to be behind are read, which is normally
none. Stopping cortex is safe at any point: the batch in hand finishes within
`CORTEX_SHUTDOWN_GRACE` (30s) and is committed, and anything not committed is replayed.

**Merge rules** (how two feeds' views of one finding combine):

| Field             | Rule                                                                   |
| :---------------- | :--------------------------------------------------------------------- |
| title             | a real title wins; a title that only repeats the id is ignored         |
| description       | the best feed's wins — GitHub, then NVD, then vendors — not the newest |
| scores            | the most authoritative feed's win — NVD, then GitHub — not the newest  |
| references        | unioned, de-duplicated                                                 |
| sources           | unioned — which feeds reported it                                      |
| ids               | unioned; the canonical id is re-chosen from the union (1.3)            |
| kind              | malware if any feed says so, and it stays malware                      |
| affected packages | unioned by package; the first version range seen is kept               |
| dates             | the newest non-empty wins                                              |

NVD has no title field, so an NVD-only record has an empty title and every view shows its
description instead.

Description and scores are single values, so two feeds reporting one finding differently
means choosing between them. The choice is by **which feed is worth quoting**, not which
polled last — otherwise the same record shows NVD's paragraph at noon and GitHub's
write-up at one o'clock. The winning source is recorded on the row, a feed may always
correct itself, and values stored before this existed are replaced by the first attributed
observation.

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

**Version matching.** Depending on a library is not the same as being exposed to its flaw,
so every path from a repository to a finding is judged by comparing what the manifest
declares with what the advisory says is affected:

| Verdict           | Means                                                           | Example                                |
| :---------------- | :-------------------------------------------------------------- | :------------------------------------- |
| affected          | every version the declaration allows is affected                | `4.17.4` against `< 4.17.12`           |
| possibly affected | some allowed versions are; the installed one (lockfile) decides | `^5.11.0` against `>= 5.2.0, < 5.12.8` |
| not affected      | no allowed version is                                           | `^5.11.0` against `< 5.0.8`            |
| unknown           | one side cannot be read — a dist-tag, a git or file reference   | `latest`                               |

npm ranges are read as npm reads them (`^`, `~`, x-ranges, hyphen ranges, `||`, and
pre-releases kept out of a range unless named); a `go.mod` requirement is the exact version
built. Blast radius lists the exposed repositories first and marks the rest.

**Repository exposure — the other direction.** Given a repository, lists the findings its
dependencies reach (to the same depth as blast radius), each with its verdict, severity,
declared version and affected range, worst first. Findings its versions rule out are hidden
unless asked for. A repository the graph has never seen is reported as not scanned —
unknown, not clean.

**How to use.** deck's Repositories tab (`enter` on a repository); GraphQL
`repositoryExposure(fullName:, includeUnaffected:)`; gRPC
`IntelligenceService/GetRepositoryExposure`.

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

**Flags.** Every listed repository carries an exposure summary: how many critical and high
findings it may be exposed to, split into affected and possibly affected, each finding
counted once at its worst verdict. Malware counts as critical; an unknown verdict counts as
possible, since it cannot be ruled out. A repository that is not scanned, or had no
dependency file read, is marked "not computed" rather than clean. deck shows it as the RISK
column; GraphQL `trackedRepositories { exposure { … } }`.

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

### 2.6a Malware triage

**What it does.** A malicious package is only alerted on when a tracked repository
actually depends on it. The graph answers that — `MAL-…` records are linked to their
packages exactly as advisories are — and a finding nothing depends on is stored, indexed
and searchable, but nobody is told about it.

**How it is rated.** A malicious package is critical, and the domain says so rather than a
feed: no CVSS vector is ever written for one. The rating lives on the finding itself, so
it needs no invented score — and a finding rated without a score sorts by its rating's
CVSS floor (critical = 9.0) rather than as zero. That rating is stored in its own
`severity` column, so it survives a restart and a `task reindex`; before it had one, a
rating held on the finding rather than in a score was dropped on write and the record read
back as UNKNOWN.

**Why only malware.** OSV's malware dataset is ~240,000 records, nearly all typosquats of
popular names that nobody has installed; a subscription with a broad rule matching all of
them is indistinguishable from one matching none. An ordinary advisory is different: it is
worth hearing about whether or not that library is on the watchlist today, because the
watchlist changes.

**Where it stops.** A graph that cannot answer alerts anyway — noise is an annoyance,
silence about a package someone has installed is not. The records still cost storage and
index space.

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

### 3.1 Alerting through the gateway

**What it does.** Subscriptions and alerts are served by nexus, like everything else a
user touches:

| Operation   | GraphQL                                                                                             |
| :---------- | :-------------------------------------------------------------------------------------------------- |
| List rules  | `query { subscriptions { id name rule { term minSeverity } } }`                                     |
| Create one  | `mutation { createSubscription(name: "Log4j", rule: {term: "log4j", minSeverity: "HIGH"}) { id } }` |
| Remove one  | `mutation { deleteSubscription(id: "sub_…") }`                                                      |
| Read alerts | `query { alerts(limit: 20) { cveId reason vulnerability { title } } }`                              |

```bash
task subscribe -- Log4j '{"term":"log4j","minSeverity":"HIGH"}'
task subscriptions
task alerts
task unsubscribe -- sub_1234
```

**Why it matters.** These were reachable only over gRPC on :50051, which made `grpcurl`
the only way to use the platform's headline feature — and meant any authentication, API
key or per-tenant scoping added at the edge would not have applied to them. gRPC is now
internal transport only: service to service.

A rule with no conditions is refused at the edge, because it would match every finding
ever ingested — the alert fatigue the platform exists to prevent. The finding on an alert
is resolved when the alert is read, so a later correction shows through rather than the
alert freezing what was true when it fired.

## 4. Terminal UI (deck)

`task run:deck`. Four tabs; `tab` / `shift+tab` cycle them, `1`–`4` jump, `q` quits.
It goes through nexus by default (`DECK_TRANSPORT=grpc` talks to cortex directly).

### 4.0 The live feed

**What it does.** cortex announces each finding as it is stored;
`StreamFindings` (server-streaming gRPC) fans it out to whoever is watching, and nexus
relays it to HTTP clients as Server-Sent Events at **`GET /stream`**. deck subscribes on
start, so the feed updates when something lands rather than on its 30s timer.

```bash
curl -N http://localhost:8080/stream                 # watch it yourself
curl -N 'http://localhost:8080/stream?kind=malware'  # one kind only
```

**Three decisions worth knowing.**

- **Ingest never waits for a watcher.** A subscriber that has stopped reading — a frozen
  ssh session, a switched tab — fills its buffer (256) and then _misses_ findings. Losing
  updates to a terminal nobody is looking at is nothing; stalling ingestion behind one
  would be serious.
- **deck refreshes on arrival, it does not insert the streamed record.** What the list
  shows is what the query returns; rebuilding rows from the stream would duplicate the
  feed's ordering, malware filtering and version verdicts in a second place, free to
  disagree with the first. Arrivals are debounced to one refresh per 2s, because a
  backfill lands thousands a second.
- **The feed carries no history and is not durable.** It is in memory in cortex, and a
  client that was not connected has missed nothing it cannot ask Search for. The poll
  timer stays as the safety net: if the stream never connects or dies, deck keeps working
  exactly as it did before.

**Where it stops.** Nothing replays what was missed while disconnected, the stream has no
authentication (v4), and `console` does not consume it yet.

### 4.1 Live Feed (1)

The latest findings, newest first, refreshed every `DECK_REFRESH_INTERVAL` (30s). Each row
is **id · severity · headline**, where the headline is the title or, for records with none
(everything from NVD), the description. A malicious package shows **MALWARE** in place of a
severity. Malware is left out of the feed until `m` brings it in; searching for its exact
id (`MAL-…`, `GHSA-…`) finds it either way.

**Batches are folded.** Publishers file findings in runs, and the Linux kernel CNA files
them in runs of hundreds — consecutively numbered, every one of them opening "In the Linux
kernel, the following vulnerability has been resolved", and unscored, because that CNA
assigns no CVSS at all. Sorted newest-first they arrive adjacent, so one batch fills the
screen and everything else published that day is pushed below the fold.

Six or more consecutive findings sharing an opening collapse to a single row:

```
  CVE-2026-9001       CRITICAL  Remote code execution in Acme Server via crafted header
  CVE-2026-9002       HIGH      Path traversal in Widget CMS uploads
  + 198 findings      HIGH      In the Linux kernel, the following vulnerability … · high 1 · unknown 197
```

The header carries the count, **the worst rating inside the run**, and the breakdown by
rating, so a fold can never bury the one finding in two hundred that mattered — the row
above is rated HIGH because one of the 198 is. `enter` opens the run in place and closes it
again. Five or fewer in a row are left alone: they read perfectly well as ordinary rows,
and a fold over them is more chrome than it saves. A run stays open across a refresh, because
the fold is remembered by the wording it groups on rather than by a position in a list that
the refresh replaces.

| Key                         | Does                                                              |
| :-------------------------- | :---------------------------------------------------------------- |
| `/`                         | search (every key is text until `enter` / `esc`)                  |
| `s`                         | switch a search between best match and newest                     |
| `m`                         | include malware in the feed, or leave it out again                |
| `↑↓` `jk` `g G` `pgup pgdn` | move; reaching the end loads the next page                        |
| `n`                         | load the next page now                                            |
| `enter`                     | open the finding in **Details** (blast radius starts loading too) |
| `enter` (on a fold)         | open or close that run of findings                                |
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

Each repository is marked with its version verdict — `affected`, `possibly affected`,
`ruled out by version` or `version unknown` — with the declared and affected versions, so
the judgement can be checked by eye. Exposed repositories come first.

### 4.4 Repositories (4)

The watchlist, with each repository's scan state, dependency count, **risk** and last scan
(and the error, when a scan failed). While a scan is pending the list refreshes itself every
5s.

The RISK column flags what a repository may be exposed to: `▲ 1 crit 6 high`, `▲ 2 high`,
`3 lower` (medium and low only), `clean`, or `—` when nothing could be judged — not scanned
yet, or no dependency file it can read.

| Key     | Does                                                                   |
| :------ | :--------------------------------------------------------------------- |
| `enter` | open the repository's **findings**                                     |
| `a`     | add: type a GitHub user or org, `enter` lists its repositories         |
| `space` | (in the list) select / unselect and move down; tracked ones show `[✓]` |
| `a`     | (in the list) select every untracked repository, or clear them         |
| `enter` | (in the list) track the selection; scans begin within 30s              |
| `d`     | remove the selected repository — asks `y / n` first                    |
| `s`     | re-scan the selected repository now                                    |
| `r`     | reload the list                                                        |
| `esc`   | cancel adding                                                          |

**Findings.** Everything the selected repository may be exposed to, worst first: verdict,
severity (`MALWARE` for malicious packages), id, package, declared version → affected range,
and title, under a line counting its critical and high findings. From here a repository leads
to a finding, and the finding's blast radius back to every repository it reaches.

| Key     | Does                                                         |
| :------ | :----------------------------------------------------------- |
| `enter` | open the finding in **Details** (its blast radius loads too) |
| `b`     | open the finding straight in the **Graph Explorer**          |
| `u`     | show or hide the findings ruled out by version               |
| `r`     | reload                                                       |
| `esc`   | back to the list                                             |

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
