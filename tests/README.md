# Tests

Hyperion's tests sit at three levels. Where each one lives is decided by what
it needs to reach, not by taste — Go only lets a package's own module import
`internal/`, and every service keeps its adapters and use cases there.

| Level                | Lives in                                    | Needs                       | Run with                   |
| :------------------- | :------------------------------------------ | :-------------------------- | :------------------------- |
| Unit                 | beside the code, `apps/<service>/internal/` | nothing                     | `task test:go`             |
| Adapter integration  | beside the adapter it exercises             | the infra containers        | `task test:go:integration` |
| Service end-to-end   | `apps/<service>/internal/e2e`               | the infra containers        | `task test:go:integration` |
| Black-box end-to-end | `tests/e2e` (this module)                   | a running stack (`task up`) | `task test:e2e`            |

`task test:all` runs the lot, in that order.

## Why unit tests are not in this module

A shared test module cannot import `apps/cortex/internal/...`: Go allows that
only from within `apps/cortex/`. Centralising unit tests would mean making
every internal package public — cortex's Postgres adapter, its use cases, its
domain — and anything public is something another module may depend on and we
must keep stable. The boundary that keeps adapters swappable is worth more than
having every test under one path.

So: tests that need the inside of a service live inside it; tests that only
need its published contracts live here.

## What each end-to-end suite covers

- `apps/cortex/internal/e2e` — an event in the shape siphon publishes, through
  the real consumer, use cases, Postgres, Elasticsearch and Neo4j, and out as
  search results, a blast radius, and a repository's exposure judged against
  the versions a lockfile pins.
- `apps/siphon/internal/e2e` — a repository on a stand-in GitHub, through the
  scanner and every manifest parser, over real gRPC to a stand-in cortex, as
  the snapshot cortex will store.
- `tests/e2e` — a running Hyperion, driven the way a client drives it: cortex
  over gRPC and nexus over GraphQL, using nothing but the published contracts.
  It asserts what must hold whatever data the stack holds — every id resolves
  to one finding, malware stays out of ordinary search, and what a repository
  is exposed to agrees with what a finding's blast radius reaches.
