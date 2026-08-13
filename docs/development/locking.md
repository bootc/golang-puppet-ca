# Locking and concurrency

Reference for contributors (human or AI) touching any code path that reads or
mutates shared CA state. Deploying `openvox-ca` needs none of this. Companion
documents: [storage internals](storage-internals.md) for the backend contract
and [the inventory store](inventory-store.md) for inventory integrity.

The one-paragraph version: **mutations serialise on cluster-wide named locks
taken through `StorageService.WithLock`; read-only paths never take a
distributed lock** — they use in-memory caches and process-local read locks
only. When you add a code path, decide which side of that line it is on first,
and everything else follows.

## The three tiers

Locking happens at three distinct levels. They are not interchangeable — each
protects against a different class of interleaving.

| Tier | Mechanism | Protects against | Defined in |
| --- | --- | --- | --- |
| Cluster-wide named locks | `StorageService.WithLock(ctx, name, fn)` | Concurrent mutations from **other replicas** sharing the same backend, or failing that from **other processes on this host** | [storage.go](../../internal/storage/storage.go) |
| Storage-service mutexes | `serialMu`, `inventoryMu` (RW), `crlMu` (RW), `fileMu` (RW) | Interleaved compound storage operations **within this process** | [storage.go](../../internal/storage/storage.go) |
| CA in-memory state | `ca.CA.mu` (RW) | Torn reads/writes of the CA's **in-memory caches** | [ca.go](../../internal/ca/ca.go) |

### Tier 1: cluster-wide named locks (`WithLock`)

`StorageService.WithLock` runs `fn` while holding a named lock, taking the
strongest lock the backend offers. Three sub-tiers, tried in order:

1. **`Locker`** — coordinated across every replica sharing the backend (etcd,
   Redis, PostgreSQL, MySQL).
2. **`SameHostLocker`** — coordinated across every process on this host, and
   across no more than that. An exclusive `flock(2)` on a file per lock name,
   provided by the two single-node backends (filesystem, SQLite).
3. A process-local named `sync.Mutex`, for a backend offering neither.

The two capabilities are deliberately separate interfaces rather than one with
a quality setting. A caller deciding whether it is safe to start a second
*replica* must not be told "yes" because a second *process* is handled, so the
filesystem backend implements `SameHostLocker` and still implements no
`Locker`, and SQLite still answers `ErrDistributedLockingUnsupported`. Nothing
that probes for cross-node coordination changed its answer when same-host
locking landed.

What sub-tier 2 buys is the case an operator actually meets: an
`openvox-ca-ctl` command, or a second server, run against the same store on the
same host as a live one. Before it, both wrote with no coordination at all —
two issuers could each pass `evictRevokedLocked` and produce two certificates
for one subject. Now the second process waits, and then fails with "another
process on this host holds the CA lock" if it waits past its deadline.

Read that as scoped to the lock names, because it is. Two processes contending
for the *same* name — the same subject, the CRL, bootstrap, a migration — now
exclude each other. Two processes issuing for **different** subjects hold
different `subject:<name>` locks and are not serialised against each other at
all, so the inventory-HMAC corruption in the motivating issue is *not* fully
closed by this tier: `AppendInventory` is guarded by `inventoryMu` and no
cluster lock, so its append and integrity rewrite can still interleave and
leave an HMAC covering a blob that never existed, which fails `InitHMAC` at the
*next* start. That is [#204](https://github.com/voxpupuli/openvox-ca/issues/204)
in the known gaps below, and the fix for it inherits cross-process coverage on
these backends from this tier.

What it does not buy is clustering. `flock(2)` is not a sound basis for
coordination across hosts — over NFS it depends on the server, the mount
options and the client's `lockd`, none of which this code can see — so shared
storage across hosts stays unsupported for both backends, exactly as
[storage backends](../storage-backends.md) scopes them.

The lock names are part of the cross-replica protocol: every replica must agree
on them, so they are **stable across releases**. Names taken through
`WithLock` by the CA layer are defined in
[init.go](../../internal/ca/init.go) — with one mirror: `migrateLockName` in
[migrate.go](../../internal/storage/migrate.go) redefines `"bootstrap"`
independently (the `internal/storage` package cannot import `internal/ca`), so
the two are coupled only by the string literal and must be renamed together.
Storage-layer and backend-internal locks live beside the code that takes them,
for the same import-direction reason: `lockNameHMACKey` (`"hmac-key"`) in
[storage.go](../../internal/storage/storage.go) and `etcdDecomposeLockName`
(`"inventory-decompose"`) in
[etcd_inventory.go](../../internal/storage/etcd_inventory.go). They are no
less protocol for it.

One name in `internal/storage` is not a lock in that sense at all:
`lockProbeName` in [storage.go](../../internal/storage/storage.go) defines
`capability-probe`, which `SupportsDistributedLocking` acquires and releases
purely to find out whether the backend coordinates across processes. It sits
outside every namespace above so it can never contend with an operation in
flight — see its row below.

| Lock name | Serialises | Taken by |
| --- | --- | --- |
| `bootstrap` | First-run CA generation; seeding supporting state (CRL/inventory/serial) for a mounted cert+key; whole-store migration | `CA.Init`, `CA.seedSupportingState`, `storage.MigrateService` (which reuses the name deliberately so a migration and a bootstrapping server exclude each other) |
| `crl` | Every CRL read-modify-write (read entries → re-sign → write), **and** the pending-supersession list's read-modify-write, which has to be mutual with the revocations it schedules | `Revoke`, `RevokeSerial`, `ReissueCRL`, `RefreshCRLIfDue`, `CleanupExpiredCerts`, `ReconcileSuperseded`, the revoke step inside `Clean`, and the retire step inside `Renew`, `AutoRenew` — "retire" because only those two can defer it to the list; `Clean` always revokes inline |
| `subject:<name>` | The whole lifecycle of one subject: evict/save CSR/sign/delete CSR/renew/import/clean/revoke/generate | `SaveRequest`, `Sign`, `SignWithTTL`, `DeleteRequest`, `Renew`, `AutoRenew`, `Clean`, `ImportCertificate`, `Revoke`, `Generate`/`GenerateWithOptions` |
| `hmac-key` | Generating and persisting the inventory HMAC key when none is usable — a cold start, or a stored blob of the wrong length | `StorageService.EnsureHMACKey`, reached from `CA.Init` → `InitHMAC` and from `MigrateService` → `RebuildInventoryHMAC`. Deliberately **not** `bootstrap`: the migration already holds that name across the rebuild, and `WithLock` is not reentrant |
| `sql-schema-migrate` | One schema-migration run, so two replicas starting at once do not migrate concurrently (SQL backends only) | `SQLBackend.EnsureReady` |
| `inventory-decompose` | One-time legacy inventory blob conversion (etcd backend only) on the first start after upgrading | `EtcdBackend.decomposeLegacyInventory`, from `EnsureReady` |
| `capability-probe` | Nothing. Acquired and released immediately by `StorageService.SupportsDistributedLocking` to find out whether this backend coordinates locks across processes at all | The offline `openvox-ca generate` pre-flight. The name sits deliberately outside every namespace above so a probe can never contend with an operation in flight |

How each backend provides the distributed lock (a summary — the full per-backend
mechanism, key layouts and transaction/retry detail lives in
[storage internals](storage-internals.md), which owns it):

| Backend | Mechanism | Crash recovery |
| --- | --- | --- |
| etcd | `concurrency.Mutex` under `<prefix>/locks/<name>` on a lease-backed session (30 s TTL) | Lease expires within the TTL, lock releases |
| Redis/Valkey | `SET NX PX` with a per-acquisition random token; a heartbeat goroutine extends the TTL while held; unlock is a Lua compare-token-and-delete | Key expires within the TTL, lock releases |
| PostgreSQL | `pg_advisory_lock` (session-level) on a dedicated pooled connection | Only when the server reaps the session — no TTL (see below) |
| MySQL/MariaDB | `GET_LOCK` on a dedicated connection, polled with a 1 s server-side wait so context cancellation is honoured | Only when the server reaps the session — no TTL (see below) |
| SQLite, filesystem | No cross-node lock — `ErrDistributedLockingUnsupported` / no `Locker`. Same-host only: an exclusive `flock(2)` per lock name, under `<cadir>/locks/` or a `.<db>.locks/` directory beside the SQLite file | Kernel releases the lock when the descriptor closes or the holder dies — no stale lock, no TTL |
| Overlay | Delegates to the base backend's `Locker`, then to its `SameHostLocker`; reports unsupported when the base has neither | as base |

The same-host lock is the one entry in that table with nothing to recover.
`flock(2)` is held by an open file description, so the kernel drops it when the
descriptor closes or the process dies, however it dies — which is why it was
chosen over an `O_EXCL` lockfile, whose stale-lock cleanup and PID-liveness
guessing are the maintenance burden that makes lockfiles a poor fit for a
service operators restart and kill. Consequences worth knowing:

- **Lock files are never removed, and deleting one on a live store is
  unsafe** — not merely useless. Unlinking a file another process is blocked on
  lets a third create a fresh inode at that name and take a lock the blocked one
  is still waiting for, so both then believe they hold it. Empty 0600 files are
  the cheaper side of that trade. They can be swept while nothing is using the
  store; while anything is, sweeping them silently defeats the exclusion.
- **The directory grows with the fleet.** One file per distinct lock name means
  `bootstrap`, `crl` — and one per subject, since `subject:<name>` is a lock
  name. It is roughly an inode per node the CA has ever locked, it never
  shrinks (`Clean` retires a node's certificate, not its lock file), and it
  rides along in any `tar <cadir>/` backup.
- **The lock identity is the path, not the inode.** Two processes exclude each
  other only if they resolve the same lock directory. The path is made
  absolute, so differently spelled configuration for one store still agrees,
  but a *relative* `cadir` or `sql_dsn` resolved from two different working
  directories will not, and neither will one store reached through two
  different symlinks. Configure absolute paths.
- **A wait announces itself once.** The first refused attempt logs `Waiting for
  the CA lock`, naming the lock and the file. Without it an `openvox-ca-ctl
  migrate` — which inherits a context with no deadline — would print nothing and
  never return, and a lock wait would be indistinguishable from a hang.
- **A store nobody can write disables the tier; a lock path this process
  cannot write does not.** Three outcomes, and which one you get depends on the
  errno and the call site:
  - *Cannot create the lock directory* (`EROFS` or `EACCES`) — the capability
    reports itself absent and `WithLock` drops to the mutex. On both backends
    that directory sits where the store's own writes go, so failing to create it
    really does mean the store cannot be written, and a store with no writer has
    nothing to exclude. `openvox-ca-ctl migrate` takes `bootstrap` on a source it
    only reads, and that source may be a read-only snapshot.
  - *Cannot open a lock file in a directory that already exists*, with
    `EACCES` — a **hard error**. `os.MkdirAll` returns nil for an existing
    directory without checking writability, so this says nothing about the
    store: it means the lock directory or the lock file belongs to another user,
    typically because a `ctl` command was run under sudo against a cadir the
    server owns. Downgrading would silently return the server to its pre-#187
    behaviour for the rest of its life while the root process went on taking
    flocks it believed were exclusive — both sides think they are safe, which is
    worse than neither being. The error names whichever of the file and the
    directory is actually foreign, and its uid, because a sudo `ctl` leaves a
    root-owned *file* inside a server-owned directory as often as it creates the
    directory itself.
  - *`EROFS` at either site, a filesystem that rejects BSD locks*
    (`EOPNOTSUPP`, `ENOSYS`), or a kernel out of lock records (`ENOLCK`) —
    absent again, not fatal. `EROFS` says nothing about ownership, and a store
    nobody can lock is the runtime form of a platform without `flock(2)`;
    failing hard there would take down a CA that worked before this tier
    existed. The three are grouped by what they cost, not by what they mean:
    the first two are properties of the mount and the third is transient
    pressure, so read the errno in the log line rather than the message.

Crash recovery is not uniform across the distributed backends. etcd and Redis self-heal
within the lock TTL (30 s): a crashed holder's lease or key expires and the lock
frees itself, which is what the 60 s `lockTimeout` below is sized to ride out.
The SQL advisory locks have **no TTL** — `pg_advisory_lock` and `GET_LOCK`
persist until the database tears the holder's session down, and after a hard
host loss or network partition that is governed by the server's own keepalive
settings (PostgreSQL `tcp_keepalives_idle`, MySQL `wait_timeout`), whose
defaults are measured in hours. A crashed replica can therefore hold `crl` or
`subject:<name>` far beyond `lockTimeout` while every surviving replica's
revoke/sign fails at that timeout; the recovery action is to terminate the
orphaned backend session (`pg_terminate_backend` / `KILL`) or to lower those
server-side keepalives for HA deployments.

Every implementation of either capability first takes a **per-name
process-local mutex** before touching the network or the filesystem. This is
load-bearing, not an optimisation: etcd's `concurrency.Mutex` is not safe for
re-entry on one session, on the SQL backends it stops N in-process callers each
pinning a pooled connection just to queue on the same lock, and for the
same-host lock it keeps in-process contention a mutex wait rather than N
goroutines each running their own `flock` retry loop. It is also what preserves
the existing re-entrancy behaviour: `flock(2)` is per open file description, so
without the mutex a second acquisition in this same process would block in the
kernel rather than on the mutex it blocks on today.

CA request paths bound lock acquisition *and* the critical section together
with `lockTimeout` (60 s, [init.go](../../internal/ca/init.go)) via
`context.WithTimeout` — long enough to ride out a brief leader election, short
enough that a crashed replica's stale lease doesn't hang requests forever. Three
things that timeout does *not* cover. First, it bounds only the
*other-process* half: the process-local mutexes (both the fallback path and the
per-name gate in front of every distributed and same-host implementation) are
plain `sync.Mutex` and do not honour context cancellation, so same-process
waiters queue unboundedly. Second, the offline `openvox-ca-ctl migrate` path
applies no timeout at all — `MigrateService` inherits the caller's context,
which is signal-cancellable but carries no deadline — so a migration waits
indefinitely on a contended `bootstrap` lock; interrupt it and stop the server
rather than waiting. Since same-host locking landed that applies to the
filesystem and SQLite backends too, where the wait used to be no wait at all.

Third, and specific to the same-host tier: the deadline bounds *waiting* for
another process, not the acquisition itself. An **uncontended** same-host lock
is granted even to a caller whose deadline has already gone, matching the
process-local mutex it replaces — that caller then fails on its own first
storage read. The distinction is visible in metrics: `Revoke` counts a failure
that reached the CRL work and does not count one refused at lock acquisition
(see [metrics](../metrics.md)), so the single-node backends stay on the
"counted" side for a spent deadline exactly as they were. A *contended*
same-host acquisition that outlasts the deadline does fail at acquisition, and
so is not counted — the one place where the split moved.

### Tier 2: storage-service mutexes

`StorageService` guards each family of logical keys with its own process-local
mutex so a compound operation (read blob → transform → write blob) can't
interleave with another goroutine's within the process. Three are
`sync.RWMutex`; `serialMu` is a plain `sync.Mutex`, since the serial counter
has no read-only fast path:

| Mutex | Guards | Why compound |
| --- | --- | --- |
| `inventoryMu` | `inventory` + `inventory_hmac` | An append must scan for duplicate serials and advance the integrity head as one unit |
| `crlMu` | `crl` | Plain read/write pairs |
| `fileMu` | `ca_cert`, `ca_pubkey`, `ca_key`, `csr/<subject>`, `cert/<subject>`, per-subject private keys | One mutex spans all subjects; simple and sufficient at current scale |
| `serialMu` | `serial` | Plain read/write pairs |

One shared-state key is absent from this table for a reason worth stating:
`hmac_key` is guarded a tier *up*, not here. Its initialisation
(`EnsureHMACKey`) is a read-modify-write, and the replicas that can fork the key
are in different processes, so a process-local mutex would never have been the
answer — the generating path takes the Tier 1 `hmac-key` lock and reads the key
again after winning it. The read-only path — a key already present *and* of the
expected length, which is every start after the first — takes no lock at all; a
present-but-wrong-length blob regenerates, and so locks. That was
[#202](https://github.com/voxpupuli/openvox-ca/issues/202); how far the
guarantee reaches is `WithLock`'s tiers and nothing more, so see the known gaps
below for the one configuration where two processes can still fork it.

These are **internal to `StorageService`** — callers never touch them, and no
`StorageService` method calls another locked method while holding one (they are
non-reentrant; doing so self-deadlocks). Methods that require a caller-held
mutex generally carry the `...Locked` suffix and always say which lock in
their doc comment. The doc comment is authoritative — a couple of helpers
(`readInventoryForHMAC`, `computeInventoryHMAC`) require `inventoryMu`
without carrying the suffix.

### Tier 3: CA in-memory state (`c.mu`)

`ca.CA.mu` protects the fields that make the hot read paths fast:
`CACert`/`CAKey` (readiness), `serialIndex` (OCSP subject lookup), `ocspCache`
(pre-signed responses), and `cachedCRL` (revocation checks for authentication
without a storage round-trip).

Mutating operations hold `c.mu` (write) across the storage mutation *and* the
cache update, so within a process the caches can never be observed out of step
with what the same process just wrote. Read paths take `c.mu.RLock` only.

`DeleteRequest` is the one mutation that takes no `c.mu` at all: a pending CSR
backs none of these caches, so there is nothing to keep in step with the write.
That is worth knowing beyond cache coherence — it is why a rejection does not
serialise against `Generate` even within a single process, where `c.mu` is what
the two would otherwise have in common.

`c.mu` is also held across the signing call itself. Every issuance path (`Sign`,
`SignWithTTL`, `SaveRequest`'s autosign, `Renew`, `AutoRenew`,
`ImportCertificate`, `Generate`) calls `issueLeafLocked` with `c.mu` held, and
`x509.CreateCertificate` runs inside it — so with an external key provider
(`ca_key_provider: openbao`, or the isolated signer) `c.mu`, not the per-subject
cluster lock, is the process-wide issuance serialiser, and it spans a
network/IPC round trip. Issuance therefore proceeds at roughly one signing
round trip at a time within a process, and a stalled signer backend pins the
mutex and stalls all issuance — see the "Performance and outage behaviour"
section of [the OpenBao Transit guide](../openbao-transit.md). This is the one
deliberate exception to rule 3 (keep expensive work outside the lock): the
signature is inside the lock because the cache update it guards must be atomic
with the issuance.

`c.mu` is non-reentrant. The same `...Locked` suffix convention applies: e.g.
`revokeLocked` requires the cluster `crl` lock **and** `c.mu`; each `...Locked`
function's comment states exactly which locks its caller must hold.

`RevokeSerial` takes the same two as `Revoke` and in the same order, and its
checks run inside them for the reason rule 3 exists: the subject a serial belongs
to, and whether that subject's stored certificate still carries it, are what
justify the CRL write, so resolving either outside the lock would let the answer
go stale before the mutation. That puts an inventory read — on blob backends an
HMAC verification over the whole blob — inside the `crl` lock, which is why the
operation is documented as operator-initiated rather than something to call in a
loop.

## Lock ordering

Nested acquisition follows a fixed order. The request paths share one chain, and
there is a second, narrower nesting on the CA-import path:

```text
subject:<name>  →  crl  →  c.mu  →  (StorageService internal mutexes)
bootstrap       →  crl                    (ImportCACertificate only)
```

Both are one-way. `bootstrap` and `subject:<name>` are never held together at
all, so the two lines do not compose into a single chain — which is why they are
written as two.

- The pending-supersession list deliberately has **no lock name of its own**.
  Its read-modify-write must exclude the sweep that rewrites it — an append
  landing between the sweep's read and its write would be erased, leaving a
  superseded certificate valid with nothing recording that it should not be —
  and the per-subject lock cannot provide that, because two renewals for
  different subjects hold different subject locks. `crl` can, and reusing it
  costs nothing: the renewal path already took that lock to revoke, so nesting
  depth (and therefore the SQL pool floor below) is unchanged, and the sweep
  needs one acquisition to cover both the list rewrite and the revocations it
  drives. See [supersede.go](../../internal/ca/supersede.go).
- `Revoke`, `Clean`, `Renew`, `AutoRenew` and `GenerateWithOptions` (the last
  on its `ReplaceExisting` path only) are the paths that take all three. For
  the four issuance paths it is the subject lock around the whole operation,
  then the `crl` lock + `c.mu` for the revocation step; note they release and
  re-acquire `c.mu` between the signing and revocation steps — `c.mu` is not
  held across a `WithLock` acquisition. `Revoke` has the same nesting for a
  different reason: the `crl` lock + `c.mu` cover the revocation that is the
  whole operation, and the subject lock is there only to serialise it against
  an issuance already under way for that subject.
- No code path acquires `subject:<name>` while holding `crl`, and none acquires
  either while holding `c.mu`. Keep it that way; the comments in
  [signing.go](../../internal/ca/signing.go) and
  [revoke.go](../../internal/ca/revoke.go) record this invariant at each
  nesting site.
- Two *different* subject locks are never held at once (bulk operations like
  `SignMultiple` loop, taking one at a time).
- `CA.Init` inverts the order (it holds `c.mu` while acquiring **two**
  distributed locks in turn: `hmac-key`, via `InitHMAC` → `EnsureHMACKey` on a
  cold start, and then `bootstrap`). They are sequential, never nested. The
  inversion itself is safe only because `Init` runs to completion before
  the server starts serving, so nothing else can be holding a distributed lock
  while waiting on `c.mu`; do not copy this pattern into anything that runs
  while serving. Init also has a *separate*, unfixed hazard on the same lock —
  its slow path can re-enter `bootstrap` and deadlock startup
  ([#201](https://github.com/voxpupuli/openvox-ca/issues/201)); see known gaps.
- `bootstrap` → `hmac-key` is the first nesting in which a name owned by
  `StorageService` sits inside one owned by the CA layer, and the only one taken
  entirely within `internal/storage`. It is not the only nesting of two
  different `WithLock` names — `subject:<name>` → `crl` above is one, and so is
  `bootstrap` → `crl` on the import path — and it is deliberately **absent from
  `allowedLockNesting`** rather than missing from it: that table keys pairs by
  lock *name* and not by (store, name), so a path holding `bootstrap` over two
  different stores is outside its scope by construction. This prose is where the
  pair is recorded, and the table must not gain it. `MigrateService` holds
  `bootstrap` on the destination across `RebuildInventoryHMAC`, which reaches
  `EnsureHMACKey`; if the copied `hmac_key` is the wrong length, that takes
  `hmac-key` inside it. An *absent* key does not: `RebuildInventoryHMAC`
  short-circuits on an `Exists` check before it calls `EnsureHMACKey`, so
  corruption is the only route to this nesting.
  This order is one-way and must stay so — nothing may acquire `bootstrap` from
  inside an `hmac-key` critical section, and `WithLock` is not reentrant at any
  tier, so the two names must also never be made equal.
- `ImportCACertificate` holds `bootstrap` across the CRL rewrite inside
  `importCAMaterial`, so **`bootstrap` → `crl`** is a second permitted nesting
  ([caImport.go](../../internal/ca/caImport.go)). One-way, like the first:
  nothing takes `crl` and then `bootstrap`, and nothing may start. This matters
  more than an import-only path sounds like it should — the documented import
  procedure restarts replicas *after* the import, so the server is serving
  throughout, and a future path acquiring `crl` before `bootstrap` would
  deadlock against a live import rather than fail.
- This section has a machine-readable counterpart: `allowedLockNesting` in
  [lockorder_test.go](../../internal/ca/lockorder_test.go) lists the
  simultaneously-held pairs the CA layer is permitted to take, and a spec fails
  on any pair that is not there — an inverted one *and* a newly introduced one.
  Adding a nesting therefore means editing both, together. See the Tests
  section below for what that does and does not reach.
- `MigrateService` holds two `bootstrap` locks (source backend, then
  destination). Pointing both at the same store deadlocks on **every** backend
  now, not only the distributed ones: on filesystem and SQLite the two are
  separate backend values with separate per-name mutexes, so the second
  acquisition blocks on the `flock` and spins in its backoff loop — a live poll
  rather than a parked goroutine, which is what a stack dump will show. Since
  `MigrateService` applies no deadline it waits forever, announcing itself once.
  Migrating a store onto itself is unsupported.

## Read paths take no distributed locks — by design

Read-only operations must stay cheap and must keep working while another
replica holds a lock. The pattern:

- **Authentication revocation checks** (`IsRevokedSerial`) and **OCSP**
  (`OCSPResponse` fast path) answer from `cachedCRL`/`ocspCache`/`serialIndex`
  under `c.mu.RLock`.
- **HTTP GETs** (certificate, CRL, status listings) read straight through
  `StorageService` getters, which take only the relevant tier-2 read lock.
- `ReadInventory` verifies the integrity HMAC under `inventoryMu.RLock` but
  takes no cluster lock.

The costs of this choice are deliberate and documented:

- A replica's in-memory caches learn about other replicas' activity only when
  this process next writes them: `cachedCRL` staleness for authentication is
  [#171](https://github.com/voxpupuli/openvox-ca/issues/171) (being fixed by
  [PR #182](https://github.com/voxpupuli/openvox-ca/pull/182)'s background
  sync), and `serialIndex`/`ocspCache` staleness for OCSP was
  [#183](https://github.com/voxpupuli/openvox-ca/issues/183), now reconciled by
  `SyncSerialIndex` on `ocsp_index_sync_interval_sec` — see the entry below for
  the lock discipline that pass uses, which is not this section's.
- A read racing a mutation sees either the old or the new state, never a torn
  one — every backend's `Put` is atomic with respect to readers (see the
  `Backend` contract in [backend.go](../../internal/storage/backend.go)).

When you add a read-only endpoint or check, follow this pattern. Do not
"defensively" wrap a read in `WithLock`: it adds a cluster round-trip per
request, serialises hot paths behind slow mutations, and — on the fallback
path — still provides no cross-replica guarantee anyway.

## Rules for new or changed code

1. **Classify the operation first.** Pure read → tier-2/3 read locks only,
   never `WithLock`. Any read-modify-write of shared backend state → the
   narrowest applicable cluster lock (`subject:<name>` where the unit of
   contention is one subject; `crl` for the CRL; `bootstrap` only for
   whole-store lifecycle).
2. **Hold the lock across the whole decision, not just the write.** The
   check that justifies a mutation (duplicate cert? already revoked? CRL still
   fresh?) must run *inside* the same `WithLock` as the mutation, or it is a
   TOCTOU bug. `RefreshCRLIfDue` (check-then-re-sign under one lock) and
   `SaveRequest` (evict-then-save-then-autosign under one lock) are the
   patterns to copy. [#173](https://github.com/voxpupuli/openvox-ca/issues/173)
   / [PR #186](https://github.com/voxpupuli/openvox-ca/pull/186) exist because
   a renewal once did such a re-check outside the lock.
3. **Keep expensive, shared-state-free work outside the lock.** Key
   generation in `Generate` runs before any lock is taken (it no longer
   assembles a CSR at all — that round trip through the signing path was
   removed); parsing and validation in `Renew`/`SaveRequest` likewise. Only the
   storage-touching tail belongs inside. The deliberate exception is the CA
   signature itself: `x509.CreateCertificate` runs under `c.mu` (see Tier 3),
   because the cache update it guards must be atomic with the issuance.
4. **Respect the ordering** (`subject` → `crl` → `c.mu`, and `bootstrap` →
   `crl` on the CA-import path), never acquire the same lock reentrantly, and
   release `c.mu` before entering another `WithLock`. Use the closure-with-defer shape from `Renew`/`AutoRenew` so a
   panic can't wedge a mutex.
5. **Calling convention:** public CA methods take their own locks and say so
   ("The caller must NOT hold c.mu"); internal `...Locked` helpers document
   which locks the caller must already hold. Preserve both halves when
   refactoring, and never call a public locking method from inside a locked
   region.
6. **A distributed lock is a serialiser, not a guarantee.** All the
   implementations are lease/session-based with no fencing tokens: a process
   paused longer than the TTL (GC pause, VM freeze, network partition) can
   lose the lock while still inside `fn`, and Redis failover can hand the lock
   over early (see the note on `RedisBackend.AcquireLock`). Where corruption
   would be the consequence, back the lock with a storage-level invariant that
   holds even without it — and check the invariant's own scope.
   `AppendInventory`'s duplicate-serial check (`ErrDuplicateSerial`) is the
   worked example: it is a cluster-wide guarantee on the structured backends —
   SQL via the database's unique index, etcd via the `by-serial` key's
   `CreateRevision == 0` guard inside the append transaction — but on the
   remaining blob backends (filesystem, redis) the scan runs under the
   process-local `inventoryMu` only (the doc comment on `ErrDuplicateSerial`
   in [storage.go](../../internal/storage/storage.go) spells this out, and
   the blob-backend gap is tracked as
   [#204](https://github.com/voxpupuli/openvox-ca/issues/204)).
7. **New lock names are protocol.** There are three homes, one per layer that
   takes a lock. Define CA-layer names as constants in
   [init.go](../../internal/ca/init.go) (keeping `migrateLockName` in
   [migrate.go](../../internal/storage/migrate.go) in sync — it redefines
   `"bootstrap"` independently); storage-layer names, taken through
   `StorageService.WithLock` by `StorageService` itself, as constants beside
   the code that takes them (e.g. `lockNameHMACKey` in
   [storage.go](../../internal/storage/storage.go)); and backend-internal
   names, taken directly via `Backend.AcquireLock`, as constants in the owning
   backend package (e.g. `etcdDecomposeLockName` in
   [etcd_inventory.go](../../internal/storage/etcd_inventory.go)); keep them
   all stable across releases, and document them in the table above. All
   callers using a name contend on one lock, so
   never derive a name from unvalidated input (subject names pass
   `ValidateSubject` first). **A new singleton name that can reach a SQL
   backend must also be reserved** in `reservedLockOrdinals` in
   [sql.go](../../internal/storage/sql.go), which is how those backends keep
   singleton locks out of the hashed key space — see rule 11. "Can reach a SQL
   backend" is the test, not "is a singleton": `inventory-decompose` is a
   singleton that only the etcd backend takes, so reserving it would claim a
   key nothing uses.

   For a name declared in `internal/storage` this is **enforced**, not just
   asked for: `SQLLockNameConstantsAreRegistered` walks the package source for
   lock-name constants and fails unless each is reserved or listed as
   deliberately exempt. A name declared in `internal/ca` is not reachable by
   that check — `internal/storage` cannot import `internal/ca` — so for those
   this rule is the only thing standing.
8. **SQL pool sizing:** on PostgreSQL/MySQL every *held* distributed lock pins
   one pooled connection. A single in-flight `Revoke`/`Clean`/`Renew`/`AutoRenew`
   needs at least three connections at once — one for the `subject:<name>` lock,
   a second for the nested `crl` lock, and a third for the reads/writes inside
   the revocation step — so `sql_max_open_conns` must be at least 3 per
   concurrently mutating request. `Revoke` joined that list when it took the
   subject lock: revoking many *distinct* subjects at once used to queue on the
   single `crl` gate and hold one lock connection between them, whereas each
   concurrent revocation now pins its own `subject:<name>` connection while it
   waits for `crl`. Set below that and a single request
   hard-stalls (not only under load), bounded only by the 60 s `lockTimeout`.
   See the `sql_max_open_conns` knob in
   [storage backends](../storage-backends.md).
9. **Offline `openvox-ca-ctl` commands** (import, migrate) assume the server
   is stopped. `MigrateService` holds `bootstrap` on both stores, which
   excludes a booting server but deliberately not per-subject signing. That
   exclusion is now genuinely cross-process on every backend — the same-host
   lock covers filesystem and SQLite, where the fallback mutex used to have no
   cross-process effect at all — but the scope is unchanged: a migration and a
   concurrent `Sign` still take different names and do not exclude each other,
   so stop the server. `MigrateService` also inherits the caller's context with
   no `lockTimeout`, so it waits indefinitely on a contended `bootstrap` lock
   (see Tier 1).
10. **A lock name is now also a filename.** On the single-node backends each
    name maps to `sha256(name).lock` in the store's lock directory. The mapping
    is protocol for the same reason the names are: a server and a `ctl` command
    exclude each other only by deriving the same file, so neither the hash nor
    the directory layout may change without a compatibility story. Hashing is
    also what keeps a name from addressing a path — nothing about a new lock
    name needs to be filesystem-safe.
11. **A lock name is also a hashed key on the SQL backends, so the key space is
    partitioned.** `pg_advisory_lock` takes a `bigint`, so a name has to be
    reduced to 64 bits and distinct names can in principle share one. That is
    tolerable between two subject locks — they cost each other contention — and
    was not tolerable between a subject lock and `crl` or `bootstrap`, where it
    is a repeatable denial of revocation
    ([#203](https://github.com/voxpupuli/openvox-ca/issues/203)). So
    `advisoryLockKey` splits the key space on bit 63 instead of hashing every
    name alike: a name in `reservedLockOrdinals` gets a namespaced base plus its
    hand-assigned ordinal, with bit 63 clear, and every other name gets the
    leading 64 bits of SHA-256 over the domain-separated name, with bit 63 set.
    Nothing a caller supplies crosses that line, so the aliasing is
    structurally impossible and `ValidateSubject` is no longer load-bearing
    for it. `mysqlLockName` partitions the same way,
    on a class tag in the `GET_LOCK` name (`openvox-ca:0:<name>` reserved,
    `openvox-ca:1:<128-bit hex>` derived); it has 64 characters to spend rather
    than 64 bits, so its derived form puts collisions between two derived names
    out of reach too.

    The base is namespaced rather than starting the ordinals at 1 because
    `pg_advisory_lock` keys are scoped to the *database*, not to the
    application: every client of that database shares one key space, and 1 and
    2 are exactly what a co-tenant's migration tool would pick. The old FNV-1a
    keys had that property by accident, being pseudorandom; the partition has
    to ask for it.

    The ordinals and the derivation are protocol, exactly as rule 10 says of
    the lock filename: replicas exclude one another only by deriving the same
    key. Never renumber or reuse an ordinal. Changing the derivation is a
    breaking change for a *running* cluster — during a rolling upgrade, nodes
    on either side of it derive different keys and do not exclude one another
    for the length of the rollout, so it needs a full restart rather than a
    rolling one.

12. **A new nesting is protocol too, not only a new name.** Rule 7 covers
    defining and documenting a lock *name*; this covers holding two of them at
    once. Any pair of **two different** named locks that the **CA layer** can
    hold simultaneously through `StorageService.WithLock` must appear both in
    the **Lock ordering** section above and in `allowedLockNesting` in
    [lockorder_test.go](../../internal/ca/lockorder_test.go), added together —
    a pair in only one is drift. **The obligation is unconditional; the
    automated detection is not.** A pair missing from the table fails that spec
    only when a spec drives the caller that takes it, and the specs drive a
    minority of the call sites (see "What the observer does not see" in the
    Tests section). Do not read a green suite as confirmation that you had
    nothing to add. The
    order within a pair is the protocol: one path taking it the other way is
    what deadlocks, and it deadlocks rather than timing out because the
    per-name gate ignores the context.

    The qualifiers are load-bearing, and each excludes a real pair the table
    deliberately does not carry. They are exclusions, not an inventory: pairs
    that *are* in scope go in the table whether or not a spec drives them —
    `bootstrap` → `crl` is listed on exactly that basis. **Two different**: `MigrateService` holds
    `bootstrap` over the source store and then over the destination, which the
    Lock ordering section documents and the table cannot express, because pairs
    are keyed by name and `("bootstrap", "bootstrap")` would read as a
    self-nesting it is not. **CA layer, through `WithLock`**: `bootstrap` →
    `sql-schema-migrate` is a live nesting reached from `MigrateService`, but
    `EnsureReady` takes that name through `Backend.AcquireLock`, so no
    `WithLock`-level observer can see it; it stays governed by rules 7 and 9.
    Do not add either pair to satisfy this rule — adding them would make the
    table claim coverage it does not have.

## Known gaps

Concurrency limitations that are understood and tracked. This list reflects the
state when the document was last updated and is not guaranteed exhaustive.

- [#197](https://github.com/voxpupuli/openvox-ca/issues/197) — OCSP's slow
  path signs responses while holding `c.mu` exclusively, so nonced requests
  (which always miss the cache) serialise process-wide behind the signing
  round trip. This is the same "signature under `c.mu`" property as the
  issuance paths (see Tier 3) surfacing on the OCSP responder; an efficiency
  gap rather than a correctness one.
- [#201](https://github.com/voxpupuli/openvox-ca/issues/201) — `CA.Init`'s slow
  path can re-enter the `bootstrap` lock (via `finishLoadExisting` →
  `seedSupportingState`) and deadlock startup, because `WithLock` is not
  reentrant and its process-local gate ignores the context. Reachable when a
  replica loads a CA bootstrapped elsewhere but then finds the CRL absent.
- ~~[#202](https://github.com/voxpupuli/openvox-ca/issues/202) — `hmac_key`
  initialisation (`EnsureHMACKey`, called by `InitHMAC` *before* the
  `bootstrap` lock) is an unlocked read-modify-write, so two replicas
  cold-starting against a fresh shared backend can generate divergent keys and
  one then fails inventory-HMAC verification.~~ Fixed: `EnsureHMACKey` now runs
  its generating path under the `hmac-key` lock and re-reads the key after
  winning it, so the replica that loses adopts the winner's key rather than
  writing over it. The re-read is the load-bearing half — a lock alone would
  only have ordered two overwrites. `InitHMAC` still runs *before* the
  `bootstrap` lock, deliberately: `InitHMAC` runs on every start, and the fast
  path immediately below it loads an already-bootstrapped CA *without* a
  distributed lock. Moving it inside `bootstrap` would make every replica's
  every start contend for that lock and would enlarge
  [#201](https://github.com/voxpupuli/openvox-ca/issues/201)'s re-entrancy
  hazard rather than avoid it. A separate reason, and a separate claim, is why
  the new name is not *called* `bootstrap`: `MigrateService` reaches
  `EnsureHMACKey` from inside that lock and `WithLock` is not reentrant, so a
  shared name would turn a migration that met a corrupt key into a hang —
  #201's failure mode arrived at from the storage side. What is left open is
  the reach of the lock itself, which is exactly `WithLock`'s: cross-replica on
  etcd, Redis and the server SQL dialects; cross-process on filesystem and
  SQLite; process-local for an in-memory SQLite database or a platform without
  `flock(2)`. Read that last tier as single-*process*, not single-node: an
  in-memory database is private to its process, but two `openvox-ca` processes
  over one `cadir` on a platform with no `flock(2)` (Windows, AIX, Solaris,
  js/wasm) can still fork the key. That is the residue. Across hosts the
  question does not arise, since shared storage is unsupported for those
  backends for the reason `flock(2)` gives above.
- ~~[#203](https://github.com/voxpupuli/openvox-ca/issues/203) — on the SQL
  backends the distributed-lock identity is a 64-bit FNV-1a hash of the name,
  so distinct names can alias; a crafted subject that passes `ValidateSubject`
  could collide with the `crl`/`bootstrap` key and deny revocation.~~ Fixed:
  the key space is now partitioned so a hashed name and a reserved singleton
  can never share a key (rule 11). What that does *not* remove is aliasing
  *within* the hashed half — two subject locks still share a `pg_advisory_lock`
  key with probability 2^-63, which the `bigint` key makes a floor rather than
  a choice (the partition spends one of the 64 bits on the class tag). The
  cost of landing on it is contention between two subjects, not a stalled
  CRL, and finding such a pair deliberately is now a search against
  SHA-256 rather than against FNV-1a, whose invertible per-byte step made a
  chosen target reachable by meet-in-the-middle. MySQL has no such floor: its
  `GET_LOCK` name carries a 128-bit digest.
- ~~[#187](https://github.com/voxpupuli/openvox-ca/issues/187) — filesystem and
  SQLite backends have no same-host, cross-**process** locking.~~ Fixed: both
  now implement `SameHostLocker`, so every name taken through `WithLock`
  excludes another process on the host. What that does *not* reach is the
  inventory append, which is guarded by `inventoryMu` and no cluster lock: two
  processes issuing for **different** subjects hold different `subject:<name>`
  locks and can still interleave an `AppendInventory` and its HMAC rewrite.
  That is the blob-backend gap below, and closing it closes the filesystem case
  with it.
- [#204](https://github.com/voxpupuli/openvox-ca/issues/204) — nothing wraps
  `AppendInventory` in a cluster lock on any blob backend, so its
  duplicate-serial check is not cross-writer on filesystem or Redis, and the
  whole-blob HMAC rewrite can cover a blob that never existed. The etcd half of
  that gap was closed by the decomposed inventory's atomic `by-serial` guard
  ([#138](https://github.com/voxpupuli/openvox-ca/issues/138)). Whatever lock
  the fix takes, the single-node backends will get it cross-process for free
  now that `WithLock` reaches a same-host tier.
  The offline `generate` still reports both capabilities in its pre-flight, via
  `SupportsDistributedLocking`/`SupportsAtomicInventory`, and still tells the
  operator to stop the server: neither is made true by the same-host tier, and
  the inventory append above is why.
- [#171](https://github.com/voxpupuli/openvox-ca/issues/171) — `cachedCRL` is
  per-replica, so authentication and renewal keep accepting a certificate
  revoked elsewhere until this process re-signs the CRL.
  [PR #182](https://github.com/voxpupuli/openvox-ca/pull/182) fixes it with a
  background poll (monotonic in the CRL number, deliberately lock-free).
- ~~[#183](https://github.com/voxpupuli/openvox-ca/issues/183) — OCSP's
  `serialIndex` is built once at startup, so certificates issued on another
  replica answer `unknown`; the `ocspCache` half can even keep serving a
  pre-signed `good` for a certificate revoked elsewhere.~~ Fixed, in two
  halves. `CA.SyncSerialIndex` reconciles the index from the inventory on
  `ocsp_index_sync_interval_sec`, and every write of `c.cachedCRL` now goes
  through `installCachedCRLLocked`, which drops the cached responses the
  incoming CRL contradicts — previously only `SyncCRLCache` and
  `revokeSerialLocked` did, so whichever path installed a peer's revocation
  first decided whether a stale `good` survived.

  **The sync's lock discipline is a deliberate exception to tier 3.** The rule
  above is that a mutation holds `c.mu` across the storage access and the cache
  update together. `SyncSerialIndex` does not: it samples `serialIndexEpoch`
  under `RLock`, reads the inventory holding no `c.mu` at all, then takes the
  write lock to reconcile. Holding `c.mu` across a whole-inventory read would
  block every OCSP answer and every issuance on this replica for the duration,
  once per interval — the cost tier 3 exists to avoid. The epoch counter is
  what makes the gap safe: an issuance landing inside it moves the counter, and
  a pass that sees it moved applies its additions but stands its removals down,
  because it cannot then tell "pruned elsewhere" from "signed here, after I
  read". Additions are always safe, removals never are.

  The exception is bounded rather than free. The reconciliation still holds the
  write lock for O(n) map *reads* over the inventory, so a very large fleet
  pays a brief pause on the admission path once per interval; it writes only
  where storage and the index disagree, so the steady-state pass — the
  overwhelmingly common one — stores nothing. `SyncCRLCache` takes
  the same shape for the same reason and is ordered instead by CRL number.

  `InventoryEntries` exists for this path: `ReadInventory` verifies and then
  fetches, and its verification recomputes from storage, so every call
  materialises the whole inventory twice — on both backend families — and a job
  on a timer should not pay that. It fetches once and folds the integrity value
  over the rows it already holds.

  **It verifies on every backend**, which is where it parts company with
  `SubjectForSerial`. That method skips the check on `InventoryStore` backends
  because doing so "would cost a second full fetch of every row"; here it costs
  no fetch at all, so the reason to skip does not apply. The distinction matters
  for this caller in particular, because it drives *removals*: a row deleted out
  of band takes a serial out of the index, and an index miss downgrades the
  responder's answer for that serial from `revoked` to `unknown` before the CRL
  is consulted. Tampering has to fail closed here.
- ~~[#196](https://github.com/voxpupuli/openvox-ca/issues/196) —
  `DELETE /certificate_request/{subject}` deleted the CSR directly through
  `StorageService`, bypassing the subject lock.~~ Fixed: the handler now goes
  through `CA.DeleteRequest`, which takes `subject:<name>` for the delete, so a
  rejection orders against an in-flight sign instead of racing it. The HTTP
  layer also stopped reporting a failed deletion as `404`, which had told the
  operator the request was gone at the moment it was still queued; it answers
  `503` now. The one issuance a rejection still cannot wait for is `Generate`,
  which saves and signs a CSR under `c.mu` alone — see the `Generate` gap
  above.
- ~~[#173](https://github.com/voxpupuli/openvox-ca/issues/173) — renewal
  re-checked revocation before acquiring the subject lock.~~ Fixed: both
  renewal paths now call `refuseIfRevoked` again as the first statement inside
  the subject lock, and `Revoke` takes `subject:<name>` → `crl` so nothing can
  revoke in the gap between that answer and the issuance it guards. The one
  issuance path a revocation still cannot wait for is `Generate`, which takes
  no distributed lock — see the `Generate` gap above.
- On blob backends (filesystem/redis), an inventory append and its HMAC
  update are two writes, not one atomic unit; the failure window is documented
  at the write site in `AppendInventory` and the structured (SQL, etcd)
  inventory — which commits the entry and its integrity head in one
  transaction — is the durable answer. See
  [the inventory store](inventory-store.md).

## Tests

`WithLock`'s fallback semantics, its overlay/unsupported delegation, and its
unlock-error handling are covered in
[withlock_test.go](../../internal/storage/withlock_test.go); each distributed
implementation's mutual exclusion is exercised in its backend integration
suite (build-tagged; see [testing](testing.md)).

The same-host tier is covered in
[filelock_test.go](../../internal/storage/filelock_test.go), which runs in the
ordinary unit suite because it needs nothing but a temporary directory. Most of
it uses two backend values over one store, which is an exact substitution
rather than a convenient one — `flock(2)` is held by an open file description,
so two `os.OpenFile` calls exclude each other whether or not a fork separates
them. One spec does not settle for that: it re-executes the test binary (via a
`TestMain` guard in
[filelock_helper_test.go](../../internal/storage/filelock_helper_test.go)) so a
real second process holds the lock, and asserts both that this process is
refused and that the lock frees itself when that process is **SIGKILLed** — no
orderly release, so the kernel dropping the descriptor is the only thing that
can explain it. That is the property the whole flock-over-lockfile choice rests
on, and it is asserted rather than assumed.

That a given path takes its lock *at all* is automated for five of them, all in
the same shape: park the operation on a held `subject:<name>` and require it to
wait, since one that stopped taking the lock returns immediately instead.
[renewrace_test.go](../../internal/ca/renewrace_test.go) does this for `Revoke`,
`Clean`, `Renew` and `AutoRenew` alongside the ordering assertions described
below, and
[deleterequest_test.go](../../internal/ca/deleterequest_test.go) for
`DeleteRequest`. That last one also pins the far side — it parks a delete on
the inventory append inside an autosigning `SaveRequest`'s issuance, so it
observes the lock being held from that append until `SaveRequest` returns, not
across the evict/save prefix ahead of it. Dropping `SaveRequest`'s `WithLock`
still fails it, which is what makes `SaveRequest` pinned too.

`Sign` is pinned as well, but in a second shape rather than this one:
[lockorder_test.go](../../internal/ca/lockorder_test.go)'s rule-9 spec compares
the count of `subject:<name>` acquisitions before and after a `Sign`, so
dropping its `WithLock` fails on the delta rather than on a lock wait. The
`c.mu` spec's expected-acquisition total counts it too. `SignWithTTL` and
`ImportCertificate` are the ones now left with no spec at all: for those the
lock-name table above is the only record, and dropping the lock fails no
assertion. Either shape is worth copying when closing one of the gaps above —
park-on-a-held-lock proves the operation *waits*, a before/after count proves it
*acquires*, and the second is much cheaper when the operation is not otherwise
concurrent.

The nested lock-ordering invariant *is* now automated, in
[renewrace_test.go](../../internal/ca/renewrace_test.go): for each caller that
holds both locks — `Revoke`, `Clean`, `Renew`, `AutoRenew` — it parks the
operation on a held subject lock and requires `crl` to still be grantable while
it waits. An inverted nesting therefore fails on an assertion rather than
deadlocking the suite to its timeout, which is how an inversion otherwise
presents: every backend serialises same-process callers on a mutex that ignores
the context deadline. These run under the race detector on every unit
run: `mage test:unit` passes `-race` over every unit package, `internal/ca`
included. Of the backend suites, `backendsEtcd`, `backendsPostgres` and
`backendsMySQL` run under it too; `backendsRedisGo` does not, and
[PR #212](https://github.com/voxpupuli/openvox-ca/pull/212) adds it. The
residue is tracked as
[#205](https://github.com/voxpupuli/openvox-ca/issues/205).

That is only the suites this document cares about. For the exhaustive list of
every `go test` the repository invokes and whether each is raced — including the
two outside storage locking — see
[testing](testing.md#which-suites-run-under--race); enumerating it in two places
is how the two came to disagree before.

That per-caller coverage is not the whole graph, and cannot be: it is a
hand-maintained list of callers — three `Entry` lines plus the standalone
`Revoke` spec beside them — so a further caller that nests two locks, or a
first caller that nests two *different* names, is protected by nothing until
somebody extends it.
[lockorder_test.go](../../internal/ca/lockorder_test.go) covers the graph
itself instead. It wraps the backend in an observer that records every
`(outer, inner)` pair the CA layer actually takes through
`StorageService.WithLock`, and asserts the observed set against
`allowedLockNesting` — the machine-readable form of the **Lock ordering**
section above. An inversion fails because the reversed pair is absent from that
table; a **new** nesting fails because the new pair is absent too, which is
deliberate. A new pair of simultaneously-held lock names is protocol in the same
sense rule 7 makes a new lock *name* protocol — rule 7 governs names, not pairs,
so the pair obligation is its own rule ("A new nesting is protocol too") in
**Rules for new or changed code** above — and it should cost a line in
`allowedLockNesting` and a line in the **Lock ordering** section above, added
together. The failure message names the offending pair.

Three things that file pins which nothing else does:

- **Rule 4's "release `c.mu` before entering another `WithLock`".** `c.mu` is
  unexported, so no spec outside `internal/ca` can probe it, and the per-caller
  table checks only that the *CRL* lock stays grantable. The observer instead
  tries `c.mu` at each acquisition and records a violation if it is held.
  `CA.Init` is excluded explicitly rather than by accident — it holds `c.mu`
  while taking `bootstrap`, which this document sanctions above — so the probe
  is armed after `Init` returns.
- **Completion under concurrency.** Competing issuance, renewal, revocation and
  clean paths run at once against a bounded context and must all finish, with
  two of them racing for one subject through different callers — the only shape
  that can close an ordering cycle, since goroutines on disjoint subjects
  serialise instead of deadlocking whatever order they take. Be clear which
  assertion is the detector: the **edge table** catches an inversion
  deterministically and in a fraction of a second, and the timeout is a *bound*
  that keeps an interleaving which does reach a real cycle legible rather than
  hanging the suite, because the per-name gate ignores the deadline.
- **Rule 9's documented *non*-edge.** A migration holding `bootstrap` must not
  exclude per-subject signing — that is precisely why operators are told to
  stop the server rather than rely on the lock. A well-meant widening of the
  migration lock would look like a safety improvement while converting a
  documented "stop the server" into a silent stall bounded only by
  `lockTimeout`.

What the observer does **not** see, stated because a check that never reaches a
class of acquisition reports a clean graph exactly as a check that reached it
would:

- **Tiers 2 and 3.** They are not named locks, so no backend wrapper can observe
  them; the tail of the order (`… → c.mu → internal mutexes`) is covered by the
  `c.mu` probe above rather than by the edge table.
- **Any caller the specs do not drive.** The observer is passive — it records
  what the operations a spec calls actually do, so it sees a minority of the
  `WithLock` call sites in `internal/ca`, and an inversion in one it does not
  reach would fail nothing. The driven and untouched sets are listed once, in
  [lockorder_test.go](../../internal/ca/lockorder_test.go)'s top-of-file comment,
  and deliberately not restated here — the same reason the `-race` roster lives
  only in [testing](testing.md#which-suites-run-under--race): a list kept in two
  places is a list that will disagree with itself. To check the ratio at any
  commit, count
  `c.Storage.WithLock` in non-test `internal/ca` plus the sites in
  [caImport.go](../../internal/ca/caImport.go) that lock through a passed-in
  store — deliberately a rule rather than a number, because which operations take
  which locks is under active change and a literal here would go stale in a merge
  that conflicts with nothing and fails no spec. What the edge table removes is
  the hand-maintained list of *pairs*, not the list of callers: driving one more
  operation checks every pair that operation takes.
- **Names taken outside `WithLock`.** `sql-schema-migrate`
  ([sql.go](../../internal/storage/sql.go)) and `inventory-decompose`
  ([etcd_inventory.go](../../internal/storage/etcd_inventory.go)) are acquired
  through `Backend.AcquireLock` directly, so a `WithLock`-level observer cannot
  see them at all.
- **`MigrateService`.** It nests the *same* name over two different stores
  (`bootstrap` source, then destination), and pairs are keyed by lock name
  rather than by store, so driving it would record a self-nesting that is not
  one. Out of scope here rather than misrepresented; rule 9's operator-visible
  half is pinned by the spec above.
