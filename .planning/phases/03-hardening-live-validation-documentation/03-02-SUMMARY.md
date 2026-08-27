---
phase: 03-hardening-live-validation-documentation
plan: 02
subsystem: testing
tags: [gtest, gmock, reentrancy, scheduler, connection-gater, pnet]

# Dependency graph
requires:
  - phase: 01-connection-gater-interface-wiring
    provides: ConnectionGater interface, 5 intercept hooks wired into Dialer/TcpListener/UpgraderSession, scheduler-deferred rejection dispatch
  - phase: 02-private-network-pnet-psk-protector
    provides: PnetProtectedConnection, PnetUpgraderDecorator, scheduler-deferred read/write completions
provides:
  - Regression tests proving every scheduler_->schedule(...) call site in the gater/pnet rejection and completion paths never invokes its downstream callback synchronously (reentrant) within the triggering call's own stack frame
  - Reusable ReentrancyGuard/Scope RAII test idiom (duplicated verbatim across 3 files, matching 03-PATTERNS.md exactly)
affects: [hardening, future-gater-hooks, future-pnet-completions]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "ReentrancyGuard/Scope RAII idiom: a bool flag set true for the duration of a triggering synchronous call, checked inside the deferred callback to prove it never fires while the flag is still true"
    - "Before/after observation (io_context run_for vs scheduler_backend drain) for call sites with no callback-taking collaborator to force synchronous completion"

key-files:
  created: []
  modified:
    - test/libp2p/network/dialer_test.cpp
    - test/libp2p/transport/tcp/tcp_listener_test.cpp
    - test/libp2p/transport/upgrader_session_test.cpp
    - test/libp2p/security/pnet/pnet_protected_connection_test.cpp

key-decisions:
  - "gtest's ASSERT_FALSE cannot be used inside a constructor (fatal-assert macros expand to `return <value>;`, invalid in a constructor per MSVC C2534); the ReentrancyGuard::Scope constructor uses EXPECT_FALSE instead, in all 3 files that define the struct"
  - "interceptAccept's reentrancy test uses a before/after intercept_called observation (io_context run_for vs scheduler_backend drain) rather than the ReentrancyGuard::Scope idiom, since interceptAccept has no callback-taking collaborator to force into synchronous completion and the entire accept-handling block is already the deferred body of one scheduler_->schedule(...) call"

patterns-established:
  - "ReentrancyGuard/Scope: reusable across any future test proving deferred, non-reentrant callback dispatch"

requirements-completed: [TEST-04]

coverage:
  - id: D1
    description: "interceptPeerDial and interceptAddrDial (non-relay) rejection paths in DialerImpl never invoke the dial callback synchronously -- only after the scheduler backend drains"
    requirement: "TEST-04"
    verification:
      - kind: unit
        ref: "test/libp2p/network/dialer_test.cpp#DialerTest.PeerDialRejectionNeverReentersSynchronously"
        status: pass
      - kind: unit
        ref: "test/libp2p/network/dialer_test.cpp#DialerTest.AddrDialRejectionNeverReentersSynchronously"
        status: pass
    human_judgment: false
  - id: D2
    description: "interceptAccept's gater check and rejection handling in TcpListener only run from within the already-scheduler-deferred accept block, never from async_accept's own completion frame"
    requirement: "TEST-04"
    verification:
      - kind: unit
        ref: "test/libp2p/transport/tcp/tcp_listener_test.cpp#TcpListenerTest.AcceptGaterRejectionDeferredUntilSchedulerDrains"
        status: pass
    human_judgment: false
  - id: D3
    description: "interceptSecured and interceptUpgraded rejection paths in UpgraderSession never invoke handler_ synchronously -- only after the scheduler backend drains; success-path tests intentionally left unguarded since they call handler_ directly by design"
    requirement: "TEST-04"
    verification:
      - kind: unit
        ref: "test/libp2p/transport/upgrader_session_test.cpp#UpgraderSessionTest.InterceptSecuredRejectionNeverReentersSynchronously"
        status: pass
      - kind: unit
        ref: "test/libp2p/transport/upgrader_session_test.cpp#UpgraderSessionTest.InterceptUpgradedRejectionNeverReentersSynchronously"
        status: pass
    human_judgment: false
  - id: D4
    description: "PnetProtectedConnection read/write completions (deferReadCallback/deferWriteCallback) never invoke the caller's callback synchronously despite the inner PipeEnd completing inline -- only after the scheduler backend drains"
    requirement: "TEST-04"
    verification:
      - kind: unit
        ref: "test/libp2p/security/pnet/pnet_protected_connection_test.cpp#PnetProtectedConnectionTest.WriteCompletionNeverReentersSynchronously"
        status: pass
      - kind: unit
        ref: "test/libp2p/security/pnet/pnet_protected_connection_test.cpp#PnetProtectedConnectionTest.ReadCompletionNeverReentersSynchronously"
        status: pass
    human_judgment: false

duration: 45min
completed: 2026-08-27
status: complete
---

# Phase 3 Plan 2: Reentrancy Regression Coverage Summary

**7 new GTest/GMock regression cases proving every scheduler-deferred gater/pnet rejection and completion path never reenters its own triggering call stack, using a verbatim-reused ReentrancyGuard/Scope RAII idiom across 4 unit test files.**

## Performance

- **Duration:** ~45 min
- **Tasks:** 3
- **Files modified:** 4

## Accomplishments
- `dialer_test.cpp`: 2 new tests proving `interceptPeerDial` and `interceptAddrDial` (non-relay) rejection dispatch in `DialerImpl` is scheduler-deferred, never synchronous
- `tcp_listener_test.cpp`: 1 new test proving `interceptAccept`'s rejection handling runs only inside the already-scheduler-deferred accept block, never from `async_accept`'s own completion frame
- `upgrader_session_test.cpp`: 2 new tests proving `interceptSecured`/`interceptUpgraded` rejection dispatch in `UpgraderSession::onSecured` is scheduler-deferred, with the pre-existing success-path tests correctly left unguarded (they call `handler_` directly by design)
- `pnet_protected_connection_test.cpp`: 2 new tests proving `deferReadCallback`/`deferWriteCallback` never invoke the caller's callback inline, even though the underlying `PipeEnd` test double completes synchronously
- Every `scheduler_->schedule(...)` call site identified in 03-RESEARCH.md's verified defer/no-defer table (excluding the `UpgraderSession` success chain, which correctly has no guard) now has a dedicated regression test

## Task Commits

Each task was committed atomically:

1. **Task 1: dialer_test.cpp + tcp_listener_test.cpp -- interceptPeerDial/interceptAddrDial/interceptAccept reentrancy** - `99d4df9` (test)
2. **Task 2: upgrader_session_test.cpp -- interceptSecured/interceptUpgraded reentrancy** - `881bbcf` (test)
3. **Task 3: pnet_protected_connection_test.cpp -- read/write completion reentrancy** - `575dd6c` (test)

_Note: no `feat`/`refactor` commits -- this plan is pure test-authoring against already-implemented, already-unit-tested Phase 1/2 production code. No production source files were touched._

## Files Created/Modified
- `test/libp2p/network/dialer_test.cpp` - Added `ReentrancyGuard`/`Scope` struct + `PeerDialRejectionNeverReentersSynchronously` + `AddrDialRejectionNeverReentersSynchronously`
- `test/libp2p/transport/tcp/tcp_listener_test.cpp` - Added `AcceptGaterRejectionDeferredUntilSchedulerDrains` (before/after observation, no guard idiom)
- `test/libp2p/transport/upgrader_session_test.cpp` - Added `ReentrancyGuard`/`Scope` struct + `InterceptSecuredRejectionNeverReentersSynchronously` + `InterceptUpgradedRejectionNeverReentersSynchronously`
- `test/libp2p/security/pnet/pnet_protected_connection_test.cpp` - Added `ReentrancyGuard`/`Scope` struct (in the file's existing anonymous namespace) + `WriteCompletionNeverReentersSynchronously` + `ReadCompletionNeverReentersSynchronously`

## Decisions Made
- **`EXPECT_FALSE` instead of `ASSERT_FALSE` inside `ReentrancyGuard::Scope`'s constructor** (Rule 1 auto-fix): gtest's fatal-assert macros (`ASSERT_*`) expand to `return <value>;`, which does not compile inside a constructor under MSVC (error C2534, "constructor cannot return a value"). This is a genuine compile-breaking bug in the verbatim scaffolding both `03-PATTERNS.md` and `03-RESEARCH.md` specify. `EXPECT_FALSE` is the non-fatal equivalent and preserves the same regression-catching intent (a failed check is still reported as a test failure, just without early-return semantics) -- applied identically across all 3 files that define the struct.
- **`interceptAccept`'s test uses before/after observation, not the `Scope` idiom** -- per the plan's explicit design (D-06's synchronous-completion technique doesn't apply to a direct-return, non-callback-taking method; the entire accept-handling block including the `interceptAccept` call is already the deferred body of one `scheduler_->schedule(...)` call, so there's no further nested scheduling to guard around at this exact site).
- **Both `PnetProtectedConnection` tests confirm eventual callback firing after `fx.drain()`**, not just the pre-drain reentrancy assertion, matching the file's existing `fired`-style pattern (`CompletionDeferredThroughScheduler`) for consistency and to guard against accidentally asserting on a callback that never fires at all.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] `ASSERT_FALSE` inside a constructor does not compile under MSVC**
- **Found during:** Task 1 (first build of `dialer_test.cpp` after adding `ReentrancyGuard::Scope`)
- **Issue:** The `ReentrancyGuard::Scope` constructor scaffolding specified verbatim in `03-PATTERNS.md` and `03-RESEARCH.md` uses `ASSERT_FALSE(g.inside);` inside the constructor. gtest's `ASSERT_*` macros expand to a bare `return <value>;` statement, which MSVC rejects with error C2534 ("constructor cannot return a value") since constructors have no return type.
- **Fix:** Changed to `EXPECT_FALSE(g.inside);` (gtest's non-fatal equivalent, which does not use `return`) in all 3 files that define the `ReentrancyGuard` struct (`dialer_test.cpp`, `upgrader_session_test.cpp`, `pnet_protected_connection_test.cpp`).
- **Files modified:** `test/libp2p/network/dialer_test.cpp`, `test/libp2p/transport/upgrader_session_test.cpp`, `test/libp2p/security/pnet/pnet_protected_connection_test.cpp`
- **Verification:** All 3 targets build cleanly under MSVC 19.44; all pre-existing and new tests pass.
- **Committed in:** `99d4df9`, `881bbcf`, `575dd6c` (part of each respective task commit)

---

**Total deviations:** 1 auto-fixed (1 bug)
**Impact on plan:** Necessary compile-fix for the exact scaffolding the plan specified verbatim from research; no scope creep, no behavior change to the assertion's intent.

## Issues Encountered
None beyond the deviation documented above.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- All 4 modified test files build and pass under `ctest` (verified individually and combined via `ctest -R "dialer_test|tcp_listener_test|upgrader_session_test|pnet_protected_connection_test"`).
- Pre-existing `TcpListenerTest.ListenCloseListen` / `TcpListenerTest.DoubleClose` failures persist (documented Windows/MSVC `boost::asio` cancellation error-code mismatch, 995 vs 105 -- carried forward in STATE.md's Blockers/Concerns since before Phase 1, unrelated to this plan).
- No production code was modified -- Phase 1/2's gater and pnet implementations are unchanged; this plan is purely additive regression coverage.
- TEST-04 is now fully covered per 03-RESEARCH.md's verified call-site table (excluding the intentionally-unguarded `UpgraderSession` success chain and the informational holepunch loop-filter site, both explicitly out of scope per D-05/Open Question #1).
- Remaining phase work: 03-03 (DOCS-01/02/03 example directories) per ROADMAP.md.

---
*Phase: 03-hardening-live-validation-documentation*
*Completed: 2026-08-27*
