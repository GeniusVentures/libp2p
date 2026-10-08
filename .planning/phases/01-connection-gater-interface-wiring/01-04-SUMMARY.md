---
phase: 01-connection-gater-interface-wiring
plan: 04
subsystem: infra
tags: [connection-gater, tcp-transport, tcp-listener, scheduler, gmock]

# Dependency graph
requires:
  - phase: 01-connection-gater-interface-wiring/01-01
    provides: "ConnectionGater interface, ConnectionGaterError enum, PermissiveConnectionGater default, ConnectionGaterMock"
  - phase: 01-connection-gater-interface-wiring/01-03
    provides: "UpgraderSession 5-arg constructors (gater/scheduler trailing params)"
provides:
  - "TcpTransport 4-arg constructor (adds gater_/scheduler_), threaded into createListener() and all 3 UpgraderSession construction sites"
  - "TcpListener 5-arg constructor (adds gater_/scheduler_/log_), doAccept()'s interceptAccept gate scheduler-deferred with immediate un-nested close on rejection"
  - "test/libp2p/transport/tcp/tcp_listener_test.cpp — new AcceptRejectedByGaterClosesConnectionWithoutUpgrading case"
  - "test/libp2p/transport/tcp/tcp_integration_test.cpp / test/acceptance/p2p/muxer.cpp — updated to construct TcpTransport with a PermissiveConnectionGater + real SchedulerImpl"
affects: []

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "TcpListener::doAccept() defers the interceptAccept decision itself via scheduler_->schedule(...), calling self->doAccept() synchronously right after so the accept loop never stalls on one pending gater decision; a rejection closes the socket immediately inside that same deferred callback with no further deferral"
    - "Local/remote multiaddr resolution failure on an accepted connection is treated identically to a gater rejection (log + guarded close), rather than silently falling through to UpgraderSession construction"

key-files:
  created:
    - .planning/phases/01-connection-gater-interface-wiring/deferred-items.md
  modified:
    - include/libp2p/transport/tcp/tcp_listener.hpp
    - src/transport/tcp/tcp_listener.cpp
    - include/libp2p/transport/tcp/tcp_transport.hpp
    - src/transport/tcp/tcp_transport.cpp
    - src/transport/tcp/CMakeLists.txt
    - test/acceptance/p2p/muxer.cpp
    - test/libp2p/transport/tcp/tcp_integration_test.cpp
    - test/libp2p/transport/tcp/tcp_listener_test.cpp
    - test/libp2p/transport/tcp/CMakeLists.txt

key-decisions:
  - "Local/remoteMultiaddr() resolution failure on an accepted connection is treated the same as a gater rejection (log via SL_DEBUG, guarded close, no UpgraderSession construction, no handle_ call) rather than falling through, per the plan's action block"
  - "TcpListener's stored log_ member (log::createLogger('TcpListener') in the constructor init list) requires the logging system to already be configured before construction — matched by adding testutil::prepareLoggers() to TcpListenerTest's SetUp(), which was previously unnecessary since this class only created ad-hoc loggers lazily inside method bodies"
  - "6 pre-existing TransportAdaptor::dial() call sites (5 in tcp_integration_test.cpp, 1 in muxer.cpp) calling dial() with only 3 args — which no longer resolves to any overload since bindaddress/source_addresses became a required parameter in an earlier, unrelated commit — are deferred (not fixed) per the scope-boundary rule; confirmed via git history this predates Phase 01 entirely. Logged to deferred-items.md"

patterns-established: []

requirements-completed: [GATE-03, GATE-05, TEST-01]

coverage:
  - id: D1
    description: "A gater configured to reject interceptAccept causes TcpListener to close the accepted socket before any UpgraderSession/security handshake is ever created, and the accept loop keeps listening for new connections without stalling on the pending decision"
    requirement: "GATE-03"
    verification:
      - kind: unit
        ref: "test/libp2p/transport/tcp/tcp_listener_test.cpp#TcpListenerTest.AcceptRejectedByGaterClosesConnectionWithoutUpgrading"
        status: pass
    human_judgment: false
  - id: D2
    description: "The interceptAccept hook call is delivered via scheduler_->schedule(...) (verified structurally: grep -c 'interceptAccept(' returns 1 and that call site is lexically inside the scheduler_->schedule(...) lambda), while a rejection inside that callback closes the socket immediately with no further deferral"
    requirement: "GATE-05"
    verification:
      - kind: other
        ref: "grep -c 'interceptAccept(' src/transport/tcp/tcp_listener.cpp == 1; manual code review confirming self->doAccept() runs synchronously immediately after scheduler_->schedule(...), outside the deferred lambda"
        status: pass
      - kind: unit
        ref: "test/libp2p/transport/tcp/tcp_listener_test.cpp#TcpListenerTest.AcceptRejectedByGaterClosesConnectionWithoutUpgrading"
        status: pass
    human_judgment: false
  - id: D3
    description: "TcpTransport threads gater_/scheduler_ to every UpgraderSession it constructs (2 dial() overloads + upgradeRelaySecure()) and to the TcpListener it creates"
    requirement: "GATE-03"
    verification:
      - kind: other
        ref: "cmake --build build --target p2p_tcp (also transitively verified by cmake --build build --target p2p_relay succeeding, since RelayMessageProcessor's UpgraderSession call site — fixed in 01-03 — was the last one blocked on this plan's TcpTransport/TcpListener fix)"
        status: pass
    human_judgment: false
  - id: D4
    description: "Pre-existing non-DI TcpTransport construction sites (test/libp2p/transport/tcp/tcp_integration_test.cpp's 7 sites, test/acceptance/p2p/muxer.cpp's 2 sites) compile against the new 4-arg constructor with a PermissiveConnectionGater and a real SchedulerImpl/AsioSchedulerBackend"
    requirement: "TEST-01"
    verification:
      - kind: other
        ref: "cmake --build build (all TcpTransport/make_shared call sites compile; the only remaining errors are 6 pre-existing, unrelated TransportAdaptor::dial() call sites documented in deferred-items.md)"
        status: pass
      human_judgment: true
      rationale: "cmake --build build --target tcp_integration_test all_muxers_acceptance_test does not fully succeed end-to-end because of 6 pre-existing dial() call sites unrelated to this plan's changes (confirmed via git history to predate Phase 01); this plan's own scope — the TcpTransport constructor threading — compiles cleanly at every site it touches."
  - id: D5
    description: "TcpListener's constructor accepts gater/scheduler as trailing params and stores a log_ member; p2p_tcp_listener links p2p_connection_gater for the ConnectionGaterError category symbol"
    requirement: "GATE-03"
    verification:
      - kind: other
        ref: "cmake --build build --target p2p_tcp"
        status: pass
    human_judgment: false
---

# Phase 01 Plan 04: TcpTransport/TcpListener Connection Gater Wiring Summary

**TcpListener's accept path gained a scheduler-deferred interceptAccept gate (immediate un-nested close on rejection), threaded end-to-end through TcpTransport's gater_/scheduler_ members and all downstream UpgraderSession/TcpListener construction sites, completing all 3 wiring call sites for GATE-03/GATE-05**

## Performance

- **Duration:** ~70 min
- **Started:** 2026-08-26T~21:00:00Z (approx)
- **Completed:** 2026-08-26T~22:10:00Z (approx)
- **Tasks:** 3
- **Files modified:** 9 (1 created, 8 modified)

## Accomplishments

- `TcpTransport`'s constructor gained trailing `gater`/`scheduler` parameters (auto-resolvable by Boost.DI), threaded into `createListener()`'s `TcpListener` construction and all 3 `UpgraderSession` construction sites (both `dial()` overloads' connect lambdas + `upgradeRelaySecure()`)
- `TcpListener`'s constructor gained trailing `gater`/`scheduler` parameters plus a stored `log_` member (`log::createLogger("TcpListener")`)
- `doAccept()`'s completion lambda now defers the entire post-accept decision (multiaddr resolution + `interceptAccept` + session creation) via `scheduler_->schedule(...)`, calling `self->doAccept()` synchronously right after so the accept loop never stalls on a single pending gater decision
- Inside the deferred callback: a `localMultiaddr()`/`remoteMultiaddr()` resolution failure or an `interceptAccept` rejection both close the connection immediately (guarded by `!isClosed()`) with no further deferral, and never construct an `UpgraderSession`; acceptance proceeds to construct the session and call `secureInbound()` exactly as before
- `src/transport/tcp/CMakeLists.txt`: `p2p_tcp_listener` links `p2p_connection_gater` for the `ConnectionGaterError` category symbol used by `.error().message()`
- `test/libp2p/transport/tcp/tcp_integration_test.cpp`: added `makeGater()`/`makeScheduler()` helpers (`PermissiveConnectionGater` + `SchedulerImpl`/`AsioSchedulerBackend`), threaded into all 7 `TcpTransport` construction sites
- `test/acceptance/p2p/muxer.cpp`: extracted each block's scheduler into a named variable, added a `PermissiveConnectionGater`, threaded both into the 2 `TcpTransport` construction sites
- `test/libp2p/transport/tcp/tcp_listener_test.cpp`: new `TEST_F(AcceptRejectedByGaterClosesConnectionWithoutUpgrading)` — a real client connects, `interceptAccept` rejects, `upgradeToSecureInbound` is never called (`StrictMock`), and the client observes the server-side socket close after pumping the manual scheduler and re-running the io_context
- `p2p_relay` (blocked since before this plan per 01-03-SUMMARY, pending this plan's `TcpTransport`/`TcpListener` fix) now builds cleanly, confirming all 4 pre-existing `UpgraderSession` call sites across the codebase are gater-aware

## Task Commits

Each task was committed atomically:

1. **Task 1: Thread gater_/scheduler_ through TcpTransport and TcpListener; defer+gate TcpListener's accept path** - `22da0e2` (feat)
2. **Task 2: Keep pre-existing non-DI TcpTransport construction sites compiling** - `c1e6933` (test)
3. **Task 3: TEST-01 new TcpListener accept-hook gater coverage** - `a5b46ad` (test)

**Plan metadata:** (this commit) `docs: complete 01-04 plan`

## Files Created/Modified

- `include/libp2p/transport/tcp/tcp_listener.hpp` - added `gater`/`scheduler` trailing constructor params, `gater_`/`scheduler_`/`log_` members
- `src/transport/tcp/tcp_listener.cpp` - constructor stores new members; `doAccept()`'s completion lambda restructured to defer the `interceptAccept` decision via `scheduler_->schedule(...)`
- `include/libp2p/transport/tcp/tcp_transport.hpp` - added `gater`/`scheduler` trailing constructor params, `gater_`/`scheduler_` members
- `src/transport/tcp/tcp_transport.cpp` - constructor stores new members; `createListener()` and all 3 `UpgraderSession` construction sites append `gater_, scheduler_`
- `src/transport/tcp/CMakeLists.txt` - `p2p_tcp_listener` links `p2p_connection_gater`
- `test/acceptance/p2p/muxer.cpp` - both `TcpTransport` construction sites append a `PermissiveConnectionGater` + named scheduler variable
- `test/libp2p/transport/tcp/tcp_integration_test.cpp` - `makeGater()`/`makeScheduler()` helpers; all 7 `TcpTransport` construction sites updated
- `test/libp2p/transport/tcp/tcp_listener_test.cpp` - fixture gains scheduler/gater members, `testutil::prepareLoggers()` call; new gater-rejection test case
- `test/libp2p/transport/tcp/CMakeLists.txt` - `tcp_integration_test` links `p2p_basic_scheduler`/`p2p_asio_scheduler_backend`; `tcp_listener_test` links `p2p_basic_scheduler`/`p2p_manual_scheduler_backend`/`p2p_connection_gater`
- `.planning/phases/01-connection-gater-interface-wiring/deferred-items.md` - new file documenting the pre-existing, out-of-scope `dial()` call-site breakage found during Task 2

## Decisions Made

- Local/remoteMultiaddr() resolution failure on an accepted connection is treated identically to a gater rejection (log, guarded close, no `UpgraderSession`/`handle_` call) rather than falling through silently, matching the plan's explicit action text.
- `TcpListener`'s new stored `log_` member requires the logging system to already be configured (`libp2p::log::setLoggingSystem`) before construction. This was a new requirement introduced by adding an unconditional `log::createLogger(...)` call to the constructor init list (this class previously only ever created ad-hoc loggers lazily inside method bodies, which never ran during plain construction). Fixed per Rule 3 (blocking) by adding `testutil::prepareLoggers();` to `TcpListenerTest::SetUp()`, matching the convention already used by `DialerTest`/`tcp_integration_test.cpp`.
- 6 pre-existing `TransportAdaptor::dial()` call sites (5 in `tcp_integration_test.cpp`, 1 in `muxer.cpp`'s `Client::connect()`) calling `dial(peerId, address, handler)` with only 3 positional args no longer resolve to any overload, since an earlier, unrelated commit (`ae18ab7`) made `bindaddress`/`source_addresses` a required parameter without updating these test files. Confirmed via `git show 8640b25:...` (immediately preceding all of Phase 01) that these exact call sites already had only 3 arguments at that commit — this predates Phase 01 entirely and is unrelated to gater wiring. Per the scope-boundary rule and `.planning/PROJECT.md`'s explicit "Auditing/fixing the general existing test suite's health beyond what this work touches" Out-of-Scope note, this was logged to `deferred-items.md` rather than fixed.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] TcpListener's new log_ member crashes without a configured logging system**
- **Found during:** Task 3 (first run of `tcp_listener_test`)
- **Issue:** `TcpListener`'s constructor now unconditionally calls `log::createLogger("TcpListener")` (added in Task 1 per the plan's own action text), which asserts/crashes (`"Logging system is not ready"`) if `libp2p::log::setLoggingSystem(...)` was never called. `TcpListenerTest` had no `SetUp()` call to `testutil::prepareLoggers()` since this class previously only created loggers lazily inside method bodies (never during plain construction/listen with valid params).
- **Fix:** Added `#include "testutil/prepare_loggers.hpp"` and a `testutil::prepareLoggers();` call at the top of `TcpListenerTest::SetUp()`, matching the pattern already used by `DialerTest` and `tcp_integration_test.cpp`'s `main()`.
- **Files modified:** `test/libp2p/transport/tcp/tcp_listener_test.cpp`
- **Verification:** All 3 `TcpListenerTest` cases run past setup without crashing; the new gater-rejection case passes.
- **Committed in:** `a5b46ad` (Task 3 commit)

**2. [Rule 1 - Bug] Test's blocking client-side read hung because TcpConnection::close() posts the real socket close onto context_**
- **Found during:** Task 3 (first run of the new `AcceptRejectedByGaterClosesConnectionWithoutUpgrading` test — hung indefinitely)
- **Issue:** `TcpConnection::close()` does not close the socket synchronously; it calls `boost::asio::post(context_, [self, reason] { self->doClose(reason); })` to keep socket operations serialized on the connection's io_context. The test pumped the manual `scheduler_backend` (triggering the gater rejection and the `close()` call) only *after* `context->run_for(100ms)` had already returned, so the posted `doClose()` sat in the io_context's queue forever, and the client's blocking `boost::asio::read()` never observed the close.
- **Fix:** Added a second `context->run_for(100ms)` call after pumping the scheduler, so the posted `doClose()` actually executes before the client attempts its blocking read.
- **Files modified:** `test/libp2p/transport/tcp/tcp_listener_test.cpp`
- **Verification:** The test now completes in ~230ms and passes; the client's read observes an error (EOF/reset) as expected.
- **Committed in:** `a5b46ad` (Task 3 commit)

### Deferred (Out of Scope)

**3. [Deferred - pre-existing, unrelated] 6 TransportAdaptor::dial() call sites broken by an earlier, unrelated commit**
- **Found during:** Task 2 (`cmake --build build --target tcp_integration_test all_muxers_acceptance_test`)
- **Issue:** `TransportAdaptor::dial()`'s 3-positional-arg overloads all require a `bindaddress`/`source_addresses` parameter with no default. 5 call sites in `tcp_integration_test.cpp` and 1 in `muxer.cpp` still call `dial(peerId, address, handler)` with only 3 args.
- **Why not fixed:** Confirmed pre-existing via `git show 8640b25:...` (predates all of Phase 01); unrelated to gater wiring; explicitly out of scope per `.planning/PROJECT.md`'s Out of Scope section ("Auditing/fixing the general existing test suite's health beyond what this work touches").
- **Logged to:** `.planning/phases/01-connection-gater-interface-wiring/deferred-items.md`

---

**Total deviations:** 2 auto-fixed (both blocking issues required to reach this plan's own verification bar), 1 deferred (pre-existing, out of scope, logged separately)
**Impact on plan:** Both auto-fixes were necessary and minimal; the deferred item does not affect the correctness of this plan's own gater-wiring changes (confirmed by inspecting build output: no error references any `TcpTransport` constructor call site after Task 2's edits).

## Issues Encountered

- **`cmake --build build --target tcp_integration_test all_muxers_acceptance_test` does not fully succeed** due to the 6 pre-existing, unrelated `dial()` call sites documented above (see Deferred item 3 and `deferred-items.md`). This plan's own scope (the `TcpTransport` 4-arg constructor threading) is unaffected — no build error references any of the updated `make_shared<TcpTransport>(...)` lines.
- **`ctest --test-dir build -R tcp_listener_test -C Debug` reports 1/3 GTest cases passing, not 3/3 as the plan's acceptance criteria assumed.** The 2 pre-existing cases (`ListenCloseListen`, `DoubleClose`) fail deterministically on this native Windows/MSVC build: both assert `ec.value() == (int)std::errc::operation_canceled` (105, POSIX generic_category), but `boost::asio`'s cancellation on Windows surfaces as `system_category` value `995` (`ERROR_OPERATION_ABORTED`). Confirmed via `git show 8640b25:test/libp2p/transport/tcp/tcp_listener_test.cpp` that both assertions are byte-for-byte unmodified since long before Phase 01, and that neither test's underlying `close()`/`handle_(ec)` code path was touched by any of this plan's edits — this is a pre-existing, platform-specific (Windows/MSVC) test-suite gap, not a regression introduced by gater wiring. The new `AcceptRejectedByGaterClosesConnectionWithoutUpgrading` case (this plan's actual TEST-01 deliverable) passes.
- **Full-project build health for Phase 01 is now unblocked**: `cmake --build build --target p2p_relay` (previously blocked per 01-03-SUMMARY, pending this plan) now builds cleanly, confirming all 4 pre-existing `UpgraderSession` construction sites in the codebase are gater-aware.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- All 3 of Phase 01's wiring call sites (`Dialer` in 01-02, `UpgraderSession` in 01-03, `TcpTransport`/`TcpListener` in this plan) are now gater-aware, completing GATE-03/GATE-05/TEST-01 for all 5 hooks.
- 2 items remain documented but unfixed, both explicitly out of scope for this phase: the pre-existing MSVC/soralog `yamux_frame.cpp` incompatibility (already tracked in `STATE.md` Blockers/Concerns) and the newly-discovered pre-existing `dial()`/Windows-`ec.value()` test-suite gaps (tracked in `deferred-items.md` and this Summary).
- Phase 2 (pnet/PSK) can proceed; no further TcpTransport/TcpListener/UpgraderSession constructor-shape changes are anticipated from this phase's work.

## Self-Check: PASSED

`include/libp2p/transport/tcp/tcp_listener.hpp`, `src/transport/tcp/tcp_listener.cpp`, `include/libp2p/transport/tcp/tcp_transport.hpp`, `src/transport/tcp/tcp_transport.cpp`, `test/libp2p/transport/tcp/tcp_listener_test.cpp`, `test/libp2p/transport/tcp/tcp_integration_test.cpp`, `test/acceptance/p2p/muxer.cpp`, and `.planning/phases/01-connection-gater-interface-wiring/deferred-items.md` all verified present on disk; all 3 task commit hashes (`22da0e2`, `c1e6933`, `a5b46ad`) verified present in `git log`; `tcp_listener_test.exe` built and the new `AcceptRejectedByGaterClosesConnectionWithoutUpgrading` case verified passing via direct execution; `p2p_tcp`, `p2p_relay`, and `upgrader_session_test` all verified building/passing with no regressions.

---
*Phase: 01-connection-gater-interface-wiring*
*Completed: 2026-08-26*
