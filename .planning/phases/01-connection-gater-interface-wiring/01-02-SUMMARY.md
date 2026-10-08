---
phase: 01-connection-gater-interface-wiring
plan: 02
subsystem: infra
tags: [boost-di, gmock, outcome, connection-gater, dialer, network]

# Dependency graph
requires:
  - phase: 01-connection-gater-interface-wiring/01-01
    provides: "ConnectionGater interface, ConnectionGaterError enum, PermissiveConnectionGater default, ConnectionGaterMock"
provides:
  - "DialerImpl 6-arg constructor (adds gater) with gater_ member + BOOST_ASSERT"
  - "interceptPeerDial gate in DialerImpl::dial() before any connection reuse/lookup"
  - "interceptAddrDial gate in DialerImpl::rotate()'s relay branch, non-relay branch, and DialerImpl::rotateHolepunch()'s loop"
  - "DialCtx::result-based error propagation so a gater rejection surfaces as GATER_REJECTED_ADDR_DIAL via completeDial() once addresses are exhausted"
  - "TEST_F(DialerTest, DialRejectedByPeerDialGater), TEST_F(DialerTest, DialRejectedByAddrDialGater)"
affects: [01-connection-gater-interface-wiring/01-03, 01-connection-gater-interface-wiring/01-04]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Gater hooks are called unconditionally (Null Object pattern from 01-01) before any transport-layer call, with rejections always scheduled via basic::Scheduler, never invoked synchronously"
    - "ctx.dialled is only set true on a genuine dial/reuse attempt OR on a gater rejection specifically so completeDial()'s check-order (!ctx.dialled before ctx.result.has_value()) surfaces the correct gater error instead of the generic address_family_not_supported fallback"

key-files:
  created: []
  modified:
    - include/libp2p/network/impl/dialer_impl.hpp
    - src/network/impl/dialer_impl.cpp
    - src/network/impl/CMakeLists.txt
    - test/libp2p/network/dialer_test.cpp
    - test/mock/libp2p/connection/capable_connection_mock.hpp
    - test/mock/libp2p/network/listener_mock.hpp

key-decisions:
  - "ctx.dialled is set true (not left false) on interceptAddrDial rejection in both rotate() branches — required for completeDial()'s existing check order (!ctx.dialled fires before ctx.result.has_value()) to surface GATER_REJECTED_ADDR_DIAL instead of falling through to address_family_not_supported; verified by the new DialRejectedByAddrDialGater test"
  - "rotateHolepunch()'s loop skips the rejected address via `continue` without setting indctx.dialled, matching the existing 'no transport found' no-op idiom, since there is no per-holepunch result-propagation field to surface the error through (pre-existing tracking gap, out of scope per plan)"

patterns-established: []

requirements-completed: [GATE-03, TEST-01]

coverage:
  - id: D1
    description: "interceptPeerDial gates DialerImpl::dial() before any connection reuse/in-progress-dial lookup; rejection is scheduled (never synchronous) and logged via SL_DEBUG"
    requirement: "GATE-03"
    verification:
      - kind: unit
        ref: "test/libp2p/network/dialer_test.cpp#DialerTest.DialRejectedByPeerDialGater"
        status: pass
    human_judgment: false
  - id: D2
    description: "interceptAddrDial gates all 3 tr->dial(...) call sites (rotate() relay branch, rotate() non-relay branch, rotateHolepunch() loop); rejection blocks the transport call and is logged via SL_DEBUG"
    requirement: "GATE-03"
    verification:
      - kind: unit
        ref: "test/libp2p/network/dialer_test.cpp#DialerTest.DialRejectedByAddrDialGater"
        status: pass
      - kind: other
        ref: "grep -c 'interceptAddrDial(' src/network/impl/dialer_impl.cpp == 3; grep -c 'interceptPeerDial(' src/network/impl/dialer_impl.cpp == 1"
        status: pass
    human_judgment: false
  - id: D3
    description: "All 8 pre-existing DialerTest cases keep passing after the fixture change (gater defaults to permissive via ON_CALL)"
    requirement: "TEST-01"
    verification:
      - kind: unit
        ref: "ctest --test-dir build -R dialer_test -C Debug (10/10 passing, includes the 8 pre-existing cases)"
        status: pass
    human_judgment: false

duration: ~55min
completed: 2026-08-26
status: complete
---

# Phase 01 Plan 02: Dialer Connection Gater Wiring Summary

**ConnectionGater wired into DialerImpl's dial/rotate/rotateHolepunch paths (interceptPeerDial + interceptAddrDial at all 3 tr->dial call sites), with 2 new DialerTest cases and 10/10 DialerTest passing**

## Performance

- **Duration:** ~55 min
- **Started:** 2026-08-26T~19:30:00Z (approx)
- **Completed:** 2026-08-26T~20:25:00Z
- **Tasks:** 2
- **Files modified:** 6

## Accomplishments
- `DialerImpl` gained a 6th constructor parameter (`gater`) and `gater_` member with `BOOST_ASSERT(gater_ != nullptr)`, auto-resolved by Boost.DI (confirmed via `network_injector_test` build — no linker errors related to `DialerImpl`/`ConnectionGater`)
- `interceptPeerDial(p.id)` gates `dial()` before `cmgr_->getBestConnectionForPeer` and the `dialing_peers_`/`dialing_holepunches_` in-progress lookups — a rejection schedules the callback with `GATER_REJECTED_PEER_DIAL` and never touches the transport layer
- `interceptAddrDial(peer_id, addr)` gates all 3 `tr->dial(...)` call sites: `rotate()`'s relay branch (gated with the outer `peer_id`, not the relay hop's `peer_id_actual`), `rotate()`'s non-relay branch, and `rotateHolepunch()`'s previously-unwired loop (closing the silent holepunch bypass called out in RESEARCH.md Pitfall 3)
- A rejected address in `rotate()` sets `ctx.result` and `ctx.dialled = true`, so once all addresses are exhausted `completeDial()` surfaces `GATER_REJECTED_ADDR_DIAL` via the existing `ctx.result`-propagation path instead of the generic `address_family_not_supported` fallback
- 2 new `DialerTest` cases (`DialRejectedByPeerDialGater`, `DialRejectedByAddrDialGater`) proving the transport layer is never reached on rejection; all 10 `DialerTest` cases pass

## Task Commits

Each task was committed atomically:

1. **Task 1: Wire ConnectionGater into DialerImpl's dial/rotate/rotateHolepunch paths** - `427a3f3` (feat)
2. **Task 2: TEST-01 dialer gater unit tests** - `6929a6b` (test)

**Plan metadata:** (this commit) `docs: complete 01-02 plan`

## Files Created/Modified
- `include/libp2p/network/impl/dialer_impl.hpp` - added `#include <libp2p/network/connection_gater.hpp>`, 6th ctor param `gater`, `gater_` member
- `src/network/impl/dialer_impl.cpp` - `interceptPeerDial` gate in `dial()`; `interceptAddrDial` gates in `rotate()`'s relay/non-relay branches and `rotateHolepunch()`'s loop; constructor updated with `gater_` init + assert
- `src/network/impl/CMakeLists.txt` - linked `p2p_connection_gater` into `p2p_dialer` for the `ConnectionGaterError` category symbol
- `test/libp2p/network/dialer_test.cpp` - `ConnectionGaterMock` wired into the fixture with permissive `ON_CALL` defaults; 2 new gater-rejection test cases; fixed a pre-existing MSVC C++20-only designated-initializer error and 2 pre-existing tests whose `EXPECT_CALL` targeted a stale, no-longer-invoked 4-arg `TransportMock::dial` overload
- `test/mock/libp2p/connection/capable_connection_mock.hpp` - added missing `getRawConnection`/`setRelay`/`isRelay`/`getStreams` mock overrides so `CapableConnectionMock` satisfies its now-extended interface
- `test/mock/libp2p/network/listener_mock.hpp` - added missing `onConnectionRelay`/`removeRelayedConnections` mock overrides so `ListenerMock` satisfies its now-extended interface

## Decisions Made
- `ctx.dialled = true` on `interceptAddrDial` rejection (both `rotate()` branches), not left `false` — required by `completeDial()`'s pre-existing check order (`!ctx.dialled` is checked before `ctx.result.has_value()`); leaving it `false` caused the generic `address_family_not_supported` error to win instead of the intended `GATER_REJECTED_ADDR_DIAL`. Discovered via the new `DialRejectedByAddrDialGater` test failing with the wrong error code, then fixed and re-verified.
- `rotateHolepunch()`'s rejected-address path uses `continue` (skip to next address) without touching `indctx.dialled`, matching the plan's explicit call-out that holepunch completion-tracking gaps are pre-existing and out of scope.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] `ctx.dialled` left `false` on gater rejection produced the wrong propagated error**
- **Found during:** Task 2 (writing/running `DialRejectedByAddrDialGater`)
- **Issue:** The plan's literal task text said to leave `ctx.dialled` false on `interceptAddrDial` rejection, but `rotate()`'s existing check order (`if (addresses.empty() && !ctx.dialled) → address_family_not_supported` runs *before* `if (addresses.empty() && ctx.result.has_value()) → ctx.result.value()`) meant the generic fallback error won instead of `GATER_REJECTED_ADDR_DIAL`, contradicting the plan's own `key_links` requirement that `ctx.result` propagate through `completeDial()`.
- **Fix:** Set `ctx.dialled = true` alongside `ctx.result = outcome::failure(gated.error())` in both `rotate()` rejection branches (relay and non-relay), so the second check branch fires and surfaces the correct gater error.
- **Files modified:** `src/network/impl/dialer_impl.cpp`
- **Verification:** `DialRejectedByAddrDialGater` passes; `ctest -R dialer_test -C Debug` 10/10 passing.
- **Committed in:** `6929a6b` (Task 2 commit)

**2. [Rule 3 - Blocking] Pre-existing MSVC C++20-only designated-initializer error blocked all compilation of `dialer_test.cpp`**
- **Found during:** Task 2 (first build attempt)
- **Issue:** `peer::PeerInfo pinfo{.id = pid, .addresses = {ma1}};` (pre-existing, unmodified by this plan) uses C++20 designated initializers, which MSVC rejects under `/std:c++17` (`error C7555`). This is unrelated to gater wiring but blocks the file from compiling at all.
- **Fix:** Rewrote as positional aggregate init: `peer::PeerInfo pinfo{pid, {ma1}};` (same field order, same values, C++17-legal).
- **Files modified:** `test/libp2p/network/dialer_test.cpp`
- **Verification:** File compiles under MSVC C++17.
- **Committed in:** `6929a6b` (Task 2 commit)

**3. [Rule 3 - Blocking] Stale `CapableConnectionMock`/`ListenerMock` missing overrides for interface methods added since the mocks were last touched**
- **Found during:** Task 2 (compiling `dialer_test.cpp`)
- **Issue:** `CapableConnection`/`SecureConnection` gained `getRawConnection`, `setRelay`, `isRelay`, `getStreams` (relay/idle-detection features) and `ListenerManager` gained `onConnectionRelay`, `removeRelayedConnections` (relay support) after these mock files were last updated, leaving both mocks abstract and un-instantiable (`std::make_shared<CapableConnectionMock>()`/`ListenerMock()` failed with `error C2259: cannot instantiate abstract class`), blocking `dialer_test.cpp` from compiling.
- **Fix:** Added the 4 missing `MOCK_METHOD`/`MOCK_CONST_METHOD` declarations to `CapableConnectionMock` and the 2 missing ones to `ListenerMock`, matching the real interface signatures exactly.
- **Files modified:** `test/mock/libp2p/connection/capable_connection_mock.hpp`, `test/mock/libp2p/network/listener_mock.hpp`
- **Verification:** `dialer_test.exe` links and runs.
- **Committed in:** `6929a6b` (Task 2 commit)

**4. [Rule 1 - Bug] 2 pre-existing `DialerTest` cases (`DialAllTheAddresses`, `DialNewConnection`) targeted a stale, no-longer-invoked `TransportMock::dial` overload**
- **Found during:** Task 2 (first test run — both failed with `executed: false` and unsatisfied `EXPECT_CALL`s, plus GMock "uninteresting mock function call" warnings for the real 7-arg overload)
- **Issue:** `TransportAdaptor::dial` gained `bindaddress`/`source_addresses` overloads (relay/dual-stack routing work, predating this plan) that supersede the old 4-arg `(peerId, addr, handler, timeout)` shape `TransportMock` still declares via `MOCK_METHOD4`. `DialerImpl` has called the 5-arg `dial(peer_id, addr, handler, timeout, source_addresses)` overload (which the base class translates into the pure-virtual 7-arg overload, dispatched via `MOCK_METHOD7`) since before this plan touched the file — the tests' `EXPECT_CALL`s on the 4-arg overload were never actually exercised. Not caused by gater wiring; confirmed pre-existing by tracing `TransportAdaptor`'s overload history (`942d3cb` originally added a simple 4-arg `dial`, later superseded).
- **Fix:** Updated both `EXPECT_CALL(*transport, dial(...))` invocations to the 7-arg signature actually dispatched (`dial(peerId, addr, handler, timeout, _, false, false)`), matching `MOCK_METHOD7`.
- **Files modified:** `test/libp2p/network/dialer_test.cpp`
- **Verification:** Both tests pass; `ctest -R dialer_test -C Debug` 10/10 passing.
- **Committed in:** `6929a6b` (Task 2 commit)

---

**Total deviations:** 4 auto-fixed (1 bug in new code, 2 blocking pre-existing compile issues, 1 bug in pre-existing tests)
**Impact on plan:** All 4 fixes were necessary to reach the plan's own required verification bar (`ctest -R dialer_test` 10/10 passing) and none touch out-of-scope files beyond what `dialer_test.cpp`'s compilation/linking required. No scope creep beyond unblocking this plan's own deliverable.

## Issues Encountered

- **Pre-existing, unrelated `network_injector_test` link failure — out of scope, not fixed.** Attempting `cmake --build build --target network_injector_test` (beyond this plan's own `<verify>` requirement, done as an extra DI-resolution sanity check) fails with `LNK2019: unresolved external symbol ... SecMock ... is_not_bound` in `NetworkBuilder_CustomAdaptorsBuilds_Test::TestBody`. This is a local test-scoped `SecMock` DI-binding issue in an unrelated security-adaptor test, with no connection to `ConnectionGater`/`DialerImpl`. No other symbols related to this plan's changes were unresolved, confirming `DialerImpl`'s new `gater` parameter resolves correctly through Boost.DI. Not auto-fixed (out of scope — different subsystem, different test file, pre-existing).
- The pre-existing MSVC/soralog yamux compile blocker flagged by 01-01's SUMMARY did **not** reproduce in this environment — `p2p_dialer`, `dialer_test`, and `network_injector_test` (transitively depending on `p2p_yamuxed_connection`) all compiled and linked yamux successfully. The blocker may have been resolved or was environment/config-specific; not re-investigated further since it's not blocking this plan.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `ConnectionGater` is now wired into both DI construction (01-01) and the Dialer stage (01-02: peer dial + address dial, including the holepunch loop).
- Ready for Plan 01-03 (`UpgraderSession` wiring — `interceptSecured`/`interceptUpgraded`) and Plan 01-04 (`TcpTransport`/`TcpListener` wiring — `interceptAccept`), both of which can follow the same "gate before the pipeline action, schedule the rejection, log via SL_DEBUG" pattern established here.
- The `CapableConnectionMock`/`ListenerMock` staleness fix (deviation 3) benefits any future test in this codebase that instantiates these mocks, since they were previously non-compilable.

## Self-Check: PASSED

All 6 modified files verified present on disk with expected changes; both task commit hashes (427a3f3, 6929a6b) verified present in `git log`; `dialer_test.exe` built and all 10 `DialerTest` cases pass via direct execution and via `ctest -R dialer_test -C Debug`.

---
*Phase: 01-connection-gater-interface-wiring*
*Completed: 2026-08-26*
