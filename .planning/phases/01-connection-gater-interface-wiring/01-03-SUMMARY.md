---
phase: 01-connection-gater-interface-wiring
plan: 03
subsystem: infra
tags: [boost-di, gmock, outcome, connection-gater, upgrader, transport]

# Dependency graph
requires:
  - phase: 01-connection-gater-interface-wiring/01-01
    provides: "ConnectionGater interface, ConnectionGaterError enum, PermissiveConnectionGater default, ConnectionGaterMock"
provides:
  - "UpgraderSession 5-arg constructors (both RawConnection and Stream overloads) adding gater_/scheduler_/log_ members"
  - "interceptSecured gate in UpgraderSession::onSecured(), deriving is_initiator/remote_peer/remote_addr from the just-secured connection's own accessors"
  - "interceptUpgraded gate in the upgradeToMuxed completion lambda"
  - "Automatic relay-path coverage (secureOutboundRelay/secureInboundRelay funnel through the same onSecured())"
  - "RelayMessageProcessor threaded with gater_/scheduler_ (Rule 3 fix to keep p2p_relay compiling against the new UpgraderSession constructor shape)"
  - "test/libp2p/transport/upgrader_session_test.cpp — UpgraderSession's first-ever dedicated test file, 4 passing cases"
affects: [01-connection-gater-interface-wiring/01-04]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Gater hooks derive their arguments from the connection object's own accessors (isInitiator()/remotePeer()/remoteMultiaddr()) rather than plumbing new members through every call site, avoiding state duplication"
    - "Every gater-rejection-triggered handler_ call is deferred via scheduler_->schedule(...), matching the codebase's TODO(107) reentrancy-avoidance convention; the pre-existing non-gater error path (onSecured's early return on !rsecure) remains synchronous and unchanged"

key-files:
  created:
    - test/libp2p/transport/upgrader_session_test.cpp
  modified:
    - include/libp2p/transport/impl/upgrader_session.hpp
    - src/transport/impl/upgrader_session.cpp
    - src/transport/impl/CMakeLists.txt
    - include/libp2p/protocol/relay/relay_msg_processor.hpp
    - src/protocol/relay/relay_msg_processor.cpp
    - include/libp2p/protocol/factory/protocol_factory.hpp
    - test/mock/libp2p/transport/upgrader_mock.hpp
    - test/mock/libp2p/connection/secure_connection_mock.hpp
    - test/libp2p/transport/CMakeLists.txt

key-decisions:
  - "No new is_initiator_/remote_peer_/remote_addr_ members added to UpgraderSession; onSecured() derives all 3 interceptSecured arguments directly from rsecure.value()'s own SecureConnection accessors (isInitiator()/remotePeer()/remoteMultiaddr()), confirmed by `grep -c 'is_initiator_' upgrader_session.hpp` == 0"
  - "RelayMessageProcessor (the one UpgraderSession call site not covered by Plan 01-04's TcpTransport/TcpListener fixes) was threaded with gater_/scheduler_ now, sourced via injector.template create<>() in protocol_factory.hpp's createRelay(), rather than deferring it and leaving p2p_relay permanently broken after this plan"

patterns-established: []

requirements-completed: [GATE-03, GATE-05, TEST-01]

coverage:
  - id: D1
    description: "interceptSecured gates UpgraderSession::onSecured() after a successful security handshake; rejection closes the secure connection (guarded by !isClosed()) and defers handler_(error) via scheduler_->schedule(...), never calling upgradeToMuxed"
    requirement: "GATE-03"
    verification:
      - kind: unit
        ref: "test/libp2p/transport/upgrader_session_test.cpp#UpgraderSessionTest.SecuredRejectedClosesAndDefersHandler"
        status: pass
    human_judgment: false
  - id: D2
    description: "interceptUpgraded gates the upgradeToMuxed completion lambda after a successful mux upgrade; rejection closes the capable connection (guarded) and defers handler_(error) the same way, never delivering the connection to the caller"
    requirement: "GATE-03"
    verification:
      - kind: unit
        ref: "test/libp2p/transport/upgrader_session_test.cpp#UpgraderSessionTest.UpgradedRejectedClosesAndDefersHandler"
        status: pass
    human_judgment: false
  - id: D3
    description: "Accept path proves both hooks don't interfere with a normal, ungated upgrade: interceptSecured/interceptUpgraded both accept, upgradeToMuxed is invoked exactly once, and the handler receives the resulting capable connection"
    requirement: "GATE-03"
    verification:
      - kind: unit
        ref: "test/libp2p/transport/upgrader_session_test.cpp#UpgraderSessionTest.SecuredAcceptedProceedsToMux"
        status: pass
      - kind: unit
        ref: "test/libp2p/transport/upgrader_session_test.cpp#UpgraderSessionTest.UpgradedAcceptedInvokesHandler"
        status: pass
    human_judgment: false
  - id: D4
    description: "Relay paths (secureOutboundRelay/secureInboundRelay) are covered automatically since they funnel through the same private onSecured() as the non-relay paths — verified by code inspection (both bodies unchanged, still call onSecured() directly) rather than a dedicated relay test, per the plan's must_haves"
    requirement: "GATE-03"
    verification:
      - kind: other
        ref: "manual review of src/transport/impl/upgrader_session.cpp confirming secureOutboundRelay/secureInboundRelay bodies are unchanged and still call onSecured()"
        status: pass
    human_judgment: true
    rationale: "No dedicated automated test drives secureOutboundRelay/secureInboundRelay directly; correctness rests on the shared private onSecured() code path already covered by D1-D3, confirmed by static code review rather than a redundant relay-specific test."
  - id: D5
    description: "p2p_upgrader_session compiles cleanly with the new 5-arg constructors"
    requirement: "GATE-03"
    verification:
      - kind: other
        ref: "cmake --build build --target p2p_upgrader_session"
        status: pass
    human_judgment: false

duration: ~40min
completed: 2026-08-26
status: complete
---

# Phase 01 Plan 03: UpgraderSession Connection Gater Wiring Summary

**UpgraderSession's onSecured()/upgradeToMuxed gained interceptSecured/interceptUpgraded gater hooks (gater_/scheduler_ deps, guarded close + deferred handler on rejection), with a new dedicated 4-case test file and RelayMessageProcessor updated to keep compiling against the new constructor shape**

## Performance

- **Duration:** ~40 min
- **Started:** 2026-08-26T~20:30:00Z (approx)
- **Completed:** 2026-08-26T20:38:28Z
- **Tasks:** 2
- **Files modified:** 9 (1 created, 8 modified)

## Accomplishments
- `UpgraderSession`'s both constructors (RawConnection overload and Stream overload) gained trailing `gater`/`scheduler` parameters, stored as `gater_`/`scheduler_`/`log_` members
- `onSecured()` derives `is_initiator`/`remote_peer`/`remote_addr` from the just-secured connection's own accessors (`isInitiator()`/`remotePeer()`/`remoteMultiaddr()`) and calls `interceptSecured()` exactly once per successful handshake; on rejection it closes the secure connection (guarded by `!isClosed()`) and defers `handler_(error)` via `scheduler_->schedule(...)`, never calling `upgradeToMuxed`
- The `upgradeToMuxed` completion lambda calls `interceptUpgraded()` exactly once when the mux upgrade succeeds; on rejection it closes the capable connection the same guarded way and defers `handler_(error)` identically
- Relay paths (`secureOutboundRelay`/`secureInboundRelay`) get identical coverage automatically since both funnel through the same private `onSecured()` — their bodies are unchanged
- `test/libp2p/transport/upgrader_session_test.cpp` — `UpgraderSession`'s first-ever dedicated test file, 4 `TEST_F` cases covering accept/reject for both hooks, all passing
- Rule 3 fix: `RelayMessageProcessor` (the one `UpgraderSession` construction site not covered by Plan 01-04's `TcpTransport`/`TcpListener` fixes) threaded with `gater_`/`scheduler_`, sourced via `injector.template create<>()` in `protocol_factory.hpp`'s `createRelay()`, keeping `p2p_relay` compiling against the new constructor shape
- Rule 3 fixes: `UpgraderMock` was missing `upgradeToSecureOutboundRelay`/`upgradeToSecureInboundRelay` overrides and `SecureConnectionMock` was missing `getRawConnection()`, both leaving the mocks abstract/uninstantiable (same staleness pattern Plan 01-02 found in `CapableConnectionMock`/`ListenerMock`)

## Task Commits

Each task was committed atomically:

1. **Task 1: Add gater_/scheduler_ dependencies and interceptSecured/interceptUpgraded calls to UpgraderSession** - `e164415` (feat)
2. **Task 2: TEST-01 new upgrader_session_test.cpp for secured/upgraded gater hooks** - `986410c` (test)

**Plan metadata:** (this commit) `docs: complete 01-03 plan`

## Files Created/Modified
- `include/libp2p/transport/impl/upgrader_session.hpp` - added `gater`/`scheduler` trailing constructor params, `gater_`/`scheduler_`/`log_` members
- `src/transport/impl/upgrader_session.cpp` - `interceptSecured` gate in `onSecured()`, `interceptUpgraded` gate in `upgradeToMuxed`'s completion lambda, both with guarded close + deferred `handler_` on rejection
- `src/transport/impl/CMakeLists.txt` - added `p2p_connection_gater` to `p2p_upgrader_session`'s link libraries
- `include/libp2p/protocol/relay/relay_msg_processor.hpp` / `.cpp` - added `gater`/`scheduler` constructor params and members, threaded into the `UpgraderSession` construction in `relayConnectUpgrade()`
- `include/libp2p/protocol/factory/protocol_factory.hpp` - `createRelay()` now sources `gater`/`scheduler` via `injector.template create<>()` and passes them to `RelayMessageProcessor`
- `test/mock/libp2p/transport/upgrader_mock.hpp` - added missing `upgradeToSecureOutboundRelay`/`upgradeToSecureInboundRelay` mock overrides
- `test/mock/libp2p/connection/secure_connection_mock.hpp` - added missing `getRawConnection()` mock override
- `test/libp2p/transport/upgrader_session_test.cpp` - new dedicated test file (`UpgraderSessionTest`, 4 cases)
- `test/libp2p/transport/CMakeLists.txt` - new `upgrader_session_test` CMake test target

## Decisions Made
- No new member state added to `UpgraderSession` for `is_initiator`/`remote_peer`/`remote_addr` — all 3 `interceptSecured` arguments are derived directly from `rsecure.value()`'s own `SecureConnection` accessors, per the plan's explicit acceptance criterion (`grep -c 'is_initiator_' upgrader_session.hpp` == 0).
- `RelayMessageProcessor` was updated now (not deferred) to thread `gater_`/`scheduler_` through to its `UpgraderSession` construction site, since it is the only one of the 4 pre-existing `UpgraderSession` call sites not already scheduled for a fix in Plan 01-04 (which only touches `TcpTransport`/`TcpListener`). Leaving it unfixed would have permanently broken `p2p_relay` compilation after this phase.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] RelayMessageProcessor's UpgraderSession construction site not covered by any planned fix**
- **Found during:** Task 1 (verifying the constructor signature change didn't silently break other consumers)
- **Issue:** 4 pre-existing call sites construct `UpgraderSession` with the old 3-arg constructor: 3 in `tcp_transport.cpp` and 1 in `tcp_listener.cpp` (both explicitly fixed by Plan 01-04's Task 1), and 1 in `src/protocol/relay/relay_msg_processor.cpp::relayConnectUpgrade()` which no plan in this phase addresses. Left as-is, `p2p_relay` would fail to compile with `error C2661: no overloaded function takes 3 arguments` even after Plan 01-04 completes.
- **Fix:** Added `gater`/`scheduler` constructor parameters and matching members to `RelayMessageProcessor`, threaded into its lone `UpgraderSession` construction site. Updated `protocol_factory.hpp`'s `createRelay()` to source both dependencies via `injector.template create<>()` (both types already unconditionally bound in the DI graph since Plan 01-01/pre-existing scheduler binding), mirroring the existing pattern used there for `transport::Upgrader`.
- **Files modified:** `include/libp2p/protocol/relay/relay_msg_processor.hpp`, `src/protocol/relay/relay_msg_processor.cpp`, `include/libp2p/protocol/factory/protocol_factory.hpp`
- **Verification:** `cmake --build build --target p2p_relay` — the only remaining compile error after this fix is the pre-existing, Plan-01-04-scoped `tcp_listener.cpp`/`tcp_transport.cpp` breakage (confirmed by inspecting the build log: no errors reference `relay_msg_processor.cpp` or `protocol_factory.hpp`).
- **Committed in:** `e164415` (Task 1 commit)

**2. [Rule 3 - Blocking] UpgraderMock missing 2 mock overrides, leaving it abstract**
- **Found during:** Task 2 (first attempt to `std::make_shared<StrictMock<UpgraderMock>>()` in the new test)
- **Issue:** `Upgrader` gained `upgradeToSecureOutboundRelay`/`upgradeToSecureInboundRelay` pure-virtual methods (relay support) after `UpgraderMock` was last updated; `UpgraderMock` only implements the original 3 methods, making it an abstract, uninstantiable class (`error C2259`). Same staleness pattern Plan 01-02 found and fixed in `CapableConnectionMock`/`ListenerMock`.
- **Fix:** Added `MOCK_METHOD3(upgradeToSecureOutboundRelay, ...)` and `MOCK_METHOD2(upgradeToSecureInboundRelay, ...)` matching the real interface signatures exactly.
- **Files modified:** `test/mock/libp2p/transport/upgrader_mock.hpp`
- **Verification:** `upgrader_session_test` compiles and instantiates `StrictMock<UpgraderMock>`.
- **Committed in:** `986410c` (Task 2 commit)

**3. [Rule 3 - Blocking] SecureConnectionMock missing getRawConnection() override, leaving it abstract**
- **Found during:** Task 2 (first build of the new test file)
- **Issue:** `SecureConnection` gained `getRawConnection()` (relay support, predating this plan) after `SecureConnectionMock` was last updated, leaving it abstract (`error C2259`) and blocking `std::make_shared<SecureConnectionMock>()` in the new test.
- **Fix:** Added `MOCK_CONST_METHOD0(getRawConnection, outcome::result<std::shared_ptr<RawConnection>>(void));` matching the real interface.
- **Files modified:** `test/mock/libp2p/connection/secure_connection_mock.hpp`
- **Verification:** `upgrader_session_test` compiles and instantiates `SecureConnectionMock`; all 4 test cases pass.
- **Committed in:** `986410c` (Task 2 commit)

**4. [Rule 1 - Bug] MSVC rejects shared_ptr<Derived> passed directly as a GMock matcher argument for a shared_ptr<Base> parameter**
- **Found during:** Task 2 (first compile of `upgrader_session_test.cpp`)
- **Issue:** `EXPECT_CALL(*upgrader, upgradeToSecureInbound(raw, _))` (and similarly for `secure`/`capable`) failed to compile under MSVC 19.44 with `error C2665: no overloaded function could convert all the argument types` — MSVC's template matcher-construction deduction doesn't perform the `shared_ptr<Derived>` -> `shared_ptr<Base>` upcast implicitly inside `EXPECT_CALL`'s matcher wrapping, unlike GCC/Clang.
- **Fix:** Introduced explicitly base-typed local variables (`raw_base`, `secure_base`, `capable_base`) via ordinary `shared_ptr` converting-constructor assignment, and passed those into `EXPECT_CALL`/`WillOnce` instead of the derived-typed mock pointers.
- **Files modified:** `test/libp2p/transport/upgrader_session_test.cpp`
- **Verification:** `upgrader_session_test` compiles; all 4 cases pass.
- **Committed in:** `986410c` (Task 2 commit)

---

**Total deviations:** 4 auto-fixed (2 blocking cross-file compile breaks from the constructor signature change, 2 blocking pre-existing mock staleness, 1 MSVC-specific test compile fix)
**Impact on plan:** All 4 fixes were necessary to reach the plan's own required verification bar (`p2p_upgrader_session` builds; `upgrader_session_test` 4/4 passing) without leaving the wider codebase (`p2p_relay`) in a permanently broken state. No scope creep beyond what the constructor signature change and new test file required.

## Issues Encountered

- **Plan's `<verify>`/acceptance criteria reference the GTest suite name (`UpgraderSessionTest`) as the `ctest -R` filter, but CTest registers tests under their CMake target name (`upgrader_session_test`, lowercase with underscores), not the GTest suite name.** `ctest --test-dir build -R UpgraderSessionTest` reports "No tests were found!!!"; the correct invocation is `ctest --test-dir build -R upgrader_session_test -C Debug`, which reports 1/1 passing (the single CTest entry that runs all 4 GTest cases internally). Verified equivalently by running the compiled binary directly (`upgrader_session_test.exe`), which shows all 4 `TEST_F` cases passing. Not a code defect — purely a naming mismatch in the plan's verification command text.
- **Full-project build remains broken between this plan and Plan 01-04, by design.** `cmake --build build --target p2p_relay` (and any other target transitively depending on `p2p_tcp_listener`) fails to compile `tcp_listener.cpp`/`tcp_transport.cpp` against `UpgraderSession`'s new 5-arg constructor — this is explicitly Plan 01-04's Task 1 responsibility (confirmed by reading 01-04-PLAN.md's action block, which names these exact 4 call sites). This plan's own `<verify>` scope (`p2p_upgrader_session` target only) is unaffected and passes cleanly.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `UpgraderSession` is now gater-aware for the secured/upgraded stages, completing all 3 of the phase's wiring call sites conceptually (Dialer in 01-02, UpgraderSession in this plan) except `TcpListener`'s accept stage.
- Ready for Plan 01-04 (`TcpTransport`/`TcpListener` wiring — `interceptAccept`), which must also update its 4 `UpgraderSession` construction sites (3 in `tcp_transport.cpp`, 1 in `tcp_listener.cpp`) to append `gater_, scheduler_` per this plan's new constructor shape — exactly as 01-04-PLAN.md's Task 1 already specifies.
- The `UpgraderMock`/`SecureConnectionMock` staleness fixes (deviations 2-3) benefit Plan 01-04's own `tcp_listener_test.cpp`/`tcp_integration_test.cpp`, which also construct these mocks.

## Self-Check: PASSED

`test/libp2p/transport/upgrader_session_test.cpp` verified present on disk; both task commit hashes (`e164415`, `986410c`) verified present in `git log`; `upgrader_session_test.exe` built and all 4 `UpgraderSessionTest` cases pass via direct execution and via `ctest -R upgrader_session_test -C Debug`.

---
*Phase: 01-connection-gater-interface-wiring*
*Completed: 2026-08-26*
