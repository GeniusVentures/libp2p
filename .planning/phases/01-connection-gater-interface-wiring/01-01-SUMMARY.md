---
phase: 01-connection-gater-interface-wiring
plan: 01
subsystem: infra
tags: [boost-di, gmock, outcome, connection-gater, network]

# Dependency graph
requires: []
provides:
  - "libp2p::network::ConnectionGater interface (5 intercept hooks: interceptPeerDial, interceptAddrDial, interceptAccept, interceptSecured, interceptUpgraded)"
  - "libp2p::network::ConnectionGaterError enum + OUTCOME error category"
  - "libp2p::network::PermissiveConnectionGater Null Object default implementation"
  - "Unconditional default DI binding of network::ConnectionGater -> PermissiveConnectionGater in makeNetworkInjector()"
  - "libp2p::injector::useConnectionGater<GaterImpl>() DI override helper"
  - "libp2p::network::ConnectionGaterMock GMock test double"
  - "p2p_connection_gater CMake leaf-library target"
affects: [01-connection-gater-interface-wiring/01-02, 01-connection-gater-interface-wiring/01-03, 01-connection-gater-interface-wiring/01-04]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Null Object default pattern for pluggable interceptor interfaces (PermissiveConnectionGater always-success)"
    - "Single-implementation DI override helper using boost::di::override, mirroring existing useTransportAdaptors<>()/useSecurityAdaptors<>() array-bind helpers but for a scalar bind"

key-files:
  created:
    - include/libp2p/network/connection_gater.hpp
    - include/libp2p/network/connection_gater_error.hpp
    - src/network/connection_gater_error.cpp
    - include/libp2p/network/impl/permissive_connection_gater.hpp
    - test/mock/libp2p/network/connection_gater_mock.hpp
  modified:
    - src/network/CMakeLists.txt
    - include/libp2p/injector/network_injector.hpp

key-decisions:
  - "ConnectionGaterError enumerators start at =1 (RawConnection::Error convention), not PeerError's =0 style, per CLAUDE.md's SCREAMING_SNAKE_CASE-starting-at-1 error code convention"
  - "useConnectionGater<GaterImpl>() binds a single type via boost::di::bind<...>().template to<GaterImpl>(), distinct from the array-bind (TransportAdaptor*[]) pattern used by useTransportAdaptors/useSecurityAdaptors/useMuxerAdaptors, since D-05 only supports one gater implementation at a time"

patterns-established:
  - "Pattern 1: New pluggable subsystem interfaces get a Null Object default that is always bound unconditionally in the injector, plus a use<X><Impl>() override helper documented in the file's top-of-file Doxygen example block"

requirements-completed: [GATE-01, GATE-02, GATE-04]

coverage:
  - id: D1
    description: "ConnectionGater interface with exactly 5 intercept hooks, each returning outcome::result<void>, named per D-01's camelCase convention"
    requirement: "GATE-01"
    verification:
      - kind: other
        ref: "cmake --build build --target p2p_connection_gater (compiles headers including connection_gater.hpp)"
        status: pass
    human_judgment: false
  - id: D2
    description: "PermissiveConnectionGater Null Object default, unconditionally bound in makeNetworkInjector() so unconfigured hosts retain today's unrestricted behavior"
    requirement: "GATE-02"
    verification:
      - kind: other
        ref: "cmake --build build --target p2p_connection_gater (compiles permissive_connection_gater.hpp); manual review of network_injector.hpp diff confirming single unconditional di::bind<network::ConnectionGater>() line"
        status: pass
    human_judgment: true
    rationale: "Full DI-graph resolution proof (injector.create<shared_ptr<ConnectionGater>>() actually yielding PermissiveConnectionGater at runtime) requires a runnable test binary; the transitive dependency chain (network_injector_test -> yamux) currently fails to compile in this environment due to a pre-existing, unrelated soralog/MSVC header incompatibility (see Known Stubs / Issues Encountered). Header-level compilation and manual code review confirm correctness, but end-to-end DI resolution has not been executed."
  - id: D3
    description: "useConnectionGater<GaterImpl>() DI override helper lets an integrator swap the default gater with zero source changes to any call site"
    requirement: "GATE-04"
    verification:
      - kind: other
        ref: "manual review of include/libp2p/injector/network_injector.hpp useConnectionGater<>() template, mirrored against useTransportAdaptors<>()/useMuxerAdaptors<>() pattern"
        status: pass
    human_judgment: true
    rationale: "Same pre-existing build-chain blocker as D2 prevents compiling network_injector_test.cpp, so the override helper has not been exercised in a compiled test; it is syntactically identical in shape to the existing, already-tested useTransportAdaptors<>()/useMuxerAdaptors<>() helpers."

duration: ~35min
completed: 2026-08-26
status: complete
---

# Phase 01 Plan 01: Connection Gater Interface + DI Wiring Summary

**ConnectionGater interface (5 hooks) + PermissiveConnectionGater Null Object default + useConnectionGater<>() DI override helper, unconditionally wired into makeNetworkInjector()**

## Performance

- **Duration:** ~35 min
- **Started:** 2026-08-26T18:50:00Z (approx)
- **Completed:** 2026-08-26T19:24:57Z
- **Tasks:** 3
- **Files modified:** 7 (5 created, 2 modified)

## Accomplishments
- `ConnectionGater` interface with exactly 5 pure virtual hooks (`interceptPeerDial`, `interceptAddrDial`, `interceptAccept`, `interceptSecured`, `interceptUpgraded`), each returning `outcome::result<void>`
- `ConnectionGaterError` enum (5 `GATER_`-prefixed values starting at `=1`) plus its `OUTCOME_HPP_DECLARE_ERROR`/`OUTCOME_CPP_DEFINE_CATEGORY` registration, with per-hook rejection messages
- `PermissiveConnectionGater` Null Object implementing all 5 hooks as unconditional `outcome::success()`
- Unconditional default DI binding `di::bind<network::ConnectionGater>().TEMPLATE_TO<network::PermissiveConnectionGater>()` inside `makeNetworkInjector()`
- `useConnectionGater<GaterImpl>()` DI override helper, documented in the file's top-of-file Doxygen Example 2 alongside `useTransportAdaptors`/`useMuxerAdaptors`/`useSecurityAdaptors`
- `ConnectionGaterMock` GMock test double covering all 5 hooks at their exact arities (1/2/2/3/1)
- New `p2p_connection_gater` CMake leaf-library target (`connection_gater_error.cpp`), linked against `Boost::boost`, `p2p_peer_id`, `p2p_multiaddress`

## Task Commits

Each task was committed atomically:

1. **Task 1: Define ConnectionGater interface and ConnectionGaterError enum** - `fd06a2b` (feat)
2. **Task 2: Implement PermissiveConnectionGater and wire DI default binding + override helper** - `bc8576e` (feat)
3. **Task 3: Add ConnectionGaterMock test double** - `c18a540` (test)

**Plan metadata:** (this commit) `docs: complete 01-01 plan`

## Files Created/Modified
- `include/libp2p/network/connection_gater.hpp` - `ConnectionGater` abstract interface, 5 intercept hooks
- `include/libp2p/network/connection_gater_error.hpp` - `ConnectionGaterError` enum + OUTCOME error declaration
- `src/network/connection_gater_error.cpp` - OUTCOME error category definition with per-hook messages
- `include/libp2p/network/impl/permissive_connection_gater.hpp` - `PermissiveConnectionGater` Null Object default
- `test/mock/libp2p/network/connection_gater_mock.hpp` - `ConnectionGaterMock` GMock double
- `src/network/CMakeLists.txt` - added `p2p_connection_gater` leaf-library target
- `include/libp2p/injector/network_injector.hpp` - added includes, `useConnectionGater<>()` helper, unconditional default binding, updated Doxygen example

## Decisions Made
- `ConnectionGaterError` starts at `=1` (matching `RawConnection::Error`, per CLAUDE.md's "start at 1" convention) rather than `PeerError`'s `=0` style, since `PeerError::SUCCESS = 0` is a special legacy case not applicable here.
- `useConnectionGater<GaterImpl>()` binds a single scalar type (`boost::di::bind<network::ConnectionGater>().template to<GaterImpl>()`) rather than the `TransportAdaptor*[]`/`SecurityAdaptor*[]` array-bind pattern used by `useTransportAdaptors`/`useSecurityAdaptors`/`useMuxerAdaptors`, since D-05 specifies a single-implementation rebind, not a plural registry.

## Deviations from Plan

None - plan executed exactly as written. All 5 hooks, error codes, DI wiring, and mock methods match the plan's `<action>` and `<acceptance_criteria>` blocks verbatim.

## Issues Encountered

- **Pre-existing, unrelated build-chain failure blocking full-project verification beyond the plan's specified `<verify>` target.** The plan's own `<verify>` commands only require `cmake --build build --target p2p_connection_gater`, which passed cleanly for all 3 tasks. However, attempting to go further and build `network_injector_test` (the actual consumer of the DI wiring added in Task 2) fails with MSVC errors in `src/muxer/yamux/yamux_frame.cpp` originating from `soralog/util.hpp` (`error C2589`, `error C2660: 'memcpy' function does not take 2 arguments`, `error C2059`) — a `memcpy`/template-argument incompatibility between the current MSVC toolset (19.44) and the pinned soralog headers, unrelated to anything touched in this plan.
  - **Confirmed pre-existing:** reproduced by `git stash`-ing all of this plan's changes and rebuilding `p2p_yamuxed_connection` directly — the same errors occur with zero changes from this plan present.
  - **Scope decision:** per the executor's scope boundary rules, this is an out-of-scope, pre-existing environment/toolchain issue not caused by this plan's changes, and is not part of any file this plan touches. Not auto-fixed.
  - **Impact:** `ConnectionGater`/`PermissiveConnectionGater`/`useConnectionGater<>()` compile correctly at the header level (verified via `p2p_connection_gater` target and manual diff review), but end-to-end DI-graph resolution (`injector.create<std::shared_ptr<network::ConnectionGater>>()` actually yielding a `PermissiveConnectionGater` instance) has not been exercised via a compiled/run test binary in this environment, since `network_injector_test` cannot currently link due to the unrelated yamux failure.
  - **Recommendation:** flag this pre-existing yamux/soralog MSVC incompatibility to the project maintainers as a separate environment fix; it will also block full compilation/testing in Plans 01-02, 01-03, and 01-04 unless resolved.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `ConnectionGater` interface, `ConnectionGaterError`, `PermissiveConnectionGater`, `useConnectionGater<>()`, and `ConnectionGaterMock` are all in place and ready to be consumed by:
  - Plan 01-02 (Dialer wiring — `interceptPeerDial`/`interceptAddrDial`)
  - Plan 01-03 (UpgraderSession wiring — `interceptSecured`/`interceptUpgraded`)
  - Plan 01-04 (TcpTransport/TcpListener wiring — `interceptAccept`)
- **Blocker for downstream plans:** the pre-existing yamux/soralog MSVC compile failure (see Issues Encountered) will block full builds/tests for 01-02/01-03/01-04 too, since most of the library (including `p2p_default_network` and any test target linking yamux) transitively depends on `p2p_yamuxed_connection`. This should be resolved (or at minimum re-confirmed as still blocking) before those plans attempt full-project verification.

## Self-Check: PASSED

All 5 created files verified present on disk; all 3 task commit hashes (fd06a2b, bc8576e, c18a540) verified present in git log.

---
*Phase: 01-connection-gater-interface-wiring*
*Completed: 2026-08-26*
