# Deferred Items -- Phase 03

Items discovered during execution that are out of scope for the current
plan/task and were not fixed, per the Scope Boundary rule.

## From 03-03 (example/ documentation plan)

**Pre-existing full-build (`TESTING=ON`) test-target failures, unrelated to
example/ or the pnet/gater code this plan documents.**

- Discovered during: Task 3's full-build verification step
  (`cmake --build build --config Debug -- -m`, all targets, no
  `--target` filter), run to confirm the 3 new example targets didn't
  break the existing 4.
- Observed: ~129 compiler/linker error lines across many `test/` targets
  unrelated to `example/`, gater, or pnet, e.g.:
  - `test/libp2p/protocol/identify_test.cpp`: `HostMock` cannot instantiate
    abstract `Host` (missing overrides for `getRelayAddresses`,
    `getObservedAddressesReal`, `connect(...)` with holepunch params,
    `getRelayRepository`, `getObservedRepository`,
    `getConnectionManagerConfig` x2) -- `Host` interface additions were
    never backfilled into `test/mock/libp2p/host/host_mock.hpp`.
  - Similar abstract-class-instantiation errors for `DialerMock`,
    `LoopbackStream`, `NiceMock<SecurityAdaptorMock>` in other unrelated
    test targets.
  - `test/deps/outcome_test.cpp`, `test/libp2p/crypto/keys_test.cpp`,
    `test/acceptance/p2p/host/protocol/client_test_session.cpp`: missing
    include files (`boost/outcome/result.hpp`, `gtest/gtest.h`) --
    consistent with the already-documented pre-existing MSVC 19.44 /
    soralog / Hunter-cache build fragility noted in STATE.md's Blockers
    section for this milestone.
  - `test/acceptance/p2p/muxer.cpp:188`: `TransportAdaptor::dial` called
    with 3 arguments -- this is the SAME already-documented deferred item
    from Phase 1 (STATE.md: "6 pre-existing TransportAdaptor::dial() call
    sites... calling dial() with only 3 args are deferred... confirmed via
    git history to predate Phase 01 entirely").
- Why deferred: none of these files were touched by this plan (which only
  added `example/05-private-network/`, `example/07-connection-gater/`,
  `example/06-private-network-gater/`, edited `example/CMakeLists.txt`,
  and made 2 CMake-wiring fixes -- `cmake/dependencies.cmake` Boost
  components, `src/network/impl/CMakeLists.txt` `p2p_dialer` link -- both
  needed only to make `EXAMPLES=ON` buildable at all). Fixing a
  library-wide `Host`-interface-vs-mocks gap and multiple unrelated
  pre-existing test-target breakages is a different, much larger scope of
  work than "author 3 example directories."
- Verified narrowly instead: grepped the full-build log for
  `example[\\/].*error` (zero matches) and confirmed all 3 new example
  `.vcxproj` targets plus the pre-existing 4 (`01-echo`, `02-kademlia`,
  `03-gossip`, `04-dnstxt`) linked successfully; ran each of the 3 new
  binaries and observed their documented output.
- Status: Deferred, not fixed. Flagged here for a future
  hardening/test-repair pass, not blocking DOCS-01/02/03.

## From 03-03 (CMake fixes made, in scope, for reference)

Two blocking CMake-wiring issues were fixed as Rule 3 auto-fixes (not
deferred -- these directly blocked this plan's own acceptance criteria):

1. `cmake/dependencies.cmake`: Boost was fetched with only
   `random filesystem program_options` components, but every
   `example/*/CMakeLists.txt` (including the pre-existing `01-echo`,
   `02-kademlia`, `04-dnstxt`) links `Boost::date_time` and
   `Boost::regex` -- `EXAMPLES=ON` had never successfully configured in
   this environment. Fixed by adding `date_time regex` to both the
   `hunter_add_package(Boost ...)` and `find_package(Boost ...)` calls.
2. `src/network/impl/CMakeLists.txt`: `p2p_dialer` (via
   `dialer_impl.cpp`'s pnet-bootstrap-refusal path added in
   03-01/03-02) references
   `libp2p::security::pnet::make_error_code(PnetError)` but never linked
   `p2p_pnet` -- any executable linking `p2p_dialer`/`p2p_default_network`
   without separately linking `p2p_pnet` (e.g. the gater-only
   `07-connection-gater` example) failed with an `LNK2019` unresolved
   external. Fixed by adding `p2p_pnet` to `p2p_dialer`'s
   `target_link_libraries`.
