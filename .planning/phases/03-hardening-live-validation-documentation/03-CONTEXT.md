# Phase 3: Hardening, live validation & documentation - Context

**Gathered:** 2026-08-26
**Status:** Ready for planning

<domain>
## Phase Boundary

The combined gater (Phase 1) + pnet (Phase 2) access-control boundary is proven under live two-node and reentrant-callback conditions — the two failure modes this codebase has historically shipped bugs in — and integrators get runnable documentation for both layers. This phase covers TEST-03 (live two-node PSK test), TEST-04 (reentrancy regression test), and DOCS-01/02/03 (integrator documentation for PSK config, custom gater registration, and the complementary-layers explanation). It does not add new gater/pnet functionality — both are already implemented and unit-tested (Phase 1 complete, Phase 2 complete).

</domain>

<decisions>
## Implementation Decisions

### Live two-node PSK test (TEST-03)
- **D-01:** New test directory `test/acceptance/p2p/pnet/`, separate from `test/acceptance/p2p/host/` — keeps pnet-specific acceptance tests aligned with the `src/security/pnet/` module boundary rather than folding into the existing `host_integration_test.cpp`.
- **D-02:** Exactly 2 nodes, purpose-built fixture — not a reuse/extension of `HostIntegrationTest`'s parametrized `TestWithParam<HostIntegrationTestConfig>` N-peer echo fixture (that fixture is built around echo-ping-many-peers, not accept/reject semantics). Matches the roadmap's literal "live two-node test" wording.
- **D-03:** Mismatched-PSK rejection is asserted black-box, from the dialing peer's side: the connection attempt fails or times out and no stream ever opens, within a bounded timeout — following the same future/promise-wait pattern `HostIntegrationTest` already uses. Not asserting a specific `PnetError` code at the connect callback (that's a stronger claim than the roadmap success criterion requires: "the attempt fails at the pnet layer and never reaches multiselect").
- **D-04:** Runs in the default `ctest` suite via normal `addtest()`, same treatment as `host_integration_test.cpp` (which is already TCP-loopback and already "live") — no new CMake gating option introduced for this.

### Reentrancy regression test (TEST-04)
- **D-05:** Scope is both new-code surfaces from Phases 1–2: the 5 gater hooks (`interceptPeerDial`/`interceptAddrDial`/`interceptAccept`/`interceptSecured`/`interceptUpgraded`) AND the pnet decorator/connection (`PnetUpgraderDecorator`, `PnetProtectedConnection`). Matches TEST-04's wording ("gater and pnet callback paths") exactly. Explicitly NOT extended to the pre-existing `TODO(107): Reentrancy` sites elsewhere (secio/plaintext/tcp_transport/mplex) — those are out of scope per PROJECT.md's "auditing/fixing the general existing test suite's health beyond what this work touches."
- **D-06:** Force reentrancy via a test double (mock `ConnectionGater` / mock `RawConnection`) whose `interceptX()`/`read()`/`write()` invokes the passed completion callback synchronously, inline, before returning — exercises the real production call sites (`Dialer`, `UpgraderSession`, `PnetUpgraderDecorator`) against a worst-case collaborator, rather than testing the `Scheduler` boundary in isolation.
- **D-07:** Pass criterion is a stack-depth / re-entry-flag assertion — instrument the code path under test with a re-entrancy guard (an "inside call" flag/counter checked and set around the risky region) and assert it's never true/nonzero when the deferred callback actually fires. This directly proves no reentrant execution occurred, rather than inferring it from gmock call-ordering.

### Documentation format & location (DOCS-01, DOCS-02)
- **D-08:** Documentation is runnable code under `example/`, no separate markdown narrative layer — follows this repo's existing convention exactly (README.md already says "explore example/ to read examples of how to use the library").
- **D-09:** Each `example/<N>-<name>/` directory gets its own `README.md`, matching the existing pattern already present in `example/01-echo/`, `example/02-kademlia/`, `example/03-gossip/` (confirmed via repo scan — not a new top-level `docs/` structure).
- **D-10:** DOCS-01 (PSK config) and DOCS-02 (custom gater) are two separate example directories, each focused on one layer — `example/05-private-network/` for PSK-only, a second dir for gater-only — matching the existing one-topic-per-example-dir granularity (01-echo, 02-kademlia, 03-gossip are each single-concept).

### Complementary PSK+gater worked example (DOCS-03)
- **D-11:** A third example directory, `example/06-private-network-gater/`, dedicated to the "valid PSK, gater-denied peer" scenario — standalone from the two single-layer examples, continuing the one-topic-per-example-dir convention rather than folding into either of them or living only as cross-referencing prose.
- **D-12:** Runnable code, not a narrated/pseudocode walkthrough — consistent with D-08's "code is the documentation" convention. This is independent of the Phase 3 live two-node test (`test/acceptance/p2p/pnet/`, D-01) — the example is a documentation artifact for integrators to read/run, not a third test case bolted onto the regression suite.

### Claude's Discretion
None — all 4 discussed areas resulted in explicit decisions above.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Project scope & requirements
- `.planning/PROJECT.md` — core value, constraints (C++17, DI-only construction, upgrade-pipeline integration, pnet spec compliance), out-of-scope list
- `.planning/REQUIREMENTS.md` — TEST-03, TEST-04, DOCS-01, DOCS-02, DOCS-03 (this phase's mapped requirements)
- `.planning/ROADMAP.md` §"Phase 3: Hardening, live validation & documentation" — goal, 5 success criteria, dependency on Phase 1 + Phase 2

### Prior phase context (patterns to reuse, conventions this phase follows)
- `.planning/phases/01-connection-gater-interface-wiring/01-CONTEXT.md` — Phase 1 decisions: hook naming (`interceptX` camelCase), `GATER_`-prefixed error codes, null-object default, `SL_DEBUG` rejection logging, scheduler `post`/`dispatch` requirement
- `.planning/phases/02-private-network-pnet-psk-protector/02-CONTEXT.md` — Phase 2 decisions: pnet wrap point (`Upgrader` decorator + `RawConnection` decorator before multiselect), `usePrivateNetwork(key)` combined DI module, silent bootstrap-filter semantics (D-11–D-13), `SL_DEBUG` dial-refusal logging
- `.planning/phases/02-private-network-pnet-psk-protector/02-04-SUMMARY.md` — "Notes for Phase 3" section: `makeHostInjector(usePrivateNetwork(swarm_key_text))` is the complete integration surface; flags that identify/kademlia-initiated connections traverse `DialerImpl` too (same bootstrap gate) but a live two-node test should confirm no other dial entry point bypasses it; relay streams remain unwrapped (documented limitation, not a regression target)

### Codebase maps
- `.planning/codebase/TESTING.md` — GTest/GMock conventions, `test/acceptance/p2p/host/` structure, `EXPECT_OUTCOME_TRUE/FALSE` macros, fixture patterns (`TEST_F`, `@given/@when/@then` doc blocks), legacy `MOCK_METHODn` mock style
- `.planning/codebase/CONCERNS.md` — documented concurrency/reentrancy history (scheduler, yamux, TCP transport); the 10 pre-existing `TODO(107): Reentrancy` sites this phase's TEST-04 explicitly does NOT extend to; "Test Coverage Gaps" section confirms concurrency/reentrancy regression tests are historically absent — this phase closes that gap for the new gater/pnet surface specifically
- `.planning/codebase/STRUCTURE.md` — `example/` directory convention (each subdir a standalone CMake target + own README), `test/acceptance/p2p/host/` layout this phase's new `test/acceptance/p2p/pnet/` mirrors

### Existing code to reuse as templates
- `test/acceptance/p2p/host/host_integration_test.cpp` — the multi-peer, real-`BasicHost`, TCP-loopback fixture pattern (`TestWithParam`, `PeerPromise`/`PeerFuture`, `TearDown`) the new 2-node PSK test adapts (D-01–D-04)
- `README.md` §"Examples" — confirms the "code is the documentation, see example/" convention (D-08)
- `example/01-echo/README.md`, `example/02-kademlia/README.md`, `example/03-gossip/README.md` — the per-example-dir README pattern the 3 new example dirs follow (D-09)

### Project conventions
- `w:\gnus\GeniusNetwork\thirdparty\libp2p\.claude\CLAUDE.md` — naming/error-handling/logging conventions (per-module `error.hpp` enums, `OUTCOME_*` registration, `SL_*` macros, camelCase methods, trailing-underscore members)

No SPEC.md exists for this phase — requirements come directly from REQUIREMENTS.md/ROADMAP.md above.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `test/acceptance/p2p/host/host_integration_test.cpp` — real `BasicHost` + TCP transport + promise/future peer-info exchange pattern; template for the new `test/acceptance/p2p/pnet/` live 2-node test
- `test/mock/libp2p/network/connection_gater_mock.hpp` (Phase 1) and pnet's `PnetUpgraderDecorator`/`PnetProtectedConnection` (Phase 2) — the collaborators the reentrancy test doubles wrap
- `example/01-echo/`, `example/02-kademlia/`, `example/03-gossip/` — structural template (CMake target + README.md) for the 3 new example dirs (05-private-network, gater example, 06-private-network-gater)

### Established Patterns
- `outcome::result<T>` for fallible APIs; `EXPECT_OUTCOME_TRUE`/`EXPECT_OUTCOME_FALSE` macros for asserting on them in tests
- Static per-TU logger + `SL_DEBUG` — the observability convention Phase 1 (gater rejections) and Phase 2 (dial-time PSK bootstrap refusal) both follow; this phase's tests validate that convention under adversarial/reentrant conditions rather than introducing a new one
- `basic::Scheduler` `post`/`dispatch` — the mechanism under regression test in TEST-04

### Integration Points
- `makeHostInjector(usePrivateNetwork(swarm_key_text))` (per 02-04-SUMMARY.md) — the entry point both the live 2-node test and the example code construct hosts through
- `include/libp2p/injector/network_injector.hpp` — where `usePrivateNetwork(key)` and the gater DI rebind both attach; the combined example (`06-private-network-gater/`) exercises both bindings together
- `src/network/impl/dialer_impl.cpp` — bootstrap-refusal dial path Phase 2 added; 02-04-SUMMARY.md flags this as needing live-test confirmation that no other dial entry point (identify/kademlia-initiated) bypasses it

</code_context>

<specifics>
## Specific Ideas

- The user's mismatched-PSK test assertion (D-03) deliberately stays at the black-box "never establishes a usable connection" level rather than asserting a specific `PnetError` enum value — matches the roadmap success criterion's exact wording, no stronger claim added.
- The user confirmed a genuine convention (not a new invention) for D-09: `example/01-echo/README.md`, `example/02-kademlia/README.md`, and `example/03-gossip/README.md` already exist — the per-example README is pre-existing practice this phase continues, not a new pattern.
- Three new example directories total: `example/05-private-network/` (PSK only, DOCS-01), a gater-only example (DOCS-02), and `example/06-private-network-gater/` (both together, DOCS-03) — each single-topic, each with its own README, no combined/narrative-only alternative.

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope. No scope-creep suggestions came up.

</deferred>

---

*Phase: 3-Hardening, live validation & documentation*
*Context gathered: 2026-08-26*
</code_context>
