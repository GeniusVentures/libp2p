# Phase 3: Hardening, live validation & documentation - Research

**Researched:** 2026-08-26
**Domain:** GTest/GMock acceptance + regression testing of already-implemented C++17 access-control code (Boost.DI, Boost.Asio); example/doc authoring for a C++ library
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Live two-node PSK test (TEST-03)**
- D-01: New test directory `test/acceptance/p2p/pnet/`, separate from `test/acceptance/p2p/host/`.
- D-02: Exactly 2 nodes, purpose-built fixture — not a reuse/extension of `HostIntegrationTest`'s parametrized `TestWithParam<HostIntegrationTestConfig>` N-peer echo fixture.
- D-03: Mismatched-PSK rejection is asserted black-box, from the dialing peer's side: the connection attempt fails or times out and no stream ever opens, within a bounded timeout — following the same future/promise-wait pattern `HostIntegrationTest` already uses. Not asserting a specific `PnetError` code at the connect callback.
- D-04: Runs in the default `ctest` suite via normal `addtest()`, same treatment as `host_integration_test.cpp` — no new CMake gating option introduced for this.

**Reentrancy regression test (TEST-04)**
- D-05: Scope is both new-code surfaces from Phases 1-2: the 5 gater hooks (`interceptPeerDial`/`interceptAddrDial`/`interceptAccept`/`interceptSecured`/`interceptUpgraded`) AND the pnet decorator/connection (`PnetUpgraderDecorator`, `PnetProtectedConnection`). Explicitly NOT extended to the pre-existing `TODO(107): Reentrancy` sites elsewhere (secio/plaintext/tcp_transport/mplex) — out of scope per PROJECT.md.
- D-06: Force reentrancy via a test double (mock `ConnectionGater` / mock `RawConnection`) whose `interceptX()`/`read()`/`write()` invokes the passed completion callback synchronously, inline, before returning — exercises the real production call sites (`Dialer`, `UpgraderSession`, `PnetUpgraderDecorator`) against a worst-case collaborator, rather than testing the `Scheduler` boundary in isolation.
- D-07: Pass criterion is a stack-depth / re-entry-flag assertion — instrument the code path under test with a re-entrancy guard (an "inside call" flag/counter checked and set around the risky region) and assert it's never true/nonzero when the deferred callback actually fires.

**Documentation format & location (DOCS-01, DOCS-02)**
- D-08: Documentation is runnable code under `example/`, no separate markdown narrative layer — follows the existing convention exactly (README.md says "explore example/ to read examples of how to use the library").
- D-09: Each `example/<N>-<name>/` directory gets its own `README.md`, matching `example/01-echo/`, `example/02-kademlia/`, `example/03-gossip/`.
- D-10: DOCS-01 (PSK config) and DOCS-02 (custom gater) are two separate example directories, each focused on one layer — `example/05-private-network/` for PSK-only, a second dir for gater-only.

**Complementary PSK+gater worked example (DOCS-03)**
- D-11: A third example directory, `example/06-private-network-gater/`, dedicated to the "valid PSK, gater-denied peer" scenario — standalone from the two single-layer examples.
- D-12: Runnable code, not a narrated/pseudocode walkthrough — consistent with D-08's "code is the documentation" convention. Independent of the live two-node test (D-01) — the example is a documentation artifact, not a third test case.

### Claude's Discretion
None — all 4 discussed areas resulted in explicit decisions above.

### Deferred Ideas (OUT OF SCOPE)
None — discussion stayed within phase scope. No scope-creep suggestions came up.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| TEST-03 | A live two-node test confirms peers sharing a PSK connect successfully, and a peer with a missing/mismatched PSK is rejected | §"Live two-node acceptance test pattern", §"Package/CMake wiring", §"DI injector call shapes" |
| TEST-04 | New gater/pnet code delivers callbacks via the scheduler (`post`/`dispatch`) rather than invoking inline, with a regression test guarding against reentrant invocation | §"Reentrancy-forcing test technique", §"Scheduler mechanics", §"Exact gater/pnet call sites" |
| DOCS-01 | Integrator documentation explains how to configure a PSK for a private network | §"Example directory + CMake convention" |
| DOCS-02 | Integrator documentation explains how to register a custom `ConnectionGater` implementation | §"Example directory + CMake convention" |
| DOCS-03 | Documentation clarifies that pnet and the gater are complementary layers (PSK proves network membership, gater proves peer-level authorization) — not redundant | §"Example directory + CMake convention", §"Combined-layer worked example" |
</phase_requirements>

## Summary

This phase adds zero production code paths — Phase 1 (`ConnectionGater`, 5 hooks, wired through `Dialer`/`TcpListener`/`UpgraderSession`) and Phase 2 (`pnet` PSK protector: `PnetUpgraderDecorator`, `PnetProtectedConnection`, `usePrivateNetwork(key)` DI module) are both complete and unit-tested. Phase 3 is pure test-authoring (two new GTest targets) plus doc-authoring (three new `example/` directories). Every pattern needed already exists in the repo and was read in full for this research: `test/acceptance/p2p/host/host_integration_test.cpp` + its `Peer`/`PeerPromise`/`TearDown` fixture is the template for the new live two-node PSK test; `test/libp2p/transport/upgrader_session_test.cpp` already constructs a real `UpgraderSession` against a `ConnectionGaterMock` + `ManualSchedulerBackend`/`SchedulerImpl` pair with a `pump()` helper — this is the *exact* existing pattern to extend for the reentrancy regression test, not a new technique to invent. `example/01-echo/`, `02-kademlia/`, `03-gossip/` establish the `add_executable` + own-`README.md` convention the three new example dirs must follow.

Two load-bearing corrections to the phase brief surfaced during research, both documented in detail below: (1) the scheduler's actual API is `Scheduler::schedule(cb[, delay])`, not literally `post()`/`dispatch()` — REQUIREMENTS.md's wording is the *concept* (defer, don't invoke inline), not the literal method name, and the plan/tests must use `schedule()`; (2) only the **rejection** branches of the 5 gater hooks (and all PnetProtectedConnection completions) currently defer via `scheduler_->schedule(...)` — the **success/accept** branches of `interceptSecured`→`interceptUpgraded`→`handler_(...)` in `UpgraderSession` chain synchronously with whatever the inner `Upgrader`'s callback did, with no scheduler hop of their own. The existing `UpgraderSessionTest.SecuredAcceptedProceedsToMux` test already relies on this: it never needs `pump()` on the success path because everything (including `handler_cb.Call`) fires synchronously inside `session->secureInbound()`. This is not a bug to fix in Phase 3 (no production code changes allowed per phase boundary) — it is the exact shape of "reentrant execution" the regression test must characterize honestly: the guard must be scoped to the paths that scheduler-defer today (all 5 hook rejection paths + all `PnetProtectedConnection` read/write completions), not asserted universally across every hook invocation.

**Primary recommendation:** Build the reentrancy regression test as a direct extension of the existing `UpgraderSessionTest` fixture (`ConnectionGaterMock` + `ManualSchedulerBackend`/`SchedulerImpl` + `pump()`), adding a synchronous-completion `RawConnectionMock`/`UpgraderMock` action and a boolean re-entry guard checked inside the gater-rejection and pnet-completion lambdas; build the live two-node test as a purpose-built `TEST_F` fixture in `test/acceptance/p2p/pnet/` that either reuses `test/acceptance/p2p/host/peer/test_peer.hpp`'s manual (non-injector) `Peer::makeHost()` composition extended with a `PnetUpgraderDecorator`, or constructs two hosts directly via `makeHostInjector(usePrivateNetwork(key))` / `makeHostInjector()` (see DI injector call shapes below) — the injector route is simpler and is the actual GNUS integration surface, so prefer it unless a Phase-1/2-established manual-wiring precedent is required by the plan.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Live 2-node PSK accept/reject validation | Test infrastructure (GTest acceptance) | Network/Transport (real `BasicHost`+TCP) | Exercises the full DI-assembled stack over real TCP loopback, not mocks — belongs in `test/acceptance/`, matching `host_integration_test.cpp`'s precedent |
| Reentrancy regression (gater hooks + pnet decorator) | Test infrastructure (GTest unit) | Network/Transport (`Dialer`, `UpgraderSession`, `PnetUpgraderDecorator`) | Targets specific class call sites in isolation with mocked collaborators — belongs in `test/libp2p/`, matching `upgrader_session_test.cpp`'s existing pattern (NOT `test/acceptance/`) |
| PSK configuration documentation | Docs/Examples (`example/05-private-network/`) | Injector (`network_injector.hpp` `usePrivateNetwork`) | D-08: code is the documentation; the example directly demonstrates the DI entry point |
| Custom gater registration documentation | Docs/Examples (new `example/0N-connection-gater/`) | Injector (`network_injector.hpp` `useConnectionGater<T>()`) | Same rationale as above, for the gater DI entry point |
| Complementary-layers worked example | Docs/Examples (`example/06-private-network-gater/`) | Injector (both `usePrivateNetwork` + `useConnectionGater` composed) | D-11/D-12: standalone runnable demo combining both DI modules in one `makeHostInjector(...)` call |

## Standard Stack

No new external dependencies. This phase uses only what Phase 1/Phase 2 already introduced and what the existing test suite already depends on.

### Core (already in the build — verified present)
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| GoogleTest/GoogleMock | pinned via Hunter (`cmake/dependencies.cmake`) | `TEST_F`, `MOCK_METHODn`, `ManualSchedulerBackend`-driven pump loops | Existing project-wide test framework; `EXPOSE_MOCKS`-gated mocks already cover `ConnectionGater`, `RawConnection`, `Upgrader` |
| Boost.DI | Soramitsu fork, pinned in `cmake/dependencies.cmake` | `makeHostInjector(usePrivateNetwork(key), useConnectionGater<T>())` composition in examples and (optionally) the live test | Already the only sanctioned construction path per CLAUDE.md |
| Boost.Asio | via Boost | Real `io_context`/TCP loopback for the live two-node test | Existing transport layer dependency, no new wiring needed |

### Package Legitimacy Audit

**Not applicable** — this phase introduces zero new external packages (npm/PyPI/crates/Hunter). It adds only new `.cpp`/`.hpp` test and example files built against libraries already resolved by Hunter in Phase 1/Phase 2. No `Package Legitimacy Gate` run was needed.

## Architecture Patterns

### System Architecture Diagram (test/doc data flow, not production architecture)

```
┌─────────────────────────────── TEST-03: live two-node PSK test ───────────────────────────────┐
│                                                                                                  │
│  test/acceptance/p2p/pnet/pnet_two_node_test.cpp  (TEST_F, purpose-built, D-01/D-02)            │
│                                                                                                  │
│   Node A (PSK=K)  ──makeHostInjector(usePrivateNetwork(K))──▶ BasicHost A ──TCP:127.0.0.1:P──┐  │
│   Node B (PSK=K)  ──makeHostInjector(usePrivateNetwork(K))──▶ BasicHost B ◀──listen──────────┘  │
│         │                                                         │                             │
│         └── dial B's PeerInfo, newStream(echo) ──▶ PSK matches ──▶ stream opens (assert success)│
│                                                                                                   │
│   Node C (PSK=K')  ──makeHostInjector(usePrivateNetwork(K'))──▶ BasicHost C                     │
│         └── dial B's PeerInfo, newStream(echo) ──▶ PSK mismatch ──▶ multiselect never reached,  │
│                                                      connect callback errors OR times out         │
│                                                      (assert black-box failure, D-03)             │
└───────────────────────────────────────────────────────────────────────────────────────────────┘

┌────────────────────────── TEST-04: reentrancy regression (per hook / decorator) ───────────────┐
│                                                                                                    │
│  test/libp2p/network/dialer_reentrancy_test.cpp   OR extension of upgrader_session_test.cpp      │
│  test/libp2p/security/pnet/pnet_reentrancy_test.cpp                                              │
│                                                                                                    │
│   ConnectionGaterMock.interceptX()  ──(EXPECT_CALL WillOnce Invoke synchronous reject)──▶         │
│        production call site (DialerImpl::dial / rotate / UpgraderSession::onSecured/onMuxed)     │
│            │                                                                                       │
│            ├─ sets re-entry guard flag=true before calling scheduler_->schedule(cb)               │
│            ├─ scheduler_->schedule enqueues (ManualSchedulerBackend, not yet fired)                │
│            └─ guard flag=false after schedule() returns  ──▶ ASSERT flag was false when            │
│                                                                 backend->shift()/pump() fires cb    │
│                                                                                                     │
│   RawConnectionMock.read()/write()  ──(WillOnce Invoke synchronous completion)──▶                 │
│        PnetProtectedConnection::writeSome/readWithNonce/doWriteProtected/doReadProtected           │
│            └─ same guard-flag pattern around deferReadCallback/deferWriteCallback                  │
└────────────────────────────────────────────────────────────────────────────────────────────────┘

┌───────────────────────────── DOCS-01/02/03: example/ directories ───────────────────────────────┐
│  example/05-private-network/        (PSK-only, D-10)         → own CMakeLists.txt + README.md   │
│  example/0N-connection-gater/       (gater-only, D-10)        → own CMakeLists.txt + README.md   │
│  example/06-private-network-gater/  (both layers, D-11/D-12)  → own CMakeLists.txt + README.md   │
│  each: add_executable(...) + makeHostInjector(usePrivateNetwork/useConnectionGater) + main.cpp    │
└────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Recommended Project Structure

```
test/
├── acceptance/p2p/
│   ├── host/                          # existing, untouched
│   └── pnet/                          # NEW (D-01)
│       ├── CMakeLists.txt             # mirrors host/CMakeLists.txt's addtest() block
│       └── pnet_two_node_test.cpp     # purpose-built TEST_F, D-02/D-03/D-04
├── libp2p/
│   ├── network/
│   │   └── dialer_test.cpp            # existing — extend OR add dialer_reentrancy_test.cpp
│   └── security/pnet/
│       ├── pnet_upgrader_decorator_test.cpp   # existing
│       └── pnet_reentrancy_test.cpp            # NEW, or extend pnet_protected_connection_test.cpp
example/
├── 00-install/ 01-echo/ 02-kademlia/ 03-gossip/ 04-dnstxt/   # existing, untouched
├── 05-private-network/                # NEW (D-10) — PSK-only (DOCS-01)
│   ├── CMakeLists.txt
│   ├── README.md
│   └── main.cpp (or similarly named .cpp)
├── 0N-connection-gater/               # NEW (D-10) — gater-only (DOCS-02); N is the next free
│   │                                    slot AFTER 06 is reserved by D-11 (see Open Questions)
│   ├── CMakeLists.txt
│   ├── README.md
│   └── main.cpp
└── 06-private-network-gater/          # NEW (D-11/D-12) — combined worked example (DOCS-03)
    ├── CMakeLists.txt
    ├── README.md
    └── main.cpp
```

### Pattern 1: Live two-node fixture, adapted from `HostIntegrationTest`/`Peer`

**What:** `test/acceptance/p2p/host/host_integration_test.cpp` builds N real `Peer` (wrapping `BasicHost`) instances, each owning its own `io_context` + dedicated `std::thread` running `context_->run_for(timeout)`. Peer info is exchanged via `std::promise<PeerInfo>`/`std::shared_future<PeerInfo>` (`PeerPromise`/`PeerFuture` aliases on the fixture) so the test never sleeps to "wait for server ready" beyond one bounded `future_timeout` wait — `f.wait_for(future_timeout); ASSERT_EQ(status, std::future_status::ready);`. `TearDown()` clears `peers`/`peerinfo_futures` vectors (their destructors join threads and stop hosts — see `Peer::~Peer(){ wait(); }` and `Peer::wait()` which joins the thread then calls `host_->stop()`).

Crucially, `Peer::makeHost()` (`test/acceptance/p2p/host/peer/test_peer.cpp`) does **NOT** use `makeHostInjector` — despite including `<libp2p/injector/host_injector.hpp>`, it hand-constructs every component (`CryptoProviderImpl`, `IdentityManagerImpl`, `Multiselect`, `UpgraderImpl`, `TcpTransport`, `DialerImpl`, `NetworkImpl`, `BasicHost`, ...) directly. This is a manual-wiring precedent, not a DI-injector precedent.

**When to use:** Template for the new 2-node PSK fixture (D-01/D-02). Two structurally valid approaches:
1. **Injector-based** (recommended — see `## DI injector call shapes` below): construct each of the 2 nodes via `makeHostInjector(usePrivateNetwork(key_text))` (or no module = public/mismatched for the negative case), matching `02-04-SUMMARY.md`'s stated integration surface (`makeHostInjector(usePrivateNetwork(swarm_key_text))` is "the complete GNUS integration surface"). Simpler, exercises the real DI graph end-to-end (including `Router`, echo protocol registration via `host->setProtocolHandler`), and is more representative of what an actual integrator does.
2. **Manual-wiring** (mirrors `Peer::makeHost()` exactly): hand-build each node, injecting a `PnetUpgraderDecorator` wrapping the hand-built `UpgraderImpl` in place of the plain `UpgraderImpl`. More code, but stays byte-for-byte consistent with `test_peer.hpp`'s existing style if the plan prefers zero divergence from that file's approach.

Either way, keep: real TCP loopback (`/ip4/127.0.0.1/tcp/<port>`), `PeerPromise`/`PeerFuture` for readiness sync, bounded `future_timeout` wait, `TearDown` cleanup of node objects.

**Example (readiness-sync pattern, verbatim from the existing fixture):**
```cpp
// Source: test/acceptance/p2p/host/host_integration_test.cpp
using PeerPromise = std::promise<peer::PeerInfo>;
using PeerFuture = std::shared_future<peer::PeerInfo>;

void TearDown() override {
  peers.clear();
  peerinfo_futures.clear();
}
// ...
auto promise = std::make_shared<PeerPromise>();
peerinfo_futures.push_back(promise->get_future());
// ... peer->startServer(ma, std::move(promise)); (sets p->set_value(host_->getPeerInfo()) once host_->start() has run)
for (auto &f : peerinfo_futures) {
  auto status = f.wait_for(future_timeout);
  ASSERT_EQ(status, std::future_status::ready);
}
```

**D-03 mismatched-PSK assertion shape:** Do NOT assert a specific `PnetError`. Instead, dial from the mismatched-PSK node, register a `newStream`/connect callback, and assert (within a bounded timeout, e.g. via a second promise/future or a `std::atomic<bool>` polled after `context_->run_for(timeout)` returns) that the callback either (a) never fires with success, or (b) fires with *any* failure — the black-box claim is "no usable connection/stream is ever established," matching the roadmap wording exactly. `EXPECT_OUTCOME_FALSE` on the connect/newStream result is the natural assertion once the callback fires; a bounded `future_timeout` guards against the callback never firing at all (hang).

### Pattern 2: DI injector call shapes — confirmed exact syntax

**What:** The precise, verified (from `include/libp2p/injector/network_injector.hpp` and `test/libp2p/security/pnet/pnet_injector_test.cpp`) call shapes for building hosts with a PSK and/or a custom gater. `makeHostInjector` forwards all variadic args straight into `makeNetworkInjector` (see `include/libp2p/injector/host_injector.hpp`), so every `network_injector.hpp` helper (`usePrivateNetwork`, `useConnectionGater<T>()`, `useKeyPair`, `useSecurityAdaptors<...>()`, etc.) composes directly at the `makeHostInjector(...)` call site — this is the exact syntax both the live 2-node test (if injector-based) and all three new `example/` dirs must use.

```cpp
// Source: include/libp2p/injector/network_injector.hpp (verified, Phase 2 code)
// PSK-only:
auto injector = libp2p::injector::makeHostInjector(
    libp2p::injector::usePrivateNetwork(
        "/key/swarm/psk/1.0.0/\n/base16/000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f\n"));
auto host = injector.create<std::shared_ptr<libp2p::Host>>();

// Custom gater only (Phase 1 code, confirmed in network_injector.hpp doc comment
// and test/libp2p/injector/host_injector_test.cpp's CustomAdaptors test style):
struct MyGaterImpl : public libp2p::network::ConnectionGater { /* ... */ };
auto injector = libp2p::injector::makeHostInjector(
    libp2p::injector::useConnectionGater<MyGaterImpl>());

// Both layers together (DOCS-03 combined example, D-11):
auto injector = libp2p::injector::makeHostInjector(
    libp2p::injector::usePrivateNetwork(swarm_key_text),
    libp2p::injector::useConnectionGater<MyGaterImpl>());
```

`usePrivateNetwork` accepts three text shapes (dispatch order: swarm-key framing `/key/swarm/psk/1.0.0/\n/base16/<64 hex>\n` → raw base16 → raw base64) and throws `libp2p::injector::PskValidationError` **eagerly, from the call itself**, before any injector is assembled, on invalid input (PNET-05 fail-safe — confirmed exercised by `PnetInjectorTest.InvalidKeyThrowsEagerly`). There is also an exception-free `usePrivateNetwork(Psk validated_psk)` overload for integrators holding an already-validated `Psk`.

**When to use:** Use the swarm-key-text overload for the PSK example (DOCS-01) since that's the format most integrators will hold (a `swarm.key` file's contents) — demonstrate reading/pasting that text into `usePrivateNetwork(...)`. Absence of `usePrivateNetwork(...)` = public mode (confirmed by `PnetInjectorTest.AbsenceIsPublicMode` — `Upgrader` resolves to plain `UpgraderImpl`, not `PnetUpgraderDecorator`).

### Pattern 3: Reentrancy regression test — extend the existing `UpgraderSessionTest` fixture, don't invent a new harness

**What:** `test/libp2p/transport/upgrader_session_test.cpp` (Phase 1) already constructs a real `UpgraderSession` wired to a `ConnectionGaterMock`, a real `SchedulerImpl` backed by `ManualSchedulerBackend`, and a `pump()` helper that drains all pending scheduler callbacks deterministically (`while (!scheduler_backend->empty()) scheduler_backend->shift(1ms);`). Custom gmock `ACTION_P` helpers already exist in `test/testutil/gmock_actions.hpp` (`UpgradeToSecureInbound`, `UpgradeToSecureOutbound`, `UpgradeToMuxed`) that invoke the completion callback **synchronously, inline** as part of the mock's `WillOnce(...)` action — this is the exact "test double that completes synchronously" technique D-06 asks for; it already exists and is already exercised against real `UpgraderSession` code today.

**When to use:** For the 5 gater hooks: extend `dialer_test.cpp` (which already has a `ConnectionGaterMock` collaborator per `02-04-SUMMARY.md`'s D5/D6 coverage) and/or `upgrader_session_test.cpp` with new `TEST_F` cases that (a) make the gater mock's `interceptX` return a rejection synchronously (gmock `Invoke`/`Return` is already synchronous by default — no new mocking technique needed there, since `outcome::result<void> interceptX(...)` is NOT itself a callback-taking async method), and (b) instrument a re-entry guard around the specific `scheduler_->schedule(...)` call site under test.

**Key nuance (D-06 applies differently to sync-returning vs callback-taking APIs):** The 5 `ConnectionGater` hooks are synchronous, direct-return methods (`outcome::result<void> interceptPeerDial(...)`) — they cannot themselves be "invoked reentrantly" in the callback sense; the reentrancy risk is in what `DialerImpl`/`UpgraderSession` do with the result (defer via `scheduler_->schedule` vs. call `cb`/`handler_` inline). D-06's "synchronous completion" concern applies literally to `RawConnection::read()`/`write()` (callback-taking) inside `PnetProtectedConnection`, and to `Upgrader::upgradeToSecureInbound/Outbound/upgradeToMuxed(...)` (also callback-taking, already exercised synchronously by the existing `UpgradeToSecureInbound`/`UpgradeToMuxed` gmock actions) — those are the two places a mock *can* be made to fire its callback before returning, driving genuine reentrancy into the gater/pnet completion logic that wraps them.

**Example — re-entry guard scaffolding:**
```cpp
// Extends: test/libp2p/transport/upgrader_session_test.cpp's fixture (verified pattern)
struct ReentrancyGuard {
  bool inside = false;
  struct Scope {
    ReentrancyGuard &g;
    Scope(ReentrancyGuard &g) : g(g) { ASSERT_FALSE(g.inside); g.inside = true; }
    ~Scope() { g.inside = false; }
  };
};

TEST_F(UpgraderSessionTest, InterceptSecuredRejectionNeverReentersSynchronously) {
  ReentrancyGuard guard;
  auto secure = std::make_shared<SecureConnectionMock>();
  EXPECT_CALL(*upgrader, upgradeToSecureInbound(raw_base, _))
      .WillOnce(UpgradeToSecureInbound(   // synchronous completion (existing action)
          [&](auto &&) { return outcome::success(std::shared_ptr<SecureConnection>(secure)); }));
  EXPECT_CALL(*secure, remotePeer()).WillOnce(Return(pid));
  EXPECT_CALL(*secure, remoteMultiaddr()).WillOnce(Return(ma));
  EXPECT_CALL(*secure, isInitiatorMock()).WillOnce(Return(false));
  EXPECT_CALL(*gater, interceptSecured(false, pid, ma))
      .WillOnce(Return(outcome::failure(ConnectionGaterError::REJECTED_SECURED)));  // adjust to actual enum

  bool handler_fired_reentrant = false;
  EXPECT_CALL(handler_cb, Call(_)).WillOnce(Invoke([&](auto &&) {
    // guard.inside must be FALSE here: production code deferred via
    // scheduler_->schedule(...) before invoking handler_, so this fires from
    // pump(), not from inside session->secureInbound()'s call stack.
    handler_fired_reentrant = guard.inside;
  }));

  { ReentrancyGuard::Scope scope(guard);   // marks "inside session->secureInbound()"
    session->secureInbound(); }             // scope destructs -> guard.inside=false HERE
  ASSERT_FALSE(handler_fired_reentrant) << "handler_ must not fire before scheduler defers it";
  pump();
}
```
This directly targets the `scheduler_->schedule([self, err]{ self->handler_(err); })` line in `UpgraderSession`'s `interceptSecured`-rejection branch (confirmed present, see Code Examples below) and proves `handler_cb` only fires *after* `secureInbound()`'s own call stack has fully unwound (i.e., from `pump()`, not synchronously nested inside the mock's inline callback invocation).

### Anti-Patterns to Avoid
- **Asserting reentrancy-freedom on the `UpgraderSession` success path (no rejection):** the current success chain (`interceptSecured` passes → `upgrader_->upgradeToMuxed(...)` → `interceptUpgraded` passes → `handler_(r)`) does **not** call `scheduler_->schedule(...)` before invoking `handler_` — it calls `handler_` directly inside whatever callback the inner `Upgrader::upgradeToMuxed` mock/impl invoked. Asserting "never reentrant" universally across success AND rejection paths will fail; TEST-04's regression guard must be scoped to the paths that *do* defer today (all 5 hook rejection branches, all `PnetProtectedConnection` completions) — see Common Pitfalls below for the full list of verified defer/no-defer call sites.
- **Reusing `HostIntegrationTest`'s `TestWithParam` fixture for TEST-03:** explicitly rejected by D-02 — it is built for N-peer echo-ping-many, not 2-node accept/reject semantics; a purpose-built `TEST_F` is simpler and matches the roadmap wording.
- **Asserting a specific `PnetError` value in the mismatched-PSK live test:** explicitly rejected by D-03 — assert black-box connection failure only.
- **Writing prose/markdown "how it works" documentation instead of runnable examples:** explicitly rejected by D-08/D-12 — every doc requirement (DOCS-01/02/03) must be satisfied by code under `example/`, with a `README.md` per D-09, not a `docs/` narrative tree.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Deterministic scheduler control in tests | A custom fake clock / manual event loop | `libp2p::basic::ManualSchedulerBackend` + `SchedulerImpl` + a `pump()`-style drain loop (`while (!backend->empty()) backend->shift(1ms);`) | Already the established pattern in `pnet_upgrader_decorator_test.cpp` and `upgrader_session_test.cpp`; reinventing it risks subtly different (and less trustworthy) timing semantics |
| Synchronous mock-callback invocation | A bespoke "SyncInvoker" wrapper class | The existing `ACTION_P` helpers in `test/testutil/gmock_actions.hpp` (`UpgradeToSecureInbound`, `UpgradeToSecureOutbound`, `UpgradeToMuxed`, `ArgNCallbackWithArg`) — or a plain gmock `Invoke([](...){ cb(...); return ...; })` lambda, which is synchronous by default | These actions already exist, are already used against the exact production classes (`UpgraderSession`) this phase targets, and match D-06's stated technique exactly |
| Two-node TCP loopback host wiring | A new minimal from-scratch `Host` builder | `test/acceptance/p2p/host/peer/test_peer.hpp`'s `Peer` class (manual wiring) OR `makeHostInjector(...)` directly (DI wiring, the actual integration surface) | Both are proven, compiling, already-tested paths to a real `BasicHost` over TCP; a third bespoke wiring path adds risk without benefit |

**Key insight:** Every technique this phase needs (deterministic scheduler pumping, synchronous mock completion, real two-node TCP hosts) already has a working, compiling precedent in this exact repository, authored during Phase 1/Phase 2. The task is disciplined reuse and composition, not invention.

## Common Pitfalls

### Pitfall 1: Treating "scheduler post/dispatch" as a literal API name
**What goes wrong:** REQUIREMENTS.md's TEST-04 wording ("delivers callbacks via the scheduler (`post`/`dispatch`)") does not match the actual `libp2p::basic::Scheduler` API, which exposes `schedule(Callback&&)`, `schedule(Callback&&, delay)`, `scheduleWithHandle(...)` — there is no method literally named `post` or `dispatch` on `Scheduler` (that terminology comes from `boost::asio::io_context::post`/`dispatch`, which `Scheduler` wraps internally via `AsioSchedulerBackend`, not from `Scheduler`'s own public surface).
**Why it happens:** REQUIREMENTS.md was likely written referencing the general Asio idiom rather than this specific project's `Scheduler` façade.
**How to avoid:** Plans and tests should assert/reference `scheduler_->schedule(...)` calls (confirmed exact call sites below), not search for `post`/`dispatch` symbols on `Scheduler` itself.
**Warning signs:** A plan task that says "verify `dispatch()` is called" will find no such symbol and stall.

### Pitfall 2: Assuming every gater/pnet completion is scheduler-deferred (it is not, uniformly)
**What goes wrong:** Building a reentrancy test that expects `handler_` to *always* fire from a `pump()`/deferred context will fail on the `UpgraderSession` success path.
**Why it happens:** Phase 1/2 deferred callbacks specifically on **rejection** branches (where a gater/pnet error must propagate back through the exact same shape as an async failure) and on **all `PnetProtectedConnection` I/O completions** (both success and failure, since pnet wraps every read/write), but the `UpgraderSession` **success** path (`interceptSecured` OK → `upgradeToMuxed` OK → `interceptUpgraded` OK → `handler_(r)`) calls `handler_` synchronously inline with whatever the inner `Upgrader`'s own callback did.
**How to avoid:** Scope the regression test's re-entry-guard assertions precisely per call site (see verified list below), not as one blanket assertion across every hook.
**Warning signs:** A `TEST_F` that ties the guard flag to `session->secureInbound()` as a whole (rather than to the specific rejection lambda) will spuriously fail on success-path tests.

**Verified exact call sites (confirmed by direct code read, `src/network/impl/dialer_impl.cpp`, `src/transport/impl/upgrader_session.cpp`, `src/transport/tcp/tcp_listener.cpp`, `src/security/pnet/pnet_protected_connection.cpp`):**

| Hook / component | File:approx-line | Defers via `scheduler_->schedule`? |
|---|---|---|
| `interceptPeerDial` rejection | `dialer_impl.cpp:71-77` | Yes — `scheduler_->schedule([cb, err]{ cb(err); })` |
| `interceptAddrDial` rejection (×3 call sites: relay dual-addr, non-relay, holepunch) | `dialer_impl.cpp:252-262`, `288-298`, `367-370` | Yes for the first two (`scheduler_->schedule([wp, peer_id]{ rotate(...) })`); the holepunch site (`367-370`) just `continue`s the loop without an explicit schedule — worth a plan verification step to confirm intended behavior parity |
| `interceptAccept` rejection | `tcp_listener.cpp:179-193` | The *entire* accept-handling block (including the `interceptAccept` call itself) already runs inside one `scheduler_->schedule([self, conn]{ ... })` deferred from `async_accept`'s own completion handler — rejection just returns early from within that already-deferred callback (no *additional* nested schedule call) |
| `interceptSecured` rejection | `upgrader_session.cpp:78-95` | Yes — `scheduler_->schedule([self, err]{ self->handler_(err); })` |
| `interceptUpgraded` rejection | `upgrader_session.cpp:101-116` | Yes — `self->scheduler_->schedule([self, err]{ self->handler_(err); })` |
| `UpgraderSession` **success** chain (`interceptSecured` OK → `upgradeToMuxed` OK → `interceptUpgraded` OK → `handler_(r)`) | `upgrader_session.cpp:98-118` | **No** — `handler_` called directly, synchronously, from whatever context `upgradeToMuxed`'s own callback ran in |
| `PnetProtectedConnection` read/write completions (all paths, success and failure) | `pnet_protected_connection.cpp: deferReadCallback`/`deferWriteCallback`, called from every terminal branch of `writeSome`/`doWriteProtected`/`readWithNonce`/`doReadProtected` | Yes — always routes through `scheduler_->schedule(...)`, unconditionally, "Phase 1 carry-forward: every completion routes through the scheduler" (verbatim source comment) |
| `DialerImpl::completeDial` / holepunch completion fan-out | `dialer_impl.cpp:386-397`, `403-415` | Yes — every queued callback is wrapped in its own `scheduler_->schedule(...)` |

### Pitfall 3: Confusing this phase's reentrancy scope with the pre-existing `TODO(107)` sites
**What goes wrong:** Accidentally "fixing" or writing regression tests against the 10 pre-existing `TODO(107): Reentrancy` sites (`tcp_transport.cpp:32,189`, `secio_connection.cpp`, `plaintext.cpp`, `mplex*.cpp`, `message_read_writer_bigendian.cpp`, `varint_reader.cpp`) — explicitly out of scope per D-05 and PROJECT.md's "auditing/fixing the general existing test suite's health beyond what this work touches."
**Why it happens:** These sites are architecturally similar (synchronous inline callback invocation) and are visually adjacent in the same files the gater/pnet code touches (e.g. `tcp_transport.cpp`).
**How to avoid:** Confirmed concrete example read directly: `tcp_transport.cpp:32-33` — `if (!canDial(address)) { //TODO(107): Reentrancy \n return handler(std::errc::address_family_not_supported); }` — this is genuinely synchronous/inline (no scheduler hop at all, not even a deferred one) and is a **different, older, unrelated code path** to the ones this phase's tests target. There is no existing reentrancy-test utility purpose-built for these TODO sites to reuse — they remain unfixed and untested, by design, this phase.
**Warning signs:** A plan task referencing `tcp_transport.cpp` line numbers directly (rather than `dialer_impl.cpp`/`upgrader_session.cpp`/`pnet_protected_connection.cpp`) is out of scope.

### Pitfall 4: `example/` directory numbering collision
**What goes wrong:** `example/04-dnstxt/` already exists (confirmed: `example/` currently contains `00-install`, `01-echo`, `02-kademlia`, `03-gossip`, `04-dnstxt`, registered in `example/CMakeLists.txt` via 4 `add_subdirectory(...)` calls). CONTEXT.md's D-10 locks `example/05-private-network/` (PSK-only) and D-11 locks `example/06-private-network-gater/` (combined) as literal directory names — but D-10's "second dir for gater-only" example has **no locked number**, and inserting it as `example/05-...` would collide with the already-locked `05-private-network`.
**Why it happens:** CONTEXT.md's decisions were recorded in discussion order (PSK example discussed first → got `05`; combined example discussed third → got `06`), but the gater-only example (discussed second) was left without an explicit number.
**How to avoid:** The only non-colliding, order-preserving-where-it-matters resolution is to number the gater-only example **after** `06`, i.e. `example/07-connection-gater/` (or a similarly descriptive `07-*` name) — since `05` and `06` are both locked verbatim in CONTEXT.md and cannot be renumbered without contradicting a locked decision. The plan should treat this as a confirmed resolution, not reopen it with the user, since both locked numbers are unambiguous and `07` is simply the next free integer.
**Warning signs:** A plan that tries to place the gater-only example between `05` and `06` (e.g. `05b-...`) breaks the existing `NN-name` numeric convention with no precedent in the repo.

### Pitfall 5: `example/04-dnstxt/` has no `README.md`
**What goes wrong:** Unlike `01-echo`, `02-kademlia`, `03-gossip` (each has its own `README.md`, confirmed by direct listing), `example/04-dnstxt/` contains only `CMakeLists.txt` and `ares_resolver.cpp` — no `README.md`.
**Why it happens:** Likely an inconsistency introduced when `04-dnstxt` was added, not something this phase should perpetuate.
**How to avoid:** D-09 locks "each `example/<N>-<name>/` directory gets its own `README.md`" as the pattern to follow — treat `01-echo`/`02-kademlia`/`03-gossip` as the canonical examples of this convention (all three confirmed to have README.md), not `04-dnstxt` (the outlier). All three new Phase 3 example dirs must include a `README.md`.
**Warning signs:** None — this is purely informational so the plan doesn't cite `04-dnstxt` as a counter-example.

## Code Examples

### CMake registration for the new live 2-node test target (mirrors `test/acceptance/p2p/host/CMakeLists.txt` exactly)
```cmake
# Source: test/acceptance/p2p/host/CMakeLists.txt (verified addtest() convention)
# New file: test/acceptance/p2p/pnet/CMakeLists.txt
addtest(pnet_two_node_test
    pnet_two_node_test.cpp
    )
target_link_libraries(pnet_two_node_test
    p2p_default_network       # or the manual-wiring library set test_peer.hpp uses, if that route is chosen
    p2p_basic_host
    p2p_pnet
    p2p_pnet_upgrader
    p2p_peer_repository
    p2p_inmem_address_repository
    p2p_inmem_key_repository
    p2p_inmem_protocol_repository
    p2p_protocol_echo
    p2p_multiaddress
    p2p_testutil
    p2p_literals
    )
```
And register the new subdirectory:
```cmake
# Source: test/acceptance/p2p/CMakeLists.txt (existing file, add one line)
add_subdirectory(host)
add_subdirectory(pnet)   # NEW
```
`addtest()` itself (`cmake/functions.cmake:8-26`) creates the executable, links `GTest::main`/`GMock::main`/`GTest::gtest`, registers it with `add_test(NAME <target> COMMAND $<TARGET_FILE:<target>>)`, and routes the binary to `${CMAKE_BINARY_DIR}/test_bin` — confirming D-04 (no new CMake gating option needed; this is the exact same mechanism `host_integration_test` uses, so it runs in the default `ctest` invocation automatically).

### Existing `p2p_pnet`/`p2p_pnet_upgrader` library targets to link against (from Phase 2, confirmed)
```cmake
# Source: src/security/pnet/CMakeLists.txt
libp2p_add_library(p2p_pnet
    pnet_error.cpp psk.cpp pnet_protected_connection.cpp)
# links: OpenSSL::Crypto, p2p_hexutil, p2p_multibase_codec, p2p_crypto_xsalsa20, p2p_basic_scheduler
```
```cmake
# test/libp2p/security/pnet/CMakeLists.txt (existing test target link pattern to mirror)
addtest(pnet_upgrader_decorator_test pnet_upgrader_decorator_test.cpp)
target_link_libraries(pnet_upgrader_decorator_test
    p2p_pnet_upgrader p2p_manual_scheduler_backend p2p_testutil p2p_literals)
```

### Example directory CMake convention (mirrors `example/01-echo/CMakeLists.txt`)
```cmake
# New file: example/05-private-network/CMakeLists.txt
add_executable(libp2p_private_network_example
    private_network_example.cpp
    )
target_link_libraries(libp2p_private_network_example
    Boost::Boost.DI
    p2p_basic_host
    p2p_default_network
    p2p_pnet
    p2p_pnet_upgrader
    p2p_peer_repository
    p2p_inmem_address_repository
    p2p_inmem_key_repository
    p2p_inmem_protocol_repository
    p2p_protocol_echo
    p2p_literals
    Boost::date_time
    Boost::regex
    ${WIN_CRYPT_LIBRARY}
    )
```
Register in `example/CMakeLists.txt`:
```cmake
add_subdirectory(01-echo)
add_subdirectory(02-kademlia)
add_subdirectory(03-gossip)
add_subdirectory(04-dnstxt)
add_subdirectory(05-private-network)         # NEW
add_subdirectory(07-connection-gater)        # NEW (see Pitfall 4 on numbering)
add_subdirectory(06-private-network-gater)   # NEW
```

### `main()` shape to follow for the new examples (adapted from `example/01-echo/libp2p_echo_server.cpp`)
```cpp
// Source: example/01-echo/libp2p_echo_server.cpp (pattern), adapted for
// example/05-private-network/private_network_example.cpp
#include <libp2p/injector/host_injector.hpp>
// ...
auto injector = libp2p::injector::makeHostInjector(
    libp2p::injector::usePrivateNetwork(
        "/key/swarm/psk/1.0.0/\n/base16/<64 hex chars>\n"));
auto host = injector.create<std::shared_ptr<libp2p::Host>>();
auto io_context = injector.create<std::shared_ptr<boost::asio::io_context>>();
// ... host->setProtocolHandler(...), io_context->post([...]{ host->listen(...); host->start(); }),
// io_context->run();
```

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|----------------|
| A1 | The gater-only example directory should be numbered `07-connection-gater` (not renumbering `05`/`06`, which are locked verbatim in CONTEXT.md) | Pitfall 4, Code Examples | Low — this is a naming-only choice; if the planner/user prefers a different scheme it's a one-line rename with no structural impact |
| A2 | The reentrancy regression test should live in `test/libp2p/` (unit-level, mirroring `upgrader_session_test.cpp`'s existing pattern) rather than `test/acceptance/p2p/pnet/` alongside the live 2-node test | Architectural Responsibility Map, Pattern 3 | Low-Medium — CONTEXT.md doesn't explicitly pin the reentrancy test's directory (only the live-test directory, D-01); TESTING.md's established convention (unit tests isolate one class with mocks, acceptance tests wire real components) strongly supports this placement, but the plan should confirm |
| A3 | The live two-node test should prefer the DI-injector construction path (`makeHostInjector(usePrivateNetwork(...))`) over `test_peer.hpp`'s manual-wiring style | Pattern 1 | Low — both are valid, compiling precedents in this repo; choosing manual-wiring instead only affects code volume/consistency-with-neighbor-file, not correctness |
</functions>

**If this table is empty:** N/A — see above; both assumptions are low-risk naming/structure choices, not fact claims requiring user reconfirmation of behavior or requirements.

## Open Questions

1. **Exact holepunch-path `interceptAddrDial` rejection behavior (no explicit `scheduler_->schedule` there)**
   - What we know: `dialer_impl.cpp:367-370` rejects a holepunch-candidate address via `interceptAddrDial` and simply `continue`s the loop (no `scheduler_->schedule` call, no callback invocation at that point at all — it's mid-loop address filtering, not a terminal callback).
   - What's unclear: Whether this is a deliberate simplification (holepunch dial results are collected and dispatched later via `dialing_holepunches_`'s own `scheduler_->schedule` fan-out at `dialer_impl.cpp:403-415`, which the plan should double check covers this case) or a gap.
   - Recommendation: The plan's reentrancy test should scope its `interceptAddrDial` coverage to the two definitively-deferred call sites (relay dual-addr, non-relay) per D-05's literal scope; treat the holepunch `continue` site as informational (it's a loop-filter, not a completion callback, so "reentrancy" doesn't apply the same way) rather than a required test target — but flag it for a human-verify checkpoint if the plan wants full 1:1 coverage of every `interceptAddrDial` call site.

2. **Whether the live two-node test needs a third "control" node to fully exercise D-03's "attempt fails at the pnet layer and never reaches multiselect" framing, or whether 2 nodes (matched pair + reuse one node's PSK-mismatched dial attempt) suffices**
   - What we know: D-02 locks "exactly 2 nodes." The roadmap success criterion needs both a positive case (matched PSK connects) and a negative case (mismatched/missing PSK rejected).
   - What's unclear: Whether "exactly 2 nodes" means the test file contains exactly 2 `Peer`/host instances total (requiring the SAME 2 nodes to be reconfigured/reused across positive and negative sub-cases, or requiring 2 separate `TEST_F` cases each spinning up their own pair), or whether it's a looser "2-peer topology" framing that still permits e.g. a 3rd short-lived mismatched-key host object within the same test binary.
   - Recommendation: Interpret D-02 literally — each `TEST_F` case constructs exactly 2 nodes for that case (one positive-case test with matched-PSK nodes A+B; one negative-case test with mismatched-PSK nodes A+C, freshly constructed, not reusing A+B's PSK state) — this is the simplest reading consistent with both "exactly 2 nodes" and needing independent PSK configurations per case, and matches `HostIntegrationTest`'s own per-`TEST_P`-invocation node construction style.

## Environment Availability

No new external dependencies. Build toolchain (CMake ≥3.12, GCC 7.4+/Clang 6.0.1+/AppleClang 11.0+/MSVC per README, Hunter-resolved GTest/GMock/Boost/OpenSSL) is already fully verified working by Phase 1 and Phase 2's completed, tested code — no new probe needed for this phase.

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| ctest / GTest+GMock | Both new test targets | Yes (used throughout repo) | Hunter-pinned | — |
| TCP loopback (`127.0.0.1`) | Live two-node test | Yes (already used by `host_integration_test.cpp`) | OS-level | — |

**Missing dependencies with no fallback:** None.

**Known pre-existing environment caveat (from STATE.md Blockers/Concerns, carried forward, not introduced by this phase):** MSVC 19.44 + soralog header incompatibility in `src/muxer/yamux/yamux_frame.cpp` blocks building any target transitively depending on `p2p_yamuxed_connection` on native Windows/MSVC builds — this affects full-build verification of Phase 3's new test targets too, since both new tests link against real `Host`/yamux-muxed connections. Not new to this phase; was already flagged as blocking Phase 1 plan verification.

## Security Domain

`security_enforcement` is `true` in `.planning/config.json` (ASVS level 1). This phase adds no new production attack surface (no new code paths) — it validates existing Phase 1/2 access-control enforcement under adversarial conditions (mismatched credentials, reentrant callbacks) and documents correct configuration. The relevant ASVS lens here is verifying the *existing* controls, not introducing new ones.

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-------------------|
| V4 Access Control | Yes | This phase's TEST-03 is itself the ASVS V4 verification artifact: it proves peer-level (gater) and network-level (pnet PSK) access control actually rejects unauthorized connections under live conditions, not just unit-mocked ones |
| V5 Input Validation | Partially — indirectly | `usePrivateNetwork`'s eager `PskValidationError` (PNET-05, already implemented) is the existing input-validation control for PSK material; this phase's docs (DOCS-01) should demonstrate the correct swarm-key text format so integrators don't hand-roll malformed key parsing |
| V6 Cryptography | No new work | XSalsa20/PSK crypto is Phase 2's completed, unit-tested implementation (`p2p_crypto_xsalsa20`, `p2p_pnet`); this phase does not touch crypto code |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation (already implemented, this phase validates it) |
|---------|--------|------------------------------------------------------------------|
| Reentrant callback corrupting in-flight connection/session state during upgrade | Tampering / Elevation of Privilege (a corrupted state could cause a rejection to be silently skipped) | `scheduler_->schedule(...)` deferral at every gater-rejection and pnet-completion call site (verified list in Pitfall 2) — TEST-04 is the regression guard for this exact mitigation |
| Peer without matching PSK reaching multiselect/application protocols | Spoofing / Elevation of Privilege | `PnetProtectedConnection` wraps every raw connection before multiselect; a wrong-PSK peer decrypts garbage, multiselect fails naturally (confirmed via source comment in `pnet_protected_connection.cpp`) — TEST-03 is the live-condition regression guard for this |
| Integrator misconfiguring PSK-only OR gater-only, believing it's sufficient defense-in-depth alone | Elevation of Privilege (via documentation/config gap, not code) | DOCS-03's worked "valid PSK, gater-denied peer" example (`example/06-private-network-gater/`) is the mitigation — it is a *documentation* control, not a code control, and is this phase's direct responsibility |

## Sources

### Primary (HIGH confidence — direct code read this session)
- `test/acceptance/p2p/host/host_integration_test.cpp`, `peer/test_peer.hpp`, `peer/test_peer.cpp`, `peer/tick_counter.hpp` — full read
- `test/acceptance/p2p/host/CMakeLists.txt`, `test/acceptance/p2p/CMakeLists.txt`, `test/acceptance/p2p/host/peer/CMakeLists.txt` — full read
- `test/libp2p/transport/upgrader_session_test.cpp` (partial, fixture + 1 full test case) — direct read
- `test/mock/libp2p/network/connection_gater_mock.hpp`, `test/mock/libp2p/connection/raw_connection_mock.hpp` — full read
- `test/testutil/gmock_actions.hpp` — full read
- `include/libp2p/network/connection_gater.hpp`, `include/libp2p/basic/scheduler.hpp`, `include/libp2p/basic/scheduler/manual_scheduler_backend.hpp` — full read
- `include/libp2p/injector/network_injector.hpp`, `include/libp2p/injector/host_injector.hpp` — full read
- `test/libp2p/security/pnet/pnet_injector_test.cpp`, `pnet_upgrader_decorator_test.cpp` — full read
- `test/libp2p/injector/host_injector_test.cpp` — full read
- `src/network/impl/dialer_impl.cpp` (grepped call sites with context), `src/transport/impl/upgrader_session.cpp` (relevant sections), `src/transport/tcp/tcp_listener.cpp` (relevant section), `src/transport/tcp/tcp_transport.cpp` (TODO(107) context) — direct read
- `src/transport/impl/pnet_upgrader_decorator.cpp`, `include/libp2p/transport/impl/pnet_upgrader_decorator.hpp`, `src/security/pnet/pnet_protected_connection.cpp`, `include/libp2p/security/pnet/psk.hpp` — full read
- `src/security/pnet/CMakeLists.txt`, `test/libp2p/security/pnet/CMakeLists.txt`, `cmake/functions.cmake` (`addtest`) — full read
- `example/01-echo/` (CMakeLists.txt, README.md, libp2p_echo_server.cpp full read), `example/04-dnstxt/CMakeLists.txt`, `example/CMakeLists.txt` — full read
- `README.md` "Examples" section — direct read
- `.planning/phases/02-private-network-pnet-psk-protector/02-04-SUMMARY.md` — full read
- `.planning/codebase/CONCERNS.md`, `.planning/codebase/TESTING.md`, `.planning/codebase/STRUCTURE.md` — full read
- `.planning/config.json` — full read (confirmed `nyquist_validation: false`, `security_enforcement: true`)

### Secondary (MEDIUM confidence)
None — no external web sources were needed; this phase is entirely internal-codebase-grounded (per `research_focus`'s explicit instruction to investigate only existing code, not new libraries).

### Tertiary (LOW confidence)
None.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — no new dependencies, all verified present and already in use
- Architecture/test patterns: HIGH — every pattern cited was read in full from the actual source file, not inferred
- Pitfalls: HIGH — the defer/no-defer call-site table (Pitfall 2) was built from direct grep+read of the actual production code, not assumed
- Example numbering resolution (A1): MEDIUM — a reasoned recommendation given a genuine gap in CONTEXT.md's locked decisions, not itself a locked decision

**Research date:** 2026-08-26
**Valid until:** No expiry concern — this research is grounded entirely in the current state of this specific repository's already-completed Phase 1/2 code, which will not drift out from under this phase unless Phase 1/2 code is retroactively modified (out of this phase's scope).
