# Phase 1: Connection Gater interface + wiring - Research

**Researched:** 2026-08-26
**Domain:** C++17 connection-lifecycle access control (libp2p connection upgrade pipeline), Boost.DI wiring
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Hook naming convention**
- **D-01:** The 5 gater hook methods use this codebase's camelCase convention, not go-libp2p's PascalCase names: `interceptPeerDial`, `interceptAddrDial`, `interceptAccept`, `interceptSecured`, `interceptUpgraded`. Same 5 stages and semantics as go-libp2p's `ConnectionGater`, styled to match the rest of the cpp-libp2p public API (CLAUDE.md: camelCase for methods).

**Rejection error semantics**
- **D-02:** Gater rejections use per-hook error codes (one enum value per hook), not a single generic `REJECTED` code — so callers/logs can tell which of the 5 stages rejected the connection.
- **D-03:** Each error code/message must make it unmistakable that the *gater* was the cause of rejection (not some other layer) — name the enum values so "gater" is legible in the error text itself (e.g. a `GATER_` prefix or equivalent, not a bare `REJECTED_PEER_DIAL` that could be confused with an unrelated dial failure). This is a specific, deliberate ask — don't drop the "gater" framing when researching/planning the error enum.

**Default gater binding strategy**
- **D-04:** Use the Null Object pattern. A `PermissiveConnectionGater` (or equivalent name) is *always* bound in the DI graph by default. `Dialer`, `TcpListener`, and `UpgraderSession` call into the gater unconditionally at each of their hooks — no `if (gater_)` null checks scattered across the 3 call sites.
- **D-05:** Overriding the default is a single DI rebind (`di::bind<ConnectionGater>().to<CustomGater>()`-style), consistent with GATE-04 (no source changes required to `Dialer`/`TcpListener`/`UpgraderSession` to register a custom gater).

**Rejection observability**
- **D-06:** The library itself logs gater rejections — not left solely to the integrator's gater implementation. Log at `SL_DEBUG` (matching this codebase's convention: SL_DEBUG for notable-but-non-error events like peer disconnects/malformed frames), including which hook rejected and the peer id / address where available.

### Claude's Discretion
None — all 4 discussed areas resulted in explicit decisions above (see D-01 through D-06).

### Deferred Ideas (OUT OF SCOPE)
None — discussion stayed within phase scope. No scope-creep suggestions came up.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-------------------|
| GATE-01 | Library exposes a `ConnectionGater` interface with 5 intercept hooks: peer dial, address dial, accept, secured, upgraded | Proposed interface in Code Examples (`connection_gater.hpp`); Architectural Responsibility Map confirms leaf-library placement so both network and transport layers can depend on it |
| GATE-02 | Default (unconfigured) behavior is fully permissive — existing hosts behave identically to today when no gater is set | Pattern 1 (`PermissiveConnectionGater` Null Object, always DI-bound); confirmed no `if(gater_)` guards needed at any of the 4 call sites |
| GATE-03 | Gater hooks are wired into the actual dial, accept, and upgrade code paths (`Dialer`, `TcpListener`/`ListenerManager`, `Upgrader`/`UpgraderSession`) so a configured gater can reject a connection at each of the 5 stages | System Architecture Diagram + Recommended Project Structure enumerate all 4 concrete `UpgraderSession` construction sites, both `DialerImpl` dial loops (`rotate()`/`rotateHolepunch()` — flagged as Pitfall 3 / Open Question 1), and the exact `TcpListener::doAccept()` insertion point |
| GATE-04 | Integrators can bind a custom `ConnectionGater` implementation via the existing Boost.DI injector pattern | Pattern 3 + proposed `useConnectionGater<GaterImpl>()` helper in Code Examples, mirroring existing `useSecurityAdaptors<...>()` |
| GATE-05 | A gater rejection at any stage cleanly tears down the in-progress connection (socket closed, no leaked fds/threads) using the existing hardened connection-close paths | Pattern 2 + Pitfall 5 (`conn->close()` via `TcpConnection`'s Windows-hardened close path, guarded by `!isClosed()`, exactly as already used in `DialerImpl`'s orphaned-dial-result handling) |
| TEST-01 | Unit tests validate accept and reject behavior at each of the 5 gater hooks | Pitfall 4 flags that `UpgraderSession` has zero existing test coverage and `UpgraderTest` is entirely `DISABLED_`; Don't Hand-Roll table specifies the GMock mock file to add and which existing test fixtures (`DialerTest`, `ManualSchedulerBackend`) to model new tests on |
</phase_requirements>

## Summary

This phase adds a `ConnectionGater` interface with 5 synchronous decision hooks
(`interceptPeerDial`, `interceptAddrDial`, `interceptAccept`, `interceptSecured`,
`interceptUpgraded`) and wires it into the 4 concrete call sites that drive the
connection lifecycle: `DialerImpl::dial()`/`rotate()` (peer/addr dial),
`TcpListener::doAccept()` (accept), and `UpgraderSession::onSecured()` (secured +
upgraded — a single internal method shared by both inbound and outbound, plus relay
paths). A `PermissiveConnectionGater` Null Object is always bound in the DI graph by
default so the 3 call sites never null-check; overriding it is a single
`boost::di::bind<network::ConnectionGater>().to<Custom>()[boost::di::override]`.

The most consequential, non-obvious finding from reading the actual code (not just the
interfaces) is that **`TcpListener` and `UpgraderSession` currently have zero
`basic::Scheduler` dependency**. Every other async component in this codebase (Dialer,
TransportManager-adjacent code) already threads a `Scheduler` through and uses
`scheduler_->schedule(...)` to defer callback delivery — this is the concrete mechanism
behind the roadmap's "post/dispatch" language (there is no method literally named
`post`/`dispatch`; `Scheduler::schedule()` is the asio-`post()`-equivalent primitive in
this codebase). To satisfy roadmap success criterion 5 ("gater hook callbacks are
always delivered via scheduler post/dispatch"), both `TcpListener` and
`UpgraderSession` need a new `shared_ptr<basic::Scheduler>` constructor parameter in
addition to the new `shared_ptr<network::ConnectionGater>` parameter — this is a real,
previously-invisible scope item for planning, not just "call the gater and check the
result."

A second consequential finding: `UpgraderSession` is constructed manually (not via DI)
at **4 call sites** — 2 in `TcpTransport::dial()` (two overloads), 1 in
`TcpTransport::upgradeRelaySecure()`, and 1 in `TcpListener::doAccept()`. All 4 must
propagate the new `gater_`/`scheduler_` members. Because `secureOutboundRelay`/
`secureInboundRelay` also funnel through the same private `onSecured()` method as the
plain `secureOutbound`/`secureInbound` paths, gating the secured/upgraded hooks in
`onSecured()` automatically covers circuit-relay connections too — no special-casing
needed. However, `DialerImpl::rotateHolepunch()` is a **second, parallel** per-address
dial loop (separate from `rotate()`) that also calls `tr->dial(...)` directly; if
`interceptAddrDial` is added only to `rotate()`, holepunch dial attempts silently
bypass the gater. This must be an explicit planning decision, not an oversight.

**Primary recommendation:** Give `ConnectionGater` 5 synchronous
`outcome::result<void>`-returning hook methods (no I/O inside the gater itself — mirrors
go-libp2p's fully-synchronous `ConnectionGater` semantics, adapted to this codebase's
`outcome::result` idiom instead of bare `bool`). Push all asynchronous-boundary
discipline into the 3 call sites via `scheduler_->schedule(...)`, exactly like the
existing `DialerImpl` error-propagation pattern already does for
`destination_address_required`/`address_family_not_supported`. Place the new interface,
error enum, and default impl in a new **leaf** library (`p2p_connection_gater`, under
`src/network/`) with minimal dependencies (`p2p_peer_id`, `p2p_multiaddress`) so both
the `network` layer (`Dialer`) and the `transport` layer (`TcpListener`, `TcpTransport`,
`UpgraderSession`) can link it without introducing a `transport → network` layering
inversion.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| `ConnectionGater` interface + error enum | Network/Transport shared leaf (new `p2p_connection_gater` library) | — | Consumed by both `network::Dialer` and `transport::TcpListener`/`transport::TcpTransport`/`transport::UpgraderSession`; must not create a `transport → network` dependency, so it lives in its own leaf library rather than inside `libp2p::network`'s existing `p2p_dialer`/`p2p_network` libraries |
| Peer dial / address dial policy enforcement | Network Layer (`DialerImpl`) | — | `Dialer` is the sole owner of the per-peer/per-address dial loop (`rotate()`, `rotateHolepunch()`) |
| Accept policy enforcement | Transport Layer (`TcpListener`) | — | `TcpListener::doAccept()` is the only point with access to the raw pre-handshake socket; `ListenerManager::onConnection()` fires only after full upgrade, too late for GATE-03's "before any security handshake bytes are exchanged" requirement |
| Secured / upgraded policy enforcement | Transport Layer (`UpgraderSession`) | — | `UpgraderSession::onSecured()` is the single internal method reached by all 4 secure/mux entry points (outbound, inbound, outbound-relay, inbound-relay) |
| Default permissive behavior (Null Object) | DI graph (`network_injector.hpp`) | — | Boost.DI binds `PermissiveConnectionGater` unconditionally; overriding is a rebind, no call-site changes |
| Rejection logging (SL_DEBUG) | Call sites (Dialer/TcpListener/UpgraderSession) | — | D-06: the library, not the gater implementation, logs rejections — logging belongs where the `outcome::result<void>` from the hook is consumed |

## Standard Stack

This phase introduces **no new third-party dependencies**. It is pure C++17
interface + wiring work inside the existing codebase, using only facilities already
present: `outcome::result<T>` (Boost.Outcome-style), Boost.DI, `basic::Scheduler`,
`soralog`-backed `SL_DEBUG`/`SL_TRACE` macros, GoogleTest/GoogleMock.

### Core (existing, reused — not newly added)
| Library | Version (as pinned in this repo) | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Boost.DI (soramitsu/masterjedy fork) | pinned via `cmake/dependencies.cmake` | DI binding for `ConnectionGater` override | Already the sole construction mechanism for every other subsystem in this codebase |
| Boost (Asio, `random`, `filesystem`, `program_options`) | pinned via `cmake/dependencies.cmake` | Async I/O underlying `TcpListener`/`TcpTransport` | Existing, unaffected by this phase |
| GTest/GMock | `hunter_add_package(GTest)`, gated by `TESTING` option | TEST-01 unit tests for all 5 hooks | Existing test infra; `test/mock/libp2p/network/*_mock.hpp` pattern already established |

### Supporting
| Library | Purpose | When to Use |
|---------|---------|-------------|
| `libp2p::outcome::result<T>` | Return type for all 5 gater hooks and the new `ConnectionGaterError` enum | Consistent with every other fallible interface method in this codebase (`Host::listen`, `RawConnection::Error`, `Scheduler::Error`, etc.) |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Synchronous `outcome::result<void>` hooks + scheduler-deferred call-site delivery | Fully async hooks taking a completion callback (`void interceptPeerDial(p, ResultCb cb)`), mirroring `SecurityAdaptor`/`TransportAdaptor` | Async-hook design would let a gater do I/O (e.g. consult an external allow-list service) but pushes the "must defer via scheduler" burden onto every custom gater implementation instead of the 3 call sites — directly contradicts D-05's "single DI rebind, no source changes" simplicity goal, and none of go-libp2p's 5 hooks are I/O-bound by design. **Recommend synchronous.** |
| New leaf library `p2p_connection_gater` | Put the interface inside `p2p_dialer` (network layer) and have `transport/` link `p2p_dialer` | Would make the transport layer depend on the network layer, inverting the existing `network → transport` dependency direction (Dialer depends on TransportManager, not vice versa) — avoid |

**Installation:** No new packages. No `npm`/`pip`/`cargo`/Hunter package additions required for this phase.

**Version verification:** N/A — no new external package versions to verify. Existing pinned dependencies (Boost.DI, GTest, Boost) are unchanged by this phase; verified present via `cmake --version` (3.29.2, exceeds the `CMakeLists.txt` minimum of 3.12) `[VERIFIED: local environment probe]`.

## Package Legitimacy Audit

**Not applicable — no external packages are installed in this phase.** This phase adds
only first-party C++ headers/sources to the existing fork; no `hunter_config`,
`cmake/dependencies.cmake`, or Hunter package additions are required.

## Architecture Patterns

### System Architecture Diagram

```text
                              ┌─────────────────────────────┐
                              │   ConnectionGater (new)      │
                              │  interceptPeerDial(peer)     │
                              │  interceptAddrDial(peer,addr)│
                              │  interceptAccept(local,remote)│
                              │  interceptSecured(dir,peer,addr)
                              │  interceptUpgraded(conn)     │
                              │  -> outcome::result<void>    │
                              └───────┬───────┬───────┬──────┘
                     called by:       │       │       │
      ┌────────────────────────────┐ │       │       │  ┌──────────────────────────────┐
      │  DialerImpl::dial()         │◄┘       │       └─►│ UpgraderSession::onSecured()  │
      │   interceptPeerDial (top)   │         │          │  interceptSecured  (after    │
      │  DialerImpl::rotate()       │         │          │    security handshake, before│
      │   interceptAddrDial (per    │         │          │    upgradeToMuxed)            │
      │    address, before          │         │          │  interceptUpgraded (after    │
      │    tr->dial(...))           │         │          │    upgradeToMuxed succeeds,   │
      │  [ALSO: rotateHolepunch()   │         │          │    before handler_ fires)     │
      │   parallel loop — same gap] │         │          │  On reject: conn->close() via │
      │  On reject: scheduler_      │         │          │   hardened close path, then   │
      │   ->schedule(cb(GATER_*))   │         │          │   scheduler_->schedule(       │
      └──────────────┬───────────────┘         │          │     handler_(GATER_*))       │
                     │ (opens RawConnection     │          └───────────────┬───────────────┘
                     │  only if not rejected)   │                          │ reached from
                     ▼                          │                          │ BOTH inbound
      ┌────────────────────────────┐            │                          │ (TcpListener)
      │  TransportAdaptor::dial()   │            │                          │ AND outbound
      │  (TcpTransport)             │            │                          │ (TcpTransport)
      └──────────────┬───────────────┘            │                          │ AND relay paths
                     │ creates UpgraderSession ───┘                          │
                     │ (outbound)                                            │
                     ▼                                                       │
      ┌────────────────────────────┐   accepts raw socket   ┌────────────────┴──────────────┐
      │  TcpListener::doAccept()    │────────────────────────│  creates UpgraderSession       │
      │   interceptAccept(local,    │                        │  (inbound) -> secureInbound()  │
      │    remote) BEFORE creating  │                        └────────────────────────────────┘
      │    UpgraderSession/         │
      │    secureInbound()          │
      │  On reject: conn->close()   │
      │   (no UpgraderSession ever  │
      │    created), continue       │
      │    doAccept() loop          │
      └────────────────────────────┘

Default binding (network_injector.hpp):
  di::bind<network::ConnectionGater>().TEMPLATE_TO<network::PermissiveConnectionGater>()
Override (integrator code, no source changes to the 3 call sites above):
  makeNetworkInjector(useConnectionGater<MyCustomGater>())
```

### Recommended Project Structure
```
include/libp2p/network/
├── connection_gater.hpp            # NEW - interface (namespace libp2p::network)
├── connection_gater_error.hpp      # NEW - ConnectionGaterError enum + OUTCOME_HPP_DECLARE_ERROR
└── impl/
    └── permissive_connection_gater.hpp   # NEW - Null Object default impl

src/network/
├── connection_gater_error.cpp      # NEW - OUTCOME_CPP_DEFINE_CATEGORY
├── impl/
│   └── permissive_connection_gater.cpp   # NEW
└── CMakeLists.txt                  # NEW library target: p2p_connection_gater (leaf)

# modified (existing files):
src/network/impl/dialer_impl.{hpp,cpp}          # + gater_ member, interceptPeerDial/AddrDial calls
src/transport/tcp/tcp_listener.{hpp,cpp}        # + gater_, scheduler_ members; interceptAccept call
src/transport/tcp/tcp_transport.{hpp,cpp}       # + gater_, scheduler_ members (threaded to TcpListener + 3 UpgraderSession sites)
src/transport/impl/upgrader_session.{hpp,cpp}   # + gater_, scheduler_ members; interceptSecured/Upgraded calls in onSecured()
include/libp2p/injector/network_injector.hpp    # + default binding, useConnectionGater<>() helper
```

### Pattern 1: Null Object default gater (D-04)
**What:** `PermissiveConnectionGater` implements all 5 hooks returning
`outcome::success()` unconditionally; it is *always* bound in the DI graph, never
conditionally constructed.
**When to use:** Default binding in `makeNetworkInjector()`.
**Example (mirrors the existing `TransportAdaptor`/`SecurityAdaptor` DI-bound-by-default
pattern already used for TCP/Plaintext/Noise):**
```cpp
// include/libp2p/network/impl/permissive_connection_gater.hpp
namespace libp2p::network {
  class PermissiveConnectionGater : public ConnectionGater {
   public:
    outcome::result<void> interceptPeerDial(const peer::PeerId &) override {
      return outcome::success();
    }
    outcome::result<void> interceptAddrDial(
        const peer::PeerId &, const multi::Multiaddress &) override {
      return outcome::success();
    }
    outcome::result<void> interceptAccept(
        const multi::Multiaddress &, const multi::Multiaddress &) override {
      return outcome::success();
    }
    outcome::result<void> interceptSecured(
        bool, const peer::PeerId &, const multi::Multiaddress &) override {
      return outcome::success();
    }
    outcome::result<void> interceptUpgraded(
        const std::shared_ptr<connection::CapableConnection> &) override {
      return outcome::success();
    }
  };
}  // namespace libp2p::network
```

### Pattern 2: Scheduler-deferred rejection delivery (roadmap criterion 5)
**What:** The gater hook call itself is synchronous, but the *caller-visible result*
of a rejection (invoking a dial/newStream callback, or the `UpgraderSession::handler_`)
must never be invoked inline in the same stack frame as the hook call — defer via
`scheduler_->schedule(...)`, exactly like existing `DialerImpl` error paths.
**When to use:** Every call site where a gater rejection needs to notify an external
caller (Dialer's `cb`, UpgraderSession's `handler_`). Does **not** apply to
`TcpListener::doAccept()`'s rejection path in the same sense, because there is no
external caller callback fired on a rejected *inbound* accept (the accept loop simply
continues) — but the socket-close operation itself should still be deferred for
consistency with the "never call back into fragile teardown code synchronously from an
asio completion handler" lesson already learned in this codebase's TCP-transport
history (see Common Pitfalls below).
**Example (existing pattern in `DialerImpl::dial`, to be replicated for gater
rejections):**
```cpp
// src/network/impl/dialer_impl.cpp — EXISTING pattern (destination_address_required)
scheduler_->schedule(
    [cb{std::move(cb)}] { cb(std::errc::destination_address_required); });
```
```cpp
// PROPOSED for gater rejection at top of DialerImpl::dial()
if (auto gated = gater_->interceptPeerDial(p.id); !gated) {
  SL_DEBUG(log_, "gater rejected peer dial to {}: {}", p.id.toBase58(),
           gated.error().message());
  scheduler_->schedule(
      [cb{std::move(cb)}, err{gated.error()}] { cb(err); });
  return;
}
```

### Pattern 3: Leaf-library placement to avoid layering inversion
**What:** `p2p_connection_gater` depends only on `p2p_peer_id` and `p2p_multiaddress`
(mirroring `p2p_listener_manager`'s dependency set). It must NOT depend on `p2p_dialer`,
`p2p_network`, or `p2p_upgrader`.
**When to use:** Any time a new cross-cutting interface needs to be consumed by both
the `network` layer and the `transport` layer — this codebase's existing dependency
direction is `network → transport` (Dialer → TransportManager → TransportAdaptor), so a
shared interface must sit below both, not inside either.

### Anti-Patterns to Avoid
- **Null-checking `gater_` at call sites:** D-04 explicitly forbids `if (gater_)` guards
  — the Null Object pattern (always-bound `PermissiveConnectionGater`) makes this
  unnecessary and is the whole point of the pattern.
- **Wiring `interceptAddrDial` only into `DialerImpl::rotate()` and forgetting
  `rotateHolepunch()`:** these are two independent per-address dial loops in the same
  class; only wiring one silently creates a gater-bypass path via holepunching. Flag
  explicitly as a planning decision (see Common Pitfalls).
- **Closing the raw asio socket directly in `TcpListener::doAccept()` instead of via
  `TcpConnection::close()`:** `tcp_connection.cpp`'s close/teardown path already carries
  Windows-specific fixes (commit `af85794`, per `.planning/codebase/CONCERNS.md`) —
  bypassing it to hand-roll a raw `sock.close()` before `TcpConnection` is constructed
  reintroduces exactly the platform-teardown bug class already fixed once.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Deferring a callback to avoid reentrancy | A new "defer" helper/wrapper | `basic::Scheduler::schedule(Callback&&)` | Already the established mechanism throughout `DialerImpl`; the 10 unresolved `TODO(107): Reentrancy` markers in `.planning/codebase/CONCERNS.md` are exactly instances of code that skipped this and called back inline — do not repeat that mistake in new gater wiring |
| Converting a raw TCP endpoint to a `multi::Multiaddress` for `interceptAccept` | New endpoint-parsing code in `TcpListener::doAccept()` | `TcpConnection::localMultiaddr()` / `remoteMultiaddr()` (already implemented, inherited from `RawConnection`) — call these on the already-constructed `conn` before invoking `interceptAccept` | Avoids duplicating the `detail::makeAddress`/endpoint-conversion logic already used in `TcpListener::getListenMultiaddr()` |
| Error-code category boilerplate for `ConnectionGaterError` | A custom exception type or raw `int` error codes | `OUTCOME_HPP_DECLARE_ERROR` / `OUTCOME_CPP_DEFINE_CATEGORY` macro pair, exactly as used in `include/libp2p/peer/errors.hpp` / `src/peer/errors.cpp` and `include/libp2p/connection/raw_connection.hpp` / `src/connection/error_codes.cpp` | Every other subsystem's error enum follows this pattern; deviating breaks `outcome::result<T>` interop across the codebase |
| A new DI-override syntax/helper style for registering a custom gater | Ad-hoc `boost::di::bind<...>` call documented only in prose | A `useConnectionGater<GaterImpl>()` helper function in `network_injector.hpp`, mirroring the existing `useSecurityAdaptors<...>()`/`useMuxerAdaptors<...>()`/`useKeyPair(...)` helpers | Matches the documented Example 2/3/4 patterns already in `network_injector.hpp`'s file-level Doxygen comment; integrators already know this API shape |
| GMock test doubles for `ConnectionGater` | Hand-written stub classes per test file | `test/mock/libp2p/network/connection_gater_mock.hpp` using `MOCK_METHOD`, mirroring `test/mock/libp2p/network/dialer_mock.hpp`/`listener_mock.hpp` | Consistent with every other interface mock in `test/mock/libp2p/**`; reuse `Arg2CallbackWithArg`/`InvokeArgument<N>` helpers from `testutil/gmock_actions.hpp` already used in `dialer_test.cpp`/`upgrader_test.cpp` |

**Key insight:** Nothing in this phase requires new infrastructure — it requires
correctly reusing 4 idioms this codebase already has (Scheduler defer, outcome error
categories, DI override helpers, GMock mock generation) at 4 call sites that don't
currently share a common "policy hook" abstraction.

## Runtime State Inventory

Not applicable — this is a greenfield interface + wiring phase, not a rename/refactor/
migration. No stored data, live service config, OS-registered state, secrets, or build
artifacts reference a renamed identifier.

## Common Pitfalls

### Pitfall 1: Assuming "scheduler post/dispatch" is a literal API on `basic::Scheduler`
**What goes wrong:** Looking for `Scheduler::post()`/`Scheduler::dispatch()` methods
that don't exist, or worse, reaching for `boost::asio::post(io_context, ...)` directly
and bypassing the `Scheduler` abstraction this codebase centralizes all deferred
callbacks through.
**Why it happens:** The roadmap/requirements phrasing borrows asio terminology
("post"/"dispatch") but `include/libp2p/basic/scheduler.hpp` only exposes
`schedule(Callback&&)` (defer to next IO loop iteration — the `post()` analog) and
`scheduleWithHandle(...)` (same, with a cancellable/reschedulable handle).
**How to avoid:** Use `scheduler_->schedule(std::move(cb))` for one-shot deferred
callback delivery, matching `DialerImpl`'s existing usage exactly.
**Warning signs:** Any new code calling `io_context_->post(...)` or `->dispatch(...)`
directly instead of going through an injected `Scheduler`.

### Pitfall 2: `TcpListener` and `UpgraderSession` have no `Scheduler` today
**What goes wrong:** Planning the gater wiring as "just call `gater_->interceptX()`
and handle the result" without noticing these two classes need a **new constructor
dependency** to defer anything at all.
**Why it happens:** `Dialer` already has a `scheduler_` member so its wiring looks like
"just add the gater call"; `TcpListener`/`UpgraderSession` look the same from the
interface but are missing the underlying primitive.
**How to avoid:** Explicitly add `std::shared_ptr<basic::Scheduler> scheduler_` to both
`TcpListener` and `UpgraderSession` constructors, threaded from `TcpTransport` (which
Boost.DI will auto-resolve since `basic::Scheduler` is already bound in
`network_injector.hpp`).
**Warning signs:** A gater-rejection code path that calls `handler_(error)` or
`conn->close()` directly inline inside `onSecured()` or `doAccept()`'s accept lambda —
this reintroduces the exact `TODO(107): Reentrancy` pattern already flagged as a
historical bug source in `tcp_transport.cpp:32,189`.

### Pitfall 3: `DialerImpl::rotateHolepunch()` is a second, easy-to-miss dial loop
**What goes wrong:** Wiring `interceptAddrDial` only into `rotate()` (the primary
non-holepunch address-dial loop) and missing that `rotateHolepunch()` independently
calls `tr->dial(peer_id, addr, dial_handler, ...)` for holepunch attempts, silently
bypassing the gater for that code path.
**Why it happens:** `rotate()` and `rotateHolepunch()` look like near-duplicates but
are genuinely separate methods with separate state (`dialing_peers_` vs.
`dialing_holepunches_`).
**How to avoid:** This must be an explicit planning decision (either wire both, or
document that holepunch dials are intentionally out of GATE-03's scope for Phase 1) —
do not let it be silently skipped because `rotate()` was the only one checked.
**Warning signs:** A GATE-03 verification test that dials via holepunch and finds the
gater was never consulted.

### Pitfall 4: `UpgraderTest` (upgrader_test.cpp) tests are ALL `DISABLED_`
**What goes wrong:** Assuming there is existing automated coverage of the secure/mux
upgrade path that new gater tests can extend.
**Why it happens:** `test/libp2p/transport/upgrader_test.cpp` exists and looks
complete, but every single `TEST_F` in it is prefixed `DISABLED_` (5 of 5), and it
tests `UpgraderImpl` in isolation — not `UpgraderSession`, which is where the new
`interceptSecured`/`interceptUpgraded` calls actually live. `UpgraderSession` currently
has **zero** dedicated test file.
**How to avoid:** TEST-01 work for the secured/upgraded hooks needs a brand-new test
file (e.g. `test/libp2p/transport/upgrader_session_test.cpp`) built on
`RawConnectionMock`/`SecureConnectionMock`/`CapableConnectionMock` +
`ManualSchedulerBackend`/`SchedulerImpl`, following the `DialerTest` fixture pattern —
not an extension of the existing disabled `UpgraderTest`.
**Warning signs:** A plan that says "add test cases to `upgrader_test.cpp`" for the
secured/upgraded hooks.

### Pitfall 5: Bypassing `TcpConnection::close()` for the InterceptAccept teardown path
**What goes wrong:** Closing the raw `boost::asio::ip::tcp::socket` directly inside the
`async_accept` completion lambda (before a `TcpConnection` is even constructed) to
"save an allocation," instead of constructing `TcpConnection` first and calling its
`close()`.
**Why it happens:** It looks like a valid micro-optimization since `interceptAccept`
only needs local/remote multiaddresses, which could theoretically be read directly off
the raw `ip::tcp::socket`.
**How to avoid:** Construct `TcpConnection` first (as the existing code already does),
call `conn->localMultiaddr()`/`conn->remoteMultiaddr()` for the hook, and on rejection
call `conn->close()` — this reuses the Windows-teardown-hardened close path
(`.planning/codebase/CONCERNS.md`, commit `af85794`) rather than re-deriving raw-socket
close semantics that were already buggy once.
**Warning signs:** New code that calls `.close()`/`.shutdown()` on a
`boost::asio::ip::tcp::socket` object directly anywhere in the gater wiring.

## Code Examples

### Proposed `ConnectionGater` interface
```cpp
// include/libp2p/network/connection_gater.hpp
#ifndef LIBP2P_NETWORK_CONNECTION_GATER_HPP
#define LIBP2P_NETWORK_CONNECTION_GATER_HPP

#include <memory>

#include <libp2p/connection/capable_connection.hpp>
#include <libp2p/multi/multiaddress.hpp>
#include <libp2p/outcome/outcome.hpp>
#include <libp2p/peer/peer_id.hpp>

namespace libp2p::network {

  /**
   * @brief Pluggable connection-level access-control policy, consulted at each
   * stage of the connection lifecycle. Default (no gater configured) behavior
   * is fully permissive — see PermissiveConnectionGater.
   */
  struct ConnectionGater {
    virtual ~ConnectionGater() = default;

    /// Called before Dialer attempts to dial peer p at all (any address).
    virtual outcome::result<void> interceptPeerDial(
        const peer::PeerId &p) = 0;

    /// Called before Dialer dials a specific multiaddress for peer p.
    virtual outcome::result<void> interceptAddrDial(
        const peer::PeerId &p, const multi::Multiaddress &addr) = 0;

    /// Called immediately after TcpListener accepts a raw connection, before
    /// any security handshake bytes are exchanged.
    virtual outcome::result<void> interceptAccept(
        const multi::Multiaddress &local,
        const multi::Multiaddress &remote) = 0;

    /// Called after the security handshake completes (SecureConnection
    /// established), before muxer negotiation begins.
    virtual outcome::result<void> interceptSecured(
        bool is_initiator, const peer::PeerId &remote_peer,
        const multi::Multiaddress &remote_addr) = 0;

    /// Called after muxer negotiation completes (CapableConnection
    /// established), before the connect/accept caller is notified.
    virtual outcome::result<void> interceptUpgraded(
        const std::shared_ptr<connection::CapableConnection> &conn) = 0;
  };

}  // namespace libp2p::network

#endif  // LIBP2P_NETWORK_CONNECTION_GATER_HPP
```

### Proposed error enum (D-02, D-03)
```cpp
// include/libp2p/network/connection_gater_error.hpp
namespace libp2p::network {
  enum class ConnectionGaterError {
    GATER_REJECTED_PEER_DIAL = 1,
    GATER_REJECTED_ADDR_DIAL,
    GATER_REJECTED_ACCEPT,
    GATER_REJECTED_SECURED,
    GATER_REJECTED_UPGRADED,
  };
}
OUTCOME_HPP_DECLARE_ERROR(libp2p::network, ConnectionGaterError)
```
```cpp
// src/network/connection_gater_error.cpp
OUTCOME_CPP_DEFINE_CATEGORY(libp2p::network, ConnectionGaterError, e) {
  using E = libp2p::network::ConnectionGaterError;
  switch (e) {
    case E::GATER_REJECTED_PEER_DIAL:
      return "ConnectionGater: rejected at interceptPeerDial";
    case E::GATER_REJECTED_ADDR_DIAL:
      return "ConnectionGater: rejected at interceptAddrDial";
    case E::GATER_REJECTED_ACCEPT:
      return "ConnectionGater: rejected at interceptAccept";
    case E::GATER_REJECTED_SECURED:
      return "ConnectionGater: rejected at interceptSecured";
    case E::GATER_REJECTED_UPGRADED:
      return "ConnectionGater: rejected at interceptUpgraded";
  }
  return "ConnectionGater: unknown rejection";
}
```
*(Exact enum spelling is a proposal, not a locked decision — D-02/D-03 only lock the
principle of per-hook codes with "gater" legible in the text. `[ASSUMED]` naming,
confirm with planner/user if a different convention is preferred.)*

### Proposed injector helper (mirrors `useSecurityAdaptors<...>()`)
```cpp
// include/libp2p/injector/network_injector.hpp — additions
#include <libp2p/network/connection_gater.hpp>
#include <libp2p/network/impl/permissive_connection_gater.hpp>

namespace libp2p::injector {
  template <typename GaterImpl>
  inline auto useConnectionGater() {
    return boost::di::bind<network::ConnectionGater>()
        .template to<GaterImpl>()[boost::di::override];
  }
}  // namespace libp2p::injector

// inside makeNetworkInjector(...)'s di::make_injector<InjectorConfig>(...) list:
di::bind<network::ConnectionGater>().TEMPLATE_TO<network::PermissiveConnectionGater>(),
```
Integrator usage (GATE-04/D-05 — no source changes to Dialer/TcpListener/UpgraderSession):
```cpp
auto injector = libp2p::injector::makeHostInjector(
    libp2p::injector::useConnectionGater<MyCustomGater>());
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|---------------|--------|
| No connection-level access control in this fork | `ConnectionGater` interface at 5 lifecycle stages | This phase | Enables permissioned/private SuperGenius networks (project's stated core value) |

**Deprecated/outdated:** N/A — no existing gater mechanism to deprecate in this fork.

**Reference note on go-libp2p:** go-libp2p's `connmgr.ConnectionGater` interface
(`InterceptPeerDial`, `InterceptAddrDial`, `InterceptAccept`, `InterceptSecured`,
`InterceptUpgraded`) uses the same 5 stages and fully synchronous, side-effect-free
semantics this research recommends mirroring (adapted to `outcome::result<void>`
instead of bare `bool` + `control.DisconnectReason`). Per `.planning/PROJECT.md`, wire
interop with go-libp2p is explicitly out of scope, so exact go-libp2p signature
conformance is not required — only the conceptual 5-stage model, which D-01 already
locks via the camelCase renaming. `[ASSUMED: based on training-data knowledge of
go-libp2p's ConnectionGater interface; not verified via WebSearch/Context7 in this
research session — if precise upstream signature parity ever matters, verify against
current go-libp2p `core/connmgr/gater.go` before implementation.]`

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `ConnectionGater` hooks should be synchronous `outcome::result<void>` (no callback param), with async-boundary discipline pushed to the 3 call sites via `scheduler_->schedule(...)` | Architecture Patterns, Standard Stack (Alternatives Considered) | If the planner/user actually wants async (I/O-capable) gater hooks, the interface signature, all 4 call sites, and every test would need a callback-based redesign — moderate rework, but no CONTEXT.md decision locks this either way, so it is a genuine open design choice, not a verified fact |
| A2 | Exact `ConnectionGaterError` enum member spelling (`GATER_REJECTED_PEER_DIAL`, etc.) | Code Examples | Low risk — D-02/D-03 lock the *principle* (per-hook codes, "gater" legible in text), not exact spelling; trivial to rename during planning/implementation |
| A3 | go-libp2p's `ConnectionGater` interface has exactly these 5 hook names/semantics (`InterceptPeerDial`, `InterceptAddrDial`, `InterceptAccept`, `InterceptSecured`, `InterceptUpgraded`) | State of the Art | Low risk — this phase does not require go-libp2p wire/API conformance (explicitly out of scope per PROJECT.md); cited only as background context, not a locked requirement |
| A4 | `rotateHolepunch()` should be an explicit in-scope-or-out-of-scope decision for `interceptAddrDial` wiring, rather than assumed covered | Common Pitfalls #3 | Medium risk if silently skipped — could leave a real gater-bypass path in the shipped Phase 1 behavior; low risk if planner explicitly decides and documents either way |

**If this table is empty:** N/A — see entries above; none are compliance/security-policy
claims requiring external verification, all are C++ design choices confirmed directly
against this repository's source.

## Open Questions

1. **Should `interceptAddrDial` also gate `DialerImpl::rotateHolepunch()`'s address
   attempts, or is holepunch dialing intentionally out of Phase 1 scope?**
   - What we know: `rotate()` and `rotateHolepunch()` are structurally parallel but
     independent per-address dial loops in `DialerImpl`; roadmap/REQUIREMENTS text
     refers to "Dialer" generically without distinguishing them.
   - What's unclear: Whether holepunch-initiated dials are meant to be covered by
     GATE-03 in Phase 1, or deferred (holepunch/relay are call-out features not
     mentioned in the phase's stated 5-stage scope).
   - Recommendation: Planner should make this an explicit task-level decision (wire
     both, or document the gap) rather than let it default to "only `rotate()` gets
     touched because that's what the obvious code path shows."

2. **Should `TcpListener`'s `interceptAccept` rejection-driven `conn->close()` be
   scheduler-deferred, or is synchronous close acceptable since no external callback
   fires on that path?**
   - What we know: Unlike the secured/upgraded rejection paths (which must fire
     `handler_(error)` — an external caller's callback — and therefore must defer),
     an inbound accept that gets rejected has no waiting caller; `doAccept()` just
     continues its accept loop.
   - What's unclear: Whether roadmap criterion 5's blanket "always delivered via
     scheduler post/dispatch" language is meant to cover this close-operation too
     (for reentrancy-safety consistency with the asio completion-handler context it
     runs in), or only applies to caller-visible callback delivery.
   - Recommendation: Given this codebase's documented history of TCP-transport
     teardown bugs (`.planning/codebase/CONCERNS.md`), recommend deferring the close
     via the newly-added `scheduler_` member for consistency/safety even though it's
     not strictly required by "no external callback exists" reasoning — cheap
     insurance against a currently-undocumented reentrancy edge case in
     `acceptor_.async_accept`'s completion handler.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| CMake | Build system | ✓ | 3.29.2 | — |
| MSVC (`cl`) on PATH | Windows native build | ✗ (not on PATH directly) | — | Build via "Developer Command Prompt for VS" / CMake Visual Studio generator, which sets up `cl` — this is the project's existing normal Windows workflow, not new to this phase |
| Hunter package manager | Dependency fetch (bootstrapped by CMake) | ✓ (bootstrapped automatically via `cmake/Hunter/init.cmake`) | pinned soramitsu fork | — |
| GTest | TEST-01 unit tests | ✓ (Hunter-fetched, gated by `TESTING` CMake option, default ON) | Hunter-pinned | — |

**Missing dependencies with no fallback:** None.

**Missing dependencies with fallback:** MSVC not directly on PATH in this shell session
— use the project's existing Visual Studio / Developer Command Prompt build workflow
(unaffected by this phase; not a new requirement it introduces).

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-------------------|
| V1 Architecture, Design and Threat Modeling | Yes | Explicit access-control boundary added at a well-defined layer (connection upgrade pipeline); default-permissive behavior (GATE-02) is a deliberate, requirements-locked deviation from "secure by default" — documented here, not silently accepted. Deny-by-default reference policy is explicitly deferred (POLICY-01, v2) |
| V4 Access Control | Yes | `ConnectionGater`'s 5 hooks are the standard control — this phase's entire purpose. No new access-control primitive should be hand-rolled elsewhere once this exists |
| V5 Input Validation | Partial | `PeerId`/`Multiaddress` values passed into hook methods are already validated/parsed upstream (by `PeerId::fromBytes`/`Multiaddress::create`, which return `outcome::result`) before reaching the gater — hooks receive already-validated types, not raw bytes |
| V7 Error Handling and Logging | Yes | D-06 requires the library (not the gater) to log rejections at `SL_DEBUG`, including hook name + peer/address where available — this is the standard control for this phase |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|----------------------|
| Resource exhaustion via repeated rejected-then-retried inbound connections (fd/thread leak on rejection) | Denial of Service | GATE-05: gater rejection must always route through the existing hardened close path (`conn->close()`, guarded by `!conn->isClosed()`) — never leave a rejected raw socket/`TcpConnection` unclosed |
| Reentrant callback invocation during a gater rejection corrupting caller state (same class of bug as the 10 documented `TODO(107)` sites) | Tampering / Denial of Service (crash) | Scheduler-deferred delivery (`scheduler_->schedule(...)`) for every caller-visible callback fired as a result of a gater decision |
| Silent gater bypass via an un-wired code path (e.g. holepunch dial loop) | Elevation of Privilege (unauthorized peer reaches a stage that should have been blocked) | Explicit, complete enumeration and wiring of every address-dial/accept/secure/upgrade call site — see Common Pitfalls #3 |
| Ambiguous rejection error (caller can't tell gater rejected vs. unrelated network failure) | Repudiation / operational blindness | D-03: `GATER_`-prefixed, per-hook error codes with unambiguous message text |

## Sources

### Primary (HIGH confidence)
- Direct repository source reads (this session): `include/libp2p/network/dialer.hpp`,
  `src/network/impl/dialer_impl.{hpp,cpp}`, `src/transport/tcp/tcp_listener.{hpp,cpp}`,
  `include/libp2p/transport/tcp/tcp_listener.hpp`,
  `src/transport/tcp/tcp_transport.cpp`, `include/libp2p/transport/tcp/tcp_transport.hpp`,
  `include/libp2p/transport/impl/upgrader_session.hpp`,
  `src/transport/impl/upgrader_session.cpp`, `include/libp2p/transport/upgrader.hpp`,
  `src/transport/impl/upgrader_impl.cpp`, `include/libp2p/injector/network_injector.hpp`,
  `include/libp2p/injector/host_injector.hpp`, `include/libp2p/basic/scheduler.hpp`,
  `include/libp2p/connection/{raw_connection,secure_connection,capable_connection}.hpp`,
  `src/network/impl/listener_manager_impl.cpp`, `include/libp2p/peer/{errors,peer_id,peer_info}.hpp`,
  `src/peer/errors.cpp`, `src/connection/error_codes.cpp`,
  `include/libp2p/transport/transport_adaptor.hpp`, `include/libp2p/security/security_adaptor.hpp`,
  `include/libp2p/basic/adaptor.hpp`, `test/libp2p/network/dialer_test.cpp`,
  `test/libp2p/transport/tcp/tcp_listener_test.cpp`, `test/libp2p/transport/upgrader_test.cpp`,
  various `CMakeLists.txt` under `src/network/`, `src/transport/`, `src/connection/`
  `[VERIFIED: local repository read]`

### Secondary (MEDIUM confidence)
- `.planning/codebase/ARCHITECTURE.md`, `.planning/codebase/CONCERNS.md` — prior
  codebase-mapping pass (2026-08-26), cross-checked against direct source reads in this
  session and found accurate `[CITED: .planning/codebase/*]`

### Tertiary (LOW confidence)
- go-libp2p `ConnectionGater` interface shape (5 hook names/semantics) —
  training-data recollection, not verified via WebSearch/Context7 this session
  `[ASSUMED]` — see Assumptions Log A3

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — no new dependencies; existing pinned toolchain confirmed via
  direct CMake probe
- Architecture: HIGH — every claim about call sites, constructor signatures, and
  missing Scheduler dependencies is a direct source read, not inference
- Pitfalls: HIGH — all 5 pitfalls are grounded in specific line-numbered code and/or
  `.planning/codebase/CONCERNS.md` cross-references

**Research date:** 2026-08-26
**Valid until:** Effectively indefinite for the architectural findings (tied to this
specific repository's current source, not an external/versioned API) — re-verify only
if the codebase's `Dialer`/`TcpListener`/`UpgraderSession` implementations change
materially before this phase is planned/executed.
