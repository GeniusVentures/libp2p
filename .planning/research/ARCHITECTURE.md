# Architecture Research

**Domain:** libp2p Connection Gater + Private Network (pnet) integration into a Boost.DI-wired C++17 connection-upgrade pipeline
**Researched:** 2026-08-25
**Confidence:** MEDIUM-HIGH (go-libp2p source/spec cross-checked across 3+ independent sources via WebSearch; this-codebase mapping is HIGH — verified by direct reads of `dialer_impl.cpp`, `tcp_listener.cpp`, `tcp_transport.cpp`, `upgrader_impl.cpp`, `upgrader_session.cpp`, `raw_connection.hpp`, `network_injector.hpp`)

## Standard Architecture (go-libp2p reference)

### System Overview

```
                          OUTBOUND DIAL                         INBOUND ACCEPT
                               │                                      │
                               ▼                                      ▼
                   ┌─────────────────────┐                ┌─────────────────────┐
                   │ Swarm.DialPeer(pid)  │                │  Transport Listener  │
                   │ ①InterceptPeerDial   │                │  .Accept() → raw     │
                   └──────────┬───────────┘                │  conn                │
                               │ (resolve addrs)             │  ③InterceptAccept    │
                               ▼                            └──────────┬───────────┘
                   ┌─────────────────────┐                             │
                   │ per-address dial     │                            │
                   │ ②InterceptAddrDial   │                            │
                   └──────────┬───────────┘                            │
                               │                                       │
                               └───────────────┬───────────────────────┘
                                               ▼
                               ┌───────────────────────────────┐
                               │   transport.Upgrader.Upgrade()  │
                               │  ┌───────────────────────────┐ │
                               │  │ pnet.Protector (if PSK set) │ │  ← wraps net.Conn,
                               │  │  wraps raw net.Conn FIRST   │ │    INNERMOST layer
                               │  └─────────────┬─────────────┘ │
                               │                ▼               │
                               │   security handshake (multistream-select
                               │   chooses noise/tls, then Diffie-Hellman)
                               │                ▼               │
                               │        ④InterceptSecured        │  (after security,
                               │                ▼               │   before muxer)
                               │   muxer negotiation (multistream-select
                               │   chooses yamux/mplex)
                               │                ▼               │
                               │        ⑤InterceptUpgraded       │  (final checkpoint,
                               └───────────────┬───────────────┘   can emit DisconnectReason)
                                               ▼
                                    CapableConnection returned
                                    to Swarm / registered
```

### Component Responsibilities

| Component | Responsibility | Typical Implementation |
|-----------|----------------|------------------------|
| `ConnectionGater` | 5-method interface, one method per lifecycle checkpoint, each returns allow/deny (last one also a disconnect reason) | `core/connmgr/gater.go`, injected once into `Swarm` and `Upgrader` |
| `pnet.Protector` / PSK | Wraps the raw transport `net.Conn` in an XSalsa20 stream cipher before any other byte leaves/enters the pipe | `go-libp2p-pnet`, referenced as `Upgrader.psk` field, applied inside `Upgrader.Upgrade()` |
| `Upgrader` | Single choke point that both dial and accept paths route through; owns security transports, muxers, gater, and (optionally) the PSK protector | `p2p/net/upgrader/upgrader.go` |
| `Swarm` (dialer + listener) | Calls `InterceptPeerDial`/`InterceptAddrDial` before dialing; calls `InterceptAccept` right after `Accept()` returns, before handing the raw conn to `Upgrader` | `p2p/net/swarm/swarm_dial.go`, `swarm_listen.go` |

**Key confirmed fact (cross-checked, MEDIUM confidence — WebSearch, no direct doc/MCP access):** the PSK protector is applied **before** security transport negotiation begins, and the encryption is fully transparent — it covers every byte including the multistream-select negotiation traffic itself. There is no separate pnet "handshake protocol" visible on the wire beyond a 24-byte nonce; a peer without the correct PSK sees scrambled bytes and the multistream-select/security layer above simply fails to parse them. Traffic ends up double-encrypted (PSK + regular security transport) by design — the two layers are independent defenses.

## Recommended Mapping onto This Codebase

This fork's pipeline is structurally the same shape as go-libp2p's (raw → secure → muxed, funneled through a single `Upgrader`), which is what makes this integration low-risk: **every place go-libp2p puts a gater hook or the PSK wrap, this codebase already has a distinct, narrow call site for.**

### Confirmed call sites (read directly from source)

| go-libp2p hook | This codebase's exact insertion point | Why this is the only place it needs to go |
|---|---|---|
| ① `InterceptPeerDial` | `DialerImpl::dial()` in `src/network/impl/dialer_impl.cpp`, top of the method (after the empty-peer-id guard, before the connection-manager reuse check / `DialCtx` construction) | This is the single entry point for all outbound dials — both `Host::connect` and `newStream`-triggered auto-dial funnel through here. |
| ② `InterceptAddrDial` | `DialerImpl::rotate()` in the same file, immediately before each `tr->dial(peer_id, addr, dial_handler, ...)` call (both the circuit-relay branch and the plain branch, ~lines 187 and 214) | `rotate()` is the only place a specific `(peer_id, multiaddr)` pair is chosen right before dialing it — exactly matches go-libp2p's per-address timing. |
| ③ `InterceptAccept` | `TcpListener::doAccept()` in `src/transport/tcp/tcp_listener.cpp`, immediately after `acceptor_.async_accept` succeeds and before `std::make_shared<TcpConnection>(...)` / `UpgraderSession` are created (~line 153) | This is the only inbound accept call site; `TcpListener` is the sole `TransportListener` implementation today. Denying here means closing `sock` and calling `self->doAccept()` again — no `TcpConnection`/`UpgraderSession` object is ever constructed for rejected peers. |
| ④ `InterceptSecured` | `UpgraderSession::onSecured()` in `src/transport/impl/upgrader_session.cpp`, right after `rsecure` is confirmed successful, before the call to `upgrader_->upgradeToMuxed(...)` (line ~62) | `UpgraderSession` already exists specifically to sit between the secure and muxed stages for both inbound and outbound sessions — this is its natural home. |
| ⑤ `InterceptUpgraded` | Inside the same `onSecured()`'s `upgradeToMuxed` completion lambda, after `conn_res` (the `CapableConnection`) is available, before `self->handler_(...)` is invoked | This is the last point `UpgraderSession` touches the connection before handing it back to `TcpTransport::dial`/`TcpListener::doAccept`, which pass it to `ConnectionManager` via `Dialer`/`ListenerManager::onConnection`. |

**Both `InterceptSecured` and `InterceptUpgraded` belong in `UpgraderSession`, not `UpgraderImpl`.** `UpgraderSession` is a per-connection, stateful helper that already exists purely to sequence secure→mux and knows direction (inbound/outbound), the remote `PeerId` (from the now-secured connection), and both multiaddresses — everything the two hooks need. `UpgraderImpl` (`src/transport/impl/upgrader_impl.cpp`) is a stateless, shared, DI-singleton service that picks adaptors via multiselect; it should not be touched at all.

### Where the pnet PSK wrapper goes (confirmed by reading the actual call graph)

Both `TcpTransport::dial()` (outbound, `src/transport/tcp/tcp_transport.cpp`) and `TcpListener::doAccept()` (inbound, `src/transport/tcp/tcp_listener.cpp`) do the exact same thing after obtaining a raw `TcpConnection`: construct a `UpgraderSession(upgrader_, conn, handler)` and call `secureOutbound()`/`secureInbound()`. Those calls go straight into `UpgraderImpl::upgradeToSecureOutbound/Inbound()`, which calls `protocol_muxer_->selectOneOf(security_protocols_, conn, ...)` **directly on the raw connection** — i.e. multiselect negotiation runs on `conn` with no wrapping today.

This means **there is exactly one place** to insert the pnet wrap that covers both inbound and outbound without touching `TcpTransport`, `TcpListener`, or `UpgraderSession` at all: **inside the `Upgrader` interface itself**, as a decorator.

- Add a `PnetProtectedConnection` implementing `connection::RawConnection` (`include/libp2p/connection/raw_connection.hpp` — a small interface: `basic::ReadWriteCloser` + `isInitiator()`/`localMultiaddr()`/`remoteMultiaddr()`, all of which just delegate to the wrapped inner connection except `read`/`write`, which XOR/XSalsa20-encrypt through the PSK). This is a thin decorator — the interface is small enough that this is genuinely low-risk.
- Add a `PnetUpgraderDecorator` implementing `transport::Upgrader` (`include/libp2p/transport/upgrader.hpp`) that holds `std::shared_ptr<Upgrader> inner_` and a PSK. Each of its four `upgradeToSecure*` methods wraps the incoming `RawSPtr`/`StrSPtr` in a `PnetProtectedConnection` (when a PSK is configured) and delegates to `inner_`. `upgradeToMuxed` passes through unchanged (it already operates on the post-security `SecureConnection`, which is above the PSK layer).
- **This satisfies the constraint "no bypassing Upgrader"** exactly: nothing routes around `Upgrader`/`UpgraderSession`/multiselect. The PSK layer sits *underneath* the byte stream that `Upgrader` already negotiates over, which is precisely where go-libp2p puts it (innermost, before multistream-select ever runs) — so protocol negotiation bytes are opaque to a non-participant exactly like upstream.
- DI wiring: when a PSK is configured, bind `Upgrader` to `PnetUpgraderDecorator` (constructed with the real `UpgraderImpl` as `inner_`); when no PSK is configured, bind `Upgrader` directly to `UpgraderImpl` as today. No other component's DI binding or constructor signature changes.

### Recommended Project Structure

```
include/libp2p/
├── network/
│   └── connection_gater.hpp          # NEW — the 5-method ConnectionGater interface
├── security/
│   └── pnet/
│       ├── psk.hpp                    # NEW — PSK type (32-byte key) + spec-format parsing
│       └── pnet_protected_connection.hpp  # NEW — RawConnection decorator (XSalsa20)
└── transport/
    └── impl/
        └── pnet_upgrader_decorator.hpp # NEW — Upgrader decorator that applies the PSK wrap

src/
├── network/
│   └── impl/
│       └── permissive_connection_gater.cpp  # NEW — default no-op ConnectionGater impl
└── security/
    └── pnet/                            # NEW — mirrors include/libp2p/security/pnet/
        ├── psk.cpp
        └── pnet_protected_connection.cpp
└── transport/
    └── impl/
        └── pnet_upgrader_decorator.cpp   # NEW

test/
├── mock/libp2p/network/connection_gater_mock.hpp  # NEW — GMock for ConnectionGater
└── libp2p/
    ├── network/connection_gater_test.cpp           # NEW
    └── security/pnet/pnet_protected_connection_test.cpp  # NEW
```

### Structure Rationale

- `network/connection_gater.hpp` lives in `network/` (not `connection/`) because it gates dial/accept/secured/upgraded *decisions* made by `Dialer`/`ListenerManager`/`Upgrader` — it's a policy interface, not a connection-stage interface, matching how `Router`/`ConnectionManager` are organized.
- `security/pnet/` (not `transport/pnet/`) because pnet is conceptually a security/access-control primitive (per `PROJECT.md`'s framing and the libp2p spec's own categorization as "an additional encryption layer"), even though its *implementation hook point* is inside `transport/impl/`. This mirrors `security/noise/`, `security/secio/` as sibling adaptors, and keeps `transport/impl/` for the two upgrade-pipeline glue classes (`UpgraderImpl`, `UpgraderSession`, and now the new `PnetUpgraderDecorator`).
- `permissive_connection_gater.cpp`'s home in `network/impl/` follows the existing 1:1 pairing convention (`include/libp2p/network/` ↔ `src/network/impl/`) used by `DialerImpl`, `ListenerManagerImpl`, etc.

## Architectural Patterns

### Pattern 1: Single `ConnectionGater` interface, not per-hook callables

**What:** One abstract interface with 5 pure-virtual methods (mirroring go-libp2p's `ConnectionGater` exactly), injected as a single `std::shared_ptr<network::ConnectionGater>` wherever a hook fires (`DialerImpl`, `TcpListener`, `UpgraderSession`).

**When to use:** Always, for this feature. Rejected alternative: 5 separate `std::function<...>` callable bindings (one per hook).

**Trade-offs:**
- *For:* Matches every existing adaptor pattern in this codebase (`SecurityAdaptor`, `MuxerAdaptor`, `TransportAdaptor` are all single interfaces registered once in `network_injector.hpp`, per `include/libp2p/injector/network_injector.hpp:200-230`). A single interface is trivially mockable (`test/mock/libp2p/network/connection_gater_mock.hpp`, matching the existing `test/mock/libp2p/` convention) for unit tests at each hook. It's also what go-libp2p itself does — direct prior art for a spec-compliance-motivated project. One DI binding to reason about, one object identity shared across the 3 consumer call sites (useful if a real gater implementation needs shared state, e.g. a connection-count limiter that must see peer-dial, accept, and upgrade events together).
- *Against:* A consumer that only wants to override one hook (e.g. just `InterceptAccept`) must still implement all 5 methods — mitigated by providing a `BaseConnectionGater` with default-permissive implementations of all 5 that a custom gater can selectively override (this is exactly what go-libp2p's own ecosystem does with helper base structs).

**Example:**
```cpp
// include/libp2p/network/connection_gater.hpp
namespace libp2p::network {
  struct ConnectionGater {
    virtual ~ConnectionGater() = default;
    virtual bool interceptPeerDial(const peer::PeerId &p) = 0;
    virtual bool interceptAddrDial(const peer::PeerId &p,
                                    const multi::Multiaddress &addr) = 0;
    virtual bool interceptAccept(const multi::Multiaddress &remote) = 0;
    virtual bool interceptSecured(bool is_inbound, const peer::PeerId &p,
                                   const multi::Multiaddress &remote) = 0;
    virtual bool interceptUpgraded(
        const std::shared_ptr<connection::CapableConnection> &conn) = 0;
  };
}
```

### Pattern 2: Default no-op gater bound by default, override via DI

**What:** `network_injector.hpp` binds `ConnectionGater` to a `PermissiveConnectionGater` (all 5 methods return `true`/allow) by default — identical in spirit to how `useSecurityAdaptors<...>()`/`useTransportAdaptors<...>()` let a caller override the default binding.

**When to use:** Always — this is what makes the feature purely additive (satisfies the PROJECT.md "Default no-op gater behavior" requirement) and keeps every existing test/example working unmodified.

**Trade-offs:** None significant — this is the same DI-override pattern already documented in `network_injector.hpp`'s own doc comments (Example 3/4).

**Example:**
```cpp
// in network_injector.hpp, alongside the existing default bindings:
di::bind<network::ConnectionGater>().TEMPLATE_TO<network::PermissiveConnectionGater>(),

// consumer override, exactly like existing di::bind<Router> example:
auto injector = makeNetworkInjector(
    di::bind<network::ConnectionGater>().TEMPLATE_TO<MyCustomGater>()
);
```

### Pattern 3: pnet as an `Upgrader` decorator, not a change to `TcpConnection`/`TcpListener`/`TcpTransport`

**What:** `PnetUpgraderDecorator : Upgrader` wraps the real `Upgrader` and, in each `upgradeToSecure*` method, wraps the incoming raw connection/stream in a `PnetProtectedConnection` before delegating.

**When to use:** Always, for this feature — it's the only approach that touches exactly one binding in `network_injector.hpp` and zero other files in the transport layer.

**Trade-offs:**
- *For:* Keeps `TcpTransport`/`TcpListener`/`UpgraderSession` completely untouched — both inbound and outbound paths are covered automatically because both already funnel through `Upgrader`. Fully composable with the gater (gater's `InterceptAccept` still fires on the true raw multiaddr before pnet even starts, since it lives in `TcpListener`, outside `Upgrader` entirely; gater's `InterceptSecured`/`InterceptUpgraded` fire on the post-pnet, post-security connection in `UpgraderSession`, seeing exactly what go-libp2p's gater sees).
- *Against:* Decorating an interface with 6 methods (4 `upgradeToSecure*` + `upgradeToMuxed`, only 4 need wrapping) means some boilerplate pass-through code; acceptable given the alternative (touching every raw-connection construction site) is strictly worse.

**Example:**
```cpp
// include/libp2p/transport/impl/pnet_upgrader_decorator.hpp
class PnetUpgraderDecorator : public Upgrader {
 public:
  PnetUpgraderDecorator(std::shared_ptr<Upgrader> inner, security::pnet::Psk psk);

  void upgradeToSecureInbound(RawSPtr conn, OnSecuredCallbackFunc cb) override {
    inner_->upgradeToSecureInbound(
        std::make_shared<security::pnet::PnetProtectedConnection>(std::move(conn), psk_),
        std::move(cb));
  }
  // ...upgradeToSecureOutbound, *Relay variants: same wrap-then-delegate...
  void upgradeToMuxed(SecSPtr conn, OnMuxedCallbackFunc cb) override {
    inner_->upgradeToMuxed(std::move(conn), std::move(cb));  // pass-through, unwrapped already
  }

 private:
  std::shared_ptr<Upgrader> inner_;
  security::pnet::Psk psk_;
};
```

## Data Flow

### Outbound Dial (with gater + pnet)

```
Host::connect(peerInfo)
    ↓
DialerImpl::dial()
    ↓ [①gater.interceptPeerDial(peer_id) — deny → immediate error callback]
DialCtx built, DialerImpl::rotate() picks next untried address
    ↓ [②gater.interceptAddrDial(peer_id, addr) — deny → skip address, keep rotating]
TransportAdaptor(TcpTransport)::dial(remoteId, addr, handler)
    ↓ (raw TCP connect via boost::asio, produces TcpConnection : RawConnection)
UpgraderSession(upgrader_, conn, handler)::secureOutbound(remoteId)
    ↓
Upgrader::upgradeToSecureOutbound(conn, remoteId, cb)
    │  ── if PnetUpgraderDecorator is bound: conn wrapped in PnetProtectedConnection HERE,
    │     before multiselect ever reads a byte from it
    ↓
protocol_muxer_ (multiselect) negotiates security proto over the (possibly PSK-wrapped) conn
    ↓ security adaptor (noise/tls/plaintext) produces SecureConnection
UpgraderSession::onSecured(rsecure)
    ↓ [④gater.interceptSecured(outbound, remoteId, remoteMultiaddr) — deny → error, close conn]
Upgrader::upgradeToMuxed(secConn, cb) → multiselect negotiates muxer (yamux) → CapableConnection
    ↓ [⑤gater.interceptUpgraded(capableConn) — deny → error, close conn]
UpgraderSession's handler_(capableConn) → back to DialerImpl::rotate()'s dial_handler
    ↓
ConnectionManager registers connection; DialerImpl::completeDial() fires user callbacks
```

### Inbound Accept (with gater + pnet)

```
TcpListener::doAccept() — acceptor_.async_accept() completes
    ↓ [③gater.interceptAccept(remote multiaddr from socket) — deny → close(sock), doAccept() again;
       no TcpConnection/UpgraderSession ever constructed for rejected peers]
TcpConnection constructed, UpgraderSession(upgrader_, conn, handle_)::secureInbound()
    ↓
Upgrader::upgradeToSecureInbound(conn, cb)
    │  ── same PnetUpgraderDecorator wrap point as outbound, symmetric
    ↓
multiselect negotiates security (responder side) → SecureConnection
    ↓ [④gater.interceptSecured(inbound, remotePeerId, remoteMultiaddr)]
multiselect negotiates muxer → CapableConnection
    ↓ [⑤gater.interceptUpgraded(capableConn)]
handle_(capableConn) → ListenerManager::onConnection() → ConnectionManager registers it
    ↓
Router dispatches inbound streams to registered protocol handlers
```

### Key Data Flows

1. **pnet wraps strictly below multiselect, on both paths symmetrically:** because both `TcpTransport::dial()` and `TcpListener::doAccept()` construct a `UpgraderSession` and immediately call into `Upgrader`, a single `PnetUpgraderDecorator` binding protects every connection uniformly — there's no separate "inbound PSK path" vs "outbound PSK path" to keep in sync.
2. **Gater and pnet do not interact — they compose orthogonally:** the gater answers "who/where," pnet answers "can they even read the bytes." `InterceptAccept` fires in `TcpListener` before `Upgrader` (hence before pnet) ever runs; `InterceptSecured`/`InterceptUpgraded` fire in `UpgraderSession` after pnet has already been stripped off by the security layer's view of the connection (pnet operates below `RawConnection`, security/muxer operate above it — the gater's two upgrade-stage hooks never see PSK-wrapped bytes, only the fully negotiated result).
3. **Denial is always "stop propagating the connection," never "manually negotiate an alternative":** every gater hook's rejection path reuses existing failure plumbing (`DialerImpl`'s `dial_handler` error path, `TcpListener::doAccept()`'s `self->doAccept()` retry loop, `UpgraderSession::onSecured`'s early-return-with-error). No new negotiation or retry logic is introduced.

## Scaling Considerations

| Scale | Architecture Adjustments |
|-------|--------------------------|
| Single private network, few nodes | Exactly as described above — no changes needed. |
| Many concurrent inbound connections (accept-stage gating under load) | `InterceptAccept` must be cheap and non-blocking (it runs synchronously inside `TcpListener::doAccept()`'s completion handler, on the `io_context` thread) — a gater backed by a large blocklist should use an O(1) lookup (hash set), not a linear scan, to avoid stalling the accept loop under connection-flood conditions. |
| pnet CPU cost | XSalsa20 is a stream cipher applied per-byte on every connection's `read`/`write` — cheap per-byte but adds a memcpy/xor pass; negligible at typical libp2p traffic volumes, but worth a note if this ever needs to support very high-throughput data channels. |

### Scaling Priorities

1. **First bottleneck:** none expected at GNUS's stated private-network scale — this is explicitly out of scope per `PROJECT.md` (no go-libp2p-scale public bootstrap interop required).
2. **Second bottleneck:** if a future gater implementation needs cross-node state (e.g. a shared blocklist synced via gossipsub), that's an application-layer concern layered on top of the `ConnectionGater` interface, not an architectural change to the hook points themselves.

## Anti-Patterns

### Anti-Pattern 1: Wrapping the raw connection outside `Upgrader`

**What people do:** Add pnet wrapping logic inside `TcpTransport::dial()` or `TcpListener::doAccept()` directly (e.g. "just wrap `conn` before constructing `UpgraderSession`").
**Why it's wrong:** Duplicates the wrap in two places (inbound and outbound) that must stay in sync, and couples a security/access-control concern into the transport-specific implementation — meaning a future second transport (QUIC, WebSocket, per `STRUCTURE.md`'s "New Transport" guidance) would have to remember to re-implement it.
**Instead:** Wrap once, inside a `PnetUpgraderDecorator` bound in place of `Upgrader` — every transport that routes through `Upgrader` (all of them, by the existing `Upgrader` contract) gets pnet for free.

### Anti-Pattern 2: Per-hook `std::function` callables instead of one interface

**What people do:** Bind 5 separate `std::function<bool(...)>` DI bindings (one per hook) instead of a single `ConnectionGater` interface.
**Why it's wrong:** Breaks from every existing adaptor pattern in this codebase (`SecurityAdaptor`, `MuxerAdaptor`, `TransportAdaptor` are all single interfaces); makes it impossible for a real gater implementation to share state cleanly across hooks (e.g. a per-peer connection counter that needs to see both `interceptAccept` and `interceptUpgraded`); harder to mock as a unit (5 separate mocks instead of 1).
**Instead:** Single `ConnectionGater` interface, bound once, injected as `std::shared_ptr<ConnectionGater>` into `DialerImpl`, `TcpListener`, and `UpgraderSession`.

### Anti-Pattern 3: Bypassing `Upgrader`/multiselect to implement pnet's "handshake"

**What people do:** Because pnet has a nonce exchange, it's tempting to treat it like a mini-protocol requiring its own negotiation step spliced into the pipeline before multiselect runs.
**Why it's wrong:** Per the spec, pnet has **no discoverable handshake protocol** — it's transparent encryption of the raw byte stream, including the multistream-select bytes themselves. Adding an explicit negotiation step would both violate the spec (defeating the "hide protocol traffic from non-participants" goal, since a fingerprint-able handshake gives away that this is a pnet connection) and duplicate multiselect logic — directly the anti-pattern already documented in `.planning/codebase/ARCHITECTURE.md`'s "Bypassing the Upgrader" section.
**Instead:** `PnetProtectedConnection` is a pure `RawConnection` decorator — `read()`/`write()` transparently encrypt/decrypt, nothing else changes. Multiselect runs exactly as it does today, just against a connection whose bytes happen to be PSK-encrypted underneath.

## Integration Points

### External Services

None — pnet and the gater are entirely local, in-process policy/crypto layers. No new external dependency beyond a crypto primitive for XSalsa20 (check whether `crypto/` already exposes a Salsa20/XSalsa20 provider alongside its existing AES-CTR (`crypto/aes_ctr/`) provider before adding a new one).

### Internal Boundaries

| Boundary | Communication | Notes |
|----------|---------------|-------|
| `DialerImpl` ↔ `ConnectionGater` | Direct synchronous virtual call (`interceptPeerDial`, `interceptAddrDial`) | Injected via constructor, following the existing `DialerImpl(multiselect, tmgr, cmgr, listener, scheduler)` pattern — add `gater` as a new constructor parameter. |
| `TcpListener` ↔ `ConnectionGater` | Direct synchronous virtual call (`interceptAccept`) inside `doAccept()`'s completion handler | Injected via constructor alongside existing `(context, upgrader, handler)` params. |
| `UpgraderSession` ↔ `ConnectionGater` | Direct synchronous virtual call (`interceptSecured`, `interceptUpgraded`) inside `onSecured()` | Injected via constructor alongside existing `(upgrader, raw/stream, handler)` params. |
| `network_injector.hpp` ↔ `Upgrader` binding | DI binding swap: `Upgrader` → `PnetUpgraderDecorator` wrapping `UpgraderImpl` when a PSK is configured, else `Upgrader` → `UpgraderImpl` directly | Mirrors the existing `useSecurityAdaptors<...>()`/`useTransportAdaptors<...>()` helper-function pattern — add a `usePrivateNetwork(psk)` helper analogous to `useKeyPair(...)`. |

## Sources

- go-libp2p `ConnectionGater` interface (5 methods, doc comments, call-site timing): [go-libp2p PR #881 "implement connection gating at the top level"](https://github.com/libp2p/go-libp2p/pull/881), [connmgr package docs](https://pkg.go.dev/github.com/libp2p/go-libp2p/core/connmgr), [go-libp2p-core PR #139 "add connection gating interfaces and types"](https://github.com/libp2p/go-libp2p-core/pull/139) — confidence MEDIUM (WebSearch-derived, cross-checked across 3 independent sources, no direct source fetch of current `gater.go` succeeded)
- go-libp2p `Upgrader`/pnet Protector field and wrap ordering: [go-libp2p-transport-upgrader](https://github.com/libp2p/go-libp2p-transport-upgrader), [upgrader.go](https://github.com/libp2p/go-libp2p-transport-upgrader/blob/master/upgrader.go), [go-conn-security-multistream](https://github.com/libp2p/go-conn-security-multistream) — confidence MEDIUM (WebSearch synthesis; direct fetch of current `p2p/net/upgrader/upgrader.go` returned struct fields and wrap order, cross-checked against the pnet spec below)
- libp2p pnet spec (handshake/encryption model, no distinct handshake protocol, double-encryption design): [libp2p/specs `pnet/Private-Networks-PSK-V1.md`](https://github.com/libp2p/specs/blob/master/pnet/Private-Networks-PSK-V1.md), [Kubuxu's pnet gist](https://gist.github.com/Kubuxu/b96b64be00ef949c8d486fe6e6bfc43e) — confidence MEDIUM-HIGH (spec document, cross-checked, consistent across sources)
- This codebase's actual call graph (HIGH confidence — direct source reads, not inferred): `src/network/impl/dialer_impl.cpp`, `src/transport/tcp/tcp_listener.cpp`, `src/transport/tcp/tcp_transport.cpp`, `src/transport/impl/upgrader_impl.cpp`, `src/transport/impl/upgrader_session.cpp`, `include/libp2p/connection/raw_connection.hpp`, `include/libp2p/transport/upgrader.hpp`, `include/libp2p/injector/network_injector.hpp`
- `.planning/PROJECT.md`, `.planning/codebase/ARCHITECTURE.md`, `.planning/codebase/STRUCTURE.md` (project context and existing architecture documentation)

---
*Architecture research for: libp2p Connection Gater + pnet integration*
*Researched: 2026-08-25*
