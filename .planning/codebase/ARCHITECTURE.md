<!-- refreshed: 2026-08-26 -->
# Architecture

**Analysis Date:** 2026-08-26

## System Overview

```text
┌─────────────────────────────────────────────────────────────────────┐
│                              Host Layer                              │
│   `include/libp2p/host/host.hpp`  `src/host/basic_host/basic_host.cpp`│
│   Coordinates connect/listen/newStream, owns Network + PeerRepository │
└───────────────┬───────────────────────────┬───────────────────────────┘
                │                           │
                ▼                           ▼
┌────────────────────────────┐  ┌─────────────────────────────────────┐
│     Protocol Layer          │  │           Network Layer              │
│ `include/libp2p/protocol/*` │  │ `include/libp2p/network/network.hpp` │
│ ping, identify, kademlia,   │  │ Dialer, ListenerManager, Router,     │
│ gossip, relay, autonat,     │  │ ConnectionManager, TransportManager  │
│ holepunch                   │  │ `src/network/impl/*`                 │
└──────────────┬──────────────┘  └───────────────┬───────────────────────┘
                │  (uses Streams)                 │  (creates Connections)
                ▼                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       Protocol Muxer (multiselect)                   │
│      `src/protocol_muxer/multiselect.cpp` — negotiates security/     │
│      muxer/application protocol IDs over a raw connection            │
└───────────────┬───────────────────────────┬───────────────────────────┘
                │                           │
                ▼                           ▼
┌────────────────────────────┐  ┌─────────────────────────────────────┐
│      Muxer Layer            │  │          Security Layer              │
│ `include/libp2p/muxer/*`    │  │ `include/libp2p/security/*`          │
│ yamux, mplex — multiplex    │  │ noise, secio, tls, plaintext —       │
│ many `Stream`s over one     │  │ encrypt/authenticate a `RawConnection│
│ `SecureConnection`          │  │ ` into a `SecureConnection`          │
└──────────────┬──────────────┘  └───────────────┬───────────────────────┘
                │                                 │
                └────────────────┬────────────────┘
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                          Transport Layer                             │
│ `include/libp2p/transport/*`  `src/transport/tcp/*`                  │
│ TcpTransport / TcpConnection / TcpListener → `RawConnection`         │
│ `Upgrader` (`src/transport/impl/upgrader_impl.cpp`) drives raw →     │
│ secure → capable (muxed) connection upgrade                          │
└─────────────────────────────────────────────────────────────────────┘
```

## Component Responsibilities

| Component | Responsibility | File |
|-----------|----------------|------|
| Host | Public façade: connect, listen, newStream, protocol handler registration | `include/libp2p/host/host.hpp`, `src/host/basic_host/basic_host.cpp` |
| Network | Aggregates Dialer, ListenerManager, ConnectionManager, Router | `include/libp2p/network/network.hpp`, `src/network/impl/network_impl.cpp` |
| Dialer | Opens outbound connections/streams to peers | `include/libp2p/network/dialer.hpp`, `src/network/impl/dialer_impl.cpp` |
| ListenerManager | Owns transport listeners, accepts inbound connections | `include/libp2p/network/listener_manager.hpp`, `src/network/impl/listener_manager_impl.cpp` |
| ConnectionManager | Tracks live connections per peer, closes/prunes them | `include/libp2p/network/connection_manager.hpp`, `src/network/impl/connection_manager_impl.cpp` |
| Router | Maps protocol IDs to stream handlers | `include/libp2p/network/router.hpp`, `src/network/impl/router_impl.cpp` |
| TransportManager | Registry of available `TransportAdaptor`s (currently TCP) | `include/libp2p/network/transport_manager.hpp`, `src/network/impl/transport_manager_impl.cpp` |
| TransportAdaptor (TCP) | Creates `RawConnection`s / listens on multiaddresses | `include/libp2p/transport/tcp.hpp`, `src/transport/tcp/tcp_transport.cpp` |
| Upgrader | Drives raw→secure→muxed (capable) connection upgrade sequence | `include/libp2p/transport/upgrader.hpp`, `src/transport/impl/upgrader_impl.cpp`, `src/transport/impl/upgrader_session.cpp` |
| Multiselect (protocol muxer) | Negotiates security/muxer/protocol IDs via the multistream-select protocol | `include/libp2p/protocol_muxer/`, `src/protocol_muxer/multiselect.cpp` |
| Security adaptors (noise/secio/tls/plaintext) | Encrypt a `RawConnection` into a `SecureConnection` | `include/libp2p/security/*`, `src/security/{noise,secio,tls,plaintext}/*` |
| Muxer adaptors (yamux/mplex) | Multiplex many `Stream`s over a `SecureConnection` → `CapableConnection` | `include/libp2p/muxer/*`, `src/muxer/{yamux,mplex}/*` |
| Protocol implementations | Application-level protocols speaking over `Stream` | `include/libp2p/protocol/*`, `src/protocol/{ping,identify,kademlia,gossip,relay,autonat,holepunch,echo}/*` |
| PeerRepository | Address/key/protocol bookkeeping per `PeerId` | `include/libp2p/peer/peer_repository.hpp`, `src/peer/*` |
| Scheduler | Cooperative timer/task scheduling used across async components | `include/libp2p/basic/scheduler.hpp`, `src/basic/scheduler.cpp` |
| Injector (Boost.DI) | Wires interfaces to concrete implementations, builds the object graph | `include/libp2p/injector/{host_injector,network_injector,kademlia_injector}.hpp` |

## Pattern Overview

**Overall:** Layered protocol stack (transport → security → multiplexing → protocol) behind interface/implementation separation, wired together with compile-time dependency injection (Boost.DI). This mirrors the canonical libp2p architecture (transport-agnostic, pluggable security & muxing, protocol negotiation via multistream-select).

**Key Characteristics:**
- Every subsystem is defined as an abstract interface in `include/libp2p/<area>/*.hpp` with concrete implementation(s) in `src/<area>/**` (often under an `impl/` subfolder, e.g. `src/network/impl/`, `src/transport/impl/`).
- Object graph assembly happens exclusively through Boost.DI injectors (`include/libp2p/injector/*.hpp`); application code (see `example/`) builds a `Host` via `injector::makeHostInjector(...)` rather than `new`-ing implementations directly.
- Connections progress through explicit upgrade stages: `RawConnection` → `SecureConnection` → `CapableConnection` (muxed), each represented by its own interface in `include/libp2p/connection/`.
- Protocol negotiation (which security scheme, which muxer, which application protocol) is centralized in the multiselect/protocol_muxer component rather than duplicated per protocol.
- Asynchronous I/O is Boost.Asio based; most components take callbacks/handlers rather than blocking calls (see `Host::connect`, `Host::newStream` signatures in `include/libp2p/host/host.hpp`).

## Layers

**Host Layer:**
- Purpose: single public entry point representing "this peer"; exposes connect/listen/newStream/protocol-handler API
- Location: `include/libp2p/host/`, `src/host/basic_host/`
- Contains: `Host` interface, `BasicHost` implementation, `DefaultHost` convenience wrapper (`src/host/default_host.cpp`)
- Depends on: Network, PeerRepository, event::Bus, Router
- Used by: application code (`example/`), higher-level protocol wiring in `include/libp2p/injector/*`

**Network Layer:**
- Purpose: connection/stream lifecycle management: dialing, listening, tracking, routing
- Location: `include/libp2p/network/`, `src/network/impl/`, `src/network/cares/` (DNS resolution)
- Contains: `Network`, `Dialer`, `ListenerManager`, `ConnectionManager`, `Router`, `TransportManager`, `DnsaddrResolver`
- Depends on: Transport layer (via `TransportManager`), protocol_muxer for negotiation
- Used by: Host layer

**Protocol Muxer Layer:**
- Purpose: multistream-select negotiation of security/muxer/application protocols on a connection or stream
- Location: `include/libp2p/protocol_muxer/`, `src/protocol_muxer/multiselect.cpp`
- Depends on: `basic::MessageReader/Writer` primitives (`src/basic/*`)
- Used by: Upgrader (for security/muxer negotiation), Host/protocols (for application protocol negotiation on new streams)

**Security Layer:**
- Purpose: authenticate and encrypt a raw transport connection
- Location: `include/libp2p/security/`, `src/security/{noise,secio,tls,plaintext}/`
- Contains: pluggable `SecurityAdaptor` implementations, each producing a `SecureConnection`
- Depends on: `crypto/` (key types, primitives), `RawConnection`
- Used by: Upgrader during connection upgrade

**Muxer Layer:**
- Purpose: multiplex many logical `Stream`s over one `SecureConnection`
- Location: `include/libp2p/muxer/`, `src/muxer/{yamux,mplex}/`
- Contains: `yamux` (primary, has its own frame/state machine: `yamuxed_connection.cpp`, `yamux_reading_state.cpp`) and `mplex` (legacy/simple)
- Depends on: `SecureConnection`
- Used by: Upgrader, produces `CapableConnection`

**Transport Layer:**
- Purpose: transport-specific connection establishment (raw byte streams)
- Location: `include/libp2p/transport/`, `src/transport/tcp/`, `src/transport/impl/`
- Contains: `TcpTransport`, `TcpConnection`, `TcpListener`, `Upgrader`/`UpgraderImpl`/`UpgraderSession`, `MultiaddressParser`
- Depends on: Boost.Asio, `multi::Multiaddress`
- Used by: Network layer (via `TransportManager`)

**Protocol Layer:**
- Purpose: application-level libp2p protocols implemented on top of `Stream`
- Location: `include/libp2p/protocol/`, `src/protocol/{ping,identify,identify(push/delta),kademlia,gossip,relay,autonat,holepunch,echo,common}/`
- Depends on: Host (to register handlers / open streams), own protobuf-generated message types (`src/protocol/*/protobuf/`)
- Used by: application code, other protocols (e.g. identify informs peer repository; kademlia uses relay/holepunch for NAT traversal)

## Data Flow

### Outbound Connect + New Stream

1. Application calls `Host::connect(peerInfo, handler)` (`include/libp2p/host/host.hpp:144`)
2. `BasicHost` delegates to `Network::getDialer().dial(...)` (`src/host/basic_host/basic_host.cpp`, `src/network/impl/dialer_impl.cpp`)
3. `Dialer` selects a `TransportAdaptor` via `TransportManager` for the peer's multiaddress and opens a `RawConnection` (`src/network/impl/transport_manager_impl.cpp`, `src/transport/tcp/tcp_transport.cpp`)
4. `Upgrader`/`UpgraderSession` negotiates security (multiselect → noise/tls/secio/plaintext) then muxer (multiselect → yamux/mplex), producing a `CapableConnection` (`src/transport/impl/upgrader_session.cpp`)
5. `ConnectionManager` registers the new `CapableConnection` for the peer (`src/network/impl/connection_manager_impl.cpp`)
6. `Host::newStream(...)` opens a `Stream` on the muxed connection, negotiates the application protocol via multiselect, and invokes the caller's callback (`include/libp2p/host/host.hpp:181`)

### Inbound Connection Handling

1. `ListenerManager` owns one or more `TransportListener`s bound to configured multiaddresses (`src/network/impl/listener_manager_impl.cpp`, `src/transport/tcp/tcp_listener.cpp`)
2. On accept, the same Upgrader path as outbound runs in the server role (security responder, muxer acceptor)
3. Once muxed, inbound streams arrive and are dispatched by `Router` to the handler registered via `Host::setProtocolHandler` (`src/network/impl/router_impl.cpp`)

**State Management:**
- Per-peer connection state lives in `ConnectionManager` (`src/network/impl/connection_manager_impl.cpp`); per-peer addressing/key/protocol metadata lives in `PeerRepository` and its sub-repositories (`src/peer/address_repository.cpp`, `include/libp2p/peer/key_repository/`, `include/libp2p/peer/protocol_repository/`).
- Cross-cutting async coordination (timers, delayed callbacks) goes through `basic::Scheduler` (`src/basic/scheduler.cpp`), not raw `asio::steady_timer` usage scattered per-component.
- Cross-component notifications (e.g. new connection, new stream) are published on `event::Bus` (`include/libp2p/event/bus.hpp`) rather than direct callbacks between unrelated layers.

## Key Abstractions

**Connection progression interfaces:**
- Purpose: represent a connection at each stage of the libp2p upgrade pipeline
- Examples: `include/libp2p/connection/raw_connection.hpp`, `include/libp2p/connection/secure_connection.hpp`, `include/libp2p/connection/capable_connection.hpp`
- Pattern: each stage is a distinct interface; `CapableConnection` is a `SecureConnection` that also supports opening/accepting `Stream`s (muxing)

**Stream:**
- Purpose: bidirectional byte-stream abstraction used by all application protocols, independent of the underlying muxer
- Examples: `include/libp2p/connection/stream.hpp`, `include/libp2p/connection/stream_and_protocol.hpp`
- Pattern: protocols only depend on `Stream`, never on `yamux`/`mplex` concretely

**Adaptor pattern (Transport/Security/Muxer):**
- Purpose: pluggable strategy per layer, selected at runtime via multiselect protocol IDs
- Examples: `include/libp2p/transport/transport_adaptor.hpp`, `include/libp2p/security/security_adaptor.hpp` (implied by `src/security/*/*.cpp` adaptors), `include/libp2p/muxer/muxer_adaptor.hpp` (implied by `src/muxer/{yamux,mplex}`)
- Pattern: interface + registry (`TransportManager`) + DI binding of concrete adaptors in `injector/network_injector.hpp`

**outcome::result<T> for error handling:**
- Purpose: explicit, allocation-light error propagation instead of exceptions for expected failure paths
- Examples: used throughout interfaces, e.g. `Host::listen`, `Host::closeListener` return `outcome::result<void>` (`include/libp2p/host/host.hpp:202`)
- Pattern: `include/libp2p/outcome/outcome.hpp` wraps a Boost.Outcome-style result type; each subsystem defines its own error code enum (e.g. `src/peer/errors.cpp`, `src/security/error.cpp`, `src/crypto/error.cpp`, `src/connection/error_codes.cpp`)

## Entry Points

**Application `Host` construction:**
- Location: `include/libp2p/injector/host_injector.hpp` (`makeHostInjector`), `include/libp2p/injector/network_injector.hpp` (`makeNetworkInjector`)
- Triggers: application `main()` (see `example/01-echo/libp2p_echo_server.cpp`, `example/02-kademlia/`, `example/03-gossip/`)
- Responsibilities: builds the full DI graph (transports, security, muxers, repositories) and resolves a `std::shared_ptr<Host>`

**Kademlia DI entry point:**
- Location: `include/libp2p/injector/kademlia_injector.hpp`
- Triggers: applications needing DHT support add this injector alongside `makeHostInjector`
- Responsibilities: wires kademlia-specific config/impl on top of the base host graph

**Amalgamated umbrella header:**
- Location: `include/libp2p/libp2p.hpp`
- Responsibilities: single include pulling in the public API surface for consumers

## Architectural Constraints

- **Threading:** Boost.Asio `io_context`-driven single- or multi-threaded event loop; components generally assume handlers run on the io_context's thread(s) unless explicitly synchronized. `basic::Scheduler` (`src/basic/scheduler.cpp`) centralizes timer-based callbacks.
- **Global state:** Logging is a shared global facility (`include/libp2p/log/`, `src/log/logger.cpp`, `src/log/configurator.cpp`) configured once at startup; no other module-level singletons identified in the layer interfaces reviewed.
- **DI-only construction:** Concrete implementations of interfaces (e.g. `BasicHost`, `NetworkImpl`, `DialerImpl`) are expected to be constructed via Boost.DI injectors, not directly `new`'d in application code — plan new features to add DI bindings in the relevant `injector/*.hpp` file.
- **Protocol negotiation coupling:** Any new security scheme or muxer must integrate with the multiselect protocol IDs in `src/protocol_muxer/multiselect.cpp` and be registered in `network_injector.hpp` to be selectable.

## Anti-Patterns

### Bypassing the Upgrader for connection setup

**What happens:** Code that manually wires security/muxer negotiation instead of going through `Upgrader`/`UpgraderSession`.
**Why it's wrong:** Breaks the single negotiated path for security+muxer selection and duplicates multiselect logic, risking protocol-ID mismatches between client/server.
**Do this instead:** Route all connection upgrade through `transport::Upgrader` (`include/libp2p/transport/upgrader.hpp`, `src/transport/impl/upgrader_impl.cpp`).

### Constructing subsystem implementations directly instead of via injector

**What happens:** Instantiating e.g. `NetworkImpl` or `BasicHost` with `new`/`make_shared` outside the DI graph.
**Why it's wrong:** Misses required bound dependencies (transport managers, repositories, schedulers) that the injector wires automatically, and diverges from the pattern used throughout `example/`.
**Do this instead:** Extend `makeHostInjector`/`makeNetworkInjector` in `include/libp2p/injector/*.hpp` with `di::bind<...>` overrides.

## Error Handling

**Strategy:** `outcome::result<T>` (Boost.Outcome-based, `include/libp2p/outcome/outcome.hpp`) for all fallible interface methods; dedicated `error_code` enums per subsystem.

**Patterns:**
- Each subsystem defines its own error codes and a `.cpp` registering the error category (e.g. `src/peer/errors.cpp`, `src/security/error.cpp`, `src/crypto/error.cpp`, `src/connection/error_codes.cpp`, `src/protocol_muxer/protocol_muxer_error.cpp`, `src/protocol/kademlia/error.cpp`)
- Async operations report failures through the same `outcome::result<T>` type passed into completion handlers (e.g. `Host::ConnectionResult` in `include/libp2p/host/host.hpp:47`)

## Cross-Cutting Concerns

**Logging:** Centralized logger with runtime-configurable levels/groups, `include/libp2p/log/`, `src/log/logger.cpp`, `src/log/configurator.cpp`.
**Validation:** Protocol message validation happens in per-protocol message processors (e.g. `src/protocol/identify/identify_msg_processor.cpp`, `src/protocol/kademlia/message.cpp`) using protobuf-generated types under each protocol's `protobuf/` subfolder.
**Authentication:** Handled entirely by the Security layer during connection upgrade (`src/security/{noise,secio,tls,plaintext}/`); peer identity is a `crypto` public key derived `PeerId` (`src/peer/peer_id.cpp`, `include/libp2p/crypto/`).

---

*Architecture analysis: 2026-08-26*
