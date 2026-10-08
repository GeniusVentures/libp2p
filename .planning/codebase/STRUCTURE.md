# Codebase Structure

**Analysis Date:** 2026-08-26

## Directory Layout

```
libp2p/
├── include/libp2p/        # Public headers — interfaces + some header-only impls
│   ├── basic/              # Low-level I/O primitives (message read/writer, scheduler, buffers)
│   ├── common/              # Shared utilities (byteutil, hexutil, literals)
│   ├── connection/          # Connection/Stream interface hierarchy (Raw/Secure/Capable/Stream)
│   ├── crypto/               # Key types, crypto primitives, error codes
│   ├── event/                # Event bus (pub/sub between components)
│   ├── host/                 # Host interface + BasicHost/DefaultHost
│   ├── injector/              # Boost.DI graph builders (host/network/kademlia)
│   ├── log/                    # Logging facade + configurator
│   ├── multi/                  # multiaddr / multihash / CID / uvarint types
│   ├── muxer/                   # Stream-muxer interfaces (yamux, mplex live in src/)
│   ├── network/                  # Network/Dialer/ListenerManager/Router/ConnectionManager/TransportManager
│   ├── outcome/                   # outcome::result<T> error-handling wrapper
│   ├── peer/                       # PeerId/PeerInfo/PeerRepository + sub-repositories
│   ├── protocol/                    # Application protocol interfaces (ping, identify, kademlia, gossip, relay, autonat, holepunch)
│   ├── protocol_muxer/                # multistream-select negotiation interfaces
│   ├── routing/                        # Routing-table-related interfaces (used by kademlia)
│   ├── security/                        # Security adaptor interfaces (noise, secio, tls, plaintext)
│   ├── storage/                          # Storage interfaces (sqlite-backed)
│   ├── transport/                         # Transport interfaces + TCP headers
│   └── libp2p.hpp                          # Umbrella include for consumers
├── src/                    # Implementations, mirrors include/libp2p/ structure 1:1
│   ├── basic/
│   ├── common/
│   ├── connection/
│   ├── crypto/
│   ├── event/                # (interfaces only; no .cpp — event bus is header-only)
│   ├── host/
│   │   └── basic_host/        # BasicHost implementation
│   ├── log/
│   ├── multi/
│   ├── muxer/
│   │   ├── mplex/               # mplex muxer implementation
│   │   └── yamux/                # yamux muxer implementation (primary)
│   ├── network/
│   │   ├── cares/                 # c-ares based DNS resolver
│   │   └── impl/                   # concrete Network/Dialer/Listener/Connection/Router/TransportManager
│   ├── peer/
│   ├── protocol/
│   │   ├── autonat/                 # each protocol subdir may contain its own protobuf/ generated dir
│   │   ├── common/
│   │   ├── echo/
│   │   ├── gossip/impl/
│   │   ├── holepunch/
│   │   ├── identify/
│   │   ├── kademlia/impl/
│   │   ├── ping/
│   │   └── relay/
│   ├── protocol_muxer/                # multiselect implementation
│   ├── security/
│   │   ├── noise/crypto/               # noise-specific crypto helpers
│   │   ├── plaintext/
│   │   ├── secio/
│   │   └── tls/
│   ├── storage/                          # sqlite.cpp
│   ├── transport/
│   │   ├── impl/                          # Upgrader/UpgraderSession/MultiaddressParser
│   │   └── tcp/                            # TcpTransport/TcpConnection/TcpListener
│   └── libp2p.cpp                           # top-level translation unit
├── test/                   # GTest-based test suite
│   ├── acceptance/p2p/host/  # end-to-end / acceptance tests exercising Host
│   ├── libp2p/                # unit tests, mirrors src/ layout by subsystem
│   ├── mock/libp2p/             # GMock-generated mocks of interfaces, mirrors include/libp2p/
│   ├── testutil/                 # test helpers (async utilities, libp2p-specific helpers)
│   └── deps/                      # test-only third-party deps
├── example/                # Standalone example programs (each its own CMake target)
│   ├── 00-install/           # minimal "does it build/link" example
│   ├── 01-echo/                # echo protocol client/server (C++ and a Go interop peer)
│   ├── 02-kademlia/              # DHT example
│   ├── 03-gossip/                 # gossipsub example
│   └── 04-dnstxt/                   # DNS TXT resolution example
├── cmake/                  # CMake modules: Hunter package manager config, toolchains, sanitizers
│   ├── 3rdparty/
│   ├── Hunter/
│   ├── san/                  # sanitizer (ASAN/TSAN/UBSAN/etc) toggles
│   └── toolchain/              # cxx17 toolchain file
├── housekeeping/           # repo maintenance scripts (formatting/lint helpers)
├── CMakeLists.txt          # root build config, options: TESTING, EXAMPLES, ASAN/TSAN/etc, METRICS_ENABLED
└── docker-compose.yml      # containerized build/test environment
```

## Directory Purposes

**`include/libp2p/<area>/`:**
- Purpose: public API — abstract interfaces (structs with pure virtual methods) consumed by application code and other layers
- Contains: `*.hpp` interfaces; occasionally header-only implementations (e.g. `event/bus.hpp`)
- Key files: one interface header per concept, e.g. `include/libp2p/network/network.hpp`, `include/libp2p/connection/capable_connection.hpp`

**`src/<area>/`:**
- Purpose: concrete implementations of the matching `include/libp2p/<area>/` interfaces
- Contains: `.cpp` files, `CMakeLists.txt` per subsystem, and for protocols with wire formats, a generated `protobuf/` subdirectory
- Key files: implementations often under `impl/` (e.g. `src/network/impl/network_impl.cpp`) or a named backend subdir (e.g. `src/muxer/yamux/`, `src/security/noise/`)

**`src/protocol/<name>/protobuf/`:**
- Purpose: protobuf-generated (or hand-authored `.proto`) message types for wire-format protocols
- Contains: `.proto`/generated marshalling code for that protocol's messages (identify, kademlia, gossip, relay, holepunch, autonat)
- Generated: yes (proto compilation is part of the build)

**`test/mock/libp2p/<area>/`:**
- Purpose: GMock mock classes for each public interface, used by unit tests that isolate a single component
- Contains: `mock_*.hpp` per interface, mirrors `include/libp2p/<area>/` structure

**`test/libp2p/<area>/`:**
- Purpose: unit tests for the corresponding `src/<area>/` implementation
- Contains: `*_test.cpp` per implementation file/class

**`test/acceptance/p2p/host/`:**
- Purpose: higher-level, cross-layer tests exercising real `Host` instances (closer to integration/e2e)

**`example/`:**
- Purpose: minimal standalone programs demonstrating library usage patterns (DI setup, protocol usage); each subdir is a separate CMake target and a template for new consumers

**`cmake/`:**
- Purpose: build system plumbing — Hunter package manager bootstrap (`cmake/Hunter/`), sanitizer flags (`cmake/san/`), C++17 toolchain (`cmake/toolchain/cxx17.cmake`), third-party find modules (`cmake/3rdparty/`)

## Key File Locations

**Entry Points:**
- `include/libp2p/libp2p.hpp`: umbrella header for consumers
- `include/libp2p/injector/host_injector.hpp`: primary DI graph builder (`makeHostInjector`)
- `include/libp2p/injector/network_injector.hpp`: lower-level DI graph (transports/security/muxers) consumed by host_injector
- `include/libp2p/injector/kademlia_injector.hpp`: adds DHT support on top of host injector
- `src/libp2p.cpp`: top-level library translation unit

**Configuration:**
- `CMakeLists.txt` (root): build options (`TESTING`, `EXAMPLES`, `ASAN`/`TSAN`/`UBSAN`/`LSAN`/`MSAN`, `METRICS_ENABLED`, `EXPOSE_MOCKS`)
- `cmake/toolchain/cxx17.cmake`: compiler/standard configuration
- `cmake/Hunter/init.cmake`: Hunter package manager bootstrap (dependency resolution)
- `docker-compose.yml`: containerized dev/test environment

**Core Logic:**
- `src/host/basic_host/basic_host.cpp`: main `Host` implementation
- `src/network/impl/`: dialing, listening, connection tracking, routing
- `src/transport/impl/upgrader_impl.cpp`, `src/transport/impl/upgrader_session.cpp`: connection upgrade pipeline (raw → secure → capable)
- `src/protocol_muxer/multiselect.cpp`: multistream-select protocol negotiation
- `src/muxer/yamux/yamuxed_connection.cpp`: primary stream multiplexer

**Testing:**
- `test/libp2p/`: unit tests, one subdir per subsystem matching `src/`
- `test/mock/libp2p/`: GMock mocks matching `include/libp2p/`
- `test/acceptance/p2p/host/`: end-to-end tests
- `test/testutil/`: shared test helpers (async wait helpers, etc.)

## Naming Conventions

**Files:**
- Snake_case for filenames: `connection_manager_impl.cpp`, `yamuxed_connection.cpp`
- Interface header matches interface name: `include/libp2p/network/dialer.hpp` declares `struct Dialer`
- Implementation suffixed `_impl` or named after the concrete strategy: `dialer_impl.cpp` → `DialerImpl`; `yamux.cpp` → `Yamux`
- Error types live in `errors.cpp`/`error.cpp` per subsystem directory (e.g. `src/peer/errors.cpp`, `src/security/error.cpp`)

**Directories:**
- `include/libp2p/<area>/` and `src/<area>/` are always paired 1:1 by name
- Multi-backend layers (transport/security/muxer/protocol) use a subdirectory per concrete backend: `security/{noise,secio,tls,plaintext}`, `muxer/{yamux,mplex}`, `protocol/{ping,identify,kademlia,gossip,relay,autonat,holepunch,echo,common}`
- `impl/` subdirectory used when a layer has exactly one primary concrete implementation set rather than multiple pluggable backends (e.g. `network/impl/`, `transport/impl/`)

## Where to Add New Code

**New Application Protocol (e.g. a new libp2p protocol ID):**
- Interface: `include/libp2p/protocol/<new_protocol>/` (define the protocol's public API/session interfaces)
- Implementation: `src/protocol/<new_protocol>/` with its own `CMakeLists.txt`; add a `protobuf/` subfolder if it needs wire messages
- Register in: `src/protocol/CMakeLists.txt` (add subdirectory), and any relevant injector if it needs DI-managed dependencies
- Tests: `test/libp2p/protocol/<new_protocol>/`, mocks (if other code depends on the new interface) under `test/mock/libp2p/protocol/`

**New Transport (e.g. QUIC, WebSocket):**
- Interface conformance: implement `transport::TransportAdaptor` / `TransportListener` (`include/libp2p/transport/transport_adaptor.hpp`, `transport_listener.hpp`)
- Implementation: new `src/transport/<name>/` directory, following the `src/transport/tcp/` pattern
- Register in: `include/libp2p/injector/network_injector.hpp` (DI binding), `src/transport/CMakeLists.txt`

**New Security Adaptor:**
- Implementation: new `src/security/<name>/` directory, following `src/security/noise/` or `src/security/plaintext/` pattern
- Register in: `include/libp2p/injector/network_injector.hpp`, protocol ID recognized by `src/protocol_muxer/multiselect.cpp`

**New Muxer:**
- Implementation: new `src/muxer/<name>/` directory, following `src/muxer/yamux/` pattern
- Register in: `include/libp2p/injector/network_injector.hpp`

**Utilities:**
- Shared byte/hex/string helpers: `src/common/` and `include/libp2p/common/`
- Async/scheduling helpers: `include/libp2p/basic/`, `src/basic/scheduler.cpp`

## Special Directories

**`src/*/protobuf/` (e.g. `src/protocol/kademlia/protobuf/`):**
- Purpose: protobuf-generated message marshalling code for that protocol's wire format
- Generated: yes
- Committed: check per-directory `.gitignore`/CMake generation step before assuming; treat as generated build artifacts unless proven otherwise

**`test/mock/libp2p/`:**
- Purpose: GMock mocks of every public interface, gated by `EXPOSE_MOCKS` CMake option for use by downstream/child projects
- Generated: no (hand-written, mirrors interface headers)
- Committed: yes

**`test/deps/`:**
- Purpose: test-only third-party dependencies vendored or fetched for the test suite
- Committed: check contents before assuming vendored vs. fetched-at-configure-time

**`housekeeping/`:**
- Purpose: repository maintenance scripts (formatting, lint, CI helper scripts)

**`cmake/Hunter/`:**
- Purpose: Hunter C++ package manager bootstrap/config, resolves all third-party dependencies (Boost, GTest, GMock, protobuf, sqlite, etc.) at CMake configure time

---

*Structure analysis: 2026-08-26*
