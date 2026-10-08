<!-- GSD:project-start source:PROJECT.md -->

## Project

**cpp-libp2p Connection Gating & Private Networks**

This is GNUS/GeniusNetwork's fork of cpp-libp2p (C++17), the peer-to-peer networking library underlying "SuperGenius" networks. This project adds two access-control primitives the fork currently lacks — a **Connection Gater** (pluggable accept/reject hooks at each stage of the connection upgrade pipeline) and **Private Networks / pnet** (PSK-protected swarm isolation) — so GNUS can run permissioned, private SuperGenius networks where only nodes with the right credentials can join.

Originates from [GeniusVentures/libp2p#10](https://github.com/GeniusVentures/libp2p/issues/10).

**Core Value:** A node without the correct network credentials (matching PSK, or passing gater policy) must be unable to join or communicate on a private SuperGenius network — access control is enforced at the network layer, not left to the application layer.

### Constraints

- **Language standard**: C++17 — rules out borrowing patterns or code from upstream cpp-libp2p that assume C++20.
- **Dependency injection**: New bindings (gater, PSK config) must follow the existing Boost.DI adaptor pattern in `include/libp2p/injector/*.hpp` — no direct `new`/`make_shared` construction outside the DI graph.
- **Upgrade pipeline integration**: Gater hooks must integrate with the existing `RawConnection` → `SecureConnection` → `CapableConnection` progression through `Upgrader`/`UpgraderSession` — no bypassing it with parallel/manual negotiation logic.
- **Spec compliance**: The pnet/PSK implementation should follow the libp2p pnet spec even though go-libp2p interop isn't a near-term requirement, to preserve future compatibility.

<!-- GSD:project-end -->

<!-- GSD:stack-start source:codebase/STACK.md -->

## Technology Stack

## Languages

- C++17 - entire library (`src/`, `include/libp2p/`), enforced via `cmake/toolchain/cxx17.cmake` (`CMAKE_CXX_STANDARD 17`, `CMAKE_CXX_STANDARD_REQUIRED ON`, `CMAKE_CXX_EXTENSIONS OFF`)
- Protobuf IDL - wire message schemas compiled to C++ (`src/**/protobuf/*.proto`)
- Python - housekeeping tooling only, not part of the library (`housekeeping/filter_compile_commands.py`)
- Bash - CI/dev scripts (`housekeeping/clang-tidy.sh`, `housekeeping/codecov.sh`)

## Runtime

- Native compiled C++ library (static/shared), no language runtime/VM. Target compilers per `README.md`: GCC 7.4, Clang 6.0.1, AppleClang 11.0.
- [Hunter](https://hunter.sh) (CMake-based C++ package manager), bootstrapped in `cmake/Hunter/init.cmake` via `HunterGate` in `cmake/Hunter/HunterGate.cmake`
- Hunter source pinned to a Soramitsu fork: `https://github.com/soramitsu/soramitsu-hunter/archive/v0.23.257-soramitsu31.tar.gz` (SHA1-pinned) in `cmake/Hunter/init.cmake`
- Local override hook: `cmake/Hunter/config.cmake` (empty template for `hunter_config(...)` overrides)
- Optional binary cache: `https://github.com/soramitsu/hunter-binary-cache`, credentials via `GITHUB_HUNTER_USERNAME` / `GITHUB_HUNTER_TOKEN` env vars (`cmake/Hunter/init.cmake`, `docker-compose.yml`)
- Lockfile: none (Hunter pins exact versions/URLs per-package inside `cmake/dependencies.cmake`, no separate lockfile artifact)

## Frameworks

- CMake 3.12+ build system - `CMakeLists.txt` (root), with modular includes in `cmake/` (`libp2p_add_library.cmake`, `install.cmake`, `functions.cmake`, `san.cmake`)
- Boost.DI - dependency injection framework for wiring host/network components, package `Boost.DI` in `cmake/dependencies.cmake`, used throughout `include/libp2p/injector/` and `src/injector/`
- Boost.Asio (via Boost) - async I/O / event loop for all networking (TCP transport, DNS resolution), see `src/network/cares/cares.cpp`, `src/network/impl/dnsaddr_resolver_impl.cpp`, `src/transport/tcp/`
- GoogleTest / GoogleMock (GTest) - `hunter_add_package(GTest)` gated by `option(TESTING "Build tests" ON)` in `CMakeLists.txt`; test tree under `test/` (mirrors `src/` layout, plus `test/mock`, `test/testutil`, `test/acceptance`)
- CTest - test runner, invoked via `ctest` per `README.md`
- Coverage: `option(COVERAGE "Enable generation of coverage info" OFF)`, `cmake/coverage.cmake`, `cmake/3rdparty/CodeCoverage.cmake`, reported to Codecov (`codecov.yml`, `housekeeping/codecov.sh`, `.github/workflows/coverage.yml`)
- ccache - auto-detected and wired into compile/link rules if present (`CMakeLists.txt` top)
- clang-format - `option(CLANG_FORMAT "Enable clang-format target" ON)`, config in `.clang-format`, target defined in `cmake/clang-format.cmake`
- clang-tidy - `option(CLANG_TIDY "Enable clang-tidy checks during compilation" OFF)`, config in `cmake/clang-tidy.cmake`, driven by `housekeeping/clang-tidy.sh` and `.github/workflows/clang-tidy.yml`
- Sanitizers - `cmake/san.cmake` + `cmake/san/`, toggled via `ASAN`/`LSAN`/`MSAN`/`TSAN`/`UBSAN` CMake options, applied only to the libp2p target (not dependencies)
- Docker dev container - `docker-compose.yml`, image `soramitsu/kagome-dev:8`, mounts repo at `/app`

## Key Dependencies

- Boost (`random`, `filesystem`, `program_options` components, plus Asio) - core async networking and utilities, `cmake/dependencies.cmake`
- OpenSSL - cryptographic primitives backing `src/crypto/*_provider` (RSA, ECDSA, Ed25519, secp256k1, AES, ChaChaPoly, HMAC, SHA), `cmake/dependencies.cmake`
- Protobuf - wire-format serialization for protocol messages (`src/**/protobuf/*.proto` → generated C++), `cmake/dependencies.cmake`
- c-ares - async DNS resolution used by `src/network/cares/cares.cpp`, `src/network/impl/dnsaddr_resolver_impl.cpp`
- fmt - string formatting used throughout logging and error messages
- soralog - Soramitsu logging framework, integrated in `include/libp2p/log/` and `src/log/`
- yaml-cpp - YAML config parsing (used by soralog config and/or library config)
- Microsoft.GSL - Guidelines Support Library (span, not_null, etc.) utility types
- tsl_hat_trie (`tsl::htrie_map`) - trie data structure, likely for multiaddress/peer-id lookups (`https://github.com/masterjedy/hat-trie`)
- SQLiteModernCpp - C++ wrapper around SQLite, backing `src/storage/sqlite.cpp` (Soramitsu fork: `https://github.com/soramitsu/libp2p-sqlite-modern-cpp/tree/hunter`)
- Boost.DI (`https://github.com/masterjedy/di` Soramitsu-hosted fork) - dependency-injection container wiring the whole host/network stack, `include/libp2p/injector/`, `src/injector/`
- Threads (`find_package(Threads)`) - native pthread/Win32 threading support

## Configuration

- No `.env` files present in this submodule; configuration is entirely CMake-option and env-var driven
- Env vars: `GITHUB_HUNTER_USERNAME`, `GITHUB_HUNTER_TOKEN` (Hunter binary-cache auth, optional) — read in `cmake/Hunter/init.cmake`, passed through in `docker-compose.yml`
- Behavior toggles via CMake options in `CMakeLists.txt`: `TESTING`, `EXAMPLES`, `CLANG_FORMAT`, `CLANG_TIDY`, `COVERAGE`, `ASAN`/`LSAN`/`MSAN`/`TSAN`/`UBSAN`, `EXPOSE_MOCKS`, `METRICS_ENABLED` (adds `LIBP2P_METRICS_ENABLED` compile definition), `LOCAL_BUILD`
- Root `CMakeLists.txt` plus `cmake/` directory: `Hunter/` (package manager bootstrap + per-package overrides), `toolchain/cxx17.cmake` (language standard), `dependencies.cmake` (all third-party packages), `libp2p_add_library.cmake` / `functions.cmake` (internal library/test helper macros), `install.cmake` (install/export rules, `libp2pConfig.cmake.in`), `clang-format.cmake`, `clang-tidy.cmake`, `coverage.cmake`, `san.cmake`, `print.cmake`
- `LOCAL_BUILD` option triggers `cmake/localbuild.cmake` for local (non-CI) build tweaks

## Platform Requirements

- CMake ≥ 3.12, a C++17-capable compiler (GCC 7.4+/Clang 6.0.1+/AppleClang 11.0+), internet access for Hunter package downloads (or a warmed Hunter cache directory)
- Optional Docker workflow via `docker-compose.yml` (`soramitsu/kagome-dev:8` image)
- Consumed as a C++ library dependency (this repo is a git submodule of a parent project — `w:\gnus\GeniusNetwork`); no standalone deployment target of its own. `cmake/install.cmake` provides CMake package export (`libp2pConfig.cmake.in`) for downstream consumers.

<!-- GSD:stack-end -->

<!-- GSD:conventions-start source:CONVENTIONS.md -->

## Conventions

## Naming Patterns

- `snake_case.hpp` / `snake_case.cpp`, one primary class/interface per file.
- Interfaces live at `include/libp2p/<module>/<name>.hpp` (e.g. `include/libp2p/connection/stream.hpp`).
- Implementations live under `src/<module>/<subsystem>/<name>_impl.cpp` (e.g. `src/crypto/hmac_provider/hmac_provider_impl.cpp`), matched by a header of the same name under `include/libp2p/...`.
- Error definitions: `error.hpp` or `<module>_error.hpp` / `<module>_errors.hpp` per module (e.g. `include/libp2p/crypto/error.hpp`, `include/libp2p/peer/errors.hpp`).
- Test files: `<thing>_test.cpp` (e.g. `test/libp2p/crypto/hmac_test.cpp`).
- Mock files: `test/mock/libp2p/<module>/<name>_mock.hpp`, mirroring the `include/libp2p/<module>/` tree.
- `#ifndef LIBP2P_<PATH_COMPONENTS>_HPP` / `#define ...` / `#endif // LIBP2P_..._HPP` (not `#pragma once`). Guard name mirrors path, e.g. `LIBP2P_STREAM_MOCK_HPP`, `LIBP2P_CRYPTO_ERROR_HPP`.
- Root namespace `libp2p`, with nested namespaces per module matching directory structure: `libp2p::crypto`, `libp2p::connection`, `libp2p::crypto::hmac`, etc. Namespace closing braces are commented: `}  // namespace libp2p::connection`.
- `NamespaceIndentation: All` per `.clang-format` — code inside every namespace level is indented.
- `PascalCase` for classes, structs, enums (`YamuxedConnection`, `HmacProviderImpl`, `CryptoProviderError`).
- Interfaces are abstract base classes named without an `I` prefix (e.g. `Stream`, `Host`); concrete implementations suffixed `Impl` (`BasicHost`, `HmacProviderImpl`) or named for their mechanism (`YamuxedConnection`).
- Mock classes suffixed `Mock` (`StreamMock`, `NetworkMock`), implementing the real interface directly via GMock macros.
- Enum class error codes use `SCREAMING_SNAKE_CASE` values (`INVALID_KEY_TYPE`, `FAILED_INITIALIZE_CONTEXT`), starting at `= 1` (0 reserved for "no error").
- `camelCase` for methods and free functions (`calculateDigest`, `getPeerInfo`, `processHeader`).
- `snake_case` for locals and parameters.
- Private/protected member variables use a **trailing underscore**: `config_`, `connection_`, `scheduler_`, `logger_` — enforced consistently across `src/`.
- Constants use `kPascalCase` (e.g. `YamuxFrame::kInitialWindowSize`).

## Code Style

- Enforced via `.clang-format` (root), `BasedOnStyle: Google` with overrides: `NamespaceIndentation: All`, `PointerAlignment: Right` (`Type *var`), `AllowShortFunctionsOnASingleLine: Empty`, `AllowShortIfStatementsOnASingleLine: false`, `BinPackArguments/BinPackParameters: true`.
- 2-space indentation (Google style default), 80-column soft wrap typical of Google style.
- CMake option `CLANG_FORMAT` (default ON) wires a `clang-format` target — run it before committing.
- `.clang-tidy` (root) enables `clang-analyzer-*, readability-*, modernize-*, boost-*, bugprone-*, cppcoreguidelines-*, google-*, hicpp-*, performance-*` with many project-specific suppressions (see file for exact exclusion list, e.g. `-readability-magic-numbers`, `-hicpp-named-parameter`).
- `WarningsAsErrors` is limited to a small, high-value subset: `modernize-*`, `cppcoreguidelines-*`, `boost-*`, `google-build-using-namespace`, `readability-else-after-return`, `google-readability-todo`.
- `HeaderFilterRegex: 'libp2p/.*\.hpp'` — tidy only enforces on project headers, not third-party/generated code.
- CMake option `CLANG_TIDY` (default OFF) enables tidy-during-compile; test targets call `disable_clang_tidy(${target})` (`cmake/functions.cmake`) to exempt test binaries.

## Import Organization

## Error Handling

- Each module declares its own scoped `enum class <Module>Error { ... = 1, ... }` in an `error.hpp`/`errors.hpp` file (see `include/libp2p/crypto/error.hpp`, `include/libp2p/peer/errors.hpp`, `include/libp2p/security/error.hpp`).
- Errors registered with `OUTCOME_HPP_DECLARE_ERROR(libp2p::<ns>, <EnumType>)` at file scope, paired with `OUTCOME_CPP_DEFINE_CATEGORY_3` (or similar) in the corresponding `.cpp`.
- Enum values are commented with Doxygen `///<` trailing comments describing the failure.
- Functions returning fallible results use signature `outcome::result<T> doThing(...)`; callers check via `if (!result) { ... result.error() ... }` or via macros.
- Async/callback-based APIs use `outcome::result<T>` as the callback argument type (e.g. `Reader::ReadCallbackFunc = std::function<void(outcome::result<size_t>)>`).
- `assert()` is used for internal invariants that should never be false in correct code (e.g. `assert(scheduler_);` in `src/muxer/yamux/yamuxed_connection.cpp`), not for recoverable/expected errors.

## Logging

- Static logger created once per translation unit/class: `static auto logger = log::createLogger("YamuxConn");`, typically stored/exposed through a `log_()` accessor.
- Structured logging macros `SL_TRACE`, `SL_DEBUG` (and similarly `SL_INFO`/`SL_WARN`/`SL_ERROR` elsewhere) take the logger then a format string + args: `SL_TRACE(log_(), "read {} bytes from {}", n, remotePeer().value().toBase58());`
- Use `SL_TRACE` for high-frequency internal state tracing, `SL_DEBUG` for notable-but-non-error events (peer disconnects, malformed frames).

## Comments

## Function Design

## Module Design

<!-- GSD:conventions-end -->

<!-- GSD:architecture-start source:ARCHITECTURE.md -->

## Architecture

## System Overview

```text

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

- Every subsystem is defined as an abstract interface in `include/libp2p/<area>/*.hpp` with concrete implementation(s) in `src/<area>/**` (often under an `impl/` subfolder, e.g. `src/network/impl/`, `src/transport/impl/`).
- Object graph assembly happens exclusively through Boost.DI injectors (`include/libp2p/injector/*.hpp`); application code (see `example/`) builds a `Host` via `injector::makeHostInjector(...)` rather than `new`-ing implementations directly.
- Connections progress through explicit upgrade stages: `RawConnection` → `SecureConnection` → `CapableConnection` (muxed), each represented by its own interface in `include/libp2p/connection/`.
- Protocol negotiation (which security scheme, which muxer, which application protocol) is centralized in the multiselect/protocol_muxer component rather than duplicated per protocol.
- Asynchronous I/O is Boost.Asio based; most components take callbacks/handlers rather than blocking calls (see `Host::connect`, `Host::newStream` signatures in `include/libp2p/host/host.hpp`).

## Layers

- Purpose: single public entry point representing "this peer"; exposes connect/listen/newStream/protocol-handler API
- Location: `include/libp2p/host/`, `src/host/basic_host/`
- Contains: `Host` interface, `BasicHost` implementation, `DefaultHost` convenience wrapper (`src/host/default_host.cpp`)
- Depends on: Network, PeerRepository, event::Bus, Router
- Used by: application code (`example/`), higher-level protocol wiring in `include/libp2p/injector/*`
- Purpose: connection/stream lifecycle management: dialing, listening, tracking, routing
- Location: `include/libp2p/network/`, `src/network/impl/`, `src/network/cares/` (DNS resolution)
- Contains: `Network`, `Dialer`, `ListenerManager`, `ConnectionManager`, `Router`, `TransportManager`, `DnsaddrResolver`
- Depends on: Transport layer (via `TransportManager`), protocol_muxer for negotiation
- Used by: Host layer
- Purpose: multistream-select negotiation of security/muxer/application protocols on a connection or stream
- Location: `include/libp2p/protocol_muxer/`, `src/protocol_muxer/multiselect.cpp`
- Depends on: `basic::MessageReader/Writer` primitives (`src/basic/*`)
- Used by: Upgrader (for security/muxer negotiation), Host/protocols (for application protocol negotiation on new streams)
- Purpose: authenticate and encrypt a raw transport connection
- Location: `include/libp2p/security/`, `src/security/{noise,secio,tls,plaintext}/`
- Contains: pluggable `SecurityAdaptor` implementations, each producing a `SecureConnection`
- Depends on: `crypto/` (key types, primitives), `RawConnection`
- Used by: Upgrader during connection upgrade
- Purpose: multiplex many logical `Stream`s over one `SecureConnection`
- Location: `include/libp2p/muxer/`, `src/muxer/{yamux,mplex}/`
- Contains: `yamux` (primary, has its own frame/state machine: `yamuxed_connection.cpp`, `yamux_reading_state.cpp`) and `mplex` (legacy/simple)
- Depends on: `SecureConnection`
- Used by: Upgrader, produces `CapableConnection`
- Purpose: transport-specific connection establishment (raw byte streams)
- Location: `include/libp2p/transport/`, `src/transport/tcp/`, `src/transport/impl/`
- Contains: `TcpTransport`, `TcpConnection`, `TcpListener`, `Upgrader`/`UpgraderImpl`/`UpgraderSession`, `MultiaddressParser`
- Depends on: Boost.Asio, `multi::Multiaddress`
- Used by: Network layer (via `TransportManager`)
- Purpose: application-level libp2p protocols implemented on top of `Stream`
- Location: `include/libp2p/protocol/`, `src/protocol/{ping,identify,identify(push/delta),kademlia,gossip,relay,autonat,holepunch,echo,common}/`
- Depends on: Host (to register handlers / open streams), own protobuf-generated message types (`src/protocol/*/protobuf/`)
- Used by: application code, other protocols (e.g. identify informs peer repository; kademlia uses relay/holepunch for NAT traversal)

## Data Flow

### Outbound Connect + New Stream

### Inbound Connection Handling

- Per-peer connection state lives in `ConnectionManager` (`src/network/impl/connection_manager_impl.cpp`); per-peer addressing/key/protocol metadata lives in `PeerRepository` and its sub-repositories (`src/peer/address_repository.cpp`, `include/libp2p/peer/key_repository/`, `include/libp2p/peer/protocol_repository/`).
- Cross-cutting async coordination (timers, delayed callbacks) goes through `basic::Scheduler` (`src/basic/scheduler.cpp`), not raw `asio::steady_timer` usage scattered per-component.
- Cross-component notifications (e.g. new connection, new stream) are published on `event::Bus` (`include/libp2p/event/bus.hpp`) rather than direct callbacks between unrelated layers.

## Key Abstractions

- Purpose: represent a connection at each stage of the libp2p upgrade pipeline
- Examples: `include/libp2p/connection/raw_connection.hpp`, `include/libp2p/connection/secure_connection.hpp`, `include/libp2p/connection/capable_connection.hpp`
- Pattern: each stage is a distinct interface; `CapableConnection` is a `SecureConnection` that also supports opening/accepting `Stream`s (muxing)
- Purpose: bidirectional byte-stream abstraction used by all application protocols, independent of the underlying muxer
- Examples: `include/libp2p/connection/stream.hpp`, `include/libp2p/connection/stream_and_protocol.hpp`
- Pattern: protocols only depend on `Stream`, never on `yamux`/`mplex` concretely
- Purpose: pluggable strategy per layer, selected at runtime via multiselect protocol IDs
- Examples: `include/libp2p/transport/transport_adaptor.hpp`, `include/libp2p/security/security_adaptor.hpp` (implied by `src/security/*/*.cpp` adaptors), `include/libp2p/muxer/muxer_adaptor.hpp` (implied by `src/muxer/{yamux,mplex}`)
- Pattern: interface + registry (`TransportManager`) + DI binding of concrete adaptors in `injector/network_injector.hpp`
- Purpose: explicit, allocation-light error propagation instead of exceptions for expected failure paths
- Examples: used throughout interfaces, e.g. `Host::listen`, `Host::closeListener` return `outcome::result<void>` (`include/libp2p/host/host.hpp:202`)
- Pattern: `include/libp2p/outcome/outcome.hpp` wraps a Boost.Outcome-style result type; each subsystem defines its own error code enum (e.g. `src/peer/errors.cpp`, `src/security/error.cpp`, `src/crypto/error.cpp`, `src/connection/error_codes.cpp`)

## Entry Points

- Location: `include/libp2p/injector/host_injector.hpp` (`makeHostInjector`), `include/libp2p/injector/network_injector.hpp` (`makeNetworkInjector`)
- Triggers: application `main()` (see `example/01-echo/libp2p_echo_server.cpp`, `example/02-kademlia/`, `example/03-gossip/`)
- Responsibilities: builds the full DI graph (transports, security, muxers, repositories) and resolves a `std::shared_ptr<Host>`
- Location: `include/libp2p/injector/kademlia_injector.hpp`
- Triggers: applications needing DHT support add this injector alongside `makeHostInjector`
- Responsibilities: wires kademlia-specific config/impl on top of the base host graph
- Location: `include/libp2p/libp2p.hpp`
- Responsibilities: single include pulling in the public API surface for consumers

## Architectural Constraints

- **Threading:** Boost.Asio `io_context`-driven single- or multi-threaded event loop; components generally assume handlers run on the io_context's thread(s) unless explicitly synchronized. `basic::Scheduler` (`src/basic/scheduler.cpp`) centralizes timer-based callbacks.
- **Global state:** Logging is a shared global facility (`include/libp2p/log/`, `src/log/logger.cpp`, `src/log/configurator.cpp`) configured once at startup; no other module-level singletons identified in the layer interfaces reviewed.
- **DI-only construction:** Concrete implementations of interfaces (e.g. `BasicHost`, `NetworkImpl`, `DialerImpl`) are expected to be constructed via Boost.DI injectors, not directly `new`'d in application code — plan new features to add DI bindings in the relevant `injector/*.hpp` file.
- **Protocol negotiation coupling:** Any new security scheme or muxer must integrate with the multiselect protocol IDs in `src/protocol_muxer/multiselect.cpp` and be registered in `network_injector.hpp` to be selectable.

## Anti-Patterns

### Bypassing the Upgrader for connection setup

### Constructing subsystem implementations directly instead of via injector

## Error Handling

- Each subsystem defines its own error codes and a `.cpp` registering the error category (e.g. `src/peer/errors.cpp`, `src/security/error.cpp`, `src/crypto/error.cpp`, `src/connection/error_codes.cpp`, `src/protocol_muxer/protocol_muxer_error.cpp`, `src/protocol/kademlia/error.cpp`)
- Async operations report failures through the same `outcome::result<T>` type passed into completion handlers (e.g. `Host::ConnectionResult` in `include/libp2p/host/host.hpp:47`)

## Cross-Cutting Concerns

<!-- GSD:architecture-end -->

<!-- GSD:skills-start source:skills/ -->

## Project Skills

No project skills found. Add skills to any of: `.claude/skills/`, `.agents/skills/`, `.cursor/skills/`, `.github/skills/`, or `.codex/skills/` with a `SKILL.md` index file.
<!-- GSD:skills-end -->

<!-- GSD:workflow-start source:GSD defaults -->

## GSD Workflow Enforcement

Before using Edit, Write, or other file-changing tools, start work through a GSD command so planning artifacts and execution context stay in sync.

Use these entry points:

- `/gsd-quick` for small fixes, doc updates, and ad-hoc tasks
- `/gsd-debug` for investigation and bug fixing
- `/gsd-execute-phase` for planned phase work

Do not make direct repo edits outside a GSD workflow unless the user explicitly asks to bypass it.
<!-- GSD:workflow-end -->

<!-- GSD:profile-start -->

## Developer Profile

> Profile not yet configured. Run `/gsd-profile-user` to generate your developer profile.
> This section is managed by `generate-claude-profile` -- do not edit manually.
<!-- GSD:profile-end -->
