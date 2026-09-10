# External Integrations

**Analysis Date:** 2026-08-26

## APIs & External Services

This is a peer-to-peer networking library (C++ implementation of the [libp2p spec](https://github.com/libp2p/specs)), not an application with SaaS integrations. Its "external integrations" are network protocols spoken to arbitrary libp2p peers, plus build/CI infrastructure services.

**libp2p protocol stack (peer-to-peer, not a traditional API):**
- Transports: TCP - `src/transport/tcp/`
- Security/handshake protocols:
  - Plaintext 2.0 - `src/security/plaintext/`
  - SECIO - `src/security/secio/`
  - Noise - `src/security/noise/` (protobuf schema `src/security/noise/protobuf/noise.proto`)
  - TLS - `src/security/tls/`
- Stream multiplexers: MPlex (`src/muxer/mplex/`), Yamux (`src/muxer/yamux/`)
- Application-level protocols under `src/protocol/`:
  - Kademlia DHT - `src/protocol/kademlia/` (`src/protocol/kademlia/protobuf/kademlia.proto`)
  - Gossipsub (pubsub, WIP per README) - `src/protocol/gossip/` (`src/protocol/gossip/protobuf/rpc.proto`)
  - Identify - `src/protocol/identify/` (`src/protocol/identify/protobuf/identify.proto`)
  - AutoNAT - `src/protocol/autonat/` (`src/protocol/autonat/protobuf/autonat.proto`)
  - Hole punching - `src/protocol/holepunch/` (`src/protocol/holepunch/protobuf/holepunch.proto`)
  - Relay (circuit relay) - `src/protocol/relay/` (`src/protocol/relay/protobuf/relay.proto`)
  - Ping - `src/protocol/ping/`
  - Echo (example/test protocol) - `src/protocol/echo/`

## Data Storage

**Databases:**
- SQLite (embedded, no server) - `src/storage/sqlite.cpp`, via the `SQLiteModernCpp` Hunter package (Soramitsu fork of `sqlite_modern_cpp`, `cmake/dependencies.cmake`). Used for local peer/DHT persistence rather than any remote database service.

**File Storage:**
- Local filesystem only (via Boost.Filesystem, `cmake/dependencies.cmake` `Boost` component `filesystem`); no cloud/object storage integration.

**Caching:**
- No external cache service. In-process data structures (e.g. `tsl::htrie_map` trie via `tsl_hat_trie` package) serve as lookup caches, and a Hunter binary cache (build artifact cache, see below) is used at build time only.

## Authentication & Identity

**Auth Provider:**
- None (no user/account auth). Peer identity is cryptographic: each libp2p peer has a keypair (`src/crypto/`, supporting RSA, Ed25519, secp256k1, ECDSA providers) whose public key hash forms its PeerId (`include/libp2p/peer/`). Session-level authentication happens via the security/handshake protocols listed above (Noise, SECIO, TLS, Plaintext).

## Monitoring & Observability

**Error Tracking:**
- None (no Sentry/Bugsnag-style service). Errors are represented via `outcome`-based result types (`include/libp2p/outcome/`) and typed error enums (`src/*/error.cpp`).

**Logs:**
- `soralog` (Soramitsu logging library) - `include/libp2p/log/`, `src/log/`, package pinned in `cmake/dependencies.cmake`. YAML-configurable via `yaml-cpp`.

**Metrics:**
- Optional, compile-time gated: `option(METRICS_ENABLED "Enable libp2p metrics" OFF)` in `CMakeLists.txt`, adds `LIBP2P_METRICS_ENABLED` define; no specific metrics backend vendored in this repo (integration point for a consumer to hook in).

## CI/CD & Deployment

**Hosting:**
- None — this is a library submodule, not a deployed service.

**CI Pipeline:**
- GitHub Actions - `.github/workflows/ci.yml` (build/test), `.github/workflows/clang-tidy.yml` (static analysis, driven by `housekeeping/clang-tidy.sh`), `.github/workflows/coverage.yml` (coverage upload, driven by `housekeeping/codecov.sh`), `.github/workflows/stale.yml` (issue/PR staleness bot)
- Coverage reporting: Codecov - `codecov.yml` (ignores `test/`, PR comment layout `reach, diff, flags, files`, restricted to `master` branch comments)
- Build artifact caching: Hunter binary cache at `github.com/soramitsu/hunter-binary-cache`, authenticated via `GITHUB_HUNTER_USERNAME`/`GITHUB_HUNTER_TOKEN` (`cmake/Hunter/init.cmake`)

## Environment Configuration

**Required env vars:**
- `GITHUB_HUNTER_USERNAME`, `GITHUB_HUNTER_TOKEN` — optional; enable Hunter binary-cache download/upload during CMake configure (`cmake/Hunter/init.cmake`). Build works without them, just slower (compiles all dependencies locally).

**Secrets location:**
- None committed. No `.env`, credentials, or key files found in this submodule tree. Hunter cache credentials are supplied purely via environment variables at build time (see `docker-compose.yml`, which forwards them into the dev container).

## Webhooks & Callbacks

**Incoming:**
- None (library, not a service with HTTP endpoints).

**Outgoing:**
- None in application logic. All outbound network traffic is peer-to-peer libp2p protocol traffic (see APIs & External Services above), not webhook-style HTTP callbacks.

---

*Integration audit: 2026-08-26*
