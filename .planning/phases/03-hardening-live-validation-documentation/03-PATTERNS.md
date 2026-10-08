# Phase 3: Hardening, live validation & documentation - Pattern Map

**Mapped:** 2026-08-26
**Files analyzed:** 11 new files (2 tests + CMake wiring + 3 example dirs)
**Analogs found:** 11 / 11 (all have strong, directly-cited analogs; RESEARCH.md already performed full-repo reads)

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `test/acceptance/p2p/pnet/pnet_two_node_test.cpp` | test (acceptance) | request-response (TCP loopback, real hosts) | `test/acceptance/p2p/host/host_integration_test.cpp` | role-match (fixture style differs per D-02, but readiness-sync/teardown pattern is identical) |
| `test/acceptance/p2p/pnet/CMakeLists.txt` | config (CMake) | — | `test/acceptance/p2p/host/CMakeLists.txt` | exact |
| `test/acceptance/p2p/CMakeLists.txt` (modified: add_subdirectory) | config (CMake) | — | same file, existing `add_subdirectory(host)` line | exact |
| `test/libp2p/network/dialer_reentrancy_test.cpp` (or extend `dialer_test.cpp`) | test (unit) | event-driven (scheduler defer) | `test/libp2p/network/dialer_test.cpp` (existing, has `ConnectionGaterMock`) | exact |
| `test/libp2p/security/pnet/pnet_reentrancy_test.cpp` (or extend `pnet_protected_connection_test.cpp`) | test (unit) | event-driven (scheduler defer) | `test/libp2p/transport/upgrader_session_test.cpp` + `test/libp2p/security/pnet/pnet_upgrader_decorator_test.cpp` | exact |
| `test/libp2p/transport/upgrader_session_test.cpp` (extended, new `TEST_F` cases) | test (unit) | event-driven (scheduler defer) | itself (existing fixture: `ConnectionGaterMock` + `SchedulerImpl`/`ManualSchedulerBackend` + `pump()`) | exact |
| `example/05-private-network/CMakeLists.txt` + `.cpp` + `README.md` | config+entrypoint (example) | request-response (DI-built Host) | `example/01-echo/CMakeLists.txt` + `libp2p_echo_server.cpp` + `README.md` | exact |
| `example/07-connection-gater/CMakeLists.txt` + `.cpp` + `README.md` | config+entrypoint (example) | request-response (DI-built Host) | `example/01-echo/` (same as above) | exact |
| `example/06-private-network-gater/CMakeLists.txt` + `.cpp` + `README.md` | config+entrypoint (example) | request-response (DI-built Host, composed modules) | `example/01-echo/` (same as above) | exact |
| `example/CMakeLists.txt` (modified: 3 new `add_subdirectory`) | config (CMake) | — | same file, existing `add_subdirectory(0N-...)` lines | exact |
| `test/testutil/gmock_actions.hpp` (read-only reuse, not modified) | test utility | — | itself — already provides synchronous-completion `ACTION_P` helpers | n/a (reuse as-is) |

## Pattern Assignments

### `test/acceptance/p2p/pnet/pnet_two_node_test.cpp` (test, acceptance/request-response)

**Analog:** `test/acceptance/p2p/host/host_integration_test.cpp` (full file read in RESEARCH.md; fixture at lines 40-55, readiness-sync at 76-91, teardown at 48-51)

**Imports pattern** (lines 1-16):
```cpp
#include "libp2p/host/basic_host/basic_host.hpp"

#include <chrono>
#include <future>

#include <gtest/gtest.h>
#include "acceptance/p2p/host/peer/test_peer.hpp"
#include "acceptance/p2p/host/peer/tick_counter.hpp"
#include "testutil/ma_generator.hpp"
#include "testutil/prepare_loggers.hpp"

using namespace libp2p;
using std::chrono_literals::operator""s;
using std::chrono_literals::operator""ms;
```
For the new pnet test, swap `test_peer.hpp` for direct `<libp2p/injector/host_injector.hpp>` + `<libp2p/injector/network_injector.hpp>` (D-01/D-02: purpose-built fixture, injector-based per RESEARCH.md Pattern 2 recommendation), plus `<libp2p/security/pnet/psk.hpp>` if constructing `Psk` values directly.

**Readiness-sync pattern (promise/future), verbatim reusable** (lines 45-55, 76-91):
```cpp
using PeerPromise = std::promise<peer::PeerInfo>;
using PeerFuture = std::shared_future<peer::PeerInfo>;

void TearDown() override {
  peers.clear();
  peerinfo_futures.clear();
}
// ...
auto promise = std::make_shared<PeerPromise>();
peerinfo_futures.push_back(promise->get_future());
// ... peer->startServer(ma, std::move(promise));
for (auto &f : peerinfo_futures) {
  auto status = f.wait_for(future_timeout);
  ASSERT_EQ(status, std::future_status::ready);
}
```

**Core pattern — DI-based host construction** (from RESEARCH.md, verified against `include/libp2p/injector/network_injector.hpp`):
```cpp
auto injector = libp2p::injector::makeHostInjector(
    libp2p::injector::usePrivateNetwork(
        "/key/swarm/psk/1.0.0/\n/base16/000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f\n"));
auto host = injector.create<std::shared_ptr<libp2p::Host>>();
auto io_context = injector.create<std::shared_ptr<boost::asio::io_context>>();
```
Matched-PSK pair (2 nodes) asserts a stream opens; mismatched-PSK pair (2 fresh nodes, per RESEARCH.md Open Question #2 recommendation — do not reuse node A/B across positive/negative cases) asserts black-box failure/timeout, `EXPECT_OUTCOME_FALSE`-style, no specific `PnetError` assertion (D-03).

**Error handling / assertion pattern:** `ASSERT_EQ(status, std::future_status::ready)` for bounded-timeout waits (hang guard); `EXPECT_OUTCOME_FALSE`/manual outcome-error check on the connect/newStream callback result for the mismatched-PSK negative case.

---

### `test/acceptance/p2p/pnet/CMakeLists.txt` and `test/acceptance/p2p/CMakeLists.txt` (config)

**Analog:** `test/acceptance/p2p/host/CMakeLists.txt`, `cmake/functions.cmake` (`addtest()`, lines 8-26)

```cmake
addtest(pnet_two_node_test
    pnet_two_node_test.cpp
    )
target_link_libraries(pnet_two_node_test
    p2p_default_network
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
Register: add one line `add_subdirectory(pnet)` to `test/acceptance/p2p/CMakeLists.txt` next to the existing `add_subdirectory(host)`. `addtest()` already wires `GTest::main`/`GMock::main`, `add_test(...)`, and `test_bin` output dir — no new CMake option needed (D-04).

---

### `test/libp2p/network/dialer_reentrancy_test.cpp` (test, unit/event-driven) — gater-hook reentrancy

**Analog:** existing `test/libp2p/network/dialer_test.cpp` fixture (already has `ConnectionGaterMock` per 02-04-SUMMARY.md) + the guard-scaffolding pattern below (from `test/libp2p/transport/upgrader_session_test.cpp`, RESEARCH.md Pattern 3).

**Re-entry guard scaffolding** (concrete pattern to copy, from RESEARCH.md's verified extension of `upgrader_session_test.cpp`):
```cpp
struct ReentrancyGuard {
  bool inside = false;
  struct Scope {
    ReentrancyGuard &g;
    Scope(ReentrancyGuard &g) : g(g) { ASSERT_FALSE(g.inside); g.inside = true; }
    ~Scope() { g.inside = false; }
  };
};
```
Scope this per-call-site: `interceptPeerDial` rejection (`src/network/impl/dialer_impl.cpp:71-77`, defers via `scheduler_->schedule([cb, err]{ cb(err); })`), `interceptAddrDial` rejection (`dialer_impl.cpp:252-262`, `288-298` — both defer; the holepunch site at `367-370` does NOT defer and is excluded from D-05 scope per RESEARCH.md Open Question #1).

**Error handling / assertion pattern:** assert `guard.inside == false` at the moment the deferred callback fires (i.e., only after `pump()`/`backend->shift(...)` drains the scheduler), proving the callback never nests inside the production call stack that scheduled it.

---

### `test/libp2p/security/pnet/pnet_reentrancy_test.cpp` and extended `upgrader_session_test.cpp` (test, unit/event-driven) — pnet + UpgraderSession reentrancy

**Analog:** `test/libp2p/transport/upgrader_session_test.cpp` (fixture + `pump()` helper, `ConnectionGaterMock`, `SchedulerImpl`+`ManualSchedulerBackend`) and `test/libp2p/security/pnet/pnet_upgrader_decorator_test.cpp` (same scheduler-pump technique applied to pnet).

**Synchronous-completion mock action pattern** (`test/testutil/gmock_actions.hpp`, full file, lines 1-82 — reuse as-is, no modification needed):
```cpp
ACTION_P(UpgradeToSecureInbound, do_upgrade) {
  arg1(do_upgrade(arg0));
}
ACTION_P(UpgradeToSecureOutbound, do_upgrade) {
  arg2(do_upgrade(arg0));
}
ACTION_P(UpgradeToMuxed, do_upgrade) {
  arg1(do_upgrade(arg0));
}
```
These already invoke the completion callback synchronously/inline as part of `WillOnce(...)` — exactly D-06's "test double that completes synchronously" technique; no new action needed, reuse verbatim.

**Full test case template** (from RESEARCH.md, verified against real `UpgraderSession` production code at `src/transport/impl/upgrader_session.cpp:78-118`):
```cpp
TEST_F(UpgraderSessionTest, InterceptSecuredRejectionNeverReentersSynchronously) {
  ReentrancyGuard guard;
  auto secure = std::make_shared<SecureConnectionMock>();
  EXPECT_CALL(*upgrader, upgradeToSecureInbound(raw_base, _))
      .WillOnce(UpgradeToSecureInbound(
          [&](auto &&) { return outcome::success(std::shared_ptr<SecureConnection>(secure)); }));
  EXPECT_CALL(*secure, remotePeer()).WillOnce(Return(pid));
  EXPECT_CALL(*secure, remoteMultiaddr()).WillOnce(Return(ma));
  EXPECT_CALL(*secure, isInitiatorMock()).WillOnce(Return(false));
  EXPECT_CALL(*gater, interceptSecured(false, pid, ma))
      .WillOnce(Return(outcome::failure(ConnectionGaterError::REJECTED_SECURED)));

  bool handler_fired_reentrant = false;
  EXPECT_CALL(handler_cb, Call(_)).WillOnce(Invoke([&](auto &&) {
    handler_fired_reentrant = guard.inside;
  }));

  { ReentrancyGuard::Scope scope(guard);
    session->secureInbound(); }
  ASSERT_FALSE(handler_fired_reentrant) << "handler_ must not fire before scheduler defers it";
  pump();
}
```

**Scoping constraint (critical, from Pitfall 2):** apply the guard ONLY to the 5 hook rejection branches and all `PnetProtectedConnection` I/O completions (`interceptSecured` rejection `upgrader_session.cpp:78-95`, `interceptUpgraded` rejection `upgrader_session.cpp:101-116`, `PnetProtectedConnection` read/write completions via `deferReadCallback`/`deferWriteCallback`). Do NOT assert reentrancy-freedom on the `UpgraderSession` success chain (`interceptSecured` OK → `upgradeToMuxed` OK → `interceptUpgraded` OK → `handler_(r)`) — that path calls `handler_` synchronously by design and a universal guard assertion will spuriously fail there.

---

### `example/05-private-network/` (PSK-only, DOCS-01)

**Analog:** `example/01-echo/` — `CMakeLists.txt` (lines 1-22), `libp2p_echo_server.cpp` (full file, lines 1-160), `README.md`.

**CMakeLists.txt pattern** (lines 6-22 of `example/01-echo/CMakeLists.txt`):
```cmake
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

**main() structure pattern** (adapted from `libp2p_echo_server.cpp` lines 54-160 — logging setup, injector construction, `setProtocolHandler`, `io_context->post([...]{ host->listen(...); host->start(); })`, `io_context->run()`):
```cpp
#include <libp2p/injector/host_injector.hpp>
// ...
auto injector = libp2p::injector::makeHostInjector(
    libp2p::injector::usePrivateNetwork(
        "/key/swarm/psk/1.0.0/\n/base16/<64 hex chars>\n"));
auto host = injector.create<std::shared_ptr<libp2p::Host>>();
auto io_context = injector.create<std::shared_ptr<boost::asio::io_context>>();
```
Keep the same logging-system bootstrap (soralog `LoggingSystem`+`ConfiguratorFromYAML`, `libp2p_echo_server.cpp` lines 79-98), `setProtocolHandler`+echo protocol wiring (lines 122-131), and `io_context->post(...)` listen/start pattern (lines 134-150) for a runnable, demonstrable example.

**README.md pattern:** mirror `example/01-echo/README.md` structure (what it demonstrates, how to build/run, expected output) — must exist per D-09 (unlike the `04-dnstxt` outlier, which has no README and should not be copied as precedent).

---

### `example/07-connection-gater/` (gater-only, DOCS-02)

**Analog:** same as above (`example/01-echo/`), plus the gater DI call shape from `include/libp2p/injector/network_injector.hpp` / `test/libp2p/injector/host_injector_test.cpp`'s `CustomAdaptors` test style:
```cpp
struct MyGaterImpl : public libp2p::network::ConnectionGater { /* ... */ };
auto injector = libp2p::injector::makeHostInjector(
    libp2p::injector::useConnectionGater<MyGaterImpl>());
```
**Numbering note (Pitfall 4):** must be `07-connection-gater`, not `05-...` — `05` and `06` are locked verbatim by D-10/D-11 for the PSK-only and combined examples respectively; `07` is the only non-colliding slot.

---

### `example/06-private-network-gater/` (combined, DOCS-03)

**Analog:** same as `example/01-echo/`, composing both DI modules in one call (verified shape from `network_injector.hpp`):
```cpp
auto injector = libp2p::injector::makeHostInjector(
    libp2p::injector::usePrivateNetwork(swarm_key_text),
    libp2p::injector::useConnectionGater<MyGaterImpl>());
```
Scenario to demonstrate per D-11/D-12: a peer with a valid/matching PSK but denied by the custom gater — proves the two layers are complementary (PSK proves network membership, gater proves peer-level authorization), not redundant.

---

### `example/CMakeLists.txt` (modified)

**Analog:** existing file, current contents:
```cmake
add_subdirectory(01-echo)
add_subdirectory(02-kademlia)
add_subdirectory(03-gossip)
add_subdirectory(04-dnstxt)
```
Append:
```cmake
add_subdirectory(05-private-network)
add_subdirectory(07-connection-gater)
add_subdirectory(06-private-network-gater)
```

## Shared Patterns

### Scheduler-deferred completion (reentrancy prevention)
**Source:** `src/network/impl/dialer_impl.cpp`, `src/transport/impl/upgrader_session.cpp`, `src/security/pnet/pnet_protected_connection.cpp`
**Apply to:** both reentrancy test files
```cpp
scheduler_->schedule([self, err]{ self->handler_(err); });
```
Verified defer/no-defer call-site table (from RESEARCH.md, direct code read):

| Call site | File:line | Defers via `scheduler_->schedule`? |
|---|---|---|
| `interceptPeerDial` rejection | `dialer_impl.cpp:71-77` | Yes |
| `interceptAddrDial` rejection (relay dual-addr, non-relay) | `dialer_impl.cpp:252-262`, `288-298` | Yes |
| `interceptAddrDial` rejection (holepunch) | `dialer_impl.cpp:367-370` | No — loop-filter `continue`, out of D-05 scope (informational only) |
| `interceptAccept` rejection | `tcp_listener.cpp:179-193` | Already inside a deferred `async_accept` callback; no *additional* nested schedule |
| `interceptSecured` rejection | `upgrader_session.cpp:78-95` | Yes |
| `interceptUpgraded` rejection | `upgrader_session.cpp:101-116` | Yes |
| `UpgraderSession` success chain | `upgrader_session.cpp:98-118` | **No** — do not test for reentrancy-freedom here |
| `PnetProtectedConnection` read/write completions | `pnet_protected_connection.cpp` (`deferReadCallback`/`deferWriteCallback`) | Yes, unconditionally |

### Deterministic scheduler pumping in tests
**Source:** `test/libp2p/transport/upgrader_session_test.cpp`, `test/libp2p/security/pnet/pnet_upgrader_decorator_test.cpp`
**Apply to:** both reentrancy test files
```cpp
while (!scheduler_backend->empty()) { scheduler_backend->shift(1ms); }
```
Use `libp2p::basic::ManualSchedulerBackend` + `SchedulerImpl`, not a bespoke fake clock.

### DI injector composition for examples
**Source:** `include/libp2p/injector/network_injector.hpp`, `include/libp2p/injector/host_injector.hpp`
**Apply to:** all 3 new `example/` directories
```cpp
auto injector = libp2p::injector::makeHostInjector(
    libp2p::injector::usePrivateNetwork(swarm_key_text),   // optional
    libp2p::injector::useConnectionGater<MyGaterImpl>());  // optional
auto host = injector.create<std::shared_ptr<libp2p::Host>>();
```
`usePrivateNetwork` throws `PskValidationError` eagerly on malformed key text (PNET-05) — demonstrate the correct swarm-key text format in DOCS-01 so integrators don't hand-roll parsing.

### Promise/future readiness sync (no sleep-polling)
**Source:** `test/acceptance/p2p/host/host_integration_test.cpp` lines 45-55, 76-91
**Apply to:** `pnet_two_node_test.cpp`
Already excerpted above under that file's Pattern Assignment.

## No Analog Found

None — every file in scope has a direct, verified analog already read in full by RESEARCH.md.

## Metadata

**Analog search scope:** `test/acceptance/p2p/host/`, `test/libp2p/transport/`, `test/libp2p/security/pnet/`, `test/libp2p/network/`, `test/testutil/`, `example/01-echo/`, `example/04-dnstxt/`, `example/CMakeLists.txt`, `src/network/impl/dialer_impl.cpp`, `src/transport/impl/upgrader_session.cpp`, `src/security/pnet/pnet_protected_connection.cpp`, `include/libp2p/injector/`
**Files scanned:** ~30 (per RESEARCH.md Sources section; this pass re-verified `host_integration_test.cpp`, `gmock_actions.hpp`, `example/01-echo/CMakeLists.txt`, `example/01-echo/libp2p_echo_server.cpp`, and directory listings for `test/acceptance/p2p/host/`, `example/`, `test/libp2p/security/pnet/`)
**Pattern extraction date:** 2026-08-26
