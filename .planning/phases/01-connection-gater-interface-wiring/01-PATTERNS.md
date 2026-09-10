# Phase 1: Connection Gater interface + wiring - Pattern Map

**Mapped:** 2026-08-26
**Files analyzed:** 13 (5 new + 8 modified)
**Analogs found:** 13 / 13

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|--------------------|------|-----------|-----------------|----------------|
| `include/libp2p/network/connection_gater.hpp` | interface (adaptor) | request-response | `include/libp2p/transport/transport_adaptor.hpp` | role-match (pluggable strategy interface) |
| `include/libp2p/network/connection_gater_error.hpp` | error enum | transform | `include/libp2p/peer/errors.hpp` | exact |
| `src/network/connection_gater_error.cpp` | error category impl | transform | `src/peer/errors.cpp` | exact |
| `include/libp2p/network/impl/permissive_connection_gater.hpp` | Null Object impl | request-response | `include/libp2p/transport/transport_adaptor.hpp` (default-impl pattern), conceptually like `security::Plaintext` as a default adaptor binding | role-match |
| `src/network/impl/permissive_connection_gater.cpp` | Null Object impl | request-response | (trivial, one-per-hook `outcome::success()`) — no direct analog needed | n/a |
| `src/network/CMakeLists.txt` (new leaf lib target) | config | n/a | `src/peer/CMakeLists.txt` / other leaf `libp2p_add_library` targets | role-match |
| `src/network/impl/dialer_impl.{hpp,cpp}` (modified) | controller/service | request-response, event-driven | itself (existing scheduler-deferred error pattern) | exact (self-analog) |
| `src/transport/tcp/tcp_listener.{hpp,cpp}` (modified) | controller/service | event-driven (accept loop) | `src/network/impl/dialer_impl.cpp` (for scheduler-defer pattern to borrow) | role-match |
| `src/transport/tcp/tcp_transport.{hpp,cpp}` (modified) | service (constructs sessions) | request-response | itself + `tcp_listener.cpp` (constructor wiring) | role-match |
| `src/transport/impl/upgrader_session.{hpp,cpp}` (modified) | service | request-response, event-driven | `src/network/impl/dialer_impl.cpp` (for scheduler-defer pattern) | role-match |
| `include/libp2p/injector/network_injector.hpp` (modified) | DI config | n/a | itself — `useSecurityAdaptors<...>()` / default `SecurityAdaptor` binding | exact (self-analog) |
| `test/mock/libp2p/network/connection_gater_mock.hpp` | test mock | n/a | `test/mock/libp2p/network/dialer_mock.hpp` | exact |
| `test/libp2p/network/dialer_test.cpp` (extended) + new `test/libp2p/transport/upgrader_session_test.cpp` | test | n/a | `test/libp2p/network/dialer_test.cpp` | exact |

## Pattern Assignments

### `include/libp2p/network/connection_gater.hpp` (interface, request-response)

**Analog:** `include/libp2p/transport/transport_adaptor.hpp` (lines 1-35)

**Imports pattern** (lines 1-21):
```cpp
#ifndef LIBP2P_TRANSPORT_ADAPTOR_HPP
#define LIBP2P_TRANSPORT_ADAPTOR_HPP

#include <chrono>
#include <functional>
#include <memory>
#include <system_error>

#include <libp2p/basic/adaptor.hpp>
#include <libp2p/connection/capable_connection.hpp>
#include <libp2p/event/emitter.hpp>
#include <libp2p/multi/multiaddress.hpp>
#include <libp2p/outcome/outcome.hpp>  // for outcome::result
#include <libp2p/peer/peer_id.hpp>
#include <libp2p/transport/transport_listener.hpp>
#include <libp2p/network/route_helper.hpp>

namespace libp2p::transport {
```
Apply the same include-ordering convention (`<...>` project headers, no relative
includes) for `connection_gater.hpp`: pull in `<libp2p/connection/capable_connection.hpp>`,
`<libp2p/multi/multiaddress.hpp>`, `<libp2p/outcome/outcome.hpp>`,
`<libp2p/peer/peer_id.hpp>`, plus `<memory>`. Root namespace should be `libp2p::network`
(per RESEARCH.md's leaf-library placement decision — do NOT put it under
`libp2p::transport` despite the closest analog living there).

**Core interface pattern** (transport_adaptor.hpp lines 29-45):
```cpp
class TransportAdaptor : public basic::Adaptor {
 public:
  using ConnectionCallback =
      void(outcome::result<std::shared_ptr<connection::CapableConnection>>);
  using HandlerFunc = std::function<ConnectionCallback>;

  ~TransportAdaptor() override = default;

  virtual void dial(const peer::PeerId &remoteId, multi::Multiaddress address,
                    HandlerFunc handler, ...) = 0;
```
`ConnectionGater` should follow the same "pure virtual interface with `virtual ~X()
= default;`" shape but return `outcome::result<void>` synchronously (no
`HandlerFunc`/callback — RESEARCH.md Pattern/Alternatives explicitly recommends
synchronous hooks, unlike `TransportAdaptor`'s async `dial`). Use `struct ... { virtual
~ConnectionGater() = default; ... };` exactly as RESEARCH.md's proposed interface shows
(this is the locked/recommended shape — use it verbatim as your starting point, not
`transport_adaptor.hpp`'s async signature).

**Guard/namespace convention:** `#ifndef LIBP2P_NETWORK_CONNECTION_GATER_HPP` /
`#define ...` / `#endif  // LIBP2P_NETWORK_CONNECTION_GATER_HPP`, namespace closing
comment `}  // namespace libp2p::network`.

---

### `include/libp2p/network/connection_gater_error.hpp` + `src/network/connection_gater_error.cpp` (error enum, transform)

**Analog:** `include/libp2p/peer/errors.hpp` + `src/peer/errors.cpp` (full files, both ≤20 lines)

**Header pattern** (`peer/errors.hpp` lines 1-19, copy verbatim structure):
```cpp
#ifndef LIBP2P_PEER_ERRORS_HPP
#define LIBP2P_PEER_ERRORS_HPP

#include <libp2p/outcome/outcome.hpp>

namespace libp2p::peer {

  enum class PeerError { SUCCESS = 0, NOT_FOUND };

}

OUTCOME_HPP_DECLARE_ERROR(libp2p::peer, PeerError)

#endif  // LIBP2P_PEER_ERRORS_HPP
```
For `ConnectionGaterError`, follow this exact shape but in `libp2p::network` and with
the 5 `GATER_REJECTED_*` values (D-02/D-03), starting at `= 1` per this codebase's
convention (see `include/libp2p/crypto/error.hpp`-style enums, not `peer::PeerError`'s
`= 0` start — CLAUDE.md: "Enum class error codes ... starting at `= 1` (0 reserved for
'no error')"). `OUTCOME_HPP_DECLARE_ERROR(libp2p::network, ConnectionGaterError)` at
file scope below the enum, same as `peer/errors.hpp` line 17.

**Category impl pattern** (`peer/errors.cpp` lines 1-19, copy verbatim structure):
```cpp
#include <libp2p/peer/errors.hpp>

OUTCOME_CPP_DEFINE_CATEGORY(libp2p::peer, PeerError, e) {
  using libp2p::peer::PeerError;

  switch (e) {
    case PeerError::SUCCESS:
      return "success";
    case PeerError::NOT_FOUND:
      return "not found";
  }

  return "unknown";
}
```
For `ConnectionGaterError`, mirror this switch-per-enum-value structure. D-03 requires
"gater" legible in the message text itself — use strings like `"ConnectionGater:
rejected at interceptPeerDial"` per RESEARCH.md's proposed category impl (Code Examples
section), not bare `"rejected"`.

---

### `include/libp2p/network/impl/permissive_connection_gater.hpp` (Null Object, request-response)

**Analog:** RESEARCH.md's proposed Pattern 1 (verbatim-usable) — no simpler existing
codebase analog because this is the first Null Object default-adaptor of this shape;
closest structural precedent is how `security::Plaintext`/`transport::TcpTransport` are
concrete default implementations always instantiated by the DI graph (see
`network_injector.hpp` line 296/299 below), just without the array-binding.

**Core pattern** (all 5 hooks return `outcome::success()` unconditionally):
```cpp
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
Follow this codebase's usual header/impl split convention (`.hpp` declares class,
`.cpp` defines methods out-of-line) if the methods grow non-trivial; given they're
one-liners, an all-inline header (as shown) is acceptable and matches how small
Null-Object-style classes are typically kept header-only elsewhere in this codebase.

---

### `src/network/impl/dialer_impl.{hpp,cpp}` (modified) — controller/service, request-response + event-driven

**Analog:** itself — `src/network/impl/dialer_impl.cpp` already has the exact
scheduler-deferred-callback pattern needed for gater rejections.

**Constructor/member pattern** (`dialer_impl.hpp` lines 28-32, 104-109 — already has
`scheduler_`, no new dependency needed beyond `gater_`):
```cpp
DialerImpl(std::shared_ptr<protocol_muxer::ProtocolMuxer> multiselect,
           std::shared_ptr<TransportManager> tmgr,
           std::shared_ptr<ConnectionManager> cmgr,
           std::shared_ptr<ListenerManager> listener,
           std::shared_ptr<basic::Scheduler> scheduler);
...
std::shared_ptr<basic::Scheduler> scheduler_;
log::Logger log_;
```
Add `std::shared_ptr<network::ConnectionGater> gater_;` alongside `scheduler_`
(constructor param + member + `BOOST_ASSERT(gater_ != nullptr);` in the constructor
body, matching the existing assert block at `dialer_impl.cpp` lines 467-472).

**Scheduler-deferred rejection pattern** (`dialer_impl.cpp` lines 20-26, the exact
pattern to replicate for `interceptPeerDial`/`interceptAddrDial` rejections):
```cpp
if (p.id.toBase58().size() == 0)
{
    scheduler_->schedule(
        [cb{ std::move(cb) }] { cb(std::errc::destination_address_required); });
    SL_ERROR(log_, "Dialing contains no peer ID to dial");
    return;
}
```
For the gater call at top of `dial()` (interceptPeerDial) and inside `rotate()`/
`rotateHolepunch()` before `tr->dial(...)` (interceptAddrDial):
```cpp
if (auto gated = gater_->interceptPeerDial(p.id); !gated) {
  SL_DEBUG(log_, "gater rejected peer dial to {}: {}", p.id.toBase58(),
           gated.error().message());
  scheduler_->schedule(
      [cb{std::move(cb)}, err{gated.error()}] { cb(err); });
  return;
}
```
**Logging convention to reuse** (`dialer_impl.cpp` line 27, `SL_TRACE`; use `SL_DEBUG`
per D-06 for rejections specifically, not `SL_TRACE`/`SL_ERROR`):
```cpp
SL_TRACE(log_, "Dialing to {} from IPv4:{} IPv6:{} they have {} addresses", ...);
```

**Two dial loops requiring separate wiring** (`dialer_impl.cpp`):
- `rotate()` — lines 97-225, the primary per-address loop; add `interceptAddrDial`
  before both `tr->dial(...)` call sites (relay branch line ~187, non-relay branch line
  ~214).
- `rotateHolepunch()` — lines 227-288, a **second, independent** per-address loop with
  its own `tr->dial(...)` call at line 281. RESEARCH.md Pitfall 3 flags this as an
  easy-to-miss bypass — planner must explicitly decide whether to wire `interceptAddrDial`
  here too or document the gap.

---

### `src/transport/tcp/tcp_listener.{hpp,cpp}` (modified) — controller, event-driven (accept loop)

**Analog:** `src/transport/tcp/tcp_listener.cpp` itself (accept-loop structure) +
`dialer_impl.cpp` (for the scheduler-defer idiom this class currently lacks).

**Current constructor** (`tcp_listener.hpp` lines 25-27, needs new params):
```cpp
TcpListener(boost::asio::io_context &context,
            std::shared_ptr<Upgrader> upgrader,
            TransportListener::HandlerFunc handler);
```
Add `std::shared_ptr<network::ConnectionGater> gater` and
`std::shared_ptr<basic::Scheduler> scheduler` params (Pitfall 2: this class has
**zero** `Scheduler` today — a genuinely new dependency, not just a call added inline).
Corresponding new members: `gater_`, `scheduler_` (trailing-underscore convention,
matching existing `upgrader_`, `handle_`).

**doAccept() insertion point** (`tcp_listener.cpp` lines 139-163 — exact code to
modify):
```cpp
acceptor_.async_accept(
    [self{this->shared_from_this()}](const boost::system::error_code &ec,
                                     ip::tcp::socket sock) {
      if (ec) {
        return self->handle_(ec);
      }

      boost::system::error_code nodelay_ec;
      sock.set_option(boost::asio::ip::tcp::no_delay(true), nodelay_ec);
      ...
      auto conn =
          std::make_shared<TcpConnection>(self->context_, std::move(sock));

      auto session = std::make_shared<UpgraderSession>(
          self->upgrader_, std::move(conn), self->handle_);

      session->secureInbound();

      self->doAccept();
    });
```
Insert `interceptAccept(conn->localMultiaddr().value(), conn->remoteMultiaddr().value())`
**after** `TcpConnection` is constructed (so `Don't Hand-Roll` table's
`localMultiaddr()`/`remoteMultiaddr()` accessors are usable — do NOT parse the raw
`ip::tcp::socket` endpoint directly) but **before** `UpgraderSession` is constructed. On
rejection, call `conn->close()` (Pitfall 5 — never a raw `sock.close()`), log via
`SL_DEBUG` with the logger already created via `log::createLogger("TcpListener")`
pattern seen at lines 65-67/150/167, then continue the accept loop (`self->doAccept()`)
without constructing `UpgraderSession`. Consider deferring the `conn->close()` through
`scheduler_->schedule(...)` per RESEARCH.md Open Question 2's recommendation (cheap
reentrancy-safety insurance inside an asio completion handler).

**Existing logger-creation idiom to reuse** (`tcp_listener.cpp` line 150, 167):
```cpp
log::createLogger("TcpListener")->warn("Failed to set TCP_NODELAY: {}", nodelay_ec.message());
```
Prefer a static per-class logger (`log::createLogger("TcpListener")` stored once, not
re-created per call) if adding a `log_` member — matches this codebase's documented
static-logger convention (CLAUDE.md Logging section) more closely than the current
ad-hoc `log::createLogger(...)` calls scattered inline in this file.

---

### `src/transport/tcp/tcp_transport.{hpp,cpp}` (modified) — service, request-response

**Analog:** itself; must thread the new `gater_`/`scheduler_` to `TcpListener`'s
constructor and to all `UpgraderSession` construction sites it owns (2 in `dial()`
overloads, 1 in `upgradeRelaySecure()`, per RESEARCH.md's Architecture summary). No
direct code excerpt was read this session (file not opened — 4-5 analog cap reached
via `dialer_impl.cpp`/`tcp_listener.cpp`/`upgrader_session.cpp`); planner should read
`src/transport/tcp/tcp_transport.cpp` directly during planning to enumerate the exact
line numbers of all `UpgraderSession(...)`/`TcpListener(...)` construction calls before
writing the plan's action list.

---

### `src/transport/impl/upgrader_session.{hpp,cpp}` (modified) — service, request-response + event-driven

**Analog:** `src/network/impl/dialer_impl.cpp` (for the scheduler-defer idiom this
class also lacks — Pitfall 2).

**Current constructor/state** (`upgrader_session.hpp` lines 26-46, no `Scheduler`
today):
```cpp
UpgraderSession(std::shared_ptr<transport::Upgrader> upgrader,
                std::shared_ptr<connection::RawConnection> raw,
                HandlerFunc handler);
...
 private:
  std::shared_ptr<transport::Upgrader> upgrader_;
  std::shared_ptr<connection::RawConnection> raw_;
  std::shared_ptr<connection::Stream> stream_;
  HandlerFunc handler_;

  void onSecured(
      outcome::result<std::shared_ptr<connection::SecureConnection>> rsecure);
```
Add `std::shared_ptr<network::ConnectionGater> gater_` and
`std::shared_ptr<basic::Scheduler> scheduler_` members, threaded through both
constructors (raw-connection overload and stream/relay overload).

**`onSecured()` insertion point** (`upgrader_session.cpp` lines 56-66 — exact code to
modify, this is where BOTH `interceptSecured` and `interceptUpgraded` must be added):
```cpp
void UpgraderSession::onSecured(
    outcome::result<std::shared_ptr<connection::SecureConnection>> rsecure) {
  if (!rsecure) {
    return handler_(rsecure.error());
  }

  upgrader_->upgradeToMuxed(rsecure.value(),
                            [self{shared_from_this()}](auto &&r) {
                              self->handler_(std::forward<decltype(r)>(r));
                            });
}
```
`interceptSecured(is_initiator, remote_peer, remote_addr)` goes right after the
`!rsecure` early-return, before calling `upgradeToMuxed`; on rejection, call
`rsecure.value()->close()` (guarded, per GATE-05) and deliver `handler_(gater_error)`
via `scheduler_->schedule(...)` (Pattern 2 — this fires an *external caller's*
`handler_`, so deferral is mandatory per RESEARCH.md, unlike `TcpListener`'s accept-loop
close). `interceptUpgraded(conn)` goes inside the `upgradeToMuxed` completion lambda,
after a successful `r` but before invoking `self->handler_(std::forward<decltype(r)>(r))`
— same close-then-scheduler-deferred-handler pattern on rejection. Because
`secureOutboundRelay`/`secureInboundRelay` (lines 35-40, 49-54) also funnel through this
same private `onSecured()`, gating here automatically covers relay paths too — no
special-casing needed (confirmed by RESEARCH.md).

**`is_initiator` derivation:** `secureOutbound`/`secureOutboundRelay` vs.
`secureInbound`/`secureInboundRelay` are the 4 distinct public entry points (lines 27,
35, 42, 49) — plumb a bool captured at each entry point through to `onSecured()` (e.g.
a new private member set at the start of each `secureX()` method) to supply
`interceptSecured`'s `is_initiator` parameter.

---

### `include/libp2p/injector/network_injector.hpp` (modified) — DI config

**Analog:** itself — `useSecurityAdaptors<...>()` helper (lines 200-204) and the
default-adaptor binding block (lines 294-299).

**Override-helper pattern to replicate exactly** (lines 200-204):
```cpp
template <typename... SecImpl>
inline auto useSecurityAdaptors() {
  return boost::di::bind<security::SecurityAdaptor *[]>()  // NOLINT
      .TEMPLATE_TO<SecImpl...>()[boost::di::override];
}
```
For the gater (single-implementation override, not an array like security adaptors —
`ConnectionGater` has exactly one active implementation at a time, matching D-05's
"single DI rebind"):
```cpp
template <typename GaterImpl>
inline auto useConnectionGater() {
  return boost::di::bind<network::ConnectionGater>()
      .template to<GaterImpl>()[boost::di::override];
}
```

**Default-binding insertion point** (inside `makeNetworkInjector()`'s
`di::make_injector<InjectorConfig>(...)` list, lines 283-291 block — add alongside the
other "internal" bindings, before the "default adaptors" comment at line 294):
```cpp
di::bind<network::Dialer>().TEMPLATE_TO<network::DialerImpl>(),
di::bind<network::Network>().TEMPLATE_TO<network::NetworkImpl>(),
```
Add: `di::bind<network::ConnectionGater>().TEMPLATE_TO<network::PermissiveConnectionGater>(),`
in this same "internal" section (always-bound default per D-04, unconditional — no
`if`/optional binding).

**Doxygen usage-example convention** (lines 92-95 file-level comment block) — add a
`useConnectionGater<MyCustomGater>()` line to the existing multi-line `@code` example
block at the top of the file, alongside `useMuxerAdaptors<...>()`/
`useSecurityAdaptors<...>()`, so integrators discover it the same way.

---

### `test/mock/libp2p/network/connection_gater_mock.hpp` (new) — test mock

**Analog:** `test/mock/libp2p/network/dialer_mock.hpp` (full file, 52 lines)

**Full structural pattern to copy:**
```cpp
#ifndef LIBP2P_DIALER_MOCK_HPP
#define LIBP2P_DIALER_MOCK_HPP

#include <libp2p/network/dialer.hpp>
#include <libp2p/network/route_helper.hpp>

#include <gmock/gmock.h>

namespace libp2p::network {

  struct DialerMock : public Dialer {
    ~DialerMock() override = default;

    MOCK_METHOD2(dial, void(const peer::PeerInfo &, DialResultFunc));
    ...
  };

}  // namespace libp2p::network

#endif  // LIBP2P_DIALER_MOCK_HPP
```
For `ConnectionGaterMock`: `#include <libp2p/network/connection_gater.hpp>` +
`<gmock/gmock.h>`, `struct ConnectionGaterMock : public ConnectionGater`, one
`MOCK_METHOD1`/`MOCK_METHOD2`/`MOCK_METHOD3` per hook matching each hook's real arity
(`interceptPeerDial`: 1 arg, `interceptAddrDial`: 2 args, `interceptAccept`: 2 args,
`interceptSecured`: 3 args, `interceptUpgraded`: 1 arg), each returning
`outcome::result<void>`. Guard `LIBP2P_CONNECTION_GATER_MOCK_HPP`.

---

### Test files (TEST-01) — `test/libp2p/network/dialer_test.cpp` (extend) + new `upgrader_session_test.cpp`

**Analog:** `test/libp2p/network/dialer_test.cpp` (fixture setup, lines 1-70 read)

**Include/fixture pattern to replicate:**
```cpp
#include "libp2p/network/impl/dialer_impl.hpp"

#include <gtest/gtest.h>
#include <libp2p/basic/scheduler/manual_scheduler_backend.hpp>
#include <libp2p/basic/scheduler/scheduler_impl.hpp>
#include <libp2p/common/literals.hpp>
#include "mock/libp2p/connection/capable_connection_mock.hpp"
#include "mock/libp2p/connection/stream_mock.hpp"
#include "mock/libp2p/network/connection_manager_mock.hpp"
#include "mock/libp2p/network/listener_mock.hpp"
#include "mock/libp2p/network/router_mock.hpp"
#include "mock/libp2p/network/transport_manager_mock.hpp"
#include "mock/libp2p/peer/address_repository_mock.hpp"
#include "mock/libp2p/protocol_muxer/protocol_muxer_mock.hpp"
#include "mock/libp2p/transport/transport_mock.hpp"
#include "testutil/gmock_actions.hpp"
#include "testutil/outcome.hpp"
#include "testutil/prepare_loggers.hpp"

using namespace libp2p;
using namespace network;
...
using ::testing::_;
using ::testing::InvokeArgument;
using ::testing::Return;

struct DialerTest : public ::testing::Test {
  void SetUp() override {
    testutil::prepareLoggers();
    dialer = std::make_shared<DialerImpl>(proto_muxer, tmgr, cmgr, listener,
                                          scheduler);
  }
  ...
  std::shared_ptr<ManualSchedulerBackend> scheduler_backend =
      std::make_shared<ManualSchedulerBackend>();

  std::shared_ptr<Scheduler> scheduler =
      std::make_shared<SchedulerImpl>(scheduler_backend, Scheduler::Config{});
```
Extend `DialerTest`'s fixture with a `std::shared_ptr<ConnectionGaterMock> gater =
std::make_shared<ConnectionGaterMock>();` member, pass it into the `DialerImpl`
constructor, and add cases asserting `interceptPeerDial`/`interceptAddrDial` are
called with `EXPECT_CALL(*gater, interceptPeerDial(_)).WillOnce(Return(outcome::success()))`
/ `WillOnce(Return(ConnectionGaterError::GATER_REJECTED_PEER_DIAL))`, matching the
`Return(...)` gmock-action style already used in this fixture.

For `upgrader_session_test.cpp` (brand new file — RESEARCH.md Pitfall 4: do NOT extend
`upgrader_test.cpp`, which tests `UpgraderImpl` in isolation and is entirely
`DISABLED_`): copy this same `ManualSchedulerBackend`/`SchedulerImpl` +
`testutil::prepareLoggers()` + gmock-mock-per-dependency fixture shape, but construct
`UpgraderSession` directly with `RawConnectionMock`/`SecureConnectionMock`/
`CapableConnectionMock` + `UpgraderMock` (all exist under `test/mock/libp2p/`) +
`ConnectionGaterMock` + the new `SchedulerImpl`.

## Shared Patterns

### Scheduler-deferred callback delivery (D-06 / roadmap criterion 5)
**Source:** `src/network/impl/dialer_impl.cpp` lines 22-23, 63-65 (existing, real usage)
```cpp
scheduler_->schedule(
    [cb{std::move(cb)}] { cb(std::errc::destination_address_required); });
```
**Apply to:** Every gater-rejection path in `DialerImpl` (already has `scheduler_`),
`UpgraderSession::onSecured()`'s `interceptSecured`/`interceptUpgraded` rejections
(needs new `scheduler_` member), and — per RESEARCH.md Open Question 2's
recommendation — `TcpListener::doAccept()`'s `interceptAccept` rejection close path
(needs new `scheduler_` member). There is no literal `post()`/`dispatch()` API in this
codebase — `Scheduler::schedule(Callback&&)` is the one-shot-defer primitive to use.

### Per-module error enum + OUTCOME macro pair
**Source:** `include/libp2p/peer/errors.hpp` + `src/peer/errors.cpp` (full files, this
session)
```cpp
enum class PeerError { SUCCESS = 0, NOT_FOUND };
```
```
OUTCOME_HPP_DECLARE_ERROR(libp2p::peer, PeerError)
```
```cpp
OUTCOME_CPP_DEFINE_CATEGORY(libp2p::peer, PeerError, e) {
  using libp2p::peer::PeerError;
  switch (e) { case PeerError::SUCCESS: return "success"; ... }
  return "unknown";
}
```
**Apply to:** `ConnectionGaterError` enum + category definition — D-02/D-03 require
per-hook `GATER_`-prefixed values (start at `= 1`, not `= 0` like `PeerError`, per
CLAUDE.md's general error-enum convention) and "gater" legible directly in the returned
message strings.

### Hardened connection close before propagating rejection (GATE-05)
**Source:** `src/network/impl/dialer_impl.cpp` lines 126-131, 160-164, 242-246, 262-265
(4 near-identical occurrences of this exact guard, already an established idiom in this
file)
```cpp
if (result.has_value() && !result.value()->isClosed()) {
    SL_ERROR(self->log_, "How often does this happen?");
    auto close_res = result.value()->close();
    BOOST_ASSERT(close_res);
}
```
**Apply to:** Every gater-rejection teardown path (`TcpListener`'s `conn->close()`,
`UpgraderSession`'s `rsecure.value()->close()`/muxed-connection close) — always guard
with `!isClosed()` before calling `close()`, and prefer the object's own hardened
`close()` method over touching a raw asio socket (Pitfall 5's `TcpConnection::close()`
requirement generalizes this same idiom one layer down).

### DI override helper + always-on default binding
**Source:** `include/libp2p/injector/network_injector.hpp` lines 200-204 (helper),
lines 283-291 (default binding block)
```cpp
template <typename... SecImpl>
inline auto useSecurityAdaptors() {
  return boost::di::bind<security::SecurityAdaptor *[]>()  // NOLINT
      .TEMPLATE_TO<SecImpl...>()[boost::di::override];
}
...
di::bind<network::Dialer>().TEMPLATE_TO<network::DialerImpl>(),
```
**Apply to:** `useConnectionGater<GaterImpl>()` helper (single-type, not array — one
active gater at a time) + the always-bound
`di::bind<network::ConnectionGater>().TEMPLATE_TO<network::PermissiveConnectionGater>()`
default in `makeNetworkInjector()`'s "internal" binding section (D-04/D-05).

### Static per-TU logger + SL_DEBUG for notable-non-error events
**Source:** CLAUDE.md Logging conventions, cross-checked against
`dialer_impl.cpp`'s `log_` member usage (`SL_TRACE`, `SL_ERROR` throughout) and
`tcp_listener.cpp`'s inline `log::createLogger("TcpListener")` calls (lines 65-67, 150,
167, 177, 221, 251)
```cpp
static auto logger = log::createLogger("YamuxConn");
...
SL_TRACE(log_(), "read {} bytes from {}", n, remotePeer().value().toBase58());
```
**Apply to:** All 3 call sites' rejection logging — use `SL_DEBUG` specifically (per
D-06, matching this codebase's convention for "notable-but-non-error events" like peer
disconnects), including which hook rejected and peer id/address where available.
`TcpListener` currently creates a fresh logger per-call inline rather than storing one
member `log_` — prefer adding a proper stored `log_` member (matching `DialerImpl`'s
pattern) rather than perpetuating the ad-hoc inline `log::createLogger(...)` calls when
touching this file for gater wiring.

## No Analog Found

None — every file in scope has a close existing analog in this codebase (this is
consistent with RESEARCH.md's "Don't Hand-Roll" finding that no new infrastructure is
required, only correct reuse of 4 existing idioms).

## Metadata

**Analog search scope:** `include/libp2p/{network,transport,peer}/`,
`src/{network,transport,peer}/`, `include/libp2p/injector/`, `test/mock/libp2p/network/`,
`test/libp2p/network/`
**Files scanned:** 13 (read in full or targeted ranges): `transport_adaptor.hpp`,
`peer/errors.hpp`, `peer/errors.cpp`, `network/impl/dialer_impl.hpp`,
`network/impl/dialer_impl.cpp`, `transport/tcp/tcp_listener.hpp`,
`transport/tcp/tcp_listener.cpp`, `transport/impl/upgrader_session.hpp`,
`transport/impl/upgrader_session.cpp`, `injector/network_injector.hpp` (targeted
ranges), `test/mock/libp2p/network/dialer_mock.hpp`,
`test/libp2p/network/dialer_test.cpp` (partial)
**Pattern extraction date:** 2026-08-26
