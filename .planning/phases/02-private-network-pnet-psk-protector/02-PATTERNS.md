# Phase 2: Private network (pnet) PSK protector - Pattern Map

**Mapped:** 2026-08-26
**Files analyzed:** 15 (10 new + 5 modified)
**Analogs found:** 15 / 15

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `include/libp2p/crypto/xsalsa20/xsalsa20.hpp` (NEW) | utility (crypto primitive) | transform (stream cipher) | `include/libp2p/crypto/sha/sha256.hpp` (stateful class + free function in `libp2p::crypto`) | role-match |
| `src/crypto/xsalsa20/xsalsa20.cpp` (NEW) | utility impl | transform | `src/crypto/sha/sha256.cpp` (OpenSSL-free sibling; contrast for what NOT to copy) | role-match |
| `src/crypto/xsalsa20/CMakeLists.txt` (NEW) | config | n/a | `src/crypto/sha/CMakeLists.txt` | exact |
| `include/libp2p/security/pnet/psk.hpp` (NEW) | model (value type) | transform (config parse) | `include/libp2p/common/hexutil.hpp` (`outcome::result` free-function decode surface) + `outcome::result` factory style | role-match |
| `src/security/pnet/psk.cpp` (NEW) | model impl | transform | `src/multi/multibase_codec/codecs/base64.cpp` (decode + validate, outcome errors) | role-match |
| `include/libp2p/security/pnet/pnet_error.hpp` (NEW) | error enum | n/a | `include/libp2p/network/connection_gater_error.hpp` (Phase 1) | exact |
| `src/security/pnet/pnet_error.cpp` (NEW) | error category impl | n/a | `src/network/connection_gater_error.cpp` (Phase 1) | exact |
| `include/libp2p/security/pnet/pnet_protected_connection.hpp` (NEW) | decorator (RawConnection) | streaming (byte-stream encrypt/decrypt) | `include/libp2p/connection/raw_connection.hpp` (interface being decorated) + `include/libp2p/transport/impl/upgrader_impl.hpp` (shared_from_this + callback-deferred delegation style) | role-match |
| `src/security/pnet/pnet_protected_connection.cpp` (NEW) | decorator impl | streaming | `src/transport/impl/upgrader_impl.cpp` (callback-parameter forwarding, `deferReadCallback`/`deferWriteCallback` semantics per `reader.hpp`/`writer.hpp`) | role-match |
| `src/security/pnet/CMakeLists.txt` (NEW) | config | n/a | `test/libp2p/security/CMakeLists.txt` structure; lib target per `src/security/plaintext/CMakeLists.txt` leaf-lib pattern | exact |
| `include/libp2p/transport/impl/pnet_upgrader_decorator.hpp` + `src/transport/impl/pnet_upgrader_decorator.cpp` (NEW) | decorator (Upgrader) | request-response (async upgrade) | `include/libp2p/transport/impl/upgrader_impl.hpp` / `src/transport/impl/upgrader_impl.cpp` | exact |
| `src/transport/impl/CMakeLists.txt` (MODIFIED — add decorator src to `p2p_upgrader` or new target) | config | n/a | itself (`libp2p_add_library(p2p_upgrader ...)` block) | exact |
| `include/libp2p/injector/network_injector.hpp` (MODIFIED — add `usePrivateNetwork`) | DI config | n/a | itself — `useConnectionGater<GaterImpl>()` (lines 250-254) + default `ConnectionGater` binding (line 312) | exact |
| `include/libp2p/network/impl/dialer_impl.hpp` + `src/network/impl/dialer_impl.cpp` (MODIFIED — nullable `Psk` ctor param + dial-time refusal) | controller/service | request-response, event-driven | itself — Phase 1 `gater_` ctor param (hpp line 45) + `interceptPeerDial` refusal block (cpp lines 24-34) | exact (self-analog) |
| `test/libp2p/crypto/xsalsa20/xsalsa20_test.cpp`, `test/libp2p/security/pnet/{psk_test,pnet_protected_connection_test,pnet_upgrader_decorator_test}.cpp` (NEW), `test/libp2p/network/dialer_test.cpp` (EXTENDED), new test `CMakeLists.txt`s | test | n/a | `test/libp2p/network/dialer_test.cpp` (mock-harness + ManualSchedulerBackend) + `test/libp2p/security/CMakeLists.txt` (addtest leaf targets) | exact |

---

## Pattern Assignments

### `include/libp2p/crypto/xsalsa20/xsalsa20.hpp` + `src/crypto/xsalsa20/xsalsa20.cpp` (utility, transform)

**Analog:** `include/libp2p/crypto/sha/sha256.hpp`

**Header pattern** (`sha256.hpp` lines 1-30, copy structure):
```cpp
#ifndef LIBP2P_SHA256_HPP
#define LIBP2P_SHA256_HPP

#include <openssl/sha.h>
#include <gsl/span>
#include <libp2p/common/types.hpp>
#include <libp2p/crypto/hasher.hpp>

namespace libp2p::crypto {

  class Sha256 : public Hasher {
   public:
    ...
    outcome::result<void> write(gsl::span<const uint8_t> data) override;
    ...
  };

  outcome::result<libp2p::common::Hash256> sha256(gsl::span<const uint8_t> input);
}  // namespace libp2p::crypto
```

Apply to `xsalsa20.hpp` — guard `LIBP2P_CRYPTO_XSALSA20_XSALSA20_HPP`, namespace `libp2p::crypto::xsalsa20` (mirroring `crypto::aes`, `crypto::hmac` nesting). Per D-02 the shape is: a **stateful stream class** + **free function** wrappers, both `outcome`-styled:

- `class XSalsa20Stream` — holds key/nonce-derived state, 64-bit block counter, leftover-bytes buffer (Pitfall 1: any length must advance position by exactly that length; expose `crypt(gsl::span<uint8_t> in_out)` used for both encrypt/decrypt since XSalsa20 is XOR-based).
- Free function `outcome::result<...> xsalsa20(...)` one-shot convenience — same "free function next to the class" layout as `sha256` at `sha256.hpp` line 53.
- `outcome::result<std::array<uint8_t, kNonceSize>> generateNonce()` using OpenSSL `RAND_bytes` (D-04); constants `kKeySize = 32`, `kNonceSize = 24`, sigma `"expand 32-byte k"`.

**DO NOT copy** the OpenSSL include — this file is deliberately *vendored* (D-01: no libsodium/Crypto++; OpenSSL lacks XSalsa20). The analog supplies the *API shape*, not the implementation. `RAND_bytes`/`OPENSSL_cleanse` go in the nonce/zeroing call sites only — note `RAND_bytes` is not used anywhere in `src/` currently (replacement: existing `crypto::random::CSPRNG`/`BoostRandomGenerator::randomBytes` is an alternative — `src/security/secio/secio.cpp:66` uses `csprng_->randomBytes(16)` for exactly this "random nonce material" purpose; prefer whichever already links into the pnet leaf lib).

**CMake pattern** (`src/crypto/sha/CMakeLists.txt`, copy verbatim structure):
```cmake
libp2p_add_library(p2p_sha
    sha256.cpp
    )
target_link_libraries(p2p_sha
    PUBLIC
    p2p_crypto_error
    OpenSSL::SSL
    OpenSSL::Crypto
    )
```
For `src/crypto/xsalsa20/CMakeLists.txt`: `libp2p_add_library(p2p_crypto_xsalsa20 xsalsa20.cpp)` linking `p2p_crypto_error` + `OpenSSL::Crypto` (only if `RAND_bytes` used there; keep deps minimal per Pitfall 6). Add `add_subdirectory(xsalsa20)` to `src/crypto/CMakeLists.txt` (alphabetical position in the existing list, lines 6-18).

**Vendored core:** ~150-line HSalsa20 subkey + Salsa20/20 core — public-domain reference (djb / libsodium semantics). Keep it in an anonymous/detail namespace except the D-02 free-function surface.

---

### `include/libp2p/security/pnet/pnet_error.hpp` + `src/security/pnet/pnet_error.cpp` (error enum)

**Analog:** `include/libp2p/network/connection_gater_error.hpp` + `src/network/connection_gater_error.cpp` (Phase 1 — themselves analogs of `peer/errors.{hpp,cpp}`)

**Header pattern** (`connection_gater_error.hpp`, copy exactly):
```cpp
#ifndef LIBP2P_NETWORK_CONNECTION_GATER_ERROR_HPP
#define LIBP2P_NETWORK_CONNECTION_GATER_ERROR_HPP

#include <libp2p/outcome/outcome.hpp>

namespace libp2p::network {

  enum class ConnectionGaterError {
    GATER_REJECTED_PEER_DIAL = 1,  ///< interceptPeerDial rejected the peer
    ...
  };

}  // namespace libp2p::network

OUTCOME_HPP_DECLARE_ERROR(libp2p::network, ConnectionGaterError)
```

For `pnet_error.hpp`: guard `LIBP2P_SECURITY_PNET_PNET_ERROR_HPP`, namespace `libp2p::security::pnet`, enum `PnetError` with `PNET_`-prefixed values starting `= 1` with `///<` Doxygen trailing comments. Values needed (from CONTEXT/RESEARCH): `PNET_INVALID_PSK_FORMAT`, `PNET_INVALID_PSK_LENGTH` (≠32 bytes), `PNET_NONCE_GENERATION_FAILED`, `PNET_NONCE_READ_FAILED`, `PNET_ENCRYPT_FAILED`/`PNET_DECRYPT_FAILED` (as applicable), `PNET_PUBLIC_BOOTSTRAP_REFUSED` (D-12 dial refusal).

**Category impl pattern** (`connection_gater_error.cpp` full file — copy exactly):
```cpp
OUTCOME_CPP_DEFINE_CATEGORY(libp2p::network, ConnectionGaterError, e) {
  using libp2p::network::ConnectionGaterError;

  switch (e) {
    case ConnectionGaterError::GATER_REJECTED_PEER_DIAL:
      return "ConnectionGater: rejected at interceptPeerDial";
    ...
  }

  return "ConnectionGater: unknown rejection";
}
```
Mirror with "Pnet:"-legible message strings (`"pnet: invalid pre-shared key length"` etc.) — Phase 1's unmistakable-attribution convention.

---

### `include/libp2p/security/pnet/psk.hpp` + `src/security/pnet/psk.cpp` (model, transform)

**Analog:** `include/libp2p/common/hexutil.hpp` (outcome-styled decode free functions) + `src/security/secio/secio.cpp:66` (CSPRNG usage style); no existing move-only self-zeroing value type in tree — hygiene rules come from D-06 / PITFALLS §3.

**Decoding reuse — exact signatures to call (do not hand-roll)**:
- Hex: `outcome::result<std::vector<uint8_t>> common::unhex(std::string_view hex)` — `include/libp2p/common/hexutil.hpp:46` (case-insensitive per doc comment).
- Base64: `multibase_codec::decodeBase64` — `include/libp2p/multi/multibase_codec/codecs/base64.hpp` (RESEARCH-verified).

**Type shape** (per D-05/D-06 and RESEARCH Pattern 3 — no codebase analog for the move-only mechanics; this is the concrete form):
```cpp
namespace libp2p::security::pnet {

  class Psk {
   public:
    static outcome::result<Psk> fromSwarmKeyText(std::string_view text);
    static outcome::result<Psk> fromRawBytes(gsl::span<const uint8_t> bytes);
    static outcome::result<Psk> fromBase16String(std::string_view hex);
    static outcome::result<Psk> fromBase64String(std::string_view b64);

    Psk(Psk &&) noexcept;             // move-and-cleanse source
    Psk &operator=(Psk &&) noexcept;
    Psk(const Psk &) = delete;        // D-06: non-copyable
    Psk &operator=(const Psk &) = delete;
    ~Psk();                           // OPENSSL_cleanse(key_)

    /// constant-time-ish view for the cipher; never expose as vector
    gsl::span<const uint8_t> span() const noexcept;  // exactly 32 bytes

   private:
    Psk() = default;
    std::array<uint8_t, 32> key_{};   // kKeySize = 32 (D-05)
  };
}
```
Errors: every reject path maps to a `PnetError` value (31B/33B → `PNET_INVALID_PSK_LENGTH`; bad hex/b64/missing `/key/swarm/psk/1.0.0/` header/wrong version → `PNET_INVALID_PSK_FORMAT`). `/bin/` codec: reject with `PNET_INVALID_PSK_FORMAT` (RESEARCH A5). Tolerate trailing `\n`/whitespace in swarm-key text. **Never `SL_*`-log key bytes** (Pitfall 8) — no logger in this file at all.

---

### `include/libp2p/security/pnet/pnet_protected_connection.hpp/.cpp` (decorator, streaming)

**Analog (interface):** `include/libp2p/connection/raw_connection.hpp` (full file in context above)

```cpp
struct RawConnection : public basic::ReadWriteCloser {
    virtual bool isInitiator() const noexcept = 0;
    virtual outcome::result<multi::Multiaddress> localMultiaddr() = 0;
    virtual outcome::result<multi::Multiaddress> remoteMultiaddr() = 0;
};
```
`ReadWriteCloser = ReadWriter + Closeable` → the decorator must implement `read/readSome/write/writeSome/close/deferReadCallback/deferWriteCallback` + the 3 RawConnection methods, delegating all but read/write paths to `inner_`.

**Async contract excerpts (verbatim load-bearing docs)** — from `include/libp2p/basic/reader.hpp:37-43` / `writer.hpp:29-35`:
```cpp
/**
 * @brief Reads exactly {@code} min(out.size(), bytes) {@nocode} bytes ...
 * @note caller should maintain validity of an output buffer until callback
 * is executed. It is usually done with either wrapping buffer as shared
 * pointer, or having buffer as part of some class/struct, and using
 * enable_shared_from_this()
 */
```
Consequences to implement:
- **Peer-nonce read uses the exact variant**: `inner_->read(nonce_buf, 24, cb)` (`Reader::read` reads exactly `min(out.size(), bytes)` — Pitfall 3; never `readSome` for the nonce).
- **Write ciphertext as `std::shared_ptr<std::vector<uint8_t>>` captured in the completion lambda** (Pitfall 2 — const input span must be copy-encrypted into owned memory that outlives the async inner write; `input` may also need copying into the lambda since the caller's span validity ends at callback, not return).
- **Delegation/callback style analog** — `src/transport/impl/upgrader_impl.cpp:70-77`:
```cpp
protocol_muxer_->selectOneOf(
    security_protocols_, conn, conn->isInitiator(), true,
    [self{shared_from_this()}, cb = std::move(cb),
     conn](outcome::result<peer::Protocol> proto_res) mutable {
      if (!proto_res) {
        return cb(proto_res.error());
      }
```
Copy this `self{shared_from_this()}, cb = std::move(cb)` capture idiom + `enable_shared_from_this` base (see `upgrader_impl.hpp:13-14`), routing all completions through `deferReadCallback`/`deferWriteCallback` (scheduler-backed — carry-forward reentrancy rule) rather than invoking `cb` inline.
- Per-direction lazy state: `std::optional<XSalsa20Stream> write_stream_`, `read_stream_`; two independent nonces per connection, never shared (Pattern 1 + nonce-reuse threat).

---

### `include/libp2p/transport/impl/pnet_upgrader_decorator.hpp/.cpp` (decorator, request-response)

**Analog:** `include/libp2p/transport/impl/upgrader_impl.hpp` (full file in context above)

**Class shape** (`upgrader_impl.hpp:12-14` pattern):
```cpp
class UpgraderImpl : public Upgrader,
                     public std::enable_shared_from_this<UpgraderImpl> {
```
`PnetUpgraderDecorator : public Upgrader, public std::enable_shared_from_this<PnetUpgraderDecorator>` with ctor (RESEARCH Pattern 2 — **concrete inner type to avoid Boost.DI recursion**, A1):
```cpp
PnetUpgraderDecorator(std::shared_ptr<UpgraderImpl> inner,
                      std::shared_ptr<const security::pnet::Psk> psk,
                      std::shared_ptr<basic::Scheduler> scheduler);
```
**Method coverage matrix** (verified against `upgrader.hpp:42-78`):
| Upgrader method | Decorator behavior |
|---|---|
| `upgradeToSecureOutbound(RawSPtr, remoteId, cb)` | wrap `conn` in `PnetProtectedConnection`, forward to `inner_` |
| `upgradeToSecureInbound(RawSPtr, cb)` | wrap, forward |
| `upgradeToSecureOutboundRelay(StrSPtr, ...)` / `upgradeToSecureInboundRelay(StrSPtr, ...)` | **pass through unchanged** (Open Q1 resolution — document limitation at the decorator, research A4) |
| `upgradeToMuxed(SecSPtr, cb)` | pass through (muxed sits above PSK layer) |

**CMake:** add `pnet_upgrader_decorator.cpp` to `p2p_upgrader` target in `src/transport/impl/CMakeLists.txt` (block at lines 14-19) + link `p2p_pnet`; OR a separate leaf target if dependency direction demands it (prefer separate target `p2p_pnet_upgrader` linking `p2p_upgrader` + `p2p_pnet` to keep `p2p_upgrader` yamux-free — Pitfall 6).

---

### `include/libp2p/injector/network_injector.hpp` (MODIFIED — `usePrivateNetwork` DI module)

**Analog:** itself — `useConnectionGater` (lines 243-254) and scalar-override composition (line 296+)

**Named-module pattern** (lines 243-254, copy shape):
```cpp
template <typename GaterImpl>
inline auto useConnectionGater() {
  return boost::di::bind<network::ConnectionGater>()
      .template to<GaterImpl>()[boost::di::override];
}
```
`usePrivateNetwork` is richer (RESEARCH DI-module sketch is the concrete form to adapt):
```cpp
template <typename PskArg>
inline auto usePrivateNetwork(PskArg &&key) {
  auto psk = security::pnet::Psk::create(std::forward<PskArg>(key));
  if (!psk) { throw PskValidationError{psk.error()}; }  // eager, D-09/D-10, Pitfall 5
  auto psk_ptr = std::make_shared<const security::pnet::Psk>(std::move(psk.value()));
  return boost::di::make_injector(
      boost::di::bind<std::shared_ptr<const security::pnet::Psk>>().to(psk_ptr),
      boost::di::bind<transport::Upgrader>()
          .template to<transport::PnetUpgraderDecorator>()[boost::di::override]);
}
```
Key mechanics copied from the existing file: `inline auto` return, `TEMPLATE_TO`/`.template to<>` spellings, `[boost::di::override]` on every user-facing rebind, `std::forward<decltype(args)>(args)...` composition slot (line 338). **No default binding for `shared_ptr<const Psk>`** anywhere in `makeNetworkInjector` (D-08) — but `DialerImpl`'s ctor param must be satisfiable when module absent; follow how unbound `shared_ptr` params resolve or add a `di::bind<std::shared_ptr<const Psk>>().to(nullptr)` default ONLY if the DI fork requires it (verify in Wave-0, A2). Provide `usePrivateNetwork(Psk validated)` exception-free overload (Pitfall 5 resolution).

Also: `host_injector.hpp` forwards variadic args into `makeNetworkInjector` already, so no change needed there beyond include-flow — verify, don't assume.

---

### `include/libp2p/network/impl/dialer_impl.hpp` + `src/network/impl/dialer_impl.cpp` (MODIFIED — dial-time bootstrap refusal)

**Analog:** itself — Phase 1 gater wiring (self-analog, exact)

**Ctor parameter pattern** (`dialer_impl.hpp:33-39` — append nullable psk following `gater`):
```cpp
DialerImpl(std::shared_ptr<protocol_muxer::ProtocolMuxer> multiselect,
           std::shared_ptr<TransportManager> tmgr,
           std::shared_ptr<ConnectionManager> cmgr,
           std::shared_ptr<ListenerManager> listener,
           std::shared_ptr<basic::Scheduler> scheduler,
           std::shared_ptr<ConnectionGater> gater,
           std::shared_ptr<const security::pnet::Psk> psk = nullptr);  // NEW (D-08: null = public mode)
```
plus member `std::shared_ptr<const security::pnet::Psk> psk_;` next to `gater_` (line 66).

**Refusal block pattern** (`dialer_impl.cpp:24-34` — the gater rejection to clone):
```cpp
if (auto gated = gater_->interceptPeerDial(p.id); !gated) {
    SL_DEBUG(log_, "gater rejected peer dial to {}: {}", p.id.toBase58(),
              gated.error().message());
    scheduler_->schedule(
        [cb{ std::move(cb) }, err{ gated.error() }] { cb(err); });
    return;
}
```
Copy this verbatim structure for the bootstrap refusal (D-12/D-13): when `psk_ != nullptr` and target matches (a) multiaddress containing `kBootstrapAddress` (`/dnsaddr/bootstrap.libp2p.io`, `include/libp2p/peer/address_repository.hpp:21`) or (b) peer ID in the compile-time public-bootstrap ID snapshot → `SL_DEBUG` with peer ID/address, `scheduler_->schedule` the callback with `PnetError::PNET_PUBLIC_BOOTSTRAP_REFUSED`, return. The check slots immediately after (or before) the gater block at the top of `dial()`. Snapshot IDs live in a `constexpr` list beside the check (research Open Q3 — transcribe at implementation time).

---

### Test files (test)

**Analog 1 — mock-harness fixture:** `test/libp2p/network/dialer_test.cpp:42-95` (full excerpt in context above)
```cpp
struct DialerTest : public ::testing::Test {
  void SetUp() override {
    testutil::prepareLoggers();
    ON_CALL(*gater, interceptPeerDial(_))
        .WillByDefault(Return(outcome::success()));
    ...
    dialer = std::make_shared<DialerImpl>(proto_muxer, tmgr, cmgr, listener,
                                          scheduler, gater);
  }
  ...
  std::shared_ptr<ManualSchedulerBackend> scheduler_backend =
      std::make_shared<ManualSchedulerBackend>();
```
Copy for: dialer refusal tests (extend existing fixture — add `psk` member + construct `DialerImpl` with/without it) and `pnet_upgrader_decorator_test.cpp` (mock `Upgrader` via `test/mock/` convention — see `test/mock/libp2p/network/connection_gater_mock.hpp` for header-guard/namespace mock layout). Drain pattern for scheduler-deferred assertions:
```cpp
while (!scheduler_backend->empty()) {
  scheduler_backend->shift(std::chrono::milliseconds(1));
}
```
(with `EXPECT_...` inside the dial callback, per `DialAllTheAddresses`).

**Analog 2 — CMake leaf test targets:** `test/libp2p/security/CMakeLists.txt` (full file in context above)
```cmake
addtest(plaintext_adaptor_test
    plaintext_adaptor_test.cpp
    )
target_link_libraries(plaintext_adaptor_test
    Boost::Boost.DI
    p2p_plaintext
    ...
    )
```
New targets: `xsalsa20_test` (link `p2p_crypto_xsalsa20`), `psk_test` (link `p2p_pnet`), `pnet_protected_connection_test` (link `p2p_pnet`, `p2p_testutil`; needs an in-memory pipe pair — reuse `testutil/` helpers if present, else two cross-wired mocks), `pnet_upgrader_decorator_test`. Keep links **minimal** — no `p2p_network`-family/yamux targets (Pitfall 6). Remember ctest registers the **target name** and multi-config builds need `-C Debug` (Pitfall 7). For the connection test's mock `RawConnection` inner: follow `test/mock/libp2p/connection/*_mock.hpp` placement.

---

## Shared Patterns

### outcome error enum + category (every new fallible file)
**Source:** `include/libp2p/network/connection_gater_error.hpp` + `src/network/connection_gater_error.cpp` (Phase 1; excerpts above)
**Apply to:** `pnet_error.hpp/.cpp`; every `Psk` factory, handshake step, and dial refusal returns/enqueues these codes. Values `= 1`+, `///<` comments, `OUTCOME_HPP_DECLARE_ERROR` at file scope, `OUTCOME_CPP_DEFINE_CATEGORY` switch in the `.cpp`, message strings carry "pnet:" attribution.

### Scheduler-deferred callback delivery (all async pnet code)
**Source:** `dialer_impl.cpp` `scheduler_->schedule([cb{std::move(cb)}, err]{cb(err);})` (excerpt above) + `deferReadCallback`/`deferWriteCallback` virtuals (`reader.hpp:58-64`, `writer.hpp:47-53`)
**Apply to:** `PnetProtectedConnection` read/write completions, nonce-read failure paths, dial-refusal callback. Never invoke a completion callback inline from an inner connection callback (carry-forward + Pitfall 8/reentrancy).

### enable_shared_from_this + moved-callback lambda captures
**Source:** `src/transport/impl/upgrader_impl.cpp:70-77` (`[self{shared_from_this()}, cb = std::move(cb), conn](...) mutable`)
**Apply to:** `PnetProtectedConnection` (write path especially: capture `self` + `shared_ptr` ciphertext buffer), `PnetUpgraderDecorator`.

### DI named module + override
**Source:** `network_injector.hpp` `useConnectionGater` / `useKeyPair` (lines 150-155, 250-254) + default-binding block (272-338)
**Apply to:** `usePrivateNetwork` (binding excerpt above). Rules: `inline auto`, `[boost::di::override]`, module evaluated eagerly *before* injector assembly, single combined module for Psk + decorator + (transitively) dialer psk param (D-07).

### gsl::span buffers + shared_ptr lifetime
**Source:** `reader.hpp`/`writer.hpp` doc comments (validity-until-callback rule)
**Apply to:** every read/write wrapper; ciphertext/nonce buffers owned via `std::make_shared<std::vector<uint8_t>>`/`std::array` captured in lambdas.

### Logging
**Source:** `dialer_impl.cpp` (`SL_DEBUG`/`SL_TRACE`/`SL_ERROR` with `log_` member, `testutil::prepareLoggers()` in tests)
**Apply to:** dial refusals (`SL_DEBUG`, D-13), handshake failure observability. **Never log key material** (D-06; grep-check new files for any `SL_*`/`log_` line touching `psk` bytes).

---

## No Analog Found

| File | Role | Data Flow | Reason / Fallback |
|------|------|-----------|-------------------|
| XSalsa20 vendored core (`xsalsa20.cpp` internals) | utility | transform | No stream cipher exists in-tree (AES-CTR is OpenSSL-wrapped). Use RESEARCH.md Code Examples: libsodium `stream.c`/`core2.c` vectors + `x/crypto/salsa20` golden pair; chunked-vs-one-shot equivalence test is the correctness gate (Pitfall 1). Public API shape still copies `sha256.hpp`. |
| Move-only self-zeroing value type (`Psk` hygiene mechanics) | model | n/a | First of its kind in tree. Shape locked by RESEARCH Pattern 3 + D-06 (excerpt above); `static_assert(!std::is_copy_constructible_v<Psk>)` in `psk_test.cpp`. |
| Boost.DI instance-binding of move-only via `shared_ptr<const T>` + concrete-type decorator ctor | config | n/a | No precedent in-tree (A1/A2, MEDIUM confidence). Fallback per research: `PskProvider` indirection type. **Gate behind Wave-0 compile check.** |

## Metadata

**Analog search scope:** `include/libp2p/{crypto,security,transport,network,basic,common,peer,injector}`, `src/{crypto,security,transport,network}`, `test/{libp2p,mock}`, `.planning/phases/01-*`
**Files scanned:** ~20 (all excerpts read in full or targeted ranges this session)
**Pattern extraction date:** 2026-08-26
