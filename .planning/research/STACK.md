# Stack Research

**Domain:** libp2p Connection Gating + PSK-based Private Networks (pnet), C++17 brownfield fork of cpp-libp2p
**Researched:** 2026-08-25
**Confidence:** MEDIUM (no context7/curated package-registry source exists for a wire-format spec + Go/Rust/JS source trees — all findings cross-verified across ≥2 independent web sources and, for the core protocol facts, against fetched primary source: `libp2p/specs` repo and `libp2p/go-libp2p` source files directly)

## Recommended Stack

### Core Technologies

| Technology | Version | Purpose | Why Recommended |
|------------|---------|---------|------------------|
| **libp2p pnet spec v1** (`/key/swarm/psk/1.0.0/`) | v1 (only version; unchanged since introduction) | Wire-format spec for the PSK protector — key file format, nonce handshake, cipher choice | This is **not a design choice** — it's a fixed wire protocol. PROJECT.md explicitly requires spec-following for future compatibility even without near-term go-libp2p interop testing. Deviating from it (e.g. swapping in ChaCha20) breaks the contract silently. |
| **XSalsa20 stream cipher** (256-bit key, 192-bit/24-byte nonce, no MAC) | N/A (algorithm, not a package) | The actual cipher the pnet protector applies to the raw connection | Spec-mandated. Chosen upstream over AES-CTR (96-bit nonce → far smaller safe rekey window) and ChaCha20 (no vetted cross-language implementations at spec-writing time). Confidence: MEDIUM (cross-verified across `libp2p/specs`, go-libp2p, rust-libp2p, js-libp2p descriptions). |
| **libsodium** (or **Crypto++**) for the XSalsa20 primitive | libsodium latest stable (1.0.20+) via Hunter `hunter_add_package(libsodium)`; Crypto++ 8.x via `hunter_add_package(cryptopp)` | Supplies the one cryptographic primitive OpenSSL lacks: `crypto_stream_xsalsa20_xor` (libsodium) or `CryptoPP::XSalsa20::Encryption` (Crypto++) | **Confirmed OpenSSL has no Salsa20/XSalsa20 support** in any EVP cipher table, 1.1.x or 3.x (checked via OpenSSL's own GitHub discussions — only ChaCha20 exists, and it is a different, non-interoperable cipher). Both libsodium and Crypto++ have existing Hunter recipes, so adding either is a small, well-trodden CMake dependency addition, not a from-scratch vendoring exercise. Recommend **libsodium primary**: its `crypto_stream_xsalsa20*` function is the literal reference implementation the pnet spec is built against (NaCl-family), has the smallest relevant API surface (no MAC/AEAD baggage — `crypto_secretbox_*` is the wrong function, don't use it), and is C (trivial `extern "C"` linkage from C++17). Crypto++ is the fallback if the team prefers a native C++ API and already-idiomatic `salsa.h`/`XSalsa20::Encryption` class over adding a C library. |
| **go-libp2p `ConnectionGater` interface shape** (5-hook design) | N/A (interface pattern, currently in `github.com/libp2p/go-libp2p/core/connmgr`) | Reference interface to port into C++ `ConnectionGater` abstract class | This is the de facto standard shape across the libp2p ecosystem (go, and conceptually mirrored — though less centrally enforced — in rust/js). Porting the same 5 hook points keeps the C++ fork's mental model aligned with upstream libp2p docs/tutorials, which matters since GNUS engineers will cross-reference go-libp2p behavior when debugging. |

### Supporting Libraries

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| libsodium | 1.0.20+ (via Hunter) | XSalsa20 keystream generation for the pnet protector | Only inside the new pnet connection-wrapper component; do not use for anything beyond this one primitive — OpenSSL remains the primary crypto backend for everything else (RSA/ECDSA/Ed25519/secp256k1/AES/ChaChaPoly/HMAC/SHA already in `src/crypto/*_provider`) |
| OpenSSL (existing dependency) | already pinned in `cmake/dependencies.cmake` | `RAND_bytes` (or equivalent) for the 24-byte nonce generation on the write side of the pnet handshake | Reuse the existing OpenSSL RNG rather than adding a second RNG source — libsodium's own `randombytes_buf` is also fine and matches upstream conventions, but there's no reason to introduce it if OpenSSL's CSPRNG is already wired into the codebase's crypto providers |

### Development Tools

| Tool | Purpose | Notes |
|------|---------|-------|
| Hunter package manager (existing) | Fetches libsodium/Crypto++ as a pinned, hash-verified dependency | Add via `hunter_config(libsodium ...)` in `cmake/Hunter/config.cmake` if a specific version/fork pin is needed, following the same pattern already used for `SQLiteModernCpp` (Soramitsu fork pin) and `tsl_hat_trie` |
| GoogleTest/GTest (existing) | Unit-test the PSK protector (nonce round-trip, encrypt/decrypt symmetry, mismatched-PSK rejection) and the 5 gater hooks (accept/reject at each stage) independently of live networking | Mirror existing `test/` tree structure (`test/security/...`-style layout) for `test/pnet/` and `test/network/conngater/` (or wherever the gater implementation lands) |

## Installation

```cmake
# cmake/dependencies.cmake — add alongside existing hunter_add_package() calls
hunter_add_package(libsodium)
find_package(libsodium CONFIG REQUIRED)
# ... then target_link_libraries(libp2p PRIVATE libsodium::libsodium) in the relevant CMakeLists
```

```cpp
// Primitive needed from libsodium — this is the entire crypto surface required:
// #include <sodium.h>
// crypto_stream_xsalsa20_xor(unsigned char *c, const unsigned char *m, unsigned long long mlen,
//                             const unsigned char *n /* 24 bytes */, const unsigned char *k /* 32 bytes */);
```

If Crypto++ is chosen instead:

```cmake
hunter_add_package(cryptopp)
find_package(cryptopp CONFIG REQUIRED)
# target_link_libraries(libp2p PRIVATE cryptopp-static)
```

```cpp
// #include <cryptopp/salsa.h>
// CryptoPP::XSalsa20::Encryption enc;
// enc.SetKeyWithIV(key, 32, nonce, 24);
// enc.ProcessData(out, in, len);
```

## Alternatives Considered

| Recommended | Alternative | When to Use Alternative |
|--------------|-------------|--------------------------|
| libsodium for XSalsa20 | Crypto++ | If the team wants a purely C++ (no `extern "C"`) API, or already anticipates needing other Crypto++ primitives elsewhere; otherwise libsodium's narrower, purpose-built API is preferable for a single-primitive use case |
| libsodium/Crypto++ (external dependency) | Vendor a small, self-contained public-domain XSalsa20 implementation (as go-libp2p itself does via the small `davidlazar/go-crypto/salsa20` package rather than pulling in a full crypto library) | If the team wants to avoid adding a new Hunter dependency at all — a correct XSalsa20 (HSalsa20 subkey derivation + Salsa20 core) is ~150–250 lines of well-understood, publicly reviewed C code. Trade-off: you own security review/maintenance of hand-rolled crypto vs. a one-line Hunter dependency add. Given this project already has a documented history of concurrency bugs needing careful review (`.planning/codebase/CONCERNS.md`), **do not** take on hand-rolled crypto maintenance burden unless there's a hard constraint against new dependencies — prefer the audited library. |
| go-libp2p's 5-hook `ConnectionGater` shape | rust-libp2p's approach (no first-class equivalent; community guidance is to implement gating via a custom `identify`-adjacent protocol that encrypts a protocol string with the PSK and rejects non-matching peers) | Not applicable here — rust-libp2p's workaround-style approach exists specifically *because* it lacks a first-class gater interface; it is strictly worse as a reference model than go-libp2p's explicit 5-hook interface, which this project should port instead |
| No key-derivation step (raw 32-byte PSK used directly as XSalsa20 key, per spec) | Deriving the key via SHA-256 of a human-memorable passphrase | Only as an **optional integrator convenience** for generating a `swarm.key` file from a passphrase (common in IPFS tooling) — this must happen *outside* the wire protocol, producing the raw 32-byte key that then flows into the unmodified pnet handshake. Do not build passphrase hashing into the protector itself; keep it a separate key-provisioning utility if built at all. |

## What NOT to Use

| Avoid | Why | Use Instead |
|-------|-----|--------------|
| OpenSSL's `EVP_chacha20` as a substitute for XSalsa20 | Confirmed OpenSSL has no Salsa20/XSalsa20 EVP cipher at all; ChaCha20 is a different (non-interoperable) ARX stream cipher — substituting it silently breaks the pnet wire format and violates the spec-compliance constraint in PROJECT.md | libsodium's `crypto_stream_xsalsa20_xor` or Crypto++'s `XSalsa20::Encryption` |
| `crypto_secretbox_*` (libsodium's authenticated/AEAD box, XSalsa20+Poly1305) | Not what the pnet spec defines — pnet is a **bare, unauthenticated** stream cipher (XOR keystream only, no MAC). Using secretbox changes the wire format and breaks interop/spec-compliance | `crypto_stream_xsalsa20` / `crypto_stream_xsalsa20_xor` (the unauthenticated, plain stream-cipher functions) |
| Building gating logic as an ad-hoc protocol-string check inside `identify` (the rust-libp2p community workaround pattern) | Bolted onto an unrelated protocol, easy to bypass, doesn't give the clean 5-stage intercept points the project's architecture (`RawConnection → SecureConnection → CapableConnection`) naturally supports | A dedicated `ConnectionGater` interface with hooks wired directly into `Dialer`, `ListenerManager`/`TcpListener`, and `Upgrader`/`UpgraderSession`, per PROJECT.md's Active requirements |
| Treating pnet as "the" access-control mechanism and skipping the gater | pnet only proves "this peer knows the shared secret" — it has no revocation, no key rotation, no per-peer identity story (this is precisely why `libp2p/specs#489` proposes deprecating pnet ecosystem-wide, as of last check still open/unresolved since Dec 2022). PROJECT.md correctly treats gater + pnet as *two complementary* layers, not one | Keep both: pnet for coarse swarm-level admission (matching PSK), gater for fine-grained peer/address-level policy (blacklist, allowlist, custom logic) on top |

## Stack Patterns by Variant

**If the team wants zero new Hunter dependencies:**
- Vendor a small (~150–250 line) public-domain/MIT XSalsa20 implementation (HSalsa20 subkey derivation feeding the Salsa20 core) directly under `src/crypto/` or a new `src/security/pnet/` directory
- Because this mirrors exactly what go-libp2p itself does — it doesn't pull in a full NaCl/libsodium dependency either, it vendors a small dedicated Salsa20 package (`davidlazar/go-crypto/salsa20`) — so "no new heavy dependency" is a legitimate, precedented choice, not a shortcut
- Trade-off: the team owns correctness/security review of hand-rolled crypto code going forward

**If the team is fine adding one new small Hunter dependency (recommended default):**
- Use libsodium's `crypto_stream_xsalsa20_xor` — audited, constant-time, minimal API surface, and it's the literal reference implementation the spec targets
- Because it eliminates any risk of a subtle implementation bug in hand-rolled ARX cipher code, which is disproportionately risky compared to the small dependency-management cost of one more Hunter package

**If go-libp2p wire interop is ever required later (currently explicitly out of scope per PROJECT.md):**
- Confirm PSK is used raw (no SHA-256/derivation) exactly as go-libp2p's `psk_conn.go` does, and confirm nonce-first-then-XOR framing matches byte-for-byte
- Because any deviation (e.g. an extra KDF step) will silently fail to interoperate with real go-libp2p private-network peers even though the "shape" of the protocol looks right

## Version Compatibility

| Package A | Compatible With | Notes |
|-----------|------------------|-------|
| libsodium (Hunter package) | CMake 3.12+ / C++17 toolchain (existing project baseline) | libsodium exposes a plain C API; no C++ standard requirements to worry about, trivially linkable from C++17 code |
| Crypto++ 8.x (Hunter package) | CMake 3.12+ / C++17 toolchain | Crypto++ is C++-native; confirm the Hunter recipe's pinned version still builds against GCC 7.4/Clang 6.0.1 (project's minimum supported compilers) before committing — Crypto++ 8.x is old enough this should not be an issue, but verify during implementation since no compiler-matrix CI check was found for it specifically |
| pnet wire format (spec v1) | go-libp2p, rust-libp2p, js-libp2p (all still ship it as of this research) | Only one spec version exists; no versioning concerns. Note the ecosystem-wide deprecation proposal (`libp2p/specs#489`) means this spec is stable-but-stagnant — do not expect new spec features, but also low risk of breaking spec changes landing unexpectedly |

## Sources

- [libp2p/specs — Private-Networks-PSK-V1.md](https://github.com/libp2p/specs/blob/master/pnet/Private-Networks-PSK-V1.md) (fetched raw content directly) — PSK file format, XSalsa20 nonce handshake — MEDIUM confidence (webfetch of primary spec source)
- [libp2p/go-libp2p — core/connmgr/gater.go](https://github.com/libp2p/go-libp2p/blob/master/core/connmgr/gater.go) (fetched raw content directly) — ConnectionGater interface, 5 method signatures — MEDIUM confidence
- [libp2p/go-libp2p — p2p/net/pnet/{protector.go,psk_conn.go}](https://github.com/libp2p/go-libp2p/tree/master/p2p/net/pnet) — pskConn struct, nonce exchange order, `davidlazar/go-crypto/salsa20` usage, no-KDF confirmation — MEDIUM confidence
- [libp2p/go-libp2p — p2p/net/conngater](https://pkg.go.dev/github.com/libp2p/go-libp2p/p2p/net/conngater) — BasicConnectionGater reference default implementation — MEDIUM confidence (cross-verified via 2 websearch queries)
- [Kubuxu's "libp2p Private Networks - pnet" design gist](https://gist.github.com/Kubuxu/b96b64be00ef949c8d486fe6e6bfc43e) — XSalsa20-vs-AES-CTR-vs-ChaCha20 selection rationale — MEDIUM confidence
- [libp2p/specs Issue #489 — "Proposal: deprecate pnet / PSK"](https://github.com/libp2p/specs/issues/489) (opened 2022-12-01, open as of this research) — ecosystem-wide caveats on pnet's limitations — MEDIUM confidence
- [rust-libp2p — libp2p-pnet crate](https://crates.io/crates/libp2p-pnet) / [docs.rs pnet module](https://docs.rs/libp2p/latest/libp2p/pnet/index.html) — Rust equivalent implementation, `salsa20` crate usage — MEDIUM confidence
- [js-libp2p — @libp2p/pnet](https://www.npmjs.com/package/@libp2p/pnet) / [@libp2p/interface-connection-gater](https://www.npmjs.com/package/@libp2p/interface-connection-gater) — JS equivalents — MEDIUM confidence
- [OpenSSL GitHub Discussion #24519 — EVP stream cipher](https://github.com/openssl/openssl/discussions/24519) plus absence of any Salsa20/XSalsa20 EVP entry in OpenSSL docs — confirms no native support — MEDIUM confidence (absence-of-evidence cross-checked across multiple searches, not a single authoritative negative-confirmation source)
- [libsodium documentation — XSalsa20 stream cipher](https://doc.libsodium.org/advanced/stream_ciphers/xsalsa20) — `crypto_stream_xsalsa20`/`crypto_stream_xsalsa20_xor` API — MEDIUM confidence
- [Crypto++ Wiki — Salsa20](https://www.cryptopp.com/wiki/Salsa20) / [Crypto++ XSalsa20 struct reference](https://cryptopp.com/docs/ref/struct_x_salsa20.html) — confirms native `CryptoPP::XSalsa20::Encryption` class exists — MEDIUM confidence
- [Hunter package docs — libsodium](https://hunter.readthedocs.io/en/latest/packages/pkg/libsodium.html) / [Hunter package docs — cryptopp](https://hunter.readthedocs.io/en/latest/packages/pkg/cryptopp.html) — confirms both are available as ready-made Hunter recipes, matching the project's existing package-manager pattern — MEDIUM confidence

---
*Stack research for: libp2p Connection Gating + PSK Private Networks (pnet), C++17*
*Researched: 2026-08-25*
