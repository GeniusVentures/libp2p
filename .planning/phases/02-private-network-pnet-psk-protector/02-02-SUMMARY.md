---
phase: 02-private-network-pnet-psk-protector
plan: 02
subsystem: security
tags: [pnet, psk, swarm-key, pre-shared-key, key-hygiene]

requires:
  - phase: 02-private-network-pnet-psk-protector
    provides: Nothing (Wave 1 sibling of 02-01; both feed Wave 2)
provides:
  - "libp2p::security::pnet::PnetError enum (6 values, PNET_-prefixed, 'pnet:'-attributed messages)"
  - "libp2p::security::pnet::Psk move-only self-zeroing value type with fromSwarmKeyText/fromRawBytes/fromBase16String/fromBase64String factories"
  - "p2p_pnet leaf CMake library + psk_test suite (11 cases)"
affects: [02-03-pnet-protected-connection, 02-04-wiring]

tech-stack:
  added: []
  patterns:
    - "Factory-only construction via private default ctor + static outcome::result factories"
    - "Key hygiene: deleted copy, OPENSSL_cleanse in dtor and move-out, zero log statements in pnet files (D-06)"

key-files:
  created:
    - include/libp2p/security/pnet/pnet_error.hpp
    - include/libp2p/security/pnet/psk.hpp
    - src/security/pnet/pnet_error.cpp
    - src/security/pnet/psk.cpp
    - src/security/pnet/CMakeLists.txt
    - test/libp2p/security/pnet/psk_test.cpp
    - test/libp2p/security/pnet/CMakeLists.txt
  modified:
    - src/security/CMakeLists.txt
    - test/libp2p/security/CMakeLists.txt

key-decisions:
  - "Decode-framework failures (UnhexError, BaseError) are mapped to PnetError::PNET_INVALID_PSK_FORMAT at the factory boundary — Psk never leaks foreign error enums"
  - "base64 payloads are materialized into std::string before decodeBase64: its isValidBase64 uses the C-string regex_match overload and reads past non-NUL-terminated string_views (pre-existing upstream quirk, noted for Plan 03/04 and worth an upstream fix)"
  - "/bin/ codec framing rejected (PNET_INVALID_PSK_FORMAT) — no reliable length framing for raw bytes in the textual format"

patterns-established:
  - "Psk value-type shape: private ctor + static factories + span() accessor; consumed by DI binding in Plan 04 via usePrivateNetwork"

requirements-completed: [PNET-02, PNET-04, PNET-05, TEST-02]

coverage:
  - id: D1
    description: "go-ipfs swarm.key text parses as-is (base16 and base64 framing, uppercase hex, trailing newline tolerated)"
    requirement: PNET-04
    verification:
      - kind: unit
        ref: "test/libp2p/security/pnet/psk_test.cpp#PskTest.SwarmKeyBase16Valid"
        status: pass
      - kind: unit
        ref: "test/libp2p/security/pnet/psk_test.cpp#PskTest.SwarmKeyBase64Valid"
        status: pass
      - kind: unit
        ref: "test/libp2p/security/pnet/psk_test.cpp#PskTest.SwarmKeyBase16UppercaseValid"
        status: pass
  - id: D2
    description: "Raw hex/base64/bytes constructors agree on the same 32-byte key"
    requirement: PNET-04
    verification:
      - kind: unit
        ref: "test/libp2p/security/pnet/psk_test.cpp#PskTest.RawConstructorsAgree"
        status: pass
  - id: D3
    description: "Every malformed input rejected explicitly: 31/33 raw bytes, 62/66-char hex, non-hex payload, missing header, wrong version, /bin/ codec — distinct PNET_INVALID_PSK_LENGTH vs PNET_INVALID_PSK_FORMAT codes"
    requirement: PNET-05
    verification:
      - kind: unit
        ref: "test/libp2p/security/pnet/psk_test.cpp#PskTest.RejectsWrongRawLength"
        status: pass
      - kind: unit
        ref: "test/libp2p/security/pnet/psk_test.cpp#PskTest.RejectsWrongDecodedLength"
        status: pass
      - kind: unit
        ref: "test/libp2p/security/pnet/psk_test.cpp#PskTest.RejectsNonHexPayload"
        status: pass
      - kind: unit
        ref: "test/libp2p/security/pnet/psk_test.cpp#PskTest.RejectsMissingOrWrongHeader"
        status: pass
      - kind: unit
        ref: "test/libp2p/security/pnet/psk_test.cpp#PskTest.RejectsBinCodec"
        status: pass
  - id: D4
    description: "Psk hygiene: copy deleted at compile time (static_asserts), move preserves key for moved-to object, zero logging in pnet files (grep-verified)"
    requirement: PNET-02
    verification:
      - kind: unit
        ref: "test/libp2p/security/pnet/psk_test.cpp#PskTest.MoveOnlyHygiene"
        status: pass
      - kind: unit
        ref: "test/libp2p/security/pnet/psk_test.cpp#PskTest.ErrorMessagesCarryAttribution"
        status: pass
    human_judgment: false
---

# Plan 02-02 Summary: PnetError + Psk configuration surface

## Accomplishments

- **`PnetError`** (`include/libp2p/security/pnet/pnet_error.hpp`): 6 SCREAMING_SNAKE values starting at =1 (INVALID_PSK_FORMAT, INVALID_PSK_LENGTH, NONCE_GENERATION_FAILED, NONCE_READ_FAILED, ENCRYPT_FAILED, PUBLIC_BOOTSTRAP_REFUSED — the last four consumed by Plans 03/04), all messages carrying "pnet:" attribution per the Phase 1 convention.
- **`Psk`** (`psk.hpp`/`psk.cpp`): `std::array<uint8_t,32>` internals, factory-only construction (`fromSwarmKeyText`, `fromRawBytes`, `fromBase16String`, `fromBase64String`), `span()` accessor, copy deleted, move + dtor `OPENSSL_cleanse` the key bytes, exactly-32-byte post-decode check on every path, zero logging (D-06).
- **Parsing**: swarm-key framing parsed strictly (exact `/key/swarm/psk/1.0.0/` header → `/base16/` or `/base64/` codec → payload; `/bin/` and wrong versions rejected), trailing whitespace tolerated, decoding fully reused from `common::unhex` / `multi::detail::decodeBase64` — no hand-rolled loops.
- **CMake**: `p2p_pnet` leaf library (Boost::boost, OpenSSL::Crypto, p2p_hexutil, p2p_multibase_codec — no yamux/network deps); registered `add_subdirectory(pnet)` in src/security and test trees.
- **`psk_test`**: 11 cases, all passing on MSVC/Debug — full D-05 parse matrix, move-only compile-time asserts, "pnet:" attribution checks.

## Deviations from Plan

**[Rule 3 - Missing behavior] Error-mapping gap** — Found during: Task 2 test run | Issue: `OUTCOME_TRY` propagated raw `UnhexError`/`BaseError` out of the factories instead of `PNET_INVALID_PSK_FORMAT` (plan requires explicit mapping) | Fix: manual result check + map at the factory boundary | Files: src/security/pnet/psk.cpp | Verification: RejectsNonHexPayload asserts the exact PnetError | Commit: 1a8f0a1

**[Rule 3 - Environment] decodeBase64 C-string overload pitfall** — Found during: Task 2 test run | Issue: `isValidBase64` calls `regex_match(string.data())` (C-string overload) — reads past a `string_view` that is not NUL-terminated (e.g. payload sliced from mid-buffer), rejecting valid base64; pre-existing upstream quirk, NOT auto-fixed in shared code per scope boundary | Fix (local): materialize payload into `std::string` before decoding | Files: src/security/pnet/psk.cpp | Verification: SwarmKeyBase64Valid passes | Commit: 1a8f0a1

**Total deviations:** 2 auto-fixed (1 conformance, 1 workaround). **Impact:** none on plan scope; upstream quirk documented for future fix.

## Notes for Plan 02-03 / 02-04

- `Psk::span()` is the accessor the protected connection will feed into `XSalsa20Stream` (key bytes; nonce comes from the 24-byte exchange).
- `PNET_NONCE_*`, `PNET_ENCRYPT_FAILED`, `PNET_PUBLIC_BOOTSTRAP_REFUSED` are declared and message-registered already — Plans 03/04 can use them without touching pnet_error again.
- The `decodeBase64` view-termination quirk applies anywhere a non-NUL-terminated view is decoded — Plan 03/04 must not pass subspan-made views directly.

## Self-Check: PASSED

- [x] All tasks executed (2/2)
- [x] Each task committed individually (1a8f0a1, 66a2a02)
- [x] `psk.hpp` contains all four factories + `Psk(const Psk &) = delete`
- [x] `psk.cpp` uses `common::unhex` + `decodeBase64` (no hand-rolled decode loops)
- [x] `OPENSSL_cleanse` present in dtor/move paths
- [x] Zero log statements in pnet header/source files (grep clean)
- [x] Length check after decode against 32 (`PNET_INVALID_PSK_LENGTH` ×2 sites)
- [x] `add_subdirectory(pnet)` in src/security/CMakeLists.txt; `addtest(psk_test` links `p2p_pnet`
- [x] `cmake --build build --target p2p_pnet --config Debug` exits 0; `ctest -C Debug -R psk_test` passes (11 tests)
