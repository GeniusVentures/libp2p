---
phase: 02-private-network-pnet-psk-protector
plan: 01
subsystem: crypto
tags: [xsalsa20, stream-cipher, salsa20, hsalsa20, known-answer-tests]

requires:
  - phase: 01-connection-gater-interface-wiring
    provides: Nothing directly (Wave 1 foundation plan)
provides:
  - "libp2p::crypto::xsalsa20 namespace with XSalsa20Stream (stateful keystream), xsalsa20() one-shot, generateNonce() (RAND_bytes, D-04)"
  - "Vendored HSalsa20 subkey + Salsa20/20 core (public-domain reference semantics, D-01)"
  - "p2p_crypto_xsalsa20 leaf CMake library + xsalsa20_test KAT suite (D-03)"
affects: [02-03-pnet-protected-connection, 02-04-wiring]

tech-stack:
  added: []  # D-01: nothing added via package manager
  patterns:
    - "Self-contained leaf crypto library: free functions + stateful stream type side by side (sha256.hpp analog, D-02 low-ceremony style)"
    - "xor_ic-equivalent incremental keystream positioning: leftover-bytes buffer, counter advances only when a buffered block is fully consumed"

key-files:
  created:
    - include/libp2p/crypto/xsalsa20/xsalsa20.hpp
    - src/crypto/xsalsa20/xsalsa20.cpp
    - src/crypto/xsalsa20/CMakeLists.txt
    - test/libp2p/crypto/xsalsa20_test.cpp
  modified:
    - src/crypto/CMakeLists.txt
    - test/libp2p/crypto/CMakeLists.txt

key-decisions:
  - "XSalsa20Error declared in the public header with OUTCOME_HPP_DECLARE_ERROR so the leaf lib stays self-contained (no p2p_crypto_error linkage; links only Boost::boost + OpenSSL::Crypto)"
  - "Test vectors transcribed from libsodium .exp result files, not the .c generators: stream.exp lines are crypto_stream (raw keystream) output, and each per-length line's final byte is the memset fill value i, not keystream — only bytes 0..i-1 of line i are genuine (63 usable from the longest line)"
  - "4 MiB full-keystream SHA-256 vector (662b9d0e...) from stream.exp line 1 chosen as the primary multi-block KAT — stronger than per-block vectors and immune to the fill-byte artifact"

patterns-established:
  - "KAT vector acquisition: transcribe expected values from upstream .exp files verbatim; cross-check the semantics of how the upstream test prints them before embedding"

requirements-completed: [PNET-02, TEST-02]

coverage:
  - id: D1
    description: "Vendored XSalsa20 cipher reproduces published libsodium vectors byte-for-byte (first 63 keystream bytes via per-length line i=63; full 4 MiB keystream SHA-256; HSalsa20 subkey chain transitively via block 0)"
    requirement: PNET-02
    verification:
      - kind: unit
        ref: "test/libp2p/crypto/xsalsa20_test.cpp#XSalsa20Test.KnownAnswerFirstBlockAndSubkeyChain"
        status: pass
      - kind: unit
        ref: "test/libp2p/crypto/xsalsa20_test.cpp#XSalsa20Test.KnownAnswerFull4MiBKeystream"
        status: pass
  - id: D2
    description: "Incremental-positioning semantics: chunked crypt == one-shot crypt for arbitrary chunk boundaries, decrypt==encrypt, empty-input no-op (Pitfall 1 eliminated)"
    requirement: TEST-02
    verification:
      - kind: unit
        ref: "test/libp2p/crypto/xsalsa20_test.cpp#XSalsa20Test.IncrementalPositioningUnequalChunks"
        status: pass
      - kind: unit
        ref: "test/libp2p/crypto/xsalsa20_test.cpp#XSalsa20Test.DecryptIsEncryptVariousLengths"
        status: pass
      - kind: unit
        ref: "test/libp2p/crypto/xsalsa20_test.cpp#XSalsa20Test.EmptyInputIsNoOp"
        status: pass
  - id: D3
    description: "One-shot free function + CSPRNG nonce generation (RAND_bytes, D-04)"
    requirement: PNET-02
    verification:
      - kind: unit
        ref: "test/libp2p/crypto/xsalsa20_test.cpp#XSalsa20Test.OneShotFreeFunctionEqualsStream"
        status: pass
      - kind: unit
        ref: "test/libp2p/crypto/xsalsa20_test.cpp#XSalsa20Test.NonceGeneration"
        status: pass
    human_judgment: false
---

# Plan 02-01 Summary: Vendored XSalsa20 stream cipher

## Accomplishments

- **`p2p_crypto_xsalsa20` leaf library** (`libp2p::crypto::xsalsa20`): `XSalsa20Stream` stateful keystream class (constructor derives HSalsa20 subkey from key+nonce[0..16), runs Salsa20/20 core from counter 0 with nonce[16..24) as the stream nonce; `crypt(gsl::span<uint8_t>)` in-place XOR advancing position by exactly n bytes), `xsalsa20(key, nonce, message)` one-shot free function, `generateNonce()` via OpenSSL `RAND_bytes` (D-04), and `kKeySize`/`kNonceSize` constants.
- **Vendored core** (no libsodium/Crypto++/Hunter addition, per D-01): sigma constant, little-endian helpers, `salsaDoubleRound`, `salsa20InputState`, `salsa20Core` (20 rounds + feed-forward), `hsalsa20Subkey` (output words x0,x5,x10,x15,x6,x7,x8,x9) — all in an anonymous namespace, ~380 lines total.
- **KAT test suite** (`xsalsa20_test`, 8 tests, all passing on MSVC/Debug via `ctest -C Debug -R xsalsa20_test`):
  - published first-63-byte keystream vector (transitive HSalsa20 validation)
  - published 4 MiB full-keystream SHA-256, generated in uneven chunks (1,3,64,7,1000,100000)
  - chunked-vs-one-shot equivalence with different encrypt/decrypt partitions (1,3,64,7,100,25 vs 5,60,135)
  - decrypt==encrypt for lengths 1/63/64/65/200; empty-input no-op; one-shot==stream; size validation; nonce CSPRNG sanity.

## Deviations from Plan

**[Rule 1 - Bug] Initial 64-byte vector literal was wrong** — Found during: Task 2 | Issue: transcribed "kKeystreamFirst64" included byte 63 = `0x3f`, but the upstream per-length lines print i keystream bytes followed by memset fill — byte 63 of line i=63 is the fill value, not keystream | Fix: assert the 63 genuine bytes; multi-block correctness covered by the 4 MiB SHA-256 KAT | Files: test/libp2p/crypto/xsalsa20_test.cpp | Verification: ctest 8/8 pass | Commit: 801c974

**[Rule 3 - Missing critical] Self-contained error category** — Found during: Task 1 acceptance gate | Issue: reusing `OpenSslError`/`RandomProviderError` from `p2p_crypto_error` broke the acceptance criterion "links only Boost::boost and OpenSSL::Crypto" | Fix: local `XSalsa20Error` enum declared in the header (`OUTCOME_HPP_DECLARE_ERROR`), defined in the cpp | Files: include/libp2p/crypto/xsalsa20/xsalsa20.hpp, src/crypto/xsalsa20/xsalsa20.cpp, src/crypto/xsalsa20/CMakeLists.txt | Verification: builds standalone, tests 8/8 | Commit: b067b84

**Total deviations:** 2 auto-fixed (1 bug, 1 conformance). **Impact:** none — final artifacts satisfy all acceptance criteria.

## Notes for Plan 02-03

- `XSalsa20Stream` is the exact type `PnetProtectedConnection` needs: one instance per direction, fed arbitrary-sized read/write buffers; the leftover-buffer semantics guarantee byte-position alignment between peers without block alignment.
- Nonce generation is unused by pnet v1 (nonces are exchanged per-connection, not generated by protectors) — `generateNonce()` exists per plan spec for potential test/tooling use.

## Self-Check: PASSED

- [x] All tasks executed (2/2)
- [x] Each task committed individually (b067b84, 801c974)
- [x] `add_subdirectory(xsalsa20)` present in src/crypto/CMakeLists.txt (alphabetical: sha → x25519_provider → xsalsa20)
- [x] Target links only Boost::boost + OpenSSL::Crypto
- [x] No file under src/crypto/xsalsa20/ references an external cipher package
- [x] `cmake --build build --target p2p_crypto_xsalsa20 --config Debug` exits 0
- [x] `ctest -C Debug -R xsalsa20_test` passes (8 tests, includes >20-byte transcribed upstream ciphertext/keystream literals and two chunk partitions)
