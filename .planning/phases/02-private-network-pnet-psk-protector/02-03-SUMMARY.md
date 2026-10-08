---
phase: 02-private-network-pnet-psk-protector
plan: 03
subsystem: security
tags: [pnet, psk, xsalsa20, raw-connection-decorator, nonce-exchange]

requires:
  - phase: 02-private-network-pnet-psk-protector
    provides: "XSalsa20Stream (02-01) and Psk/PnetError (02-02)"
provides:
  - "libp2p::security::pnet::PnetProtectedConnection — RawConnection decorator enforcing the PSK boundary (PNET-01)"
  - "Lazy per-direction 24-byte nonce exchange + full-direction XSalsa20 wrap, psk_conn.go-exact"
  - "pnet_protected_connection_test (7 cases: round-trip both directions, wire-leak, mismatch, chunk-storm, defer, delegation, nonce-failure)"
affects: [02-04-wiring]

tech-stack:
  added: []
  patterns:
    - "Statement-boundary sequencing for span views vs move-capturing lambdas (indeterminate argument evaluation order)"
    - "PipeEnd byte-pipe test harness for RawConnection decorators"

key-files:
  created:
    - include/libp2p/security/pnet/pnet_protected_connection.hpp
    - src/security/pnet/pnet_protected_connection.cpp
    - test/libp2p/security/pnet/pnet_protected_connection_test.cpp
  modified:
    - src/security/pnet/CMakeLists.txt
    - test/libp2p/security/pnet/CMakeLists.txt

key-decisions:
  - "write()-all semantics via a partial-write retry loop in doWriteProtected: payload is crypted exactly once (offset==0), retries resume from the new offset without re-crypting"
  - "Nonce-read failures (short/error exact-variant reads) map to PNET_NONCE_READ_FAILED defensively even though the exact-variant contract is all-or-error"
  - "deferReadCallback/deferWriteCallback route every completion through scheduler_->schedule (Phase 1 carry-forward), verified by CompletionDeferredThroughScheduler asserting a synchronously-completing inner write still defers"

patterns-established:
  - "PSK wrap point: RawConnection decorator below the Upgrader — Plan 04 wraps connections in PnetUpgraderDecorator using this class"

requirements-completed: [PNET-01, PNET-02, PNET-03, TEST-02]

coverage:
  - id: D1
    description: "Same-PSK peers round-trip multi-block payloads in both directions (two independent nonce exchanges)"
    requirement: PNET-01
    verification:
      - kind: unit
        ref: "test/libp2p/security/pnet/pnet_protected_connection_test.cpp#PnetProtectedConnectionTest.RoundTripSamePskBothDirections"
        status: pass
  - id: D2
    description: "Wire shows exactly 24 cleartext nonce bytes per direction; post-nonce bytes are neither the plaintext nor a /multistream/1.0.0/ prefix"
    requirement: PNET-01
    verification:
      - kind: unit
        ref: "test/libp2p/security/pnet/pnet_protected_connection_test.cpp#PnetProtectedConnectionTest.NonceFirstOnWireNothingElseCleartext"
        status: pass
  - id: D3
    description: "Mismatched-PSK peer decrypts garbage (decryption != plaintext) — multiselect can never succeed (PNET-03)"
    requirement: PNET-03
    verification:
      - kind: unit
        ref: "test/libp2p/security/pnet/pnet_protected_connection_test.cpp#PnetProtectedConnectionTest.MismatchedPskDecryptsGarbage"
        status: pass
  - id: D4
    description: "Chunked I/O at arbitrary unequal write/read boundaries never desynchronizes the keystream"
    requirement: PNET-02
    verification:
      - kind: unit
        ref: "test/libp2p/security/pnet/pnet_protected_connection_test.cpp#PnetProtectedConnectionTest.ChunkStormUnequalPartitions"
        status: pass
  - id: D5
    description: "All completions deferred through the scheduler (never inline); close/isClosed/isInitiator delegate; nonce-read failure surfaces PNET_NONCE_READ_FAILED"
    requirement: TEST-02
    verification:
      - kind: unit
        ref: "test/libp2p/security/pnet/pnet_protected_connection_test.cpp#PnetProtectedConnectionTest.CompletionDeferredThroughScheduler"
        status: pass
      - kind: unit
        ref: "test/libp2p/security/pnet/pnet_protected_connection_test.cpp#PnetProtectedConnectionTest.Delegation"
        status: pass
      - kind: unit
        ref: "test/libp2p/security/pnet/pnet_protected_connection_test.cpp#PnetProtectedConnectionTest.NonceReadFailurePath"
        status: pass
---

# Plan 02-03 Summary: PnetProtectedConnection

## Accomplishments

- **`PnetProtectedConnection`** (`pnet_protected_connection.hpp/.cpp`, added to `p2p_pnet`): a `RawConnection` decorator implementing the pnet PSK boundary with go-libp2p `psk_conn.go` semantics — lazy per-direction 24-byte nonce exchange (nonce on the wire in the clear, exactly once per direction), then XSalsa20 over everything following. Two independent `std::optional<XSalsa20Stream>` states (`write_stream_`, `read_stream_`); key material via `psk_->span()`; never logged.
- **Write path**: payload copied into a `make_shared`-owned vector (const span can't be crypted in place; must outlive async write — Pitfall 2), encrypted exactly once, with a partial-write retry loop resuming from the write offset without re-crypting; nonce generated via `generateNonce()` (D-04), failures map to `PNET_NONCE_GENERATION_FAILED`.
- **Read path**: peer nonce acquired with an exact-24-byte `inner_->read` (never `readSome` — Pitfall 3), shared-array-owned across the async chain; failures map to `PNET_NONCE_READ_FAILED`; after the nonce, `read`/`readSome` delegate and the completion decrypts exactly `n` bytes in the caller's buffer.
- **Defer discipline**: every completion routed through `deferReadCallback`/`deferWriteCallback` → `scheduler_->schedule` (Phase 1 carry-forward); `close`/`isClosed`/`isInitiator`/multiaddr getters are pure delegation.
- **CMake**: `p2p_pnet` now links `p2p_crypto_xsalsa20` + `p2p_basic_scheduler` (still no yamux/network deps).
- **`pnet_protected_connection_test`** — 7 cases over an in-memory byte-pipe harness (`PipeEnd`) with a `ManualSchedulerBackend` drain idiom: both-direction round-trip, wire-leak (24B nonce then no `/multistream/1.0.0/` prefix), mismatched-PSK garbage, chunk-storm with unequal partitions, scheduler-deferral (synchronously-completing inner still defers), delegation, and the nonce-read failure path.

## Deviations from Plan

**[Rule 1 - Bug] Indeterminate argument evaluation order crashed the nonce write (MSVC)** — Found during: Task 2 test run | Issue: `inner_->writeSome(*nonce_buf, nonce_buf->size(), [nonce_buf{std::move(nonce_buf)}...]{...})` — MSVC sequences lambda-construction move-captures BEFORE the `*nonce_buf` argument evaluation, nulling the shared_ptr → access violation (0xc0000005) in 6/7 tests | Fix: build the span view in its own statement before the call (statement boundary sequences it first); same pattern applied in `doWriteProtected` | Files: src/security/pnet/pnet_protected_connection.cpp | Verification: all 7 tests pass | Commits: a0a465b, 2ec85e3

**[Rule 3 - Test bug] Delegation assertion inverted** — Found during: Task 2 | Issue: `ASSERT_FALSE(prot->close())` — success is truthy for `outcome::result<void>` | Fix: `ASSERT_TRUE` with comment | Files: test file | Verification: passes | Commit: 2ec85e3

**Total deviations:** 2 auto-fixed (1 Rule-1 bug with real production significance — documented below; 1 test bug). **Impact:** the eval-order hazard pattern is now documented in-code and applies to any future span+move-lambda call.

## Notes for Plan 02-04

- Wrap point: `PnetUpgraderDecorator` should construct this class as `std::make_shared<PnetProtectedConnection>(raw_conn, psk, scheduler)` — the ctor is public and the type is `enable_shared_from_this`.
- The `PipeEnd` harness is reusable for decorator-level tests if 02-04 needs them.
- **Pattern warning (from the Rule-1 bug)**: when passing a view into `*shared_buf` alongside a lambda that move-captures `shared_buf`, always sequence the view construction in a prior statement.

## Self-Check: PASSED

- [x] All tasks executed (2/2), committed (a0a465b, 2ec85e3)
- [x] Two independent XSalsa20Stream states (write_stream_/read_stream_)
- [x] Nonce path uses `inner_->read` only (no readSome in the nonce acquisition)
- [x] Write path buffers via `make_shared<std::vector<uint8_t>>`
- [x] All completions through defer* → scheduler (test-asserted)
- [x] Zero log statements referencing key material
- [x] `ctest -C Debug -R pnet_protected_connection_test` — 7/7 pass; `psk_test` and `xsalsa20_test` still green (no regression)
