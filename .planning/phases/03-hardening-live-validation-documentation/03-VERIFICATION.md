---
phase: 03-hardening-live-validation-documentation
verified: 2026-08-27T03:37:19Z
status: human_needed
score: 5/5 must-haves verified
behavior_unverified: 0
overrides_applied: 0
human_verification:
  - test: "Confirm the removal of TcpTransport::dial()'s unconditional loopback-destination rejection (`isLocalHost(...)` guard) in src/transport/tcp/tcp_transport.cpp, committed as a 03-01 'Rule 1 bug fix', was actually a bug and not a deliberate SSRF-style safety guard."
    expected: "Either (a) confirmation from the project maintainer that the prior loopback-rejection guard (added in commit 3d61147, 'Added localhost filter', by the same author/maintainer) was unintentional/incorrect and its removal is accepted, or (b) the guard is restored with a narrower carve-out (e.g. only bypassed for test builds, or gated behind an explicit opt-in) so a malicious peer's PeerInfo cannot induce this node to dial its own loopback-bound services by default."
    why_human: "This is a security-relevant behavior change in production dial() code, made as an unplanned deviation while unblocking TEST-03's live two-node test, in a project whose explicit core value is network-layer access control (Connection Gater + Private Networks / SSRF-adjacent hardening). The original guard was added deliberately by the same maintainer in a prior, non-GSD-tracked commit with no test coverage either way (no tcp_transport_test exists), so grep/build/test evidence cannot establish intent or safety — only a human with the original context can judge whether this was truly dead-weight or a load-bearing control. It was not covered by 03-01-PLAN.md's STRIDE threat register, and no requirement/success-criterion in REQUIREMENTS.md or ROADMAP.md exercises loopback-dial rejection, so it cannot be resolved by more automated verification."
---

# Phase 3: Hardening, Live Validation & Documentation Verification Report

**Phase Goal:** The combined gater+pnet access-control boundary is proven under live two-node and reentrant-callback conditions — the two failure modes this codebase has historically shipped bugs in — and integrators have documentation showing how to configure and correctly combine both layers.
**Verified:** 2026-08-27T03:37:19Z
**Status:** human_needed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

All 5 ROADMAP.md Success Criteria for Phase 3, independently re-verified (built and executed by the verifier, not taken from SUMMARY.md claims):

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | A live two-node test demonstrates that nodes sharing a PSK connect and exchange streams, and a mismatched/missing-PSK node is rejected and never completes the handshake | ✓ VERIFIED | `cmake --build build --config Debug --target pnet_two_node_test -- -m` succeeded; `ctest --test-dir build -C Debug -R pnet_two_node_test --output-on-failure` → `PnetTwoNodeTest.MatchedPskConnectsAndOpensEchoStream` and `PnetTwoNodeTest.MismatchedPskNeverEstablishesUsableStream` both `Passed` (2.04s), re-run independently by the verifier, not sourced from SUMMARY.md |
| 2 | A regression test forces reentrant invocation of gater/pnet callback paths and confirms deferred (scheduler-drained) dispatch, not synchronous reentry | ✓ VERIFIED | Independently built and ran `dialer_test`, `upgrader_session_test`, `pnet_protected_connection_test`, `tcp_listener_test`. New cases confirmed present and passing: `DialerTest.PeerDialRejectionNeverReentersSynchronously`/`AddrDialRejectionNeverReentersSynchronously`, `UpgraderSessionTest.InterceptSecuredRejectionNeverReentersSynchronously`/`InterceptUpgradedRejectionNeverReentersSynchronously`, `PnetProtectedConnectionTest.WriteCompletionNeverReentersSynchronously`/`ReadCompletionNeverReentersSynchronously`, `TcpListenerTest.AcceptGaterRejectionDeferredUntilSchedulerDrains` — all `[ OK ]`. `tcp_listener_test` binary shows 2/4 failing (`ListenCloseListen`, `DoubleClose`) but these are the pre-existing Windows/MSVC `ec.value() 995 vs 105` mismatch documented in STATE.md's Blockers section *before* Phase 3 began (confirmed via git blame: file last touched for gater coverage in Phase 1, unrelated line) |
| 3 | Integrator documentation walks through configuring a PSK for a private network | ✓ VERIFIED | `example/05-private-network/` exists (CMakeLists.txt, private_network_example.cpp, README.md); built cleanly (`libp2p_private_network_example.exe` present in build/example/05-private-network/Debug/); independently run under a 5s bounded timeout — printed `Listening on: /ip4/127.0.0.1/tcp/40530`, `Peer id: 12D3KooW...`, `This peer requires a matching PSK to connect` |
| 4 | Integrator documentation walks through registering a custom `ConnectionGater` via DI | ✓ VERIFIED | `example/07-connection-gater/` exists; built cleanly; independently run — printed `Listening on: /ip4/127.0.0.1/tcp/40531` and `denylisted peer correctly rejected by the custom gater` (the non-"UNEXPECTED" branch, confirming `DenylistGater`/`useConnectionGater<T>()` actually rejects the hardcoded denylisted peer) |
| 5 | Documentation explains pnet and gater are complementary, non-redundant layers, illustrated with a "valid PSK, gater-denied peer" worked example | ✓ VERIFIED | `example/06-private-network-gater/` exists; built cleanly; independently run — printed `Listening on: /ip4/127.0.0.1/tcp/40532` and the complementary-layers message `"peer holds the correct PSK for this private network but is still denied by the gater -- PSK proves network membership, the gater proves peer-level authorization; they are independent, non-redundant checks."`; `README.md` explicitly walks through why each layer alone is insufficient |

**Score:** 5/5 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `test/acceptance/p2p/pnet/pnet_two_node_test.cpp` | 2 TEST_F cases, live 2-node PSK acceptance test | ✓ VERIFIED | 242 lines, `PnetTwoNodeTest` fixture with `Node`/`makeNode<Marker>`/`startListening`; matched-PSK and mismatched-PSK cases match plan spec exactly (marker-type DI workaround, heap-allocated promises, D-03 timeout-or-failure branching, no `PnetError` assertion) |
| `test/acceptance/p2p/pnet/CMakeLists.txt` | addtest + correct library links | ✓ VERIFIED | `addtest(pnet_two_node_test ...)` + all 12 libraries from the plan's verified set, including `p2p_pnet`/`p2p_pnet_upgrader` |
| `test/acceptance/p2p/CMakeLists.txt` | `add_subdirectory(pnet)` registered | ✓ VERIFIED | Line 7 confirmed |
| `test/libp2p/network/dialer_test.cpp` | +2 reentrancy TEST_F cases | ✓ VERIFIED | `PeerDialRejectionNeverReentersSynchronously` (line 574), `AddrDialRejectionNeverReentersSynchronously` (line 607); `ReentrancyGuard`/`Scope` idiom present, matches plan's guard-then-drain-then-assert structure |
| `test/libp2p/transport/tcp/tcp_listener_test.cpp` | +1 before/after observation test | ✓ VERIFIED | `AcceptGaterRejectionDeferredUntilSchedulerDrains` present and passing |
| `test/libp2p/transport/upgrader_session_test.cpp` | +2 reentrancy TEST_F cases | ✓ VERIFIED | Both present (lines 201, 340), passing |
| `test/libp2p/security/pnet/pnet_protected_connection_test.cpp` | +2 reentrancy tests | ✓ VERIFIED | Both present (lines 472, 511), passing |
| `example/05-private-network/{CMakeLists.txt,*.cpp,README.md}` | Runnable PSK example | ✓ VERIFIED | All 3 files present; builds; runs; README explains swarm-key format and substitution warning |
| `example/07-connection-gater/{CMakeLists.txt,*.cpp,README.md}` | Runnable custom-gater example | ✓ VERIFIED | All 3 files present; builds; runs; README explains the 5-hook interface |
| `example/06-private-network-gater/{CMakeLists.txt,*.cpp,README.md}` | Runnable complementary-layers example | ✓ VERIFIED | All 3 files present; builds; runs; README is DOCS-03's primary artifact, explicitly reasoning through why neither layer alone suffices |

### Key Link Verification

| From | To | Via | Status | Details |
|------|-----|-----|--------|---------|
| `pnet_two_node_test.cpp` | `PnetUpgraderDecorator`/full DI graph | `makeHostInjector(usePrivateNetwork(...))`, resolved through real `p2p_pnet`/`p2p_pnet_upgrader` link, not a mock | ✓ WIRED | Confirmed by actually running the test over real TCP loopback (not mocked) — matched-PSK stream opens, mismatched-PSK never does |
| `test/acceptance/p2p/CMakeLists.txt` | `pnet_two_node_test` target | `add_subdirectory(pnet)` | ✓ WIRED | Test appears in default `ctest` suite (`ctest -R pnet_two_node_test` finds and runs it without any special flag) |
| `example/CMakeLists.txt` | 3 new example subdirectories | `add_subdirectory(05-private-network)`, `add_subdirectory(07-connection-gater)`, `add_subdirectory(06-private-network-gater)` | ✓ WIRED | Confirmed present in file, in the documented order; all 3 `.exe` targets build under `EXAMPLES=ON` alongside the 4 pre-existing examples |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Live 2-node PSK test passes | `cmake --build build --config Debug --target pnet_two_node_test -- -m && ctest --test-dir build -C Debug -R pnet_two_node_test --output-on-failure` | Both TEST_F cases `Passed`, 2.04s | ✓ PASS |
| Reentrancy regression suite passes (minus pre-existing unrelated failures) | `ctest --test-dir build -C Debug -R "dialer_test\|upgrader_session_test\|tcp_listener_test\|pnet_protected_connection_test\|pnet_two_node_test"` | 4/5 binaries pass fully; `tcp_listener_test` 2/4 cases fail on pre-existing, pre-Phase-3 Windows/MSVC error-code mismatch; both new tcp_listener cases (`AcceptRejectedByGaterClosesConnectionWithoutUpgrading`, `AcceptGaterRejectionDeferredUntilSchedulerDrains`) pass | ✓ PASS |
| PSK example runs and demonstrates `usePrivateNetwork(...)` | `timeout 5 build/example/05-private-network/Debug/libp2p_private_network_example.exe` | Printed listening addr, peer id, PSK-required message | ✓ PASS |
| Gater example runs and demonstrates rejection | `timeout 5 build/example/07-connection-gater/Debug/libp2p_connection_gater_example.exe` | Printed `denylisted peer correctly rejected by the custom gater` | ✓ PASS |
| Combined PSK+gater example runs and demonstrates complementary layers | `timeout 5 build/example/06-private-network-gater/Debug/libp2p_private_network_gater_example.exe` | Printed the complementary-layers explanatory message | ✓ PASS |
| Injector regression (PNET-05 force-fail-safe, GATE-04 DI binding) unaffected by 03-01's `PskHandle` baseline-binding change | `ctest --test-dir build -C Debug -R "pnet_injector_test\|host_injector_test\|network_injector_test"` | 3/3 pass | ✓ PASS |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|--------------|--------|----------|
| TEST-03 | 03-01 | Live two-node test confirms PSK-matched connect / mismatched reject | ✓ SATISFIED | `pnet_two_node_test` (2 cases), independently re-run, passes |
| TEST-04 | 03-02 | New gater/pnet code delivers callbacks via scheduler, regression-guarded against reentrancy | ✓ SATISFIED | 7 new tests across 4 files, independently re-run, all pass |
| DOCS-01 | 03-03 | Integrator docs: configure PSK | ✓ SATISFIED | `example/05-private-network/`, run and confirmed |
| DOCS-02 | 03-03 | Integrator docs: register custom `ConnectionGater` | ✓ SATISFIED | `example/07-connection-gater/`, run and confirmed |
| DOCS-03 | 03-03 | Docs: pnet + gater are complementary, non-redundant | ✓ SATISFIED | `example/06-private-network-gater/`, run and confirmed |

No orphaned requirements found — REQUIREMENTS.md's Phase 3 traceability row set (`TEST-03, TEST-04, DOCS-01, DOCS-02, DOCS-03`) exactly matches the union of `requirements:` fields declared across `03-01-PLAN.md`/`03-02-PLAN.md`/`03-03-PLAN.md`.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `src/network/impl/dialer_impl.cpp` | 348 | `//TODO: Need to track all dials in a holepunch...` | ℹ️ Info | Pre-existing (git blame: commit `16ec5d4`, 2024-09-24), not touched by this phase's diff hunks, not a new debt marker |
| `src/transport/tcp/tcp_transport.cpp` | 32, 187 | `//TODO(107): Reentrancy` | ℹ️ Info | Pre-existing (git blame: commit `8d1b7ef`, 2021-04-02 / `ae18ab7`, 2025-09-25), references issue #107, not new |

No new TBD/FIXME/XXX/TODO/HACK/PLACEHOLDER markers were introduced by any file this phase modified. No blocker-level anti-patterns found in the artifacts that satisfy the 5 must-have truths.

**One significant out-of-band production change requires human judgment** (not a code-smell anti-pattern, but a scope/security concern — see Human Verification below): 03-01 removed `TcpTransport::dial()`'s unconditional rejection of loopback (127.0.0.0/8, ::1) destination addresses (`isLocalHost(...)` guard), as one of 5 "Rule 1 bug fix" deviations needed to make the live two-node test's premise achievable at all. Independently confirmed via `git log`/`git show 3d61147` that this guard was deliberately added by the same project maintainer in a prior (non-GSD, non-Phase-3) commit titled "Added localhost filter" — not an obviously accidental typo or dead branch. No dedicated `tcp_transport_test` exists to pin down the guard's original intent or prove the new (guard-removed) behavior is safe. Given this project's explicit core value is network-layer access control / SSRF-adjacent hardening ("a node without the correct network credentials... must be unable to join or communicate"), and a permissive-gater node now unconditionally allows dialing any loopback-destination multiaddr supplied by a remote peer's `PeerInfo`, this falls outside 03-01-PLAN.md's own STRIDE threat register and outside any ROADMAP/REQUIREMENTS truth this phase claims — it is flagged for human sign-off rather than as a phase-blocking gap, since no roadmap Success Criterion actually depends on loopback-dial rejection.

### Human Verification Required

### 1. Loopback-dial guard removal (TcpTransport::dial())

**Test:** Review `git show 78de11e -- src/transport/tcp/tcp_transport.cpp` and the prior guard's origin at `git show 3d61147`. Decide whether the removed `isLocalHost(...)` → `bad_address` rejection was (a) accidental/obsolete and safe to leave removed, or (b) a deliberate SSRF-style safety control that should be restored (potentially in a narrower form, e.g. gater-mediated rather than unconditional).

**Expected:** An explicit accept/reject decision recorded (e.g. a VERIFICATION.md override entry, a follow-up issue, or a restoring commit).

**Why human:** No existing test or documentation records this guard's original intent; git history shows it was added deliberately by the maintainer, not left as leftover scaffolding. This project's charter is specifically about network-layer access control, so a default-allow change to which addresses this node will dial deserves an explicit human call, not an automated pass/fail.

### Deviations Note (for completeness, not gaps)

03-01 and 03-03 each made "Rule 1/Rule 3 auto-fix" production/build-wiring deviations beyond their plans' original "no production code changes" framing. Independently re-verified all of them:
- `DialerImpl` psk ctor switched to `PskHandle` — confirmed compiles, `dialer_test`/`pnet_injector_test`/`host_injector_test`/`network_injector_test` all pass; closes a real BOOT-01 DI-wiring gap, does not weaken any existing check.
- `RouteHelper` loopback-listener fallback — additive-only fallback tier, does not remove any existing behavior.
- `PnetProtectedConnection` write-success reporting fix — corrects a genuine "success reported as failure" bug; `pnet_protected_connection_test` passes.
- `TcpTransport::dial()` loopback-rejection removal — see Human Verification item #1 above; this is the one deviation the verifier could not close out purely from codebase evidence.
- `cmake/dependencies.cmake` Boost `date_time`/`regex` components, `p2p_dialer`→`p2p_pnet` link — pure build-wiring fixes required for `EXAMPLES=ON` to configure/link at all; confirmed no impact on non-example targets, full example build succeeds.

### Gaps Summary

No ROADMAP.md Success Criterion or REQUIREMENTS.md requirement (TEST-03, TEST-04, DOCS-01, DOCS-02, DOCS-03) failed independent re-verification. All 5 are demonstrated by real, independently-built-and-run artifacts (tests and example binaries), not just SUMMARY.md narrative. The phase goal — proving the combined gater+pnet boundary under live two-node and reentrant-callback conditions, plus integrator documentation — is achieved.

The one open item is not a failed must-have but a scope/security judgment call surfaced during independent scrutiny of the phase's self-reported deviations (per this verification's explicit mandate to check them, not just accept the SUMMARY's own Rule-1 self-classification): the production removal of a loopback-dial rejection guard that predates this milestone and was not evaluated against this project's own access-control threat model before being removed. It routes this verification to `human_needed` rather than `passed`.

---

*Verified: 2026-08-27T03:37:19Z*
*Verifier: Claude (gsd-verifier)*
