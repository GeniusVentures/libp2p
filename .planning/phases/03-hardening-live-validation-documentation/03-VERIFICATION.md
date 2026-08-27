---
phase: 03-hardening-live-validation-documentation
verified: 2026-08-27T07:15:00Z
status: passed
score: 5/5 must-haves verified
behavior_unverified: 0
overrides_applied: 0
re_verification:
  previous_status: human_needed
  previous_score: 5/5 must-haves verified
  gaps_closed:
    - "Loopback-dial guard removal (TcpTransport::dial()) — restored secure-by-default via quick task 260827-2w7 (AllowLoopbackDial DI type, defaults to reject, opt-in via injector::useAllowLoopbackDial())"
  gaps_remaining: []
  regressions: []
---

# Phase 3: Hardening, Live Validation & Documentation Verification Report (Re-verification)

**Phase Goal:** The combined gater+pnet access-control boundary is proven under live two-node and reentrant-callback conditions — the two failure modes this codebase has historically shipped bugs in — and integrators have documentation showing how to configure and correctly combine both layers.
**Verified:** 2026-08-27T07:15:00Z
**Status:** passed
**Re-verification:** Yes — after resolution of the single `human_needed` item via quick task 260827-2w7

## Context

The initial verification (2026-08-27T03:37:19Z) found all 5 ROADMAP.md Success Criteria met and zero requirement gaps, but routed to `human_needed` on one item: plan 03-01 had silently removed `TcpTransport::dial()`'s unconditional loopback-rejection guard (`isLocalHost(...)` → `bad_address`) as an unplanned "Rule 1 bug fix" to unblock the live two-node test, with no threat-model coverage of the change in a project whose core value is network-layer access control.

The maintainer reviewed the finding (03-UAT.md) and directed a specific resolution: restore secure-by-default rejection, but make it DI-configurable so the live test can still opt in. Quick task `260827-2w7-add-a-di-configurable-allow-localhost-di` implemented this. This re-verification independently re-examines the resolution from the codebase — not from the SUMMARY.md/UAT.md self-report — and re-confirms the original 5 truths did not regress.

## Goal Achievement

### Observable Truths (full re-check, not just the resolved item)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | A live two-node test demonstrates that nodes sharing a PSK connect and exchange streams, and a mismatched/missing-PSK node is rejected and never completes the handshake | ✓ VERIFIED | Independently rebuilt (`cmake --build build --config Debug --target pnet_two_node_test ... -- -m`, exit 0) and re-ran (`ctest --test-dir build -C Debug -R pnet_two_node_test --output-on-failure`) — both `TEST_F` cases `Passed`, 2.04s. This test now legitimately requires the loopback-dial opt-in to reach real TCP dial; it still passes, proving the opt-in mechanism works end-to-end, not just at compile time |
| 2 | A regression test forces reentrant invocation of gater/pnet callback paths and confirms deferred (scheduler-drained) dispatch, not synchronous reentry | ✓ VERIFIED | Independently rebuilt and re-ran `dialer_test`, `upgrader_session_test`, `pnet_protected_connection_test`, `tcp_listener_test` (8-target `ctest -R` run). All target reentrancy cases still `[ OK ]`: `DialerTest.{Peer,Addr}DialRejectionNeverReentersSynchronously`, `UpgraderSessionTest.Intercept{Secured,Upgraded}RejectionNeverReentersSynchronously`, `PnetProtectedConnectionTest.{Write,Read}CompletionNeverReentersSynchronously`, `TcpListenerTest.AcceptGaterRejectionDeferredUntilSchedulerDrains`. `tcp_listener_test` still shows the same 2/4 pre-existing Windows/MSVC `995 vs 105` error-code-mismatch failures documented before Phase 3 began — unchanged by the quick task, confirmed not a new regression |
| 3 | Integrator documentation walks through configuring a PSK for a private network | ✓ VERIFIED | `example/05-private-network` rebuilt (exit 0) and re-run under bounded timeout — printed `Private-network server started`, `Listening on: /ip4/127.0.0.1/tcp/40530`, `Peer id: ...`, `This peer requires a matching PSK to connect`. No source change was needed per the quick task (this example never dials), confirmed unaffected |
| 4 | Integrator documentation walks through registering a custom `ConnectionGater` via DI | ✓ VERIFIED | `example/07-connection-gater` rebuilt (exit 0) and re-run — printed `denylisted peer correctly rejected by the custom gater`, confirming the denylisted-peer self-dial is still rejected at `DialerImpl::interceptPeerDial` (before `TcpTransport::dial()` is reached), unaffected by the new loopback guard |
| 5 | Documentation explains pnet and gater are complementary, non-redundant layers, illustrated with a "valid PSK, gater-denied peer" worked example | ✓ VERIFIED | `example/06-private-network-gater` rebuilt (exit 0) and re-run — printed the complementary-layers message `"peer holds the correct PSK for this private network but is still denied by the gater -- ..."`, unaffected |

**Score:** 5/5 truths verified (unchanged from initial verification; no regressions)

### Resolution of the Human-Verification Item

**Item:** Loopback-dial guard removal in `TcpTransport::dial()`.

**Independent re-verification (not taken from SUMMARY.md/03-UAT.md claims):**

1. **Guard restored, reject-by-default confirmed by reading current source.** `src/transport/tcp/tcp_transport.cpp` — both `dial()` overloads (the `multi::Multiaddress bindaddress` overload, line 48, and the `RouteHelper::SourceAddresses source_addresses` overload, line 215) contain:
   ```cpp
   if (!allow_loopback_dial_.allow) {
     if (address.hasProtocol(...IP4) && isLocalHost(...)) return handler(std::errc::bad_address);
     if (address.hasProtocol(...IP6) && isLocalHost(...)) return handler(std::errc::bad_address);
   }
   ```
   This matches the pre-78de11e shape (same `isLocalHost` check, same `bad_address` error code), placed immediately after `canDial()`, before any connection is opened.

2. **Gated behind a DI-bindable flag, not a no-op or trivially bypassed.** `include/libp2p/transport/tcp/allow_loopback_dial.hpp` defines `struct AllowLoopbackDial` with `bool allow = false` and only an explicit (non-aggregate) constructor — following the `PskHandle` precedent specifically to prevent Boost.DI's aggregate-member auto-injection from silently defaulting the flag some other way. `include/libp2p/injector/network_injector.hpp` binds a baseline `AllowLoopbackDial{}` (allow=false) in `makeNetworkInjector`'s `di::make_injector` call (line 434, immediately before the `TcpTransport` binding) — so the flag is always explicitly resolved, never left to chance. `useAllowLoopbackDial(bool allow = true)` (line 275) is the only way to override it, via `[boost::di::override]`. Grepped all direct `make_shared<TcpTransport>(...)` call sites in the tree (`test/acceptance/p2p/muxer.cpp`, `test/libp2p/transport/tcp/tcp_integration_test.cpp`) — all use the 4-arg form, which defaults to `AllowLoopbackDial{}` = reject, i.e. every non-opted-in caller gets the secure default.

3. **`pnet_two_node_test.cpp` independently re-run, passes.** `test/acceptance/p2p/pnet/pnet_two_node_test.cpp`'s `makeNode<Marker>()` (line 104) passes `injector::useAllowLoopbackDial()` into `makeHostInjector(...)`. Independently rebuilt and re-ran via `ctest -R pnet_two_node_test` (not sourced from SUMMARY.md) — both cases `Passed`, confirming the opt-in is load-bearing and the live two-node test still reaches real TCP loopback dial.

4. **None of the original 5 ROADMAP success criteria regressed.** See Observable Truths table above — all 5 independently re-verified green after the change. The 8-target regression ctest suite (`pnet_two_node_test`, `dialer_test`, `tcp_listener_test`, `upgrader_session_test`, `pnet_protected_connection_test`, `pnet_injector_test`, `host_injector_test`, `network_injector_test`) was independently rebuilt (exit 0) and run: 7/8 fully pass, `tcp_listener_test` fails only its 2 pre-existing (pre-Phase-3, pre-quick-task) Windows/MSVC error-code-mismatch cases — same failure signature as the initial verification, not a new regression. All 3 example binaries (`05-private-network`, `06-private-network-gater`, `07-connection-gater`) independently rebuilt and re-run, printing their documented proof strings unchanged.

5. **Resolution is sufficient to route to `passed`.** The quick task's own threat register (`260827-2w7-PLAN.md`) documents the residual risk explicitly: T-quick-01 (SSRF via loopback dial) is now `mitigate`d by the restored default-reject guard; T-quick-02 (an integrator calling `useAllowLoopbackDial()` in production) is `accept`ed as a deliberate, discoverable, Doxygen-documented opt-in, structurally identical to the project's existing `useConnectionGater<PermissiveConnectionGater>()` opt-out pattern. This mirrors how the codebase already treats explicit, single-call-site security relaxations. No new unresolved security-relevant behavior change was introduced by the fix itself — the fix is additive (a new opt-in type) and defaults to the previously-flagged-as-safe posture. No new anti-patterns or debt markers were introduced in any of the 5 files the quick task modified/created (grepped for `TBD|FIXME|XXX|TODO|HACK|PLACEHOLDER` — zero matches in `allow_loopback_dial.hpp`, `tcp_transport.hpp`, `network_injector.hpp`, `pnet_two_node_test.cpp`; `tcp_transport.cpp` retains only its pre-existing, previously-flagged `//TODO(107): Reentrancy` markers, unrelated to this change).

**Verdict:** The resolution is real, independently confirmed against the actual codebase (not SUMMARY.md/03-UAT.md narrative), and closes the gap without introducing a new concern. This phase now routes to `passed`.

### Behavioral Spot-Checks (independently re-run for this re-verification)

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Full regression rebuild succeeds | `cmake --build build --config Debug --target pnet_two_node_test dialer_test tcp_listener_test upgrader_session_test pnet_protected_connection_test pnet_injector_test host_injector_test network_injector_test -- -m` | Exit 0 | ✓ PASS |
| 8-target regression suite passes at documented pre-existing rate | `ctest --test-dir build -C Debug -R "pnet_two_node_test\|dialer_test\|tcp_listener_test\|upgrader_session_test\|pnet_protected_connection_test\|pnet_injector_test\|host_injector_test\|network_injector_test" --output-on-failure` | 7/8 binaries fully pass; `tcp_listener_test` 2/4 cases fail on pre-existing Windows/MSVC error-code mismatch (995 vs 105), unchanged from initial verification | ✓ PASS |
| `pnet_two_node_test` live loopback dial succeeds via explicit opt-in | `ctest --test-dir build -C Debug -R pnet_two_node_test --output-on-failure` | Both `TEST_F` cases `Passed`, 2.04s | ✓ PASS |
| 3 example binaries rebuild and run under EXAMPLES=ON | `cmake --build build --config Debug --target libp2p_private_network_example libp2p_connection_gater_example libp2p_private_network_gater_example -- -m` | Exit 0, all 3 built | ✓ PASS |
| PSK example unaffected | `timeout 5 build/example/05-private-network/Debug/libp2p_private_network_example.exe` | Printed listening addr, peer id, PSK-required message | ✓ PASS |
| Gater example unaffected | `timeout 5 build/example/07-connection-gater/Debug/libp2p_connection_gater_example.exe` | Printed `denylisted peer correctly rejected by the custom gater` | ✓ PASS |
| Combined PSK+gater example unaffected | `timeout 5 build/example/06-private-network-gater/Debug/libp2p_private_network_gater_example.exe` | Printed the complementary-layers explanatory message | ✓ PASS |
| No new debt markers in quick-task-modified files | Grep `TBD\|FIXME\|XXX\|TODO\|HACK\|PLACEHOLDER` on `allow_loopback_dial.hpp`, `network_injector.hpp`, `pnet_two_node_test.cpp` | Zero matches | ✓ PASS |

### Requirements Coverage (re-confirmed)

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|--------------|--------|----------|
| TEST-03 | 03-01 | Live two-node test confirms PSK-matched connect / mismatched reject | ✓ SATISFIED | `pnet_two_node_test`, independently re-run post-fix, passes |
| TEST-04 | 03-02 | New gater/pnet code delivers callbacks via scheduler, regression-guarded against reentrancy | ✓ SATISFIED | 7 tests across 4 files, independently re-run post-fix, all pass |
| DOCS-01 | 03-03 | Integrator docs: configure PSK | ✓ SATISFIED | `example/05-private-network`, re-run post-fix, unaffected |
| DOCS-02 | 03-03 | Integrator docs: register custom `ConnectionGater` | ✓ SATISFIED | `example/07-connection-gater`, re-run post-fix, unaffected |
| DOCS-03 | 03-03 | Docs: pnet + gater are complementary, non-redundant | ✓ SATISFIED | `example/06-private-network-gater`, re-run post-fix, unaffected |

`.planning/REQUIREMENTS.md` confirms all 5 marked `[x]` and `Complete` for Phase 3 (lines 34-41, 84-88). No orphaned requirements. `03-UAT-01` (the quick task's own requirement ID) is not a Phase 3 roadmap requirement and correctly does not appear in `REQUIREMENTS.md`'s Phase 3 traceability table.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `src/transport/tcp/tcp_transport.cpp` | 32, 208 | `//TODO(107): Reentrancy` | ℹ️ Info | Pre-existing, unrelated to this change (unchanged since before Phase 3) |

No new TBD/FIXME/XXX/TODO/HACK/PLACEHOLDER markers introduced by the quick task's created/modified files.

### Human Verification Required

None. The single item from the initial verification is resolved and independently confirmed.

### Gaps Summary

No gaps. All 5 ROADMAP.md Success Criteria remain independently verified (re-built and re-run, not sourced from SUMMARY.md/UAT.md claims) with no regressions introduced by the resolving quick task. The one `human_needed` item from the initial verification — the unplanned, security-relevant removal of `TcpTransport::dial()`'s loopback-rejection guard — has been resolved per the maintainer's explicit direction: secure-by-default behavior restored, made DI-configurable via a new non-aggregate `AllowLoopbackDial` type (`allow=false` baseline binding), with `pnet_two_node_test.cpp` opting in explicitly. This was independently confirmed by reading the current source (not trusting the commit message or SUMMARY), rebuilding and re-running the full regression suite and all 3 example binaries, and cross-checking that no direct `TcpTransport` construction site anywhere in the tree bypasses the new secure default.

The phase goal — proving the combined gater+pnet access-control boundary under live two-node and reentrant-callback conditions, with integrator documentation, delivered without a lingering unresolved security concern — is achieved.

---

*Verified: 2026-08-27T07:15:00Z*
*Verifier: Claude (gsd-verifier)*
