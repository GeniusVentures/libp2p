---
phase: 01-connection-gater-interface-wiring
verified: 2026-08-26T00:00:00Z
status: human_needed
score: 4/5 must-haves verified
behavior_unverified: 1
overrides_applied: 0
behavior_unverified_items:
  - truth: "A host built via the injector with no gater configured connects and accepts exactly as it did before this phase — the default PermissiveConnectionGater is behaviorally invisible to existing consumers (roadmap SC 1)."
    test: "Build a full Host via makeHostInjector()/makeNetworkInjector() with no ConnectionGater override, then dial and accept a real connection end-to-end, confirming the connection succeeds/behaves identically to a pre-phase build."
    expected: "Boost.DI resolves network::ConnectionGater to PermissiveConnectionGater with zero explicit binding, and the resulting Host connects/accepts with no observable behavior change from before this phase."
    why_human: "The only 3 test binaries in the repo that construct a Host/Network via the full DI graph (host_injector_test, network_injector_test, muxers_and_streams_test) all fail to build in this environment for reasons confirmed pre-existing and unrelated to ConnectionGater: host_injector_test/network_injector_test fail to LINK due to an unresolved SecMock/Boost.DI symbol inside an unrelated security-adaptor test case (byte-identical file since before commit 8640b25, the commit immediately preceding this phase); muxers_and_streams_test fails to COMPILE due to an fmt v10 formatter-strictness error on an unrelated libp2p::regression::Stats::Event type (also unmodified since 8640b25). No runnable test in this environment can currently exercise the actual Boost.DI resolution of ConnectionGater end-to-end for a real Host."
---

# Phase 01: Connection Gater Interface + Wiring Verification Report

**Phase Goal:** Integrators can plug in connection-level accept/reject policy at all 5 stages of the connection lifecycle (peer dial, address dial, accept, secured, upgraded) without touching upgrade-pipeline internals, and existing hosts behave exactly as they do today when no gater is configured.
**Verified:** 2026-08-26
**Status:** human_needed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths (Roadmap Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | A host built via the injector with no gater configured connects/accepts exactly as before; `PermissiveConnectionGater` is behaviorally invisible | ⚠️ PRESENT_BEHAVIOR_UNVERIFIED | Code review of `network_injector.hpp` confirms a single unconditional `di::bind<network::ConnectionGater>().TEMPLATE_TO<network::PermissiveConnectionGater>()` line (line 312), syntactically identical to 5 other already-working unconditional bindings in the same function. Strong supporting unit evidence: `DialerTest`'s 8 pre-existing cases still pass with a permissive `ConnectionGaterMock`; `UpgraderSessionTest`'s accept-path cases (`SecuredAcceptedProceedsToMux`, `UpgradedAcceptedInvokesHandler`) prove no behavior change on accept; `TcpListenerTest`'s 2 pre-existing cases (`ListenCloseListen`, `DoubleClose`) never reach the new `interceptAccept` code path at all (they fail only on an unrelated, pre-existing Windows/MSVC socket-error-code mismatch — see Anti-Patterns/Behavioral Spot-Checks below). No end-to-end DI-graph-resolution test (`injector.create<shared_ptr<Host>>()` actually dial/accept) could be run — see `behavior_unverified_items`. |
| 2 | A gater rejecting `InterceptPeerDial`/`InterceptAddrDial` prevents `Dialer` from ever opening a socket | ✓ VERIFIED | `test/libp2p/network/dialer_test.cpp#DialerTest.DialRejectedByPeerDialGater` and `#DialerTest.DialRejectedByAddrDialGater` — both independently re-run, pass (`dialer_test.exe`: 10/10 passing). Code review of `src/network/impl/dialer_impl.cpp` confirms `interceptPeerDial` gates `dial()` before `cmgr_->getBestConnectionForPeer`/`tmgr_->findBest` (1 call site, `grep -c interceptPeerDial` == 1) and `interceptAddrDial` gates all 3 `tr->dial(...)` sites (`rotate()` relay branch, non-relay branch, `rotateHolepunch()` loop; `grep -c interceptAddrDial` == 3). |
| 3 | A gater rejecting `InterceptAccept` causes `TcpListener` to close the socket before any security handshake bytes are exchanged | ✓ VERIFIED | `test/libp2p/transport/tcp/tcp_listener_test.cpp#TcpListenerTest.AcceptRejectedByGaterClosesConnectionWithoutUpgrading` independently re-run, passes. `StrictMock<UpgraderMock>` fails the test on any call to `upgradeToSecureInbound`, proving no handshake bytes are exchanged; the test also asserts a real client-side socket observes the server-side close. Code review of `src/transport/tcp/tcp_listener.cpp::doAccept()` confirms `interceptAccept` (1 call site) is called inside the `scheduler_->schedule(...)`-deferred lambda, with the guarded `conn->close()` happening immediately inside that same callback (no nested deferral), and `self->doAccept()` runs synchronously right after scheduling so the accept loop never stalls. |
| 4 | A gater rejecting at secured/upgraded stage causes `UpgraderSession` to cleanly tear down via the hardened close path, with an explicit rejection error surfaced to the caller | ✓ VERIFIED | `test/libp2p/transport/upgrader_session_test.cpp#UpgraderSessionTest.SecuredRejectedClosesAndDefersHandler` and `#UpgradedRejectedClosesAndDefersHandler` independently re-run, pass (`upgrader_session_test.exe`: 4/4 passing). Code review of `src/transport/impl/upgrader_session.cpp` confirms both `onSecured()` and the `upgradeToMuxed` completion lambda call `interceptSecured`/`interceptUpgraded` exactly once, close the connection guarded by `!isClosed()`, and defer `handler_(error)` via `scheduler_->schedule(...)` on rejection. Relay paths (`secureOutboundRelay`/`secureInboundRelay`) funnel through the same `onSecured()`, confirmed unchanged by code review — `p2p_relay` (whose `RelayMessageProcessor` also constructs `UpgraderSession`) builds cleanly, confirming the 4th call site is gater-aware too. |
| 5 | Gater callbacks are always delivered via scheduler `post`/`dispatch`, never synchronously inline; a custom `ConnectionGater` can be registered purely via Boost.DI, with zero source changes to `Dialer`/`TcpListener`/`UpgraderSession` | ✓ VERIFIED | Scheduler-deferral: proven by all 3 test files above, each of which pumps a `ManualSchedulerBackend` to observe that rejection-triggered callbacks are NOT delivered until the scheduler is pumped. DI override: `include/libp2p/injector/network_injector.hpp`'s `useConnectionGater<GaterImpl>()` (lines 249-253) uses `boost::di::bind<network::ConnectionGater>().template to<GaterImpl>()[boost::di::override]`, mirroring the already-established `useTransportAdaptors<>()`/`useMuxerAdaptors<>()` pattern; `DialerImpl`/`UpgraderSession`/`TcpTransport`/`TcpListener` all depend on the abstract `network::ConnectionGater` interface type only (never `PermissiveConnectionGater` concretely), so no source change to any of these 3 classes is structurally required to swap implementations. |

**Score:** 4/5 truths verified (1 present + wired, behavior-unverified)

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `include/libp2p/network/connection_gater.hpp` | `ConnectionGater` interface, 5 hooks | ✓ VERIFIED | Exactly 5 pure virtual methods (`interceptPeerDial`, `interceptAddrDial`, `interceptAccept`, `interceptSecured`, `interceptUpgraded`), all `outcome::result<void>`, matching D-01 naming |
| `include/libp2p/network/connection_gater_error.hpp` | `ConnectionGaterError` enum | ✓ VERIFIED | 5 `GATER_`-prefixed values starting at `=1`; `OUTCOME_HPP_DECLARE_ERROR` present |
| `src/network/connection_gater_error.cpp` | Error category definition | ✓ VERIFIED | Switch covers all 5 enumerators, each message contains "ConnectionGater" + hook name, plus fallthrough |
| `include/libp2p/network/impl/permissive_connection_gater.hpp` | Null Object default | ✓ VERIFIED | All 5 hooks unconditionally `return outcome::success();`, no branching |
| `test/mock/libp2p/network/connection_gater_mock.hpp` | GMock double | ✓ VERIFIED | Used successfully by `dialer_test.cpp`, `upgrader_session_test.cpp`, `tcp_listener_test.cpp` — all compile/link/pass |
| `DialerImpl` 6-arg constructor | Adds gater | ✓ VERIFIED | `dial()`/`rotate()`/`rotateHolepunch()` gated as specified; `dialer_test` 10/10 pass |
| `UpgraderSession` 5-arg constructors (both overloads) | Adds gater + scheduler | ✓ VERIFIED | `upgrader_session_test` 4/4 pass |
| `TcpTransport` 4-arg constructor | Adds gater, scheduler | ✓ VERIFIED | Threaded into `createListener()` and all 3 `UpgraderSession` sites; `p2p_tcp`/`p2p_relay` build clean |
| `TcpListener` 5-arg constructor | Adds gater, scheduler | ✓ VERIFIED | `doAccept()` restructured as specified; `tcp_listener_test` new case passes |
| `p2p_connection_gater` CMake target | New leaf library | ✓ VERIFIED | Builds cleanly, linked by `p2p_dialer`, `p2p_upgrader_session`, `p2p_tcp_listener` |
| `useConnectionGater<GaterImpl>()` | DI override helper | ✓ VERIFIED (code review only — see Truth 5/1) | Present, syntactically correct, not exercised end-to-end by a runnable test due to pre-existing environment blockers |

### Key Link Verification

| From | To | Via | Status | Details |
|------|-----|-----|--------|---------|
| `network_injector.hpp`'s unconditional `ConnectionGater` bind | `DialerImpl`/`UpgraderSession`/`TcpTransport`/`TcpListener` constructors | Boost.DI auto-resolution | ⚠️ Code-review verified, not exercised end-to-end | Same pre-existing blocker as Truth 1 |
| `src/network/CMakeLists.txt`'s `p2p_connection_gater` target | `p2p_dialer`, `p2p_upgrader_session`, `p2p_tcp_listener` | `target_link_libraries` | ✓ WIRED | Confirmed by independently building `dialer_test`, `upgrader_session_test`, `tcp_listener_test` — all link and run |
| `DialerImpl::gater_` | `interceptPeerDial()`/`interceptAddrDial()` in `dial()`/`rotate()`/`rotateHolepunch()` | Direct member calls | ✓ WIRED | `grep -c` counts match plan spec exactly (1 + 3) |
| `UpgraderSession::gater_`/`scheduler_` | `onSecured()` / `upgradeToMuxed` completion lambda | Direct member calls + `scheduler_->schedule` | ✓ WIRED | Confirmed by direct file read |
| `TcpListener::doAccept()`'s deferred lambda | `gater_->interceptAccept(...)` → guarded `conn->close()` or `UpgraderSession` construction | `scheduler_->schedule(...)` | ✓ WIRED | Confirmed by direct file read; `self->doAccept()` runs synchronously outside the deferred lambda |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Dialer gater rejection blocks transport layer | `ctest --test-dir build -R dialer_test -C Debug` (independently re-run) | 10/10 passing | ✓ PASS |
| UpgraderSession gater rejection tears down cleanly | `ctest --test-dir build -R upgrader_session_test -C Debug` (independently re-run) | 4/4 passing | ✓ PASS |
| TcpListener gater rejection closes socket pre-handshake | `ctest --test-dir build -R tcp_listener_test -C Debug` (independently re-run) | 1/3 GTest cases in this binary pass (`AcceptRejectedByGaterClosesConnectionWithoutUpgrading` passes; 2 pre-existing cases fail on an unrelated Windows `ec.value()` 995-vs-105 mismatch, confirmed byte-identical to commit 8640b25 via `git show`) | ✓ PASS (phase's own deliverable); pre-existing unrelated failures noted, not a regression |
| `p2p_relay` builds against new `UpgraderSession` constructor shape (4th call site, `RelayMessageProcessor`) | `cmake --build build --config Debug --target p2p_relay` | Build succeeded | ✓ PASS |
| Full-project build health | `cmake --build build --config Debug -- -m` | Fails; independently traced every failure to files **unmodified since commit 8640b25** (the commit immediately preceding this phase): 5 `dial()` 3-arg call sites in `tcp_integration_test.cpp` + 1 in `muxer.cpp` (`git show 8640b25:...` confirms identical 3-arg calls pre-phase), `HostMock`/stale-mock abstract-class errors in `identify_test.cpp`/`ping_test.cpp` (files untouched since well before 8640b25), C++20-designated-initializer errors in `secio_*_test.cpp`/`plaintext_adaptor_test.cpp` (untouched since before 8640b25), an fmt v10 formatter-strictness error on an unrelated `regression::Stats::Event` type in `muxers_and_streams_test.cpp` (untouched since 8640b25), and a `SecMock`/Boost.DI unresolved-symbol link failure in `host_injector_test.cpp`/`network_injector_test.cpp` (untouched since long before 8640b25) | ℹ️ Confirmed pre-existing, unrelated to this phase's changes |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|--------------|--------|----------|
| GATE-01 | 01-01 | `ConnectionGater` interface, 5 hooks | ✓ SATISFIED | `connection_gater.hpp` verified |
| GATE-02 | 01-01 | Default permissive behavior | ✓ SATISFIED (structural) / see Truth 1 for full runtime caveat | Unconditional DI bind + `PermissiveConnectionGater`; unit-level regression evidence strong, end-to-end DI resolution not runnable in this environment |
| GATE-03 | 01-02, 01-03, 01-04 | Hooks wired into `Dialer`/`TcpListener`/`Upgrader(Session)` | ✓ SATISFIED | All 3 call sites confirmed wired and tested |
| GATE-04 | 01-01 | Bind custom gater via Boost.DI | ✓ SATISFIED (structural) | `useConnectionGater<>()` present, mirrors established pattern; not exercised by a runnable end-to-end test (same pre-existing blocker) |
| GATE-05 | 01-03, 01-04 | Clean teardown, no leaked fds/threads | ✓ SATISFIED | Guarded `!isClosed()`/`close()` on every rejection path, confirmed via tests asserting `close()` invoked exactly once |
| TEST-01 | 01-02, 01-03, 01-04 | Unit tests for accept/reject at all 5 hooks | ✓ SATISFIED | `DialRejectedByPeerDialGater`, `DialRejectedByAddrDialGater`, `AcceptRejectedByGaterClosesConnectionWithoutUpgrading`, `SecuredRejectedClosesAndDefersHandler`, `UpgradedRejectedClosesAndDefersHandler` — all 5 hooks covered, all independently re-run and passing |

**Orphaned requirements:** None. All 6 requirement IDs declared in PLAN frontmatter (`GATE-01` through `GATE-05`, `TEST-01`) match REQUIREMENTS.md's Phase 1 traceability table exactly; no additional Phase-1-mapped requirement IDs exist in REQUIREMENTS.md beyond these 6.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `src/network/impl/dialer_impl.cpp` | 289 | `//TODO: Need to track all dials in a holepunch...` | ℹ️ Info | Pre-existing (verified byte-identical at commit 8640b25), not introduced by this phase; `TODO` is warning-tier, not a blocking debt marker |
| `src/transport/tcp/tcp_listener.cpp` | 51 | `// TODO(@warchant): replace with parser PRE-129` | ℹ️ Info | Pre-existing (verified at 8640b25), unrelated to gater wiring |
| `src/transport/tcp/tcp_transport.cpp` | 32, 194 | `//TODO(107): Reentrancy` | ℹ️ Info | Pre-existing (verified at 8640b25); notably this phase's own gater-rejection paths explicitly close this reentrancy gap via `scheduler_->schedule(...)` deferral, per the plans' threat models |

No `TBD`/`FIXME`/`XXX` blocker-tier debt markers found in any file this phase touches. No stub patterns (`return null`/empty handlers/hardcoded empty data flowing to output) found in any of the 5 new files or the wiring changes to `DialerImpl`/`UpgraderSession`/`TcpTransport`/`TcpListener`.

### Human Verification Required

#### 1. End-to-end DI-graph resolution of the default (unconfigured) `ConnectionGater`

**Test:** Once the pre-existing, unrelated blockers are fixed (the `SecMock`/Boost.DI link failure in `host_injector_test.cpp`/`network_injector_test.cpp`, and/or the fmt v10 formatter issue in `muxers_and_streams_test.cpp`), build a `Host`/`Network` via `makeHostInjector()`/`makeNetworkInjector()` with **no** `useConnectionGater<>()` override, and dial/accept a real connection end-to-end.

**Expected:** The connection succeeds exactly as it would have before this phase — `PermissiveConnectionGater` is resolved by Boost.DI with zero explicit binding and adds no observable friction, latency, or rejection.

**Why human:** No test binary in this repository that constructs a full Host/Network via the DI graph can currently build in this environment (confirmed via 3 independent build attempts: `host_injector_test`, `network_injector_test`, `muxers_and_streams_test`), and all 3 failures were independently traced to code unmodified since commit 8640b25 (immediately preceding this phase) — none reference `ConnectionGater`, `PermissiveConnectionGater`, or any file this phase touches. Unit-level evidence (DialerTest/UpgraderSessionTest/TcpListenerTest all showing unchanged behavior with a permissive gater) is strong but does not substitute for an actual DI-resolved `Host` connecting/accepting.

### Gaps Summary

No gaps found — no truth failed, no artifact is missing or a stub, and no key link is unwired. The single open item (Truth 1 / the DI-graph-resolution half of Truths 1 and 5) is a **present-but-behavior-unverified** item: the code is written, structurally correct by review, and mirrors an already-proven Boost.DI pattern, but cannot currently be exercised end-to-end by any runnable test in this environment because of pre-existing, unrelated build/link breakage that predates this phase (confirmed via `git show 8640b25` diffs against every failing file). This routes to human verification rather than a blocking gap, since fixing it is out of this phase's scope (per `.planning/PROJECT.md`'s explicit "Auditing/fixing the general existing test suite's health beyond what this work touches" exclusion) and the phase's own new code has no evidence of being the cause.

---

*Verified: 2026-08-26*
*Verifier: Claude (gsd-verifier)*
