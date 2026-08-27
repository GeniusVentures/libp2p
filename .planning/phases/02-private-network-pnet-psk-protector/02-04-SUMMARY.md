---
phase: 02-private-network-pnet-psk-protector
plan: 04
subsystem: injector / network
tags: [pnet, boost-di, usePrivateNetwork, bootstrap-refusal, fail-fast]

requires:
  - phase: 02-private-network-pnet-psk-protector
    provides: "PnetProtectedConnection (02-03), Psk/PnetError (02-02)"
provides:
  - "libp2p::transport::PnetUpgraderDecorator — wraps both RawSPtr upgrade paths before multiselect; relay/muxed pass through (documented limitation)"
  - "libp2p::injector::usePrivateNetwork(key) combined DI module + PskValidationError (eager, pre-injector throw)"
  - "libp2p::security::pnet::PskHandle — copyable DI-bindable holder for the move-only Psk"
  - "DialerImpl nullable psk ctor param + public-bootstrap dial refusal (PNET_PUBLIC_BOOTSTRAP_REFUSED, SL_DEBUG, scheduler-deferred)"
  - "CMake target p2p_pnet_upgrader; test targets pnet_upgrader_decorator_test, pnet_injector_test; dialer_test extended (4 new cases)"
affects: [03-integration-validation]

tech-stack:
  added: []
  patterns:
    - "Boost.DI value-instance binding via a copyable Handle struct for move-only secret types"
    - "Dial-time policy refusal mirroring the Phase 1 gater refusal block (SL_DEBUG + scheduler_->schedule + return)"

key-files:
  created:
    - include/libp2p/transport/impl/pnet_upgrader_decorator.hpp
    - src/transport/impl/pnet_upgrader_decorator.cpp
    - test/libp2p/security/pnet/pnet_upgrader_decorator_test.cpp
    - test/libp2p/security/pnet/pnet_injector_test.cpp
  modified:
    - include/libp2p/injector/network_injector.hpp
    - include/libp2p/security/pnet/psk.hpp
    - include/libp2p/network/impl/dialer_impl.hpp
    - src/network/impl/dialer_impl.cpp
    - test/libp2p/network/dialer_test.cpp
    - test/libp2p/security/pnet/CMakeLists.txt
    - test/libp2p/network/CMakeLists.txt
    - src/transport/impl/CMakeLists.txt

key-decisions:
  - "PskHandle (copyable, holds shared_ptr<const Psk>) introduced because Boost.DI forbids smart-pointer bind types AND its instance scope requires copyable types — the move-only Psk satisfies neither; absence of a PskHandle binding remains the public-mode signal (D-08 preserved)"
  - "The DI smoke test composes the REAL makeNetworkInjector (not a reduced graph) — decorator resolution, 32-byte Psk, and public-mode negative all verified against the full network graph on MSVC"
  - "Bootstrap match = dnsaddr/bootstrap.libp2p.io string containment (primary; also catches ny5/sg1/am6/sv15 subdomain forms) + advisory constexpr peer-ID snapshot transcribed from the LIVE dnsaddr TXT records (2026-08-26), per A3"
  - "Relay upgrade overloads pass through unwrapped — header doc comment states the limitation explicitly (research A4)"
  - "usePrivateNetwork text dispatch order: swarm-key framing → base16 → base64; report error fixed to PNET_INVALID_PSK_FORMAT when all shapes fail"

patterns-established:
  - "usePrivateNetwork(key) module shape: validate-then-bind, eager throw, single combined injector (D-07) — the GNUS integrator-facing API for private networks"

requirements-completed: [PNET-01, PNET-04, PNET-05, BOOT-01, TEST-02]

coverage:
  - id: D1
    description: "upgradeToSecureOutbound/Inbound wrap the raw conn in PnetProtectedConnection before the inner upgrader (dynamic-cast asserted at the security adaptor)"
    requirement: PNET-01
    verification:
      - kind: unit
        ref: "test/libp2p/security/pnet/pnet_upgrader_decorator_test.cpp#PnetUpgraderDecoratorTest.OutboundWrapsInProtectedConnection"
        status: pass
      - kind: unit
        ref: "test/libp2p/security/pnet/pnet_upgrader_decorator_test.cpp#PnetUpgraderDecoratorTest.InboundWrapsInProtectedConnection"
        status: pass
  - id: D2
    description: "Relay overload passes the SAME stream pointer through unwrapped (identity assertion)"
    requirement: PNET-01
    verification:
      - kind: unit
        ref: "test/libp2p/security/pnet/pnet_upgrader_decorator_test.cpp#PnetUpgraderDecoratorTest.RelayPassesThroughUnwrapped"
        status: pass
  - id: D3
    description: "usePrivateNetwork(validKey) → real injector graph resolves PnetUpgraderDecorator + 32-byte Psk; invalid key throws PskValidationError eagerly at module call"
    requirement: PNET-04
    verification:
      - kind: unit
        ref: "test/libp2p/security/pnet/pnet_injector_test.cpp#PnetInjectorTest.ValidKeyResolvesDecoratorAndPsk"
        status: pass
      - kind: unit
        ref: "test/libp2p/security/pnet/pnet_injector_test.cpp#PnetInjectorTest.RawKeyShapesAccepted"
        status: pass
      - kind: unit
        ref: "test/libp2p/security/pnet/pnet_injector_test.cpp#PnetInjectorTest.InvalidKeyThrowsEagerly"
        status: pass
  - id: D4
    description: "Injector WITHOUT the module = public mode identical to today (plain UpgraderImpl)"
    requirement: PNET-04
    verification:
      - kind: unit
        ref: "test/libp2p/security/pnet/pnet_injector_test.cpp#PnetInjectorTest.AbsenceIsPublicMode"
        status: pass
  - id: D5
    description: "With a PSK: bootstrap-address dials and bootstrap-peer-ID dials refused (transport Times(0), PNET_PUBLIC_BOOTSTRAP_REFUSED via scheduler); ordinary peers proceed"
    requirement: BOOT-01
    verification:
      - kind: unit
        ref: "test/libp2p/network/dialer_test.cpp#DialerTest.PskRefusesBootstrapAddressDial"
        status: pass
      - kind: unit
        ref: "test/libp2p/network/dialer_test.cpp#DialerTest.PskRefusesBootstrapPeerIdDial"
        status: pass
      - kind: unit
        ref: "test/libp2p/network/dialer_test.cpp#DialerTest.PskAllowsOrdinaryPeerDial"
        status: pass
  - id: D6
    description: "Without a PSK: bootstrap dials proceed exactly as before (public mode untouched)"
    requirement: PNET-05
    verification:
      - kind: unit
        ref: "test/libp2p/network/dialer_test.cpp#DialerTest.NoPskAllowsBootstrapDial"
        status: pass
---

# Plan 02-04 Summary: DI wiring + dial-time bootstrap refusal

## Accomplishments

- **`PnetUpgraderDecorator`** (`p2p_pnet_upgrader` leaf, p2p_upgrader stays pnet-free): wraps both RawSPtr upgrade paths in `PnetProtectedConnection` before multiselect; relay overloads + `upgradeToMuxed` pass through with the limitation documented in the header.
- **`usePrivateNetwork(key)`** (network_injector.hpp): single combined module (D-07) — validates via swarm-key/base16/base64 dispatch, throws `PskValidationError` eagerly on any invalid key (before injector assembly — PNET-05), then binds `PskHandle` + rebinds `Upgrader`→`PnetUpgraderDecorator` with `[boost::di::override]`. Plus the exception-free `usePrivateNetwork(Psk)` overload.
- **`PskHandle`**: copyable holder introduced to make the move-only Psk bindable in Boost.DI (see key decisions). Absence of binding = public mode (D-08 untouched — no default binding added to makeNetworkInjector).
- **`DialerImpl`**: appended nullable `psk = nullptr` ctor param after gater; dial-time refusal block mirrors the Phase 1 gater refusal (SL_DEBUG with peer id + address only, scheduler-deferred error callback): dnsaddr containment (primary) + live-transcribed peer-ID snapshot (advisory).
- **Tests**: decorator method-coverage matrix (3 cases incl. dynamic-cast wrap asserts and relay identity), DI smoke against the REAL `makeNetworkInjector` graph (4 cases), dialer extension (4 cases). Full phase regression: 7 suites, all passing (xsalsa20, psk, protected connection, decorator, injector, dialer, upgrader_session from Phase 1).

## Deviations from Plan

**[Rule 3 - DI constraint] PskHandle indirection** — Found during: Task 2 | Issue: plan assumed `bind<std::shared_ptr<const Psk>>()`; Boost.DI rejects smart-pointer bind types (`has_disallowed_qualifiers`) AND instance scope needs copyable types, but Psk is move-only by design (D-06) | Fix: copyable `PskHandle{ shared_ptr<const Psk> psk; }` bound by value; consumers pull `handle.psk` | Files: psk.hpp, network_injector.hpp, pnet_upgrader_decorator.* | Verification: pnet_injector_test passes against the real graph | Commits: dead09f

**[Rule 1 - Bug] Fabricated-then-corrected bootstrap IDs** — Found during: Task 3 | Issue: my first snapshot attempt reconstructed peer IDs from memory and produced corrupted strings | Fix: transcribed from the LIVE dnsaddr TXT records (`Resolve-DnsName _dnsaddr.bootstrap.libp2p.io`) — 4 verified current IDs; per A3 snapshot is advisory anyway | Files: dialer_impl.cpp | Verification: PskRefusesBootstrapPeerIdDial uses the transcribed ID | Commit: 3250d36

**Total deviations:** 2 auto-fixed. **Impact:** none on requirements; PskHandle is now the documented DI pattern for secret value types.

## DI verification substitution

**None taken.** The DI smoke test composes the real `makeNetworkInjector()` with the module applied (linked via `p2p_default_network` + `p2p_cares`, the same set the existing network_injector_test uses), so decorator resolution, Psk size, and public-mode negatives are all verified against the genuine full network graph on MSVC. Phase 3 live end-to-end validation remains the plan-of-record for runtime behavior (two-node swarm), but no wiring assumption is left static-unverified.

## Notes for Phase 3

- End-to-end: `makeHostInjector(usePrivateNetwork(swarm_key_text))` is the complete GNUS integration surface.
- The bootstrap refusal covers dial(); identify/kademlia-initiated connections traverse DialerImpl too (same gate), but a live two-node test should confirm no other dial entry point bypasses it.
- Relay streams remain unwrapped (A4) — revisit only if SuperGenius adopts circuit relay in private networks.

## Self-Check: PASSED

- [x] All tasks executed (3/3), committed (8cd78e7, dead09f, 3250d36)
- [x] Decorator ctor takes concrete `shared_ptr<UpgraderImpl>`; wraps exactly the two RawSPtr methods; relay/muxed identity pass-through with documented rationale
- [x] `p2p_pnet_upgrader` separate leaf; p2p_upgrader source list unchanged
- [x] usePrivateNetwork binds PskHandle + Upgrader rebind in ONE make_injector (D-07); no default Psk binding in the base injector (D-08)
- [x] Invalid key throws from the module call itself (EXPECT_THROW verified)
- [x] dialer refusal block contains SL_DEBUG + scheduler_->schedule + PNET_PUBLIC_BOOTSTRAP_REFUSED; no key bytes logged
- [x] Bootstrap match set = dnsaddr containment + constexpr peer-ID list
- [x] All suites pass: 7/7 (regression incl. Phase 1 upgrader_session_test)
