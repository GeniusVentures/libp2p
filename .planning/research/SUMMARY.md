# Project Research Summary

**Project:** SuperGenius libp2p fork
**Confidence:** MEDIUM

## Executive Summary

This project adds two complementary access-control primitives to a Boost.DI-wired C++17 libp2p fork: a 5-stage `ConnectionGater` interface (peer/address/accept/secured/upgraded checkpoints, ported from go-libp2p's canonical shape) and a PSK-based private-network (`pnet`) transport wrapper using XSalsa20 encryption per the libp2p spec (`/key/swarm/psk/1.0.0/`).

The recommended approach: implement the gater as a single DI-bound interface (matching the existing `SecurityAdaptor`/`MuxerAdaptor`/`TransportAdaptor` pattern) wired into exactly three call sites already identified by direct source reads (`DialerImpl::dial`/`rotate`, `TcpListener::doAccept`, `UpgraderSession::onSecured`), defaulting to a genuine DI-bound no-op `PermissiveConnectionGater` (never ad hoc null checks).

The key risks are all integration risks, not design risks: (1) partial/inconsistent gater wiring across the 3 distant call sites, (2) wrapping pnet in the wrong place (post-negotiation, leaking protocol IDs), (3) reproducing this codebase's known reentrant-synchronous-callback anti-pattern (`TODO(107)`) in new gater/PSK code, and (4) treating PSK possession as full peer authorization when it only proves network membership, not identity.

## Key Findings

### Recommended Stack

The core stack decision here is narrow but non-optional: the pnet spec mandates XSalsa20 (256-bit key, 192-bit nonce, no MAC), which OpenSSL does not implement in any version. The team must add libsodium (recommended, `crypto_stream_xsalsa20_xor`) or Crypto++ as an alternative, or vendor a small standalone XSalsa20 implementation as go-libp2p itself does.

**Core technologies:**
- **libp2p pnet spec v1** (`/key/swarm/psk/1.0.0/`) — fixed wire protocol, not a design choice
- **XSalsa20 via libsodium** — the one cryptographic primitive OpenSSL lacks; add via Hunter
- **go-libp2p's 5-hook ConnectionGater shape** — the ecosystem-standard interface pattern to port

### Expected Features

**Must have (table stakes, v1/launch):**
- 5-stage ConnectionGater interface wired into Dialer, ListenerManager/TcpListener, Upgrader/UpgraderSession
- Default no-op/allow-all gater (DI-bound null object, not ad hoc checks)
- DI binding for custom ConnectionGater implementations
- PSK-based pnet wrapper applied before security negotiation, spec-compliant XSalsa20
- Pnet fails closed on PSK mismatch
- PSK configuration via DI
- Unit tests for accept/reject at each hook + live two-node PSK match/mismatch test
- Integrator documentation for PSK config + custom gater registration

**Should have (differentiators, v1.x):**
- Reference allow-list ConnectionGater implementation (deny-by-default, peer-ID/pubkey membership) — go-libp2p's own BasicConnectionGater is deny-list only; GNUS actually needs an allow-list
- Force-pnet fail-safe (refuse to start without valid PSK in private-network mode)
- Kademlia bootstrap list scoped to private-network seed peers

**Defer (v2+):**
- Per-IP inbound rate limiting at InterceptAccept
- Persistent/dynamic-mutation block-list (datastore-backed, runtime add/remove)
- Full peer-scoring/reputation system

### Architecture Approach

The fork's connection pipeline (RawConnection -> SecureConnection -> CapableConnection, funneled through a single Upgrader) already structurally mirrors go-libp2p's shape, making this a low-risk integration with confirmed, exact insertion points verified by direct source reads. The gater is a single DI-bound interface, not 5 separate callables, injected into DialerImpl (hooks 1-2), TcpListener (hook 3), and UpgraderSession (hooks 4-5). The pnet PSK wrapper is implemented as one PnetUpgraderDecorator wrapping the real Upgrader, applying a PnetProtectedConnection to raw connections before delegating - the only insertion point that covers both inbound and outbound paths without touching TcpTransport, TcpListener, or UpgraderSession, and correctly sits below multistream-select per spec.

**Major components:**
1. network::ConnectionGater (new interface) - 5 pure-virtual hooks, DI-bound singleton, default PermissiveConnectionGater
2. security::pnet::PnetProtectedConnection (new, RawConnection decorator) - XSalsa20 encrypt/decrypt on read/write
3. transport::impl::PnetUpgraderDecorator (new, Upgrader decorator) - wraps raw connections in the PSK layer before delegating to UpgraderImpl
4. security::pnet::Psk (new, dedicated non-copyable type) - validated 32-byte key holder with explicit zeroing destructor

### Critical Pitfalls

1. **Gating only some of the 5 stages / inconsistent wiring** - the 5 hooks live in 3 structurally distant files; treat this as one feature with a 20-cell test matrix (5 hooks x accept/reject x in/out), not 3 independent PRs.
2. **PSK wrapped after (not before) multistream/security negotiation** - leaks protocol IDs to non-PSK-holders and defeats the spec's design goal. Implement pnet strictly as a pre-Upgrader raw-connection transform, never as a SecurityAdaptor participating in multiselect. Highest recovery cost if gotten wrong (near-redesign).
3. **Reentrant synchronous callback invocation** - this codebase already has 10 open TODO(107) reentrancy sites; new gater/PSK code copying the adjacent style will reproduce the exact defect class that caused prior race/deadlock fixes. Route all gater/pnet callback delivery through scheduler post, never call inline.
4. **PSK-only access control mistaken for peer authentication** - PSK proves network membership, not identity; document pnet + gater as complementary layers, and add a test case for "valid PSK, gater-denied peer."
5. **Gater-driven teardown reintroducing TCP teardown races** - route gater-rejection closes through the same hardened TcpConnection close path, not an ad hoc socket close; test explicitly on Windows.

## Implications for Roadmap

Based on research, suggested phase structure:

### Phase 1: ConnectionGater interface + wiring skeleton
**Rationale:** Establishes the interface contract and all 5 call sites before any policy logic exists, so the wired-consistently property is baked in structurally rather than retrofitted. Lowest-risk phase to validate the DI pattern fit.
**Delivers:** ConnectionGater interface, PermissiveConnectionGater default, DI bindings in network_injector.hpp, all 5 hooks wired into DialerImpl, TcpListener, UpgraderSession with reentrancy-safe (post-deferred) callback delivery.
**Addresses:** 5-stage interface, default no-op gater, DI binding for custom implementations (P1 table stakes).
**Avoids:** Pitfall 1 (inconsistent wiring), Pitfall 5 (InterceptAccept checked too late), Pitfall 6 (reentrant callbacks), Pitfall 10 (ad hoc null-gater checks).

### Phase 2: pnet PSK protector
**Rationale:** Depends on the crypto-dependency decision (libsodium) but is otherwise independent of Phase 1's gater wiring - the two compose orthogonally. Sequenced second because it has the highest single-decision risk (wrap point correctness) and highest recovery cost if wrong.
**Delivers:** Psk type (validated, zeroing, non-copyable), PnetProtectedConnection (RawConnection decorator), PnetUpgraderDecorator (Upgrader decorator), DI wiring (usePrivateNetwork helper), spec-compliant nonce handshake.
**Uses:** libsodium crypto_stream_xsalsa20_xor, Upgrader-decorator pattern.
**Avoids:** Pitfall 2 (wrap point correctness), Pitfall 3 (PSK key material handling).

### Phase 3: Reference policy implementations + fail-safes
**Rationale:** Both the allow-list gater and the force-pnet fail-safe are cheap once Phases 1-2 exist, and they are the actual policies GNUS will run in production. Sequenced after the base primitives are proven so policy bugs don't get conflated with wiring bugs.
**Delivers:** Allow-list ConnectionGater (deny-by-default, checked at InterceptPeerDial provisionally and InterceptSecured authoritatively), force-pnet fail-safe, Kademlia bootstrap list scoping to private seed peers.

### Phase 4: Hardening, concurrency validation, and documentation
**Rationale:** This codebase's history shows race/deadlock bugs are discovered late and expensively, typically only via manual/ASan testing rather than committed regression suites - make concurrency and teardown validation an explicit phase.
**Delivers:** TSan-enabled concurrent stress tests, Windows + POSIX teardown coverage for the gater-reject path, wire-capture regression test proving no protocol-ID leakage pre-PSK-check, PSK-never-logged grep/CI check, integrator documentation.
**Addresses:** Unit + live two-node accept/reject tests, integrator documentation (P1 table stakes carried through to completion).

### Phase Ordering Rationale

- Gater wiring comes first because it's the lower-risk, more mechanical piece and establishes the DI/testing conventions the rest of the work reuses.
- pnet comes second because its single wrap-point decision is the highest-consequence design choice in the whole project (Pitfall 2's recovery cost is rated HIGH) and deserves focused attention without also juggling gater policy logic.
- Policy implementations (allow-list, force-pnet) are deliberately separated from the base-primitive phases so "does the interface/wrap work correctly" and "is the production policy correct" are validated independently.
- Hardening is its own phase rather than folded into each preceding phase because this codebase's documented failure mode is specifically skipping concurrency/teardown validation under time pressure; making it a named, gated phase counters that pattern directly.

### Research Flags

Phases likely needing deeper research during planning:
- **Phase 2 (pnet PSK protector):** Needs research-phase treatment for the exact libsodium API integration and Hunter dependency pinning specifics (CMake config, compiler-matrix verification for Crypto++ fallback if chosen) - unverified against this project's specific compiler baseline (GCC 7.4/Clang 6.0.1).
- **Phase 4 (hardening):** Needs research/planning attention for how to structure TSan stress tests and Windows-specific teardown CI given this codebase has no existing automated regression coverage for its prior race fixes.

Phases with standard patterns (skip research-phase):
- **Phase 1 (gater interface + wiring):** Well-documented go-libp2p reference pattern, exact call sites already confirmed via direct source reads.
- **Phase 3 (policy implementations):** Standard, low-complexity inversions of already-established patterns.

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | MEDIUM | No context7/curated package registry source for this spec; cross-verified across 2+ independent sources per claim, core protocol facts checked against fetched primary sources. |
| Features | MEDIUM | No single HIGH-confidence primary source fetched in full, but every load-bearing claim corroborated across 3+ independent sources. |
| Architecture | MEDIUM-HIGH | go-libp2p reference architecture is MEDIUM (WebSearch-derived); this-codebase mapping is HIGH (direct source reads). |
| Pitfalls | MEDIUM-HIGH | Ecosystem/spec pitfall claims are MEDIUM; this-codebase-specific pitfalls (reentrancy, teardown races, concurrency) are HIGH, grounded directly in source reads and CONCERNS.md. |

**Overall confidence:** MEDIUM-HIGH

### Gaps to Address

- **Crypto++ compiler-matrix verification:** If libsodium is rejected in favor of Crypto++, no CI check was found confirming the pinned Crypto++ 8.x Hunter recipe builds against this project's minimum supported compilers - verify during Phase 2 implementation.
- **No compiler/CI-verified precedent for TSan stress testing in this repo:** Phase 4's TSan stress-test approach has no existing pattern to follow in this codebase and will need to be designed from scratch during planning.
- **PSK swarm-key file format vs. DI-only config:** Decide during Phase 2 planning whether on-disk swarm.key format parsing is in scope for v1 or deferred.
- **Thread-model assumptions for gater/PSK state:** Multi-threaded io_context::run() is a supported configuration in this codebase; Phase 4 should validate against actual GNUS deployment configuration.

## Sources

### Primary (HIGH confidence)
- src/network/impl/dialer_impl.cpp, src/transport/tcp/tcp_listener.cpp, src/transport/tcp/tcp_transport.cpp, src/transport/impl/upgrader_impl.cpp, src/transport/impl/upgrader_session.cpp, include/libp2p/connection/raw_connection.hpp, include/libp2p/transport/upgrader.hpp, include/libp2p/injector/network_injector.hpp, src/security/plaintext/plaintext.cpp - this codebase, read directly
- .planning/codebase/CONCERNS.md, .planning/codebase/ARCHITECTURE.md, .planning/codebase/TESTING.md, .planning/PROJECT.md - project context, read in full
- libp2p/specs Private-Networks-PSK-V1.md (https://github.com/libp2p/specs/blob/master/pnet/Private-Networks-PSK-V1.md) - official spec, fetched raw content directly

### Secondary (MEDIUM confidence)
- go-libp2p core/connmgr/gater.go, p2p/net/pnet/protector.go and psk_conn.go, p2p/net/conngater package docs
- Kubuxu's pnet design gist - cipher selection rationale, LIBP2P_FORCE_PNET fail-safe rationale
- libp2p/specs Issue #489 - deprecate pnet/PSK proposal
- libp2p/go-libp2p-pnet Issue #3 - nonce exhaustion and bridging
- go-libp2p PR #881 - implement connection gating at top level
- go-libp2p-quic-transport PR #152 - real-world source of "InterceptAccept checked too late" pitfall
- OpenSSL GitHub Discussion #24519 - confirms no native Salsa20/XSalsa20 EVP cipher
- libsodium docs, Hunter package docs (libsodium/cryptopp) - dependency integration details
- rust-libp2p and js-libp2p docs/crates - cross-implementation confirmation

### Tertiary (LOW confidence)
- None - all research files report every load-bearing claim was corroborated across 2+ independent sources.

---
*Research completed: 2026-08-25*
*Ready for roadmap: yes*
