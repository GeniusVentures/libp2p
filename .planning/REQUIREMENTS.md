# Requirements: cpp-libp2p Connection Gating & Private Networks

**Defined:** 2026-08-26
**Core Value:** A node without the correct network credentials (matching PSK, or passing gater policy) must be unable to join or communicate on a private SuperGenius network — access control is enforced at the network layer, not left to the application layer.

## v1 Requirements

Requirements for initial release. Each maps to roadmap phases.

### Connection Gater

- [x] **GATE-01**: Library exposes a `ConnectionGater` interface with 5 intercept hooks: peer dial, address dial, accept, secured, upgraded
- [x] **GATE-02**: Default (unconfigured) behavior is fully permissive — existing hosts behave identically to today when no gater is set
- [x] **GATE-03**: Gater hooks are wired into the actual dial, accept, and upgrade code paths (`Dialer`, `TcpListener`/`ListenerManager`, `Upgrader`/`UpgraderSession`) so a configured gater can reject a connection at each of the 5 stages
- [x] **GATE-04**: Integrators can bind a custom `ConnectionGater` implementation via the existing Boost.DI injector pattern
- [ ] **GATE-05**: A gater rejection at any stage cleanly tears down the in-progress connection (socket closed, no leaked fds/threads) using the existing hardened connection-close paths

### Private Networks (pnet)

- [ ] **PNET-01**: A PSK-protected connection wrapper is applied to raw connections before security/multiselect negotiation begins
- [ ] **PNET-02**: The PSK wrapper implements the libp2p pnet spec (`/key/swarm/psk/1.0.0/`, XSalsa20 stream cipher, 256-bit key)
- [ ] **PNET-03**: A connection between peers with mismatched or missing PSKs fails to establish a usable connection
- [ ] **PNET-04**: The PSK is configured via Boost.DI, not hardcoded
- [ ] **PNET-05**: If private-network mode is configured without a valid 256-bit PSK, host construction fails explicitly rather than silently falling back to public/plaintext operation (force-pnet fail-safe)

### Bootstrap Scoping

- [ ] **BOOT-01**: Kademlia bootstrap/seed peer configuration can be scoped to a known set of private-network peers, so DHT bootstrap doesn't attempt to dial public go-libp2p bootstrap addresses in private-network deployments

### Testing

- [x] **TEST-01**: Unit tests validate accept and reject behavior at each of the 5 gater hooks
- [ ] **TEST-02**: Unit tests validate PSK accept/reject behavior at the pnet boundary
- [ ] **TEST-03**: A live two-node test confirms peers sharing a PSK connect successfully, and a peer with a missing/mismatched PSK is rejected
- [ ] **TEST-04**: New gater/pnet code delivers callbacks via the scheduler (`post`/`dispatch`) rather than invoking inline, with a regression test guarding against reentrant invocation

### Documentation

- [ ] **DOCS-01**: Integrator documentation explains how to configure a PSK for a private network
- [ ] **DOCS-02**: Integrator documentation explains how to register a custom `ConnectionGater` implementation
- [ ] **DOCS-03**: Documentation clarifies that pnet and the gater are complementary layers (PSK proves network membership, gater proves peer-level authorization) — not redundant

## v2 Requirements

Deferred to future release. Tracked but not in current roadmap.

### Policy

- **POLICY-01**: Reference `ConnectionGater` policy implementation (e.g. allow-list, deny-by-default) — deferred; integrators implement their own via the DI extension point for now
- **POLICY-02**: Per-IP inbound rate limiting at `InterceptAccept`
- **POLICY-03**: Persistent/dynamic-mutation block-list (datastore-backed, runtime add/remove)

## Out of Scope

Explicitly excluded. Documented to prevent scope creep.

| Feature | Reason |
|---------|--------|
| Full peer-scoring / reputation system | Massive scope increase (persistent state, tuning, decay curves); PSK + gater already covers the permissioned-network access-control need without behavioral scoring |
| go-libp2p wire-level interop testing for pnet/gating | Private networks aren't expected to bootstrap against public go-libp2p peers; the PSK implementation still follows the libp2p pnet spec for future compatibility, but cross-implementation interop suites aren't built |
| Upstreaming to `libp2p/cpp-libp2p` | Fork has diverged too far (C++17 here vs. C++20 upstream) and already carries features upstream lacks; not worth reconciling |
| Re-enabling the mplex muxer | Stays disabled; unrelated to gating/pnet |
| Auditing/fixing the general existing test suite's health beyond what this work touches | Current pass/fail state of the broader suite is unknown; out of scope beyond validating the code this project actually adds or touches |

## Traceability

Which phases cover which requirements. Updated during roadmap creation.

| Requirement | Phase | Status |
|-------------|-------|--------|
| GATE-01 | Phase 1 | Complete |
| GATE-02 | Phase 1 | Complete |
| GATE-03 | Phase 1 | Complete |
| GATE-04 | Phase 1 | Complete |
| GATE-05 | Phase 1 | Pending |
| PNET-01 | Phase 2 | Pending |
| PNET-02 | Phase 2 | Pending |
| PNET-03 | Phase 2 | Pending |
| PNET-04 | Phase 2 | Pending |
| PNET-05 | Phase 2 | Pending |
| BOOT-01 | Phase 2 | Pending |
| TEST-01 | Phase 1 | Complete |
| TEST-02 | Phase 2 | Pending |
| TEST-03 | Phase 3 | Pending |
| TEST-04 | Phase 3 | Pending |
| DOCS-01 | Phase 3 | Pending |
| DOCS-02 | Phase 3 | Pending |
| DOCS-03 | Phase 3 | Pending |

**Coverage:**

- v1 requirements: 18 total
- Mapped to phases: 18 (100%)
- Unmapped: 0 ✓

---
*Requirements defined: 2026-08-26*
*Last updated: 2026-08-26 after roadmap creation*
