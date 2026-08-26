# Roadmap: cpp-libp2p Connection Gating & Private Networks

## Overview

This milestone adds two complementary, network-layer access-control primitives to the GNUS libp2p fork: a 5-stage `ConnectionGater` interface wired into every stage of the connection upgrade pipeline, and a PSK-based private-network (`pnet`) transport wrapper. The work proceeds in risk order — the mechanical, lower-risk gater wiring first (establishing the reentrancy-safe callback pattern the rest of the project reuses), then the pnet PSK protector (highest single-decision risk: correct wrap point below multiselect, plus a new libsodium crypto dependency), then a hardening/validation/documentation pass that proves both layers work together under live and reentrant-callback conditions and gets them in front of integrators. A node without the correct PSK or gater-level authorization ends up unable to join or communicate on the network by the end of Phase 3.

## Phases

**Phase Numbering:**

- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 1: Connection Gater interface + wiring** - Pluggable 5-stage accept/reject hooks wired into Dialer, TcpListener, and UpgraderSession, defaulting to fully permissive behavior (completed 2026-08-26)
- [ ] **Phase 2: Private network (pnet) PSK protector** - XSalsa20 PSK wrapper applied to raw connections before security negotiation, DI-configured, with a force-pnet fail-safe and private-network-scoped Kademlia bootstrap
- [ ] **Phase 3: Hardening, live validation & documentation** - Live two-node PSK test, reentrant-callback regression test, and integrator documentation for both layers

## Phase Details

### Phase 1: Connection Gater interface + wiring

**Goal**: Integrators can plug in connection-level accept/reject policy at all 5 stages of the connection lifecycle (peer dial, address dial, accept, secured, upgraded) without touching upgrade-pipeline internals, and existing hosts behave exactly as they do today when no gater is configured.
**Depends on**: Nothing (first phase)
**Requirements**: GATE-01, GATE-02, GATE-03, GATE-04, GATE-05, TEST-01
**Success Criteria** (what must be TRUE):

  1. A host built via the injector with no gater configured connects and accepts exactly as it did before this phase — the default `PermissiveConnectionGater` is behaviorally invisible to existing consumers.
  2. A gater configured to reject at `InterceptPeerDial` or `InterceptAddrDial` prevents the `Dialer` from ever opening a socket to that peer/address.
  3. A gater configured to reject `InterceptAccept` causes `TcpListener` to close the accepted socket immediately, before any security handshake bytes are exchanged.
  4. A gater configured to reject at the secured or upgraded stage causes `UpgraderSession` to cleanly tear down the in-progress connection via the existing hardened close path (no leaked sockets/threads), and the connect/accept caller receives an explicit rejection error.
  5. Gater hook callbacks are always delivered via scheduler `post`/`dispatch` rather than invoked synchronously inline, and a custom `ConnectionGater` implementation can be registered purely through a Boost.DI binding, with no source changes required to `Dialer`, `TcpListener`, or `UpgraderSession`.

**Plans**: 4/4 plans complete
Plans:
**Wave 1**

- [x] 01-01-PLAN.md — ConnectionGater interface, ConnectionGaterError enum, PermissiveConnectionGater default, DI wiring, test mock (wave 1)

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 01-02-PLAN.md — Wire ConnectionGater into DialerImpl (peer dial, addr dial, holepunch loop) + tests (wave 2)
- [x] 01-03-PLAN.md — Wire ConnectionGater into UpgraderSession (secured, upgraded) + tests (wave 2)

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 01-04-PLAN.md — Thread gater/scheduler through TcpTransport/TcpListener, gate accept, keep existing tests compiling (wave 3)

### Phase 2: Private network (pnet) PSK protector

**Goal**: A PSK-protected private-network wrapper isolates raw connections before any protocol negotiation begins, so only peers holding the matching pre-shared key can establish a usable connection, private-network hosts fail loudly rather than silently falling back to public/plaintext operation, and private-network deployments don't leak toward the public DHT via bootstrap.
**Depends on**: Phase 1 (reuses the reentrancy-safe callback pattern established there; not a hard technical dependency — pnet composes orthogonally with the gater)
**Requirements**: PNET-01, PNET-02, PNET-03, PNET-04, PNET-05, BOOT-01, TEST-02
**Success Criteria** (what must be TRUE):

  1. When a PSK is configured via DI, every raw connection — inbound and outbound — is wrapped in XSalsa20 encryption (per `/key/swarm/psk/1.0.0/`) before multiselect/security negotiation begins; a packet capture shows no protocol-ID or negotiation bytes in the clear ahead of the PSK check.
  2. Two nodes configured with the same 256-bit PSK complete the connection upgrade and exchange application data normally.
  3. A node with a missing or mismatched PSK fails to establish a usable connection to a PSK-protected peer — the attempt fails at the pnet layer and never reaches multiselect.
  4. Configuring private-network mode without a valid 256-bit PSK causes host construction to fail explicitly (an error is raised), rather than silently continuing in public/plaintext mode.
  5. In a private-network deployment, Kademlia bootstrap is scoped to the configured private-network seed peers and does not attempt to dial the default public go-libp2p bootstrap addresses.

**Plans**: TBD

### Phase 3: Hardening, live validation & documentation

**Goal**: The combined gater+pnet access-control boundary is proven under live two-node and reentrant-callback conditions — the two failure modes this codebase has historically shipped bugs in — and integrators have documentation showing how to configure and correctly combine both layers.
**Depends on**: Phase 1, Phase 2
**Requirements**: TEST-03, TEST-04, DOCS-01, DOCS-02, DOCS-03
**Success Criteria** (what must be TRUE):

  1. A live two-node test demonstrates that nodes sharing a PSK connect and exchange streams successfully, and a node with a missing/mismatched PSK is rejected and never completes the handshake.
  2. A regression test forces reentrant invocation of gater and pnet callback paths (synchronous completion during the triggering call) and confirms the code still defers via scheduler `post`/`dispatch` instead of corrupting state or reentering unsafely.
  3. Integrator documentation walks through a complete, working example of configuring a PSK for a private network.
  4. Integrator documentation walks through a complete, working example of registering a custom `ConnectionGater` implementation via DI.
  5. Documentation explicitly explains that pnet (proves network membership) and the gater (proves peer-level authorization) are complementary, non-redundant layers, illustrated with a worked "valid PSK, gater-denied peer" example.

**Plans**: TBD

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Connection Gater interface + wiring | 4/4 | Complete   | 2026-08-26 |
| 2. Private network (pnet) PSK protector | 0/TBD | Not started | - |
| 3. Hardening, live validation & documentation | 0/TBD | Not started | - |
