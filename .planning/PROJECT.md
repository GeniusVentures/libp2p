# cpp-libp2p Connection Gating & Private Networks

## What This Is

This is GNUS/GeniusNetwork's fork of cpp-libp2p (C++17), the peer-to-peer networking library underlying "SuperGenius" networks. This project adds two access-control primitives the fork currently lacks — a **Connection Gater** (pluggable accept/reject hooks at each stage of the connection upgrade pipeline) and **Private Networks / pnet** (PSK-protected swarm isolation) — so GNUS can run permissioned, private SuperGenius networks where only nodes with the right credentials can join.

Originates from [GeniusVentures/libp2p#10](https://github.com/GeniusVentures/libp2p/issues/10).

## Core Value

A node without the correct network credentials (matching PSK, or passing gater policy) must be unable to join or communicate on a private SuperGenius network — access control is enforced at the network layer, not left to the application layer.

## Requirements

### Validated

<!-- Inferred from existing codebase — .planning/codebase/ARCHITECTURE.md -->

- ✓ TCP transport with raw→secure→muxed connection upgrade pipeline (`Upgrader`/`UpgraderSession`) — existing
- ✓ Pluggable security adaptors (noise, secio, tls, plaintext) — existing
- ✓ Pluggable muxers (yamux primary; mplex present but disabled) — existing
- ✓ Boost.DI-based dependency injection wiring the full host/network object graph — existing
- ✓ Protocol suite: kademlia, gossipsub, identify, autonat, relay, holepunch, ping — existing
- ✓ Kademlia bootstrap interop with go-libp2p peers (used for public network discovery) — existing
- ✓ Live two-node test: nodes sharing a PSK connect successfully; a peer with a missing/mismatched PSK is rejected — Validated in Phase 3 (`test/acceptance/p2p/pnet/pnet_two_node_test.cpp`, TEST-03)
- ✓ Integrator documentation: how to configure a PSK and register a custom `ConnectionGater` — Validated in Phase 3 (`example/05-private-network/`, `example/06-private-network-gater/`, `example/07-connection-gater/`, DOCS-01/02/03)

### Active

- [ ] Connection Gater interface with 5 intercept hooks: peer dial, address dial, accept, secured, upgraded
- [ ] Default no-op gater behavior — preserves existing behavior when no gater is configured
- [ ] Gater wired into `Dialer` (peer/addr dial stages), `ListenerManager`/`TcpListener` (accept stage), `Upgrader`/`UpgraderSession` (secured/upgraded stages)
- [ ] DI binding for custom `ConnectionGater` implementations, following the existing adaptor pattern in `include/libp2p/injector/`
- [ ] PSK-based private network (pnet) wrapper applied before security negotiation
- [ ] Pnet rejects connections from peers without the matching PSK
- [ ] PSK configuration via DI
- [ ] Unit tests validating accept/reject logic at each gater hook and at the pnet boundary

### Out of Scope

- Upstreaming to `libp2p/cpp-libp2p` — the fork has diverged too far (C++17 here vs. C++20 upstream) and already carries features upstream lacks (autonat, holepunching, circuit relay); reconciling isn't worth it
- go-libp2p wire-level interop testing for pnet/gating — a private network isn't expected to bootstrap against public go-libp2p peers, so this isn't tested, though the PSK implementation still follows the libp2p pnet spec for compatibility
- Auditing/fixing the general existing test suite's health beyond what this work touches — its current pass/fail state is unknown; GNUS's primary current libp2p usage path is via `ipfs-pubsub` (gossip), not the broader libp2p test/example surface
- Re-enabling the mplex muxer — stays disabled; unrelated to this work

## Context

- This is a git submodule (`thirdparty/libp2p`) inside the GeniusNetwork monorepo. It has its own `.planning/` scoped to this project, independent of the parent monorepo's GSD project ("GNUS Child Wallet").
- GNUS's primary current usage of this library is through `ipfs-pubsub` (gossip protocol) in `thirdparty/`, not the wider libp2p API surface — confidence in the existing test suite's overall health is low.
- The codebase has a documented history of concurrency bugs (races, deadlocks, ASan failures) concentrated in the scheduler, yamux muxer, and TCP transport/connection teardown — see `.planning/codebase/CONCERNS.md`. Recent commits (`d26b61b`, `78a845b`, `af85794`) reactively patched several of these.
- 10 unresolved `TODO(107): Reentrancy` markers exist across TCP transport, plaintext/secio security, and mplex — some of this surface overlaps with code this project touches (TCP transport, `Upgrader` path).
- Full architecture reference: `.planning/codebase/ARCHITECTURE.md`. Connections progress through explicit stages — `RawConnection` → `SecureConnection` → `CapableConnection` — each represented by its own interface; this is exactly where the 5 gater hooks and the pnet wrapper attach.

## Constraints

- **Language standard**: C++17 — rules out borrowing patterns or code from upstream cpp-libp2p that assume C++20.
- **Dependency injection**: New bindings (gater, PSK config) must follow the existing Boost.DI adaptor pattern in `include/libp2p/injector/*.hpp` — no direct `new`/`make_shared` construction outside the DI graph.
- **Upgrade pipeline integration**: Gater hooks must integrate with the existing `RawConnection` → `SecureConnection` → `CapableConnection` progression through `Upgrader`/`UpgraderSession` — no bypassing it with parallel/manual negotiation logic.
- **Spec compliance**: The pnet/PSK implementation should follow the libp2p pnet spec even though go-libp2p interop isn't a near-term requirement, to preserve future compatibility.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Build both Connection Gater and pnet in one project | Together they form a single access-control boundary for private SuperGenius networks | — Pending |
| Not pursuing upstream contribution to cpp-libp2p | Fork has diverged too far (C++17 vs C++20, extra features already built); not worth reconciling | — Pending |
| Fix root-cause bugs encountered in touched fragile code (TCP transport, Upgrader, Scheduler) rather than working around them | Codebase already has a history of reactive point-patches; better to fix properly while already in that code | — Pending |
| No go-libp2p wire interop testing required for pnet/gating, but still follow the libp2p pnet spec | Private networks are isolated from public bootstrap; spec-following costs little and preserves future compatibility | — Pending |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-08-27 after Phase 3 completion*
