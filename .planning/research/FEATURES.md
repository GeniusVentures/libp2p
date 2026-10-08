# Feature Research

**Domain:** P2P networking access control — Connection Gater + Private Networks (pnet/PSK), for a permissioned C++17 libp2p fork (SuperGenius)
**Researched:** 2026-08-25
**Confidence:** MEDIUM (cross-referenced across official libp2p specs, go-libp2p godoc/source, js-libp2p docs, and community discussion threads; no single HIGH-confidence primary source fetched in full, but findings converge across 3+ independent sources for each core claim — see Sources)

## Feature Landscape

### Table Stakes (Users Expect These)

These are what "having a Connection Gater" and "having pnet" mean at all in the libp2p ecosystem. Missing any of these means the feature doesn't actually gate access or doesn't actually isolate the network — it would be insecure or a no-op, not a smaller version of the feature.

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| 5-stage `ConnectionGater` interface (`InterceptPeerDial`, `InterceptAddrDial`, `InterceptAccept`, `InterceptSecured`, `InterceptUpgraded`) | This is the canonical go-libp2p/js-libp2p contract (`core/connmgr.ConnectionGater`). Anything less isn't recognized as "a connection gater" by anyone porting policy code from go-libp2p, and each stage exists to reject at the cheapest possible point (see cost analysis below). Already an Active requirement in PROJECT.md. | MEDIUM | Signatures per stage: `InterceptPeerDial(peer.ID) bool`, `InterceptAddrDial(peer.ID, Multiaddr) bool`, `InterceptAccept(ConnMultiaddrs) bool`, `InterceptSecured(Direction, peer.ID, ConnMultiaddrs) bool`, `InterceptUpgraded(Conn) (bool, DisconnectReason)`. C++17 equivalent needs peer ID, direction enum, and multiaddr types already present in this fork. |
| Default no-op / allow-all gater | Every real deployment (go-libp2p, js-libp2p) ships with gating optional and defaults to permissive — existing hosts must not change behavior when no gater is configured. Already an Active requirement. | LOW | Simplest correct default: a `PermissiveConnectionGater` (or `nullptr` treated as allow) wired through DI so untouched code paths are unaffected. |
| Gater wired into every real interception point (`Dialer`, `ListenerManager`/`TcpListener`, `Upgrader`/`UpgraderSession`) | A gater that isn't actually called at accept-time or post-handshake time is decorative. In go-libp2p, gating is deliberately implemented "at the top level" (swarm/upgrader), not bolted onto one transport, precisely so it can't be bypassed by adding a new transport. | MEDIUM-HIGH | This is the highest-complexity item because it touches 3 distinct subsystems already flagged as containing concurrency bugs (`CONCERNS.md`) and 10 open reentrancy TODOs. Needs careful placement so a reject at `InterceptAccept` actually closes the raw socket without leaking fds/threads, and a reject at `InterceptSecured`/`InterceptUpgraded` tears down partially-established `SecureConnection`/`CapableConnection` objects cleanly. |
| Deny-by-peer-ID, deny-by-IP, deny-by-subnet (CIDR) policy building blocks | This is exactly what go-libp2p's shipped `BasicConnectionGater` (`p2p/net/conngater`, since v0.12.0) provides, and it is the reference "default policy implementation" every downstream project (Filecoin/Lotus, IPFS) builds on. Block-by-peer, block-by-addr, block-by-subnet are the three primitives real deployments actually use. | LOW-MEDIUM | go-libp2p's `BasicConnectionGater` is explicitly **deny-list only** — no built-in allow-list primitive. Don't assume upstream has a ready-made allow-list to port; GNUS needs to build the allow-list variant itself (see Differentiators). |
| PSK-based `pnet` transport-level protector wrapping the raw connection pre-security-handshake | This is the entire mechanism of libp2p private networks per the spec (`libp2p/specs/pnet/Private-Networks-PSK-V1.md`): a 256-bit PSK, XSalsa20 stream cipher, applied as an outer encryption layer *before* the normal security handshake (noise/tls) runs. It is not a security transport substitute — it wraps whatever transport/security stack already exists. Already an Active requirement and explicitly placed "before security negotiation" in PROJECT.md, matching the spec. | MEDIUM-HIGH | Cipher note: XSalsa20/Salsa20 is **not** in OpenSSL. This fork will need libsodium (`crypto_stream_xsalsa20`) or a vendored Salsa20/XSalsa20 implementation — a new dependency decision, not just a wiring decision. Handshake: each side sends a random 24-byte nonce; both derive an XSalsa20 keystream from PSK+nonce and XOR all subsequent bytes. |
| PSK/swarm-key config surface (equivalent of `swarm.key` file + `/key/swarm/psk/1.0.0/` multicodec framing) | Every real pnet deployment (go-ipfs, go-libp2p, js-libp2p `@libp2p/pnet`) reads the PSK from this exact format. Following it costs little and is explicitly required by PROJECT.md ("should follow the libp2p pnet spec ... to preserve future compatibility"). | LOW | Format: multicodec path header `/key/swarm/psk/1.0.0/` + base-encoding indicator (`/bin/`, `/base16/`, `/base64/`) + 32-byte key. DI-driven config (per PROJECT.md constraint) can accept the key directly (bytes/hex) without necessarily parsing the on-disk file format — but keep the *256-bit-exact* validation, since a wrong-length key is a common misconfiguration in the wild. |
| Reject-fails-closed semantics at every gater/pnet checkpoint | The universal expectation across implementations: a `false`/reject return from any hook must prevent the connection from proceeding, and PSK mismatch must prevent higher-layer protocol data from ever being interpretable. GNUS's "Core Value" (PROJECT.md line 11) states this directly — a node without correct credentials "must be unable to join or communicate," full stop. | LOW (logic) / MEDIUM (correctness under concurrency) | The risk isn't the boolean logic, it's teardown correctness under this codebase's known scheduler/TCP-teardown race history — every reject path must be tested under the same conditions that caused prior deadlocks/races. |

### Differentiators (Competitive Advantage)

These go beyond the bare go-libp2p/js-libp2p feature set. They are not required to call the feature "done," but they are what make it fit for GNUS's specific "permissioned SuperGenius network" use case rather than a generic port of upstream primitives.

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| Allow-list gater policy (peer-ID and/or pubkey allow-list, deny-by-default) | go-libp2p's shipped `BasicConnectionGater` is deny-list-only; a permissioned network's actual requirement is closer to "reject everyone except this known set." An allow-list is a small inversion of the same primitive (`InterceptPeerDial`/`InterceptSecured` check membership instead of absence) but it's the policy GNUS actually needs, not what upstream ships by default. | LOW-MEDIUM | Cheapest, highest-value differentiator: same interface, different default policy (deny-by-default + allow-list) instead of allow-by-default + deny-list. Should be the reference `ConnectionGater` implementation this project ships, analogous to go-libp2p's `BasicConnectionGater` but inverted. |
| Combining pnet + gater as one layered access-control boundary (PSK for "in the right network at all," gater allow-list for "and you're one of our known nodes") | This is explicitly GNUS's stated design (PROJECT.md Key Decisions: "Together they form a single access-control boundary"). Neither primitive alone gives defense in depth: PSK alone only proves "has the shared secret" (which could leak or be shared too broadly); gater alone only filters at the libp2p layer without cryptographically blocking unauthorized traffic before it's even parseable. | LOW (once both pieces exist) | Not new code — this is a *documentation/composition* deliverable: show integrators how to configure both together, and what each layer catches that the other doesn't (PSK catches "wrong network entirely" cheaply/cryptographically; gater catches "right network, wrong/unapproved peer" with fine-grained identity logic). |
| Static/DI-configured Kademlia bootstrap list restricted to known-good peers, combined with pnet | GNUS already has Kademlia bootstrap interop (validated capability). For a private network, the practical operational need is: don't let the DHT bootstrap process wander toward public go-libp2p bootstrap peers or accept arbitrary discovered peers into the routing table. Community guidance confirms this is a real, recurring want (filtering DHT routing-table inserts by protocol/identity match) but isn't a built-in go-libp2p feature — projects hand-roll it. | LOW-MEDIUM | Because pnet already makes cross-network traffic uninterpretable, DHT peer discovery is naturally "safe" against public peers *once pnet is enforced*, but Kademlia can still waste cycles trying (and failing) to dial public bootstrap addresses if the config isn't scoped to private bootstrap peers. Recommend: configure Kademlia bootstrap list to private-network-only seed nodes (a config-time decision, not new gater logic), and let the gater/pnet layers do rejection if any address is still attempted. Avoid building new DHT-specific filtering code — this is a config/composition win, not a new subsystem. |
| `LIBP2P_FORCE_PNET`-equivalent fail-safe (refuse to start / refuse non-PSK connections if PSK is misconfigured or absent) | This is the single most-cited operational gotcha across go-ipfs/js-libp2p production usage: without a forced-pnet guard, a node that fails to load its PSK silently falls back to operating as a public, unprotected node instead of refusing to start. For a permissioned network this is a severe, non-obvious failure mode. | LOW | Concretely: if a build/deployment is configured as "private network mode," construction should hard-fail (not silently degrade to plaintext dialing) if no valid 256-bit PSK is supplied. Cheap insurance against the worst pnet misconfiguration class. |
| Simple inbound rate limiting at `InterceptAccept` (per-IP connection-attempt throttling) | go-libp2p added this as a real production DoS mitigation (`x/rate` package: per-IP token bucket, default ~1 conn/5s burst 16) precisely because `InterceptAccept` is the cheapest point to reject floods (before any crypto CPU cost is spent). For a permissioned network already gated by PSK + allow-list, the residual risk is a compromised/misbehaving *member* node hammering others, not the wider internet — so this is a nice-to-have, not core. | MEDIUM | Only worth building if GNUS anticipates a malicious or buggy *authorized* peer inside the private network; otherwise the allow-list + PSK combination already blocks the entire outside internet, making generic DoS rate limiting materially lower-value than it is for a public go-libp2p node. Flag as a candidate for a later phase, not this one. |

### Anti-Features (Commonly Requested, Often Problematic)

| Feature | Why Requested | Why Problematic | Alternative |
|---------|---------------|------------------|-------------|
| Full peer-scoring / reputation system (gossipsub-style dynamic scoring, decaying trust) | "Since we're doing access control, why not also score peer behavior over time like gossipsub peer scoring?" | Massive scope increase: needs persistent state, tuning, decay curves, and is a well-known source of subtle bugs and false-positive bans in the libp2p ecosystem (see go-libp2p pubsub scoring complexity). PROJECT.md explicitly wants a bounded 2-primitive deliverable (gater + pnet), not a trust-management subsystem. | A static allow-list (peer-ID/pubkey membership) plus the existing deny-list primitives (`BlockPeer`/`BlockAddr`/`BlockSubnet`-equivalent) covers "permissioned network" requirements without behavioral scoring. |
| Persistent/datastore-backed block-list with dynamic runtime mutation API (add/remove blocked peers at runtime, survive restarts) | go-libp2p's `BasicConnectionGater` supports optional datastore persistence, so it "looks like" table stakes. | For a permissioned network whose membership is defined by PSK + a config-time allow-list, dynamic runtime mutation and persistence add real complexity (concurrent-safe mutation of gater state while dials/accepts are in flight — exactly the class of race this codebase has a documented history with) for a use case (membership changes) that's more naturally handled by redistributing a new PSK/allow-list and restarting/rotating, not hot-patching. | Config-time (DI-time) allow-list/PSK, redeployed on membership change. Only build a live-mutation API if GNUS has a concrete, near-term requirement for it — currently out of scope per PROJECT.md's Active requirements. |
| Full go-libp2p wire-level interop / cross-implementation testing for pnet+gater against public go-libp2p peers | "Shouldn't we verify our pnet implementation actually interops with the real go-libp2p pnet wire format?" | Explicitly called out as Out of Scope in PROJECT.md: a private network isn't expected to bootstrap against public go-libp2p peers, so this isn't a near-term need, even though following the spec bytes-for-bytes is still worthwhile for *future* compatibility. | Follow the published spec (multicodec framing, XSalsa20, nonce handling) for correctness and future-proofing, but validate via internal two-node tests (already an Active requirement), not cross-implementation interop suites. |
| Custom/non-standard encryption-before-encryption scheme instead of the spec's XSalsa20 pnet layer | Since OpenSSL doesn't have Salsa20/XSalsa20 built in, a tempting shortcut is "just use an OpenSSL-native stream cipher (e.g. ChaCha20) instead, it's close enough." | Breaks spec compliance (explicitly a Constraint in PROJECT.md) and forfeits the "preserve future compatibility" goal for zero real benefit — libsodium's `crypto_stream_xsalsa20` is a small, well-audited, easy-to-vendor dependency, not a hard blocker. | Bring in libsodium (or a minimal vendored XSalsa20/Salsa20 implementation) specifically for pnet; don't substitute a different cipher to avoid a new dependency. |
| Rejecting at the earliest possible stage for every policy, regardless of what information is available at that stage | Superficially "more efficient" — reject at `InterceptPeerDial` always to save cost. | Some policy decisions genuinely require information only available later (e.g., "reject unless client presents the right identity at the security layer" needs `InterceptSecured`; "reject based on negotiated capabilities" needs `InterceptUpgraded`). Forcing every check into the earliest hook either loses correctness or requires stashing state across stages awkwardly. | Match each policy to the earliest stage where the *required information* is actually available: peer-ID allow/deny → `InterceptPeerDial`; IP/subnet → `InterceptAddrDial`/`InterceptAccept`; identity-confirmed-by-crypto policies → `InterceptSecured`; capability-based policies → `InterceptUpgraded`. |

## Feature Dependencies

```
[5-stage ConnectionGater interface]
    └──requires──> [Default no-op gater] (must not change existing behavior when unset)
    └──requires──> [Wiring into Dialer / ListenerManager+TcpListener / Upgrader+UpgraderSession]
                       └──requires──> [RawConnection -> SecureConnection -> CapableConnection stage boundaries] (already exists, per ARCHITECTURE.md)

[Deny-list policy primitives (peer/addr/subnet block)]
    └──requires──> [5-stage ConnectionGater interface]

[Allow-list gater policy] (differentiator)
    └──requires──> [5-stage ConnectionGater interface]
    └──enhances──> [Deny-list policy primitives] (same mechanism, inverted default)

[PSK pnet protector]
    └──requires──> [PSK/swarm-key config surface via DI]
    └──requires──> [XSalsa20 cipher availability] (new dependency: libsodium or vendored impl — OpenSSL lacks it)
    └──must apply before──> [Security handshake (noise/secio/tls/plaintext)] (existing, per Constraints)

[Force-pnet fail-safe] (differentiator)
    └──requires──> [PSK pnet protector]
    └──requires──> [PSK/swarm-key config surface via DI]

[Kademlia bootstrap scoped to private peers] (differentiator)
    └──enhances──> [PSK pnet protector] (pnet already blocks cross-network traffic cryptographically; bootstrap scoping avoids wasted dial attempts)
    └──requires──> [Existing Kademlia bootstrap capability] (already validated in codebase)

[Combined pnet + gater documentation/composition] (differentiator)
    └──requires──> [5-stage ConnectionGater interface]
    └──requires──> [PSK pnet protector]

[Inbound rate limiting at InterceptAccept] (differentiator, lower priority)
    └──requires──> [5-stage ConnectionGater interface] (specifically InterceptAccept)
    └──conflicts (priority-wise) with──> [Allow-list gater policy] (largely redundant once allow-list + PSK block all non-members; lower ROI in this specific deployment model)

[Persistent/dynamic-mutation block-list API] (anti-feature)
    └──conflicts──> [Codebase's existing concurrency-safety concerns] (CONCERNS.md: races/deadlocks in scheduler, yamux, TCP teardown — adding concurrent-mutable gater state raises the same risk class)

[Full peer-scoring / reputation system] (anti-feature)
    └──conflicts──> [Bounded 2-primitive project scope stated in PROJECT.md]
```

### Dependency Notes

- **Gater wiring requires the existing `RawConnection`→`SecureConnection`→`CapableConnection` progression:** PROJECT.md's architecture reference confirms these are already distinct interfaces in this fork — the 5 hooks map directly onto stage transitions that already exist structurally, which is why this is MEDIUM-HIGH complexity (careful integration) rather than a new architectural layer.
- **Allow-list enhances rather than replaces deny-list machinery:** the same `ConnectionGater` interface and the same per-stage check functions serve both; only the default-allow-vs-default-deny policy and the membership-set semantics differ. Build one flexible policy primitive, not two parallel systems.
- **pnet must apply before the security handshake, not alongside or after it:** this is both a spec requirement and an explicit Constraint in PROJECT.md. It's an outer transport-level wrapper (double encryption), so it has no interface dependency on noise/secio/tls internals — it wraps whatever `RawConnection` produces before `Upgrader` begins security negotiation.
- **XSalsa20 dependency is a real, non-trivial fork decision:** OpenSSL (whatever crypto library this fork currently uses for TLS/noise, presumably OpenSSL/BoringSSL-family) does not provide Salsa20/XSalsa20. This should be flagged explicitly for the roadmap/stack decision — likely need to vendor libsodium (small, well-audited, permissive license) or a minimal standalone XSalsa20 implementation, since pulling in all of libsodium just for one stream cipher is a heavier dependency than the feature otherwise warrants.
- **Force-pnet fail-safe conflicts with "silent fallback to public network":** the go-ipfs/js-libp2p community precedent is unanimous that a private-network deployment failing to load its PSK must refuse to start in plaintext/public mode — this should be the *default* behavior in a private-network build config, not an opt-in flag, given GNUS's Core Value statement.
- **Rate limiting is deprioritized relative to allow-list + PSK:** in a deployment where every peer must already possess the correct PSK *and* be on an identity allow-list, the residual attack surface that per-IP rate limiting protects against (unauthenticated connection floods from arbitrary internet hosts) is largely already closed by pnet. This is why it's ranked as a lower-priority differentiator, not table stakes, unlike in public go-libp2p deployments where it's now considered close to essential DoS mitigation.

## MVP Definition

### Launch With (v1)

Minimum viable product — matches the Active requirements already listed in PROJECT.md; this research confirms none of them are over-scoped relative to what "gater" and "pnet" mean in the ecosystem.

- [ ] 5-stage `ConnectionGater` interface, wired into `Dialer`, `ListenerManager`/`TcpListener`, `Upgrader`/`UpgraderSession` — without this, "connection gater" isn't a meaningful feature
- [ ] Default no-op/allow-all gater behavior — required so existing behavior is unaffected when unconfigured
- [ ] DI binding for custom `ConnectionGater` implementations, following the existing adaptor pattern — required for GNUS to actually plug in a policy
- [ ] PSK-based pnet wrapper applied before security negotiation, spec-compliant XSalsa20 — this *is* the private-network primitive; anything less isn't pnet
- [ ] Pnet rejects (fails to establish usable) connections without matching PSK — this is the entire point of the feature
- [ ] PSK configuration via DI — required for GNUS to actually deploy it per-network
- [ ] Unit tests for accept/reject at each gater hook and at the pnet boundary, plus a live two-node PSK match/mismatch test — required to trust the fail-closed guarantee, especially given this codebase's concurrency-bug history
- [ ] Integrator documentation for PSK config + custom gater registration — required for the feature to be usable by anyone besides its authors

### Add After Validation (v1.x)

Features to add once the core primitives are proven correct and integrated.

- [ ] Reference allow-list `ConnectionGater` implementation (deny-by-default, peer-ID/pubkey membership) — add once the base interface + wiring is validated; this is the actual policy GNUS will run in production, so it should follow soon after v1, not be indefinitely deferred
- [ ] Force-pnet fail-safe (refuse to start without valid PSK in private-network build mode) — cheap, high-value; add as soon as PSK config plumbing exists
- [ ] Kademlia bootstrap list scoped to known private-network seed peers — add once pnet is proven working, as a config-level hardening/efficiency pass, not new subsystem code

### Future Consideration (v2+)

Features to defer until the base access-control boundary is running in production and a concrete new need arises.

- [ ] Per-IP inbound rate limiting at `InterceptAccept` — defer until/unless GNUS observes misbehaving authorized peers inside a private network; low ROI while PSK+allow-list already block outside traffic entirely
- [ ] Persistent/dynamic-mutation block-list (datastore-backed, runtime add/remove) — defer until there's a concrete operational need for live membership changes without redeploying config/PSK; adding concurrent-mutable state here fights this codebase's existing concurrency-safety debt

## Feature Prioritization Matrix

| Feature | User Value | Implementation Cost | Priority |
|---------|------------|---------------------|----------|
| 5-stage ConnectionGater interface + wiring | HIGH | HIGH | P1 |
| Default no-op gater | HIGH | LOW | P1 |
| PSK pnet protector (XSalsa20, pre-security-handshake) | HIGH | HIGH | P1 |
| PSK config via DI | HIGH | LOW | P1 |
| Unit + live two-node accept/reject tests | HIGH | MEDIUM | P1 |
| Integrator documentation | MEDIUM | LOW | P1 |
| Allow-list gater reference implementation | HIGH | LOW-MEDIUM | P2 |
| Force-pnet fail-safe | MEDIUM | LOW | P2 |
| Kademlia bootstrap scoping to private peers | MEDIUM | LOW-MEDIUM | P2 |
| Per-IP inbound rate limiting | LOW (given PSK+allow-list already present) | MEDIUM | P3 |
| Persistent/dynamic-mutation block-list | LOW (no stated near-term need) | HIGH (concurrency risk) | P3 |
| Full peer-scoring/reputation system | LOW (out of proportion to stated need) | VERY HIGH | Not planned |

**Priority key:**
- P1: Must have for launch (matches PROJECT.md Active requirements)
- P2: Should have, add when possible (closes real gaps vs. bare go-libp2p feature set for a permissioned deployment)
- P3: Nice to have, future consideration (real go-libp2p features, but lower value in this specific PSK+allow-list deployment model)

## Rejection Cost/Timing Analysis by Gater Stage

This directly answers "does rejection differ in cost/timing at each stage" — it should inform which stage GNUS puts each policy check at, and what "cost" a bug at each stage carries.

| Stage | When it fires | Cost already spent if rejected here | Cost of the reject itself | Notes for this fork |
|-------|---------------|---------------------------------------|----------------------------|----------------------|
| `InterceptPeerDial` | Before any dial attempt, given just a peer ID (e.g., from Kademlia/peerstore) | Nothing — no socket, no DNS/multiaddr resolution | Trivial (skip dial entirely) | Cheapest possible rejection point. Ideal for peer-ID allow/deny-list checks when the peer ID is already known before dialing (e.g., from DHT results). |
| `InterceptAddrDial` | After address resolution, once per candidate multiaddr, before each individual dial | Address resolution cost only | Trivial (skip this one dial attempt; other addrs for same peer may still be tried unless also rejected) | Right place for IP/subnet-based policy when the peer ID alone isn't enough (e.g., peer allowed generally but a specific stale/untrusted address should be avoided). |
| `InterceptAccept` | Immediately after the transport (TCP listener in this fork) accepts a raw socket, before any crypto | One accepted TCP socket (kernel-level accept, minimal CPU) | Cheap — close the raw socket, no crypto CPU wasted | This is the correct point for IP/subnet deny-lists and rate limiting on **inbound** connections — go-libp2p's rate-limiting package is built specifically around this hook because it's the cheapest point to stop a flood before expensive asymmetric crypto runs. In this fork, this is where `ListenerManager`/`TcpListener` wiring matters most for DoS resistance. |
| `InterceptSecured` | After the security handshake (noise/tls/etc.) completes — the remote peer's identity is now cryptographically confirmed — but before mux negotiation | A full asymmetric-crypto handshake has run on **both sides** (real CPU + round-trip cost); pnet's XSalsa20 layer has also already been exercised if applied here | Moderate — the remote already spent CPU on the handshake; rejecting here is the first point identity-based policy can be enforced with cryptographic certainty (you now know *for sure* who you're talking to, not just what IP they dialed from) | This is the natural home for peer-ID allow-list enforcement when identity can only be trusted post-handshake (i.e., don't rely on an unauthenticated peer-ID claim pre-handshake for anything security-sensitive — `InterceptPeerDial`/`InterceptAddrDial` checks are necessarily provisional/unauthenticated). For GNUS's permissioned model, this is likely the *primary* enforcement point for "is this a member of our allow-list," since it's the first point where peer identity is trustworthy. |
| `InterceptUpgraded` | After mux negotiation — connection is fully capable/usable | Everything above, plus mux negotiation | Highest — most work already done; rejecting here is closest to "let them fully connect, then immediately hang up" | go-libp2p's interface supports returning a `DisconnectReason` here (though go-libp2p itself currently ignores the value at the call site) — useful mainly for capability-based policy (e.g., reject peers that don't support a required protocol/mux) rather than identity policy, which should already have been decided at `InterceptSecured`. |

**Practical implication for GNUS's design:** put peer-ID/pubkey allow-list checks at `InterceptPeerDial` (cheap, provisional — outbound dials) *and* re-check at `InterceptSecured` (authoritative, post-crypto — catches any peer that got through with a spoofed/unverified ID claim, and covers inbound connections where you had no chance to check identity before accept). Put IP/subnet policy and rate limiting at `InterceptAccept` (cheapest point with concrete address information for inbound). Reserve `InterceptUpgraded` for capability/protocol-based policy, not identity policy — identity should already be settled two stages earlier.

## Sources

- [libp2p specs: Private-Networks-PSK-V1.md](https://github.com/libp2p/specs/blob/master/pnet/Private-Networks-PSK-V1.md) — official spec: PSK format, multicodec framing, XSalsa20 handshake, no-explicit-error-on-mismatch behavior (MEDIUM confidence, web-fetched summary of primary source)
- [go-libp2p core/connmgr package docs (pkg.go.dev)](https://pkg.go.dev/github.com/libp2p/go-libp2p/core/connmgr) — authoritative `ConnectionGater` interface signatures and per-stage doc comments (MEDIUM confidence)
- [go-libp2p PR #881: implement connection gating at the top level](https://github.com/libp2p/go-libp2p/pull/881) — confirms gating is deliberately wired at swarm/upgrader level, not per-transport (MEDIUM confidence)
- [go-libp2p-core PR #139: add connection gating interfaces and types](https://github.com/libp2p/go-libp2p-core/pull/139) — origin of the 5-hook interface design
- [discuss.libp2p.io: Auth with ConnectionGater](https://discuss.libp2p.io/t/auth-with-connectiongater/2038) — community usage patterns
- [go-libp2p conngater package docs (pkg.go.dev)](https://pkg.go.dev/github.com/libp2p/go-libp2p/p2p/net/conngater) — `BasicConnectionGater` deny-by-peer/addr/subnet primitives, datastore persistence (MEDIUM confidence)
- [libp2p.io: Announcing go-libp2p v0.42.0](https://libp2p.io/releases/2025-06-23-go-libp2p/) and [docs.libp2p.io: DoS Mitigation](https://docs.libp2p.io/concepts/security/dos-mitigation/) — `x/rate` per-IP/subnet rate limiting at `InterceptAccept`, default 1 conn/5s burst 16 (MEDIUM confidence)
- [filecoin-project/lotus libp2p.go](https://github.com/filecoin-project/lotus/blob/master/node/modules/lp2p/libp2p.go) and [Lotus bootstrap docs](https://lotus.filecoin.io/lotus/configure/bootstrap/) — production connection-manager/gating tuning example (MEDIUM confidence)
- [go-libp2p-pnet package docs (pkg.go.dev)](https://pkg.go.dev/github.com/libp2p/go-libp2p-pnet) and [go-libp2p-pnet issue #3: nonce exhaustion and bridging](https://github.com/libp2p/go-libp2p-pnet/issues/3) — XSalsa20, 192-bit nonce, protector wraps raw transport pre-security-handshake (MEDIUM confidence)
- [libp2p Private Networks - pnet (gist, Kubuxu)](https://gist.github.com/Kubuxu/b96b64be00ef949c8d486fe6e6bfc43e) — practitioner write-up: double-encryption model, `LIBP2P_FORCE_PNET` fail-safe rationale (MEDIUM confidence)
- [js-libp2p CONFIGURATION.md](https://github.com/libp2p/js-libp2p/blob/main/doc/CONFIGURATION.md) and [@libp2p/pnet npm](https://www.npmjs.com/package/@libp2p/pnet) — cross-implementation confirmation of `connectionGater`/`connectionProtector` config shape and `LIBP2P_FORCE_PNET` behavior (MEDIUM confidence)
- [rust-libp2p discussion #5135: Correct way to implement private relay?](https://github.com/libp2p/rust-libp2p/discussions/5135) — cross-implementation note that rust-libp2p treats pnet as a less-central pattern in 2024+, useful context that GNUS's PSK+gater approach (not rust's identify-based approach) matches the original spec more directly (MEDIUM confidence)
- No LOW-confidence claims are presented as authoritative in this document; all load-bearing claims above were corroborated across 2+ independent sources.

---
*Feature research for: libp2p connection gating and private networks (pnet), permissioned P2P networking*
*Researched: 2026-08-25*
