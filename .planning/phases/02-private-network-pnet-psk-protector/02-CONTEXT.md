# Phase 2: Private network (pnet) PSK protector - Context

**Gathered:** 2026-08-26
**Status:** Ready for planning

<domain>
## Phase Boundary

A PSK-protected private-network wrapper isolates raw connections before any protocol negotiation begins (XSalsa20 per `/key/swarm/psk/1.0.0/`), configured via DI, with a force-pnet fail-safe and private-network-scoped Kademlia bootstrap. This phase covers requirements PNET-01 through PNET-05, BOOT-01, and TEST-02. It does not cover live two-node validation, reentrancy regression tests, or integrator documentation (Phase 3), nor any gater work (Phase 1, complete).

</domain>

<decisions>
## Implementation Decisions

### XSalsa20 crypto provider
- **D-01:** Vendor a small, self-contained public-domain XSalsa20 implementation (~150 lines, as go-libp2p itself does with golang.org/x/crypto/salsa20) under the crypto layer — do **not** add libsodium or Crypto++ as a Hunter dependency. This eliminates the MSVC/Hunter packaging risk flagged in STATE.md as a phase blocker. OpenSSL lacks XSalsa20, which is why a vendored primitive is needed at all.
- **D-02:** Expose the primitive as plain free function(s) in the `libp2p::crypto` namespace (`outcome::result` style) — low-ceremony like the existing crypto provider code. No new provider interface, no DI binding for the cipher itself.
- **D-03:** Validate the vendored cipher against **published XSalsa20/libsodium test vectors** (fixed key+nonce+plaintext → expected ciphertext), mirroring how upstream go-libp2p tests its vendored copy.
- **D-04:** The 24-byte handshake nonce on the initiating side comes from **OpenSSL `RAND_bytes`** (already wired into the codebase's crypto providers). User guidance: "whatever matches spec — go-libp2p uses Go's `crypto/rand` (standard OS CSPRNG); OpenSSL `RAND_bytes` is the direct C++ equivalent here."

### PSK config surface
- **D-05:** The `Psk` type accepts **both** the go-ipfs `swarm.key` file text (`/key/swarm/psk/1.0.0/` + `/base16/` or `/base64/` framing) **and** a raw hex/base64 string/byte constructor — existing GNUS swarm.key files work as-is. Parse errors are explicit failures, never silent truncation/acceptance. Validate exactly 32 bytes (256-bit) at parse time.
- **D-06:** PSK hygiene per research (PITFALLS.md §3): dedicated non-copyable `Psk` type (move-only), explicit zeroing destructor (`OPENSSL_cleanse` or equivalent non-optimizable clear), never passed as raw `std::vector<uint8_t>`, and never logged — enforce the no-logging rule in tests/review.
- **D-07:** A **single combined named DI module** (e.g. `usePrivateNetwork(key)`) binds both the `Psk` and the pnet-enabled marker in one call — one line turns on private-network mode. The pair cannot be configured independently, so half-configured states are impossible by construction.
- **D-08:** **No default binding** — absence of the module means no `Psk` in the graph, no pnet wrapper at all, public mode, exactly today's behavior. Absence is meaningful and checked once at injector/host-construction time (mirrors Phase 1's null-object default philosophy).

### Force-pnet trigger (PNET-05)
- **D-09:** The combined `usePrivateNetwork(key)` module **is** the private-network-mode signal: enabling it requires the `Psk` to parse to exactly 32 bytes or construction fails explicitly. No env var (`LIBP2P_FORCE_PNET` equivalent rejected — DI-only, matching the project constraint), no separate mode flag to fall out of sync.
- **D-10:** The failure surfaces at **injector build / host-construction time** (`makeHostInjector` / DI-graph construction) — the earliest impossible-to-miss point. No `Host` object ever exists in a broken half-configured state; no zombie Host failing per-dial.

### Bootstrap scoping (BOOT-01)
- **D-11:** **Silent filter** — when a `Psk` is present, default public go-libp2p bootstrap addresses are never dialed, with no error surfaced to the caller. (User explicitly rejected the recommended fail-loud-on-conflict option in favor of silent filtering — this is a deliberate choice, not an oversight. Deliberate misconfiguration is treated as harmless-and-ignored rather than fatal.)
- **D-12:** The filter is implemented as **dial-time refusal inside `DialerImpl`** — if a `Psk` is present, dial attempts targeting known public-bootstrap peer IDs/multiaddrs are refused. This covers any config path (broader than stripping defaults at injector level) at the cost of a hardcoded public-peer list and per-dial check in the dial path.
- **D-13:** Refusals are **logged at `SL_DEBUG`** (same level Phase 1 chose for gater rejections) with the peer ID/address. "Silent" means no error to the caller, but the behavior is observable when debugging why a node never dials public peers.

### Carry-forward (locked in prior phases/research — do not re-litigate)
- **Wrap point:** pnet wraps the `RawConnection` *before* `Upgrader`/multiselect, as a `RawConnection` decorator applied via an `Upgrader` decorator — never a `SecurityAdaptor` participating in multiselect (spec-mandated, highest-recovery-cost pitfall per PITFALLS.md §2; see research ARCHITECTURE.md "Where the pnet PSK wrapper goes").
- **Cipher parameters:** XSalsa20 stream cipher, 256-bit key, 24-byte nonce, no MAC — fixed by the pnet spec v1, not a design choice. Only the 24-byte nonce exchange is sent in the clear.
- **Reentrancy:** any pnet callback delivery defers via scheduler `post`/`dispatch` (Phase 1 pattern; TEST-04 formal regression lands in Phase 3).
- **Error observability:** gater-rejection logging at `SL_DEBUG` library-side (Phase 1 D-06) sets the convention pnet error logging follows.

### Claude's Discretion
None — all 4 discussed areas resulted in explicit decisions above. (Note D-11–D-13: user chose against the recommended options in two of those; honor the user's selections exactly.)

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Project scope & requirements
- `.planning/PROJECT.md` — core value, constraints (C++17, DI-only construction, upgrade-pipeline integration, pnet spec compliance), out-of-scope list
- `.planning/REQUIREMENTS.md` — PNET-01 through PNET-05, BOOT-01, TEST-02 (this phase's mapped requirements)
- `.planning/ROADMAP.md` §"Phase 2: Private network (pnet) PSK protector" — goal, 5 success criteria, dependency on Phase 1

### Research (pnet-specific — highest value for this phase)
- `.planning/research/ARCHITECTURE.md` — confirms the single correct wrap point (`Upgrader` decorator + `RawConnection` decorator, covering inbound+outbound without touching `TcpTransport`/`TcpListener`/`UpgraderSession`); the proposed `PnetProtectedConnection` / `PnetUpgraderDecorator` / `Psk` component shapes
- `.planning/research/PITFALLS.md` — §2 (wrap-after-negotiation leak — the #1 pitfall), §3 (PSK key-material hygiene: validation, zeroing, no-copy, never-logged — feeds D-05/D-06), §6 (reentrant synchronous callback anti-pattern, TODO(107) sites)
- `.planning/research/STACK.md` — pnet spec v1 + XSalsa20 parameter pinning; the libsodium/Crypto++/vendored decision matrix (feeds D-01); existing OpenSSL dependency notes (feeds D-04)
- `.planning/research/FEATURES.md` — PSK/swarm-key config surface expectations; force-pnet fail-safe pattern; bootstrap-scoping rationale
- `.planning/research/SUMMARY.md` — component list (PnetProtectedConnection, PnetUpgraderDecorator, Psk) and risk ranking

### Prior phase context (patterns to reuse)
- `.planning/phases/01-connection-gater-interface-wiring/01-CONTEXT.md` — Phase 1 decisions (null-object default, error-code attribution with unmistakable gater-prefix naming, `SL_DEBUG` observability, scalar DI rebind for single-impl overrides) that set the conventions this phase follows
- `.planning/phases/01-connection-gater-interface-wiring/deferred-items.md` — known deferred items adjacent to transport code this phase touches

### Codebase maps
- `.planning/codebase/ARCHITECTURE.md` — upgrade-pipeline flow (`RawConnection` → `SecureConnection` → `CapableConnection`), `Dialer`/`Upgrader`/`TransportManager` responsibilities and file locations, DI-only construction constraint
- `.planning/codebase/CONCERNS.md` — documented concurrency/reentrancy history in TCP transport/Upgrader/Scheduler; MSVC 19.44/soralog build issue affecting `network_injector_test` and targets transitively depending on `p2p_yamuxed_connection` (still relevant to full-build verification this phase)
- `.planning/codebase/STACK.md` — Hunter dependency-addition pattern (`hunter_config` overrides in `cmake/Hunter/config.cmake`) in case any build-system change is needed; note D-01 deliberately avoids needing it for crypto

### Project conventions
- `w:\gnus\GeniusNetwork\thirdparty\libp2p\.claude\CLAUDE.md` — naming/error-handling/logging conventions (per-module `error.hpp` enums, `OUTCOME_*` registration, `SL_*` macros, camelCase methods, trailing-underscore members) and the pnet spec-compliance constraint

No SPEC.md exists for this phase — requirements come directly from REQUIREMENTS.md/ROADMAP.md above.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `PermissiveConnectionGater` + `useConnectionGater<T>()` scalar DI-rebind pattern (Phase 1) — the template for the new `usePrivateNetwork(key)` module's shape: one named module, single rebind point, no source changes at call sites
- `src/crypto/*_provider` implementations backed by OpenSSL — the existing RNG surface (`RAND_bytes`) D-04 reuses; also the low-ceremony code style D-02 mirrors
- Per-module error pattern (`src/security/error.cpp`, `src/peer/errors.cpp`, Phase 1's `ConnectionGaterError`) — template for a new pnet error enum (`PNET_`-prefixed values starting at `= 1`, unmistakable attribution)
- `basic::Scheduler` `post`/`dispatch` — the mechanism all pnet callback delivery must use (carry-forward constraint)

### Established Patterns
- Decorator over `Upgrader` (proposed in research ARCHITECTURE.md): `PnetUpgraderDecorator` implements `transport::Upgrader`, holds `inner_` + `Psk`, wraps each `upgradeToSecure*` incoming raw connection in a `PnetProtectedConnection` (implementing `connection::RawConnection`, delegating everything except `read`/`write`); `upgradeToMuxed` passes through
- `outcome::result<T>` for all fallible API — `Psk` parsing/validation, pnet handshake, DI module construction
- Static per-TU logger + `SL_DEBUG` — for D-13 dial-refusal observability and any pnet handshake failure logging

### Integration Points
- `src/transport/impl/upgrader_impl.cpp` / `upgrader_session.cpp` — the choke point every dial/accept routes through; the decorator wraps here (not inside `TcpTransport`/`TcpListener`)
- `include/libp2p/injector/host_injector.hpp` — where `usePrivateNetwork(key)` binds the `Psk`, the pnet marker (D-07), and swaps `Upgrader` for the decorated variant when the module is active
- `src/network/impl/dialer_impl.cpp` — the dial-time bootstrap-refusal check lands here (D-12), next to the Phase 1 gater hooks; needs access to the active `Psk` (or its absence) and the public-bootstrap address/peer-ID list
- `include/libp2p/injector/kademlia_injector.hpp` (verification only) — confirm nothing dials public bootstrap peers behind the dial-time filter when a `Psk` is present
- `test/libp2p/...` layout — TEST-02 (pnet accept/reject unit tests) mirrors Phase 1's test placement convention (tests live in the phase producing the code; live two-node is Phase 3)

</code_context>

<specifics>
## Specific Ideas

- The user's guiding reference for pnet behavior is go-libp2p: nonce from the platform's standard CSPRNG, vendored cipher approach, swarm.key file format compatibility — "whatever matches spec" (D-04, D-05).
- Existing GNUS deployments carry go-ipfs-style `swarm.key` files — the dual-format `Psk` constructor (D-05) exists specifically so those files work without conversion.
- The user deliberately prefers silent-filter semantics for bootstrap scoping (D-11) over the fail-loud pattern used elsewhere in this project (PNET-05). This asymmetry is intentional — public-peer misconfiguration is deemed harmless, while a bad PSK is fatal.

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope. No scope-creep suggestions came up.

</deferred>

---

*Phase: 2-Private network (pnet) PSK protector*
*Context gathered: 2026-08-26*
