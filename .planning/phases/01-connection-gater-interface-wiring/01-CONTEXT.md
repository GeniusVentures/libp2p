# Phase 1: Connection Gater interface + wiring - Context

**Gathered:** 2026-08-26
**Status:** Ready for planning

<domain>
## Phase Boundary

Integrators can plug in connection-level accept/reject policy at all 5 stages of the connection lifecycle (peer dial, address dial, accept, secured, upgraded) without touching upgrade-pipeline internals. Existing hosts behave exactly as they do today when no gater is configured (default permissive behavior). This phase covers the `ConnectionGater` interface, its DI binding, and wiring into `Dialer`, `TcpListener`/`ListenerManager`, and `Upgrader`/`UpgraderSession`. It does not cover pnet/PSK (Phase 2) or live two-node/reentrancy validation and docs (Phase 3).

</domain>

<decisions>
## Implementation Decisions

### Hook naming convention
- **D-01:** The 5 gater hook methods use this codebase's camelCase convention, not go-libp2p's PascalCase names: `interceptPeerDial`, `interceptAddrDial`, `interceptAccept`, `interceptSecured`, `interceptUpgraded`. Same 5 stages and semantics as go-libp2p's `ConnectionGater`, styled to match the rest of the cpp-libp2p public API (CLAUDE.md: camelCase for methods).

### Rejection error semantics
- **D-02:** Gater rejections use per-hook error codes (one enum value per hook), not a single generic `REJECTED` code — so callers/logs can tell which of the 5 stages rejected the connection.
- **D-03:** Each error code/message must make it unmistakable that the *gater* was the cause of rejection (not some other layer) — name the enum values so "gater" is legible in the error text itself (e.g. a `GATER_` prefix or equivalent, not a bare `REJECTED_PEER_DIAL` that could be confused with an unrelated dial failure). This is a specific, deliberate ask — don't drop the "gater" framing when researching/planning the error enum.

### Default gater binding strategy
- **D-04:** Use the Null Object pattern. A `PermissiveConnectionGater` (or equivalent name) is *always* bound in the DI graph by default. `Dialer`, `TcpListener`, and `UpgraderSession` call into the gater unconditionally at each of their hooks — no `if (gater_)` null checks scattered across the 3 call sites.
- **D-05:** Overriding the default is a single DI rebind (`di::bind<ConnectionGater>().to<CustomGater>()`-style), consistent with GATE-04 (no source changes required to `Dialer`/`TcpListener`/`UpgraderSession` to register a custom gater).

### Rejection observability
- **D-06:** The library itself logs gater rejections — not left solely to the integrator's gater implementation. Log at `SL_DEBUG` (matching this codebase's convention: SL_DEBUG for notable-but-non-error events like peer disconnects/malformed frames), including which hook rejected and the peer id / address where available.

### Claude's Discretion
None — all 4 discussed areas resulted in explicit decisions above.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Project scope & requirements
- `.planning/PROJECT.md` — core value, constraints (C++17, DI-only construction, upgrade-pipeline integration, spec compliance), out-of-scope list
- `.planning/REQUIREMENTS.md` — GATE-01 through GATE-05 and TEST-01 (this phase's mapped requirements)
- `.planning/ROADMAP.md` §"Phase 1: Connection Gater interface + wiring" — goal, success criteria, dependencies

### Codebase architecture & conventions
- `.planning/codebase/ARCHITECTURE.md` — connection upgrade pipeline (`RawConnection` → `SecureConnection` → `CapableConnection`), `Dialer`/`ListenerManager`/`Upgrader`/`UpgraderSession` responsibilities and file locations, existing adaptor pattern (Transport/Security/Muxer) to mirror for the gater's DI binding, `outcome::result<T>` error-handling pattern
- `.planning/codebase/CONCERNS.md` — reentrancy TODOs and scheduler/TCP-transport fragility directly relevant to GATE-05 (clean teardown) and the roadmap's scheduler `post`/`dispatch` requirement; read before touching `TcpListener`, `UpgraderSession`, or `Dialer` teardown paths
- `w:\gnus\GeniusNetwork\thirdparty\libp2p\.claude\CLAUDE.md` — naming/error-handling/logging conventions applied in the decisions above (error enum pattern in `error.hpp`/`errors.hpp` per module, `SL_DEBUG`/`SL_WARN` logging macros, camelCase methods, trailing-underscore members)

No SPEC.md exists for this phase — requirements come directly from REQUIREMENTS.md/ROADMAP.md above.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- Existing adaptor pattern (`include/libp2p/transport/transport_adaptor.hpp`, `security/security_adaptor.hpp`, `muxer/muxer_adaptor.hpp` + their DI bindings in `injector/network_injector.hpp`) is the template to follow for the `ConnectionGater` interface + DI binding — interface + registry/injection point, no direct `new`.
- Existing per-module error pattern (`src/peer/errors.cpp`, `src/security/error.cpp`, `src/connection/error_codes.cpp`) is the template for the new `ConnectionGaterError` enum (SCREAMING_SNAKE_CASE values, `OUTCOME_HPP_DECLARE_ERROR`/`OUTCOME_CPP_DEFINE_CATEGORY_3`).

### Established Patterns
- `outcome::result<T>` for all fallible interface methods — gater hook results and rejection errors should follow this, not exceptions.
- `basic::Scheduler` (`post`/`dispatch`) is the required mechanism for any callback that could otherwise fire reentrantly/synchronously — applies directly to how gater hook callbacks are delivered (roadmap success criterion #5).
- Static per-translation-unit logger (`log::createLogger(...)`) + `SL_DEBUG`/`SL_WARN` macros — used for the rejection-observability decision (D-06).

### Integration Points
- `Dialer` (`src/network/impl/dialer_impl.cpp`) — peer dial / address dial hooks, before a `RawConnection` is opened.
- `TcpListener`/`ListenerManager` (`src/transport/tcp/tcp_listener.cpp`, `src/network/impl/listener_manager_impl.cpp`) — accept hook, before any security handshake bytes are exchanged.
- `Upgrader`/`UpgraderSession` (`src/transport/impl/upgrader_impl.cpp`, `src/transport/impl/upgrader_session.cpp`) — secured and upgraded hooks, tearing down via the existing hardened close path on rejection.
- `include/libp2p/injector/network_injector.hpp` (and/or `host_injector.hpp`) — where the default `PermissiveConnectionGater` binding and the override point live.

</code_context>

<specifics>
## Specific Ideas

No specific UI/behavioral references beyond the 4 decisions above — this is a backend interface + wiring phase. The user's clearest specific ask: rejection error codes must read as gater-caused in the error text itself, not just be distinguishable by enum value.

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope. No scope-creep suggestions came up.

</deferred>

---

*Phase: 1-Connection Gater interface + wiring*
*Context gathered: 2026-08-26*
