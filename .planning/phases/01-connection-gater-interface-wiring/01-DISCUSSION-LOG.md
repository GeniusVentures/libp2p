# Phase 1: Connection Gater interface + wiring - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-08-26
**Phase:** 1-Connection Gater interface + wiring
**Areas discussed:** Hook naming convention, Rejection error semantics, Default gater binding strategy, Rejection observability

---

## Hook naming convention

| Option | Description | Selected |
|--------|-------------|----------|
| go-libp2p names (PascalCase) | InterceptPeerDial, InterceptAddrDial, InterceptAccept, InterceptSecured, InterceptUpgraded — instantly recognizable to anyone who knows the libp2p ConnectionGater spec, but breaks from this codebase's camelCase method convention | |
| Project camelCase convention | interceptPeerDial, interceptAddrDial, interceptAccept, interceptSecured, interceptUpgraded — consistent with every other method in this codebase's public API, semantically identical to go-libp2p's hooks | ✓ |

**User's choice:** Project camelCase convention (Recommended)
**Notes:** None beyond the selection.

---

## Rejection error semantics

| Option | Description | Selected |
|--------|-------------|----------|
| Per-hook error codes | e.g. ConnectionGaterError::REJECTED_BY_PEER_DIAL / _ADDR_DIAL / _ACCEPT / _SECURED / _UPGRADED — matches per-module error enum convention, callers can tell which stage rejected | ✓ |
| Single generic error | One ConnectionGaterError::REJECTED for all 5 hooks — simpler, but no per-stage visibility without gater's own logging | |

**User's choice:** Per-hook error codes
**Notes:** User added an explicit requirement beyond the option text: the error message/enum naming must make it unmistakable that the *gater* specifically was the cause of rejection — not just distinguishable by hook. Captured in CONTEXT.md as D-03 (e.g. a `GATER_` prefix or equivalent, not a bare `REJECTED_PEER_DIAL` that could be confused with an unrelated dial failure).

---

## Default gater binding strategy

| Option | Description | Selected |
|--------|-------------|----------|
| Null Object pattern | PermissiveConnectionGater always bound by default in DI; call sites invoke unconditionally, no null checks; override via a single di::bind rebind | ✓ |
| Nullable/optional gater | Gater is optional/nullable; each of the 3 call sites null-checks before invoking | |

**User's choice:** Null Object pattern (Recommended)
**Notes:** None beyond the selection.

---

## Rejection observability

| Option | Description | Selected |
|--------|-------------|----------|
| Library logs at SL_DEBUG | Dialer/TcpListener/UpgraderSession log an SL_DEBUG line on rejection (hook, peer id/address where available), matching codebase's SL_DEBUG convention for notable-but-non-error events | ✓ |
| Library logs at SL_WARN | Same, but at WARN level — more likely to surface in production log filters | |
| No library-side logging | Silent by default; entirely the integrator's gater's responsibility | |

**User's choice:** Library logs at SL_DEBUG (Recommended)
**Notes:** None beyond the selection.

---

## Claude's Discretion

None — all 4 discussed areas resulted in explicit user decisions.

## Deferred Ideas

None — discussion stayed within phase scope; no scope-creep suggestions came up.
