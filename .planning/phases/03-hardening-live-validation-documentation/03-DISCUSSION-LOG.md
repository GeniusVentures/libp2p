# Phase 3: Hardening, live validation & documentation - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-08-26
**Phase:** 3-Hardening, live validation & documentation
**Areas discussed:** Live two-node PSK test mechanics, Reentrancy regression test approach, Documentation format & location, Complementary PSK+gater worked example

---

## Live two-node PSK test mechanics

**Q: Where should the live two-node PSK test live?**

| Option | Description | Selected |
|--------|-------------|----------|
| test/acceptance/p2p/pnet/ (new dir) | New directory alongside test/acceptance/p2p/host/ — keeps pnet-specific acceptance tests separate, mirrors the src/security/pnet/ module boundary | ✓ |
| test/acceptance/p2p/host/ (existing dir) | Add alongside host_integration_test.cpp — reuses the same directory since it's still a Host-level integration test | |

**Q: What topology should the live test use?**

| Option | Description | Selected |
|--------|-------------|----------|
| Exactly 2 nodes, purpose-built test | New minimal fixture: node A and node B, matching PSK vs mismatched PSK cases | ✓ |
| Reuse HostIntegrationTest's parametrized N-peer fixture | Extend the existing TestWithParam<HostIntegrationTestConfig> pattern with a psk field | |

**Q: How should the mismatched-PSK rejection be asserted?**

| Option | Description | Selected |
|--------|-------------|----------|
| Connection attempt fails/times out, no stream ever opens | Black-box from the dialing peer's side, bounded timeout | ✓ |
| Assert a specific pnet-layer error surfaces | Capture and assert the actual error code/category at the connect callback | |

**Q: Should the live two-node test run in the default `ctest` suite, or be separately gated?**

| Option | Description | Selected |
|--------|-------------|----------|
| Default suite, same as host_integration_test.cpp | Registered via addtest() like every other test | ✓ |
| Gated behind a CMake option (e.g. LIVE_TESTS) | Opt-in only, avoids adding runtime/flakiness risk to default build | |

**Notes:** None beyond the selections above.

---

## Reentrancy regression test approach

**Q: Which callback paths should the reentrancy regression test force reentrant invocation on?**

| Option | Description | Selected |
|--------|-------------|----------|
| Both: gater hooks (Phase 1) + pnet decorator/connection (Phase 2) | Covers all 5 interceptX hooks plus PnetUpgraderDecorator/PnetProtectedConnection | ✓ |
| Gater hooks only | Narrower scope, leaves pnet decorator path unverified | |

**Q: How should the test force a callback to try to fire reentrantly?**

| Option | Description | Selected |
|--------|-------------|----------|
| Test double that invokes the completion callback inline | Mock ConnectionGater/RawConnection calls the passed callback synchronously before returning | ✓ |
| Synchronous Scheduler test backend | Swap in a Scheduler backend that runs post()/dispatch() immediately inline | |

**Q: What should count as a pass for the reentrancy regression test?**

| Option | Description | Selected |
|--------|-------------|----------|
| Stack-depth / re-entry flag assertion | Instrument the code path with a re-entrancy guard flag, assert never true when callback fires | ✓ |
| Call-order assertion via gmock sequencing | Use EXPECT_CALL .After()/InSequence to assert return-before-callback ordering | |

**Notes:** Explicitly scoped away from the 10 pre-existing `TODO(107)` sites (secio/plaintext/tcp_transport/mplex) — those are out of scope per PROJECT.md.

---

## Documentation format & location

**Q: What form should the integrator documentation take?**

| Option | Description | Selected |
|--------|-------------|----------|
| Runnable example(s) under example/, no markdown | Follows existing repo convention — README already points to example/ | ✓ |
| Runnable example(s) + a short markdown walkthrough | Adds a markdown doc narrating the conceptual DOCS-03 point | |

**Q: Where should the markdown walkthrough live (if any)?**

| Option | Description | Selected |
|--------|-------------|----------|
| New example/05-private-network/README.md | Scoped to the new example directory | ✓ |
| New top-level docs/ directory | A new repo-level convention | |

**Note:** Reconciled with the prior answer during synthesis — `example/01-echo/`, `02-kademlia/`, `03-gossip/` already each have their own README.md, so a per-example README is pre-existing convention, not a new narrative-doc layer.

**Q: Should DOCS-01 (PSK config) and DOCS-02 (custom gater) be one combined example or two separate ones?**

| Option | Description | Selected |
|--------|-------------|----------|
| Two separate examples, each focused on one layer | example/05-private-network/ for PSK-only, a second dir for gater-only | ✓ |
| One combined example covering both | Fewer files, but conflates two independent concepts | |

**Notes:** None beyond the selections above.

---

## Complementary PSK+gater worked example

**Q: Where should the DOCS-03 "valid PSK, gater-denied peer" worked example live?**

| Option | Description | Selected |
|--------|-------------|----------|
| Third example dir: example/06-private-network-gater/ | Standalone, matching the one-topic-per-example-dir convention | ✓ |
| Narrative only, in the two example READMEs | Cross-referencing prose, no new runnable code | |
| Extend the live two-node test as the worked example | One artifact serves as both regression test and documentation | |

**Q: Should this worked example be runnable code or a narrated/pseudocode walkthrough?**

| Option | Description | Selected |
|--------|-------------|----------|
| Runnable code | Actual compiling example, consistent with "code is documentation" | ✓ |
| Narrated walkthrough only | Prose + code snippets, breaks from the runnable-example convention | |

**Notes:** None beyond the selections above.

---

## Claude's Discretion

None — all 4 discussed areas resulted in explicit decisions.

## Deferred Ideas

None — discussion stayed within phase scope.
