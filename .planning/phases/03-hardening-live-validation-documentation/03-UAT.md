---
status: resolved
phase: 03-hardening-live-validation-documentation
source: [03-VERIFICATION.md]
started: 2026-08-27T03:39:26Z
updated: 2026-08-27T06:21:19Z
---

## Current Test

[testing complete]

## Tests

### 1. Loopback-dial guard removal (TcpTransport::dial())
expected: |
  Review `git show 78de11e -- src/transport/tcp/tcp_transport.cpp` and the
  prior guard's origin at `git show 3d61147`. Decide whether the removed
  `isLocalHost(...)` -> `bad_address` rejection was (a) accidental/obsolete
  and safe to leave removed, or (b) a deliberate SSRF-style safety control
  that should be restored (potentially in a narrower form, e.g.
  gater-mediated rather than unconditional).
result: pass
note: |
  Resolved via quick task 260827-2w7. The `isLocalHost(...)` -> `bad_address`
  guard was restored in both `TcpTransport::dial()` overloads, matching the
  pre-78de11e shape, but gated behind a new DI-injectable
  `AllowLoopbackDial` value type (following the `PskHandle` precedent --
  explicit non-aggregate constructors, not a bare `bool` ctor param).
  Defaults to `false` (reject) when no override is bound -- secure by
  default. Integrators opt in via a new `injector::useAllowLoopbackDial()`
  DI helper in `network_injector.hpp`, matching the `usePrivateNetwork()`/
  `useConnectionGater<T>()` naming convention.
  `test/acceptance/p2p/pnet/pnet_two_node_test.cpp`'s `makeNode<Marker>()`
  now opts in explicitly since it legitimately needs live loopback TCP
  dialing between its DI-assembled nodes. None of `example/05-private-network`,
  `example/06-private-network-gater`, `example/07-connection-gater` needed
  source changes: 05 never dials at all, and 06/07's denylisted-peer
  self-dial is rejected earlier at `DialerImpl::interceptPeerDial`
  (confirmed via grep of `dialer_impl.cpp`: `interceptPeerDial` at line 71,
  before any `tr->dial(` call in `rotate()`), before
  `TransportAdaptor::dial()` is ever invoked -- confirmed empirically too,
  since both examples' smoke runs printed their denylist-rejection message
  with no `useAllowLoopbackDial()` opt-in present.
  Verified green: full Debug rebuild (all 8 named regression ctest targets
  build and link; `tcp_listener_test`'s 2 pre-existing MSVC/Windows
  `ERROR_OPERATION_ABORTED`-vs-`operation_canceled` failures persist,
  unrelated to this change, already documented in STATE.md); all 3 example
  binaries built and, under a bounded timeout, printed their documented
  proof strings ("Private-network server started",
  "denylisted peer correctly rejected by the custom gater", "still denied
  by the gater").

## Summary

total: 1
passed: 1
issues: 0
pending: 0
skipped: 0
blocked: 0

## Gaps
