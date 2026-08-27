---
status: testing
phase: 03-hardening-live-validation-documentation
source: [03-VERIFICATION.md]
started: 2026-08-27T03:39:26Z
updated: 2026-08-27T03:39:26Z
---

## Current Test

number: 1
name: Loopback-dial guard removal in TcpTransport::dial()
expected: |
  Either (a) confirmation that the prior loopback-rejection guard
  (added in commit 3d61147, "Added localhost filter") was unintentional/
  incorrect and its removal in 78de11e is accepted, or (b) the guard is
  restored with a narrower carve-out (e.g. only bypassed for test builds,
  or gated behind an explicit opt-in) so a malicious peer's PeerInfo
  cannot induce this node to dial its own loopback-bound services by
  default.
awaiting: user response

## Tests

### 1. Loopback-dial guard removal (TcpTransport::dial())
expected: |
  Review `git show 78de11e -- src/transport/tcp/tcp_transport.cpp` and the
  prior guard's origin at `git show 3d61147`. Decide whether the removed
  `isLocalHost(...)` -> `bad_address` rejection was (a) accidental/obsolete
  and safe to leave removed, or (b) a deliberate SSRF-style safety control
  that should be restored (potentially in a narrower form, e.g.
  gater-mediated rather than unconditional).
result: [pending]

## Summary

total: 1
passed: 0
issues: 0
pending: 1
skipped: 0
blocked: 0

## Gaps
