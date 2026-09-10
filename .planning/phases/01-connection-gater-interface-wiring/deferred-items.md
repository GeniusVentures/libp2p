# Deferred Items — Phase 01 (connection-gater-interface-wiring)

Items discovered during execution that are **out of scope** per this plan's
scope boundary (pre-existing, unrelated to the current task's changes) and
were intentionally left unfixed.

## 01-04 Task 2: Pre-existing `TcpTransport::dial()`/`TransportAdaptor::dial()` call-site breakage

**Found during:** Plan 01-04, Task 2 (`cmake --build build --target tcp_integration_test all_muxers_acceptance_test`)

**Issue:** `TcpTransport::dial()`/`TransportAdaptor::dial()` requires a `bindaddress`
(or `source_addresses`) parameter with no default value on the 3-positional-arg
overload. 5 call sites in `test/libp2p/transport/tcp/tcp_integration_test.cpp`
(lines 165, 212, 246, 274, 320 post-edit) and 1 in
`test/acceptance/p2p/muxer.cpp` (`Client::connect()`, line ~188) still call
`dial(peerId, address, handler)` with only 3 arguments, which no longer
resolves to any overload.

**Confirmed pre-existing and unrelated to gater wiring:** verified via
`git show 8640b25:...` (the commit immediately preceding all of Phase 01's
work) — these exact call sites already had only 3 arguments at that commit,
predating this phase entirely. The `bindaddress`-required-parameter change
was introduced by an earlier, unrelated commit (`ae18ab7`, "Experimental,
dialing routes now choose an ip6 and ip4 route...") that did not update
these test files.

**Why deferred, not auto-fixed:** Per this plan's Scope Boundary rule, only
issues directly caused by the current task's changes are auto-fixed;
pre-existing failures in unrelated files are logged here instead. This also
matches `.planning/PROJECT.md`'s explicit Out of Scope note: "Auditing/fixing
the general existing test suite's health beyond what this work touches —
its current pass/fail state is unknown."

**Impact on this plan's verification:** `cmake --build build --target
tcp_integration_test all_muxers_acceptance_test` cannot fully succeed until
this pre-existing breakage is fixed — independently of Task 2's own changes
(the 7 `TcpTransport` 4-arg constructor updates in `tcp_integration_test.cpp`
and 2 in `muxer.cpp` compile cleanly; no error references those lines).

**Suggested fix (out of scope for this plan):** add an explicit
`multi::Multiaddress` bind address argument (e.g.
`"/ip4/0.0.0.0/tcp/0"_multiaddr`) to each of the 6 call sites, or add a
convenience overload with a default bind address for test-only callers.

**Status:** Deferred — not fixed by Plan 01-04.
