# Pitfalls Research: Connection Gater & Private Networks (pnet)

**Domain:** libp2p access control — Connection Gater hooks + PSK-based private networks (pnet), applied to a brownfield C++17 cpp-libp2p fork
**Researched:** 2026-08-25
**Confidence:** MEDIUM (ecosystem/spec claims: MEDIUM, cross-checked against official libp2p spec + go-libp2p source/issue discussion; this-codebase claims: HIGH, grounded directly in current source reads of `tcp_transport.cpp`, `plaintext.cpp`, `upgrader_session.cpp`, `network_injector.hpp`, and `.planning/codebase/CONCERNS.md`)

## Critical Pitfalls

### Pitfall 1: Gating only some of the 5 stages, or gating them inconsistently

**What goes wrong:**
A gater is wired into `Dialer` (peer/addr dial) and `Upgrader`/`UpgraderSession` (secured/upgraded) but the accept path (`TcpListener` → `ListenerManager`) is skipped, or vice versa. The net effect: a peer blocked at `InterceptPeerDial` can still get in via a raw inbound connection because `InterceptAccept` was never wired, or a peer allowed through `InterceptAccept` is never re-checked at `InterceptSecured` once its real peer ID is known (post-handshake identity), which is the entire point of that hook (pre-handshake `InterceptAccept` only has the IP, not the identity).

**Why it happens:**
The 5 hooks live in 3 structurally distant places — `Dialer` (network layer), `TcpListener`/`ListenerManager` (transport/network boundary), and `UpgraderSession::onSecured` / the final `handler_` callback in `upgrader_session.cpp` (transport/impl). There's no single chokepoint in this codebase today; a dev wiring the gater into `Upgrader` (the "obvious" place since it drives raw→secure→muxed) will naturally hit `InterceptSecured`/`InterceptUpgraded` but has to remember to separately go add `InterceptAccept` to `TcpListener` and `InterceptPeerDial`/`InterceptAddrDial` to `DialerImpl` — three separate PRs' worth of surface, easy to partially finish.

**How to avoid:**
- Treat the 5-hook gater as one feature with one acceptance test matrix (5 hooks × accept/reject × inbound/outbound = 20 cells), not 3 independent integrations.
- Bind a single `ConnectionGater` interface through DI (`network_injector.hpp`) and have exactly one call site per hook — grep for all 5 method names across the codebase during code review to confirm each is called exactly once at the intended pipeline stage.
- Match go-libp2p's own convention (verified in this research): `InterceptSecured` is called for **both** inbound and outbound after security handshake, `InterceptUpgraded` for both after muxer negotiation — do not special-case outbound-only or inbound-only for these two.

**Warning signs:**
- A `ConnectionGater` unit test suite that covers `InterceptPeerDial`/`InterceptAddrDial` thoroughly but has zero test cases for `InterceptAccept` (or vice versa).
- Grep shows a hook method referenced in the interface/mock but never called anywhere in `src/`.

**Phase to address:** Gater hook wiring phase — write the 20-cell test matrix *before* implementing any single hook, so partial wiring is visible immediately in test coverage rather than discovered later.

---

### Pitfall 2: PSK protector applied after (not before) multistream/security negotiation — leaking protocol IDs and metadata to non-participants

**What goes wrong:**
The pnet protector is spliced in *after* `Upgrader` already ran multiselect to negotiate the security protocol (noise/plaintext/secio/tls) and muxer (yamux), instead of wrapping the raw TCP byte stream *before* any multistream-select bytes are exchanged. Result: any TCP-level observer or connecting party — even one without the PSK — can see which security/muxer protocol IDs a node speaks (`/noise/1.0.0`, `/yamux/1.0.0`, etc.), which stage-by-stage narrows fingerprinting/targeting of the private network, and defeats the pnet spec's explicit design goal ("designed to leak the absolute minimum of information on its own").

**Why it happens:**
In this codebase, `Upgrader`/`UpgraderSession` already owns the raw→secure→muxed pipeline (`upgradeToSecureOutbound`/`upgradeToSecureInbound` → `upgradeToMuxed`), and it's tempting to add pnet as "one more stage" inserted *inside* that pipeline (e.g., as a pseudo-`SecurityAdaptor`) rather than as a wrapper applied to the `RawConnection` *before* it's handed to the `Upgrader` at all. The former is architecturally convenient (fits the existing adaptor pattern) but wrong per spec — the PSK layer must protect the *entire* connection including the multistream-select handshake bytes.

**How to avoid:**
- Confirmed via the official libp2p pnet spec and go-libp2p transport-upgrader source: the `Protector` wraps the raw connection at the transport level, before multistream negotiation starts. Implement pnet as a transform on `RawConnection` (`RawConnection → RawConnection`, PSK-protected) applied in `TcpTransport::dial`/`TcpListener` accept path, *before* the connection is handed to `UpgraderSession`/`Upgrader` — not as a `SecurityAdaptor` registered with multiselect.
- Only the 24-byte nonce exchange itself is sent in the clear (by design, per spec) — everything else, including the multistream-select protocol negotiation, must be inside the XSalsa20 keystream.
- Add a regression test that captures raw bytes on the wire (loopback pcap or an in-process byte-tap `RawConnection` decorator) for a pnet-enabled dial and asserts nothing but the nonce is unencrypted.

**Warning signs:**
- Any design where pnet is registered via the same DI mechanism as `useSecurityAdaptors<...>()` / participates in multiselect protocol-ID negotiation.
- A dial that succeeds against a peer using a *different* PSK but proceeds far enough to attempt multiselect (should instead fail immediately/silently at the byte level, since XSalsa20 with the wrong key produces garbage that multiselect will reject, but if pnet is applied post-negotiation, multiselect ID bytes will have already been visible on the wire regardless of PSK correctness).

**Phase to address:** pnet wrapper phase — this is the single most important design decision for that phase; get the wrap point right before writing any protector code.

---

### Pitfall 3: PSK key material handling — no length/format validation, no zeroing, accidental logging

**What goes wrong:**
The PSK is loaded (DI config, file, env var) without validating it's exactly 256 bits (32 bytes), accepted in an unexpected encoding (raw vs base16 vs base64 vs the `/key/swarm/psk/1.0.0/.../` multicodec-path text format used by `swarm.key` files) without disambiguation, held in a `std::string`/`std::vector<uint8_t>` that's copied around (into lambda captures, DI singletons, logger calls) without ever being zeroed, and/or accidentally logged in a debug trace (this codebase already has `SL_DEBUG`/`log_->error` calls sprinkled through the security adaptors, e.g. `plaintext.cpp`, and `iostream`/`std::cout` debug prints in `tcp_transport.cpp` — a copy-pasted debug line touching PSK-adjacent state is a realistic mistake).

**Why it happens:**
C++17 has no built-in secure-erase primitive (no `zeroize` crate equivalent) and no existing convention for secret handling in this codebase (grep shows no existing "secure buffer" type). Ordinary `std::vector<uint8_t>`/`std::string` destruction does not guarantee zeroing — the compiler can optimize away a manual `memset` before deallocation. Multiple lambda captures (this codebase's dial/accept callbacks all capture `shared_from_this()`/config objects by value) create multiple live copies of secret bytes each with independent lifetime, several of them living inside `shared_ptr`-captured lambdas that survive on the heap until the async chain completes.

**How to avoid:**
- Validate PSK length (32 bytes) and format explicitly at config-load time with an `outcome::result<PSK, Error>` return (matches the codebase's existing `outcome::result<T>` error-handling convention — see Pitfall 8 below) — do not accept a raw arbitrary-length byte string silently.
- Use `OPENSSL_cleanse()` (OpenSSL is already a dependency per `CONCERNS.md`'s note on `ba0eb39` "Fix openssl error lock on shutdown") or an equivalent explicit, non-optimizable clear function in the PSK holder's destructor — do not rely on a plain `memset`.
- Wrap the PSK in a dedicated small type (e.g. `PreSharedKey`) with deleted copy constructor (only move/shared_ptr), so the number of live copies is bounded and auditable, rather than passing raw `std::vector<uint8_t>` through multiple layers.
- Grep for the PSK type/variable name before merging each PR in this phase to confirm it never reaches a `log_->`/`SL_DEBUG`/`std::cout` call.

**Warning signs:**
- PSK config type is a bare `std::string`/`std::vector<uint8_t>` with default copy semantics.
- No dedicated PSK validation error code exists in the equivalent of `src/security/error.cpp`.
- ASan/Valgrind not run over the PSK holder's destruction path to confirm no dangling copies.

**Phase to address:** pnet wrapper phase (design of the PSK holder type) + testing phase (verify no plaintext PSK bytes survive after teardown, and add a "PSK never logged" grep/test check to CI).

---

### Pitfall 4: PSK-only "access control" is not peer authentication — bridging/confused-deputy risk

**What goes wrong:**
The team treats "has the correct PSK" as equivalent to "is an authorized peer" and stops there. A node that legitimately holds the PSK (e.g., a leaked key, or a compromised/rogue node) can transparently bridge the private network to the public network or to a different private network, because PSK encryption alone provides no identity verification — it only proves "this byte stream is XSalsa20-encrypted with the same 256-bit secret," not "this specific peer is authorized." This is a documented, acknowledged limitation of the pnet design itself (see `libp2p/go-libp2p-pnet` issue #3), not a bug — but it becomes a *pitfall* if the roadmap/docs imply pnet alone is sufficient access control for "permissioned" SuperGenius networks per this project's stated Core Value.

**Why it happens:**
PSK feels like "the" access-control mechanism because it's the one that rejects connections outright (garbage decrypts to garbage, multiselect fails, connection drops) — it's visibly effective in the two-node happy-path/reject-path acceptance test this project's roadmap already calls for. The subtler bridging/leak risk (a legitimate PSK holder relaying traffic to an unauthorized party) doesn't show up in that test at all.

**How to avoid:**
- Document clearly (per this project's own "Integrator documentation" requirement) that pnet provides *network isolation*, not *peer authorization* — the Connection Gater (peer ID allow/deny lists, `InterceptSecured` checking the now-known peer identity) is the actual authorization layer, and the two features are complementary, not redundant.
- Recommend combining pnet with a Connection Gater policy that checks peer identity post-handshake (`InterceptSecured`) against an allow-list, so a bridging/rogue PSK holder is still constrained by peer-identity policy, not just key possession.
- Explicitly scope PSK rotation/revocation as a known gap in docs (if the PSK leaks, the only remediation is rotating the key across the whole network — there's no per-peer revocation via pnet alone).

**Warning signs:**
- Docs or roadmap language treating "PSK configured" as the complete definition of "private/permissioned network," without mentioning peer-identity gating as the complementary control.
- No test scenario for "PSK-holding peer, but not on the gater allow-list" (should be rejected by the gater even though pnet accepted it).

**Phase to address:** Requirements/roadmap framing (make sure the roadmap phase for gater and the phase for pnet are explicitly described as *complementary*, not either/or) + integrator documentation phase.

---

### Pitfall 5: `InterceptAccept` checked too late — after the upgrade pipeline has already started work

**What goes wrong:**
`InterceptAccept` is meant to be the earliest inbound check — called "as soon as a transport listener receives an inbound connection request, before any upgrade takes place." If it's instead checked only inside `UpgraderSession`/`onSecured` (i.e., effectively merged with the `InterceptSecured` check), the library has already spent CPU/allocation on TCP accept, `TcpConnection` construction, and potentially a full security handshake before rejecting a connection that should have been dropped immediately at accept time. This is a real, documented mistake — go-libp2p's own QUIC transport hit exactly this ambiguity (couldn't cleanly distinguish "reject at accept" from "reject after handshake") and had to choose between dropping packets early, closing before handshake, or completing the handshake and rejecting after.

**Why it happens:**
In this codebase, `TcpListener` (accept) and `UpgraderSession` (secure/upgrade) are separate classes with a callback handoff between them; `InterceptAccept` naturally belongs at the `TcpListener`/`ListenerManager` boundary, but it's easy to defer it to inside `UpgraderSession` where the gater is already needed for `InterceptSecured`/`InterceptUpgraded`, especially since that's a single, tidy insertion point.

**How to avoid:**
- Wire `InterceptAccept` at `TcpListener`'s raw-accept callback, before `UpgraderSession` is even constructed — reject and close the raw socket immediately, never handing it to the `Upgrader`.
- This also matters for resource exhaustion / DoS resistance: this codebase's `CONCERNS.md` already flags gossip's lack of peer banning and unbounded growth as a known gap — an `InterceptAccept` that's effectively a no-op (because it's really checked post-handshake) provides zero protection against connection-flood attacks aimed at exhausting handshake/CPU resources.

**Warning signs:**
- `InterceptAccept` and `InterceptSecured` calls are adjacent in the same function/callback rather than in genuinely separate pipeline stages.
- Load-testing a rejected-peer flood shows CPU/allocation cost proportional to full handshake attempts rather than to raw accept + immediate close.

**Phase to address:** Gater hook wiring phase (`TcpListener`/`ListenerManager` integration specifically) — should be its own sub-task distinct from the `Upgrader`-side `InterceptSecured`/`InterceptUpgraded` wiring.

---

### Pitfall 6: Reentrant synchronous callback invocation from a gater hook or PSK completion handler — this codebase's existing anti-pattern, extended into new code

**What goes wrong:**
A gater hook (e.g., `InterceptAddrDial`) or the pnet handshake's completion callback invokes its result callback *synchronously*, inline, from within the same call stack that initiated the dial/accept — exactly the pattern already marked `TODO(107): Reentrancy` at 10 sites in this codebase, including `src/transport/tcp/tcp_transport.cpp:32` (`return handler(std::errc::address_family_not_supported)` called synchronously, in the *same stack frame* as `TcpTransport::dial()`, before any async operation even starts) and the plaintext security adaptor's send/receive callback chains (`src/security/plaintext/plaintext.cpp:122,144`). If a new `ConnectionGater::InterceptAddrDial` check is inserted at the top of `TcpTransport::dial` following the same style as the existing `canDial()` check just above it, a caller iterating a list of pending dials (or a container of candidate addresses) that doesn't expect a same-frame synchronous callback can have that container mutated mid-iteration — the exact class of bug this codebase's git history (`78a845b`, `d26b61b`) shows recurring.

**Why it happens:**
The existing code already does this: `TcpTransport::dial()` calls `handler(...)` directly and synchronously for the `canDial()`/localhost checks, marked with its own unresolved `TODO(107)` comment acknowledging the problem. A gater/pnet author copying this exact adjacent pattern (very likely, since it's the nearest example in the file) will reproduce the same defect in new code, and `UpgraderSession::onSecured` similarly invokes `handler_(...)` directly inline rather than via `post()`/`dispatch()` on the io_context — so an `InterceptSecured`/`InterceptUpgraded` check inserted there inherits the same risk.

**How to avoid:**
- Do not follow the adjacent `canDial()`/localhost-check style in `tcp_transport.cpp` as a template for the new gater checks — that style is explicitly flagged as broken (`TODO(107)`), not exemplary.
- Route all gater-hook and PSK-completion callback invocations through the `Scheduler`'s `post()` (or `io_context::post`) so the caller's stack always unwinds before the result is delivered, even in the synchronous-reject case (PSK mismatch, gater deny). This is the exact fix approach `CONCERNS.md` already recommends for the existing `TODO(107)` sites — apply it to the *new* code from day one rather than adding new instances of the same defect.
- Per this project's own Key Decision ("fix root-cause bugs encountered in touched fragile code... rather than working around them") — since this phase necessarily touches `tcp_transport.cpp` and `upgrader_session.cpp` to wire hooks in, consider fixing the adjacent `TODO(107)` reentrancy in those exact functions as part of the same change, rather than layering new reentrancy-safe code next to old reentrancy-unsafe code in the same function.
- Add a targeted regression test that forces a synchronous-reject path (gater denies immediately, PSK check fails immediately) and asserts the callback is *not* invoked within the originating call's stack frame (e.g., using a re-entrancy guard/flag or a call-depth counter in the test).

**Warning signs:**
- New gater/pnet code that calls its callback directly (`return handler(...)`, `cb(...)`) without first going through `scheduler_->post(...)` or equivalent, especially on the "reject" fast path where there's no actual I/O to wait for.
- Stack traces during a gater-deny scenario show the deny callback nested directly inside the originating `dial()`/`accept()` call.

**Phase to address:** Gater hook wiring phase and pnet wrapper phase (both must apply this from initial implementation) — verified in testing phase with an explicit reentrancy regression test, mirroring what `CONCERNS.md` recommends for the existing 10 `TODO(107)` sites.

---

### Pitfall 7: Exception safety across DI-constructed gater/PSK adaptors — inconsistent with the codebase's `outcome::result<T>` convention

**What goes wrong:**
A new `ConnectionGater` implementation or PSK config object validates its input (e.g., PSK length, allow-list format) by `throw`ing in its constructor. Because Boost.DI (`network_injector.hpp`) constructs the entire object graph at `injector.create<std::shared_ptr<Host>>()` time via compile-time-wired constructors, that exception propagates straight out of `injector.create<...>()` — uncaught, with a stack trace pointing into DI-generated code rather than application code, and inconsistent with the rest of the codebase's established `outcome::result<T>` error-handling strategy (per `ARCHITECTURE.md`: "explicit, allocation-light error propagation instead of exceptions for expected failure paths," with dedicated error-code enums per subsystem, e.g. `src/security/error.cpp`).

**Why it happens:**
Constructor-time validation with exceptions is the path of least resistance in C++ (constructors can't return `outcome::result<T>`), and Boost.DI's compile-time binding style makes it easy to forget that "the DI graph construction step" is itself a fallible operation that the application startup code needs to handle — nothing in the existing `makeNetworkInjector`/`makeHostInjector` examples in this codebase shows a try/catch around `injector.create<...>()`.

**How to avoid:**
- Keep constructors of the new `ConnectionGater`/PSK adaptor types exception-*free* for expected failure modes (invalid PSK length, malformed allow-list) — validate in a separate factory/`init()` step that returns `outcome::result<T>`, called *before* the DI graph is constructed (e.g., validate PSK config up front, pass only an already-validated value type into the DI graph via `di::bind<...>.to(validatedInstance)`).
- Reserve exceptions strictly for genuine programmer-error/invariant violations (`BOOST_ASSERT`-style, as already used in `Plaintext`'s constructor for non-null dependency checks) — not for "the user configured a bad PSK," which is an expected, recoverable failure mode.
- If a throwing path is unavoidable somewhere in the DI graph, wrap the specific `injector.create<...>()` call site in application/example code with try/catch and document it — do not leave it as an undocumented "may throw" surface.

**Warning signs:**
- New PSK/gater config types with validation logic inside their constructor body rather than a separate factory function.
- No existing precedent grep-able in `src/injector/` or `example/` for handling a throwing `injector.create<...>()`.

**Phase to address:** DI/injector integration phase (gater + PSK config bindings) — decide the validation strategy before writing the binding code, since retrofitting it after the constructor signature is fixed is more disruptive.

---

### Pitfall 8: Thread-safety of gater/PSK state if hooks fire from multiple io_context threads

**What goes wrong:**
A `ConnectionGater` implementation holds mutable state (a dynamic ban list, a counter, an allow-list that can be updated at runtime) without synchronization, on the assumption that all hook invocations happen on a single io_context thread. If the application runs `io_context::run()` on a thread pool (a legitimate, already-anticipated configuration per `ARCHITECTURE.md`'s own note: "Boost.Asio `io_context`-driven single- or multi-threaded event loop; components generally assume handlers run on the io_context's thread(s) unless explicitly synchronized"), `InterceptAccept` for one inbound connection and `InterceptPeerDial` for an outbound dial can execute concurrently on different threads, racing on the gater's internal state — the same category of bug that forced the recursive-mutex retrofit in `SchedulerImpl` (`d26b61b`) and the race/teardown fixes in `YamuxedConnection`/`TcpConnection` (`78a845b`).

**Why it happens:**
The gater interface itself (5 simple predicate-style methods) doesn't visually suggest "this needs a mutex" the way a stateful connection class does — it's easy to implement it as a simple in-memory set/vector without threading it through the same locking discipline the rest of this codebase had to learn the hard way. Similarly, if a single PSK protector/security-adaptor *instance* is shared across multiple concurrent connections (rather than one protector state machine per connection), its per-connection nonce/keystream-position state is a shared-mutable-state race waiting to happen.

**How to avoid:**
- Design the `ConnectionGater` implementation's internal state with explicit synchronization from the start (a plain `std::mutex`, or immutable snapshot-swap for allow/deny lists) — do not assume single-threaded access just because the initial two-node acceptance test only exercises one thread.
- Ensure the pnet protector's per-connection state (nonce, XSalsa20 keystream position/counter) is owned per-`RawConnection` instance, never shared/reused across connections — reusing a keystream position across connections is also a cryptographic nonce-reuse risk, not just a concurrency bug.
- Explicitly document (mirroring `CONCERNS.md`'s existing recommendation for the Scheduler) which gater/PSK methods are safe to call from any thread vs. which assume the io_context thread, rather than leaving it implicit.
- Add a stress test that exercises concurrent dial + accept + gater-state-mutation (e.g., dynamically updating a ban list) under ASan/TSan, matching the testing gap `CONCERNS.md` already flags project-wide ("historical race/deadlock/crash fixes appear to have been validated primarily through manual testing and ASan runs rather than committed automated regression tests").

**Warning signs:**
- Gater implementation compiles and passes single-threaded unit tests but has no TSan/concurrent stress test.
- Any `mutable` state in the gater class without an accompanying mutex or documented single-thread invariant.

**Phase to address:** Gater hook wiring phase (design) + testing phase (TSan/ASan concurrent stress test, following the same pattern this project's constraints already call for: "fix root-cause bugs... rather than working around them").

---

### Pitfall 9: Gater-driven connection teardown reintroducing TCP teardown races

**What goes wrong:**
When a gater hook rejects a connection post-accept or post-secure (`InterceptAccept` returning false, or `InterceptSecured` returning false after a completed handshake), the rejecting code path closes the connection through an ad hoc/shortcut route (e.g., directly closing the underlying socket, or calling `close()` from within the gater-hook's own callback stack) instead of going through the same teardown path already hardened by `78a845b` ("Fixed race conditions and teardown in `YamuxedConnection` and `TcpConnection`") and `af85794` ("Fixed teardown bugs in Windows"). This risks resurrecting exactly the platform-specific (Windows) and general teardown races those commits fixed, because the new "reject and close" path is a *new* code path through `TcpConnection`'s lifecycle that the existing hardening wasn't written to specifically anticipate.

**Why it happens:**
"Just close the socket" feels like the simplest possible response to a gater rejection, and it's tempting to bypass the full connection-manager-mediated close/destroy sequence for what looks like an edge case (a connection that never even become part of `ConnectionManager`'s tracked set). But `TcpConnection`'s teardown fragility (per `CONCERNS.md`) is specifically about "the shutdown sequence interacts with platform socket semantics in ways not fully abstracted" — an early, ad hoc close is exactly the kind of code path least likely to have been exercised by the existing teardown fixes/tests.

**How to avoid:**
- Route gater-rejection closes through the same `TcpConnection::close()` (or equivalent) path used elsewhere, not a bespoke shortcut — reuse the already-hardened teardown code rather than adding a parallel one.
- Explicitly test gater-rejection-triggered teardown on both Windows and POSIX (per `CONCERNS.md`'s existing recommendation: "recommend explicit CI coverage on Windows for shutdown/destructor sequences" — this is a new trigger for that same code, so the recommendation applies directly to it).
- Watch for the reentrant-callback risk (Pitfall 6) compounding this: if the gater-rejection close is invoked synchronously from within an accept/read completion handler, it's touching the same reentrancy-sensitive teardown code the `TODO(107)` markers in `tcp_transport.cpp` already flag as risky.

**Warning signs:**
- A new/separate code path for "close due to gater rejection" that doesn't share code with the normal connection-close path.
- No Windows-specific test run for the gater-reject-and-teardown scenario.

**Phase to address:** Gater hook wiring phase (implementation) + testing phase (explicit Windows + POSIX teardown coverage for the reject path specifically, not just the happy path).

---

### Pitfall 10: Default no-op gater implemented as a nullable pointer checked ad hoc at each of the 5 call sites

**What goes wrong:**
Rather than binding a genuine `DefaultConnectionGater` (null-object pattern, always-allow) through DI, the implementation uses a `nullptr`/`std::optional<std::shared_ptr<ConnectionGater>>` and checks `if (gater_) { ... }` independently at each of the 5 call sites. Over time, one call site's null-check is written slightly differently (e.g., treats null as "deny" instead of "allow," or is simply forgotten when a new call site is added later — e.g., if relay/holepunch dial paths, which this codebase already has, need gating too), silently breaking the "preserve existing behavior when no gater is configured" requirement at exactly one of the 5-20 cells from Pitfall 1's matrix.

**Why it happens:**
A nullable pointer is the path of least resistance in C++, and each of the 5 call sites is in a different file (`dialer_impl.cpp`, `tcp_listener.cpp`, `upgrader_session.cpp`) written by potentially different people/PRs — there's no single place enforcing "no-gater-configured always means allow."

**How to avoid:**
- Follow this codebase's existing adaptor pattern (per `include/libp2p/injector/*.hpp` — "no direct `new`/`make_shared` construction outside the DI graph"): bind a concrete `DefaultConnectionGater` (always returns allow/success for all 5 hooks) as the DI default, so every call site unconditionally calls `gater_->InterceptX(...)` without ever null-checking. This also sidesteps a null-pointer-dereference risk entirely.
- Write a single test that constructs the host with *no* gater override and asserts all 5 hooks are still invoked (via a spy/no-op that counts calls) and all still return "allow" — proving the default preserves existing behavior by construction, not by convention.

**Warning signs:**
- `if (gater_)` / `gater_.has_value()` checks scattered across multiple files instead of one DI-bound default implementation.
- Existing behavior tests (pre-gater) start failing or need special-casing once the gater is wired in — a sign the "no-op by default" property isn't actually structural.

**Phase to address:** Gater hook wiring phase (this is a design decision to make before, not after, wiring the first hook).

---

## Technical Debt Patterns

| Shortcut | Immediate Benefit | Long-term Cost | When Acceptable |
|----------|-------------------|-----------------|-----------------|
| Implementing pnet as a `SecurityAdaptor` (multiselect-negotiated) instead of a pre-multiselect raw-connection wrapper | Reuses existing adaptor DI pattern, less new plumbing | Leaks multistream protocol IDs to non-PSK-holders (Pitfall 2), diverges from spec | Never — this is a correctness/spec-compliance issue, not a style choice |
| Ad hoc `if (gater_)` null checks instead of a DI-bound `DefaultConnectionGater` | Slightly less code up front | Inconsistent gating coverage over time (Pitfall 10) | Never — the null-object pattern is barely more code |
| PSK held as plain `std::vector<uint8_t>`/`std::string` without a dedicated zeroing type | Faster to prototype | Secret material lingers in memory after use; no auditability of copies | Acceptable only for a throwaway local spike, never for the merged implementation |
| Gater-rejection close via direct socket close instead of shared `TcpConnection::close()` path | Feels simpler for the "never fully connected" case | Reintroduces teardown races this codebase already spent multiple commits fixing (Pitfall 9) | Never |
| Skipping TSan/concurrent stress tests for gater state, relying only on the two-node happy-path acceptance test | Ships faster | This is precisely the category of bug (races validated only manually) `CONCERNS.md` flags as the project's #1 recurring issue | Only for a prototype spike explicitly not intended to merge |

## Integration Gotchas

| Integration | Common Mistake | Correct Approach |
|-------------|-----------------|-------------------|
| Boost.DI (`network_injector.hpp`) + new `ConnectionGater`/PSK bindings | Validating config in the bound type's constructor, letting exceptions escape `injector.create<...>()` | Validate via a separate `outcome::result<T>`-returning step before constructing the DI graph (Pitfall 7) |
| `TcpTransport::dial` / existing `canDial()`+localhost-check pattern | Copying the adjacent synchronous-callback style (already `TODO(107)`-flagged) for new gater checks | Route gater/PSK callback delivery through `scheduler_->post(...)`, never call the handler inline in the same stack frame (Pitfall 6) |
| `UpgraderSession::onSecured` | Inserting `InterceptSecured`/`InterceptUpgraded` calls that invoke `handler_(...)` synchronously within the existing lambda chain | Same as above — defer via post/dispatch; also confirm `shared_from_this()` lifetime is still valid across the deferred call |
| pnet spec's `swarm.key` PSK file format | Accepting only raw 32 bytes and not the documented `/key/swarm/psk/1.0.0/<encoding>/<data>` textual multicodec-path format (or vice versa) — a format mismatch with any future interop tooling | Follow the spec's documented format even though go-libp2p interop testing is explicitly out of scope for this project — per this project's own Constraint: "pnet/PSK implementation should follow the libp2p pnet spec... to preserve future compatibility" |

## Security Mistakes

| Mistake | Risk | Prevention |
|---------|------|------------|
| Treating PSK possession as full peer authorization | Bridging/confused-deputy risk — a rogue PSK holder relays traffic between private/public networks (Pitfall 4) | Combine pnet with gater-based peer-identity checks at `InterceptSecured`; document PSK as network-isolation, not authorization |
| PSK applied after multistream negotiation | Protocol-ID/metadata leak to non-participants (Pitfall 2) | Wrap `RawConnection` with the PSK protector before handing it to `Upgrader` |
| No PSK zeroing / accidental logging | Secret key material lingers in process memory or ends up in debug logs (Pitfall 3) | Dedicated non-copyable PSK type with explicit `OPENSSL_cleanse()`-style destructor; grep for PSK var name in all log call sites before merge |
| `InterceptAccept` effectively merged with `InterceptSecured` (checked too late) | Connection-flood/DoS resistance is nullified — attacker forces full handshake cost even for connections that should've been dropped instantly (Pitfall 5) | Wire `InterceptAccept` at raw-accept time in `TcpListener`, before `UpgraderSession` construction |
| Gater/PSK state races under multi-threaded io_context | Time-of-check/time-of-use gaps in access-control decisions; potential for a denied peer to slip through during a state update window | Explicit synchronization discipline for all mutable gater/PSK state (Pitfall 8), stress-tested under TSan |

## "Looks Done But Isn't" Checklist

- [ ] **Connection Gater:** All 5 hooks may be implemented in the interface, but verify each is actually *called* at its intended pipeline stage — grep every hook method name across `src/network/impl/`, `src/transport/tcp/`, `src/transport/impl/` and confirm exactly one call site per hook, at the correct stage (Pitfall 1, 5).
- [ ] **pnet wrapper:** "Two nodes with matching PSK connect, mismatched PSK rejected" may pass, but verify the wrap point is *before* multistream-select (not just that rejection works) — capture raw bytes on the wire and confirm no protocol IDs leak pre-PSK-check (Pitfall 2).
- [ ] **PSK config:** May accept a 32-byte key correctly, but verify it's zeroed on destruction, never copied more than necessary, and never reaches a log statement (Pitfall 3).
- [ ] **DI wiring:** `makeNetworkInjector(...)` may build successfully in the happy path, but verify what happens when an *invalid* PSK/gater config is supplied — does `injector.create<...>()` throw uncaught, or fail gracefully (Pitfall 7)?
- [ ] **Default (no-op) gater:** May "work" in manual testing, but verify it's a genuine DI-bound null-object implementation, not scattered `if (gater_)` checks that could silently diverge later (Pitfall 10).
- [ ] **Thread safety:** Unit tests may all pass single-threaded, but verify gater/PSK state under a multi-threaded `io_context::run()` configuration with TSan (Pitfall 8) — this codebase's own architecture doc confirms multi-threaded io_context is a supported configuration, not a hypothetical.
- [ ] **Teardown on rejection:** A gater-denied connection may appear to "just work" (socket closes, test passes) on your dev machine, but verify it's exercised on Windows specifically, given this codebase's documented history of Windows-specific teardown bugs (Pitfall 9).

## Recovery Strategies

| Pitfall | Recovery Cost | Recovery Steps |
|---------|----------------|-----------------|
| Pitfall 1 (incomplete 5-stage gating) | LOW | Add the missing call site(s); low blast radius since it's additive, not a rewrite |
| Pitfall 2 (PSK wrapped post-negotiation) | HIGH | Requires moving the wrap point from inside `Upgrader`'s pipeline to `TcpTransport`/`TcpListener` — touches connection construction on both dial and accept paths; effectively a redesign of the pnet integration, not a patch |
| Pitfall 3 (PSK not zeroed/logged) | MEDIUM | Introduce the dedicated PSK type retroactively, migrate call sites, audit + purge any log statements that touched it; also consider the leaked value already compromised (rotate PSK) if it reached production logs |
| Pitfall 6 (reentrant callbacks) | MEDIUM–HIGH | Same fix approach `CONCERNS.md` already prescribes project-wide: defer via `post()`/`dispatch()`; requires careful audit of every new gater/PSK callback path plus regression tests, but is mechanical once identified |
| Pitfall 7 (DI exception safety) | LOW–MEDIUM | Move validation out of constructors into a pre-DI factory step; contained to the specific new gater/PSK binding code |
| Pitfall 8 (thread-safety races) | HIGH | Races are notoriously hard to reproduce/fix after the fact (see this codebase's own multi-commit history chasing scheduler/yamux races) — cheaper to design in synchronization up front than retrofit |
| Pitfall 9 (teardown races on rejection) | MEDIUM–HIGH | Same class of fix as the existing `78a845b`/`af85794` commits — expect it to require careful, possibly platform-specific, iteration, not a one-line fix |

## Pitfall-to-Phase Mapping

| Pitfall | Prevention Phase | Verification |
|---------|-------------------|---------------|
| 1. Incomplete/inconsistent 5-stage gating | Gater hook wiring phase | 20-cell (5 hooks × allow/deny × in/out) test matrix; grep confirms exactly one call site per hook |
| 2. PSK wrapped after security negotiation | pnet wrapper phase | Wire-capture test proving no multistream/protocol-ID bytes appear before PSK-layer decryption succeeds |
| 3. PSK key material mishandling | pnet wrapper phase (design) | ASan/Valgrind check for lingering PSK bytes post-teardown; log-grep check for the PSK variable in CI |
| 4. PSK-only bridging/confused-deputy risk | Requirements/roadmap framing + integrator docs phase | Docs explicitly describe pnet + gater as complementary; test case for "valid PSK, gater-denied peer" |
| 5. `InterceptAccept` checked too late | Gater hook wiring phase (`TcpListener` sub-task) | Load test showing rejected-peer flood costs ~accept-only resources, not full-handshake resources |
| 6. Reentrant synchronous callbacks in new gater/PSK code | Gater hook wiring phase + pnet wrapper phase | Reentrancy regression test asserting deny/reject callbacks never fire within the originating call's stack frame |
| 7. DI construction exception safety | DI/injector integration phase | Test constructing the host with an invalid PSK/gater config and assert a graceful `outcome::result`-style failure, not an uncaught exception from `injector.create<...>()` |
| 8. Gater/PSK thread-safety under multi-threaded io_context | Gater hook wiring phase (design) + testing phase | TSan-enabled concurrent stress test: simultaneous dial/accept/gater-state-mutation |
| 9. Gater-rejection teardown races | Gater hook wiring phase (implementation) + testing phase | Windows + POSIX CI coverage specifically for the gater-reject-and-close path |
| 10. Ad hoc null-gater checks instead of DI default | Gater hook wiring phase (design) | Test: host built with no gater override still invokes all 5 hooks via a spy no-op, all returning allow |

## Sources

- [go-libp2p-core connmgr/gater.go](https://github.com/libp2p/go-libp2p-core/blob/master/connmgr/gater.go) — MEDIUM confidence (official libp2p org repo; hook semantics cross-checked across 3 independent web searches)
- [Connection Gating · Issue #872 · libp2p/go-libp2p](https://github.com/libp2p/go-libp2p/issues/872) — MEDIUM confidence (design discussion, official repo)
- [PR #152 · libp2p/go-libp2p-quic-transport — gate QUIC connections via new ConnectionGater](https://github.com/libp2p/go-libp2p-quic-transport/pull/152) — MEDIUM confidence (source of the "InterceptAccept checked too late" real-world pitfall, official repo)
- [libp2p/specs — pnet/Private-Networks-PSK-V1.md](https://github.com/libp2p/specs/blob/master/pnet/Private-Networks-PSK-V1.md) — MEDIUM confidence (verified official spec, fetched directly)
- [libp2p/go-libp2p-pnet Issue #3 — nonce exhaustion and bridging](https://github.com/libp2p/go-libp2p-pnet/issues/3) — MEDIUM confidence (official repo, security-analysis discussion, fetched directly; source of Pitfall 4)
- [go-libp2p-transport-upgrader package docs](https://pkg.go.dev/github.com/libp2p/go-libp2p-transport-upgrader) — MEDIUM confidence (protector wrap-order confirmation)
- `.planning/codebase/CONCERNS.md` — HIGH confidence (primary source, this codebase, read in full)
- `.planning/codebase/ARCHITECTURE.md` — HIGH confidence (primary source, this codebase, read in full)
- `.planning/codebase/TESTING.md` — HIGH confidence (primary source, this codebase, read in full)
- `src/transport/tcp/tcp_transport.cpp` (this codebase, read directly) — HIGH confidence, source of Pitfall 6's concrete reentrancy example
- `src/security/plaintext/plaintext.cpp` (this codebase, read directly) — HIGH confidence, source of Pitfall 6's second reentrancy example
- `src/transport/impl/upgrader_session.cpp` (this codebase, read directly) — HIGH confidence, identifies the exact insertion points for `InterceptSecured`/`InterceptUpgraded`
- `include/libp2p/injector/network_injector.hpp` (this codebase, read directly) — HIGH confidence, source of Pitfall 7's DI binding pattern analysis

---
*Pitfalls research for: libp2p Connection Gater & pnet, cpp-libp2p fork (GeniusNetwork)*
*Researched: 2026-08-25*
