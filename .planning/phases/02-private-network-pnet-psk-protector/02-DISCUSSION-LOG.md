# Phase 2: Private network (pnet) PSK protector - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-08-26
**Phase:** 2-Private network (pnet) PSK protector
**Areas discussed:** XSalsa20 crypto provider, PSK config surface, Force-pnet trigger (PNET-05), Bootstrap scoping (BOOT-01)

---

## XSalsa20 crypto provider

**Q1: Where does the XSalsa20 primitive come from?**

| Option | Description | Selected |
|--------|-------------|----------|
| Vendor XSalsa20 impl | ~150-line self-contained public-domain implementation under src/crypto/, no new Hunter package, no MSVC/Hunter packaging risk; validated against published test vectors; same approach as go-libp2p | ✓ |
| libsodium via Hunter | Full library for one primitive; cleanest crypto provenance but new Hunter package must build under MSVC 19.44 — flagged phase-blocker risk | |
| Vendor now, libsodium later | Vendored impl behind a narrow interface, swappable to libsodium later | |

**User's choice:** Vendor XSalsa20 impl
**Notes:** Eliminates the STATE.md-flagged libsodium/Hunter early blocker entirely.

**Q2: How should the vendored XSalsa20 be exposed internally?**

| Option | Description | Selected |
|--------|-------------|----------|
| Plain function | Free function(s) in libp2p::crypto namespace, outcome::result style — low-ceremony like existing crypto provider code | ✓ |
| Provider interface | Xsalsa20Provider interface + impl + DI binding, mirroring HmacProvider pattern — more ceremony | |
| You decide | Only locked constraint: vendored, tested, no new dependency | |

**User's choice:** Plain function

**Q3: What validation bar for the vendored cipher?**

| Option | Description | Selected |
|--------|-------------|----------|
| Published test vectors | Official libsodium/Salsa20 test-vector datasets (fixed key+nonce+plaintext → expected ciphertext), mirroring upstream go-libp2p's test approach | ✓ |
| Vectors + stream props | Vectors plus long-stream property tests (keystream non-repetition, offset seek) | |
| You decide | Only capture "must be validated against published vectors" | |

**User's choice:** Published test vectors

**Q4: Where does the 24-byte nonce randomness come from on the initiating side?**

| Option | Description | Selected |
|--------|-------------|----------|
| OpenSSL RNG | RAND_bytes, already wired into the codebase's crypto providers; one RNG source | ✓ (via free-text) |
| Standalone RNG | Vendored CSPRNG or std::random_device — self-contained but second RNG source | |
| You decide | Researcher/planner picks based on random_provider surface on MSVC | |

**User's choice:** (free-text) "What does go-libp2p do? We certainly have openssl available in thirdparty, whatever matches spec."
**Notes:** Answered inline: go-libp2p uses Go's `crypto/rand` (standard OS CSPRNG); OpenSSL `RAND_bytes` is the direct C++ equivalent and already a dependency — locked as OpenSSL RNG.

---

## PSK config surface

**Q1: What PSK input formats does the config surface accept?**

| Option | Description | Selected |
|--------|-------------|----------|
| swarm.key + raw string | go-ipfs swarm.key file text (/key/swarm/psk/1.0.0/ + /base16/ or /base64/) AND raw hex/base64 constructor; existing GNUS swarm.key files work as-is | ✓ |
| Raw bytes/string only | Just 32-byte hex/base64 or byte vector; integrators convert swarm.key files themselves | |
| Raw now, file later | Lock only raw-bytes core; swarm.key parsing as follow-up | |

**User's choice:** swarm.key + raw string

**Q2: How is the PSK bound into the DI graph?**

| Option | Description | Selected |
|--------|-------------|----------|
| Combined pnet module | Named DI module like usePrivateNetwork(key) binding Psk + pnet-enabled marker in one call; force-pnet semantics ride along | ✓ |
| Separate bindings | di::bind<Psk> independently — decoupled but risks half-configured states | |
| You decide | Locked semantic: PSK configured == private-network mode on; exact call shape open | |

**User's choice:** Combined pnet module

**Q3: What's the DI default when no PSK is configured?**

| Option | Description | Selected |
|--------|-------------|----------|
| No default (optional) | No binding → no Psk in graph → no pnet wrapper (public mode, today's behavior); mirrors Phase 1 null-object default philosophy | ✓ |
| Nullable always-bound | Always bind possibly-empty Psk; wrapper checks per-connection — adds per-connection branch and two-state type | |

**User's choice:** No default (optional)

---

## Force-pnet trigger (PNET-05)

**Q1: What signals private-network mode for the fail-safe?**

| Option | Description | Selected |
|--------|-------------|----------|
| DI module = mode signal | usePrivateNetwork(key) IS the signal; Psk must parse to exactly 32 bytes or construction fails; half-configured impossible; no env var (DI-only per project constraint) | ✓ |
| DI + env var override | Plus LIBP2P_FORCE_PNET=1 env var making even PSK-less host fail — matches go-libp2p exactly, belt-and-suspenders for ops | |
| Parse-check only | Construction-time check for malformed keys wherever a Psk is parsed; no first-class mode concept — weakest fit for PNET-05 | |

**User's choice:** DI module = mode signal

**Q2: Where exactly does the failure surface?**

| Option | Description | Selected |
|--------|-------------|----------|
| Fail at injector build | makeHostInjector/DI-graph construction throws/errors before any socket opens; no Host object ever exists broken | ✓ |
| Fail at listen/dial | Host constructs but listen/dial fail with ErrForcePrivateNetwork-style error — go-libp2p's runtime shape but leaves zombie Host | |
| You decide | Locked constraint only: explicit, pnet-attributed, precedes any plaintext operation | |

**User's choice:** Fail at injector build

---

## Bootstrap scoping (BOOT-01)

**Q1: How is 'no public DHT dialing' enforced when a PSK is configured?**

| Option | Description | Selected |
|--------|-------------|----------|
| Fail-loud on conflict | PSK active + default public bootstrap peers in kademlia config = explicit construction-time error — consistent with PNET-05 fail-loud pattern (recommended) | |
| Silent filter | PSK active → default public bootstrap addresses silently dropped, never dialed; no error surfaced | ✓ |
| Convention only | Private deployments override bootstrap list themselves; library does nothing special | |

**User's choice:** Silent filter
**Notes:** User explicitly rejected the recommended fail-loud option — deliberate choice; deliberate misconfiguration treated as harmless-and-ignored rather than fatal. Asymmetric with PNET-05 on purpose.

**Q2: Where does the silent filter live?**

| Option | Description | Selected |
|--------|-------------|----------|
| Injector-level strip | Filter at kademlia injector setup: PSK present → public bootstrap peers removed from config before Kademlia sees them | |
| Dial-time refusal | Filter in DialerImpl: PSK present → dials to known public-bootstrap peer IDs/multiaddrs refused; covers any config path | ✓ |
| You decide | Locked constraint only: default public bootstrap peers never dialed when PSK active | |

**User's choice:** Dial-time refusal

**Q3: Should the dial-time refusal be observable in logs?**

| Option | Description | Selected |
|--------|-------------|----------|
| SL_DEBUG log | Same level as Phase 1 gater rejections; includes peer ID/address; silent-to-caller but debuggable | ✓ |
| No logging | Truly silent — zero trace of why a misconfigured node never connects | |
| SL_WARN log | Louder, signals misconfiguration — but filtering is expected behavior in private mode | |

**User's choice:** SL_DEBUG log

---

## Claude's Discretion

None — every question in all four areas received an explicit selection or a definitive free-text answer.

## Deferred Ideas

None — discussion stayed within phase scope.
