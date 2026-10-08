# Example: Private Network + Connection Gater -- Complementary Layers (DOCS-03)

## General description

This is the worked example for the project's core value: **a node without
the correct network credentials must be unable to join or communicate on a
private network -- access control is enforced at the network layer, not
left to the application layer.** It composes BOTH access-control primitives
this fork adds on top of upstream cpp-libp2p in a single `Host`:

- `usePrivateNetwork(...)` (see `../05-private-network/README.md`) -- a
  **network-membership** boundary. Every raw connection is XSalsa20-wrapped
  with the swarm PSK before multiselect runs.
- `useConnectionGater<T>()` (see `../07-connection-gater/README.md`) -- a
  **peer-level authorization** boundary. A pluggable policy hook that can
  reject specific peers/addresses/connections at each stage of the upgrade
  pipeline.

## Why neither layer alone is sufficient

**PSK alone is not enough:** a peer that holds the correct swarm key proves
it belongs to the network, but says nothing about whether *that specific
peer* should be allowed to connect. This example's `DenylistGater` denies
one hardcoded peer id at `interceptPeerDial` regardless of whether that peer
would otherwise present a valid PSK -- proving a valid-PSK peer can still be
correctly denied.

**The gater alone is not enough:** `PnetProtectedConnection` sits *below*
multiselect, wrapping the raw connection before any protocol negotiation
happens. A peer without the matching PSK can never even reach the point
where the gater's `interceptSecured`/`interceptUpgraded` hooks would fire
(those run after the security handshake, which itself cannot complete
without the correct PSK) -- a gater-allowed peer without the PSK is stuck
before the gater is ever meaningfully consulted for that connection.

These are independent, non-redundant checks: PSK proves network membership,
the gater proves peer-level authorization.

## Build & run

1. Build the C++ target `libp2p_private_network_gater_example` (requires
   the `EXAMPLES` CMake option to be `ON`):
   ```
   cmake -S . -B build -DEXAMPLES=ON
   cmake --build build --config Debug --target libp2p_private_network_gater_example
   ```
2. Run it. If you built with CMake and are in this directory, it can be
   launched as
   `../../build/example/06-private-network-gater/Debug/libp2p_private_network_gater_example`.
3. Watch the console: after the server starts, it dials its own hardcoded
   denylisted peer id (which, for the sake of this demonstration, is assumed
   to also hold the correct swarm PSK) and prints the complementary-layers
   message.

## Expected output

```
Private-network + gater server started
Listening on: /ip4/127.0.0.1/tcp/40532
Peer id: <this host's peer id>
peer holds the correct PSK for this private network but is still denied by
the gater -- PSK proves network membership, the gater proves peer-level
authorization; they are independent, non-redundant checks.
```

See `../05-private-network/README.md` and `../07-connection-gater/README.md`
for the two single-layer examples this one composes.
