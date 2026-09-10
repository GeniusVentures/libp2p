# Example: Private Network (PSK) Configuration

## General description

This example shows how to configure a cpp-libp2p `Host` to join a **private
network** -- a swarm that is only reachable by peers holding the same
pre-shared key (PSK), following the
[libp2p pnet spec](https://github.com/libp2p/specs/blob/master/pnet/Private-Networks-PSK-V1.md).

A private network wraps every raw connection (both dial and accept paths) in
an XSalsa20 stream cipher keyed by the PSK, via `PnetUpgraderDecorator`. This
happens **before** multiselect protocol negotiation ever runs -- a peer
without the matching key cannot decrypt the stream, so it never reaches
multistream-select, application protocols, or any handler code. It is a
network-membership boundary, not an authorization boundary (see
`../06-private-network-gater/README.md` for the complementary peer-level
authorization boundary).

## What a swarm key looks like

The PSK is supplied as text in one of the framings `usePrivateNetwork(...)`
accepts (dispatch order: swarm-key framing, then raw base16, then raw
base64). The canonical `swarm.key` file framing is:

```
/key/swarm/psk/1.0.0/
/base16/000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```

That is a 256-bit (32-byte) key, hex-encoded on the second line.

**The key hardcoded in `private_network_example.cpp` is a publicly-known
test vector** -- byte-identical to the one used in
`test/libp2p/security/pnet/pnet_injector_test.cpp`. It is **never** a real
secret. Before using this example against a real private deployment,
generate your own key (32 random bytes, hex- or base64-encode it, wrap it in
the swarm-key framing above) and substitute it for the hardcoded literal.

`usePrivateNetwork(key_text)` validates the key **eagerly** -- an invalid key
throws `PskValidationError` from the call itself, before any injector or
`Host` is assembled, so a half-configured node can never come into being.

## Build & run

1. Build the C++ target `libp2p_private_network_example` (requires the
   `EXAMPLES` CMake option to be `ON`):
   ```
   cmake -S . -B build -DEXAMPLES=ON
   cmake --build build --config Debug --target libp2p_private_network_example
   ```
2. Start the server. If you built with CMake and are in this directory, it
   can be launched as
   `../../build/example/05-private-network/Debug/libp2p_private_network_example`.
3. Watch the console: the server prints its listening address and peer ID,
   and notes that only a peer configured with the same PSK can connect.

A peer dialing this server **without** the same PSK (e.g. a plain
`example/01-echo` client, or a peer configured with a different key) cannot
open a stream to it -- the connection attempt fails at the pnet layer and
never reaches Echo or any other protocol handler.

See `../06-private-network-gater/README.md` for a worked example combining
this PSK layer with a custom `ConnectionGater`.
