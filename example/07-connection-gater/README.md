# Example: Custom Connection Gater Registration

## General description

This example shows how to plug a custom `ConnectionGater` implementation
into a cpp-libp2p `Host`, replacing the default `PermissiveConnectionGater`
(which unconditionally allows every connection). A `ConnectionGater`
provides peer-level authorization -- a policy hook that runs at each stage
of the connection upgrade pipeline, independent of the transport-level
private network (PSK) boundary demonstrated in
`../05-private-network/README.md`.

## The `ConnectionGater` interface

`include/libp2p/network/connection_gater.hpp` declares 5 hooks, each called
at a different point in the pipeline and each returning
`outcome::result<void>` (success or a rejection):

| Hook | Called |
|------|--------|
| `interceptPeerDial` | Before dialing a peer by `PeerId`, prior to address resolution |
| `interceptAddrDial` | Before dialing a specific address of a peer |
| `interceptAccept` | When an inbound raw connection is accepted, before any upgrade |
| `interceptSecured` | After a connection is secured (encrypted+authenticated), before muxing |
| `interceptUpgraded` | After a connection is fully upgraded (secured and muxed) |

This example's `DenylistGater` rejects one hardcoded peer id at the earliest
hook (`interceptPeerDial`) and returns `outcome::success()` unconditionally
from the other 4 -- i.e. fully permissive except for that one peer,
matching `PermissiveConnectionGater`'s default behavior everywhere else.

## Registering the gater

`useConnectionGater<GaterImpl>()` replaces the default gater via a single DI
binding, with zero source changes required in `Dialer`, `TcpListener`, or
`UpgraderSession`:

```cpp
struct DenylistGater : public libp2p::network::ConnectionGater { /* ... */ };

auto injector = libp2p::injector::makeHostInjector(
    libp2p::injector::useConnectionGater<DenylistGater>());
auto host = injector.create<std::shared_ptr<libp2p::Host>>();
```

## Build & run

1. Build the C++ target `libp2p_connection_gater_example` (requires the
   `EXAMPLES` CMake option to be `ON`):
   ```
   cmake -S . -B build -DEXAMPLES=ON
   cmake --build build --config Debug --target libp2p_connection_gater_example
   ```
2. Run it. If you built with CMake and are in this directory, it can be
   launched as
   `../../build/example/07-connection-gater/Debug/libp2p_connection_gater_example`.
3. Watch the console: after the server starts and listens, it dials its own
   hardcoded denylisted peer id and prints the observed result.

## Expected output

```
Connection-gater server started
Listening on: /ip4/127.0.0.1/tcp/40531
Peer id: <this host's peer id>
denylisted peer correctly rejected by the custom gater
```

If the gater were not wired (or were bypassed), the output would instead
read `UNEXPECTED: stream opened`.

See `../06-private-network-gater/README.md` for a worked example combining
this gater layer with the PSK / private-network layer.
