/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LIBP2P_TRANSPORT_ADAPTOR_HPP
#define LIBP2P_TRANSPORT_ADAPTOR_HPP

#include <chrono>
#include <functional>
#include <memory>
#include <system_error>

#include <libp2p/basic/adaptor.hpp>
#include <libp2p/connection/capable_connection.hpp>
#include <libp2p/event/emitter.hpp>
#include <libp2p/multi/multiaddress.hpp>
#include <libp2p/outcome/outcome.hpp>  // for outcome::result
#include <libp2p/peer/peer_id.hpp>
#include <libp2p/transport/transport_listener.hpp>
#include <libp2p/network/route_helper.hpp>

namespace libp2p::transport {

  /**
   * Allows to establish connections with other peers and react to received
   * attempts to do so; can be implemented, for example, as TCP, UDP etc
   */
  class TransportAdaptor : public basic::Adaptor {
   public:
    using ConnectionCallback =
        void(outcome::result<std::shared_ptr<connection::CapableConnection>>);
    using HandlerFunc = std::function<ConnectionCallback>;

    ~TransportAdaptor() override = default;

    /**
     * Try to establish connection with a peer without timeout
     * @param remoteId id of remote peer to dial
     * @param address of the peer
     * @param handler callback that will be executed on connection/error
     * @return connection in case of success, error otherwise
     */
    virtual void dial(const peer::PeerId &remoteId, multi::Multiaddress address,
                      HandlerFunc handler,
                      multi::Multiaddress bindaddress, bool holepunch = false, bool holepunchserver = false) {
      dial(remoteId, std::move(address), std::move(handler),
           std::chrono::milliseconds(0),bindaddress, holepunch, holepunchserver);
    }

    /**
     * Try to establish connection with a peer with specific timeout
     * @param remoteId id of remote peer to dial
     * @param address of the peer
     * @param handler callback that will be executed on connection/error
     * @param timeout in milliseconds for connection establishing
     * @return connection in case of success, error otherwise
     */
    virtual void dial(const peer::PeerId &remoteId, multi::Multiaddress address,
                      HandlerFunc handler,
                      std::chrono::milliseconds timeout, multi::Multiaddress bindaddress, bool holepunch = false, bool holepunchserver = false) = 0;

    /**
     * Create a listener for incoming connections of this Transport; in case
     * it was already created, return it
     * @param handler callback that will be executed on new connection
     * @return pointer to the created listener
     */
    virtual std::shared_ptr<TransportListener> createListener(
        TransportListener::HandlerFunc handler) = 0;

    /**
     * Check if this transport supports a given multiaddress
     * @param ma to be checked against
     * @return true, if transport supports that multiaddress, false otherwise
     * @note example: '/tcp/...' on tcp transport will return true
     */
    virtual bool canDial(const multi::Multiaddress &ma) const = 0;

    /**
     * Upgrade a relay connection's security
     * @param peer_id to upgrade with
     * @param connection to upgrade over
     * @param handler
     */
    virtual void upgradeRelaySecure(const peer::PeerId& remoteId, std::shared_ptr<libp2p::connection::Stream> conn, HandlerFunc handler) = 0;

    /**
     * Try to establish connection with dual source addresses (default implementation chooses one)
     * @param remoteId id of remote peer to dial
     * @param address of the peer
     * @param handler callback that will be executed on connection/error
     * @param source_addresses both IPv4 and IPv6 source addresses available
     * @return connection in case of success, error otherwise
     */
    virtual void dial(const peer::PeerId &remoteId, multi::Multiaddress address,
                      HandlerFunc handler,
                      const libp2p::network::RouteHelper::SourceAddresses &source_addresses, bool holepunch = false, bool holepunchserver = false) {
      // Default implementation: choose IPv4 if available, otherwise IPv6, otherwise fallback
      multi::Multiaddress chosen_source = multi::Multiaddress::create("/ip4/0.0.0.0").value();
      if (source_addresses.has_ipv4) {
        chosen_source = source_addresses.ipv4_source;
      } else if (source_addresses.has_ipv6) {
        chosen_source = source_addresses.ipv6_source;
      }
      dial(remoteId, std::move(address), std::move(handler), std::chrono::milliseconds(0), chosen_source, holepunch, holepunchserver);
    }

    /**
     * Try to establish connection with dual source addresses and timeout (default implementation chooses one)
     * @param remoteId id of remote peer to dial
     * @param address of the peer
     * @param handler callback that will be executed on connection/error
     * @param timeout in milliseconds for connection establishing
     * @param source_addresses both IPv4 and IPv6 source addresses available
     * @return connection in case of success, error otherwise
     */
    virtual void dial(const peer::PeerId &remoteId, multi::Multiaddress address,
                      HandlerFunc handler,
                      std::chrono::milliseconds timeout, const libp2p::network::RouteHelper::SourceAddresses &source_addresses, bool holepunch = false, bool holepunchserver = false) {
      // Default implementation: choose IPv4 if available, otherwise IPv6, otherwise fallback
      multi::Multiaddress chosen_source = multi::Multiaddress::create("/ip4/0.0.0.0").value();
      if (source_addresses.has_ipv4) {
        chosen_source = source_addresses.ipv4_source;
      } else if (source_addresses.has_ipv6) {
        chosen_source = source_addresses.ipv6_source;
      }
      dial(remoteId, std::move(address), std::move(handler), timeout, chosen_source, holepunch, holepunchserver);
    }
  };
}  // namespace libp2p::transport

#endif  // LIBP2P_TRANSPORT_ADAPTOR_HPP
