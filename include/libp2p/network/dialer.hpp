/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LIBP2P_NETWORK_DIALER_HPP
#define LIBP2P_NETWORK_DIALER_HPP

#include <chrono>

#include <libp2p/connection/capable_connection.hpp>
#include <libp2p/peer/peer_info.hpp>
#include <libp2p/peer/protocol.hpp>
#include <libp2p/network/route_helper.hpp>

namespace libp2p::network {

  /**
   * @brief Class, which is capable of opening new connections and streams using
   * registered transports.
   */
  struct Dialer {
    virtual ~Dialer() = default;

    using DialResult =
        outcome::result<std::shared_ptr<connection::CapableConnection>>;
    using DialResultFunc = std::function<void(DialResult)>;

    using StreamResult = outcome::result<std::shared_ptr<connection::Stream>>;
    using StreamResultFunc = std::function<void(StreamResult)>;

    /**
     * Establishes a connection or returns existing one to a given peer with a
     * specific timeout
     */
    virtual void dial(const peer::PeerInfo &p, DialResultFunc cb,
                      std::chrono::milliseconds timeout, const libp2p::network::RouteHelper::SourceAddresses &source_addresses, bool holepunch = false, bool holepunchserver = false) = 0;

    /**
     * Establishes a connection or returns existing one to a given peer
     */
    inline void dial(const peer::PeerInfo &p, DialResultFunc cb, const libp2p::network::RouteHelper::SourceAddresses &source_addresses, bool holepunch = false, bool holepunchserver = false) {
      dial(p, std::move(cb), std::chrono::milliseconds::zero(), source_addresses, holepunch, holepunchserver);
    }

    /**
     * Establishes a connection or returns existing one to a given peer (convenience method with default source address)
     */
    inline void dial(const peer::PeerInfo &p, DialResultFunc cb) {
      auto default_ipv4 = multi::Multiaddress::create("/ip4/0.0.0.0").value();
      auto default_ipv6 = multi::Multiaddress::create("/ip6/::").value();
      libp2p::network::RouteHelper::SourceAddresses default_sources{
        default_ipv4,  // ipv4_source
        default_ipv6,  // ipv6_source
        true,          // has_ipv4
        false          // has_ipv6
      };
      dial(p, std::move(cb), std::chrono::milliseconds::zero(), default_sources, false, false);
    }

    /**
     * NewStream returns a new stream to given peer p with a specific timeout.
     * If there is no connection to p, attempts to create one.
     */
    virtual void newStream(const peer::PeerInfo &peer_info,
                           const peer::Protocol &protocol, StreamResultFunc cb,
                           std::chrono::milliseconds timeout, const libp2p::network::RouteHelper::SourceAddresses &source_addresses) = 0;

    /**
     * NewStream returns a new stream to given peer p.
     * If there is no connection to p, attempts to create one.
     */
    inline void newStream(const peer::PeerInfo &peer_info,
                          const peer::Protocol &protocol, StreamResultFunc cb, const libp2p::network::RouteHelper::SourceAddresses &source_addresses) {
      newStream(peer_info, protocol, std::move(cb),
                std::chrono::milliseconds::zero(), source_addresses);
    }

    /**
     * NewStream returns a new stream to given peer p.
     * If there is no connection to p, returns error.
     */
    virtual void newStream(const peer::PeerId &peer_id,
                           const peer::Protocol &protocol,
                           StreamResultFunc cb, const libp2p::network::RouteHelper::SourceAddresses &source_addresses) = 0;

    /**
     * NewStream convenience methods with default source addresses
     */
    inline void newStream(const peer::PeerInfo &peer_info,
                          const peer::Protocol &protocol, StreamResultFunc cb) {
      auto default_ipv4 = multi::Multiaddress::create("/ip4/0.0.0.0").value();
      auto default_ipv6 = multi::Multiaddress::create("/ip6/::").value();
      libp2p::network::RouteHelper::SourceAddresses default_sources{
        default_ipv4,  // ipv4_source
        default_ipv6,  // ipv6_source
        true,          // has_ipv4
        false          // has_ipv6
      };
      newStream(peer_info, protocol, std::move(cb), std::chrono::milliseconds::zero(), default_sources);
    }

    inline void newStream(const peer::PeerInfo &peer_info,
                          const peer::Protocol &protocol, StreamResultFunc cb,
                          std::chrono::milliseconds timeout) {
      auto default_ipv4 = multi::Multiaddress::create("/ip4/0.0.0.0").value();
      auto default_ipv6 = multi::Multiaddress::create("/ip6/::").value();
      libp2p::network::RouteHelper::SourceAddresses default_sources{
        default_ipv4,  // ipv4_source
        default_ipv6,  // ipv6_source
        true,          // has_ipv4
        false          // has_ipv6
      };
      newStream(peer_info, protocol, std::move(cb), timeout, default_sources);
    }

    inline void newStream(const peer::PeerId &peer_id,
                          const peer::Protocol &protocol, StreamResultFunc cb) {
      auto default_ipv4 = multi::Multiaddress::create("/ip4/0.0.0.0").value();
      auto default_ipv6 = multi::Multiaddress::create("/ip6/::").value();
      libp2p::network::RouteHelper::SourceAddresses default_sources{
        default_ipv4,  // ipv4_source
        default_ipv6,  // ipv6_source
        true,          // has_ipv4
        false          // has_ipv6
      };
      newStream(peer_id, protocol, std::move(cb), default_sources);
    }
  };

}  // namespace libp2p::network

#endif  // LIBP2P_NETWORK_DIALER_HPP
