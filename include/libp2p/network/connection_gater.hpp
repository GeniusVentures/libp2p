/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LIBP2P_NETWORK_CONNECTION_GATER_HPP
#define LIBP2P_NETWORK_CONNECTION_GATER_HPP

#include <memory>

#include <libp2p/connection/capable_connection.hpp>
#include <libp2p/multi/multiaddress.hpp>
#include <libp2p/outcome/outcome.hpp>
#include <libp2p/peer/peer_id.hpp>

namespace libp2p::network {

  /**
   * @brief Pluggable accept/reject policy hooks invoked at each stage of the
   * connection upgrade pipeline (RawConnection -> SecureConnection ->
   * CapableConnection). Implementations decide whether a peer/address/
   * connection is allowed to proceed by returning outcome::success() or a
   * ConnectionGaterError.
   */
  struct ConnectionGater {
    virtual ~ConnectionGater() = default;

    /**
     * @brief Called before dialing a peer by PeerId, prior to address
     * resolution.
     * @param p peer to be dialed
     */
    virtual outcome::result<void> interceptPeerDial(const peer::PeerId &p) = 0;

    /**
     * @brief Called before dialing a specific address of a peer.
     * @param p peer to be dialed
     * @param addr address to be dialed
     */
    virtual outcome::result<void> interceptAddrDial(
        const peer::PeerId &p, const multi::Multiaddress &addr) = 0;

    /**
     * @brief Called when an inbound raw connection is accepted by a
     * listener, before any upgrade takes place.
     * @param local local listening multiaddress
     * @param remote remote multiaddress of the connecting peer
     */
    virtual outcome::result<void> interceptAccept(
        const multi::Multiaddress &local,
        const multi::Multiaddress &remote) = 0;

    /**
     * @brief Called after a connection has been secured (encrypted and
     * authenticated), before muxer negotiation.
     * @param is_initiator true if this side initiated the connection
     * @param remote_peer identity of the remote peer, as established during
     * the security handshake
     * @param remote_addr remote multiaddress of the connection
     */
    virtual outcome::result<void> interceptSecured(
        bool is_initiator, const peer::PeerId &remote_peer,
        const multi::Multiaddress &remote_addr) = 0;

    /**
     * @brief Called after a connection has been fully upgraded (secured and
     * muxed) into a CapableConnection.
     * @param conn the fully upgraded connection
     */
    virtual outcome::result<void> interceptUpgraded(
        const std::shared_ptr<connection::CapableConnection> &conn) = 0;
  };

}  // namespace libp2p::network

#endif  // LIBP2P_NETWORK_CONNECTION_GATER_HPP
