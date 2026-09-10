/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LIBP2P_NETWORK_IMPL_PERMISSIVE_CONNECTION_GATER_HPP
#define LIBP2P_NETWORK_IMPL_PERMISSIVE_CONNECTION_GATER_HPP

#include <libp2p/network/connection_gater.hpp>

namespace libp2p::network {

  /**
   * @brief Null Object default ConnectionGater: unconditionally allows every
   * connection at every stage of the upgrade pipeline. Bound by default so
   * hosts built without an explicit gater override retain today's
   * unrestricted behavior (GATE-02).
   */
  class PermissiveConnectionGater : public ConnectionGater {
   public:
    outcome::result<void> interceptPeerDial(const peer::PeerId &p) override {
      return outcome::success();
    }

    outcome::result<void> interceptAddrDial(
        const peer::PeerId &p, const multi::Multiaddress &addr) override {
      return outcome::success();
    }

    outcome::result<void> interceptAccept(
        const multi::Multiaddress &local,
        const multi::Multiaddress &remote) override {
      return outcome::success();
    }

    outcome::result<void> interceptSecured(
        bool is_initiator, const peer::PeerId &remote_peer,
        const multi::Multiaddress &remote_addr) override {
      return outcome::success();
    }

    outcome::result<void> interceptUpgraded(
        const std::shared_ptr<connection::CapableConnection> &conn)
        override {
      return outcome::success();
    }
  };

}  // namespace libp2p::network

#endif  // LIBP2P_NETWORK_IMPL_PERMISSIVE_CONNECTION_GATER_HPP
