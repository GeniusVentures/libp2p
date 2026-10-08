/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LIBP2P_NETWORK_CONNECTION_GATER_ERROR_HPP
#define LIBP2P_NETWORK_CONNECTION_GATER_ERROR_HPP

#include <libp2p/outcome/outcome.hpp>

namespace libp2p::network {

  enum class ConnectionGaterError {
    GATER_REJECTED_PEER_DIAL = 1,  ///< interceptPeerDial rejected the peer
    GATER_REJECTED_ADDR_DIAL,      ///< interceptAddrDial rejected the address
    GATER_REJECTED_ACCEPT,         ///< interceptAccept rejected the connection
    GATER_REJECTED_SECURED,        ///< interceptSecured rejected the connection
    GATER_REJECTED_UPGRADED,       ///< interceptUpgraded rejected the connection
  };

}  // namespace libp2p::network

OUTCOME_HPP_DECLARE_ERROR(libp2p::network, ConnectionGaterError)

#endif  // LIBP2P_NETWORK_CONNECTION_GATER_ERROR_HPP
