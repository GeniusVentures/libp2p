/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <libp2p/network/connection_gater_error.hpp>

OUTCOME_CPP_DEFINE_CATEGORY(libp2p::network, ConnectionGaterError, e) {
  using libp2p::network::ConnectionGaterError;

  switch (e) {
    case ConnectionGaterError::GATER_REJECTED_PEER_DIAL:
      return "ConnectionGater: rejected at interceptPeerDial";
    case ConnectionGaterError::GATER_REJECTED_ADDR_DIAL:
      return "ConnectionGater: rejected at interceptAddrDial";
    case ConnectionGaterError::GATER_REJECTED_ACCEPT:
      return "ConnectionGater: rejected at interceptAccept";
    case ConnectionGaterError::GATER_REJECTED_SECURED:
      return "ConnectionGater: rejected at interceptSecured";
    case ConnectionGaterError::GATER_REJECTED_UPGRADED:
      return "ConnectionGater: rejected at interceptUpgraded";
  }

  return "ConnectionGater: unknown rejection";
}
