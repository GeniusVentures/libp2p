/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LIBP2P_CONNECTION_GATER_MOCK_HPP
#define LIBP2P_CONNECTION_GATER_MOCK_HPP

#include <libp2p/network/connection_gater.hpp>

#include <gmock/gmock.h>

namespace libp2p::network {

  struct ConnectionGaterMock : public ConnectionGater {
    ~ConnectionGaterMock() override = default;

    MOCK_METHOD1(interceptPeerDial,
                 outcome::result<void>(const peer::PeerId &));
    MOCK_METHOD2(interceptAddrDial,
                 outcome::result<void>(const peer::PeerId &,
                                        const multi::Multiaddress &));
    MOCK_METHOD2(interceptAccept,
                 outcome::result<void>(const multi::Multiaddress &,
                                        const multi::Multiaddress &));
    MOCK_METHOD3(interceptSecured,
                 outcome::result<void>(bool, const peer::PeerId &,
                                        const multi::Multiaddress &));
    MOCK_METHOD1(interceptUpgraded,
                 outcome::result<void>(
                     const std::shared_ptr<connection::CapableConnection> &));
  };

}  // namespace libp2p::network

#endif  // LIBP2P_CONNECTION_GATER_MOCK_HPP
