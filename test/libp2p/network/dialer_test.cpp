/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "libp2p/network/impl/dialer_impl.hpp"

#include <gtest/gtest.h>
#include <libp2p/basic/scheduler/manual_scheduler_backend.hpp>
#include <libp2p/basic/scheduler/scheduler_impl.hpp>
#include <libp2p/common/literals.hpp>
#include <libp2p/network/connection_gater_error.hpp>
#include <libp2p/security/pnet/pnet_error.hpp>
#include <libp2p/security/pnet/psk.hpp>
#include "mock/libp2p/connection/capable_connection_mock.hpp"
#include "mock/libp2p/connection/stream_mock.hpp"
#include "mock/libp2p/network/connection_gater_mock.hpp"
#include "mock/libp2p/network/connection_manager_mock.hpp"
#include "mock/libp2p/network/listener_mock.hpp"
#include "mock/libp2p/network/router_mock.hpp"
#include "mock/libp2p/network/transport_manager_mock.hpp"
#include "mock/libp2p/peer/address_repository_mock.hpp"
#include "mock/libp2p/protocol_muxer/protocol_muxer_mock.hpp"
#include "mock/libp2p/transport/transport_mock.hpp"
#include "testutil/gmock_actions.hpp"
#include "testutil/outcome.hpp"
#include "testutil/prepare_loggers.hpp"

using namespace libp2p;
using namespace network;
using namespace connection;
using namespace transport;
using namespace protocol_muxer;
using namespace common;
using namespace basic;

using ::testing::_;
using ::testing::ContainerEq;
using ::testing::Contains;
using ::testing::Eq;
using ::testing::InvokeArgument;
using ::testing::Return;

struct DialerTest : public ::testing::Test {
  void SetUp() override {
    testutil::prepareLoggers();
    ON_CALL(*gater, interceptPeerDial(_))
        .WillByDefault(Return(outcome::success()));
    ON_CALL(*gater, interceptAddrDial(_, _))
        .WillByDefault(Return(outcome::success()));
    dialer = std::make_shared<DialerImpl>(proto_muxer, tmgr, cmgr, listener,
                                          scheduler, gater);
  }

  std::shared_ptr<StreamMock> stream = std::make_shared<StreamMock>();

  std::shared_ptr<CapableConnectionMock> connection =
      std::make_shared<CapableConnectionMock>();

  std::shared_ptr<TransportMock> transport = std::make_shared<TransportMock>();

  std::shared_ptr<ProtocolMuxerMock> proto_muxer =
      std::make_shared<ProtocolMuxerMock>();

  std::shared_ptr<TransportManagerMock> tmgr =
      std::make_shared<TransportManagerMock>();

  std::shared_ptr<ConnectionManagerMock> cmgr =
      std::make_shared<ConnectionManagerMock>();

  std::shared_ptr<ListenerMock> listener = std::make_shared<ListenerMock>();

  std::shared_ptr<ConnectionGaterMock> gater =
      std::make_shared<ConnectionGaterMock>();

  std::shared_ptr<ManualSchedulerBackend> scheduler_backend =
      std::make_shared<ManualSchedulerBackend>();

  std::shared_ptr<Scheduler> scheduler =
      std::make_shared<SchedulerImpl>(scheduler_backend, Scheduler::Config{});

  std::shared_ptr<Dialer> dialer;

  multi::Multiaddress ma1 = "/ip4/127.0.0.1/tcp/1"_multiaddr;
  multi::Multiaddress ma2 = "/ip4/127.0.0.1/tcp/2"_multiaddr;
  peer::PeerId pid = "1"_peerid;
  const StreamProtocols protocols = {"/protocol/1.0.0"};

  peer::PeerInfo pinfo{pid, {ma1}};
  peer::PeerInfo pinfo_two_addrs{pid, {ma1, ma2}};

  // static fixture PSK for the private-network refusal cases (01..1f)
  static std::shared_ptr<const security::pnet::Psk> testPsk() {
    static const std::vector<uint8_t> bytes = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    auto res = security::pnet::Psk::fromRawBytes(bytes);
    assert(res);
    return std::shared_ptr<const security::pnet::Psk>(
        new security::pnet::Psk(std::move(res.value())));
  }

  /// builds a dialer WITH a psk configured (private-network mode);
  /// typed as the Dialer base so convenience dial() overloads resolve
  std::shared_ptr<Dialer> makePskDialer() {
    return std::make_shared<DialerImpl>(proto_muxer, tmgr, cmgr, listener,
                                        scheduler, gater, testPsk());
  }

  void drainScheduler() {
    while (!scheduler_backend->empty()) {
      scheduler_backend->shift(std::chrono::milliseconds(1));
    }
  }
};

/**
 * @given a peer with two multiaddresses
 * @when a dial to the first address fails
 * @then the dialer will try the second supplied address too
 */
TEST_F(DialerTest, DialAllTheAddresses) {
  // we dont have connection already
  EXPECT_CALL(*cmgr, getBestConnectionForPeer(pinfo.id))
      .WillOnce(Return(nullptr));

  // connection is stored
  EXPECT_CALL(*listener, onConnection(_)).Times(1);

  // we have transport to dial
  EXPECT_CALL(*tmgr, findBest(ma1)).WillOnce(Return(transport));
  EXPECT_CALL(*tmgr, findBest(ma2)).WillOnce(Return(transport));

  // transport->dial returns an error for the first address
  EXPECT_CALL(*transport,
              dial(pinfo_two_addrs.id, ma1, _,
                   std::chrono::milliseconds::zero(), _, false, false))
      .WillOnce(
          Arg2CallbackWithArg(outcome::failure(std::errc::connection_refused)));

  // transport->dial returns valid connection for the second address
  EXPECT_CALL(*transport,
              dial(pinfo_two_addrs.id, ma2, _,
                   std::chrono::milliseconds::zero(), _, false, false))
      .WillOnce(Arg2CallbackWithArg(outcome::success(connection)));

  bool executed = false;
  dialer->dial(pinfo_two_addrs, [&](auto &&rconn) {
    EXPECT_OUTCOME_TRUE(conn, rconn);
    (void)conn;
    executed = true;
  });

  while (!scheduler_backend->empty()) {
    scheduler_backend->shift(std::chrono::milliseconds(1));
  }

  ASSERT_TRUE(executed);
}

/**
 * @given no known connections to peer, have 1 transport, 1 address supplied
 * @when dial
 * @then create new connection using transport
 */
TEST_F(DialerTest, DialNewConnection) {
  // we dont have connection already
  EXPECT_CALL(*cmgr, getBestConnectionForPeer(pinfo.id))
      .WillOnce(Return(nullptr));

  // connection is stored
  EXPECT_CALL(*listener, onConnection(_)).Times(1);

  // we have transport to dial
  EXPECT_CALL(*tmgr, findBest(ma1)).WillOnce(Return(transport));

  // transport->dial returns valid connection
  EXPECT_CALL(*transport,
              dial(pinfo.id, ma1, _, std::chrono::milliseconds::zero(), _,
                   false, false))
      .WillOnce(Arg2CallbackWithArg(outcome::success(connection)));

  bool executed = false;
  dialer->dial(pinfo, [&](auto &&rconn) {
    EXPECT_OUTCOME_TRUE(conn, rconn);
    (void)conn;
    executed = true;
  });

  while (!scheduler_backend->empty()) {
    scheduler_backend->shift(std::chrono::milliseconds(1));
  }

  ASSERT_TRUE(executed);
}

/**
 * @given no known connections to peer, no addresses supplied
 * @when dial
 * @then create new connection using transport
 */
TEST_F(DialerTest, DialNoAddresses) {
  // we dont have connection already
  EXPECT_CALL(*cmgr, getBestConnectionForPeer(pinfo.id))
      .WillOnce(Return(nullptr));

  // no addresses supplied
  peer::PeerInfo pinfo = {pid, {}};
  bool executed = false;
  dialer->dial(pinfo, [&](auto &&rconn) {
    EXPECT_OUTCOME_FALSE(e, rconn);
    EXPECT_EQ(e.value(), (int)std::errc::destination_address_required);
    executed = true;
  });

  while (!scheduler_backend->empty()) {
    scheduler_backend->shift(std::chrono::milliseconds(1));
  }

  ASSERT_TRUE(executed);
}

/**
 * @given no known connections to peer, have 1 tcp transport, 1 UDP address
 * supplied
 * @when dial
 * @then can not dial, no transports found
 */
TEST_F(DialerTest, DialNoTransports) {
  // we dont have connection already
  EXPECT_CALL(*cmgr, getBestConnectionForPeer(pinfo.id))
      .WillOnce(Return(nullptr));

  // we did not find transport to dial
  EXPECT_CALL(*tmgr, findBest(ma1)).WillOnce(Return(nullptr));

  bool executed = false;
  dialer->dial(pinfo, [&](auto &&rconn) {
    EXPECT_OUTCOME_FALSE(e, rconn);
    EXPECT_EQ(e.value(), (int)std::errc::address_family_not_supported);
    executed = true;
  });

  while (!scheduler_backend->empty()) {
    scheduler_backend->shift(std::chrono::milliseconds(1));
  }

  ASSERT_TRUE(executed);
}

/**
 * @given existing connection to peer
 * @when dial
 * @then get existing connection
 */
TEST_F(DialerTest, DialExistingConnection) {
  // we have connection
  EXPECT_CALL(*cmgr, getBestConnectionForPeer(pinfo.id))
      .WillOnce(Return(connection));

  bool executed = false;
  dialer->dial(pinfo, [&](auto &&rconn) {
    EXPECT_OUTCOME_TRUE(conn, rconn);
    (void)conn;
    executed = true;
  });

  while (!scheduler_backend->empty()) {
    scheduler_backend->shift(std::chrono::milliseconds(1));
  }

  ASSERT_TRUE(executed);
}

///
/// All tests that use newStream assume connections already exist, because
/// newStream uses dial to get connection, and dial is already tested for all
/// cases.
///

/**
 * @given no connections to peer
 * @when newStream is executed
 * @then get failure
 */
TEST_F(DialerTest, NewStreamFailed) {
  // no existing connections to peer
  EXPECT_CALL(*cmgr, getBestConnectionForPeer(pid))
      .WillOnce(Return(connection));

  // report random error.
  // we simulate a case when "newStream" gets error
  outcome::result<std::shared_ptr<Stream>> r = std::errc::io_error;
  EXPECT_CALL(*connection, newStream()).WillOnce(Return(r));

  bool executed = false;
  dialer->newStream(pinfo, protocols, [&](auto &&rstream) {
    EXPECT_OUTCOME_FALSE(e, rstream);
    EXPECT_EQ(e.value(), (int)std::errc::io_error);
    executed = true;
  });

  while (!scheduler_backend->empty()) {
    scheduler_backend->shift(std::chrono::milliseconds(1));
  }

  ASSERT_TRUE(executed);
}

/**
 * @given existing connection to peer
 * @when newStream is executed
 * @then get negotiation failure
 */
TEST_F(DialerTest, NewStreamNegotiationFailed) {
  // connection exist to peer
  EXPECT_CALL(*cmgr, getBestConnectionForPeer(pid))
      .WillOnce(Return(connection));

  // newStream returns valid stream
  EXPECT_CALL(*connection, newStream()).WillOnce(Return(stream));

  auto r = std::make_error_code(std::errc::io_error);

  EXPECT_CALL(*proto_muxer, selectOneOf(gsl::make_span(protocols), _, _, _, _))
      .WillOnce(InvokeArgument<4>(r));

  bool executed = false;
  dialer->newStream(pinfo, protocols, [&](auto &&rstream) {
    EXPECT_OUTCOME_FALSE(e, rstream);
    EXPECT_EQ(e, r);
    executed = true;
  });

  while (!scheduler_backend->empty()) {
    scheduler_backend->shift(std::chrono::milliseconds(1));
  }

  ASSERT_TRUE(executed);
}

/**
 * @given existing connection to peer
 * @when newStream is executed
 * @then get new stream
 */
TEST_F(DialerTest, NewStreamSuccess) {
  // connection exist to peer
  EXPECT_CALL(*cmgr, getBestConnectionForPeer(pid))
      .WillOnce(Return(connection));

  // newStream returns valid stream
  EXPECT_CALL(*connection, newStream()).WillOnce(Return(stream));

  EXPECT_CALL(*proto_muxer, selectOneOf(gsl::make_span(protocols), _, _, _, _))
      .WillOnce(InvokeArgument<4>(protocols[0]));

  bool executed = false;
  dialer->newStream(pinfo, protocols, [&](auto &&rstream) {
    EXPECT_OUTCOME_TRUE(s, rstream);
    (void)s;
    executed = true;
  });

  while (!scheduler_backend->empty()) {
    scheduler_backend->shift(std::chrono::milliseconds(1));
  }

  ASSERT_TRUE(executed);
}

/**
 * @given a gater configured to reject interceptPeerDial for the target peer
 * @when dial is executed
 * @then the transport layer is never consulted and the callback receives
 * GATER_REJECTED_PEER_DIAL
 */
TEST_F(DialerTest, DialRejectedByPeerDialGater) {
  EXPECT_CALL(*gater, interceptPeerDial(pinfo.id))
      .WillOnce(Return(ConnectionGaterError::GATER_REJECTED_PEER_DIAL));

  EXPECT_CALL(*cmgr, getBestConnectionForPeer(pinfo.id)).Times(0);
  EXPECT_CALL(*tmgr, findBest(_)).Times(0);

  bool executed = false;
  dialer->dial(pinfo, [&](auto &&rconn) {
    EXPECT_OUTCOME_FALSE(e, rconn);
    EXPECT_EQ(e.value(), (int)ConnectionGaterError::GATER_REJECTED_PEER_DIAL);
    executed = true;
  });

  while (!scheduler_backend->empty()) {
    scheduler_backend->shift(std::chrono::milliseconds(1));
  }

  ASSERT_TRUE(executed);
}

/**
 * @given a gater configured to reject interceptAddrDial for the peer's only
 * address
 * @when dial is executed
 * @then transport->dial is never invoked for that address and the callback
 * eventually receives GATER_REJECTED_ADDR_DIAL once addresses are exhausted
 */
TEST_F(DialerTest, DialRejectedByAddrDialGater) {
  EXPECT_CALL(*cmgr, getBestConnectionForPeer(pinfo.id))
      .WillOnce(Return(nullptr));

  EXPECT_CALL(*gater, interceptAddrDial(pinfo.id, ma1))
      .WillOnce(Return(ConnectionGaterError::GATER_REJECTED_ADDR_DIAL));

  EXPECT_CALL(*tmgr, findBest(ma1)).WillOnce(Return(transport));
  EXPECT_CALL(*transport, dial(_, _, _, _)).Times(0);

  bool executed = false;
  dialer->dial(pinfo, [&](auto &&rconn) {
    EXPECT_OUTCOME_FALSE(e, rconn);
    EXPECT_EQ(e.value(), (int)ConnectionGaterError::GATER_REJECTED_ADDR_DIAL);
    executed = true;
  });

  while (!scheduler_backend->empty()) {
    scheduler_backend->shift(std::chrono::milliseconds(1));
  }

  ASSERT_TRUE(executed);
}

/**
 * @given a private-network dialer (PSK configured)
 * @when dialing a peer whose address is /dnsaddr/bootstrap.libp2p.io
 * @then the callback receives PNET_PUBLIC_BOOTSTRAP_REFUSED after the
 *        scheduler drains and the transport is NEVER dialed (BOOT-01)
 */
TEST_F(DialerTest, PskRefusesBootstrapAddressDial) {
  auto psk_dialer = makePskDialer();

  multi::Multiaddress bootstrap_ma = "/dnsaddr/bootstrap.libp2p.io"_multiaddr;
  peer::PeerInfo bootstrap_peer{pid, {bootstrap_ma}};

  // transport must NEVER be dialed for a refused bootstrap target
  EXPECT_CALL(*transport, dial(_, _, _, _)).Times(0);

  bool executed = false;
  psk_dialer->dial(bootstrap_peer, [&](auto &&rconn) {
    EXPECT_OUTCOME_FALSE(e, rconn);
    EXPECT_EQ(e.value(),
              (int)security::pnet::PnetError::PNET_PUBLIC_BOOTSTRAP_REFUSED);
    executed = true;
  });

  drainScheduler();
  ASSERT_TRUE(executed);
}

/**
 * @given a private-network dialer (PSK configured)
 * @when dialing a peer whose ID is in the bootstrap peer-ID snapshot
 * @then the dial is refused with PNET_PUBLIC_BOOTSTRAP_REFUSED even though
 *        its address is an ordinary one (advisory snapshot guard)
 */
TEST_F(DialerTest, PskRefusesBootstrapPeerIdDial) {
  auto psk_dialer = makePskDialer();

  // from the transcribed live dnsaddr snapshot (QmbLHAnMoJPWSCR5...)
  auto bootstrap_pid_res = peer::PeerId::fromBase58(
      "QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb");
  ASSERT_TRUE(bootstrap_pid_res);
  peer::PeerInfo snapshot_peer{bootstrap_pid_res.value(), {ma1}};

  EXPECT_CALL(*transport, dial(_, _, _, _)).Times(0);

  bool executed = false;
  psk_dialer->dial(snapshot_peer, [&](auto &&rconn) {
    EXPECT_OUTCOME_FALSE(e, rconn);
    EXPECT_EQ(e.value(),
              (int)security::pnet::PnetError::PNET_PUBLIC_BOOTSTRAP_REFUSED);
    executed = true;
  });

  drainScheduler();
  ASSERT_TRUE(executed);
}

/**
 * @given a private-network dialer (PSK configured)
 * @when dialing an ordinary private peer
 * @then the dial proceeds exactly as in public mode (address resolution and
 *        transport dial still happen)
 */
TEST_F(DialerTest, PskAllowsOrdinaryPeerDial) {
  auto psk_dialer = makePskDialer();

  EXPECT_CALL(*cmgr, getBestConnectionForPeer(pinfo.id))
      .WillOnce(Return(nullptr));
  EXPECT_CALL(*listener, onConnection(_)).Times(1);
  EXPECT_CALL(*tmgr, findBest(ma1)).WillOnce(Return(transport));
  EXPECT_CALL(*transport,
              dial(pinfo.id, ma1, _,
                   std::chrono::milliseconds::zero(), _, false, false))
      .WillOnce(Arg2CallbackWithArg(outcome::success(connection)));

  bool executed = false;
  psk_dialer->dial(pinfo, [&](auto &&rconn) {
    EXPECT_OUTCOME_TRUE(conn, rconn);
    (void)conn;
    executed = true;
  });

  drainScheduler();
  ASSERT_TRUE(executed);
}

/**
 * @given a PUBLIC-mode dialer (no PSK)
 * @when dialing the bootstrap address
 * @then the dial proceeds as today — transport is dialed (D-08: absence of
 *        a PSK leaves public behavior untouched)
 */
TEST_F(DialerTest, NoPskAllowsBootstrapDial) {
  multi::Multiaddress bootstrap_ma = "/dnsaddr/bootstrap.libp2p.io"_multiaddr;
  peer::PeerInfo bootstrap_peer{pid, {bootstrap_ma}};

  EXPECT_CALL(*cmgr, getBestConnectionForPeer(pid)).WillOnce(Return(nullptr));
  EXPECT_CALL(*listener, onConnection(_)).Times(1);
  EXPECT_CALL(*tmgr, findBest(bootstrap_ma)).WillOnce(Return(transport));
  EXPECT_CALL(*transport,
              dial(pid, bootstrap_ma, _,
                   std::chrono::milliseconds::zero(), _, false, false))
      .WillOnce(Arg2CallbackWithArg(outcome::success(connection)));

  bool executed = false;
  dialer->dial(bootstrap_peer, [&](auto &&rconn) {
    EXPECT_OUTCOME_TRUE(conn, rconn);
    (void)conn;
    executed = true;
  });

  drainScheduler();
  ASSERT_TRUE(executed);
}
