/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "libp2p/transport/impl/upgrader_session.hpp"

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <libp2p/basic/scheduler/manual_scheduler_backend.hpp>
#include <libp2p/basic/scheduler/scheduler_impl.hpp>
#include <libp2p/common/literals.hpp>
#include <libp2p/network/connection_gater_error.hpp>
#include "mock/libp2p/connection/capable_connection_mock.hpp"
#include "mock/libp2p/connection/raw_connection_mock.hpp"
#include "mock/libp2p/connection/secure_connection_mock.hpp"
#include "mock/libp2p/network/connection_gater_mock.hpp"
#include "mock/libp2p/transport/upgrader_mock.hpp"
#include "testutil/gmock_actions.hpp"
#include "testutil/outcome.hpp"
#include "testutil/prepare_loggers.hpp"

using namespace libp2p;
using namespace transport;
using namespace connection;
using namespace network;
using namespace basic;
using namespace common;

using ::testing::_;
using ::testing::Invoke;
using ::testing::MockFunction;
using ::testing::Return;
using ::testing::StrictMock;

struct UpgraderSessionTest : public ::testing::Test {
  void SetUp() override {
    testutil::prepareLoggers();
    session = std::make_shared<UpgraderSession>(
        upgrader, raw,
        [this](auto &&r) { handler_cb.Call(std::forward<decltype(r)>(r)); },
        gater, scheduler);
  }

  std::shared_ptr<StrictMock<UpgraderMock>> upgrader =
      std::make_shared<StrictMock<UpgraderMock>>();

  std::shared_ptr<ConnectionGaterMock> gater =
      std::make_shared<ConnectionGaterMock>();

  std::shared_ptr<ManualSchedulerBackend> scheduler_backend =
      std::make_shared<ManualSchedulerBackend>();

  std::shared_ptr<Scheduler> scheduler =
      std::make_shared<SchedulerImpl>(scheduler_backend, Scheduler::Config{});

  std::shared_ptr<RawConnectionMock> raw =
      std::make_shared<RawConnectionMock>();
  std::shared_ptr<RawConnection> raw_base = raw;

  std::shared_ptr<UpgraderSession> session;

  MockFunction<void(outcome::result<std::shared_ptr<CapableConnection>>)>
      handler_cb;

  peer::PeerId pid = "1"_peerid;
  multi::Multiaddress ma = "/ip4/127.0.0.1/tcp/1"_multiaddr;

  void pump() {
    while (!scheduler_backend->empty()) {
      scheduler_backend->shift(std::chrono::milliseconds(1));
    }
  }
};

/**
 * @given a gater configured to accept both interceptSecured and
 * interceptUpgraded
 * @when a raw connection is secured and then muxed
 * @then upgradeToMuxed is invoked exactly once and the handler receives the
 * resulting capable connection
 */
TEST_F(UpgraderSessionTest, SecuredAcceptedProceedsToMux) {
  auto secure = std::make_shared<SecureConnectionMock>();
  std::shared_ptr<SecureConnection> secure_base = secure;
  auto capable = std::make_shared<CapableConnectionMock>();
  std::shared_ptr<CapableConnection> capable_base = capable;

  EXPECT_CALL(*upgrader, upgradeToSecureInbound(raw_base, _))
      .WillOnce(UpgradeToSecureInbound(
          [&](auto &&) { return outcome::success(secure_base); }));

  EXPECT_CALL(*secure, remotePeer()).WillOnce(Return(pid));
  EXPECT_CALL(*secure, remoteMultiaddr()).WillOnce(Return(ma));
  EXPECT_CALL(*secure, isInitiatorMock()).WillOnce(Return(false));
  EXPECT_CALL(*gater, interceptSecured(false, pid, ma))
      .WillOnce(Return(outcome::success()));

  EXPECT_CALL(*upgrader, upgradeToMuxed(secure_base, _))
      .WillOnce(UpgradeToMuxed(
          [&](auto &&) { return outcome::success(capable_base); }));
  EXPECT_CALL(*gater, interceptUpgraded(capable_base))
      .WillOnce(Return(outcome::success()));

  bool executed = false;
  EXPECT_CALL(handler_cb, Call(_))
      .WillOnce(Invoke([&](auto &&r) {
        EXPECT_OUTCOME_TRUE(conn, r);
        EXPECT_EQ(conn, capable_base);
        executed = true;
      }));

  session->secureInbound();
  pump();

  ASSERT_TRUE(executed);
}

/**
 * @given a gater configured to reject interceptSecured
 * @when a raw connection is secured
 * @then upgradeToMuxed is never called, the secure connection is closed
 * exactly once, and the handler is only invoked after the scheduler backend
 * is pumped
 */
TEST_F(UpgraderSessionTest, SecuredRejectedClosesAndDefersHandler) {
  auto secure = std::make_shared<SecureConnectionMock>();
  std::shared_ptr<SecureConnection> secure_base = secure;

  EXPECT_CALL(*upgrader, upgradeToSecureInbound(raw_base, _))
      .WillOnce(UpgradeToSecureInbound(
          [&](auto &&) { return outcome::success(secure_base); }));

  EXPECT_CALL(*secure, remotePeer()).WillOnce(Return(pid));
  EXPECT_CALL(*secure, remoteMultiaddr()).WillOnce(Return(ma));
  EXPECT_CALL(*secure, isInitiatorMock()).WillOnce(Return(true));
  EXPECT_CALL(*gater, interceptSecured(true, pid, ma))
      .WillOnce(Return(ConnectionGaterError::GATER_REJECTED_SECURED));

  EXPECT_CALL(*secure, isClosed()).WillOnce(Return(false));
  EXPECT_CALL(*secure, close()).WillOnce(Return(outcome::success()));

  EXPECT_CALL(*upgrader, upgradeToMuxed(_, _)).Times(0);

  bool executed = false;
  EXPECT_CALL(handler_cb, Call(_))
      .WillOnce(Invoke([&](auto &&r) {
        EXPECT_OUTCOME_FALSE(e, r);
        EXPECT_EQ(e.value(),
                  (int)ConnectionGaterError::GATER_REJECTED_SECURED);
        executed = true;
      }));

  session->secureInbound();

  ASSERT_FALSE(executed);

  pump();

  ASSERT_TRUE(executed);
}

/**
 * @given a gater that accepts interceptSecured and interceptUpgraded
 * @when a secured connection is upgraded to a muxed one
 * @then the handler receives the capable connection produced by
 * upgradeToMuxed
 */
TEST_F(UpgraderSessionTest, UpgradedAcceptedInvokesHandler) {
  auto secure = std::make_shared<SecureConnectionMock>();
  std::shared_ptr<SecureConnection> secure_base = secure;
  auto capable = std::make_shared<CapableConnectionMock>();
  std::shared_ptr<CapableConnection> capable_base = capable;

  EXPECT_CALL(*upgrader, upgradeToSecureInbound(raw_base, _))
      .WillOnce(UpgradeToSecureInbound(
          [&](auto &&) { return outcome::success(secure_base); }));

  EXPECT_CALL(*secure, remotePeer()).WillOnce(Return(pid));
  EXPECT_CALL(*secure, remoteMultiaddr()).WillOnce(Return(ma));
  EXPECT_CALL(*secure, isInitiatorMock()).WillOnce(Return(true));
  EXPECT_CALL(*gater, interceptSecured(true, pid, ma))
      .WillOnce(Return(outcome::success()));

  EXPECT_CALL(*upgrader, upgradeToMuxed(secure_base, _))
      .WillOnce(UpgradeToMuxed(
          [&](auto &&) { return outcome::success(capable_base); }));
  EXPECT_CALL(*gater, interceptUpgraded(capable_base))
      .WillOnce(Return(outcome::success()));

  bool executed = false;
  EXPECT_CALL(handler_cb, Call(_))
      .WillOnce(Invoke([&](auto &&r) {
        EXPECT_OUTCOME_TRUE(conn, r);
        EXPECT_EQ(conn, capable_base);
        executed = true;
      }));

  session->secureInbound();
  pump();

  ASSERT_TRUE(executed);
}

/**
 * @given a gater that accepts interceptSecured but rejects interceptUpgraded
 * @when a secured connection is upgraded to a muxed one
 * @then the capable connection is closed exactly once and the handler is
 * only invoked after the scheduler backend is pumped
 */
TEST_F(UpgraderSessionTest, UpgradedRejectedClosesAndDefersHandler) {
  auto secure = std::make_shared<SecureConnectionMock>();
  std::shared_ptr<SecureConnection> secure_base = secure;
  auto capable = std::make_shared<CapableConnectionMock>();
  std::shared_ptr<CapableConnection> capable_base = capable;

  EXPECT_CALL(*upgrader, upgradeToSecureInbound(raw_base, _))
      .WillOnce(UpgradeToSecureInbound(
          [&](auto &&) { return outcome::success(secure_base); }));

  EXPECT_CALL(*secure, remotePeer()).WillOnce(Return(pid));
  EXPECT_CALL(*secure, remoteMultiaddr()).WillOnce(Return(ma));
  EXPECT_CALL(*secure, isInitiatorMock()).WillOnce(Return(true));
  EXPECT_CALL(*gater, interceptSecured(true, pid, ma))
      .WillOnce(Return(outcome::success()));

  EXPECT_CALL(*upgrader, upgradeToMuxed(secure_base, _))
      .WillOnce(UpgradeToMuxed(
          [&](auto &&) { return outcome::success(capable_base); }));
  EXPECT_CALL(*gater, interceptUpgraded(capable_base))
      .WillOnce(Return(ConnectionGaterError::GATER_REJECTED_UPGRADED));

  EXPECT_CALL(*capable, remotePeer()).WillOnce(Return(pid));
  EXPECT_CALL(*capable, isClosed()).WillOnce(Return(false));
  EXPECT_CALL(*capable, close()).WillOnce(Return(outcome::success()));

  bool executed = false;
  EXPECT_CALL(handler_cb, Call(_))
      .WillOnce(Invoke([&](auto &&r) {
        EXPECT_OUTCOME_FALSE(e, r);
        EXPECT_EQ(e.value(),
                  (int)ConnectionGaterError::GATER_REJECTED_UPGRADED);
        executed = true;
      }));

  session->secureInbound();

  ASSERT_FALSE(executed);

  pump();

  ASSERT_TRUE(executed);
}
