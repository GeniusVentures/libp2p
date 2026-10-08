/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include <libp2p/basic/scheduler/manual_scheduler_backend.hpp>
#include <libp2p/basic/scheduler/scheduler_impl.hpp>
#include <libp2p/common/literals.hpp>
#include <libp2p/network/connection_gater_error.hpp>
#include "libp2p/transport/tcp/tcp_listener.hpp"
#include "testutil/gmock_actions.hpp"
#include "testutil/outcome.hpp"
#include "testutil/prepare_loggers.hpp"

#include "mock/libp2p/network/connection_gater_mock.hpp"
#include "mock/libp2p/transport/upgrader_mock.hpp"

using namespace libp2p;
using namespace transport;
using namespace connection;
using namespace network;
using namespace basic;
using namespace common;
using std::chrono_literals::operator""ms;

using ::testing::_;
using ::testing::Eq;
using ::testing::Invoke;
using ::testing::MockFunction;
using ::testing::Return;
using ::testing::StrictMock;

struct TcpListenerTest : public ::testing::Test {
  using CapConnResult = outcome::result<std::shared_ptr<CapableConnection>>;

  std::shared_ptr<boost::asio::io_context> context =
      std::make_shared<boost::asio::io_context>();

  std::shared_ptr<StrictMock<UpgraderMock>> upgrader =
      std::make_shared<StrictMock<UpgraderMock>>();

  StrictMock<MockFunction<void(CapConnResult)>> cb;

  std::shared_ptr<ManualSchedulerBackend> scheduler_backend =
      std::make_shared<ManualSchedulerBackend>();

  std::shared_ptr<Scheduler> scheduler =
      std::make_shared<SchedulerImpl>(scheduler_backend, Scheduler::Config{});

  std::shared_ptr<ConnectionGaterMock> gater =
      std::make_shared<ConnectionGaterMock>();

  std::shared_ptr<TcpListener> listener;

  multi::Multiaddress ma = "/ip4/127.0.0.1/tcp/40005"_multiaddr;

  void SetUp() override {
    testutil::prepareLoggers();
    ON_CALL(*gater, interceptAccept(_, _))
        .WillByDefault(Return(outcome::success()));
    listener = std::make_shared<TcpListener>(
        *context, upgrader,
        [this](auto &&r) { cb.Call(std::forward<decltype(r)>(r)); }, gater,
        scheduler);
  }
};

/**
 * @given listener
 * @when listen, close, listen, close
 * @then no error happens
 */
TEST_F(TcpListenerTest, ListenCloseListen) {
  EXPECT_CALL(cb, Call(_)).WillRepeatedly(Invoke([](CapConnResult c) {
    if (!c) {
      ASSERT_EQ(c.error().value(), (int)std::errc::operation_canceled);
    } else {
      ADD_FAILURE();
    }
  }));

  EXPECT_OUTCOME_TRUE_1(listener->listen(ma));
  ASSERT_FALSE(listener->isClosed());
  EXPECT_OUTCOME_TRUE_1(listener->close());
  ASSERT_TRUE(listener->isClosed());

  EXPECT_OUTCOME_TRUE_1(listener->listen(ma));
  ASSERT_FALSE(listener->isClosed());
  EXPECT_OUTCOME_TRUE_1(listener->close());
  ASSERT_TRUE(listener->isClosed());

  context->run_for(50ms);
}

/**
 * @give listener
 * @when double close
 * @then no error received
 */
TEST_F(TcpListenerTest, DoubleClose) {
  EXPECT_CALL(cb, Call(_)).WillOnce(Invoke([](CapConnResult c) {
    if (!c) {
      ASSERT_EQ(c.error().value(), (int)std::errc::operation_canceled);
    }
  }));

  EXPECT_OUTCOME_TRUE_1(listener->listen(ma));
  ASSERT_FALSE(listener->isClosed());
  EXPECT_OUTCOME_TRUE_1(listener->close());
  EXPECT_OUTCOME_TRUE_1(listener->close());
  ASSERT_TRUE(listener->isClosed());
  context->run_for(50ms);
}

/**
 * @given a listener with a gater configured to reject interceptAccept
 * @when a real client connects
 * @then the accepted connection is closed without ever calling
 * upgradeToSecureInbound, and the client observes the server-side close
 */
TEST_F(TcpListenerTest, AcceptRejectedByGaterClosesConnectionWithoutUpgrading) {
  EXPECT_CALL(*gater, interceptAccept(_, _))
      .WillOnce(Return(ConnectionGaterError::GATER_REJECTED_ACCEPT));
  EXPECT_CALL(*upgrader, upgradeToSecureInbound(_, _)).Times(0);

  EXPECT_OUTCOME_TRUE_1(listener->listen(ma));

  boost::asio::ip::tcp::socket client_sock(*context);
  boost::asio::ip::tcp::endpoint endpoint(
      boost::asio::ip::make_address("127.0.0.1"), 40005);

  bool connected = false;
  client_sock.async_connect(
      endpoint, [&connected](const boost::system::error_code &ec) {
        connected = !ec;
      });

  context->run_for(100ms);
  ASSERT_TRUE(connected);

  // Pump the manual scheduler so the deferred interceptAccept callback runs
  // (this enqueues TcpConnection::close()'s actual socket close as a
  // boost::asio::post(context_, ...) onto the io_context).
  while (!scheduler_backend->empty()) {
    scheduler_backend->shift(std::chrono::milliseconds(1));
  }

  // Run the io_context again so the posted close actually executes.
  context->run_for(100ms);

  // The server closed the accepted socket without upgrading it; the client
  // should observe EOF/connection-reset on a subsequent read.
  std::vector<uint8_t> buf(16);
  boost::system::error_code read_ec;
  boost::asio::read(client_sock, boost::asio::buffer(buf), read_ec);
  EXPECT_TRUE(read_ec);
}

/**
 * @given a listener with a gater configured to reject interceptAccept
 * @when a real client connects
 * @then interceptAccept is proven to run only from within the
 * scheduler-deferred accept block, never synchronously from async_accept's
 * own completion frame (reentrancy regression, TEST-04/D-05, T-03-05).
 * interceptAccept is a synchronous, direct-return method with no
 * callback-taking collaborator that can be forced into synchronous
 * completion (D-06's technique does not apply to this specific call site --
 * see 03-RESEARCH.md's "Key nuance" paragraph), and the ENTIRE
 * accept-handling block, interceptAccept call included, is already the
 * deferred body of one scheduler_->schedule(...) call -- there is no further
 * nested scheduling to guard around at this exact site. This test therefore
 * uses a before/after observation instead of the ReentrancyGuard::Scope
 * idiom used in dialer_test.cpp/upgrader_session_test.cpp.
 */
TEST_F(TcpListenerTest, AcceptGaterRejectionDeferredUntilSchedulerDrains) {
  bool intercept_called = false;
  EXPECT_CALL(*gater, interceptAccept(_, _))
      .WillOnce(Invoke([&](const multi::Multiaddress &,
                           const multi::Multiaddress &) {
        intercept_called = true;
        return outcome::result<void>(ConnectionGaterError::GATER_REJECTED_ACCEPT);
      }));
  EXPECT_CALL(*upgrader, upgradeToSecureInbound(_, _)).Times(0);

  EXPECT_OUTCOME_TRUE_1(listener->listen(ma));

  boost::asio::ip::tcp::socket client_sock(*context);
  boost::asio::ip::tcp::endpoint endpoint(
      boost::asio::ip::make_address("127.0.0.1"), 40005);

  bool connected = false;
  client_sock.async_connect(
      endpoint, [&connected](const boost::system::error_code &ec) {
        connected = !ec;
      });

  context->run_for(100ms);
  ASSERT_TRUE(connected);

  // interceptAccept must not have run purely from async_accept's own
  // completion (the io_context run loop) -- the entire accept-handling
  // block, interceptAccept call included, lives inside
  // scheduler_->schedule(...), which the ManualSchedulerBackend (a queue
  // entirely separate from context's own run loop) has not yet drained.
  ASSERT_FALSE(intercept_called);

  // Pump the manual scheduler so the deferred accept-handling block (and the
  // interceptAccept call within it) actually runs.
  while (!scheduler_backend->empty()) {
    scheduler_backend->shift(std::chrono::milliseconds(1));
  }

  ASSERT_TRUE(intercept_called);

  // Run the io_context again so the posted close (from the rejected accept)
  // actually executes.
  context->run_for(100ms);
}
