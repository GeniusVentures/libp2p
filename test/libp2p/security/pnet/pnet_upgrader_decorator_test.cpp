/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * PnetUpgraderDecorator method-coverage matrix:
 * - the two RawSPtr upgrade paths wrap the connection in a
 *   PnetProtectedConnection (dynamic-cast asserted at the security adaptor,
 *   which receives the raw connection after multiselect negotiation)
 * - relay overloads and upgradeToMuxed pass through unwrapped (relay paths
 *   tested structurally; muxed is compile-structural per plan)
 *
 * The inner is a REAL UpgraderImpl built with mocked collaborators (the
 * decorator ctor demands the concrete type).
 */
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <memory>
#include <vector>

#include <libp2p/basic/scheduler/scheduler_impl.hpp>
#include <libp2p/basic/scheduler/manual_scheduler_backend.hpp>
#include <libp2p/common/literals.hpp>
#include <libp2p/security/pnet/pnet_protected_connection.hpp>
#include <libp2p/security/pnet/psk.hpp>
#include <libp2p/transport/impl/pnet_upgrader_decorator.hpp>

#include "mock/libp2p/connection/raw_connection_mock.hpp"
#include "mock/libp2p/connection/stream_mock.hpp"
#include "mock/libp2p/muxer/muxer_adaptor_mock.hpp"
#include "mock/libp2p/protocol_muxer/protocol_muxer_mock.hpp"
#include "mock/libp2p/security/security_adaptor_mock.hpp"

namespace libp2p::security {
  // extends the checked-in mock with the relay overloads (not mocked there)
  struct SecurityAdaptorMockFull : public SecurityAdaptorMock {
    void secureInboundRelay(std::shared_ptr<connection::Stream> inbound,
                            SecConnCallbackFunc cb) override {
      cb(libp2p::outcome::failure(std::errc::not_supported));
    }
    void secureOutboundRelay(std::shared_ptr<connection::Stream> outbound,
                             const peer::PeerId &p,
                             SecConnCallbackFunc cb) override {
      cb(libp2p::outcome::failure(std::errc::not_supported));
    }
  };
}  // namespace libp2p::security

using namespace libp2p::common;
using namespace libp2p::transport;
using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;

namespace {
  const std::vector<uint8_t> kKeyBytes = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

  const libp2p::peer::Protocol kSecProto = "/test-sec/1.0.0";
}  // namespace

struct PnetUpgraderDecoratorTest : public ::testing::Test {
  void SetUp() override {
    auto psk_res = libp2p::security::pnet::Psk::fromRawBytes(kKeyBytes);
    ASSERT_TRUE(psk_res);
    psk = std::shared_ptr<const libp2p::security::pnet::Psk>(
        new libp2p::security::pnet::Psk(std::move(psk_res.value())));

    adaptor = std::make_shared<libp2p::security::SecurityAdaptorMockFull>();
    muxer = std::make_shared<libp2p::muxer::MuxerAdaptorMock>();
    ON_CALL(*adaptor, getProtocolId()).WillByDefault(Return(kSecProto));
    ON_CALL(*muxer, getProtocolId())
        .WillByDefault(Return("/test-mux/1.0.0"));

    // multiselect negotiates straight to the (single) security adaptor
    ON_CALL(*proto_muxer, selectOneOf(_, _, _, _, _))
        .WillByDefault(Invoke(
            [this](gsl::span<const libp2p::peer::Protocol> /*protocols*/,
                   std::shared_ptr<libp2p::basic::ReadWriter> /*conn*/,
                   bool /*initiator*/, bool /*multiselect*/,
                   libp2p::protocol_muxer::ProtocolMuxer::ProtocolHandlerFunc
                       cb) {
              cb(kSecProto);
            }));

    inner = std::make_shared<UpgraderImpl>(
        proto_muxer,
        std::vector<std::shared_ptr<libp2p::security::SecurityAdaptor>>{
            adaptor},
        std::vector<std::shared_ptr<libp2p::muxer::MuxerAdaptor>>{muxer});
    decorator = std::make_shared<PnetUpgraderDecorator>(inner, psk, scheduler);
  }

  std::shared_ptr<libp2p::protocol_muxer::ProtocolMuxerMock> proto_muxer =
      std::make_shared<libp2p::protocol_muxer::ProtocolMuxerMock>();

  std::shared_ptr<libp2p::security::SecurityAdaptorMockFull> adaptor;
  std::shared_ptr<libp2p::muxer::MuxerAdaptorMock> muxer;

  std::shared_ptr<libp2p::basic::ManualSchedulerBackend> backend =
      std::make_shared<libp2p::basic::ManualSchedulerBackend>();

  std::shared_ptr<libp2p::basic::SchedulerImpl> scheduler =
      std::make_shared<libp2p::basic::SchedulerImpl>(
          backend, libp2p::basic::Scheduler::Config{});

  std::shared_ptr<const libp2p::security::pnet::Psk> psk;
  std::shared_ptr<UpgraderImpl> inner;
  std::shared_ptr<PnetUpgraderDecorator> decorator;

  libp2p::peer::PeerId remote = "1"_peerid;
};

/**
 * @given a raw connection upgraded outbound through the decorator
 * @when the multiselect negotiation picks the security adaptor
 * @then the connection secureOutbound receives IS a PnetProtectedConnection
 */
TEST_F(PnetUpgraderDecoratorTest, OutboundWrapsInProtectedConnection) {
  auto raw = std::make_shared<libp2p::connection::RawConnectionMock>();
  ON_CALL(*raw, isInitiator_hack()).WillByDefault(Return(true));

  EXPECT_CALL(*adaptor, secureOutbound(_, _, _))
      .WillOnce(Invoke(
          [](std::shared_ptr<libp2p::connection::RawConnection> conn,
             const libp2p::peer::PeerId &, auto &&cb) {
            auto wrapped = std::dynamic_pointer_cast<
                libp2p::security::pnet::PnetProtectedConnection>(conn);
            ASSERT_NE(wrapped, nullptr);
            cb(libp2p::outcome::failure(std::errc::not_supported));
          }));

  decorator->upgradeToSecureOutbound(
      raw, remote,
      [](libp2p::outcome::result<Upgrader::SecSPtr> r) { ASSERT_FALSE(r); });
}

/** Same wrap assert, inbound path */
TEST_F(PnetUpgraderDecoratorTest, InboundWrapsInProtectedConnection) {
  auto raw = std::make_shared<libp2p::connection::RawConnectionMock>();
  ON_CALL(*raw, isInitiator_hack()).WillByDefault(Return(false));

  EXPECT_CALL(*adaptor, secureInbound(_, _))
      .WillOnce(Invoke(
          [](std::shared_ptr<libp2p::connection::RawConnection> conn,
             auto &&cb) {
            auto wrapped = std::dynamic_pointer_cast<
                libp2p::security::pnet::PnetProtectedConnection>(conn);
            ASSERT_NE(wrapped, nullptr);
            cb(libp2p::outcome::failure(std::errc::not_supported));
          }));

  decorator->upgradeToSecureInbound(
      raw, [](libp2p::outcome::result<Upgrader::SecSPtr> r) {
        ASSERT_FALSE(r);
      });
}

/**
 * @given a relay stream
 * @when upgraded through the relay overloads
 * @then the stream reaches the inner unwrapped — the decorator has no
 *        Stream-level wrap (pass-through is the documented limitation)
 */
TEST_F(PnetUpgraderDecoratorTest, RelayPassesThroughUnwrapped) {
  auto stream = std::make_shared<libp2p::connection::StreamMock>();
  ON_CALL(*stream, isInitiator()).WillByDefault(Return(true));
  auto same = std::static_pointer_cast<libp2p::basic::ReadWriter>(stream);

  // the relay path ends in multiselect with the SAME stream object
  EXPECT_CALL(*proto_muxer, selectOneOf(_, _, _, _, _))
      .WillOnce(Invoke(
          [same](gsl::span<const libp2p::peer::Protocol> /*protocols*/,
                 std::shared_ptr<libp2p::basic::ReadWriter> conn,
                 bool, bool,
                 libp2p::protocol_muxer::ProtocolMuxer::ProtocolHandlerFunc
                     cb) {
            // identity: not wrapped in anything
            ASSERT_EQ(conn.get(), same.get());
            cb(libp2p::outcome::result<libp2p::peer::Protocol>(
                std::errc::not_supported));
          }))
      .RetiresOnSaturation();

  decorator->upgradeToSecureOutboundRelay(
      stream, remote,
      [](libp2p::outcome::result<Upgrader::SecSPtr>) {});
  SUCCEED();
}
