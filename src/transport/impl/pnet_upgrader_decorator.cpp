/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <libp2p/transport/impl/pnet_upgrader_decorator.hpp>

#include <libp2p/security/pnet/pnet_protected_connection.hpp>

namespace libp2p::transport {

  PnetUpgraderDecorator::PnetUpgraderDecorator(
      std::shared_ptr<UpgraderImpl> inner,
      std::shared_ptr<const security::pnet::Psk> psk,
      std::shared_ptr<basic::Scheduler> scheduler)
      : inner_(std::move(inner)),
        psk_(std::move(psk)),
        scheduler_(std::move(scheduler)) {}

  void PnetUpgraderDecorator::upgradeToSecureOutbound(
      RawSPtr conn, const peer::PeerId &remoteId, OnSecuredCallbackFunc cb) {
    // wrap the raw connection in the PSK boundary before multiselect sees it
    auto protected_conn =
        std::make_shared<security::pnet::PnetProtectedConnection>(
            std::move(conn), psk_, scheduler_);
    inner_->upgradeToSecureOutbound(std::move(protected_conn), remoteId,
                                    std::move(cb));
  }

  void PnetUpgraderDecorator::upgradeToSecureOutboundRelay(
      StrSPtr conn, const peer::PeerId &remoteId, OnSecuredCallbackFunc cb) {
    // NOT PSK-wrapped: relay streams would need a full Stream decorator
    // (documented limitation — see class comment)
    inner_->upgradeToSecureOutboundRelay(std::move(conn), remoteId,
                                         std::move(cb));
  }

  void PnetUpgraderDecorator::upgradeToSecureInbound(
      RawSPtr conn, OnSecuredCallbackFunc cb) {
    auto protected_conn =
        std::make_shared<security::pnet::PnetProtectedConnection>(
            std::move(conn), psk_, scheduler_);
    inner_->upgradeToSecureInbound(std::move(protected_conn), std::move(cb));
  }

  void PnetUpgraderDecorator::upgradeToSecureInboundRelay(
      StrSPtr conn, OnSecuredCallbackFunc cb) {
    // NOT PSK-wrapped (documented limitation — see class comment)
    inner_->upgradeToSecureInboundRelay(std::move(conn), std::move(cb));
  }

  void PnetUpgraderDecorator::upgradeToMuxed(SecSPtr conn,
                                             OnMuxedCallbackFunc cb) {
    // muxing operates above the PSK layer — pass through
    inner_->upgradeToMuxed(std::move(conn), std::move(cb));
  }

}  // namespace libp2p::transport
