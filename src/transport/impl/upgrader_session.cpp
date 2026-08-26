/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <libp2p/transport/impl/upgrader_session.hpp>

#include <boost/assert.hpp>
#include <iostream>

namespace libp2p::transport {

  UpgraderSession::UpgraderSession(
      std::shared_ptr<transport::Upgrader> upgrader,
      std::shared_ptr<connection::RawConnection> raw,
      UpgraderSession::HandlerFunc handler,
      std::shared_ptr<network::ConnectionGater> gater,
      std::shared_ptr<basic::Scheduler> scheduler)
      : upgrader_(std::move(upgrader)),
        raw_(std::move(raw)),
        handler_(std::move(handler)),
        gater_(std::move(gater)),
        scheduler_(std::move(scheduler)),
        log_(log::createLogger("UpgraderSession")) {}

  UpgraderSession::UpgraderSession(
      std::shared_ptr<transport::Upgrader> upgrader,
      std::shared_ptr<connection::Stream> stream,
      UpgraderSession::HandlerFunc handler,
      std::shared_ptr<network::ConnectionGater> gater,
      std::shared_ptr<basic::Scheduler> scheduler)
      : upgrader_(std::move(upgrader)),
      stream_(std::move(stream)),
      handler_(std::move(handler)),
      gater_(std::move(gater)),
      scheduler_(std::move(scheduler)),
      log_(log::createLogger("UpgraderSession")) {}

  void UpgraderSession::secureOutbound(const peer::PeerId &remoteId) {
    auto self{shared_from_this()};
    upgrader_->upgradeToSecureOutbound(raw_, remoteId, [self](auto &&r) {
      self->onSecured(std::forward<decltype(r)>(r));
    });
  }


  void UpgraderSession::secureOutboundRelay(const peer::PeerId& remoteId) {
      auto self{ shared_from_this() };
      upgrader_->upgradeToSecureOutboundRelay(stream_, remoteId, [self](auto&& r) {
          self->onSecured(std::forward<decltype(r)>(r));
          });
  }

  void UpgraderSession::secureInbound() {
    upgrader_->upgradeToSecureInbound(
        raw_, [self{shared_from_this()}](auto &&r) {
          self->onSecured(std::forward<decltype(r)>(r));
        });
  }

  void UpgraderSession::secureInboundRelay() {
      upgrader_->upgradeToSecureInboundRelay(
          stream_, [self{ shared_from_this() }](auto&& r) {
              self->onSecured(std::forward<decltype(r)>(r));
          });
  }

  void UpgraderSession::onSecured(
      outcome::result<std::shared_ptr<connection::SecureConnection>> rsecure) {
    if (!rsecure) {
      return handler_(rsecure.error());
    }

    auto &secure = rsecure.value();
    auto remote_peer = secure->remotePeer();
    auto remote_addr = secure->remoteMultiaddr();
    if (remote_peer && remote_addr) {
      if (auto gated = gater_->interceptSecured(
              secure->isInitiator(), remote_peer.value(), remote_addr.value());
          !gated) {
        SL_DEBUG(log_,
                 "gater rejected secured connection to {} at {}: {}",
                 remote_peer.value().toBase58(),
                 remote_addr.value().getStringAddress(),
                 gated.error().message());
        if (!secure->isClosed()) {
          auto close_res = secure->close();
          BOOST_ASSERT(close_res);
        }
        scheduler_->schedule(
            [self{shared_from_this()}, err{gated.error()}] {
              self->handler_(err);
            });
        return;
      }
    }

    upgrader_->upgradeToMuxed(
        rsecure.value(), [self{shared_from_this()}](auto &&r) {
          if (r.has_value()) {
            if (auto gated = self->gater_->interceptUpgraded(r.value());
                !gated) {
              auto remote_peer = r.value()->remotePeer();
              SL_DEBUG(self->log_,
                       "gater rejected upgraded connection to {}: {}",
                       remote_peer ? remote_peer.value().toBase58()
                                   : std::string("unknown"),
                       gated.error().message());
              if (!r.value()->isClosed()) {
                auto close_res = r.value()->close();
                BOOST_ASSERT(close_res);
              }
              self->scheduler_->schedule(
                  [self, err{gated.error()}] { self->handler_(err); });
              return;
            }
          }
          self->handler_(std::forward<decltype(r)>(r));
        });
  }
}  // namespace libp2p::transport
