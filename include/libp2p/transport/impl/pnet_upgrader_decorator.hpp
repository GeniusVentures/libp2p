/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LIBP2P_TRANSPORT_IMPL_PNET_UPGRADER_DECORATOR_HPP
#define LIBP2P_TRANSPORT_IMPL_PNET_UPGRADER_DECORATOR_HPP

#include <memory>

#include <libp2p/basic/scheduler.hpp>
#include <libp2p/security/pnet/psk.hpp>
#include <libp2p/transport/impl/upgrader_impl.hpp>
#include <libp2p/transport/upgrader.hpp>

namespace libp2p::transport {

  /**
   * Upgrader decorator activating the pnet PSK boundary: the two raw
   * connection upgrade paths (inbound and outbound) get wrapped in a
   * PnetProtectedConnection BEFORE the inner upgrader (and therefore
   * multiselect) sees them — nothing negotiates in the clear past the
   * 24-byte nonce exchange.
   *
   * Deliberate limitation (explicit, not silent): the relay overloads and
   * upgradeToMuxed pass through UNWRAPPED — relay streams are not PSK-wrapped
   * this phase (private-network circuit relay would require a full Stream
   * decorator), and muxing operates above the PSK layer.
   */
  class PnetUpgraderDecorator : public Upgrader,
                                public std::enable_shared_from_this<
                                    PnetUpgraderDecorator> {
   public:
    /// NOTE: takes the CONCRETE UpgraderImpl — requesting the Upgrader
    /// interface it replaces would make Boost.DI resolve itself recursively.
    /// The PSK travels in a copyable PskHandle so Boost.DI can instance-bind
    /// it (Psk itself is move-only).
    PnetUpgraderDecorator(std::shared_ptr<UpgraderImpl> inner,
                          security::pnet::PskHandle psk_handle,
                          std::shared_ptr<basic::Scheduler> scheduler);

    ~PnetUpgraderDecorator() override = default;

    void upgradeToSecureOutbound(RawSPtr conn, const peer::PeerId &remoteId,
                                 OnSecuredCallbackFunc cb) override;

    void upgradeToSecureOutboundRelay(StrSPtr conn,
                                      const peer::PeerId &remoteId,
                                      OnSecuredCallbackFunc cb) override;

    void upgradeToSecureInbound(RawSPtr conn,
                                OnSecuredCallbackFunc cb) override;

    void upgradeToSecureInboundRelay(StrSPtr conn,
                                     OnSecuredCallbackFunc cb) override;

    void upgradeToMuxed(SecSPtr conn, OnMuxedCallbackFunc cb) override;

   private:
    std::shared_ptr<UpgraderImpl> inner_;
    std::shared_ptr<const security::pnet::Psk> psk_;
    std::shared_ptr<basic::Scheduler> scheduler_;
  };

}  // namespace libp2p::transport

#endif  // LIBP2P_TRANSPORT_IMPL_PNET_UPGRADER_DECORATOR_HPP
