/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <functional>
#include <iostream>

#include <libp2p/connection/stream.hpp>
#include <libp2p/log/logger.hpp>
#include <libp2p/network/impl/dialer_impl.hpp>
#include <iostream>

namespace libp2p::network {

  void DialerImpl::dial(const peer::PeerInfo &p, DialResultFunc cb,
                        std::chrono::milliseconds timeout, multi::Multiaddress bindaddress) {
      if (p.id.toBase58().size() == 0)
      {
          scheduler_->schedule(
              [cb{ std::move(cb) }] { cb(std::errc::destination_address_required); });
          SL_ERROR(log_, "Dialing contains no peer ID to dial");
          return;
      }
    SL_TRACE(log_, "Dialing to {} from {}", p.id.toBase58(), bindaddress.getStringAddress());
    if (auto c = cmgr_->getBestConnectionForPeer(p.id); c != nullptr) {
      // we have connection to this peer

      SL_TRACE(log_, "Reusing connection to peer {}",
               p.id.toBase58().substr(46));
      scheduler_->schedule(
          [cb{ std::move(cb) }, c{ std::move(c) }, bindaddress{ std::move(bindaddress) }]() mutable { cb(std::move(c)); });
      return;
    }

    if (auto ctx = dialing_peers_.find(p.id); dialing_peers_.end() != ctx) {
      SL_TRACE(log_, "Dialing to {} is already in progress",
               p.id.toBase58().substr(46));
      // populate known addresses for in-progress dial if any new appear
      for (const auto &addr : p.addresses) {
        if (0 == ctx->second.tried_addresses.count(addr)) {
          ctx->second.addresses.insert(addr);
        }
      }
      ctx->second.callbacks.emplace_back(std::move(cb));
      return;
    }

    // we don't have a connection to this peer.
    // did user supply its addresses in {@param p}?
    if (p.addresses.empty()) {
      // we don't have addresses of peer p
      scheduler_->schedule(
          [cb{std::move(cb)}] { cb(std::errc::destination_address_required); });
      return;
    }

    DialCtx new_ctx{/* .addresses =*/ {p.addresses.begin(), p.addresses.end()},
                    /*.timeout =*/ timeout,
                    /*.bindaddress= */ bindaddress};
    new_ctx.callbacks.emplace_back(std::move(cb));
    bool scheduled = dialing_peers_.emplace(p.id, std::move(new_ctx)).second;
    BOOST_ASSERT(scheduled);
    rotate(p.id);
  }

  void DialerImpl::rotate(const peer::PeerId &peer_id) {
    auto ctx_found = dialing_peers_.find(peer_id);
    if (dialing_peers_.end() == ctx_found) {
      SL_ERROR(log_, "State inconsistency - cannot dial {}",
               peer_id.toBase58());
      return;
    }
    auto &&ctx = ctx_found->second;

    if (ctx.addresses.empty() && !ctx.dialled) {
      completeDial(peer_id, std::errc::address_family_not_supported);
      return;
    }
    if (ctx.addresses.empty() && ctx.result.has_value()) {
      completeDial(peer_id, ctx.result.value());
      return;
    }
    if (ctx.addresses.empty()) {
      // this would never happen. Previous if-statement should work instead'
      completeDial(peer_id, std::errc::host_unreachable);
      return;
    }

    auto dial_handler =
        [wp{weak_from_this()}, peer_id](
            outcome::result<std::shared_ptr<connection::CapableConnection>>
                result) {
          if (auto self = wp.lock()) {
            auto ctx_found = self->dialing_peers_.find(peer_id);
            if (self->dialing_peers_.end() == ctx_found) {
              SL_ERROR(
                  self->log_,
                  "State inconsistency - uninteresting dial result for peer {}",
                  peer_id.toBase58());
              if (result.has_value() && !result.value()->isClosed()) {
                auto close_res = result.value()->close();
                BOOST_ASSERT(close_res);
              }
            return;
          }

            if (result.has_value()) {
              self->listener_->onConnection(result);
              if (result.value()->remoteMultiaddr().value().hasProtocol(multi::Protocol::Code::P2P_CIRCUIT))
              {
                  self->upgradeDialRelay(peer_id, result);
                  return;
              }
              self->completeDial(peer_id, result);
            return;
          }

            // store an error otherwise and reschedule one more rotate
            ctx_found->second.result = std::move(result);
            self->scheduler_->schedule([wp, peer_id] {
              if (auto self = wp.lock()) {
                self->rotate(peer_id);
              }
            });
            return;
          }
          // closing the connection when dialer and connection requester
          // callback no more exist
          if (result.has_value() && !result.value()->isClosed()) {
            auto close_res = result.value()->close();
            BOOST_ASSERT(close_res);
          }
        };

    auto first_addr = ctx.addresses.begin();
    const auto addr = *first_addr;
    ctx.tried_addresses.insert(addr);
    ctx.addresses.erase(first_addr);
    if (auto tr = tmgr_->findBest(addr); nullptr != tr) {
      ctx.dialled = true;
      SL_TRACE(log_, "Dial to {} via {}", peer_id.toBase58().substr(46),
               addr.getStringAddress());
      tr->dial(peer_id, addr, dial_handler, ctx.timeout, ctx.bindaddress);
    } else {
      scheduler_->schedule([wp{weak_from_this()}, peer_id] {
        if (auto self = wp.lock()) {
          self->rotate(peer_id);
        }
      });
      }
    }

  void DialerImpl::completeDial(const peer::PeerId &peer_id,
                                const DialResult &result) {
    if (auto ctx_found = dialing_peers_.find(peer_id);
        dialing_peers_.end() != ctx_found) {
      auto &&ctx = ctx_found->second;
      for (auto i = 0u; i < ctx.callbacks.size(); ++i) {
        scheduler_->schedule(
            [result, cb{std::move(ctx.callbacks[i])}] { cb(result); });
      }
      dialing_peers_.erase(ctx_found);
    }
  }


  void DialerImpl::upgradeDialRelay(const peer::PeerId& peer_id, const DialResult& result)
  {
      auto stream = result.value()->newStream();
      if (!result)
      {
          completeDial(peer_id, result);
          return;
      }
      //auto relayupgproc = std::make_shared<libp2p::protocol::RelayUpgraderMessageProcessor>();
      //Create a relay upgrader
      auto relayupg = std::make_shared<libp2p::protocol::RelayUpgrader>();
      //Negotiate protocol
      multiselect_->simpleStreamNegotiate(stream.value(), "/libp2p/circuit/relay/0.2.0/hop",
          [self{ shared_from_this() }, peer_id, result, relayupg](outcome::result<std::shared_ptr<connection::Stream>> stream) {
              //Upgrade the connection
              std::vector<multi::Multiaddress> addresses;
              addresses.push_back(stream.value()->remoteMultiaddr().value());
              relayupg->start(stream, peer::PeerInfo{ peer_id, addresses }, [self, peer_id, result, relayupg](const bool& success) {
                  //Resume what we were doing
                  if (success)
                  {
                      self->completeDial(peer_id, result);
                  }
                  else
                  {
                      self->completeDial(peer_id, std::errc::address_family_not_supported);
                  }
                  });
              
          });
      
  }

  void DialerImpl::newStream(const peer::PeerInfo &p,
                             const peer::Protocol &protocol,
                             StreamResultFunc cb,
                             std::chrono::milliseconds timeout,
                             multi::Multiaddress bindaddress) {
    SL_TRACE(log_, "New stream to {} for {} (peer info)",
             p.id.toBase58().substr(46), protocol);
    dial(
        p,
        [self{shared_from_this()}, cb{std::move(cb)}, protocol](
            outcome::result<std::shared_ptr<connection::CapableConnection>>
                rconn) mutable {
          if (!rconn) {
            return cb(rconn.error());
          }
          auto &&conn = rconn.value();

          auto result = conn->newStream();
          if (!result) {
            self->scheduler_->schedule(
                [cb{std::move(cb)}, result] { cb(result); });
            return;
                }
          self->multiselect_->simpleStreamNegotiate(result.value(), protocol,
                                                    std::move(cb));
        },
        timeout, bindaddress);
  }

  void DialerImpl::newStream(const peer::PeerId &peer_id,
                             const peer::Protocol &protocol,
                             StreamResultFunc cb, multi::Multiaddress bindaddress) {
    SL_TRACE(log_, "New stream to {} for {} (peer id)",
             peer_id.toBase58().substr(46), protocol);
    auto conn = cmgr_->getBestConnectionForPeer(peer_id);
    if (!conn) {
      scheduler_->schedule(
          [cb{std::move(cb)}] { cb(std::errc::not_connected); });
      return;
    }

    auto result = conn->newStream();
    if (!result) {
      scheduler_->schedule([cb{std::move(cb)}, result] { cb(result); });
      return;
    }

    multiselect_->simpleStreamNegotiate(result.value(), protocol,
                                        std::move(cb));
  }

  DialerImpl::DialerImpl(
      std::shared_ptr<protocol_muxer::ProtocolMuxer> multiselect,
      std::shared_ptr<TransportManager> tmgr,
      std::shared_ptr<ConnectionManager> cmgr,
      std::shared_ptr<ListenerManager> listener,
      std::shared_ptr<basic::Scheduler> scheduler)
      : multiselect_(std::move(multiselect)),
        tmgr_(std::move(tmgr)),
        cmgr_(std::move(cmgr)),
        listener_(std::move(listener)),
        scheduler_(std::move(scheduler)),
        log_(log::createLogger("DialerImpl", "network")) {
    BOOST_ASSERT(multiselect_ != nullptr);
    BOOST_ASSERT(tmgr_ != nullptr);
    BOOST_ASSERT(cmgr_ != nullptr);
    BOOST_ASSERT(listener_ != nullptr);
    BOOST_ASSERT(scheduler_ != nullptr);
    BOOST_ASSERT(log_ != nullptr);
  }

}  // namespace libp2p::network
