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
                        std::chrono::milliseconds timeout, multi::Multiaddress bindaddress, bool holepunch, bool holepunchserver) {
      if (p.id.toBase58().size() == 0)
      {
          scheduler_->schedule(
              [cb{ std::move(cb) }] { cb(std::errc::destination_address_required); });
          SL_ERROR(log_, "Dialing contains no peer ID to dial");
          return;
      }
    SL_TRACE(log_, "Dialing to {} from {} they have {} addresses", p.id.toBase58(), bindaddress.getStringAddress(), p.addresses.size());
    if (!holepunch)
    {
        if (auto c = cmgr_->getBestConnectionForPeer(p.id); c != nullptr) {
            // we have connection to this peer

            SL_TRACE(log_, "Reusing connection to peer {}",
                p.id.toBase58());
            scheduler_->schedule(
                [cb{ std::move(cb) }, c{ std::move(c) }, bindaddress{ std::move(bindaddress) }]() mutable { cb(std::move(c)); });
            return;
        }

        if (auto ctx = dialing_peers_.find(p.id); dialing_peers_.end() != ctx) {
            SL_TRACE(log_, "Dialing to {} is already in progress",
                p.id.toBase58());
            // populate known addresses for in-progress dial if any new appear
            for (const auto& addr : p.addresses) {
                if (0 == ctx->second.tried_addresses.count(addr)) {
                    ctx->second.addresses.insert(addr);
                }
            }
            ctx->second.callbacks.emplace_back(std::move(cb));
            return;
        }
    }
    

    // we don't have a connection to this peer.
    // did user supply its addresses in {@param p}?
    if (p.addresses.empty()) {
      // we don't have addresses of peer p
      scheduler_->schedule(
          [cb{std::move(cb)}] { cb(std::errc::destination_address_required); });
      return;
    }
    std::set<multi::Multiaddress> limitedAddresses;

    auto it = p.addresses.begin();
    auto end = p.addresses.end();

    for (size_t i = 0; i < MAX_ADDRESSES && it != end; ++i, ++it) {
        limitedAddresses.insert(*it);
    }

    DialCtx new_ctx{/* .addresses =*/ limitedAddresses,
                    /*.timeout =*/ timeout,
                    /*.bindaddress= */ bindaddress,
                    /* holepunch= */ holepunch,
                    /* holepunchserver=*/ holepunchserver};
    new_ctx.callbacks.emplace_back(std::move(cb));

    if (!holepunch)
    {
        bool scheduled = dialing_peers_.emplace(p.id, std::move(new_ctx)).second;
        BOOST_ASSERT(scheduled);
        rotate(p.id);
    }
    else {
        auto& holepunch_vec = dialing_holepunches_[p.id];
        holepunch_vec.emplace_back(std::move(new_ctx));
        rotateHolepunch(p.id);
    }
    
  }

  void DialerImpl::rotate(const peer::PeerId& peer_id) {
      auto ctx_found = dialing_peers_.find(peer_id);
      if (dialing_peers_.end() == ctx_found) {
          SL_ERROR(log_, "State inconsistency - cannot dial {}", peer_id.toBase58());
          return;
      }
      SL_TRACE(log_, "Going to try to dial {}", peer_id.toBase58());
      auto&& ctx = ctx_found->second;

      if (ctx.addresses.empty() && !ctx.dialled) {
          completeDial(peer_id, std::errc::address_family_not_supported);
          return;
      }
      if (ctx.addresses.empty() && ctx.result.has_value()) {
          completeDial(peer_id, ctx.result.value());
          return;
      }
      if (ctx.addresses.empty()) {
          completeDial(peer_id, std::errc::host_unreachable);
          return;
      }

      auto dial_handler = [wp{ weak_from_this() }, peer_id](outcome::result<std::shared_ptr<connection::CapableConnection>> result) {
          if (auto self = wp.lock()) {
              auto ctx_found = self->dialing_peers_.find(peer_id);
              if (self->dialing_peers_.end() == ctx_found) {
                  SL_ERROR(self->log_, "State inconsistency - uninteresting dial result for peer {}", peer_id.toBase58());
                  if (result.has_value() && !result.value()->isClosed()) {
                      SL_ERROR(self->log_, "How often does this happen?");
                      auto close_res = result.value()->close();
                      BOOST_ASSERT(close_res);
                  }
                  return;
              }

              auto&& ctx = ctx_found->second;
              auto last_tried_addr = *ctx.tried_addresses.rbegin();  // Get the last tried address

              if (result.has_value()) {
                  self->listener_->onConnection(result);
                  self->log_->info("Checking whether address {} has relay", last_tried_addr.getStringAddress());

                  // Check if the last tried address had a circuit relay
                  if (last_tried_addr.hasCircuitRelay()) {
                      self->upgradeDialRelay(peer_id, result.value());
                      return;
                  }
                  self->completeDial(peer_id, result);
                  return;
              }
              self->log_->trace("Error on connect to {} : {}", last_tried_addr.getStringAddress(),result.error().message());
              // store an error otherwise and reschedule one more rotate
              ctx.result = std::move(result);
              self->scheduler_->schedule([wp, peer_id] {
                  if (auto self = wp.lock()) {
                      self->rotate(peer_id);
                  }
                  });
              return;
          }
          // closing the connection when dialer and connection requester callback no more exist
          if (result.has_value() && !result.value()->isClosed()) {
              auto close_res = result.value()->close();
              BOOST_ASSERT(close_res);
          }
          };

      auto first_addr = ctx.addresses.begin();
      const auto addr = *first_addr;
      ctx.tried_addresses.insert(addr);
      ctx.addresses.erase(first_addr);
      //auto localcheck = addr.getFirstValueForProtocol(libp2p::multi::Protocol::Code::IP4);
      if (addr.hasCircuitRelay())
      {
          auto addr_peer_id = addr.getPeerId();
          if (addr_peer_id)
          {
              auto peer_id_actual = peer::PeerId::fromBase58(addr_peer_id.value());
              if (auto tr = tmgr_->findBest(addr); nullptr != tr && peer_id_actual) {

                  ctx.dialled = true;
                  SL_TRACE(log_, "Dial to {} via {}", peer_id.toBase58(), addr.getStringAddress());
                  if (auto c = cmgr_->getBestConnectionForPeer(peer_id_actual.value()); c != nullptr) {
                      SL_TRACE(log_, "We already have a connection to relay node {} but have not established a connection to target node {}", peer_id_actual.value().toBase58(), peer_id.toBase58());
                      upgradeDialRelay(peer_id, c);
                  }
                  else {
                      tr->dial(peer_id_actual.value(), addr, dial_handler, ctx.timeout, ctx.bindaddress, ctx.holepunch, ctx.holepunchserver);
                  }
                  
              }
              else {
                  scheduler_->schedule([wp{ weak_from_this() }, peer_id] {
                      if (auto self = wp.lock()) {
                          self->rotate(peer_id);
                      }
                      });
              }
          }
          else {
              scheduler_->schedule([wp{ weak_from_this() }, peer_id] {
                  if (auto self = wp.lock()) {
                      self->rotate(peer_id);
                  }
                  });
          }
      }
      else {
          if (auto tr = tmgr_->findBest(addr); nullptr != tr) {

              ctx.dialled = true;
              SL_TRACE(log_, "Dial to non-relay {} via {}", peer_id.toBase58(), addr.getStringAddress());

              tr->dial(peer_id, addr, dial_handler, ctx.timeout, ctx.bindaddress);
          }
          else {
              scheduler_->schedule([wp{ weak_from_this() }, peer_id] {
                  if (auto self = wp.lock()) {
                      self->rotate(peer_id);
                  }
                  });
          }
      }

  }

  void DialerImpl::rotateHolepunch(const peer::PeerId& peer_id) {
      auto ctx_found = dialing_holepunches_.find(peer_id);
      if (dialing_holepunches_.end() == ctx_found) {
          SL_ERROR(log_, "State inconsistency - cannot dial {}", peer_id.toBase58());
          return;
      }
      SL_TRACE(log_, "Holepunch Going to try to dial {}", peer_id.toBase58());
      auto&& ctx = ctx_found->second;

      //if (ctx.addresses.empty() && !ctx.dialled) {
      //    completeDial(peer_id, std::errc::address_family_not_supported);
      //    return;
      //}
      //if (ctx.addresses.empty() && ctx.result.has_value()) {
      //    completeDial(peer_id, ctx.result.value());
      //    return;
      //}
      //if (ctx.addresses.empty()) {
      //    completeDial(peer_id, std::errc::host_unreachable);
      //    return;
      //}

      auto dial_handler = [wp{ weak_from_this() }, peer_id](outcome::result<std::shared_ptr<connection::CapableConnection>> result) {
          if (auto self = wp.lock()) {

              auto ctx_found = self->dialing_holepunches_.find(peer_id);
              if (self->dialing_holepunches_.end() == ctx_found) {
                  SL_ERROR(self->log_, "Holepunch State inconsistency - uninteresting dial result for peer {}", peer_id.toBase58());
                  if (result.has_value() && !result.value()->isClosed()) {
                      auto close_res = result.value()->close();
                      BOOST_ASSERT(close_res);
                  }
                  return;
              }

              //auto&& ctx = ctx_found->second;

              if (result.has_value()) {
                  self->listener_->onConnection(result);
                  self->completeDialHolepunch(peer_id, result);
                  return;
              }
              self->log_->error("Error on holepunch connect to {} : {}", peer_id.toBase58(), result.error().message());

              //TODO: Need to track all dials in a holepunch to run a completeDialHolepunch with an error or something if none complete.
              return;
          }
          // closing the connection when dialer and connection requester callback no more exist
          if (result.has_value() && !result.value()->isClosed()) {
              auto close_res = result.value()->close();
              BOOST_ASSERT(close_res);
          }
          };
      for (auto& indctx : ctx)
      {
          if (!indctx.dialled)
          {
              for (auto it = indctx.addresses.begin(); it != indctx.addresses.end(); ) {
                  auto addr = *it;
                  indctx.tried_addresses.insert(addr);
                  it = indctx.addresses.erase(it);
                  if (auto tr = tmgr_->findBest(addr); nullptr != tr) {

                      indctx.dialled = true;
                      SL_TRACE(log_, "Holepunch Dial to non-relay {} via {}", peer_id.toBase58(), addr.getStringAddress());
                      tr->dial(peer_id, addr, dial_handler, indctx.timeout, indctx.bindaddress);

                  }
              }
          }
      }

  }

  void DialerImpl::completeDial(const peer::PeerId &peer_id,
                                const DialResult &result) {
      log_->info("Completed Dial to {}", peer_id.toBase58());
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


  void DialerImpl::completeDialHolepunch(const peer::PeerId& peer_id,
      const DialResult& result) {
      log_->info("Completed Dial to {}", peer_id.toBase58());
      if (auto ctx_found = dialing_holepunches_.find(peer_id);
          dialing_holepunches_.end() != ctx_found) {
          auto&& ctx = ctx_found->second;
          for (auto& indctx : ctx)
          {
              for (auto i = 0u; i < indctx.callbacks.size(); ++i) {
                  scheduler_->schedule(
                      [result, cb{ std::move(indctx.callbacks[i]) }] { cb(result); });
              }
          }
          dialing_holepunches_.erase(ctx_found);
      }
  }


  void DialerImpl::upgradeDialRelay(const peer::PeerId& peer_id, std::shared_ptr<connection::CapableConnection> result) {
      log_->info("Upgrading connection to relay {} ", result->remoteMultiaddr().value().getStringAddress());

      auto stream = result->newStream();
      if (!result) {
          log_->error("Could not create stream to upgrade relay");
          completeDial(peer_id, result);
          return;
      }

      // Create a relay upgrader
      auto relayupg = std::make_shared<libp2p::protocol::RelayUpgrader>();

      // Negotiate protocol
      multiselect_->simpleStreamNegotiate(
          stream.value(),
          relayupg->getProtocolId(),
          [wp{ weak_from_this() }, peer_id, result, relayupg](outcome::result<std::shared_ptr<connection::Stream>> stream_result) mutable {
              if (auto self = wp.lock()) {
                  if (!stream_result) {
                      self->log_->error("Stream negotiation failed for peer {}", peer_id.toBase58());
                      self->rotate(peer_id);
                      return;
                  }

                  //Upgrade the connection
                  std::vector<multi::Multiaddress> addresses;
                  addresses.push_back(stream_result.value()->remoteMultiaddr().value());
                  auto tr = self->tmgr_->findBest(stream_result.value()->remoteMultiaddr().value());
                  relayupg->start(
                      stream_result.value(),
                      peer::PeerInfo{ peer_id, addresses },
                      [self, peer_id, stream_result, relayupg, tr](const bool& success) mutable {
                          if (!self) return;

                          self->log_->info("Finished upgrading connection to relay {} ", stream_result.value()->remoteMultiaddr().value().getStringAddress());

                          //Resume what we were doing
                          if (success) {
                              self->log_->info("Encrypt Connection to other node {} ", stream_result.value()->remoteMultiaddr().value().getStringAddress());
                              //Upgrade encryption
                              //auto stream = result.value()->newStream();
                              tr->upgradeRelaySecure(peer_id, stream_result.value(), [self, peer_id](outcome::result<std::shared_ptr<connection::CapableConnection>> upgraderesult) {
                                  if (upgraderesult)
                                  {
                                      self->log_->info("Encryption Completed now we can complete the dial {} ", upgraderesult.value()->remoteMultiaddr().value().getStringAddress());
                                      self->listener_->onConnectionRelay(peer_id, upgraderesult);
                                      self->completeDial(peer_id, upgraderesult);
                                  }
                                  else {
                                      self->log_->error("Encryption relay upgrade failed to {} because {}", peer_id.toBase58(), upgraderesult.error().message());
                                      self->rotate(peer_id);
                                  }

                                  });
                          }
                          else {
                              self->rotate(peer_id);
                          }
                      });
              }
              else {
                  if (stream_result.has_value() && !stream_result.value()->isClosed()) {
                      stream_result.value()->reset();
                      self->rotate(peer_id);
                      //BOOST_ASSERT(close_res);
                  }
              }
          });
  }

  void DialerImpl::newStream(const peer::PeerInfo &p,
                             const peer::Protocol &protocol,
                             StreamResultFunc cb,
                             std::chrono::milliseconds timeout,
                             multi::Multiaddress bindaddress) {
    SL_TRACE(log_, "New stream to {} for {} (peer info)",
             p.id.toBase58(), protocol);
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
             peer_id.toBase58(), protocol);
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
