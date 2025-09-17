/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <libp2p/network/impl/connection_manager_impl.hpp>

#include <algorithm>
#include <chrono>
#include <memory>

namespace libp2p::network {

  namespace {
    auto log() {
      static auto logger = libp2p::log::createLogger("ConnectionManager");
      return logger.get();
    }
  }  // namespace

  std::vector<ConnectionManager::ConnectionSPtr>
  ConnectionManagerImpl::getConnectionsToPeer(const peer::PeerId &p) const {
    auto it = connections_.find(p);
    if (it == connections_.end()) {
      return {};
    }

    return std::vector<ConnectionManager::ConnectionSPtr>(it->second.begin(),
                                                          it->second.end());
  }

  ConnectionManager::ConnectionSPtr
  ConnectionManagerImpl::getBestConnectionForPeer(const peer::PeerId &p) const {
    // TODO(warchant): maybe make pluggable strategies
      auto it = connections_.find(p);
      if (it != connections_.end()) {
          ConnectionSPtr bestRelayConn = nullptr;

          for (const auto& conn : it->second) {
              if (!conn->isClosed()) {
                  if (!conn->isRelay()) {
                      // Return the first non-closed direct connection as these are always better
                      return conn;
                  }
                  else if (!bestRelayConn) {
                      // Keep the first non-closed relay connection in case no direct connections exist
                      bestRelayConn = conn;
                  }
              }
          }

          // If no direct connection was found, return the relay connection
          return bestRelayConn;
      }
      //No connections found
      return nullptr;
  }
  

  void ConnectionManagerImpl::addConnectionToPeer(
      const peer::PeerId &p, ConnectionManager::ConnectionSPtr c) {
    if (c == nullptr) {
      log()->error("inconsistency: not adding nullptr to active connections");
      return;
    }
    log()->trace("Adding peer connection to records {}", p.toBase58());
    auto it = connections_.find(p);
    if (it == connections_.end()) {
      connections_.insert({p, {c}});
    } else {
      connections_[p].insert(c);
    }
    bus_->getChannel<event::network::OnNewConnectionChannel>().publish(c);
    
    // Check if we need to purge idle connections due to threshold
    checkConnectionThreshold();
  }

  std::vector<ConnectionManager::ConnectionSPtr>
  ConnectionManagerImpl::getConnections() const {
    std::vector<ConnectionSPtr> out;
    out.reserve(connections_.size());

    for (auto &&entry : connections_) {
      out.insert(out.end(), entry.second.begin(), entry.second.end());
    }

    return out;
  }

  ConnectionManagerImpl::ConnectionManagerImpl(
      std::shared_ptr<libp2p::event::Bus> bus, Config config)
      : bus_(std::move(bus)), config_(std::move(config)), 
        last_purge_time_(std::chrono::steady_clock::now()) {}

  void ConnectionManagerImpl::collectGarbage() {
    for (auto it = connections_.begin(); it != connections_.end();) {
      auto &cs = it->second;
      for (auto it2 = cs.begin(); it2 != cs.end();) {
        const auto &conn = *it2;
        if (conn->isClosed()) {
          it2 = cs.erase(it2);
        } else {
          ++it2;
        }
      }

      // if peer has no connections, remove peer
      if (cs.empty()) {
        it = connections_.erase(it);
      } else {
        ++it;
      }
    }
  }

  void ConnectionManagerImpl::closeConnectionsToPeer(const peer::PeerId &p) {
    auto it = connections_.find(p);
    if (it == connections_.end()) {
      return;
    }

    auto connections = std::move(it->second);
    connections_.erase(it);

    if (connections.empty()) {
      log()->error("inconsistency: iterator and no peers");
      return;
    }

    closing_connections_to_peer_ = p;

    for (const auto &conn : connections) {
      if (!conn->isClosed()) {
        // ignore errors
        (void)conn->close();
      }
    }

    closing_connections_to_peer_.reset();

    // until all reentrancy issues are resolved, we cannot be sure whether new
    // connections not appeared during close() calls, which may call their
    // external callbacks
    if (connections_.count(p) == 0) {
      bus_->getChannel<event::network::OnPeerDisconnectedChannel>().publish(p);
    }
  }

  void ConnectionManagerImpl::onConnectionClosed(
      const peer::PeerId &peer_id,
      const std::shared_ptr<connection::CapableConnection> &conn) {
    if (closing_connections_to_peer_.has_value()
        && closing_connections_to_peer_.value() == peer_id) {
      return;
    }
    auto it = connections_.find(peer_id);
    if (it == connections_.end()) {
      log()->error("inconsistency in onConnectionClosed, peer not found");
      return;
    }

    [[maybe_unused]] auto erased = it->second.erase(conn);
    if (erased == 0) {
      log()->error("inconsistency in onConnectionClosed, connection not found");
    }

    if (it->second.empty()) {
      connections_.erase(peer_id);
      bus_->getChannel<event::network::OnPeerDisconnectedChannel>().publish(
          peer_id);
    }
  }

  void ConnectionManagerImpl::removeRelayedConnections(const peer::PeerId& p)
  {
      auto it = connections_.find(p);
      if (it == connections_.end()) {
          return;
      }

      auto connections = it->second;

      if (connections.empty()) {
          log()->error("inconsistency: iterator and no peers");
          return;
      }

      //closing_connections_to_peer_ = p;

      for (const auto& conn : connections) {
          if (!conn->isClosed() && conn->remoteMultiaddr().value().hasCircuitRelay()) {
              // ignore errors
              (void)conn->close();
          }
      }

      //closing_connections_to_peer_.reset();

  }

  void ConnectionManagerImpl::purgeIdleConnections() {
      log()->trace("Starting idle connection purge");
      
      std::vector<peer::PeerId> peers_to_close;
      
      for (const auto& [peer_id, connections] : connections_) {
          for (const auto& conn : connections) {
              if (!conn->isClosed()) {
                  // Get all active streams for this connection
                  auto streams = conn->getStreams();
                  
                  // If connection has no active streams, mark it for closure
                  if (streams.empty()) {
                      log()->debug("Found idle connection to peer {}, marking for closure", 
                                   peer_id.toBase58());
                      peers_to_close.push_back(peer_id);
                      break; // Only need to mark peer once
                  }
              }
          }
      }
      
      // Close idle connections
      for (const auto& peer_id : peers_to_close) {
          log()->info("Closing idle connection to peer {}", peer_id.toBase58());
          closeConnectionsToPeer(peer_id);
      }
      
      log()->trace("Idle connection purge completed, closed {} connections", 
                   peers_to_close.size());
  }

  void ConnectionManagerImpl::checkConnectionThreshold() {
    if (!config_.auto_purge_enabled) {
      return;
    }
    
    size_t total_connections = getTotalConnectionCount();
    if (total_connections > config_.max_connections) {
      log()->warn("Connection count {} exceeds threshold {}, triggering idle purge",
                  total_connections, config_.max_connections);
      
      // Log stats before purge
      auto stats_before = getConnectionStats();
      log()->debug("Pre-purge stats: {} peers, {} active, {} idle connections",
                   stats_before.total_peers, stats_before.active_connections, 
                   stats_before.idle_connections);
      
      purgeIdleConnections();
      
      // Log post-purge count
      size_t connections_after_purge = getTotalConnectionCount();
      log()->info("Threshold-triggered purge: {} -> {} connections (saved {})",
                  total_connections, connections_after_purge,
                  total_connections - connections_after_purge);
    } else {
      log()->trace("Connection count {} within threshold {} ({:.1f}%)",
                   total_connections, config_.max_connections,
                   (100.0 * total_connections) / config_.max_connections);
    }
  }

  size_t ConnectionManagerImpl::getTotalConnectionCount() const {
    size_t total = 0;
    for (const auto& peer_connections : connections_) {
      // Only count non-closed connections
      for (const auto& conn : peer_connections.second) {
        if (!conn->isClosed()) {
          ++total;
        }
      }
    }
    return total;
  }

  bool ConnectionManagerImpl::triggerPeriodicPurge() {
    if (!config_.periodic_purge_enabled) {
      return false;
    }
    
    auto now = std::chrono::steady_clock::now();
    auto time_since_last_purge = now - last_purge_time_;
    
    if (time_since_last_purge < config_.min_purge_interval) {
      log()->trace("Skipping periodic purge, only {}s since last purge (min {}s)",
                   std::chrono::duration_cast<std::chrono::seconds>(time_since_last_purge).count(),
                   config_.min_purge_interval.count());
      return false;
    }
    
    size_t connections_before = getTotalConnectionCount();
    log()->debug("Triggering periodic idle connection purge, {} total connections",
                 connections_before);
    
    purgeIdleConnections();
    last_purge_time_ = now;
    
    size_t connections_after = getTotalConnectionCount();
    log()->info("Periodic purge completed: {} -> {} connections",
                connections_before, connections_after);
    
    return true;
  }

  ConnectionManagerImpl::ConnectionStats ConnectionManagerImpl::getConnectionStats() const {
    ConnectionStats stats;
    stats.total_peers = connections_.size();
    
    for (const auto& peer_connections : connections_) {
      size_t peer_connection_count = 0;
      for (const auto& conn : peer_connections.second) {
        stats.total_connections++;
        peer_connection_count++;
        
        if (conn->isClosed()) {
          continue;
        }
        
        stats.active_connections++;
        
        // Check if connection is idle (no active streams)
        if (auto capable_conn = std::dynamic_pointer_cast<connection::CapableConnection>(conn)) {
          auto streams = capable_conn->getStreams();
          if (streams.empty()) {
            stats.idle_connections++;
          }
        }
      }
      
      if (peer_connection_count > stats.max_connections_per_peer) {
        stats.max_connections_per_peer = peer_connection_count;
      }
    }
    
    return stats;
  }

  void ConnectionManagerImpl::logConnectionStats() const {
    auto stats = getConnectionStats();
    log()->info("Connection Manager Stats: {} total peers, {} total connections, "
                "{} active, {} idle, max {} connections per peer",
                stats.total_peers, stats.total_connections, 
                stats.active_connections, stats.idle_connections,
                stats.max_connections_per_peer);
    
    // Log threshold status
    if (config_.auto_purge_enabled) {
      log()->info("Auto-purge threshold: {}/{} ({}% full)", 
                  stats.active_connections, config_.max_connections,
                  (stats.active_connections * 100) / config_.max_connections);
    }
  }

}  // namespace libp2p::network
