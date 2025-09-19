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
      // Check if peer already has pre-connection metadata (protection/tagging)
      auto info_it = connection_info_.find(p);
      if (info_it == connection_info_.end()) {
        // No pre-existing metadata, create new entry with connection timestamp
        connection_info_[p] = ConnectionInfo{};
      } else {
        // Pre-existing metadata exists, update connection timestamp but preserve tags/protection
        info_it->second.connected_at = std::chrono::steady_clock::now();
        log()->debug("Applied pre-connection metadata to newly connected peer {}", p.toBase58());
      }
    } else {
      connections_[p].insert(c);
    }
    bus_->getChannel<event::network::OnNewConnectionChannel>().publish(c);
    
    // Check if we need to trim connections due to high watermark
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
        last_trim_time_(std::chrono::steady_clock::now()) {}

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
    
    // Clean up connection metadata
    connection_info_.erase(p);

    if (connections.empty()) {
      log()->error("inconsistency: iterator and no peers");
      return;
    }

    closing_connections_to_peer_ = p;

    size_t closed_count = 0;
    size_t already_closed = 0;
    
    for (const auto &conn : connections) {
      if (!conn->isClosed()) {
        auto close_result = conn->close();
        if (close_result) {
          closed_count++;
          log()->trace("Successfully closed connection to peer {}", p.toBase58());
        } else {
          log()->error("Failed to close connection to peer {}: {}", p.toBase58(), close_result.error().message());
        }
      } else {
        already_closed++;
      }
    }
    
    log()->debug("Closed {} connections to peer {}, {} were already closed", 
                 closed_count, p.toBase58(), already_closed);

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
      // Clean up connection metadata when last connection to peer is removed
      connection_info_.erase(peer_id);
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
      log()->debug("Legacy purgeIdleConnections called - using go-libp2p style trim instead");
      
      // Just call forceTrim which implements the proper go-libp2p approach
      forceTrim();
  }

  void ConnectionManagerImpl::checkConnectionThreshold() {
    if (!config_.auto_purge_enabled) {
      return;
    }
    
    size_t total_connections = getTotalConnectionCount();
    
    // Check high watermark (go-libp2p style)
    if (total_connections <= config_.high_water) {
      log()->trace("Connection count {} within high watermark {} ({:.1f}%)",
                   total_connections, config_.high_water,
                   (100.0 * total_connections) / config_.high_water);
      return;
    }
    
    // Check silence period (go-libp2p style)
    auto now = std::chrono::steady_clock::now();
    auto time_since_last_trim = now - last_trim_time_;
    if (time_since_last_trim < config_.silence_period) {
      log()->debug("Skipping trim due to silence period: {}s < {}s",
                   std::chrono::duration_cast<std::chrono::seconds>(time_since_last_trim).count(),
                   config_.silence_period.count());
      return;
    }
    
    log()->warn("Connection count {} exceeds high watermark {}, triggering trim to low watermark {}",
                total_connections, config_.high_water, config_.low_water);
    
    // Perform go-libp2p style trim
    forceTrim();
    last_trim_time_ = now;
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
    // Check if we exceed high watermark first
    size_t total_connections = getTotalConnectionCount();
    if (total_connections <= config_.high_water) {
      log()->trace("Periodic trim skipped: {} <= high watermark {}",
                   total_connections, config_.high_water);
      return false;
    }
    
    // Check silence period
    auto now = std::chrono::steady_clock::now();
    auto time_since_last_trim = now - last_trim_time_;
    
    if (time_since_last_trim < config_.silence_period) {
      log()->trace("Skipping periodic trim due to silence period: {}s < {}s",
                   std::chrono::duration_cast<std::chrono::seconds>(time_since_last_trim).count(),
                   config_.silence_period.count());
      return false;
    }
    
    log()->debug("Triggering periodic trim: {} connections > high watermark {}",
                 total_connections, config_.high_water);
    
    forceTrim();
    last_trim_time_ = now;
    
    size_t connections_after = getTotalConnectionCount();
    log()->info("Periodic trim completed: {} -> {} connections",
                total_connections, connections_after);
    
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
    
    // Log watermark status (go-libp2p style)
    if (config_.auto_purge_enabled) {
      log()->info("Watermark status: {}/{} ({}% full, high={}, low={})", 
                  stats.active_connections, config_.high_water,
                  (stats.active_connections * 100) / config_.high_water,
                  config_.high_water, config_.low_water);
    }
  }

  // go-libp2p style connection management implementations
  
  void ConnectionManagerImpl::tagPeer(const peer::PeerId& peer_id, const std::string& tag, int value) {
    auto it = connection_info_.find(peer_id);
    if (it != connection_info_.end()) {
      it->second.tags[tag] = value;
      log()->trace("Tagged peer {} with {}={}", peer_id.toBase58(), tag, value);
    } else {
      // Pre-connection tagging: create entry for future connection
      connection_info_[peer_id].tags[tag] = value;
      log()->trace("Pre-tagged peer {} with {}={} (not yet connected)", peer_id.toBase58(), tag, value);
    }
  }
  
  void ConnectionManagerImpl::untagPeer(const peer::PeerId& peer_id, const std::string& tag) {
    auto it = connection_info_.find(peer_id);
    if (it != connection_info_.end()) {
      it->second.tags.erase(tag);
      log()->trace("Removed tag {} from peer {}", tag, peer_id.toBase58());
    }
  }
  
  void ConnectionManagerImpl::protectPeer(const peer::PeerId& peer_id, const std::string& tag) {
    auto it = connection_info_.find(peer_id);
    if (it != connection_info_.end()) {
      it->second.is_protected = true;
      // Also add a protection tag for tracking
      it->second.tags["protection:" + tag] = 1000;  // High value
      log()->debug("Protected peer {} with tag {}", peer_id.toBase58(), tag);
    } else {
      // Pre-connection protection: create entry for future connection
      auto& info = connection_info_[peer_id];
      info.is_protected = true;
      info.tags["protection:" + tag] = 1000;
      log()->debug("Pre-protected peer {} with tag {} (not yet connected)", peer_id.toBase58(), tag);
    }
  }
  
  bool ConnectionManagerImpl::unprotectPeer(const peer::PeerId& peer_id, const std::string& tag) {
    auto it = connection_info_.find(peer_id);
    if (it != connection_info_.end() && it->second.is_protected) {
      it->second.is_protected = false;
      it->second.tags.erase("protection:" + tag);
      log()->debug("Unprotected peer {} with tag {}", peer_id.toBase58(), tag);
      return true;
    }
    return false;
  }

  void ConnectionManagerImpl::forceTrim() {
    log()->info("Force trimming connections to low watermark {}", config_.low_water);
    
    size_t total_connections = getTotalConnectionCount();
    if (total_connections <= config_.low_water) {
      log()->debug("No trimming needed: {} <= {}", total_connections, config_.low_water);
      return;
    }
    
    // Build candidate list with values (go-libp2p style)
    struct TrimCandidate {
      peer::PeerId peer_id;
      int value;
      bool in_grace_period;
      bool is_protected;
    };
    
    std::vector<TrimCandidate> candidates;
    for (const auto& [peer_id, connections] : connections_) {
      // Skip peers with no live connections
      bool has_live_connection = false;
      for (const auto& conn : connections) {
        if (!conn->isClosed()) {
          has_live_connection = true;
          break;
        }
      }
      if (!has_live_connection) continue;
      
      candidates.push_back({
        peer_id,
        calculateConnectionValue(peer_id),
        isInGracePeriod(peer_id),
        connection_info_.count(peer_id) && connection_info_.at(peer_id).is_protected
      });
    }
    
    // Sort by: grace period (protected), then protection status, then value (ascending)
    std::sort(candidates.begin(), candidates.end(), 
              [](const TrimCandidate& a, const TrimCandidate& b) {
                if (a.in_grace_period != b.in_grace_period) {
                  return b.in_grace_period;  // Grace period connections last
                }
                if (a.is_protected != b.is_protected) {
                  return b.is_protected;     // Protected connections last
                }
                return a.value < b.value;    // Lower value first
              });
    
    // Trim from lowest value until we reach low watermark
    size_t to_trim = total_connections - config_.low_water;
    size_t trimmed = 0;
    
    for (const auto& candidate : candidates) {
      if (trimmed >= to_trim) break;
      
      log()->debug("Trimming peer {} (value={}, grace={}, protected={})",
                   candidate.peer_id.toBase58(), candidate.value,
                   candidate.in_grace_period, candidate.is_protected);
      
      closeConnectionsToPeer(candidate.peer_id);
      trimmed++;
    }
    
    log()->info("Force trim completed: removed {} connections", trimmed);
  }

  bool ConnectionManagerImpl::isInGracePeriod(const peer::PeerId& peer_id) const {
    auto it = connection_info_.find(peer_id);
    if (it == connection_info_.end()) {
      return false;
    }
    
    auto now = std::chrono::steady_clock::now();
    auto connection_age = now - it->second.connected_at;
    return connection_age < config_.grace_period;
  }
  
  int ConnectionManagerImpl::calculateConnectionValue(const peer::PeerId& peer_id) const {
    auto it = connection_info_.find(peer_id);
    if (it == connection_info_.end()) {
      return 0;
    }
    
    int value = 0;
    
    // Add stream count (active streams boost value)
    value += getStreamCount(peer_id) * 10;
    
    // Add tag values
    for (const auto& [tag, tag_value] : it->second.tags) {
      value += tag_value;
    }
    
    // Protection boost
    if (it->second.is_protected) {
      value += 10000;  // Very high protection value
    }
    
    return value;
  }
  
  size_t ConnectionManagerImpl::getStreamCount(const peer::PeerId& peer_id) const {
    auto it = connections_.find(peer_id);
    if (it == connections_.end()) {
      return 0;
    }
    
    size_t total_streams = 0;
    for (const auto& conn : it->second) {
      if (!conn->isClosed()) {
        auto streams = conn->getStreams();
        total_streams += streams.size();
      }
    }
    return total_streams;
  }

}  // namespace libp2p::network
