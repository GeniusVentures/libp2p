/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LIBP2P_CONNECTION_MANAGER_IMPL_HPP
#define LIBP2P_CONNECTION_MANAGER_IMPL_HPP

#include <unordered_set>
#include <chrono>

#include <libp2p/event/bus.hpp>
#include <libp2p/network/connection_manager.hpp>
#include <libp2p/network/transport_manager.hpp>
#include <libp2p/peer/peer_id.hpp>

namespace libp2p::network {

  class ConnectionManagerImpl : public ConnectionManager {
   public:
    /// Configuration for connection threshold management
    struct Config {
      /// High watermark - triggers trimming when exceeded (like go-libp2p)
      size_t high_water;
      /// Low watermark - target after trimming (like go-libp2p)  
      size_t low_water;
      /// Grace period for new connections (go-libp2p style)
      std::chrono::seconds grace_period;
      /// Silence period - minimum time between trims (go-libp2p style)
      std::chrono::seconds silence_period;
      /// Enable automatic purging when threshold is exceeded
      bool auto_purge_enabled;
      
      /// Default configuration following go-libp2p patterns
      Config() : high_water(1000),
                 low_water(800), 
                 grace_period(10),          // 10 seconds grace period
                 silence_period(10),        // 10 seconds between trims
                 auto_purge_enabled(true) {}
    };

    explicit ConnectionManagerImpl(std::shared_ptr<libp2p::event::Bus> bus, 
                                  Config config = Config{});

    std::vector<ConnectionSPtr> getConnections() const override;

    std::vector<ConnectionSPtr> getConnectionsToPeer(
        const peer::PeerId &p) const override;

    ConnectionSPtr getBestConnectionForPeer(
        const peer::PeerId &p) const override;

    void addConnectionToPeer(const peer::PeerId &p, ConnectionSPtr c) override;

    void collectGarbage() override;

    void closeConnectionsToPeer(const peer::PeerId &p) override;

    void onConnectionClosed(
        const peer::PeerId &peer_id,
        const std::shared_ptr<connection::CapableConnection> &conn) override;

    void removeRelayedConnections(const peer::PeerId& peer_id) override;

    void purgeIdleConnections() override;

    // go-libp2p style peer management methods
    
    /// Tag a peer with a named tag and value (for prioritization)
    void tagPeer(const peer::PeerId& peer_id, const std::string& tag, int value) override;
    
    /// Remove a tag from a peer
    void untagPeer(const peer::PeerId& peer_id, const std::string& tag) override;
    
    /// Protect a peer from connection trimming
    void protectPeer(const peer::PeerId& peer_id, const std::string& tag) override;
    
    /// Remove protection from a peer
    bool unprotectPeer(const peer::PeerId& peer_id, const std::string& tag) override;
    
    /// Force trim connections to low watermark (for testing/manual cleanup)
    void forceTrim() override;

    /// Trigger periodic idle connection purging (safe to call from external timers)
    /// Returns true if purging was performed, false if skipped
    bool triggerPeriodicPurge();

    /// Get connection statistics for monitoring/debugging
    struct ConnectionStats {
      size_t total_connections = 0;
      size_t active_connections = 0;
      size_t idle_connections = 0;
      size_t total_peers = 0;
      size_t max_connections_per_peer = 0;
    };
    ConnectionStats getConnectionStats() const;

    /// Log current connection statistics for debugging
    void logConnectionStats() const;

   private:
    /// Connection metadata for value-based trimming (go-libp2p style)
    struct ConnectionInfo {
      std::chrono::steady_clock::time_point connected_at;
      std::unordered_map<std::string, int> tags;
      bool is_protected = false;
      
      ConnectionInfo() : connected_at(std::chrono::steady_clock::now()) {}
    };

    std::unordered_map<peer::PeerId, std::unordered_set<ConnectionSPtr>>
        connections_;

    /// Connection metadata for grace period and value calculations
    std::unordered_map<peer::PeerId, ConnectionInfo> connection_info_;

    std::shared_ptr<libp2p::event::Bus> bus_;

    /// Reentrancy resolver between closeConnectionsToPeer and
    /// onConnectionClosed
    boost::optional<peer::PeerId> closing_connections_to_peer_;

    /// Configuration for connection management
    Config config_;

    /// Timestamp of last trim operation (go-libp2p silence period)
    std::chrono::steady_clock::time_point last_trim_time_;

    /// Check if connection count exceeds high watermark and trigger trim
    void checkConnectionThreshold();

    /// Check if connection is within grace period
    bool isInGracePeriod(const peer::PeerId& peer_id) const;
    
    /// Calculate connection value for trimming decisions (go-libp2p style)
    int calculateConnectionValue(const peer::PeerId& peer_id) const;
    
    /// Get stream count for a peer's connections
    size_t getStreamCount(const peer::PeerId& peer_id) const;

    /// Get total connection count across all peers
    size_t getTotalConnectionCount() const;
  };

}  // namespace libp2p::network

#endif  // LIBP2P_CONNECTION_MANAGER_IMPL_HPP
