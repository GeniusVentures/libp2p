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
      /// Maximum number of total connections before triggering idle purge
      size_t max_connections = 1000;
      /// Target number of connections to maintain after purging
      size_t target_connections = 800;
      /// Enable automatic purging when threshold is exceeded
      bool auto_purge_enabled = true;
      /// Enable periodic purging (requires external scheduling)
      bool periodic_purge_enabled = false;
      /// Minimum interval between periodic purges (in seconds)
      std::chrono::seconds min_purge_interval{300}; // 5 minutes
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
    std::unordered_map<peer::PeerId, std::unordered_set<ConnectionSPtr>>
        connections_;

    std::shared_ptr<libp2p::event::Bus> bus_;

    /// Reentrancy resolver between closeConnectionsToPeer and
    /// onConnectionClosed
    boost::optional<peer::PeerId> closing_connections_to_peer_;

    /// Configuration for connection management
    Config config_;

    /// Timestamp of last idle connection purge
    std::chrono::steady_clock::time_point last_purge_time_;

    /// Check if total connections exceed threshold and trigger purge if needed
    void checkConnectionThreshold();

    /// Get total connection count across all peers
    size_t getTotalConnectionCount() const;
  };

}  // namespace libp2p::network

#endif  // LIBP2P_CONNECTION_MANAGER_IMPL_HPP
