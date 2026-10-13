/**
 * Copyright Quadrivium LLC
 * All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <libp2p/basic/scheduler.hpp>
#include <libp2p/log/sublogger.hpp>

#include "topic_subscriptions.hpp"

namespace libp2p::protocol::gossip {

  /// Manages topic subscriptions from remote peers
  class RemoteSubscriptions {
   public:
    /// Ctor. Dependencies are passed by ref becaus this object is a part of
    /// GossipCore and lives only within its scope
    RemoteSubscriptions(const Config &config,
                        Connectivity &connectivity,
                        basic::Scheduler &scheduler,
                        log::SubLogger &log);

    /// This host subscribes or unsubscribes
    void onSelfSubscribed(bool subscribed, const TopicId &topic);

    /// Remote peer subscribes
    void onPeerSubscribed(const PeerContextPtr &peer, const TopicId &topic);

    /// Remote peer unsubscribes
    void onPeerUnsubscribed(const PeerContextPtr &peer,
                            const TopicId &topic,
                            bool disconnected);

    /// Peer disconnected - remove it from all topics it's subscribed to
    void onPeerDisconnected(const PeerContextPtr &peer);

    /// Returns if topic exists in the table
    bool hasTopic(const TopicId &topic) const;

    /// Remote peer adds topic into its mesh
    void onGraft(const PeerContextPtr &peer, const TopicId &topic);

    /// Remote peer removes topic from its mesh
    void onPrune(const PeerContextPtr &peer,
                 const TopicId &topic,
                 uint64_t backoff_time);

    /// Forwards message to its topics. If 'from' is not set then the message is
    /// published locally
    void onNewMessage(const boost::optional<PeerContextPtr> &from,
                      const TopicMessage::Ptr &msg,
                      const MessageId &msg_id);

    /// Periodic job needed to update meshes and shift "I have" caches
    void onHeartbeat();

        /// Get Number of Peers in topic
    size_t getPeerCount(const TopicId& topic) const;

    /// Get PeerIDs subscribed to topic
    std::vector<peer::PeerId> getAllPeers(const TopicId& topic) const;

   private:
    /// Returns table item, creates a new one if needed
    boost::optional<TopicSubscriptions &> getItem(const TopicId &topic,
                                                  bool create_if_not_exist);

    const Config &config_;
    Connectivity &connectivity_;
    basic::Scheduler &scheduler_;

    // GOSS-01: the remote subscription table is bounded by composition.
    // (1) Cap (D-03): onPeerSubscribed enforces the receiver-side cumulative
    //     per-peer cap config_.max_remote_subscriptions_per_peer with
    //     check-then-insert ordering — dedup early-return first (a duplicate
    //     never consumes headroom), then the cap check with a warn log
    //     before any table mutation, then the insert as the final admission
    //     step; entries beyond the cap are ignored with no table mutation.
    // (2) Sweep (D-04): onHeartbeat erases entries whose
    //     TopicSubscriptions::empty() is true — not self-subscribed, no
    //     fanout, no subscribed peers, no mesh peers. A capped-out
    //     flooder's rejected topics never populate the table, so they stay
    //     empty() and are collected on the next heartbeat; a live remote
    //     subscriber's state (mesh/graft/IHAVE dependencies) is never
    //     evicted because empty() is the erase gate.
    std::unordered_map<TopicId, TopicSubscriptions> table_;

    /// Protects table_ from concurrent access
    mutable std::mutex table_mutex_;

    log::SubLogger &log_;
  };

}  // namespace libp2p::protocol::gossip
