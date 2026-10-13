/**
 * Copyright Quadrivium LLC
 * All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <chrono>
#include <functional>
#include <set>
#include <string>
#include <vector>

#include <boost/optional.hpp>

#include <libp2p/common/byteutil.hpp>
#include <libp2p/multi/multiaddress.hpp>
#include <libp2p/peer/peer_id.hpp>
#include <libp2p/protocol/common/subscription.hpp>

namespace libp2p {
  struct Host;
  namespace basic {
    class Scheduler;
  }
  namespace crypto {
    class CryptoProvider;
    namespace marshaller {
      class KeyMarshaller;
    }
  }  // namespace crypto
  namespace peer {
    struct IdentityManager;
  }
}  // namespace libp2p

namespace libp2p::protocol::gossip {
  using ByteArray = common::ByteArray;
  /// Gossip pub-sub protocol config
  struct Config {
    /// Network density factors for gossip meshes
    size_t D_min = 5;
    size_t D_max = 10;

    /// Ideal number of connected peers to support the network
    size_t ideal_connections_num = 100;

    /// Maximum number of simultaneous connections after which new
    /// incoming peers will be rejected
    size_t max_connections_num = 1000;

    /// Forward messages to all subscribers not in mesh
    /// (floodsub mode compatibility)
    bool floodsub_forward_mode = false;

    /// Forward local message to local subscribers
    bool echo_forward_mode = false;

    /// Read or write timeout per whole network operation
    std::chrono::milliseconds rw_timeout_msec{std::chrono::seconds(10)};

    /// Lifetime of a message in message cache
    std::chrono::milliseconds message_cache_lifetime_msec{
        std::chrono::minutes(2)};

    /// Topic's message seen cache lifetime
    std::chrono::milliseconds seen_cache_lifetime_msec{
        message_cache_lifetime_msec * 3 / 4};

    /// Topic's seen cache limit
    unsigned seen_cache_limit = 100;

    /// Heartbeat interval
    std::chrono::milliseconds heartbeat_interval_msec{1000};

    /// Ban interval between dial attempts to peer
    std::chrono::milliseconds ban_interval_msec{std::chrono::minutes(1)};

    /// Max number of dial attempts before peer is forgotten
    unsigned max_dial_attempts = 3;

    /// Expiration of gossip peers' addresses in address repository
    std::chrono::milliseconds address_expiration_msec{std::chrono::hours(1)};

    /// Max RPC message size
    size_t max_message_size = 1 << 24;

    /// Max number of remote subscriptions accepted from a single peer;
    /// subscribe entries beyond the cap are ignored and logged (GOSS-01)
    size_t max_remote_subscriptions_per_peer = 1024;

    /// Max bytes admitted to the pending queue per outbound stream.
    /// Mirrors max_message_size per D-02, so a single legitimate large RPC
    /// (e.g. a large CRDT broadcast) is never dropped under default config;
    /// only queued backlog beyond it is (GOSS-02)
    size_t max_pending_bytes_per_stream = 1 << 24;

    /// Number of consecutive cap-hit drops (with no intervening full queue
    /// drain) before the outbound stream is closed (GOSS-02)
    size_t overflow_close_threshold = 8;

    /// Protocol version
    std::string protocol_version = "/meshsub/1.0.0";

    /// Sign published messages
    bool sign_messages = false;
  };

  using TopicId = std::string;
  using TopicList = std::vector<TopicId>;
  using TopicSet = std::set<TopicId>;

  /// Gossip protocol interface
  class Gossip {
   public:
    virtual ~Gossip() = default;

    /// Get Number of Peers in topic
    virtual size_t getPeerCount(const TopicId& topic) const = 0;

    /// Get PeerIDs subscribed to topic
    virtual std::vector<peer::PeerId> getAllPeers(const TopicId& topic) const = 0;
    /// Adds bootstrap peer to the set of connectable peers
    virtual void addBootstrapPeer(
        const peer::PeerId &id,
        boost::optional<multi::Multiaddress> address) = 0;
    /// Adds bootstrap peer with multiple addresses to the set of connectable peers
    virtual void addBootstrapPeer(
        const peer::PeerId &id,
        const std::vector<multi::Multiaddress> &addresses) = 0;

    /// Adds bootstrap peer address in string form
    virtual outcome::result<void> addBootstrapPeer(
        const std::string &address) = 0;

    /// Starts client and server
    virtual void start() = 0;

    /// Stops client and server
    virtual void stop() = 0;

    /// Message received on subscription.
    /// Temporary struct of fields the subscriber may store if they want
    struct Message {
      const ByteArray &from;
      const TopicId &topic;
      const ByteArray &data;
    };

    /// Validator of messages arriving from the wire
    using Validator = std::function<bool(const ByteArray &from, const ByteArray &data)>;

    /// Sets message validator for topic
    virtual void setValidator(const TopicId &topic, Validator validator) = 0;

    /// Creates unique message ID out of message fields
    using MessageIdFn = std::function<ByteArray(
        const ByteArray &from, const ByteArray &seq, const ByteArray &data)>;

    /// Sets message ID funtion that differs from default (from+sec_no)
    virtual void setMessageIdFn(MessageIdFn fn) = 0;

    /// Resource-bound violations a remote peer can sustain against this
    /// node. Escalation is exclusively for sustained outbound overflow this
    /// phase; subscription-cap drops stay log-only (D-09)
    enum class ViolationType {
      SustainedWriteOverflow = 1,
    };

    /// Handler invoked when a peer violates resource bounds (D-08/GOSS-03)
    using ViolationHandler =
        std::function<void(const peer::PeerId &, ViolationType)>;

    /// Sets handler for peer resource-bound violations; invoked after the
    /// offending stream has been torn down (GOSS-03)
    virtual void setViolationHandler(ViolationHandler handler) = 0;

    /// Empty message means EOS (end of subscription data stream)
    using SubscriptionData = boost::optional<const Message &>;
    using SubscriptionCallback = std::function<void(SubscriptionData)>;

    /// Subscribes to topics
    virtual Subscription subscribe(TopicSet topics,
                                   SubscriptionCallback callback) = 0;

    /// Publishes to topics. Returns false if validation fails or not started
    virtual bool publish(TopicId topic, ByteArray data) = 0;
  };

  // Creates Gossip object
  std::shared_ptr<Gossip> create(
      std::shared_ptr<basic::Scheduler> scheduler,
      std::shared_ptr<Host> host,
      std::shared_ptr<peer::IdentityManager> idmgr,
      std::shared_ptr<crypto::CryptoProvider> crypto_provider,
      std::shared_ptr<crypto::marshaller::KeyMarshaller> key_marshaller,
      Config config = Config{});

}  // namespace libp2p::protocol::gossip
