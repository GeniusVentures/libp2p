/**
 * Copyright Quadrivium LLC
 * All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 */

#include "local_subscriptions.hpp"

#include <cassert>
#include <vector>

namespace libp2p::protocol::gossip {
  LocalSubscriptions::LocalSubscriptions(OnSubscriptionSetChange change_fn)
      : change_fn_(std::move(change_fn)) {}

  Subscription LocalSubscriptions::subscribe(
      TopicSet topics, Gossip::SubscriptionCallback callback) {
    Subscription ret;
    std::vector<TopicId> changes;
    {
      std::lock_guard<std::recursive_mutex> lock(mutex_);
      ret = Super::subscribe(std::move(callback));

      auto ticket_id = lastTicket();
      filters_[ticket_id] = topics;

      for (const auto &t : topics) {
        if (++topics_[t] == 1) {
          changes.emplace_back(t);
        }
      }
    }

    for (const auto &t : changes) {
      change_fn_(true, t);
    }

    return ret;
  }

  std::map<TopicId, size_t> LocalSubscriptions::subscribedToSnapshot() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return topics_;
  }

  void LocalSubscriptions::forwardMessage(const TopicMessage::Ptr &msg) {
    assert(msg);
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (topics_.count(msg->topic) != 0) {
      Gossip::Message tmp_msg{msg->from, msg->topic, msg->data};
      publishWithKeepalive(msg, tmp_msg);
    }
  }

  void LocalSubscriptions::forwardEndOfSubscription() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    publish(boost::none);
  }

  bool LocalSubscriptions::filter(uint64_t ticket,
                                  Gossip::SubscriptionData data) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!data) {
      // this is the end message, broadcast to all subscriptions
      return true;
    }
    auto it = filters_.find(ticket);

    if (it == filters_.end()) {
      return false;
    }

    return it->second.count(data.value().topic) != 0;
  }

  void LocalSubscriptions::unsubscribe(uint64_t ticket) {
    std::vector<TopicId> changes;
    {
      std::lock_guard<std::recursive_mutex> lock(mutex_);
      Super::unsubscribe(ticket);

      auto it = filters_.find(ticket);
      if (it != filters_.end()) {
        TopicSet &s = it->second;
        for (auto topics_it = topics_.begin(); topics_it != topics_.end();) {
          if (s.count(topics_it->first) != 0) {
            if (--topics_it->second == 0) {
              changes.emplace_back(topics_it->first);
              topics_it = topics_.erase(topics_it);
              continue;
            }
          }
          ++topics_it;
        }
        filters_.erase(it);
      }
    }

    for (const auto &t : changes) {
      change_fn_(false, t);
    }
  }

}  // namespace libp2p::protocol::gossip
