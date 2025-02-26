/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "peer_set.hpp"

#include <algorithm>
#include <random>
#include <chrono>

#include <boost/range/adaptor/filtered.hpp>
#include <boost/range/algorithm/for_each.hpp>

namespace libp2p::protocol::gossip {

  PeerSet::PeerSet(PeerSet&& other) noexcept : peers_(std::move(other.peers_)) {
    // mutex_ doesn't need moving; it's re-created
  }

  PeerSet& PeerSet::operator=(PeerSet&& other) noexcept {
    if (this != &other) {
      std::unique_lock<std::shared_mutex> lock_this(mutex_, std::defer_lock);
      std::unique_lock<std::shared_mutex> lock_other(other.mutex_, std::defer_lock);
      std::lock(lock_this, lock_other);
      peers_ = std::move(other.peers_);
    }
    return *this;
  }
  
  boost::optional<PeerContextPtr> PeerSet::find(
    const peer::PeerId &id) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = peers_.find(id);
    if (it == peers_.end()) {
      return boost::none;
    }
    return *it;
  }

  bool PeerSet::contains(const peer::PeerId &id) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return peers_.count(id) != 0;
  }

  bool PeerSet::insert(PeerContextPtr ctx) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    if (!ctx || peers_.find(ctx) != peers_.end()) {
      return false;
    }
    peers_.emplace(std::move(ctx));
    return true;
  }

  boost::optional<PeerContextPtr> PeerSet::erase(const peer::PeerId &id) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto it = peers_.find(id);
    if (it == peers_.end()) {
      return boost::none;
    }
    boost::optional<PeerContextPtr> ret(*it);
    peers_.erase(it);
    return ret;
  }

  void PeerSet::clear() {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    peers_.clear();
  }

  bool PeerSet::empty() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return peers_.empty();
  }

  size_t PeerSet::size() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return peers_.size();
  }

  std::vector<PeerContextPtr> PeerSet::selectRandomPeers(size_t n) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::vector<PeerContextPtr> ret;
    if (n > 0 && !empty()) {
      ret.reserve(n > size() ? size() : n);
      std::mt19937 gen;
      gen.seed(std::chrono::system_clock::now().time_since_epoch().count());
      std::sample(peers_.begin(), peers_.end(), std::back_inserter(ret), n,
                  gen);
    }
    return ret;
  }

  void PeerSet::selectAll(const SelectCallback &callback) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    boost::for_each(peers_, callback);
  }

  void PeerSet::selectIf(const SelectCallback &callback,
                         const FilterCallback &filter) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    boost::for_each(peers_ | boost::adaptors::filtered(filter), callback);
  }

  void PeerSet::eraseIf(const FilterCallback &filter) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    for (auto it = peers_.begin(); it != peers_.end();) {
      if (filter(*it)) {
        it = peers_.erase(it);
      } else {
        ++it;
      }
    }
  }

}  // namespace libp2p::protocol::gossip
