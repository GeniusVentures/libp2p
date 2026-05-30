/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LIBP2P_PROTOCOL_SUBSCRIPTIONS_HPP
#define LIBP2P_PROTOCOL_SUBSCRIPTIONS_HPP

#include <deque>
#include <boost/optional.hpp>
#include <functional>
#include <memory>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#include <libp2p/protocol/common/subscription.hpp>

namespace libp2p::protocol {

  namespace detail {

    template <typename T>
    struct OptionalRefTraits {
      static constexpr bool is_optional_const_ref = false;
    };

    template <typename T>
    struct OptionalRefTraits<boost::optional<const T &>> {
      static constexpr bool is_optional_const_ref = true;
      using value_type = T;
    };

    template <typename T>
    struct PublishStorage {
      using type = std::decay_t<T>;
    };

    template <typename T>
    struct PublishStorage<boost::optional<const T &>> {
      using type = boost::optional<T>;
    };

    template <typename T>
    using PublishStorageT = typename PublishStorage<T>::type;

    template <typename... Args>
    struct PendingPublish {
      std::shared_ptr<void> keepalive;
      std::tuple<PublishStorageT<Args>...> args;
    };

    template <typename T>
    auto makePublishStorage(T &&arg) {
      using DecayedT = std::decay_t<T>;
      if constexpr (OptionalRefTraits<DecayedT>::is_optional_const_ref) {
        using ValueT = typename OptionalRefTraits<DecayedT>::value_type;
        if (arg) {
          return boost::optional<ValueT>(*arg);
        }
        return boost::optional<ValueT>{boost::none};
      } else {
        return std::forward<T>(arg);
      }
    }

    template <typename Arg, typename Stored>
    Arg makePublishView(const Stored &stored) {
      if constexpr (OptionalRefTraits<Arg>::is_optional_const_ref) {
        using ValueT = typename OptionalRefTraits<Arg>::value_type;
        if (stored) {
          return boost::optional<const ValueT &>(stored.get());
        }
        return boost::none;
      } else {
        return stored;
      }
    }

  }  // namespace detail

  /// Set of subscriptions, re-entrancy is allowed, exceptions aren't
  template <typename... Args>
  class SubscriptionsTo : public Subscription::Source {
   public:
    /// Subscription callback
    using Callback = std::function<void(Args...)>;

    ~SubscriptionsTo() override = default;

    size_t size() const {
      return subscriptions_.size();
    }

    bool empty() const {
      return subscriptions_.empty();
    }

    /// Subscribes
    Subscription subscribe(Callback callback) {
      std::unordered_map<uint64_t, Callback> &m =
          inside_publish_ ? being_subscribed_ : subscriptions_;
      m[++last_ticket_] = std::move(callback);
      return Subscription(last_ticket_, weak_from_this());
    }

    /// Forwards data to subscriptions
    void publish(Args... args) {
      publishWithKeepalive(nullptr, std::move(args)...);
    }

    /// Forwards data to subscriptions while keeping an arbitrary object alive
    /// until the deferred publish entry is fully drained.
    void publishWithKeepalive(std::shared_ptr<void> keepalive, Args... args) {
      if (empty()) {
        return;
      }

      pending_publish_.push_back({std::move(keepalive),
                                  std::make_tuple(detail::makePublishStorage(std::move(args))...)});
      if (inside_publish_) {
        return;
      }

      // N.B. they can subscribe and unsubscribe during callbacks
      inside_publish_ = true;

      while (!pending_publish_.empty()) {
        auto next = std::move(pending_publish_.front());
        pending_publish_.pop_front();

        // Snapshot callbacks for this publish iteration so we do not execute
        // function objects directly out of the map while subscriptions can be
        // mutated by nested callbacks.
        std::vector<std::pair<uint64_t, Callback>> callbacks;
        callbacks.reserve(subscriptions_.size());
        for (const auto &p : subscriptions_) {
          callbacks.emplace_back(p.first, p.second);
        }

          // Dispatch directly from owned storage, reconstructing the view args
          // inline for each call.  This avoids materialising a
          // tuple<boost::optional<const T&>> (a reference-containing optional
          // inside a tuple), which has subtle PAC/ABI problems on macOS arm64.
          for (auto &p : callbacks) {
            if (being_canceled_.count(p.first) == 0) {
              bool pass = std::apply(
                  [&](const auto &...stored_args) {
                    return filter(p.first,
                                  detail::makePublishView<Args>(stored_args)...);
                  },
                  next.args);
              if (pass) {
                std::apply(
                    [&](const auto &...stored_args) {
                      p.second(detail::makePublishView<Args>(stored_args)...);
                    },
                    next.args);
              }
            }
          }

        // maybe someone unsubscribed inside callbacks
        for (auto &ticket : being_canceled_) {
          subscriptions_.erase(ticket);
        }
        being_canceled_.clear();

        // and maybe someone subscribed inside callbacks
        for (auto& [ticket, cb] : being_subscribed_) {
          subscriptions_[ticket] = std::move(cb);
        }
        being_subscribed_.clear();
      }

      inside_publish_ = false;
    }

   protected:

    /// To be overrided, returns true if args applicable to ticket
    virtual bool filter(uint64_t ticket, Args... args) = 0;

    /// Used by derived classes to make filters
    uint64_t lastTicket() { return last_ticket_; }

    void unsubscribe(uint64_t ticket) override {
      if (inside_publish_) {
        being_canceled_.emplace(ticket);
      } else {
        subscriptions_.erase(ticket);
      }
    }

   private:

    uint64_t last_ticket_ = 0;
    std::unordered_map<uint64_t, Callback> subscriptions_;
    std::unordered_map<uint64_t, Callback> being_subscribed_;
    std::unordered_set<uint64_t> being_canceled_;
    std::deque<detail::PendingPublish<Args...>> pending_publish_;
    bool inside_publish_ = false;
  };

}  // namespace libp2p::protocol

#endif  // LIBP2P_PROTOCOL_SUBSCRIPTIONS_HPP
