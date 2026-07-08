/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <libp2p/basic/scheduler/scheduler_impl.hpp>

#include <cassert>
#include <exception>

#include <libp2p/log/logger.hpp>

#include "platform/platform.hpp"

namespace libp2p::basic {

  SchedulerImpl::SchedulerImpl(std::shared_ptr<SchedulerBackend> backend,
                               Scheduler::Config config)
      : backend_(std::move(backend)),
        config_(config),
        deferred_callbacks_(*backend_),
        timed_callbacks_(*backend_, config_.max_timer_threshold) {}

  std::chrono::milliseconds SchedulerImpl::now() const noexcept {
    return backend_->now();
  }

  Scheduler::Handle SchedulerImpl::scheduleImpl(
      Callback &&cb, std::chrono::milliseconds delay_from_now,
      bool make_handle) noexcept {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    assert(cb);

    if (!cb) {
      return Handle{};
    }

    std::chrono::milliseconds expire_time = delay_from_now;
    auto seq = ++seq_number_;

    if (expire_time.count() <= 0) {
      expire_time = kZeroTime;
      deferred_callbacks_.push(seq, std::move(cb), make_handle,
                               weak_from_this());
    } else {
      expire_time += now();
      timed_callbacks_.push(expire_time, seq, std::move(cb), weak_from_this());
    }

    if (make_handle) {
      return Handle{Ticket(expire_time, seq), weak_from_this()};
    }
    return Handle{};
  }

  void SchedulerImpl::cancel(Handle::Ticket ticket) noexcept {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (ticket.first != kZeroTime) {
      timed_callbacks_.cancel(ticket, weak_from_this());
    } else {
      deferred_callbacks_.cancel(ticket.second);
    }
  }

  outcome::result<SchedulerImpl::Handle::Ticket> SchedulerImpl::reschedule(
      Handle::Ticket ticket,
      std::chrono::milliseconds delay_from_now) noexcept {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (delay_from_now.count() <= 0) {
      return Error::kInvalidArgument;
    }

    std::chrono::milliseconds abs_time = now() + delay_from_now;

    if (ticket.first != kZeroTime) {
      // timed ticket being rescheduled
      return timed_callbacks_.rescheduleTicket(ticket, abs_time, ++seq_number_);
    }

    // deferred callback becomes timed
    auto cb = deferred_callbacks_.cancel(ticket.second);
    if (!cb) {
      return Error::kItemNotFound;
    }
    timed_callbacks_.push(abs_time, ++seq_number_, std::move(cb),
                          weak_from_this());
    return Ticket(abs_time, seq_number_);
  }

  void SchedulerImpl::pulse(std::chrono::milliseconds current_clock) noexcept {
    std::unique_lock<std::recursive_mutex> lock(mutex_);
    // Timed callbacks are allowed to call back into the scheduler, or into code
    // that takes other locks before scheduling more work. Do not execute them
    // while holding mutex_; instead, serialize overlapping backend pulses here
    // and let the active pulse drain pending work.
    if (pulse_state_.in_progress) {
      if (current_clock == kZeroTime) {
        pulse_state_.deferred_pending = true;
      } else if (current_clock > pulse_state_.timed_pending) {
        pulse_state_.timed_pending = current_clock;
      }
      return;
    }
    pulse_state_.in_progress = true;

    try {
      auto owner = shared_from_this();
      for (;;) {
        if (current_clock == kZeroTime) {
          deferred_callbacks_.onTimer(owner);
        } else {
          timed_callbacks_.onTimer(current_clock, owner, lock);
        }

        if (pulse_state_.deferred_pending) {
          pulse_state_.deferred_pending = false;
          current_clock = kZeroTime;
          continue;
        }

        if (pulse_state_.timed_pending != kZeroTime) {
          current_clock = pulse_state_.timed_pending;
          pulse_state_.timed_pending = kZeroTime;
          continue;
        }

        break;
      }
    } catch (const std::exception &e) {
      try {
        auto log = log::createLogger("Scheduler", "scheduler");
        log->error("scheduler pulse exception: {}", e.what());
      } catch (...) {
      }
    } catch (...) {
      try {
        auto log = log::createLogger("Scheduler", "scheduler");
        log->error("scheduler pulse unknown exception");
      } catch (...) {
      }
    }
    pulse_state_.in_progress = false;
  }

  void SchedulerImpl::DeferredCallbacksWithoutCancel::push(uint64_t seq,
                                                           Callback cb) {
    items_.emplace_back(seq, std::move(cb));
  }

  bool SchedulerImpl::DeferredCallbacksWithoutCancel::empty() const {
    return items_.empty();
  }

  void SchedulerImpl::DeferredCallbacksWithoutCancel::get(
      std::vector<Item> &items_to_process) {
    // New items will be deferred to the next IO cycle,
    // returned tiems will be processed now
    items_.swap(items_to_process);
    items_.clear();
  }

  void SchedulerImpl::DeferredCallbacksWithCancel::push(uint64_t seq,
                                                        Callback cb) {
    items_.emplace_back(seq);
    deferred_.emplace(seq, std::move(cb));
  }

  bool SchedulerImpl::DeferredCallbacksWithCancel::empty() const {
    return deferred_.empty();
  }

  void SchedulerImpl::DeferredCallbacksWithCancel::startProcessing(
      std::vector<uint64_t> &items_to_process) {
    items_.swap(items_to_process);
    items_.clear();

    // new callbacks arise during this processing will go the next iteration
    deferred_.swap(being_processed_);
    deferred_.clear();
  }

  void SchedulerImpl::DeferredCallbacksWithCancel::execute(uint64_t seq) {
    auto it = being_processed_.find(seq);
    if (it != being_processed_.end()) {
      if (it->second) {
        seq_in_process_ = seq;
        cb_in_process_ = std::move(it->second);
        cb_in_process_();
        cb_in_process_ = Callback{};
        seq_in_process_ = 0;
      }
    }
  }

  void SchedulerImpl::DeferredCallbacksWithCancel::endProcessing() {
    being_processed_.clear();
  }

  Scheduler::Callback SchedulerImpl::DeferredCallbacksWithCancel::cancel(
      uint64_t seq) {
    Callback cb;

    if (seq != seq_in_process_) {
      auto it = deferred_.find(seq);
      if (it != deferred_.end()) {
        cb.swap(it->second);
        deferred_.erase(it);
      } else if (seq_in_process_ != 0) {
        it = being_processed_.find(seq);
        if (it != being_processed_.end()) {
          cb.swap(it->second);
          being_processed_.erase(it);
        }
      }
    } else {
      cb.swap(cb_in_process_);
    }

    return cb;
  }

  SchedulerImpl::DeferredCallbacks::DeferredCallbacks(SchedulerBackend &backend)
      : backend_(backend) {}

  void SchedulerImpl::DeferredCallbacks::push(
      uint64_t seq, Callback cb, bool cancellable,
      std::weak_ptr<SchedulerBackendFeedback> sch) {
    if (cancellable) {
      cancellable_.push(seq, std::move(cb));
    } else {
      non_cancellable_.push(seq, std::move(cb));
    }
    rescheduleTimer(std::move(sch));
  }

  void SchedulerImpl::DeferredCallbacks::processNonCancellableItems(
      gsl::span<Item> items, const std::shared_ptr<Scheduler> &owner) {
    for (const auto &item : items) {
      assert(item.cb);
      item.cb();
      if (owner.unique()) {
        break;
      }
    }
  }

  void SchedulerImpl::DeferredCallbacks::processCancellableItems(
      gsl::span<uint64_t> items, const std::shared_ptr<Scheduler> &owner) {
    for (const auto &seq : items) {
      cancellable_.execute(seq);

      if (owner.unique()) {
        break;
      }
    }
  }

  void SchedulerImpl::DeferredCallbacks::processBothSources(
      const std::shared_ptr<Scheduler> &owner) {
    size_t first_cursor = 0;
    size_t second_cursor = 0;

    for (;;) {
      // here we guarantee that lower seq number executes earlier,
      // that's why this function exists

      uint64_t first_seq = current_nc_items_[first_cursor].seq;
      uint64_t second_seq = current_c_items_[second_cursor];

      if (first_seq < second_seq) {
        assert(current_nc_items_[first_cursor].cb);
        current_nc_items_[first_cursor].cb();

        if (owner.unique()) {
          break;
        }

        if (++first_cursor >= current_nc_items_.size()) {
          gsl::span<uint64_t> items(current_c_items_);
          processCancellableItems(items.subspan(ssize_t(second_cursor)), owner);
          break;
        }
      } else {
        cancellable_.execute(second_seq);

        if (owner.unique()) {
          break;
        }

        if (++second_cursor >= current_c_items_.size()) {
          gsl::span<Item> items(current_nc_items_);
          processNonCancellableItems(items.subspan(ssize_t(first_cursor)),
                                     owner);
          break;
        }
      }
    }

    current_c_items_.clear();
    current_nc_items_.clear();
  }

  void SchedulerImpl::DeferredCallbacks::onTimer(
      std::shared_ptr<Scheduler> owner) {
    [this, owner = std::move(owner)]() {
      timer_is_set_ = false;
      int process_type = 0;

      if (!non_cancellable_.empty()) {
        process_type += 1;
        non_cancellable_.get(current_nc_items_);
      }

      if (!cancellable_.empty()) {
        process_type += 2;
        cancellable_.startProcessing(current_c_items_);
      }

      if (process_type == 0) {
        return;
      }

      if (process_type == 1) {
        processNonCancellableItems(current_nc_items_, owner);
        current_nc_items_.clear();
      } else if (process_type == 2) {
        processCancellableItems(current_c_items_, owner);
        current_c_items_.clear();
      } else {
        assert(process_type == 3);
        processBothSources(owner);
      }

      if (process_type > 1) {
        cancellable_.endProcessing();
      }

      if (!owner.unique()) {
        rescheduleTimer(owner);
      }
    }();
  }

  Scheduler::Callback SchedulerImpl::DeferredCallbacks::cancel(uint64_t seq) {
    return cancellable_.cancel(seq);
  }

  void SchedulerImpl::DeferredCallbacks::rescheduleTimer(
      std::weak_ptr<SchedulerBackendFeedback> sch) {
    if (timer_is_set_) {
      return;
    }

    if (non_cancellable_.empty() && cancellable_.empty()) {
      return;
    }

    timer_is_set_ = true;
    backend_.setTimer(std::chrono::milliseconds::zero(), std::move(sch));
  }

  SchedulerImpl::TimedCallbacks::TimedCallbacks(
      SchedulerBackend &backend, std::chrono::milliseconds timer_threshold)
      : backend_(backend), timer_threshold_(timer_threshold) {}

  void SchedulerImpl::TimedCallbacks::push(
      std::chrono::milliseconds abs_time, uint64_t seq, Callback cb,
      std::weak_ptr<SchedulerBackendFeedback> sch) {
    items_.emplace(Ticket{abs_time, seq}, std::move(cb));
    rescheduleTimer(std::move(sch));
  }

  void SchedulerImpl::TimedCallbacks::onTimer(
      std::chrono::milliseconds clock, std::shared_ptr<Scheduler> owner,
      std::unique_lock<std::recursive_mutex> &lock) {
    [this, clock, owner = std::move(owner), &lock]() {
      current_timer_ = kZeroTime;

      while (!items_.empty() && !owner.unique()) {
        auto it = items_.begin();
        auto next_time = it->first.first;
        if (next_time > clock) {
          break;
        }

        seq_in_process_ = it->first.second;

        auto cb = std::move(it->second);
        items_.erase(it);

        assert(cb);

        try {
          // User callbacks may acquire graphsync/libp2p locks and then schedule
          // more work. Holding the scheduler lock here creates a lock inversion.
          lock.unlock();
          cb();
          lock.lock();
        } catch (...) {
          if (!lock.owns_lock()) {
            lock.lock();
          }
          seq_in_process_ = 0;
          current_callback_rescheduled_.reset();
          throw;
        }

        if (current_callback_rescheduled_.has_value()) {
          items_.emplace(std::move(current_callback_rescheduled_.value()),
                         std::move(cb));
          current_callback_rescheduled_.reset();
        }

        seq_in_process_ = 0;
      }

      if (owner.unique()) {
        // scheduler finished
        items_.clear();
        return;
      }

      rescheduleTimer(owner);
    }();
  }

  void SchedulerImpl::TimedCallbacks::rescheduleTimer(
      std::weak_ptr<SchedulerBackendFeedback> sch) {
    std::chrono::milliseconds next_time = kZeroTime;
    while (!items_.empty()) {
      auto it = items_.begin();
      if (it->second) {
        next_time = it->first.first;

        if (++it != items_.end()) {
          // we dont need high resolution timer, delay is needed to avoid
          // switching timer too often
          auto time_with_threshold = next_time + timer_threshold_;

          if (it->second && it->first.first <= time_with_threshold) {
            next_time = time_with_threshold;
          }
        }
        break;
      }

      // cleanup canceled items in lazy manner
      items_.erase(it);
    }

    if (next_time == kZeroTime) {
      return;
    }

    if (current_timer_ != kZeroTime && current_timer_ <= next_time) {
      return;
    }

    current_timer_ = next_time;

    backend_.setTimer(std::chrono::milliseconds(current_timer_),
                      std::move(sch));
  }

  void SchedulerImpl::TimedCallbacks::cancel(
      const Ticket &ticket, std::weak_ptr<SchedulerBackendFeedback> sch) {
    if (ticket.second != seq_in_process_) {
      items_.erase(ticket);
      if (seq_in_process_ != 0) {
        rescheduleTimer(std::move(sch));
      }
    }
  }

  outcome::result<SchedulerImpl::Ticket>
  SchedulerImpl::TimedCallbacks::rescheduleTicket(
      const Ticket &ticket, std::chrono::milliseconds abs_time,
      uint64_t new_seq) {
    auto seq = ticket.second;

    if (abs_time < ticket.first || seq == 0 || new_seq <= seq) {
      return Scheduler::Error::kInvalidArgument;
    }

    Ticket new_ticket(abs_time, new_seq);

    if (seq != seq_in_process_) {
      auto it = items_.find(ticket);
      if (it == items_.end()) {
        return Scheduler::Error::kItemNotFound;
      }
      auto cb = std::move(it->second);
      items_.erase(it);
      items_.emplace(new_ticket, std::move(cb));
    } else {
      current_callback_rescheduled_ = new_ticket;
    }

    return new_ticket;
  }

}  // namespace libp2p::basic
