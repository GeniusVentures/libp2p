/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <libp2p/log/logger.hpp>

#include <boost/assert.hpp>

namespace libp2p::log {

  namespace {
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    std::shared_ptr<soralog::LoggingSystem> logging_system_{};

    std::shared_ptr<soralog::LoggingSystem> getLoggingSystem() {
      auto logging_system = std::atomic_load(&logging_system_);
      BOOST_ASSERT_MSG(logging_system,
                       "Logging system is not ready. "
                       "setLoggingSystem() must be executed once before");
      return logging_system;
    }
  }  // namespace

  void setLoggingSystem(
      std::shared_ptr<soralog::LoggingSystem> logging_system) {
    std::atomic_store(&logging_system_, std::move(logging_system));
  }

  Logger createLogger(const std::string &tag) {
    return std::dynamic_pointer_cast<soralog::LoggerFactory>(getLoggingSystem())
        ->getLogger(tag, defaultGroupName);
  }

  Logger createLogger(const std::string &tag, const std::string &group) {
    return std::dynamic_pointer_cast<soralog::LoggerFactory>(getLoggingSystem())
        ->getLogger(tag, group);
  }

  Logger createLogger(const std::string &tag, const std::string &group,
                      Level level) {
    return std::dynamic_pointer_cast<soralog::LoggerFactory>(getLoggingSystem())
        ->getLogger(tag, group, level);
  }

  void setLevelOfGroup(const std::string &group_name, Level level) {
    getLoggingSystem()->setLevelOfGroup(group_name, level);
  }
  void resetLevelOfGroup(const std::string &group_name) {
    getLoggingSystem()->resetLevelOfGroup(group_name);
  }

  void setLevelOfLogger(const std::string &logger_name, Level level) {
    getLoggingSystem()->setLevelOfLogger(logger_name, level);
  }
  void resetLevelOfLogger(const std::string &logger_name) {
    getLoggingSystem()->resetLevelOfLogger(logger_name);
  }

}  // namespace libp2p::log
