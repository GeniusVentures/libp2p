/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <libp2p/log/configurator.hpp>

namespace libp2p::log {


  Configurator::Configurator() : ConfiguratorFromYAML(getEmbeddedConfig()) {}

  Configurator::Configurator(std::string config)
      : soralog::ConfiguratorFromYAML(std::move(config)) {}

}  // namespace libp2p::log
