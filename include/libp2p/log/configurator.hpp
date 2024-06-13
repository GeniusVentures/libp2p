/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LIBP2P_LOG_CONFIGURATOR
#define LIBP2P_LOG_CONFIGURATOR

#include <soralog/impl/configurator_from_yaml.hpp>

#include <boost/di.hpp>

namespace libp2p::log {

  class Configurator : public soralog::ConfiguratorFromYAML {
   public:
    BOOST_DI_INJECT_TRAITS();

    Configurator();

    explicit Configurator(std::string config);
   private:
    static const std::string& getEmbeddedConfig() {
        static const std::string embedded_config = R"(
# This is libp2p configuration part of logging system
# ------------- Begin of libp2p config --------------
groups:
  - name: libp2p
    level: off
    children:
      - name: muxer
        children:
          - name: mplex
          - name: yamux
      - name: crypto
      - name: security
        children:
          - name: plaintext
          - name: secio
          - name: noise
      - name: protocols
        children:
          - name: echo
          - name: identify
          - name: kademlia
# --------------- End of libp2p config ---------------)";
        return embedded_config;
    }
  };

}  // namespace libp2p::log

#endif  // LIBP2P_LOG_CONFIGURATOR
