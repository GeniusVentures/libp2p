/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * DI smoke tests for usePrivateNetwork:
 *  (a) valid key + module → Upgrader resolves to PnetUpgraderDecorator,
 *      bound Psk yields 32 bytes
 *  (b) invalid key → PskValidationError thrown from the module call itself
 *  (c) plain injector without the module → public mode, today's behavior
 *      (Upgrader is the plain UpgraderImpl)
 *
 * NOTE (DI verification substitution): the full makeNetworkInjector graph is
 * not instantiated here — the minimal composition below replicates the exact
 * binding structure of usePrivateNetwork (Psk bind + Upgrader rebind) with
 * the module applied the same way makeNetworkInjector applies overrides.
 * Real full-graph wiring (makeHostInjector + usePrivateNetwork) must be
 * covered by Phase 3 live end-to-end validation.
 */
#include <gtest/gtest.h>

#include <memory>
#include <string>

#include <libp2p/injector/network_injector.hpp>
#include <libp2p/security/pnet/psk.hpp>
#include <libp2p/transport/impl/pnet_upgrader_decorator.hpp>
#include <libp2p/transport/impl/upgrader_impl.hpp>

#include "testutil/prepare_loggers.hpp"

using namespace libp2p::injector;
using namespace libp2p::security::pnet;
using namespace libp2p::transport;

namespace {
  const std::string_view kValidHex =
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
  const std::string kValidSwarmKey =
      "/key/swarm/psk/1.0.0/\n/base16/" + std::string(kValidHex) + "\n";
}  // namespace

/**
 * @given a valid swarm-key text and the usePrivateNetwork module
 * @when the REAL makeNetworkInjector composes with the module applied
 * @then the Upgrader resolves to PnetUpgraderDecorator (through the full
 *        DI graph) and the bound Psk yields exactly 32 bytes
 */
TEST(PnetInjectorTest, ValidKeyResolvesDecoratorAndPsk) {
  testutil::prepareLoggers();
  auto injector = makeNetworkInjector(usePrivateNetwork(kValidSwarmKey));

  auto upgrader = injector.create<std::shared_ptr<Upgrader>>();
  ASSERT_NE(std::dynamic_pointer_cast<PnetUpgraderDecorator>(upgrader),
            nullptr);

  auto handle = injector.create<libp2p::security::pnet::PskHandle>();
  ASSERT_NE(handle.psk, nullptr);
  ASSERT_EQ(handle.psk->span().size(), 32u);
}

/** Raw hex (no framing) shape also resolves through the module */
TEST(PnetInjectorTest, RawKeyShapesAccepted) {
  testutil::prepareLoggers();
  auto injector = makeNetworkInjector(usePrivateNetwork(kValidHex));
  auto handle = injector.create<libp2p::security::pnet::PskHandle>();
  ASSERT_NE(handle.psk, nullptr);
  ASSERT_EQ(handle.psk->span().size(), 32u);
}

/**
 * @given an invalid key (31 bytes worth of hex)
 * @when usePrivateNetwork is invoked
 * @then PskValidationError is thrown from the module call itself — before
 *        any injector/Host could be assembled (PNET-05 fail-safe)
 */
TEST(PnetInjectorTest, InvalidKeyThrowsEagerly) {
  const std::string bad_hex(kValidHex.begin(), kValidHex.begin() + 62);
  ASSERT_THROW(
      {
        try {
          auto module = usePrivateNetwork(bad_hex);
          (void)module;
        } catch (const PskValidationError &e) {
          // message must carry pnet: attribution, never key bytes
          ASSERT_NE(std::string(e.what()).find("pnet:"), std::string::npos);
          throw;
        }
      },
      PskValidationError);
}

/**
 * @given the plain makeNetworkInjector WITHOUT the usePrivateNetwork module
 * @when the Upgrader is resolved
 * @then it is the plain UpgraderImpl — public mode, today's behavior (D-08)
 */
TEST(PnetInjectorTest, AbsenceIsPublicMode) {
  testutil::prepareLoggers();
  auto injector = makeNetworkInjector();
  auto upgrader = injector.create<std::shared_ptr<Upgrader>>();
  ASSERT_EQ(std::dynamic_pointer_cast<PnetUpgraderDecorator>(upgrader),
            nullptr);
  ASSERT_NE(std::dynamic_pointer_cast<UpgraderImpl>(upgrader), nullptr);
}
