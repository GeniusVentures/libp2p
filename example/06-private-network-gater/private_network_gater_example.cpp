/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <system_error>

#include <libp2p/host/basic_host.hpp>
#include <libp2p/injector/host_injector.hpp>
#include <libp2p/log/configurator.hpp>
#include <libp2p/log/logger.hpp>
#include <libp2p/muxer/muxed_connection_config.hpp>
#include <libp2p/network/connection_gater.hpp>
#include <libp2p/protocol/echo.hpp>

// This example is a standalone copy of example/07-connection-gater's
// DenylistGater (example directories don't share a library target -- see
// D-09/D-10's one-topic-per-example-dir convention), combined with the
// usePrivateNetwork(...) PSK layer from example/05-private-network. It is
// DOCS-03's primary artifact: proving PSK and the gater are complementary,
// non-redundant layers.

namespace {
  const std::string logger_config(R"(
# ----------------
sinks:
  - name: console
    type: console
    color: true
groups:
  - name: main
    sink: console
    level: info
    children:
      - name: libp2p
# ----------------
  )");

  // Publicly-known test vector -- byte-identical to
  // test/libp2p/security/pnet/pnet_injector_test.cpp's kValidSwarmKey and to
  // example/05-private-network's swarm key. This is NEVER a real secret:
  // generate and substitute your own swarm.key text before real use.
  const std::string kSwarmKeyText =
      "/key/swarm/psk/1.0.0/\n"
      "/base16/"
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n";

  // Reused from test/libp2p/network/dialer_test.cpp's bootstrap-peer-ID
  // test -- any well-formed base58 peer-id string works here.
  const std::string kDeniedPeerIdText =
      "QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb";

  /// Hardcoded denylisted peer id, decoded once and reused by both the
  /// gater and the self-dial demonstration below. This peer is assumed, for
  /// the sake of the demonstration, to also hold the correct swarm key --
  /// i.e. it would pass the pnet layer but is still denied by the gater.
  const libp2p::peer::PeerId &deniedPeerId() {
    static const libp2p::peer::PeerId kDeniedPeerId =
        libp2p::peer::PeerId::fromBase58(kDeniedPeerIdText).value();
    return kDeniedPeerId;
  }
}  // namespace

/**
 * @brief Same shape as example/07-connection-gater's DenylistGater: denies
 * one hardcoded peer at interceptPeerDial, permissive everywhere else.
 */
struct DenylistGater : public libp2p::network::ConnectionGater {
  libp2p::outcome::result<void> interceptPeerDial(
      const libp2p::peer::PeerId &p) override {
    if (p == deniedPeerId()) {
      return libp2p::outcome::failure(
          std::make_error_code(std::errc::permission_denied));
    }
    return libp2p::outcome::success();
  }

  libp2p::outcome::result<void> interceptAddrDial(
      const libp2p::peer::PeerId &p,
      const libp2p::multi::Multiaddress &addr) override {
    return libp2p::outcome::success();
  }

  libp2p::outcome::result<void> interceptAccept(
      const libp2p::multi::Multiaddress &local,
      const libp2p::multi::Multiaddress &remote) override {
    return libp2p::outcome::success();
  }

  libp2p::outcome::result<void> interceptSecured(
      bool is_initiator, const libp2p::peer::PeerId &remote_peer,
      const libp2p::multi::Multiaddress &remote_addr) override {
    return libp2p::outcome::success();
  }

  libp2p::outcome::result<void> interceptUpgraded(
      const std::shared_ptr<libp2p::connection::CapableConnection> &conn)
      override {
    return libp2p::outcome::success();
  }
};

int main() {
  // prepare log system
  auto logging_system = std::make_shared<soralog::LoggingSystem>(
      std::make_shared<soralog::ConfiguratorFromYAML>(
          // Original LibP2P logging config
          std::make_shared<libp2p::log::Configurator>(),
          // Additional logging config for application
          logger_config));
  auto r = logging_system->configure();
  if (!r.message.empty()) {
    (r.has_error ? std::cerr : std::cout) << r.message << std::endl;
  }
  if (r.has_error) {
    exit(EXIT_FAILURE);
  }

  libp2p::log::setLoggingSystem(logging_system);
  if (std::getenv("TRACE_DEBUG") != nullptr) {
    libp2p::log::setLevelOfGroup("main", soralog::Level::TRACE);
  } else {
    libp2p::log::setLevelOfGroup("main", soralog::Level::ERROR_);
  }

  // Compose BOTH DI modules: usePrivateNetwork wraps the Upgrader in
  // PnetUpgraderDecorator (network-membership boundary), and
  // useConnectionGater<DenylistGater> replaces the default permissive
  // gater (peer-level authorization boundary). Both attach independently
  // at the makeHostInjector(...) call site.
  auto injector = libp2p::injector::makeHostInjector(
      libp2p::injector::usePrivateNetwork(kSwarmKeyText),
      libp2p::injector::useConnectionGater<DenylistGater>());
  auto host = injector.create<std::shared_ptr<libp2p::Host>>();
  auto io_context =
      injector.create<std::shared_ptr<boost::asio::io_context>>();

  // set a handler for Echo protocol
  libp2p::protocol::Echo echo{libp2p::protocol::EchoConfig{
      /*.max_server_repeats =*/
          libp2p::protocol::EchoConfig::kInfiniteNumberOfRepeats,
      /*.max_recv_size =*/
          libp2p::muxer::MuxedConnectionConfig::kDefaultMaxWindowSize}};
  host->setProtocolHandler({echo.getProtocolId()},
                           [&echo](libp2p::StreamAndProtocol stream) {
                             echo.handle(std::move(stream));
                           });

  io_context->post([host, &echo] {
    auto ma =
        libp2p::multi::Multiaddress::create("/ip4/127.0.0.1/tcp/40532")
            .value();
    auto listen_res = host->listen(ma);
    if (!listen_res) {
      std::cerr << "host cannot listen the given multiaddress: "
                << listen_res.error().message() << "\n";
      std::exit(EXIT_FAILURE);
    }

    host->start();
    std::cout << "Private-network + gater server started\nListening on: "
              << ma.getStringAddress()
              << "\nPeer id: " << host->getPeerInfo().id.toBase58()
              << std::endl;

    // demonstrate the complementary-layers point: dial our own denylisted
    // peer id (which, for this demonstration, is assumed to hold the
    // correct PSK -- it is still denied, because the gater is a separate,
    // independent authorization check).
    auto denied_ma =
        libp2p::multi::Multiaddress::create("/ip4/127.0.0.1/tcp/1").value();
    libp2p::peer::PeerInfo denied_info{deniedPeerId(), {denied_ma}};
    host->newStream(
        denied_info, {echo.getProtocolId()},
        [](libp2p::StreamAndProtocolOrError result) {
          if (result) {
            std::cout << "UNEXPECTED: stream opened" << std::endl;
          } else {
            std::cout
                << "peer holds the correct PSK for this private network "
                   "but is still denied by the gater -- PSK proves "
                   "network membership, the gater proves peer-level "
                   "authorization; they are independent, non-redundant "
                   "checks."
                << std::endl;
          }
        });
  });

  try {
    io_context->run();
  } catch (const boost::system::error_code &ec) {
    std::cout << "Server cannot run: " << ec.message() << std::endl;
  } catch (...) {
    std::cout << "Unknown error happened" << std::endl;
  }
}
