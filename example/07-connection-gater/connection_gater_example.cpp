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

  // Reused from test/libp2p/network/dialer_test.cpp's bootstrap-peer-ID
  // test -- any well-formed base58 peer-id string works here, this one is
  // simply an already-exercised literal in this repo.
  const std::string kDeniedPeerIdText =
      "QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb";

  /// Hardcoded denylisted peer id, decoded once and reused by both the
  /// gater and the self-dial demonstration below.
  const libp2p::peer::PeerId &deniedPeerId() {
    static const libp2p::peer::PeerId kDeniedPeerId =
        libp2p::peer::PeerId::fromBase58(kDeniedPeerIdText).value();
    return kDeniedPeerId;
  }
}  // namespace

/**
 * @brief A ConnectionGater that denies one hardcoded peer at the earliest
 * hook (interceptPeerDial) and is otherwise fully permissive -- matching
 * PermissiveConnectionGater's default behavior everywhere else.
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

  // create a default Host, replacing the default PermissiveConnectionGater
  // with our custom DenylistGater -- one DI binding, zero changes to
  // Dialer/TcpListener/UpgraderSession.
  auto injector = libp2p::injector::makeHostInjector(
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
        libp2p::multi::Multiaddress::create("/ip4/127.0.0.1/tcp/40531")
            .value();
    auto listen_res = host->listen(ma);
    if (!listen_res) {
      std::cerr << "host cannot listen the given multiaddress: "
                << listen_res.error().message() << "\n";
      std::exit(EXIT_FAILURE);
    }

    host->start();
    std::cout << "Connection-gater server started\nListening on: "
              << ma.getStringAddress()
              << "\nPeer id: " << host->getPeerInfo().id.toBase58()
              << std::endl;

    // demonstrate the custom gater's effect: dial our own denylisted
    // peer id at a throwaway loopback address and observe the rejection.
    auto denied_ma =
        libp2p::multi::Multiaddress::create("/ip4/127.0.0.1/tcp/1").value();
    libp2p::peer::PeerInfo denied_info{deniedPeerId(), {denied_ma}};
    host->newStream(
        denied_info, {echo.getProtocolId()},
        [](libp2p::StreamAndProtocolOrError result) {
          if (result) {
            std::cout << "UNEXPECTED: stream opened\n";
          } else {
            std::cout
                << "denylisted peer correctly rejected by the custom gater\n";
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
