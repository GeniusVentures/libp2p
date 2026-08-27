/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>

#include <libp2p/host/basic_host.hpp>
#include <libp2p/injector/host_injector.hpp>
#include <libp2p/log/configurator.hpp>
#include <libp2p/log/logger.hpp>
#include <libp2p/muxer/muxed_connection_config.hpp>
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

  // Publicly-known test vector -- byte-identical to
  // test/libp2p/security/pnet/pnet_injector_test.cpp's kValidSwarmKey.
  // This is NEVER a real secret: generate and substitute your own swarm.key
  // text before using this example against a real private network.
  const std::string kSwarmKeyText =
      "/key/swarm/psk/1.0.0/\n"
      "/base16/"
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n";
}  // namespace

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

  // build a Host whose Upgrader is wrapped by PnetUpgraderDecorator: every
  // raw connection is XSalsa20-protected with the swarm key BEFORE
  // multiselect ever runs, so a peer without the matching PSK can never
  // reach protocol negotiation.
  auto injector = libp2p::injector::makeHostInjector(
      libp2p::injector::usePrivateNetwork(kSwarmKeyText));
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

  // launch a Listener part of the Host
  io_context->post([host{std::move(host)}] {
    auto ma =
        libp2p::multi::Multiaddress::create("/ip4/127.0.0.1/tcp/40530")
            .value();
    auto listen_res = host->listen(ma);
    if (!listen_res) {
      std::cerr << "host cannot listen the given multiaddress: "
                << listen_res.error().message() << "\n";
      std::exit(EXIT_FAILURE);
    }

    host->start();
    std::cout << "Private-network server started\nListening on: "
              << ma.getStringAddress()
              << "\nPeer id: " << host->getPeerInfo().id.toBase58()
              << "\nThis peer requires a matching PSK to connect\n"
              << std::endl;
  });

  // run the IO context
  try {
    io_context->run();
  } catch (const boost::system::error_code &ec) {
    std::cout << "Server cannot run: " << ec.message() << std::endl;
  } catch (...) {
    std::cout << "Unknown error happened" << std::endl;
  }
}
