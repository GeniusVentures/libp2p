#pragma once

#include <memory>
#include <stdexcept>
#include <libp2p/host/host.hpp>
#include <libp2p/protocol/identify/identify.hpp>
#include <libp2p/protocol/autonat/autonat.hpp>
#include <libp2p/protocol/relay/relay.hpp>
#include <libp2p/protocol/holepunch/holepunch_server.hpp>
#include <libp2p/protocol/holepunch/holepunch_client.hpp>
#include <libp2p/injector/network_injector.hpp>
#include <libp2p/protocol/identify/identify_msg_processor.hpp>
#include <libp2p/protocol/autonat/autonat_msg_processor.hpp>
#include <libp2p/protocol/relay/relay_msg_processor.hpp>
#include <libp2p/protocol/holepunch/holepunch_server_msg_processor.hpp>
#include <libp2p/protocol/holepunch/holepunch_client_msg_processor.hpp>

namespace libp2p::protocol::factory {

/**
 * Exception thrown when protocol configuration has invalid dependencies
 */
class InvalidProtocolConfigException : public std::invalid_argument {
 public:
  explicit InvalidProtocolConfigException(const std::string& message)
      : std::invalid_argument(message) {}
};

/**
 * Factory for creating and wiring libp2p protocols based on configuration
 */
class ProtocolFactory {
 public:
  /**
   * Structure containing all created protocols
   */
  struct ProtocolSet {
    std::shared_ptr<Identify> identify;
    std::shared_ptr<Autonat> autonat;
    std::shared_ptr<Relay> relay;
    std::shared_ptr<HolepunchServer> holepunch_server;
    std::shared_ptr<HolepunchClient> holepunch_client;
  };

  /**
   * Create and wire protocols based on configuration
   * @param host - libp2p host instance
   * @param config - protocol configuration specifying which protocols to create
   * @param injector - dependency injector for creating protocol dependencies
   * @return ProtocolSet containing all created and wired protocols
   * @throws InvalidProtocolConfigException if configuration has invalid dependencies
   */
  template<typename Injector>
  static ProtocolSet createProtocols(
      std::shared_ptr<Host> host,
      const libp2p::injector::ProtocolConfig& config,
      const Injector& injector);

 private:
  /**
   * Validate protocol configuration dependencies
   * @param config - configuration to validate
   * @throws InvalidProtocolConfigException if dependencies are invalid
   */
  static void validateConfig(const libp2p::injector::ProtocolConfig& config);

  template<typename Injector>
  static std::shared_ptr<Identify> createIdentify(
      std::shared_ptr<Host> host,
      const Injector& injector);

  template<typename Injector>
  static std::shared_ptr<Autonat> createAutonat(
      std::shared_ptr<Host> host,
      const Injector& injector);

  template<typename Injector>
  static std::shared_ptr<Relay> createRelay(
      std::shared_ptr<Host> host,
      const Injector& injector);

  template<typename Injector>
  static std::shared_ptr<HolepunchServer> createHolepunchServer(
      std::shared_ptr<Host> host,
      const Injector& injector);

  template<typename Injector>
  static std::shared_ptr<HolepunchClient> createHolepunchClient(
      std::shared_ptr<Host> host,
      const Injector& injector);
};

} // namespace libp2p::protocol::factory

namespace libp2p::protocol::factory {

inline void ProtocolFactory::validateConfig(const libp2p::injector::ProtocolConfig& config) {
  // Check AutoNAT dependencies
  if (config.enable_autonat && !config.enable_identify) {
    throw InvalidProtocolConfigException(
        "AutoNAT protocol requires Identify protocol to be enabled. "
        "AutoNAT uses peer identification information provided by Identify.");
  }

  // Check Relay dependencies
  if (config.enable_relay && !config.enable_autonat) {
    throw InvalidProtocolConfigException(
        "Relay protocol requires AutoNAT protocol to be enabled. "
        "Relay uses NAT detection capabilities provided by AutoNAT.");
  }

  // Check Holepunch Server dependencies
  if (config.enable_holepunch_server && !config.enable_relay) {
    throw InvalidProtocolConfigException(
        "Holepunch Server protocol requires Relay protocol to be enabled. "
        "Holepunch Server uses relay capabilities for establishing direct connections.");
  }

  // Note: Holepunch Client can work independently as it's typically used by clients
  // that don't need to provide relay services themselves
}

template<typename Injector>
ProtocolFactory::ProtocolSet ProtocolFactory::createProtocols(
    std::shared_ptr<Host> host,
    const libp2p::injector::ProtocolConfig& config,
    const Injector& injector) {
  
  // Validate configuration before creating protocols
  validateConfig(config);
  
  ProtocolSet protocols;

  // Create protocols based on configuration
  if (config.enable_identify) {
    protocols.identify = createIdentify(host, injector);
  }

  if (config.enable_autonat) {
    protocols.autonat = createAutonat(host, injector);
  }

  if (config.enable_relay) {
    protocols.relay = createRelay(host, injector);
  }

  if (config.enable_holepunch_server) {
    protocols.holepunch_server = createHolepunchServer(host, injector);
  }

  if (config.enable_holepunch_client) {
    protocols.holepunch_client = createHolepunchClient(host, injector);
  }

  // Wire protocols together based on what was created
  if (protocols.identify && protocols.autonat) {
    protocols.identify->setAutonat(protocols.autonat);
  }

  if (protocols.autonat && protocols.relay) {
    protocols.autonat->setRelay(protocols.relay);
  }

  if (protocols.relay && protocols.holepunch_server) {
    protocols.relay->setHolepunchServer(protocols.holepunch_server);
  }

  return protocols;
}

template<typename Injector>
std::shared_ptr<Identify> ProtocolFactory::createIdentify(
    std::shared_ptr<Host> host,
    const Injector& injector) {
  
  auto msg_processor = std::make_shared<IdentifyMessageProcessor>(
      *host,
      host->getNetwork().getConnectionManager(),
      *injector.template create<std::shared_ptr<peer::IdentityManager>>(),
      injector.template create<std::shared_ptr<crypto::marshaller::KeyMarshaller>>());

  return std::make_shared<Identify>(
      *host,
      msg_processor,
      host->getBus(),
      injector.template create<std::shared_ptr<transport::Upgrader>>(),
      []() { /* Empty completion callback for factory-created instances */ });
}

template<typename Injector>
std::shared_ptr<Autonat> ProtocolFactory::createAutonat(
    std::shared_ptr<Host> host,
    const Injector& injector) {
  
  auto msg_processor = std::make_shared<AutonatMessageProcessor>(
      *host,
      host->getNetwork().getConnectionManager());

  return std::make_shared<Autonat>(
      *host,
      msg_processor,
      host->getBus(),
      injector.template create<std::shared_ptr<transport::Upgrader>>(),
      []() { /* Empty completion callback for factory-created instances */ });
}

template<typename Injector>
std::shared_ptr<Relay> ProtocolFactory::createRelay(
    std::shared_ptr<Host> host,
    const Injector& injector) {
  
  auto msg_processor = std::make_shared<RelayMessageProcessor>(
      *host,
      host->getNetwork().getConnectionManager(),
      injector.template create<std::shared_ptr<transport::Upgrader>>());

  return std::make_shared<Relay>(
      *host,
      msg_processor,
      host->getBus(),
      []() { /* Empty completion callback for factory-created instances */ });
}

template<typename Injector>
std::shared_ptr<HolepunchServer> ProtocolFactory::createHolepunchServer(
    std::shared_ptr<Host> host,
    const Injector& injector) {
  
  auto msg_processor = std::make_shared<HolepunchServerMsgProc>(
      *host,
      host->getNetwork().getConnectionManager());

  return std::make_shared<HolepunchServer>(
      *host,
      msg_processor,
      host->getBus());
}

template<typename Injector>
std::shared_ptr<HolepunchClient> ProtocolFactory::createHolepunchClient(
    std::shared_ptr<Host> host,
    const Injector& injector) {
  
  auto msg_processor = std::make_shared<HolepunchClientMsgProc>(
      *host,
      host->getNetwork().getConnectionManager());

  return std::make_shared<HolepunchClient>(
      *host,
      msg_processor,
      host->getBus());
}

} // namespace libp2p::protocol::factory