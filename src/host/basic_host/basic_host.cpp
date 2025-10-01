/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <libp2p/host/basic_host/basic_host.hpp>

#include <boost/assert.hpp>
#include <libp2p/common/hexutil.hpp>
#include <libp2p/crypto/key_marshaller/key_marshaller_impl.hpp>
#include <libp2p/network/route_helper.hpp>

namespace libp2p::host {

  BasicHost::BasicHost(
      std::shared_ptr<peer::IdentityManager> idmgr,
      std::unique_ptr<network::Network> network,
      std::unique_ptr<peer::PeerRepository> repo,
      std::shared_ptr<event::Bus> bus,
      std::shared_ptr<network::TransportManager> transport_manager)
      : idmgr_(std::move(idmgr)),
        network_(std::move(network)),
        repo_(std::move(repo)),
        bus_(std::move(bus)),
        transport_manager_(std::move(transport_manager)),
        relayaddr_(std::make_unique<libp2p::protocol::RelayAddresses>()),
      obsaddrrepo_(std::make_unique<libp2p::protocol::ObservedAddresses>())
  {
    BOOST_ASSERT(idmgr_ != nullptr);
    BOOST_ASSERT(network_ != nullptr);
    BOOST_ASSERT(repo_ != nullptr);
    BOOST_ASSERT(bus_ != nullptr);
    BOOST_ASSERT(transport_manager_ != nullptr);    
  }

  std::string_view BasicHost::getLibp2pVersion() const {
    return "0.0.0";
  }

  std::string_view BasicHost::getLibp2pClientVersion() const {
    return "libp2p";
  }

  peer::PeerId BasicHost::getId() const {
    return idmgr_->getId();
  }

  peer::PeerInfo BasicHost::getPeerInfo() const {
    auto addresses = getAddresses();
    auto observed = getObservedAddressesReal();
    auto interfaces = getAddressesInterfaces();
    auto relays = getRelayAddresses();

    //for (const auto& addr : addresses) {
    //    std::cout << "Addresses: " << addr.getStringAddress() << std::endl; 
    //}
    //for (const auto& addr : interfaces) {
    //    std::cout << "Interface: " << addr.getStringAddress() << std::endl;
    //}
    //for (const auto& addr : observed) {
    //    std::cout << "Observed: " << addr.getStringAddress() << std::endl;
    //}
    //for (const auto& addr : relays) {
    //    std::cout << "Relays: " << addr.getStringAddress() << std::endl;
    //}
    //std::cout << "Relay address size? " << relays.size() << std::endl;
    std::set<multi::Multiaddress> unique_addresses;
    unique_addresses.insert(std::make_move_iterator(addresses.begin()),
                            std::make_move_iterator(addresses.end()));
    unique_addresses.insert(std::make_move_iterator(interfaces.begin()),
                            std::make_move_iterator(interfaces.end()));
    unique_addresses.insert(std::make_move_iterator(observed.begin()),
                            std::make_move_iterator(observed.end()));
    unique_addresses.insert(std::make_move_iterator(relays.begin()),
        std::make_move_iterator(relays.end()));


    //std::cout << "Unique Addresses: " << unique_addresses.size() << std::endl;
    // TODO(xDimon): Needs to filter special interfaces (e.g. INADDR_ANY, etc.)
    for (auto i = unique_addresses.begin(); i != unique_addresses.end();) {
      bool is_good_addr = true;
      for (auto &pv : i->getProtocolsWithValues()) {
        if (pv.first.code == multi::Protocol::Code::IP4) {
          if (pv.second == "0.0.0.0") {
            is_good_addr = false;
            break;
          }
        } else if (pv.first.code == multi::Protocol::Code::IP6) {
          if (pv.second == "::") {
            is_good_addr = false;
            break;
          }
        }
      }
      if (!is_good_addr) {
        i = unique_addresses.erase(i);
      } else {
        ++i;
      }
    }
    //std::cout << "Unique Addresses after filter: " << unique_addresses.size() << std::endl;
    std::vector<multi::Multiaddress> unique_addr_list(
        std::make_move_iterator(unique_addresses.begin()),
        std::make_move_iterator(unique_addresses.end()));
    //std::cout << "Final unique addr list size: " << unique_addr_list.size() << std::endl;
    return {getId(), std::move(unique_addr_list)};
  }

  std::vector<multi::Multiaddress> BasicHost::getAddresses() const {
    return network_->getListener().getListenAddresses();
  }

  std::vector<multi::Multiaddress> BasicHost::getAddressesInterfaces() const {
    return network_->getListener().getListenAddressesInterfaces();
  }

  std::vector<multi::Multiaddress> BasicHost::getObservedAddresses() const {
    auto r = repo_->getAddressRepository().getAddresses(getId());
    if (r) {
      return r.value();
    }

    // we don't know our addresses
    return {};
  }

  std::vector<multi::Multiaddress> BasicHost::getRelayAddresses() const {
      return relayaddr_->getAllAddresses();
  }

  std::vector<multi::Multiaddress> BasicHost::getObservedAddressesReal(bool checkconfirmed) const {
      return obsaddrrepo_->getAllAddresses(checkconfirmed);
  }

  Host::Connectedness BasicHost::connectedness(const peer::PeerInfo &p) const {
    auto conn = network_->getConnectionManager().getBestConnectionForPeer(p.id);
    if (conn != nullptr) {
      return Connectedness::CONNECTED;
    }

    // for each address, try to find transport to dial
    for (auto &&ma : p.addresses) {
      if (auto tr = transport_manager_->findBest(ma); tr != nullptr) {
        // we can dial to the peer
        return Connectedness::CAN_CONNECT;
      }
    }

    auto res = repo_->getAddressRepository().getAddresses(p.id);
    if (res.has_value()) {
      for (auto &&ma : res.value()) {
        if (auto tr = transport_manager_->findBest(ma); tr != nullptr) {
          // we can dial to the peer
          return Connectedness::CAN_CONNECT;
        }
      }
    }

    // we did not find available transports to dial
    return Connectedness::CAN_NOT_CONNECT;
  }

  void BasicHost::setProtocolHandler(
      const peer::Protocol &proto,
      const std::function<connection::Stream::Handler> &handler) {
    network_->getListener().getRouter().setProtocolHandler(proto, handler);
  }

  void BasicHost::setProtocolHandler(
      const peer::Protocol &proto,
      const std::function<connection::Stream::Handler> &handler,
      const std::function<bool(const peer::Protocol &)> &predicate) {
    network_->getListener().getRouter().setProtocolHandler(proto, handler,
                                                           predicate);
  }

  void BasicHost::newStream(const peer::PeerInfo &p,
                            const peer::Protocol &protocol,
                            const Host::StreamResultHandler &handler,
                            std::chrono::milliseconds timeout) {
      network_->getConnectionManager().collectGarbage();
    
    // Get source addresses from available listeners
    auto available_listeners = network_->getListener().getListenAddresses();
    auto source_addresses = libp2p::network::RouteHelper::getBestSourceAddresses(available_listeners);
    
    network_->getDialer().newStream(p, protocol, handler, timeout, source_addresses);
  }

  void BasicHost::newStream(const peer::PeerId &peer_id,
                            const peer::Protocol &protocol,
                            const StreamResultHandler &handler) {
      network_->getConnectionManager().collectGarbage();
    // For peer ID only, we need to construct PeerInfo from repository
    auto peer_info = repo_->getPeerInfo(peer_id);
    if (!peer_info.addresses.empty()) {
      // Get source addresses from available listeners
      auto available_listeners = network_->getListener().getListenAddresses();
      auto source_addresses = libp2p::network::RouteHelper::getBestSourceAddresses(available_listeners);
      network_->getDialer().newStream(peer_id, protocol, handler, source_addresses);
    } else {
      // Fallback: create SourceAddresses from first listener address
      auto listen_addr = network_->getListener().getListenAddresses().at(0);
      auto default_ipv4 = multi::Multiaddress::create("/ip4/0.0.0.0").value();
      auto default_ipv6 = multi::Multiaddress::create("/ip6/::").value();
      libp2p::network::RouteHelper::SourceAddresses fallback_addresses{default_ipv4, default_ipv6, false, false};
      
      std::string ip = libp2p::network::RouteHelper::extractIPFromMultiaddress(listen_addr).value();
      if (ip.find(':') == std::string::npos) {
        // IPv4
        fallback_addresses.has_ipv4 = true;
        fallback_addresses.ipv4_source = listen_addr;
      } else {
        // IPv6
        fallback_addresses.has_ipv6 = true;
        fallback_addresses.ipv6_source = listen_addr;
        fallback_addresses.has_ipv4 = false;
      }
      network_->getDialer().newStream(peer_id, protocol, handler, fallback_addresses);
    }
  }

  outcome::result<void> BasicHost::listen(const multi::Multiaddress &ma) {
    return network_->getListener().listen(ma);
  }

  outcome::result<void> BasicHost::closeListener(
      const multi::Multiaddress &ma) {
    return network_->getListener().closeListener(ma);
  }

  outcome::result<void> BasicHost::removeListener(
      const multi::Multiaddress &ma) {
    return network_->getListener().removeListener(ma);
  }

  void BasicHost::start() {
    network_->getListener().start();
  }

  event::Handle BasicHost::setOnNewConnectionHandler(
      const NewConnectionHandler &h) const {
    return bus_->getChannel<event::network::OnNewConnectionChannel>().subscribe(
        [h{std::move(h)}](const std::weak_ptr<connection::CapableConnection>& conn) {
          auto connection = conn.lock();
          if (connection) {
            auto remote_peer_res = connection->remotePeer();
            if (!remote_peer_res)
              return;

            auto remote_peer_addr_res = connection->remoteMultiaddr();
            if (!remote_peer_addr_res)
              return;

            if (h != nullptr)
              h(peer::PeerInfo{std::move(remote_peer_res.value()),
                               std::vector<multi::Multiaddress>{
                                   std::move(remote_peer_addr_res.value())}});
          }
        });
  }

  void BasicHost::stop() {
    network_->getListener().stop();
  }

  network::Network &BasicHost::getNetwork() {
    return *network_;
  }

  peer::PeerRepository &BasicHost::getPeerRepository() {
    return *repo_;
  }

  protocol::RelayAddresses& BasicHost::getRelayRepository() {
      return *relayaddr_;
  }

  protocol::ObservedAddresses& BasicHost::getObservedRepository() {
      return *obsaddrrepo_;
  }

  network::Router &BasicHost::getRouter() {
    return network_->getListener().getRouter();
  }

  event::Bus &BasicHost::getBus() {
    return *bus_;
  }

  void BasicHost::connect(const peer::PeerInfo &peer_info,
                          const ConnectionResultHandler &handler,
                          std::chrono::milliseconds timeout, bool holepunch, bool holepunchserver) {
      network_->getConnectionManager().collectGarbage();
    
    // Get source addresses from available listeners
    auto available_listeners = network_->getListener().getListenAddresses();
    auto source_addresses = libp2p::network::RouteHelper::getBestSourceAddresses(available_listeners);
    
    network_->getDialer().dial(peer_info, handler, timeout, source_addresses, holepunch, holepunchserver);
  }

  void BasicHost::disconnect(const peer::PeerId &peer_id) {
    network_->closeConnections(peer_id);
  }

  network::ConnectionManager::Config& BasicHost::getConnectionManagerConfig() {
    return network_->getConnectionManager().getConfig();
  }

  const network::ConnectionManager::Config& BasicHost::getConnectionManagerConfig() const {
    return network_->getConnectionManager().getConfig();
  }

  multi::Multiaddress BasicHost::chooseBestSourceAddress(const peer::PeerInfo &peer_info) const {
    // Get all addresses we're currently listening on
    auto available_listeners = network_->getListener().getListenAddresses();
    
    if (available_listeners.empty()) {
      // No listeners available - should not happen but handle gracefully
      static auto log = log::createLogger("basic-host");
      log->warn("No listen addresses available for source selection");
      return multi::Multiaddress::create("/ip4/0.0.0.0/tcp/0").value();
    }

    // Get both IPv4 and IPv6 source addresses
    auto source_addresses = libp2p::network::RouteHelper::getBestSourceAddresses(available_listeners);
    
    // Try to find a compatible destination in peer_info
    for (const auto &dest_addr : peer_info.addresses) {
      auto dest_ip_result = libp2p::network::RouteHelper::extractIPFromMultiaddress(dest_addr);
      if (!dest_ip_result) continue;
      
      const auto &dest_ip = dest_ip_result.value();
      bool dest_is_ipv6 = dest_ip.find(':') != std::string::npos;
      
      if (dest_is_ipv6 && source_addresses.has_ipv6) {
        static auto log = log::createLogger("basic-host");
        log->debug("Using IPv6 source {} for IPv6 destination {}", 
                  source_addresses.ipv6_source.getStringAddress(), dest_addr.getStringAddress());
        return source_addresses.ipv6_source;
      } else if (!dest_is_ipv6 && source_addresses.has_ipv4) {
        static auto log = log::createLogger("basic-host");
        log->debug("Using IPv4 source {} for IPv4 destination {}", 
                  source_addresses.ipv4_source.getStringAddress(), dest_addr.getStringAddress());
        return source_addresses.ipv4_source;
      }
    }
    
    // Fallback: prefer IPv4 if available, otherwise IPv6
    if (source_addresses.has_ipv4) {
      static auto log = log::createLogger("basic-host");
      log->debug("No compatible destination found, using IPv4 fallback: {}", 
                source_addresses.ipv4_source.getStringAddress());
      return source_addresses.ipv4_source;
    } else if (source_addresses.has_ipv6) {
      static auto log = log::createLogger("basic-host");
      log->debug("No compatible destination found, using IPv6 fallback: {}", 
                source_addresses.ipv6_source.getStringAddress());
      return source_addresses.ipv6_source;
    }

    // Final fallback to first available listener
    static auto log = log::createLogger("basic-host");
    log->debug("No route-based sources available, using first listener: {}", 
              available_listeners[0].getStringAddress());
    return available_listeners[0];
  }

}  // namespace libp2p::host
