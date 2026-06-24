/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <libp2p/transport/tcp/tcp_listener.hpp>

#include <libp2p/log/logger.hpp>
#include <libp2p/transport/impl/upgrader_session.hpp>

#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#else
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <cstring>
#endif

namespace libp2p::transport {

  TcpListener::TcpListener(boost::asio::io_context &context,
                           std::shared_ptr<Upgrader> upgrader,
                           TransportListener::HandlerFunc handler)
      : context_(context),
        acceptor_(context_),
        upgrader_(std::move(upgrader)),
        handle_(std::move(handler)) {}

  outcome::result<void> TcpListener::listen(
      const multi::Multiaddress &address) {
    if (!canListen(address)) {
      return std::errc::address_family_not_supported;
    }

    if (acceptor_.is_open()) {
      return std::errc::already_connected;
    }

    // TODO(@warchant): replace with parser PRE-129
    using namespace boost::asio;  // NOLINT
    try {
      OUTCOME_TRY(endpoint, detail::makeEndpoint(address));

      // setup acceptor, throws
      acceptor_.open(endpoint.protocol());
      acceptor_.set_option(ip::tcp::acceptor::reuse_address(true));
#ifdef SO_REUSEPORT
      boost::asio::detail::socket_option::boolean<SOL_SOCKET, SO_REUSEPORT> reuse_port_option(true);
      acceptor_.set_option(reuse_port_option);
#endif
      acceptor_.set_option(boost::asio::ip::tcp::no_delay(true));
      acceptor_.bind(endpoint);
      acceptor_.listen();

      // start listening
      doAccept();

      return outcome::success();
    } catch (const boost::system::system_error &e) {
      log::createLogger("Listener")
          ->error("Cannot listen to {}: {}", address.getStringAddress(),
                  e.code().message());
      return e.code();
    }
  }

  bool TcpListener::canListen(const multi::Multiaddress &ma) const {
    return detail::supportsIpTcp(ma);
  }

  outcome::result<std::vector<multi::Multiaddress>> TcpListener::getListenMultiaddr() const {
    boost::system::error_code ec;
    auto endpoint = acceptor_.local_endpoint(ec);
    if (ec) {
      return ec;
    }

    std::vector<multi::Multiaddress> addresses;

    // Check if this is a wildcard address (0.0.0.0 or ::)
    auto address = endpoint.address();
    if (address.is_v4() && address.to_v4() == boost::asio::ip::address_v4::any()) {
      // This is 0.0.0.0 - resolve to all available IPv4 interfaces
      auto resolved_addresses = enumerateNetworkInterfaces(endpoint.port(), false);
      if (!resolved_addresses.empty()) {
        auto logger = log::createLogger("TcpListener");
        logger->debug("Resolved 0.0.0.0:{} to {} interface addresses", endpoint.port(), resolved_addresses.size());
        return resolved_addresses;
      }
      // Fallback to wildcard if enumeration failed
    } else if (address.is_v6() && address.to_v6() == boost::asio::ip::address_v6::any()) {
      // This is :: - resolve to all available IPv6 interfaces
      auto resolved_addresses = enumerateNetworkInterfaces(endpoint.port(), true);
      if (!resolved_addresses.empty()) {
        auto logger = log::createLogger("TcpListener");
        logger->debug("Resolved [::]:{} to {} interface addresses", endpoint.port(), resolved_addresses.size());
        return resolved_addresses;
      }
      // Fallback to wildcard if enumeration failed
    }

    // For non-wildcard addresses or fallback case, return the single address
    auto addr_result = detail::makeAddress(endpoint);
    if (addr_result) {
      addresses.push_back(addr_result.value());
    } else {
      return addr_result.error();
    }

    return addresses;
  }

  bool TcpListener::isClosed() const {
    return !acceptor_.is_open();
  }

  outcome::result<void> TcpListener::close() {
    boost::system::error_code ec;
    acceptor_.close(ec);
    if (ec) {
      return outcome::failure(ec);
    }
    return outcome::success();
  }

  void TcpListener::doAccept() {
    using namespace boost::asio;    // NOLINT
    using namespace boost::system;  // NOLINT

    if (!acceptor_.is_open()) {
      return;
    }

    acceptor_.async_accept(
        [self{this->shared_from_this()}](const boost::system::error_code &ec,
                                         ip::tcp::socket sock) {
          if (ec) {
            return self->handle_(ec);
          }

          // Set TCP_NODELAY on the accepted connection socket
          boost::system::error_code nodelay_ec;
          sock.set_option(boost::asio::ip::tcp::no_delay(true), nodelay_ec);
          if (nodelay_ec) {
            log::createLogger("TcpListener")->warn("Failed to set TCP_NODELAY: {}", nodelay_ec.message());
          }

          auto conn =
              std::make_shared<TcpConnection>(self->context_, std::move(sock));

          auto session = std::make_shared<UpgraderSession>(
              self->upgrader_, std::move(conn), self->handle_);

          session->secureInbound();

          self->doAccept();
        });
  };

  std::vector<multi::Multiaddress> TcpListener::enumerateNetworkInterfaces(uint16_t port, bool ipv6) const {
    std::vector<multi::Multiaddress> addresses;
    auto logger = log::createLogger("TcpListener");

    try {
#ifdef _WIN32
      // Windows implementation using GetAdaptersAddresses
      DWORD bufferSize = 0;
      GetAdaptersAddresses(ipv6 ? AF_INET6 : AF_INET, 0, nullptr, nullptr, &bufferSize);

      IP_ADAPTER_ADDRESSES *adapterAddresses = (IP_ADAPTER_ADDRESSES *)malloc(bufferSize);
      if (!adapterAddresses) {
        logger->error("Failed to allocate memory for adapter addresses");
        return addresses;
      }

      if (GetAdaptersAddresses(ipv6 ? AF_INET6 : AF_INET, 0, nullptr, adapterAddresses, &bufferSize) == NO_ERROR) {
        for (IP_ADAPTER_ADDRESSES *adapter = adapterAddresses; adapter; adapter = adapter->Next) {
          if (adapter->OperStatus == IfOperStatusUp && adapter->IfType != IF_TYPE_SOFTWARE_LOOPBACK) {
            for (IP_ADAPTER_UNICAST_ADDRESS *unicast = adapter->FirstUnicastAddress; unicast; unicast = unicast->Next) {
              SOCKADDR *addrStruct = unicast->Address.lpSockaddr;

              if ((!ipv6 && addrStruct->sa_family == AF_INET) || (ipv6 && addrStruct->sa_family == AF_INET6)) {
                char buffer[INET6_ADDRSTRLEN];
                if (ipv6) {
                  inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)addrStruct)->sin6_addr), buffer, INET6_ADDRSTRLEN);
                  // Skip loopback
                  if (strcmp(buffer, "::1") != 0) {
                    auto ma_str = "/ip6/" + std::string(buffer) + "/tcp/" + std::to_string(port);
                    auto ma_res = multi::Multiaddress::create(ma_str);
                    if (ma_res) {
                      addresses.push_back(ma_res.value());
                    }
                  }
                } else {
                  inet_ntop(AF_INET, &(((struct sockaddr_in *)addrStruct)->sin_addr), buffer, INET_ADDRSTRLEN);
                  // Skip loopback
                  if (strcmp(buffer, "127.0.0.1") != 0) {
                    auto ma_str = "/ip4/" + std::string(buffer) + "/tcp/" + std::to_string(port);
                    auto ma_res = multi::Multiaddress::create(ma_str);
                    if (ma_res) {
                      addresses.push_back(ma_res.value());
                    }
                  }
                }
              }
            }
          }
        }
      }
      free(adapterAddresses);
#else
      // Unix-like implementation using getifaddrs
      struct ifaddrs *ifaddr, *ifa;

      if (getifaddrs(&ifaddr) == -1) {
        logger->error("getifaddrs failed: {}", strerror(errno));
        return addresses;
      }

      for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr || (ifa->ifa_flags & IFF_LOOPBACK)) continue;

        int family = ifa->ifa_addr->sa_family;
        if ((!ipv6 && family == AF_INET) || (ipv6 && family == AF_INET6)) {
          char host[INET6_ADDRSTRLEN];
          size_t addr_size = ipv6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);

          int s = getnameinfo(ifa->ifa_addr, addr_size,
                            host, INET6_ADDRSTRLEN, nullptr, 0, NI_NUMERICHOST);
          if (s == 0) {
            // Skip loopback addresses
            if (strcmp(host, "127.0.0.1") != 0 && strcmp(host, "::1") != 0) {
              auto proto = ipv6 ? "ip6" : "ip4";
              auto ma_str = "/" + std::string(proto) + "/" + std::string(host) + "/tcp/" + std::to_string(port);
              auto ma_res = multi::Multiaddress::create(ma_str);
              if (ma_res) {
                addresses.push_back(ma_res.value());
              }
            }
          }
        }
      }
      freeifaddrs(ifaddr);
#endif
    } catch (const std::exception& e) {
      logger->error("Exception in enumerateNetworkInterfaces: {}", e.what());
    }

    logger->debug("Enumerated {} network interfaces for {}v{}", addresses.size(), ipv6 ? "IP" : "IP", ipv6 ? 6 : 4);
    return addresses;
  }

}  // namespace libp2p::transport
