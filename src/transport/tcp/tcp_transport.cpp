/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <libp2p/transport/tcp/tcp_transport.hpp>

#include <libp2p/transport/impl/upgrader_session.hpp>
#include <iostream>

#ifndef _WIN32
#include <sys/resource.h>
#include <cstring>
#endif

namespace libp2p::transport {

  void TcpTransport::dial(const peer::PeerId &remoteId,
                          multi::Multiaddress address,
                          TransportAdaptor::HandlerFunc handler,
                          multi::Multiaddress bindaddress, bool holepunch, bool holepunchserver) {
    dial(remoteId, std::move(address), std::move(handler),
         std::chrono::milliseconds::zero(), bindaddress, holepunch, holepunchserver);
  }

  void TcpTransport::dial(const peer::PeerId &remoteId,
                          multi::Multiaddress address,
                          TransportAdaptor::HandlerFunc handler,
                          std::chrono::milliseconds timeout,
                          multi::Multiaddress bindaddress, bool holepunch, bool holepunchserver) {
    if (!canDial(address)) {
      //TODO(107): Reentrancy
      return handler(std::errc::address_family_not_supported);
    }

    // Loopback (127.0.0.0/8, ::1) destinations are rejected by default --
    // an SSRF-style safety control (restored, matching the pre-78de11e
    // shape) preventing a malicious/compromised peer's advertised PeerInfo
    // from inducing this node to dial its own loopback-bound services.
    // Opt-out-by-default: gated behind the DI-injectable AllowLoopbackDial
    // flag (see include/libp2p/transport/tcp/allow_loopback_dial.hpp),
    // which integrators enable per-composition via
    // injector::useAllowLoopbackDial() (network_injector.hpp) -- e.g.
    // test/acceptance/p2p/pnet/pnet_two_node_test.cpp, which legitimately
    // needs live loopback dialing between its DI-assembled nodes. See
    // .planning/phases/03-hardening-live-validation-documentation/03-UAT.md
    // test 1 for the resolution history.
    if (!allow_loopback_dial_.allow) {
      if (address.hasProtocol(libp2p::multi::Protocol::Code::IP4)
          && isLocalHost(address.getFirstValueForProtocol(
                 libp2p::multi::Protocol::Code::IP4)
                             .value())) {
        return handler(std::errc::bad_address);
      }
      if (address.hasProtocol(libp2p::multi::Protocol::Code::IP6)
          && isLocalHost(address.getFirstValueForProtocol(
                 libp2p::multi::Protocol::Code::IP6)
                             .value())) {
        return handler(std::errc::bad_address);
      }
    }

    auto conn = std::make_shared<TcpConnection>(*context_);

    auto [host, port] = detail::getHostAndTcpPort(address);

    auto connect = [self{shared_from_this()}, conn, handler{std::move(handler)},
                    remoteId, timeout, bindaddress, holepunch, holepunchserver](auto ec, auto r) mutable {
      if (ec) {
        return handler(ec);
      }

      conn->connect(
          r,
          [self, conn, handler{std::move(handler)}, remoteId, holepunch, holepunchserver](auto ec,
                                                              auto &e) mutable {
            if (ec) {
              conn->close();
              return handler(ec);
            }

            auto session = std::make_shared<UpgraderSession>(
                self->upgrader_, std::move(conn), handler, self->gater_,
                self->scheduler_);
            if (!holepunch || (holepunch && holepunchserver))
            {
                session->secureOutbound(remoteId);
            }
            else {
                session->secureInbound();
            }
          },
          timeout, bindaddress, holepunch, holepunchserver);
    };

    using P = multi::Protocol::Code;
    switch (detail::getFirstProtocol(address)) {
      case P::DNS4:
        return conn->resolve(boost::asio::ip::tcp::v4(), host, port, connect);
      case P::DNS6:
        return conn->resolve(boost::asio::ip::tcp::v6(), host, port, connect);
      default:  // Could be only DNS, IP6 or IP4 as canDial already checked for
                // that in the beginning of the method
        return conn->resolve(host, port, connect);
    }
  }

  std::shared_ptr<TransportListener> TcpTransport::createListener(
      TransportListener::HandlerFunc handler) {
    return std::make_shared<TcpListener>(*context_, upgrader_,
                                         std::move(handler), gater_,
                                         scheduler_);
  }

  bool TcpTransport::canDial(const multi::Multiaddress &ma) const {
    return detail::supportsIpTcp(ma);
  }

  bool TcpTransport::isLocalHost(const std::string& ip)
  {
      try {
          // Create an address object from the string
          boost::asio::ip::address address = boost::asio::ip::make_address(ip);

          // Check if it's an IPv4 address and compare with 127.0.0.1
          if (address.is_v4()) {
              return address.to_v4() == boost::asio::ip::address_v4::loopback();
          }

          // Check if it's an IPv6 address and compare with ::1
          if (address.is_v6()) {
              return address.to_v6() == boost::asio::ip::address_v6::loopback();
          }
      }
      catch (const std::exception& e) {
          // Handle invalid IP address format
          std::cerr << "Error: " << e.what() << std::endl;
          return false;
      }

      return false;
  }

  void TcpTransport::upgradeRelaySecure(const peer::PeerId& remoteId, std::shared_ptr<libp2p::connection::Stream> conn, TransportAdaptor::HandlerFunc handler)
  {
      auto session = std::make_shared<UpgraderSession>(
          upgrader_, std::move(conn), handler, gater_, scheduler_);

      session->secureOutboundRelay(remoteId);
  }

  TcpTransport::TcpTransport(std::shared_ptr<boost::asio::io_context> context,
                             std::shared_ptr<Upgrader> upgrader,
                             std::shared_ptr<network::ConnectionGater> gater,
                             std::shared_ptr<basic::Scheduler> scheduler,
                             AllowLoopbackDial allow_loopback_dial)
      : context_(std::move(context)), upgrader_(std::move(upgrader)),
        gater_(std::move(gater)), scheduler_(std::move(scheduler)),
        allow_loopback_dial_(std::move(allow_loopback_dial)) {
      increase_open_file_limit();
  }

  peer::Protocol TcpTransport::getProtocolId() const {
    return "/tcp/1.0.0";
  }

  void TcpTransport::increase_open_file_limit()
  {
#ifndef _WIN32
      struct rlimit limit;
      const rlim_t max_descriptors = 16384;  // Define a cap for file descriptors

      // Get current limits
      if (getrlimit(RLIMIT_NOFILE, &limit) == 0) {
          std::cout << "Current limits: " << limit.rlim_cur << " (soft), " << limit.rlim_max << " (hard)" << std::endl;

          // Set new soft limit to the minimum of the current hard limit and max_descriptors
          limit.rlim_cur = std::min(limit.rlim_max, max_descriptors);
          if (setrlimit(RLIMIT_NOFILE, &limit) != 0) {
              std::cerr << "Error setting new limits: " << strerror(errno) << std::endl;
          }
          else {
              std::cout << "New limits set successfully: " << limit.rlim_cur << " (soft), " << limit.rlim_max << " (hard)" << std::endl;
          }
      }
      else {
          std::cerr << "Error getting current limits: " << strerror(errno) << std::endl;
      }
#else
      std::cout << "File descriptor limit increase not needed on Windows." << std::endl;
#endif
  }

  void TcpTransport::dial(const peer::PeerId &remoteId,
                          multi::Multiaddress address,
                          TransportAdaptor::HandlerFunc handler,
                          const libp2p::network::RouteHelper::SourceAddresses &source_addresses, bool holepunch, bool holepunchserver) {
    dial(remoteId, std::move(address), std::move(handler),
         std::chrono::milliseconds::zero(), source_addresses, holepunch, holepunchserver);
  }

  void TcpTransport::dial(const peer::PeerId &remoteId,
                          multi::Multiaddress address,
                          TransportAdaptor::HandlerFunc handler,
                          std::chrono::milliseconds timeout,
                          const libp2p::network::RouteHelper::SourceAddresses &source_addresses, bool holepunch, bool holepunchserver) {
    if (!canDial(address)) {
      //TODO(107): Reentrancy
      return handler(std::errc::address_family_not_supported);
    }

    // Loopback (127.0.0.0/8, ::1) destinations are rejected by default --
    // see the matching note in the other dial() overload above; gated
    // behind the same AllowLoopbackDial flag.
    if (!allow_loopback_dial_.allow) {
      if (address.hasProtocol(libp2p::multi::Protocol::Code::IP4)
          && isLocalHost(address.getFirstValueForProtocol(
                 libp2p::multi::Protocol::Code::IP4)
                             .value())) {
        return handler(std::errc::bad_address);
      }
      if (address.hasProtocol(libp2p::multi::Protocol::Code::IP6)
          && isLocalHost(address.getFirstValueForProtocol(
                 libp2p::multi::Protocol::Code::IP6)
                             .value())) {
        return handler(std::errc::bad_address);
      }
    }

    auto conn = std::make_shared<TcpConnection>(*context_);

    auto [host, port] = detail::getHostAndTcpPort(address);

    auto connect = [self{shared_from_this()}, conn, handler{std::move(handler)},
                    remoteId, timeout, source_addresses, holepunch, holepunchserver](auto ec, auto r) mutable {
      if (ec) {
        return handler(ec);
      }

      conn->connect(
          r,
          [self, conn, handler{std::move(handler)}, remoteId, holepunch, holepunchserver](auto ec,
                                                              auto &e) mutable {
            if (ec) {
              return handler(ec);
            }

            auto session = std::make_shared<UpgraderSession>(
                self->upgrader_, std::move(conn), handler, self->gater_,
                self->scheduler_);
            if (!holepunch || (holepunch && holepunchserver))
            {
                session->secureOutbound(remoteId);
            }
            else {
                session->secureInbound();
            }
          },
          timeout, source_addresses, holepunch, holepunchserver);
    };

    using P = multi::Protocol::Code;
    switch (detail::getFirstProtocol(address)) {
      case P::DNS4:
        return conn->resolve(boost::asio::ip::tcp::v4(), host, port, connect);
      case P::DNS6:
        return conn->resolve(boost::asio::ip::tcp::v6(), host, port, connect);
      default:  // Could be only DNS, IP6 or IP4 as canDial already checked for
                // that in the beginning of the method
        return conn->resolve(host, port, connect);
    }
  }
}  // namespace libp2p::transport
