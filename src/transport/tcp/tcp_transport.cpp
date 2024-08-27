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
                          multi::Multiaddress bindaddress) {
    dial(remoteId, std::move(address), std::move(handler),
         std::chrono::milliseconds::zero(), bindaddress);
  }

  void TcpTransport::dial(const peer::PeerId &remoteId,
                          multi::Multiaddress address,
                          TransportAdaptor::HandlerFunc handler,
                          std::chrono::milliseconds timeout,
                          multi::Multiaddress bindaddress) {
    if (!canDial(address)) {
      //TODO(107): Reentrancy

      return handler(std::errc::address_family_not_supported);
    }

    auto conn = std::make_shared<TcpConnection>(*context_);

    auto [host, port] = detail::getHostAndTcpPort(address);

    auto connect = [self{shared_from_this()}, conn, handler{std::move(handler)},
                    remoteId, timeout, bindaddress](auto ec, auto r) mutable {
      if (ec) {
        return handler(ec);
      }

      conn->connect(
          r,
          [self, conn, handler{std::move(handler)}, remoteId](auto ec,
                                                              auto &e) mutable {
            if (ec) {
              return handler(ec);
            }

            auto session = std::make_shared<UpgraderSession>(
                self->upgrader_, std::move(conn), handler);

            session->secureOutbound(remoteId);
          },
          timeout, bindaddress);
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
                                         std::move(handler));
  }

  bool TcpTransport::canDial(const multi::Multiaddress &ma) const {
    return detail::supportsIpTcp(ma);
  }

  TcpTransport::TcpTransport(std::shared_ptr<boost::asio::io_context> context,
                             std::shared_ptr<Upgrader> upgrader)
      : context_(std::move(context)), upgrader_(std::move(upgrader)) {
      increase_open_file_limit();
  }

  peer::Protocol TcpTransport::getProtocolId() const {
    return "/tcp/1.0.0";
  }

  void TcpTransport::increase_open_file_limit()
  {
#ifndef _WIN32
      struct rlimit limit;
      const rlim_t max_descriptors = 4096;  // Define a cap for file descriptors

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
}  // namespace libp2p::transport
