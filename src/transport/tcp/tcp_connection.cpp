/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <libp2p/transport/tcp/tcp_connection.hpp>

#include <libp2p/transport/tcp/tcp_util.hpp>

#define TRACE_ENABLED 0
#include <libp2p/common/trace.hpp>
#include <iostream>

namespace libp2p::transport {

  namespace {
    auto &log() {
      static auto logger = log::createLogger("tcp-conn");
      return *logger;
    }

    inline std::error_code convert(boost::system::errc::errc_t ec) {
      return std::error_code(static_cast<int>(ec), std::system_category());
    }

    inline std::error_code convert(std::error_code ec) {
      return ec;
    }
  }  // namespace
  TcpConnection::TcpConnection(boost::asio::io_context &ctx,
                               boost::asio::ip::tcp::socket &&socket)
      : context_(ctx),
        socket_(std::move(socket)),
        connection_phase_done_{false},
        deadline_timer_(context_) {
    std::ignore = saveMultiaddresses();
  }

  TcpConnection::TcpConnection(boost::asio::io_context &ctx)
      : context_(ctx),
        socket_(context_),
        connection_phase_done_{false},
        deadline_timer_(context_) {}

  outcome::result<void> TcpConnection::close() {
    closed_by_host_ = true;
    close(convert(boost::system::errc::connection_aborted));
    return outcome::success();
  }

  void TcpConnection::close(std::error_code reason) {
    assert(reason);

    if (!close_reason_) {
      close_reason_ = reason;
      log().debug("{} closing with reason: {}", debug_str_,
                  close_reason_.message());
    }
    if (socket_.is_open()) {
      boost::system::error_code ec;
      socket_.close(ec);
    }
  }

  bool TcpConnection::isClosed() const {
    return closed_by_host_ || !socket_.is_open();
  }

  outcome::result<multi::Multiaddress> TcpConnection::remoteMultiaddr() {
    if (!remote_multiaddress_) {
      auto res = saveMultiaddresses();
      if (!res) {
        return res.error();
      }
    }
    return remote_multiaddress_.value();
  }

  outcome::result<multi::Multiaddress> TcpConnection::localMultiaddr() {
    if (!local_multiaddress_) {
      auto res = saveMultiaddresses();
      if (!res) {
        return res.error();
      }
    }
    return local_multiaddress_.value();
  }

  bool TcpConnection::isInitiator() const noexcept {
    return initiator_;
  }

  namespace {
    template <typename Callback>
    auto closeOnError(TcpConnection &conn, Callback cb) {
      return [cb{std::move(cb)}, wptr{conn.weak_from_this()}](auto ec,
                                                              auto result) {
        if (!wptr.expired()) {
          if (ec) {
            wptr.lock()->close(convert(ec));
            return cb(std::forward<decltype(ec)>(ec));
          }
          TRACE("{} {}", wptr.lock()->str(), result);
          cb(result);
        } else {
          log().debug("connection wptr expired");
        }
      };
    }
  }  // namespace

  void TcpConnection::resolve(const TcpConnection::Tcp::endpoint &endpoint,
                              TcpConnection::ResolveCallbackFunc cb) {
    auto resolver = std::make_shared<Tcp::resolver>(context_);
    resolver->async_resolve(
        endpoint,
        [wptr{weak_from_this()}, resolver, cb{std::move(cb)}](
            const ErrorCode &ec, auto &&iterator) {
          if (!wptr.expired()) {
            cb(ec, std::forward<decltype(iterator)>(iterator));
          }
        });
  }

  void TcpConnection::resolve(const std::string &host_name,
                              const std::string &port,
                              TcpConnection::ResolveCallbackFunc cb) {
    auto resolver = std::make_shared<Tcp::resolver>(context_);
    resolver->async_resolve(
        host_name, port,
        [wptr{weak_from_this()}, resolver, cb{std::move(cb)}](
            const ErrorCode &ec, auto &&iterator) {
          if (!wptr.expired()) {
            cb(ec, std::forward<decltype(iterator)>(iterator));
          }
        });
  }

  void TcpConnection::resolve(const TcpConnection::Tcp &protocol,
                              const std::string &host_name,
                              const std::string &port,
                              TcpConnection::ResolveCallbackFunc cb) {
    auto resolver = std::make_shared<Tcp::resolver>(context_);
    resolver->async_resolve(
        protocol, host_name, port,
        [wptr{weak_from_this()}, resolver, cb{std::move(cb)}](
            const ErrorCode &ec, auto &&iterator) {
          if (!wptr.expired()) {
            cb(ec, std::forward<decltype(iterator)>(iterator));
          }
        });
  }

  void TcpConnection::connect(
      const TcpConnection::ResolverResultsType &iterator,
      TcpConnection::ConnectCallbackFunc cb, multi::Multiaddress bindaddress, bool holepunch, bool holepunchserver) {
    connect(iterator, std::move(cb), std::chrono::milliseconds::zero(), bindaddress, holepunch, holepunchserver);
  }

#include <functional>  // Include this to use std::function

  void TcpConnection::connect(
      const TcpConnection::ResolverResultsType& iterator,
      ConnectCallbackFunc cb, std::chrono::milliseconds timeout, multi::Multiaddress bindaddress, bool holepunch, bool holepunchserver) {
      if (timeout > std::chrono::milliseconds::zero()) {
          connecting_with_timeout_ = true;
          deadline_timer_.expires_from_now(
              boost::posix_time::milliseconds(timeout.count()));
          deadline_timer_.async_wait(
              [wptr{ weak_from_this() }, cb](const boost::system::error_code& error) {
                  auto self = wptr.lock();
                  if (!self || self->closed_by_host_) {
                      self->socket_.close();
                      return;
                  }
                  bool expected = false;
                  if (self->connection_phase_done_.compare_exchange_strong(expected, true)) {
                      if (!error) {
                          // timeout happened, timer expired before connection was
                          // established
                          cb(boost::system::error_code{ boost::system::errc::timed_out,
                                                        boost::system::generic_category() },
                              Tcp::endpoint{});
                          self->socket_.close();
                      }
                      // Another case is: boost::asio::error::operation_aborted == error
                      // connection was established before timeout and timer has been
                      // cancelled
                  }
              });
      }
      //Get address to bind to from MA
      std::string ip_address;
      uint16_t port;
      auto ip_address_opt = bindaddress.getFirstValueForProtocol(libp2p::multi::Protocol::Code::IP4);
      if (!ip_address_opt) {
          std::cerr << "Error: IP address not found in Multiaddress" << std::endl;
          return;
      }
      ip_address = ip_address_opt.value();

      auto port_opt = bindaddress.getFirstValueForProtocol(libp2p::multi::Protocol::Code::TCP);
      if (!port_opt) {
          std::cerr << "Error: Port not found in Multiaddress" << std::endl;
          return;
      }
      port = static_cast<uint16_t>(std::stoi(port_opt.value()));
      //Bind with reuse port.
      boost::system::error_code reec;
      boost::asio::ip::tcp::endpoint local_endpoint(boost::asio::ip::make_address(ip_address), port);
      socket_.open(boost::asio::ip::tcp::v4());
      boost::asio::socket_base::reuse_address option(true);
      socket_.set_option(option, reec);
      if (reec) {
          std::cerr << "Error setting reuse address: " << reec.message() << std::endl;
          socket_.close();
          return;
      }
#ifdef SO_REUSEPORT
      boost::asio::detail::socket_option::boolean<SOL_SOCKET, SO_REUSEPORT> reuse_port_option(true);
      socket_.set_option(reuse_port_option, reec);
#endif

      socket_.bind(local_endpoint, reec);
      if (reec) {
          std::cerr << "Error binding socket: " << reec.message() << std::endl;
          socket_.close();
          return;
      }

      if (iterator.begin() != iterator.end()) {
          auto iter = iterator.begin();
          auto end = iterator.end();
          //std::cout << "Connect to: " << iter->endpoint().address().to_string() << std::endl;;
          auto connect_next = std::make_shared<std::function<void(boost::asio::ip::tcp::resolver::results_type::const_iterator)>>();

          *connect_next = [this, wptr{ weak_from_this() }, cb, local_endpoint, connect_next, end, holepunch, holepunchserver]
          (boost::asio::ip::tcp::resolver::results_type::const_iterator iter) mutable {
              auto self = wptr.lock();
              if (!self || self->closed_by_host_) {
                  self->socket_.close();
                  return;
              }

              socket_.async_connect(*iter, [this, wptr, cb, iter, end, local_endpoint, connect_next, holepunch, holepunchserver](const boost::system::error_code& ec) mutable {
                  auto self = wptr.lock();
                  if (!self || self->closed_by_host_) {
                      self->socket_.close();
                      return;
                  }

                  if (!ec) {
                      // Connection successful
                      if (self->connecting_with_timeout_) {
                          self->deadline_timer_.cancel();
                      }
                      self->initiator_ = true;
                      if (holepunch)
                      {
                          if (!holepunchserver)
                          {
                              self->initiator_ = false;
                          }
                      }
                      std::ignore = self->saveMultiaddresses();
                      cb(ec, self->socket_.remote_endpoint());
                  }
                  else if (++iter != end) {
                      // Try the next endpoint
                      self->socket_.close();
                      self->socket_.open(boost::asio::ip::tcp::v4());
                      boost::asio::socket_base::reuse_address option(true);
                      self->socket_.set_option(option);

#ifdef SO_REUSEPORT
                      boost::asio::detail::socket_option::boolean<SOL_SOCKET, SO_REUSEPORT> reuse_port_option(true);
                      self->socket_.set_option(reuse_port_option);
#endif

                      self->socket_.bind(local_endpoint);
                      std::cout << "Iterate" << std::endl;
                      (*connect_next)(iter);  // Recursively call the function through the shared_ptr
                  }
                  else {
                      // All endpoints tried and failed
                      cb(ec, Tcp::endpoint{});
                      self->socket_.close();
                  }
                  });
              };

          // Start the first connection attempt
          (*connect_next)(iterator.begin());
      }
      else {
          // No endpoints available, handle the error
          cb(boost::system::error_code{ boost::system::errc::address_not_available, boost::system::generic_category() }, Tcp::endpoint{});
          socket_.close();
      }
  }



  void TcpConnection::read(gsl::span<uint8_t> out, size_t bytes,
                           TcpConnection::ReadCallbackFunc cb) {
    TRACE("{} read {}", debug_str_, bytes);
    boost::asio::async_read(socket_, detail::makeBuffer(out, bytes),
                            closeOnError(*this, std::move(cb)));
  }

  void TcpConnection::readSome(gsl::span<uint8_t> out, size_t bytes,
                               TcpConnection::ReadCallbackFunc cb) {
    TRACE("{} read some up to {}", debug_str_, bytes);
    socket_.async_read_some(detail::makeBuffer(out, bytes),
                            closeOnError(*this, std::move(cb)));
  }

  void TcpConnection::write(gsl::span<const uint8_t> in, size_t bytes,
                            TcpConnection::WriteCallbackFunc cb) {
    TRACE("{} write {}", debug_str_, bytes);
    boost::asio::async_write(socket_, detail::makeBuffer(in, bytes),
                             closeOnError(*this, std::move(cb)));
  }

  void TcpConnection::writeSome(gsl::span<const uint8_t> in, size_t bytes,
                                TcpConnection::WriteCallbackFunc cb) {
    TRACE("{} write some up to {}", debug_str_, bytes);
    socket_.async_write_some(detail::makeBuffer(in, bytes),
                             closeOnError(*this, std::move(cb)));
  }

  namespace {
    template <typename Callback, typename Arg>
    void deferCallback(boost::asio::io_context &ctx,
                       std::weak_ptr<TcpConnection> wptr, bool &closed_by_host,
                       Callback cb, Arg arg) {
      // defers callback to the next event loop cycle,
      // cb will be called iff TcpConnection is still alive
      // and was not closed by host's side
      boost::asio::post(
          ctx,
          [wptr = std::move(wptr), cb = std::move(cb), arg, &closed_by_host]() {
            if (!wptr.expired() && !closed_by_host) {
              cb(arg);
            }
          });
    }
  }  // namespace

  void TcpConnection::deferReadCallback(outcome::result<size_t> res,
                                        ReadCallbackFunc cb) {
    deferCallback(context_, weak_from_this(), std::ref(closed_by_host_),
                  std::move(cb), res);
  }

  void TcpConnection::deferWriteCallback(std::error_code ec,
                                         WriteCallbackFunc cb) {
    deferCallback(context_, weak_from_this(), std::ref(closed_by_host_),
                  std::move(cb), ec);
  }

  outcome::result<void> TcpConnection::saveMultiaddresses() {
    boost::system::error_code ec;
    if (socket_.is_open()) {
      if (!local_multiaddress_) {
        auto endpoint(socket_.local_endpoint(ec));
        if (!ec) {
          OUTCOME_TRY((auto &&, addr), detail::makeAddress(endpoint));
          local_multiaddress_ = std::move(addr);
        }
      }
      if (!remote_multiaddress_) {
        auto endpoint(socket_.remote_endpoint(ec));
        if (!ec) {
          OUTCOME_TRY((auto &&, addr), detail::makeAddress(endpoint));
          remote_multiaddress_ = std::move(addr);
        }
      }
    } else {
      return convert(boost::system::errc::not_connected);
    }
    if (ec) {
      return convert(ec);
    }
#ifndef NDEBUG
    debug_str_ = fmt::format(
        "{} {} {}", local_multiaddress_->getStringAddress(),
        initiator_ ? "->" : "<-", remote_multiaddress_->getStringAddress());
#endif
    return outcome::success();
  }

}  // namespace libp2p::transport
