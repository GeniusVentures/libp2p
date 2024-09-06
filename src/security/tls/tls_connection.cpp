/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "tls_connection.hpp"
#include "tls_details.hpp"

namespace libp2p::connection {

  using TlsError = security::TlsError;
  using security::tls_details::log;

  namespace {
    template <typename Span>
    inline auto makeBuffer(Span s, size_t size) {
      return boost::asio::buffer(s.data(), size);
    }

    template <typename Span>
    inline auto makeBuffer(Span s) {
      return boost::asio::buffer(s.data(), s.size());
    }
  }  // namespace

  TlsConnection::TlsConnection(
      std::shared_ptr<RawConnection> raw_connection,
      std::shared_ptr<boost::asio::ssl::context> ssl_context,
      const peer::IdentityManager &idmgr, tcp_socket_t &tcp_socket,
      boost::optional<peer::PeerId> remote_peer)
      : local_peer_(idmgr.getId()),
      connection_(std::move(raw_connection)),
        ssl_context_(std::move(ssl_context)),
        socket_(std::ref(tcp_socket), *ssl_context_),
        remote_peer_(std::move(remote_peer)) {}

  TlsConnection::TlsConnection(
      std::shared_ptr<Stream> raw_connection,
      std::shared_ptr<boost::asio::ssl::context> ssl_context,
      const peer::IdentityManager& idmgr, tcp_socket_t& tcp_socket,
      boost::optional<peer::PeerId> remote_peer)
      : local_peer_(idmgr.getId()),
      connection_(std::move(raw_connection)),
      ssl_context_(std::move(ssl_context)),
      socket_(std::ref(tcp_socket), *ssl_context_),
      remote_peer_(std::move(remote_peer)) {}

  void TlsConnection::asyncHandshake(
      HandshakeCallback cb,
      std::shared_ptr<crypto::marshaller::KeyMarshaller> key_marshaller) {
      bool is_client = isInitiator();
        
        //raw_connection_->isInitiator();

    socket_.async_handshake(is_client ? boost::asio::ssl::stream_base::client
                                      : boost::asio::ssl::stream_base::server,
                            [self = shared_from_this(), cb = std::move(cb),
                             key_marshaller = std::move(key_marshaller)](
                                const boost::system::error_code &error) {
                              self->onHandshakeResult(error, cb,
                                                      *key_marshaller);
                            });
  }

  void TlsConnection::onHandshakeResult(
      const boost::system::error_code &error, const HandshakeCallback &cb,
      const crypto::marshaller::KeyMarshaller &key_marshaller) {
    std::error_code ec = error;
    while (!ec) {
      X509 *cert = SSL_get_peer_certificate(socket_.native_handle());
      if (cert == nullptr) {
        ec = TlsError::TLS_NO_CERTIFICATE;
        break;
      }
      auto id_res = security::tls_details::verifyPeerAndExtractIdentity(
          cert, key_marshaller);
      if (!id_res) {
        ec = id_res.error();
        break;
      }
      auto &id = id_res.value();
      if (remote_peer_.has_value()) {
        if (remote_peer_.value() != id.peer_id) {
          SL_DEBUG(log(), "peer ids mismatch: expected={}, got={}",
                      remote_peer_.value().toBase58(), id.peer_id.toBase58());
          ec = TlsError::TLS_UNEXPECTED_PEER_ID;
          break;
        }
      } else {
        remote_peer_ = std::move(id.peer_id);
      }
      remote_pubkey_ = std::move(id.public_key);

      SL_DEBUG(log(), "handshake success for {}bound connection to {}",
                  (isInitiator() ? "out" : "in"),
                  remote_peer_->toBase58());
      return cb(shared_from_this());
    }

    assert(ec);

    log()->info("handshake error: {}", ec.message());
    if (auto close_res = close(); !close_res) {
      log()->info("cannot close raw connection: {}",
                 close_res.error().message());
    }
    return cb(ec);
  }

  outcome::result<peer::PeerId> TlsConnection::localPeer() const {
    return local_peer_;
  }

  outcome::result<peer::PeerId> TlsConnection::remotePeer() const {
    if (!remote_peer_) {
      return TlsError::TLS_REMOTE_PEER_NOT_AVAILABLE;
    }
    return remote_peer_.value();
  }

  outcome::result<crypto::PublicKey> TlsConnection::remotePublicKey() const {
    if (!remote_pubkey_) {
      return TlsError::TLS_REMOTE_PUBKEY_NOT_AVAILABLE;
    }
    return remote_pubkey_.value();
  }

  bool TlsConnection::isInitiator() const noexcept {
      return std::visit([self{ shared_from_this() }](const auto& conn) -> bool {
          if constexpr (std::is_same_v<std::shared_ptr<RawConnection>, decltype(conn)>) {
              // RawConnection case: returns bool directly
              return conn->isInitiator();
          }
          else if constexpr (std::is_same_v<std::shared_ptr<Stream>, decltype(conn)>) {
              // Stream case: returns outcome::result<bool>
              auto result = conn->isInitiator();
              if (result.has_value()) {
                  return result.value();  // Return the value if no error
              }
              // Handle the error case
              self->log_->error("Failed to get isInitiator from Stream: {}", result.error().message());
              return false;
          }
          else {
              return false;
          }
          }, connection_);
  }

  outcome::result<multi::Multiaddress> TlsConnection::localMultiaddr() {
      return std::visit([](auto&& conn) { return conn->localMultiaddr(); }, connection_);
  }

  outcome::result<multi::Multiaddress> TlsConnection::remoteMultiaddr() {
      return std::visit([](auto&& conn) { return conn->remoteMultiaddr(); }, connection_);
  }

  template <typename Callback>
  auto closeOnError(TlsConnection &conn, Callback cb) {
    return [cb{std::move(cb)}, conn{conn.shared_from_this()}](auto &&ec,
                                                              auto &&result) {
      if (ec) {
        SL_DEBUG(log(), "connection async op error {}", ec.message());
        std::ignore = conn->close();
        return cb(std::forward<decltype(ec)>(ec));
      }
      cb(std::forward<decltype(result)>(result));
    };
  }

  void TlsConnection::read(gsl::span<uint8_t> out, size_t bytes,
                           Reader::ReadCallbackFunc f) {
    SL_TRACE(log(), "reading {} bytes", bytes);
    boost::asio::async_read(socket_, makeBuffer(out, bytes),
                            closeOnError(*this, std::move(f)));
  }

  void TlsConnection::readSome(gsl::span<uint8_t> out, size_t bytes,
                               Reader::ReadCallbackFunc cb) {
    SL_TRACE(log(), "reading some up to {} bytes", bytes);
    socket_.async_read_some(makeBuffer(out, bytes),
                            closeOnError(*this, std::move(cb)));
  }

  void TlsConnection::deferReadCallback(outcome::result<size_t> res,
                                        Reader::ReadCallbackFunc cb) {
      std::visit([res, cb](auto&& conn) { conn->deferReadCallback(res, std::move(cb)); }, connection_);
  }

  void TlsConnection::write(gsl::span<const uint8_t> in, size_t bytes,
                            Writer::WriteCallbackFunc cb) {
    SL_TRACE(log(), "writing {} bytes", bytes);
    boost::asio::async_write(socket_, makeBuffer(in, bytes),
                             closeOnError(*this, std::move(cb)));
  }

  void TlsConnection::writeSome(gsl::span<const uint8_t> in, size_t bytes,
                                Writer::WriteCallbackFunc cb) {
    SL_TRACE(log(), "writing some up to {} bytes", bytes);
    socket_.async_write_some(makeBuffer(in, bytes),
                             closeOnError(*this, std::move(cb)));
  }

  void TlsConnection::deferWriteCallback(std::error_code ec,
                                         Writer::WriteCallbackFunc cb) {
      std::visit([ec, cb](auto&& conn) { conn->deferWriteCallback(ec, std::move(cb)); }, connection_);
  }

  bool TlsConnection::isClosed() const {
      return std::visit([](auto&& conn) { return conn->isClosed(); }, connection_);
  }

  outcome::result<void> TlsConnection::close() {
      return std::visit([this](auto& conn) -> outcome::result<void> {
          if constexpr (std::is_same_v<decltype(conn), std::shared_ptr<RawConnection>>) {
              // For RawConnection, directly return the result of close()
              return conn->close();
          }
          else if constexpr (std::is_same_v<decltype(conn), std::shared_ptr<Stream>>) {
              // For Stream, handle the close operation asynchronously using a lambda
              conn->close([](outcome::result<void> res) {
                  return res;  // Just return the result and let the caller handle it
                  });
              // Return success immediately since close is now async
              return outcome::success();
          }
          return outcome::failure(std::make_error_code(std::errc::invalid_argument));  // Fallback in case neither type matches
          }, connection_);
  }
}  // namespace libp2p::connection
