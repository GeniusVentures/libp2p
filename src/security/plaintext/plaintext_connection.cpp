/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <libp2p/security/plaintext/plaintext_connection.hpp>

#include <boost/assert.hpp>
#include "libp2p/crypto/protobuf/protobuf_key.hpp"

namespace libp2p::connection {

  PlaintextConnection::PlaintextConnection(
      std::shared_ptr<RawConnection> raw_connection,
      crypto::PublicKey localPubkey, crypto::PublicKey remotePubkey,
      std::shared_ptr<crypto::marshaller::KeyMarshaller> key_marshaller)
      : connection_{std::move(raw_connection)},
        local_(std::move(localPubkey)),
        remote_(std::move(remotePubkey)),
        key_marshaller_{std::move(key_marshaller)} {
    BOOST_ASSERT(std::get<std::shared_ptr<RawConnection>>(connection_));
    BOOST_ASSERT(key_marshaller_);
  }

  PlaintextConnection::PlaintextConnection(
      std::shared_ptr<Stream> stream,
      crypto::PublicKey localPubkey, crypto::PublicKey remotePubkey,
      std::shared_ptr<crypto::marshaller::KeyMarshaller> key_marshaller)
      : connection_{ std::move(stream) },
      local_(std::move(localPubkey)),
      remote_(std::move(remotePubkey)),
      key_marshaller_{ std::move(key_marshaller) } {
      BOOST_ASSERT(std::get<std::shared_ptr<Stream>>(connection_));
      BOOST_ASSERT(key_marshaller_);
  }


  outcome::result<peer::PeerId> PlaintextConnection::localPeer() const {
    auto proto_local_key_res = key_marshaller_->marshal(local_);
    if (!proto_local_key_res) {
      return proto_local_key_res.error();
    }
    return peer::PeerId::fromPublicKey(proto_local_key_res.value());
  }

  outcome::result<peer::PeerId> PlaintextConnection::remotePeer() const {
    auto proto_remote_key_res = key_marshaller_->marshal(remote_);
    if (!proto_remote_key_res) {
      return proto_remote_key_res.error();
    }
    return peer::PeerId::fromPublicKey(proto_remote_key_res.value());
  }

  outcome::result<crypto::PublicKey> PlaintextConnection::remotePublicKey()
      const {
    return remote_;
  }

  bool PlaintextConnection::isInitiator() const noexcept {
      // Check if the connection is a Stream first because a Stream could be detected as a RawConnection
      if (auto stream_conn = std::get_if<std::shared_ptr<Stream>>(&connection_)) {
          auto result = (*stream_conn)->isInitiator();
          if (result.has_value()) {
              return result.value();
          }
          log_->error("Failed to get isInitiator from Stream: {}", result.error().message());
          return false;
      }

      // Then check if the connection is a RawConnection
      if (auto raw_conn = std::get_if<std::shared_ptr<RawConnection>>(&connection_)) {
          return (*raw_conn)->isInitiator();
      }

      // If neither type matches, return false
      return false;
  }


  outcome::result<multi::Multiaddress> PlaintextConnection::localMultiaddr() {
    return std::visit([](auto&& conn) { return conn->localMultiaddr(); }, connection_);
    //return raw_connection_->localMultiaddr();
  }

  outcome::result<multi::Multiaddress> PlaintextConnection::remoteMultiaddr() {
    return std::visit([](auto&& conn) { return conn->remoteMultiaddr(); }, connection_);
    //return raw_connection_->remoteMultiaddr();
  }

  void PlaintextConnection::read(gsl::span<uint8_t> in, size_t bytes,
                                 Reader::ReadCallbackFunc f) {
    return std::visit([in, bytes, f](auto&& conn) { return conn->read(in, bytes, std::move(f)); }, connection_);
    //return raw_connection_->read(in, bytes, std::move(f));
  };

  void PlaintextConnection::readSome(gsl::span<uint8_t> in,
                                     size_t bytes,
                                     Reader::ReadCallbackFunc f) {
    return std::visit([in, bytes, f](auto&& conn) { return conn->readSome(in, bytes, std::move(f)); }, connection_);
    //return raw_connection_->readSome(in, bytes, std::move(f));
  };

  void PlaintextConnection::write(gsl::span<const uint8_t> in, size_t bytes,
                                  Writer::WriteCallbackFunc f) {
    return std::visit([in, bytes, f](auto&& conn) { return conn->write(in, bytes, std::move(f)); }, connection_);
    //return raw_connection_->write(in, bytes, std::move(f));
  }

  void PlaintextConnection::writeSome(gsl::span<const uint8_t> in, size_t bytes,
                                      Writer::WriteCallbackFunc f) {
    return std::visit([in, bytes, f](auto&& conn) { return conn->writeSome(in, bytes, std::move(f)); }, connection_);
    //return raw_connection_->writeSome(in, bytes, std::move(f));
  }

  void PlaintextConnection::deferReadCallback(outcome::result<size_t> res,
                                         ReadCallbackFunc cb) {
    return std::visit([res, cb](auto&& conn) { return conn->deferReadCallback(res, std::move(cb)); }, connection_);
    //raw_connection_->deferReadCallback(res, std::move(cb));
  }

  void PlaintextConnection::deferWriteCallback(std::error_code ec,
                                          WriteCallbackFunc cb) {
    return std::visit([ec, cb](auto&& conn) { return conn->deferWriteCallback(ec, std::move(cb)); }, connection_);
    //raw_connection_->deferWriteCallback(ec, std::move(cb));
  }

  bool PlaintextConnection::isClosed() const {
    return std::visit([](auto&& conn) { return conn->isClosed(); }, connection_);
    //return raw_connection_->isClosed();
  }

  outcome::result<void> PlaintextConnection::close() {
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
  outcome::result<std::shared_ptr<RawConnection>> PlaintextConnection::getRawConnection() const
  {
      auto raw_conn = std::get_if<std::shared_ptr<RawConnection>>(&connection_);
      return *raw_conn;
  }
}  // namespace libp2p::connection
