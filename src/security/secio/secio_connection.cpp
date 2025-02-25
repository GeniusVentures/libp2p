/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <libp2p/security/secio/secio_connection.hpp>

#include <algorithm>

#include <arpa/inet.h>
#include <libp2p/common/byteutil.hpp>
#include <libp2p/crypto/aes_ctr/aes_ctr_impl.hpp>
#include <libp2p/crypto/error.hpp>
#include <libp2p/crypto/hmac_provider.hpp>
#include <libp2p/outcome/outcome.hpp>

OUTCOME_CPP_DEFINE_CATEGORY_3(libp2p::connection, SecioConnection::Error, e) {
  using E = libp2p::connection::SecioConnection::Error;
  switch (e) {
    case E::CONN_NOT_INITIALIZED:
      return "Connection is not initialized";
    case E::CONN_ALREADY_INITIALIZED:
      return "Connection was already initialized";
    case E::INITALIZATION_FAILED:
      return "Connection initialization failed";
    case E::UNSUPPORTED_CIPHER:
      return "Unsupported cipher algorithm is used";
    case E::UNSUPPORTED_HASH:
      return "Unsupported hash algorithm is used";
    case E::INVALID_MAC:
      return "Received message has an invalid signature";
    case E::TOO_SHORT_BUFFER:
      return "Provided buffer is too short";
    case E::NOTHING_TO_READ:
      return "Zero bytes available to read";
    case E::STREAM_IS_BROKEN:
      return "Stream cannot be read. Frames are corrupted";
    case E::OVERSIZED_FRAME:
      return "Frame exceeds the maximum allowed size";
    default:
      return "Unknown error";
  }
}

#ifndef _UNIQUE_NAME_
#define _UNIQUE_NAME_(base) base##__LINE__
#endif  // _UNIQUE_NAME_

#define IO_OUTCOME_TRY_NAME(var, val, res, cb) \
  auto && (var) = (res);                       \
  if ((var).has_error()) {                     \
    cb((var).error());                         \
    return;                                    \
  }                                            \
  auto && (val) = (var).value();

#define IO_OUTCOME_TRY(name, res, cb) \
  IO_OUTCOME_TRY_NAME(_UNIQUE_NAME_(name), name, res, cb)

namespace {
  template <typename AesSecretType>
  libp2p::outcome::result<AesSecretType> initAesSecret(
      const libp2p::common::ByteArray &key,
      const libp2p::common::ByteArray &iv) {
    AesSecretType secret{};
    if (key.size() != secret.key.size()) {
      return libp2p::crypto::OpenSslError::WRONG_KEY_SIZE;
    }
    if (iv.size() != secret.iv.size()) {
      return libp2p::crypto::OpenSslError::WRONG_IV_SIZE;
    }
    std::copy(key.begin(), key.end(), secret.key.begin());
    std::copy(iv.begin(), iv.end(), secret.iv.begin());
    return secret;
  }
}  // namespace

namespace libp2p::connection {

  SecioConnection::SecioConnection(
      std::shared_ptr<RawConnection> raw_connection,
      std::shared_ptr<crypto::hmac::HmacProvider> hmac_provider,
      std::shared_ptr<crypto::marshaller::KeyMarshaller> key_marshaller,
      crypto::PublicKey local_pubkey, crypto::PublicKey remote_pubkey,
      crypto::common::HashType hash_type,
      crypto::common::CipherType cipher_type,
      crypto::StretchedKey local_stretched_key,
      crypto::StretchedKey remote_stretched_key)
      : connection_{std::move(raw_connection)},
        hmac_provider_{std::move(hmac_provider)},
        key_marshaller_{std::move(key_marshaller)},
        local_{std::move(local_pubkey)},
        remote_{std::move(remote_pubkey)},
        hash_type_{hash_type},
        cipher_type_{cipher_type},
        local_stretched_key_{std::move(local_stretched_key)},
        remote_stretched_key_{std::move(remote_stretched_key)},
        aes128_secrets_{boost::none},
        aes256_secrets_{boost::none} {
    BOOST_ASSERT(std::get<std::shared_ptr<RawConnection>>(connection_));
    BOOST_ASSERT(hmac_provider_);
    BOOST_ASSERT(key_marshaller_);
  }

  SecioConnection::SecioConnection(
      std::shared_ptr<Stream> raw_connection,
      std::shared_ptr<crypto::hmac::HmacProvider> hmac_provider,
      std::shared_ptr<crypto::marshaller::KeyMarshaller> key_marshaller,
      crypto::PublicKey local_pubkey, crypto::PublicKey remote_pubkey,
      crypto::common::HashType hash_type,
      crypto::common::CipherType cipher_type,
      crypto::StretchedKey local_stretched_key,
      crypto::StretchedKey remote_stretched_key)
      : connection_{ std::move(raw_connection) },
      hmac_provider_{ std::move(hmac_provider) },
      key_marshaller_{ std::move(key_marshaller) },
      local_{ std::move(local_pubkey) },
      remote_{ std::move(remote_pubkey) },
      hash_type_{ hash_type },
      cipher_type_{ cipher_type },
      local_stretched_key_{ std::move(local_stretched_key) },
      remote_stretched_key_{ std::move(remote_stretched_key) },
      aes128_secrets_{ boost::none },
      aes256_secrets_{ boost::none } {
      BOOST_ASSERT(std::get<std::shared_ptr<Stream>>(connection_));
      BOOST_ASSERT(hmac_provider_);
      BOOST_ASSERT(key_marshaller_);
  }

  outcome::result<void> SecioConnection::init() {
    if (isInitialized()) {
      return Error::CONN_ALREADY_INITIALIZED;
    }

    using CT = crypto::common::CipherType;
    using AesCtrMode = crypto::aes::AesCtrImpl::Mode;
    if (cipher_type_ == CT::AES128) {
      OUTCOME_TRY(
              (auto &&, local_128),
          initAesSecret<crypto::common::Aes128Secret>(
              local_stretched_key_.cipher_key, local_stretched_key_.iv));
      OUTCOME_TRY(
              (auto &&, remote_128),
          initAesSecret<crypto::common::Aes128Secret>(
              remote_stretched_key_.cipher_key, remote_stretched_key_.iv));
      local_encryptor_ = std::make_unique<crypto::aes::AesCtrImpl>(
          local_128, AesCtrMode::ENCRYPT);
      remote_decryptor_ = std::make_unique<crypto::aes::AesCtrImpl>(
          remote_128, AesCtrMode::DECRYPT);
    } else if (cipher_type_ == CT::AES256) {
      OUTCOME_TRY(
              (auto &&, local_256),
          initAesSecret<crypto::common::Aes256Secret>(
              local_stretched_key_.cipher_key, local_stretched_key_.iv));
      OUTCOME_TRY(
              (auto &&, remote_256),
          initAesSecret<crypto::common::Aes256Secret>(
              remote_stretched_key_.cipher_key, remote_stretched_key_.iv));
      local_encryptor_ = std::make_unique<crypto::aes::AesCtrImpl>(
          local_256, AesCtrMode::ENCRYPT);
      remote_decryptor_ = std::make_unique<crypto::aes::AesCtrImpl>(
          remote_256, AesCtrMode::DECRYPT);
    } else {
      return Error::UNSUPPORTED_CIPHER;
    }

    read_buffer_ = std::make_shared<common::ByteArray>(kMaxFrameSize);

    return outcome::success();
  }

  bool SecioConnection::isInitialized() const {
    return local_encryptor_ && remote_decryptor_;
  }

  outcome::result<peer::PeerId> SecioConnection::localPeer() const {
    OUTCOME_TRY((auto &&, proto_local_key), key_marshaller_->marshal(local_));
    return peer::PeerId::fromPublicKey(proto_local_key);
  }

  outcome::result<peer::PeerId> SecioConnection::remotePeer() const {
    OUTCOME_TRY((auto &&, proto_remote_key), key_marshaller_->marshal(remote_));
    return peer::PeerId::fromPublicKey(proto_remote_key);
  }

  outcome::result<crypto::PublicKey> SecioConnection::remotePublicKey() const {
    return remote_;
  }

  bool SecioConnection::isInitiator() const noexcept {
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

  outcome::result<multi::Multiaddress> SecioConnection::localMultiaddr() {
      return std::visit([](auto&& conn) { return conn->localMultiaddr(); }, connection_);
  }

  outcome::result<multi::Multiaddress> SecioConnection::remoteMultiaddr() {
      return std::visit([](auto&& conn) { return conn->remoteMultiaddr(); }, connection_);
  }

  void SecioConnection::deferReadCallback(outcome::result<size_t> res,
                                          ReadCallbackFunc cb) {
    //raw_connection_->deferReadCallback(res, std::move(cb));
    std::visit([res, cb](auto&& conn) { conn->deferReadCallback(res, std::move(cb)); }, connection_);
  }

  void SecioConnection::deferWriteCallback(std::error_code ec,
                                           WriteCallbackFunc cb) {
    //raw_connection_->deferWriteCallback(ec, std::move(cb));
    std::visit([ec, cb](auto&& conn) { conn->deferWriteCallback(ec, std::move(cb)); }, connection_);
  }

  inline void SecioConnection::popUserData(gsl::span<uint8_t> out,
                                           size_t bytes) {
    auto to{out.begin()};
    for (size_t read = 0; read < bytes; ++read) {
      *to = user_data_buffer_.front();
      user_data_buffer_.pop();
      ++to;
    }
  }

  void SecioConnection::read(gsl::span<uint8_t> out, size_t bytes,
                             basic::Reader::ReadCallbackFunc cb) {
    // TODO(107): Reentrancy

    if (!isInitialized()) {
      log_->error("Reading on unintialized connection");
      cb(Error::CONN_NOT_INITIALIZED);
      return;
    }

    // the line below is due to gsl::span.size() has signed return type
    size_t out_size{out.empty() ? 0u : static_cast<size_t>(out.size())};
    if (out_size < bytes) {
      log_->error(
          "Provided buffer is too short. Buffer size is {} when {} required",
          out_size, bytes);
      cb(Error::TOO_SHORT_BUFFER);
      return;
    }

    if (user_data_buffer_.size() >= bytes) {
      popUserData(out, bytes);
      SL_TRACE(log_, "Successfully read {} bytes", bytes);
      cb(bytes);
      return;
    }

    ReadCallbackFunc cb_wrapper =
        [self{shared_from_this()}, user_cb{cb}, out,
         bytes](outcome::result<size_t> size_read_res) -> void {
      if (!size_read_res) {
        // in case of error, propagate it to the caller
        user_cb(size_read_res);
        return;
      }
      /* No error occurred.
       * Initiate one more read to check if there is enough decrypted bytes to
       * return to the caller.
       * If no, let's read one more SECIO frame */
      self->read(out, bytes, user_cb);
    };

    // this populates user_data_buffer_ when read successful
    readNextMessage(cb_wrapper);
  }

  void SecioConnection::readSome(gsl::span<uint8_t> out, size_t bytes,
                                 basic::Reader::ReadCallbackFunc cb) {
    // TODO(107): Reentrancy

    if (!isInitialized()) {
      cb(Error::CONN_NOT_INITIALIZED);
      return;
    }

    // define bytes quantity to read of user-level data
    size_t out_size{out.empty() ? 0 : static_cast<size_t>(out.size())};
    size_t read_limit{out_size < bytes ? out_size : bytes};

    if (!user_data_buffer_.empty()) {
      auto bytes_available{user_data_buffer_.size()};
      size_t to_read{bytes_available < read_limit ? bytes_available
                                                  : read_limit};
      popUserData(out, to_read);
      SL_TRACE(log_, "Successfully read {} bytes", to_read);
      cb(to_read);
      return;
    }

    ReadCallbackFunc cb_wrapper =
        [self{shared_from_this()}, user_cb{cb}, out,
         bytes](outcome::result<size_t> size_read_res) -> void {
      if (!size_read_res) {
        user_cb(size_read_res);
        return;
      }
      self->readSome(out, bytes, user_cb);
    };

    readNextMessage(cb_wrapper);
  }

  void SecioConnection::readNextMessage(ReadCallbackFunc cb) {
      std::visit([self{ shared_from_this() }, cb{ std::move(cb) }](auto& conn) mutable {
          conn->read(
              *self->read_buffer_, kLenMarkerSize,
              [self, buffer = self->read_buffer_,
              cb{ std::move(cb) }, conn](outcome::result<size_t> read_bytes_res) mutable {
                  IO_OUTCOME_TRY(len_marker_size, read_bytes_res, cb)
                      if (len_marker_size != kLenMarkerSize) {
                          self->log_->error(
                              "Cannot read frame header. Read {} bytes when {} expected",
                              len_marker_size, kLenMarkerSize);
                          cb(Error::STREAM_IS_BROKEN);
                          return;
                      }
                  uint32_t frame_len{
                      ntohl(common::convert<uint32_t>(buffer->data())) };  // NOLINT
                  if (frame_len > kMaxFrameSize) {
                      self->log_->error("Frame size {} exceeds maximum allowed size {}",
                          frame_len, kMaxFrameSize);
                      cb(Error::OVERSIZED_FRAME);
                      return;
                  }
                  SL_TRACE(self->log_, "Expecting frame of size {}.", frame_len);

                  conn->read(
                      *buffer, frame_len,
                      [self, buffer, frame_len,
                      cb{ cb }](outcome::result<size_t> read_bytes) mutable {
                          IO_OUTCOME_TRY(read_frame_bytes, read_bytes, cb)
                              if (frame_len != read_frame_bytes) {
                                  self->log_->error(
                                      "Unable to read expected amount of bytes. Read {} when "
                                      "{} expected",
                                      read_frame_bytes, frame_len);
                                  cb(Error::STREAM_IS_BROKEN);
                                  return;
                              }
                          SL_TRACE(self->log_, "Received frame with len {}",
                              read_frame_bytes);
                          IO_OUTCOME_TRY(mac_size, self->macSize(), cb)
                              const auto data_size{ frame_len - mac_size };
                          auto data_span{ gsl::make_span(buffer->data(), data_size) };
                          auto mac_span{
                              gsl::make_span(*buffer).subspan(data_size, mac_size) };
                          IO_OUTCOME_TRY(remote_mac, self->macRemote(data_span), cb)
                              if (gsl::make_span(remote_mac) != mac_span) {
                                  self->log_->error(
                                      "Signature does not validate for the received frame");
                                  cb(Error::INVALID_MAC);
                                  return;
                              }
                          IO_OUTCOME_TRY(decrypted_bytes,
                              (*self->remote_decryptor_)->crypt(data_span),
                              cb);
                          size_t decrypted_bytes_len{ decrypted_bytes.size() };
                          for (auto&& e : decrypted_bytes) {
                              self->user_data_buffer_.emplace(std::forward<decltype(e)>(e));
                          }
                          SL_TRACE(self->log_, "Frame decrypted successfully {} -> {}",
                              frame_len, decrypted_bytes_len);
                          cb(decrypted_bytes_len);
                      });
              });
          }, connection_);  // This ensures that the correct connection type is used
  }


  void SecioConnection::write(gsl::span<const uint8_t> in, size_t bytes,
                              basic::Writer::WriteCallbackFunc cb) {
    // TODO(107): Reentrancy

    if (!isInitialized()) {
      cb(Error::CONN_NOT_INITIALIZED);
    }
    IO_OUTCOME_TRY(mac_size, macSize(), cb);
    size_t frame_len{bytes + mac_size};
    common::ByteArray frame_buffer;
    constexpr size_t len_field_size{kLenMarkerSize};
    frame_buffer.reserve(len_field_size + frame_len);

    common::putUint32BE(frame_buffer, frame_len);
    IO_OUTCOME_TRY(encrypted_data, (*local_encryptor_)->crypt(in), cb);
    IO_OUTCOME_TRY(mac_data, macLocal(encrypted_data), cb);
    frame_buffer.insert(frame_buffer.end(),
                        std::make_move_iterator(encrypted_data.begin()),
                        std::make_move_iterator(encrypted_data.end()));
    frame_buffer.insert(frame_buffer.end(),
                        std::make_move_iterator(mac_data.begin()),
                        std::make_move_iterator(mac_data.end()));
    basic::Writer::WriteCallbackFunc cb_wrapper =
        [user_cb{std::move(cb)}, bytes,
         raw_bytes{frame_buffer.size()}](auto &&res) {
          if (!res) {
            return user_cb(res);  // pulling out the error occurred
          }
          if (res.value() != raw_bytes) {
            return user_cb(Error::STREAM_IS_BROKEN);
          }
          user_cb(bytes);
        };
    //raw_connection_->write(frame_buffer, frame_buffer.size(), cb_wrapper);
    std::visit([frame_buffer, cb_wrapper](auto&& conn) { conn->write(frame_buffer, frame_buffer.size(), cb_wrapper); }, connection_);
  }

  void SecioConnection::writeSome(gsl::span<const uint8_t> in, size_t bytes,
                                  basic::Writer::WriteCallbackFunc cb) {
    write(in, bytes, std::move(cb));
  }

  bool SecioConnection::isClosed() const {
    //return raw_connection_->isClosed();
    return std::visit([](auto&& conn) { return conn->isClosed(); }, connection_);

  }

  outcome::result<void> SecioConnection::close() {
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

  outcome::result<std::shared_ptr<RawConnection>> SecioConnection::getRawConnection() const
  {
      auto raw_conn = std::get_if<std::shared_ptr<RawConnection>>(&connection_);
      return *raw_conn;
  }

  outcome::result<size_t> SecioConnection::macSize() const {
    using HT = crypto::common::HashType;
    switch (hash_type_) {
      case HT::SHA256:
        return 32;
      case HT::SHA512:
        return 64;
      default:
        return Error::UNSUPPORTED_HASH;
    }
  }

  outcome::result<common::ByteArray> SecioConnection::macLocal(
      gsl::span<const uint8_t> message) const {
    return hmac_provider_->calculateDigest(
        hash_type_, local_stretched_key_.mac_key, message);
  }

  outcome::result<common::ByteArray> SecioConnection::macRemote(
      gsl::span<const uint8_t> message) const {
    return hmac_provider_->calculateDigest(
        hash_type_, remote_stretched_key_.mac_key, message);
  }

}  // namespace libp2p::connection
