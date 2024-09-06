/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <arpa/inet.h>

#include <libp2p/security/noise/insecure_rw.hpp>

#include <libp2p/common/byteutil.hpp>
#include <libp2p/security/noise/crypto/state.hpp>

#ifndef _UNIQUE_NAME_
#define _UNIQUE_NAME_(base) base##__LINE__
#endif  // UNIQUE_NAME

#define IO_OUTCOME_TRY_NAME(var, val, res, cb) \
  auto && (var) = (res);                       \
  if ((var).has_error()) {                     \
    cb((var).error());                         \
    return;                                    \
  }                                            \
  auto && (val) = (var).value();

#define IO_OUTCOME_TRY(name, res, cb) \
  IO_OUTCOME_TRY_NAME(_UNIQUE_NAME_(name), name, res, cb)

namespace libp2p::security::noise {
  InsecureReadWriter::InsecureReadWriter(
      std::shared_ptr<connection::RawConnection> connection,
      std::shared_ptr<common::ByteArray> buffer)
      : connection_{std::move(connection)}, buffer_{std::move(buffer)} {}

  InsecureReadWriter::InsecureReadWriter(
      std::shared_ptr<connection::Stream> connection,
      std::shared_ptr<common::ByteArray> buffer)
      : connection_{ std::move(connection) }, buffer_{ std::move(buffer) } {}

  void InsecureReadWriter::read(basic::MessageReadWriter::ReadCallbackFunc cb) {
    buffer_->resize(kMaxMsgLen);  // ensure buffer capacity
    auto read_cb = [cb{std::move(cb)}, self{shared_from_this()}](
                       outcome::result<size_t> result) mutable {
      IO_OUTCOME_TRY(read_bytes, result, cb);
      if (kLengthPrefixSize != read_bytes) {
        return cb(std::errc::broken_pipe);
      }
      uint16_t frame_len{
          ntohs(common::convert<uint16_t>(self->buffer_->data()))};  // NOLINT
      auto read_cb = [cb = std::move(cb), self,
                      frame_len](outcome::result<size_t> result) {
        IO_OUTCOME_TRY(read_bytes, result, cb);
        if (frame_len != read_bytes) {
          return cb(std::errc::broken_pipe);
        }
        self->buffer_->resize(read_bytes);
        cb(self->buffer_);
      };
      std::visit([self, frame_len, read_cb](auto&& conn) { return conn->read(*self->buffer_, frame_len, std::move(read_cb)); }, self->connection_);
      //self->connection_->read(*self->buffer_, frame_len, std::move(read_cb));
    };
    //connection_->read(*buffer_, kLengthPrefixSize, std::move(read_cb));
    std::visit([self{ shared_from_this() }, read_cb](auto&& conn) { return conn->read(*self->buffer_, kLengthPrefixSize, std::move(read_cb)); }, connection_);

  }

  void InsecureReadWriter::write(gsl::span<const uint8_t> buffer,
                                 basic::Writer::WriteCallbackFunc cb) {
    if (buffer.size() > static_cast<int64_t>(kMaxMsgLen)) {
      return cb(std::errc::message_size);
    }
    outbuf_.clear();
    outbuf_.reserve(kLengthPrefixSize + buffer.size());
    common::putUint16BE(outbuf_, buffer.size());
    outbuf_.insert(outbuf_.end(), buffer.begin(), buffer.end());
    auto write_cb = [self{shared_from_this()},
                     cb{std::move(cb)}](outcome::result<size_t> result) {
      IO_OUTCOME_TRY(written_bytes, result, cb);
      if (self->outbuf_.size() != written_bytes) {
        return cb(std::errc::broken_pipe);
      }
      cb(written_bytes - kLengthPrefixSize);
    };
    //connection_->write(outbuf_, outbuf_.size(), std::move(write_cb));
    std::visit([self{ shared_from_this() }, write_cb](auto&& conn) { return conn->write(self->outbuf_, self->outbuf_.size(), std::move(write_cb)); }, connection_);
  }
}  // namespace libp2p::security::noise
