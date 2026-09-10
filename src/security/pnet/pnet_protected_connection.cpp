/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * PnetProtectedConnection — pnet PSK boundary decorator. Semantics ported
 * from go-libp2p pnet psk_conn.go: lazy per-direction 24-byte nonce exchange
 * (nonce travels in the clear), then XSalsa20 (key = PSK, nonce = exchanged
 * value) over all following bytes in that direction. Decrypt is the same
 * operation as encrypt; a wrong-PSK peer decrypts garbage and multiselect
 * fails naturally (PNET-03).
 */

#include <libp2p/security/pnet/pnet_protected_connection.hpp>

#include <array>
#include <vector>

#include <libp2p/security/pnet/pnet_error.hpp>

namespace libp2p::security::pnet {

  PnetProtectedConnection::PnetProtectedConnection(
      std::shared_ptr<connection::RawConnection> inner,
      std::shared_ptr<const Psk> psk,
      std::shared_ptr<basic::Scheduler> scheduler)
      : inner_(std::move(inner)),
        psk_(std::move(psk)),
        scheduler_(std::move(scheduler)) {}

  // ---------- write path ----------

  void PnetProtectedConnection::write(gsl::span<const uint8_t> in, size_t bytes,
                                      basic::Writer::WriteCallbackFunc cb) {
    writeSome(in, bytes, std::move(cb));
  }

  void PnetProtectedConnection::writeSome(
      gsl::span<const uint8_t> in, size_t bytes,
      basic::Writer::WriteCallbackFunc cb) {
    // Owned ciphertext buffer: the const input span cannot be crypted in
    // place, and the buffer must outlive the async inner write (Pitfall 2)
    auto payload = std::make_shared<std::vector<uint8_t>>(in.begin(),
                                                          in.begin() + bytes);
    if (write_stream_) {
      return doWriteProtected(std::move(cb), std::move(payload), 0);
    }

    // Lazy nonce exchange for the write direction: generate, send IN THE
    // CLEAR first, then initialize the keystream from (psk, nonce)
    auto nonce_res = crypto::xsalsa20::generateNonce();
    if (!nonce_res) {
      return deferWriteCallback(PnetError::PNET_NONCE_GENERATION_FAILED,
                                std::move(cb));
    }
    auto nonce_buf = std::make_shared<std::vector<uint8_t>>(
        nonce_res.value().begin(), nonce_res.value().end());
    auto self = shared_from_this();
    // NB: build the span view in its OWN statement before the call —
    // argument evaluation order (view vs lambda-construction moves) is
    // indeterminate; the statement boundary sequences the view first and the
    // lambda capture keeps nonce_buf alive for the async lifetime
    const gsl::span<const uint8_t> nonce_view(*nonce_buf);
    inner_->writeSome(
        nonce_view, nonce_view.size(),
        [self, nonce_buf{std::move(nonce_buf)}, payload{std::move(payload)},
         cb{std::move(cb)}](outcome::result<size_t> r) mutable {
          if (!r) {
            return self->deferWriteCallback(r.error(), std::move(cb));
          }
          if (!self->write_stream_) {
            self->write_stream_.emplace(self->psk_->span(), *nonce_buf);
          }
          self->doWriteProtected(std::move(cb), std::move(payload), 0);
        });
  }

  void PnetProtectedConnection::doWriteProtected(
      basic::Writer::WriteCallbackFunc cb,
      std::shared_ptr<std::vector<uint8_t>> payload, size_t offset) {
    // The payload is encrypted exactly once, in full, before the first inner
    // write attempt (offset == 0). Partial-write retries continue from the
    // new offset without re-crypting the tail: crypt() advances the keystream
    // by exactly the bytes it processed, so the position stays wire-aligned.
    if (offset == 0) {
      write_stream_->crypt(*payload);
    }
    auto self = shared_from_this();
    // statement boundary: sequence the remainder view before any lambda
    // capture moves (same indeterminate-evaluation-order hazard as above)
    const auto remainder = gsl::span<const uint8_t>(*payload).subspan(offset);
    inner_->writeSome(
        remainder, remainder.size(),
        [self, payload, cb{std::move(cb)}, offset](
            outcome::result<size_t> r) mutable {
          if (!r) {
            return self->deferWriteCallback(r.error(), std::move(cb));
          }
          const size_t written = offset + r.value();
          if (written < payload->size()) {
            // partial inner write: the unwritten tail is already ciphertext
            return self->doWriteProtected(std::move(cb), std::move(payload),
                                          written);
          }
          // Success: report the byte count via deferReadCallback (matching
          // LoopbackStream::write's established convention), NOT
          // deferWriteCallback — the latter's contract (see writer.hpp) is
          // error-only ("if (!ec) then this function does nothing" — the
          // interface's default semantics for a no-op on success). Both
          // ReadCallbackFunc and WriteCallbackFunc are the exact same
          // std::function<void(outcome::result<size_t>)> type, so passing
          // `cb` through is valid without conversion. Passing an empty
          // std::error_code{} here instead (Rule 1 bug, Phase 3 discovery
          // — see 03-01-SUMMARY.md deviations) constructed a FAILURE
          // outcome::result with the "success" error_code (value 0,
          // message "The operation completed successfully"), which the
          // caller then treated as a genuine write failure.
          self->deferReadCallback(outcome::success(written), std::move(cb));
        });
  }

  // ---------- read path ----------

  void PnetProtectedConnection::read(gsl::span<uint8_t> out, size_t bytes,
                                     basic::Reader::ReadCallbackFunc cb) {
    readWithNonce(out, bytes, /*exact=*/true, std::move(cb));
  }

  void PnetProtectedConnection::readSome(gsl::span<uint8_t> out, size_t bytes,
                                         basic::Reader::ReadCallbackFunc cb) {
    readWithNonce(out, bytes, /*exact=*/false, std::move(cb));
  }

  void PnetProtectedConnection::readWithNonce(
      gsl::span<uint8_t> out, size_t bytes, bool exact,
      basic::Reader::ReadCallbackFunc cb) {
    if (read_stream_) {
      return doReadProtected(out, bytes, exact, std::move(cb));
    }

    // Lazy nonce acquisition for the read direction: EXACT 24-byte read of
    // the peer's cleartext nonce, NEVER readSome (Pitfall 3). The nonce
    // buffer is owned by shared state captured across the async chain.
    auto nonce_buf = std::make_shared<
        std::array<uint8_t, crypto::xsalsa20::kNonceSize>>();
    auto self = shared_from_this();
    inner_->read(
        gsl::span<uint8_t>(nonce_buf->data(), nonce_buf->size()),
        nonce_buf->size(),
        [self, nonce_buf, out, bytes, exact,
         cb{std::move(cb)}](outcome::result<size_t> r) mutable {
          if (!r || r.value() != crypto::xsalsa20::kNonceSize) {
            // the exact-variant read is all-or-error; anything else is a
            // nonce protocol failure
            return self->deferReadCallback(PnetError::PNET_NONCE_READ_FAILED,
                                           std::move(cb));
          }
          if (!self->read_stream_) {
            self->read_stream_.emplace(self->psk_->span(), *nonce_buf);
          }
          self->doReadProtected(out, bytes, exact, std::move(cb));
        });
  }

  void PnetProtectedConnection::doReadProtected(
      gsl::span<uint8_t> out, size_t bytes, bool exact,
      basic::Reader::ReadCallbackFunc cb) {
    auto self = shared_from_this();
    auto handler = [self, out,
                    cb{std::move(cb)}](outcome::result<size_t> r) mutable {
      if (!r) {
        return self->deferReadCallback(r.error(), std::move(cb));
      }
      const size_t n = r.value();
      // decrypt EXACTLY the n bytes actually read (never the full buffer)
      self->read_stream_->crypt(out.first(n));
      self->deferReadCallback(n, std::move(cb));
    };
    if (exact) {
      inner_->read(out, bytes, std::move(handler));
    } else {
      inner_->readSome(out, bytes, std::move(handler));
    }
  }

  // ---------- delegation ----------

  outcome::result<void> PnetProtectedConnection::close() {
    return inner_->close();
  }

  bool PnetProtectedConnection::isClosed() const {
    return inner_->isClosed();
  }

  bool PnetProtectedConnection::isInitiator() const noexcept {
    return inner_->isInitiator();
  }

  outcome::result<multi::Multiaddress>
  PnetProtectedConnection::localMultiaddr() {
    return inner_->localMultiaddr();
  }

  outcome::result<multi::Multiaddress>
  PnetProtectedConnection::remoteMultiaddr() {
    return inner_->remoteMultiaddr();
  }

  void PnetProtectedConnection::deferReadCallback(
      outcome::result<size_t> res, basic::Reader::ReadCallbackFunc cb) {
    // Phase 1 carry-forward: every completion routes through the scheduler
    scheduler_->schedule([res, cb{std::move(cb)}]() mutable { cb(res); });
  }

  void PnetProtectedConnection::deferWriteCallback(
      std::error_code ec, basic::Writer::WriteCallbackFunc cb) {
    scheduler_->schedule([ec, cb{std::move(cb)}]() mutable { cb(ec); });
  }

}  // namespace libp2p::security::pnet
