/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LIBP2P_SECURITY_PNET_PNET_PROTECTED_CONNECTION_HPP
#define LIBP2P_SECURITY_PNET_PNET_PROTECTED_CONNECTION_HPP

#include <memory>
#include <optional>

#include <libp2p/basic/scheduler.hpp>
#include <libp2p/connection/raw_connection.hpp>
#include <libp2p/crypto/xsalsa20/xsalsa20.hpp>
#include <libp2p/security/pnet/psk.hpp>

namespace libp2p::security::pnet {

  /**
   * RawConnection decorator establishing the pnet PSK boundary: after a lazy
   * per-direction 24-byte nonce exchange (nonce bytes travel in the clear,
   * exactly as in go-libp2p's psk_conn.go), every byte in both directions is
   * XSalsa20-encrypted with the pre-shared key. A peer without the matching
   * PSK decrypts garbage, so multiselect negotiation can never succeed
   * against it (PNET-03).
   *
   * Decorator only: no negotiation logic, no multiselect knowledge. Wraps
   * the RawConnection BEFORE the Upgrader sees it — never a SecurityAdaptor.
   */
  class PnetProtectedConnection
      : public connection::RawConnection,
        public std::enable_shared_from_this<PnetProtectedConnection> {
   public:
    PnetProtectedConnection(std::shared_ptr<connection::RawConnection> inner,
                            std::shared_ptr<const Psk> psk,
                            std::shared_ptr<basic::Scheduler> scheduler);

    ~PnetProtectedConnection() override = default;

    void read(gsl::span<uint8_t> out, size_t bytes,
              basic::Reader::ReadCallbackFunc cb) override;

    void readSome(gsl::span<uint8_t> out, size_t bytes,
                  basic::Reader::ReadCallbackFunc cb) override;

    void write(gsl::span<const uint8_t> in, size_t bytes,
               basic::Writer::WriteCallbackFunc cb) override;

    void writeSome(gsl::span<const uint8_t> in, size_t bytes,
                   basic::Writer::WriteCallbackFunc cb) override;

    outcome::result<void> close() override;

    bool isClosed() const override;

    bool isInitiator() const noexcept override;

    outcome::result<multi::Multiaddress> localMultiaddr() override;

    outcome::result<multi::Multiaddress> remoteMultiaddr() override;

    void deferReadCallback(outcome::result<size_t> res,
                           basic::Reader::ReadCallbackFunc cb) override;

    void deferWriteCallback(std::error_code ec,
                            basic::Writer::WriteCallbackFunc cb) override;

   private:
    /// Encrypted-write step; payload stays owned by the shared buffer and
    /// is encrypted exactly once (offset == 0) before any inner write
    void doWriteProtected(basic::Writer::WriteCallbackFunc cb,
                          std::shared_ptr<std::vector<uint8_t>> payload,
                          size_t offset);

    /// Ensures the read direction acquired the peer nonce (exact 24-byte
    /// inner read); invokes doReadProtected on success or defers the error
    void readWithNonce(gsl::span<uint8_t> out, size_t bytes, bool exact,
                       basic::Reader::ReadCallbackFunc cb);

    /// Post-nonce read step; decrypts exactly n bytes in the completion
    void doReadProtected(gsl::span<uint8_t> out, size_t bytes, bool exact,
                         basic::Reader::ReadCallbackFunc cb);

    std::shared_ptr<connection::RawConnection> inner_;
    std::shared_ptr<const Psk> psk_;
    std::shared_ptr<basic::Scheduler> scheduler_;

    /// Two INDEPENDENT per-direction stream states (Pitfall 1 / Pattern 1)
    std::optional<crypto::xsalsa20::XSalsa20Stream> write_stream_;
    std::optional<crypto::xsalsa20::XSalsa20Stream> read_stream_;
  };

}  // namespace libp2p::security::pnet

#endif  // LIBP2P_SECURITY_PNET_PNET_PROTECTED_CONNECTION_HPP
