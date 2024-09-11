/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LIBP2P_PLAINTEXT_CONNECTION_HPP
#define LIBP2P_PLAINTEXT_CONNECTION_HPP

#include <memory>
#include <optional>

#include <libp2p/connection/secure_connection.hpp>
#include <libp2p/crypto/key_marshaller.hpp>
#include <libp2p/connection/stream.hpp>
#include <libp2p/log/logger.hpp>
#include <variant>

namespace libp2p::connection {
  class PlaintextConnection : public SecureConnection {
   public:
       explicit PlaintextConnection(
        std::shared_ptr<RawConnection> raw_connection,
        crypto::PublicKey localPubkey, crypto::PublicKey remotePubkey,
        std::shared_ptr<crypto::marshaller::KeyMarshaller> key_marshaller);

       explicit PlaintextConnection(
        std::shared_ptr<connection::Stream> raw_connection,
        crypto::PublicKey localPubkey, crypto::PublicKey remotePubkey,
        std::shared_ptr<crypto::marshaller::KeyMarshaller> key_marshaller);

    ~PlaintextConnection() override = default;

    outcome::result<peer::PeerId> localPeer() const override;

    outcome::result<peer::PeerId> remotePeer() const override;

    outcome::result<crypto::PublicKey> remotePublicKey() const override;

    bool isInitiator() const noexcept override;

    outcome::result<multi::Multiaddress> localMultiaddr() override;

    outcome::result<multi::Multiaddress> remoteMultiaddr() override;

    void read(gsl::span<uint8_t> out, size_t bytes,
              ReadCallbackFunc cb) override;

    void readSome(gsl::span<uint8_t> out, size_t bytes,
                  ReadCallbackFunc cb) override;

    void deferReadCallback(outcome::result<size_t> res,
                           ReadCallbackFunc cb) override;

    void write(gsl::span<const uint8_t> in, size_t bytes,
               WriteCallbackFunc cb) override;

    void writeSome(gsl::span<const uint8_t> in, size_t bytes,
                   WriteCallbackFunc cb) override;

    void deferWriteCallback(std::error_code ec, WriteCallbackFunc cb) override;

    bool isClosed() const override;

    outcome::result<void> close() override;

   private:
    //std::shared_ptr<RawConnection> raw_connection_;
    //std::shared_ptr<connection::Stream> stream_;
    std::variant<std::shared_ptr<RawConnection>, std::shared_ptr<Stream>> connection_;

    crypto::PublicKey local_;
    crypto::PublicKey remote_;

    std::shared_ptr<crypto::marshaller::KeyMarshaller> key_marshaller_;

    log::Logger log_ = log::createLogger("PlaintextConnection");
  };
}  // namespace libp2p::connection

#endif  // LIBP2P_PLAINTEXT_CONNECTION_HPP
