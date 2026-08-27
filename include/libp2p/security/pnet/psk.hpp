/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LIBP2P_SECURITY_PNET_PSK_HPP
#define LIBP2P_SECURITY_PNET_PSK_HPP

#include <array>
#include <cstdint>
#include <string_view>
#include <utility>

#include <gsl/span>
#include <libp2p/outcome/outcome.hpp>

namespace libp2p::security::pnet {

  /// PSK size (in bytes) mandated by the libp2p pnet spec (256-bit key)
  inline constexpr size_t kPskSize = 32;

  /**
   * A pre-shared key for private networks. Move-only value type whose key
   * bytes are zeroed (OPENSSL_cleanse) on destruction and on move-out, and
   * which is never logged (D-06 key hygiene).
   *
   * Construct only via the factories; every parse failure is an explicit
   * PnetError (D-05) — there is no silent truncation or default key.
   */
  class Psk {
   public:
    Psk(const Psk &) = delete;
    Psk &operator=(const Psk &) = delete;

    Psk(Psk &&other) noexcept;
    Psk &operator=(Psk &&other) noexcept;

    ~Psk();

    /**
     * Parse go-ipfs swarm.key file text:
     *   /key/swarm/psk/1.0.0/\n/base16/<64 hex chars>\n
     * or the /base64/ framing (base64 of exactly 32 bytes).
     * Trailing whitespace/newlines are tolerated. The /bin/ codec line is
     * rejected (PNET_INVALID_PSK_FORMAT) — the textual format carries no
     * reliable length framing for raw bytes.
     */
    static outcome::result<Psk> fromSwarmKeyText(std::string_view text);

    /// Exactly 32 raw bytes
    static outcome::result<Psk> fromRawBytes(gsl::span<const uint8_t> bytes);

    /// 64 hex characters (case-insensitive), no /base16/ framing
    static outcome::result<Psk> fromBase16String(std::string_view hex);

    /// base64 of exactly 32 bytes, no /base64/ framing
    static outcome::result<Psk> fromBase64String(std::string_view b64);

    /// Read-only view of the 32 key bytes
    gsl::span<const uint8_t> span() const noexcept;

   private:
    Psk() = default;

    static outcome::result<Psk> fromDecoded(
        std::vector<uint8_t> decoded);

    std::array<uint8_t, kPskSize> key_{};
  };

}  // namespace libp2p::security::pnet

#endif  // LIBP2P_SECURITY_PNET_PSK_HPP
