/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LIBP2P_CRYPTO_XSALSA20_XSALSA20_HPP
#define LIBP2P_CRYPTO_XSALSA20_XSALSA20_HPP

#include <array>
#include <cstdint>
#include <vector>

#include <gsl/span>
#include <libp2p/outcome/outcome.hpp>

namespace libp2p::crypto::xsalsa20 {

  enum class XSalsa20Error {
    WRONG_KEY_SIZE = 1,        ///< key is not exactly kKeySize (32) bytes
    WRONG_NONCE_SIZE,          ///< nonce is not exactly kNonceSize (24) bytes
    NONCE_GENERATION_FAILED,   ///< CSPRNG (RAND_bytes) failed
  };

  /// Size (in bytes) of an XSalsa20 key (256 bits)
  inline constexpr size_t kKeySize = 32;

  /// Size (in bytes) of an XSalsa20 nonce (192 bits)
  inline constexpr size_t kNonceSize = 24;

  /**
   * Stateful XSalsa20 keystream cipher (libsodium crypto_stream_xsalsa20
   * semantics): HSalsa20 subkey derivation from (key, nonce[0..16)) followed
   * by the Salsa20/20 core keyed with the subkey, running from block counter 0
   * with nonce[16..24) as the 8-byte stream nonce.
   *
   * Encryption and decryption are the same operation (in-place XOR with the
   * keystream); no separate decrypt path exists by design.
   */
  class XSalsa20Stream {
   public:
    /**
     * @param key exactly kKeySize (32) bytes
     * @param nonce exactly kNonceSize (24) bytes
     */
    XSalsa20Stream(gsl::span<const uint8_t> key,
                   gsl::span<const uint8_t> nonce);

    /**
     * XOR `in_out` with the keystream in place, advancing the stream position
     * by exactly in_out.size() bytes. An empty span is a no-op.
     */
    void crypt(gsl::span<uint8_t> in_out);

   private:
    void refillBlock();

    /// Salsa20/20 input state keyed with the HSalsa20 subkey
    std::array<uint32_t, 16> input_{};
    /// 64-bit block counter of the block currently buffered in leftover_
    uint64_t block_counter_ = 0;
    /// Keystream bytes of block_counter_ not yet consumed
    std::array<uint8_t, 64> leftover_{};
    /// Number of valid (unconsumed) keystream bytes at the start of leftover_
    size_t leftover_size_ = 0;
    /// Offset of the first unconsumed byte inside leftover_
    size_t leftover_pos_ = 0;
  };

  /**
   * One-shot XSalsa20 encryption/decryption (fresh stream internally).
   * @param key exactly kKeySize (32) bytes
   * @param nonce exactly kNonceSize (24) bytes
   * @param message bytes to XOR with the keystream
   * @return keystream-XORed copy of message, or error on wrong key/nonce size
   */
  outcome::result<std::vector<uint8_t>> xsalsa20(gsl::span<const uint8_t> key,
                                                gsl::span<const uint8_t> nonce,
                                                gsl::span<const uint8_t> message);

  /**
   * Generate a fresh 24-byte nonce from OpenSSL RAND_bytes (CSPRNG).
   * @return the nonce, or error if the CSPRNG failed
   */
  outcome::result<std::array<uint8_t, kNonceSize>> generateNonce();

}  // namespace libp2p::crypto::xsalsa20

OUTCOME_HPP_DECLARE_ERROR(libp2p::crypto::xsalsa20, XSalsa20Error)

#endif  // LIBP2P_CRYPTO_XSALSA20_XSALSA20_HPP
