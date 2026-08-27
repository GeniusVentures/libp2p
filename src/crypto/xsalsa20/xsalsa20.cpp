/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Vendored, self-contained XSalsa20 stream cipher (decision D-01: no
 * external cipher dependency, nothing new added via the package manager).
 *
 * Semantics follow libsodium's crypto_stream_xsalsa20 / _xor_ic:
 *   - crypto_core_hsalsa20 subkey derivation from key + nonce[0..16)
 *     with the "expand 32-byte k" sigma constant,
 *   - crypto_core_salsa20 keystream blocks keyed with the subkey,
 *     from block counter 0, using nonce[16..24) as the 8-byte stream nonce.
 * Validated against the published libsodium test vectors
 * (test/default/stream.c, test/default/core2.c) — see xsalsa20_test.cpp.
 */

#include <libp2p/crypto/xsalsa20/xsalsa20.hpp>

#include <openssl/rand.h>

#include <array>
#include <cassert>
#include <cstring>

namespace libp2p::crypto::xsalsa20 {

  namespace {

    // "expand 32-byte k" — public-domain Salsa20 sigma constant
    constexpr std::array<uint8_t, 16> kSigma = {
        0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x33,
        0x32, 0x2d, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6b};

    constexpr size_t kBlock64 = 64;

    uint32_t loadLittleEndian32(const uint8_t *src) {
      return static_cast<uint32_t>(src[0])
          | (static_cast<uint32_t>(src[1]) << 8)
          | (static_cast<uint32_t>(src[2]) << 16)
          | (static_cast<uint32_t>(src[3]) << 24);
    }

    void storeLittleEndian32(uint8_t *dst, uint32_t value) {
      dst[0] = static_cast<uint8_t>(value & 0xff);
      dst[1] = static_cast<uint8_t>((value >> 8) & 0xff);
      dst[2] = static_cast<uint8_t>((value >> 16) & 0xff);
      dst[3] = static_cast<uint8_t>((value >> 24) & 0xff);
    }

    uint32_t rotateLeft(uint32_t value, unsigned bits) {
      return (value << bits) | (value >> (32 - bits));
    }

    /// One Salsa20 double round: four column quarter-rounds followed by four
    /// row quarter-rounds (public-domain reference semantics)
    void salsaDoubleRound(std::array<uint32_t, 16> &x) {
      // QR(x0,x4,x8,x12)
      x[4] ^= rotateLeft(x[0] + x[12], 7);
      x[8] ^= rotateLeft(x[4] + x[0], 9);
      x[12] ^= rotateLeft(x[8] + x[4], 13);
      x[0] ^= rotateLeft(x[12] + x[8], 18);
      // QR(x5,x9,x13,x1)
      x[9] ^= rotateLeft(x[5] + x[1], 7);
      x[13] ^= rotateLeft(x[9] + x[5], 9);
      x[1] ^= rotateLeft(x[13] + x[9], 13);
      x[5] ^= rotateLeft(x[1] + x[13], 18);
      // QR(x10,x14,x2,x6)
      x[14] ^= rotateLeft(x[10] + x[6], 7);
      x[2] ^= rotateLeft(x[14] + x[10], 9);
      x[6] ^= rotateLeft(x[2] + x[14], 13);
      x[10] ^= rotateLeft(x[6] + x[2], 18);
      // QR(x15,x3,x7,x11)
      x[3] ^= rotateLeft(x[15] + x[11], 7);
      x[7] ^= rotateLeft(x[3] + x[15], 9);
      x[11] ^= rotateLeft(x[7] + x[3], 13);
      x[15] ^= rotateLeft(x[11] + x[7], 18);

      // QR(x0,x1,x2,x3)
      x[1] ^= rotateLeft(x[0] + x[3], 7);
      x[2] ^= rotateLeft(x[1] + x[0], 9);
      x[3] ^= rotateLeft(x[2] + x[1], 13);
      x[0] ^= rotateLeft(x[3] + x[2], 18);
      // QR(x5,x6,x7,x4)
      x[6] ^= rotateLeft(x[5] + x[4], 7);
      x[7] ^= rotateLeft(x[6] + x[5], 9);
      x[4] ^= rotateLeft(x[7] + x[6], 13);
      x[5] ^= rotateLeft(x[4] + x[7], 18);
      // QR(x10,x11,x8,x9)
      x[11] ^= rotateLeft(x[10] + x[9], 7);
      x[8] ^= rotateLeft(x[11] + x[10], 9);
      x[9] ^= rotateLeft(x[8] + x[11], 13);
      x[10] ^= rotateLeft(x[9] + x[8], 18);
      // QR(x15,x12,x13,x14)
      x[12] ^= rotateLeft(x[15] + x[14], 7);
      x[13] ^= rotateLeft(x[12] + x[15], 9);
      x[14] ^= rotateLeft(x[13] + x[12], 13);
      x[15] ^= rotateLeft(x[14] + x[13], 18);
    }

    /// Build the 16-word input matrix of the Salsa20 expansion function:
    /// sigma on the diagonal (words 0,5,10,15), the 32-byte key split across
    /// words 1..4 and 11..14, and the 16-byte block input (stream nonce +
    /// block counter for XSalsa20) in words 6..9.
    void salsa20InputState(std::array<uint32_t, 16> &input,
                           const uint8_t *key,
                           const uint8_t in16[16]) {
      input[0] = loadLittleEndian32(kSigma.data());
      input[5] = loadLittleEndian32(kSigma.data() + 4);
      input[10] = loadLittleEndian32(kSigma.data() + 8);
      input[15] = loadLittleEndian32(kSigma.data() + 12);

      for (size_t i = 0; i < 4; ++i) {
        input[1 + i] = loadLittleEndian32(key + 4 * i);
        input[11 + i] = loadLittleEndian32(key + 16 + 4 * i);
      }

      for (size_t i = 0; i < 4; ++i) {
        input[6 + i] = loadLittleEndian32(in16 + 4 * i);
      }
    }

    /**
     * Salsa20/20 core: 20 rounds (10 double rounds) over the input state,
     * additive feed-forward, little-endian serialization to 64 keystream
     * bytes. Public-domain reference semantics.
     */
    void salsa20Core(uint8_t out[kBlock64], const std::array<uint32_t, 16> &in) {
      std::array<uint32_t, 16> x{in};
      for (int round = 0; round < 10; ++round) {
        salsaDoubleRound(x);
      }
      for (size_t i = 0; i < 16; ++i) {
        storeLittleEndian32(out + 4 * i, x[i] + in[i]);
      }
    }

    /**
     * HSalsa20: derive a 32-byte subkey from a 32-byte key and a 16-byte
     * input (the first 16 nonce bytes) with the sigma constants. 20 rounds,
     * no feed-forward; output words x0,x5,x10,x15,x6,x7,x8,x9 per the
     * HSalsa20 specification (Bernstein). Reference semantics of libsodium
     * crypto_core_hsalsa20 with sigma != NULL — validated against the
     * published core2.c/core2.exp vector.
     */
    void hsalsa20Subkey(uint8_t out[kKeySize],
                        const uint8_t in16[16],
                        const uint8_t key[kKeySize]) {
      std::array<uint32_t, 16> input{};
      salsa20InputState(input, key, in16);

      std::array<uint32_t, 16> x{input};
      for (int round = 0; round < 10; ++round) {
        salsaDoubleRound(x);
      }

      storeLittleEndian32(out, x[0]);
      storeLittleEndian32(out + 4, x[5]);
      storeLittleEndian32(out + 8, x[10]);
      storeLittleEndian32(out + 12, x[15]);
      storeLittleEndian32(out + 16, x[6]);
      storeLittleEndian32(out + 20, x[7]);
      storeLittleEndian32(out + 24, x[8]);
      storeLittleEndian32(out + 28, x[9]);
    }

  }  // namespace

  XSalsa20Stream::XSalsa20Stream(gsl::span<const uint8_t> key,
                                 gsl::span<const uint8_t> nonce) {
    assert(key.size() == kKeySize && nonce.size() == kNonceSize);

    // crypto_stream_xsalsa20: subkey = HSalsa20(key, nonce[0..16))
    std::array<uint8_t, kKeySize> subkey{};
    hsalsa20Subkey(subkey.data(), nonce.data(), key.data());

    // Salsa20/20 from block counter 0, keyed with the subkey; the last 8
    // nonce bytes are the 8-byte stream nonce (block-input words 6..7) and
    // words 8..9 carry the 64-bit block counter, little-endian.
    uint8_t in16[16]{};
    std::memcpy(in16, nonce.data() + 16, 8);  // stream nonce
    // counter 0 — bytes 8..15 already zero
    salsa20InputState(input_, subkey.data(), in16);
    block_counter_ = 0;
    leftover_size_ = 0;
    leftover_pos_ = 0;
  }

  void XSalsa20Stream::refillBlock() {
    salsa20Core(leftover_.data(), input_);
    leftover_pos_ = 0;
    leftover_size_ = kBlock64;

    // advance the 64-bit block counter (input_ words 8..9, little-endian)
    uint64_t counter = static_cast<uint64_t>(input_[8])
        | (static_cast<uint64_t>(input_[9]) << 32);
    ++counter;
    input_[8] = static_cast<uint32_t>(counter & 0xffffffffu);
    input_[9] = static_cast<uint32_t>(counter >> 32);
    block_counter_ = counter;
  }

  void XSalsa20Stream::crypt(gsl::span<uint8_t> in_out) {
    size_t offset = 0;
    const size_t total = in_out.size();

    // consume leftover keystream first
    while (offset < total && leftover_pos_ < leftover_size_) {
      in_out[offset] ^= leftover_[leftover_pos_];
      ++offset;
      ++leftover_pos_;
    }

    // whole 64-byte blocks straight into the target buffer
    while (offset + kBlock64 <= total) {
      uint8_t block[kBlock64];
      salsa20Core(block, input_);
      for (size_t i = 0; i < kBlock64; ++i) {
        in_out[offset + i] ^= block[i];
      }
      uint64_t counter = static_cast<uint64_t>(input_[8])
          | (static_cast<uint64_t>(input_[9]) << 32);
      ++counter;
      input_[8] = static_cast<uint32_t>(counter & 0xffffffffu);
      input_[9] = static_cast<uint32_t>(counter >> 32);
      block_counter_ = counter;
      offset += kBlock64;
    }

    // trailing partial block: buffer the whole keystream block (the counter
    // stays at the next block until the leftover buffer is drained, so a
    // later refill regenerates the correct successor block)
    if (offset < total) {
      refillBlock();  // buffers 64 bytes, does NOT advance past them
      const size_t n = total - offset;
      for (size_t i = 0; i < n; ++i) {
        in_out[offset + i] ^= leftover_[leftover_pos_];
        ++leftover_pos_;
      }
    }
  }

  outcome::result<std::vector<uint8_t>> xsalsa20(gsl::span<const uint8_t> key,
                                                gsl::span<const uint8_t> nonce,
                                                gsl::span<const uint8_t> message) {
    if (key.size() != kKeySize) {
      return XSalsa20Error::WRONG_KEY_SIZE;
    }
    if (nonce.size() != kNonceSize) {
      return XSalsa20Error::WRONG_NONCE_SIZE;
    }
    XSalsa20Stream stream(key, nonce);
    std::vector<uint8_t> out(message.begin(), message.end());
    stream.crypt(out);
    return out;
  }

  outcome::result<std::array<uint8_t, kNonceSize>> generateNonce() {
    std::array<uint8_t, kNonceSize> nonce{};
    if (RAND_bytes(nonce.data(), static_cast<int>(kNonceSize)) != 1) {
      return XSalsa20Error::NONCE_GENERATION_FAILED;
    }
    return nonce;
  }

}  // namespace libp2p::crypto::xsalsa20

OUTCOME_CPP_DEFINE_CATEGORY_3(libp2p::crypto::xsalsa20, XSalsa20Error, e) {
  using E = libp2p::crypto::xsalsa20::XSalsa20Error;
  switch (e) {
    case E::WRONG_KEY_SIZE:
      return "wrong XSalsa20 key size (expected 32 bytes)";
    case E::WRONG_NONCE_SIZE:
      return "wrong XSalsa20 nonce size (expected 24 bytes)";
    case E::NONCE_GENERATION_FAILED:
      return "failed to generate nonce from CSPRNG";
  }
  return "unknown XSalsa20 error";
}
