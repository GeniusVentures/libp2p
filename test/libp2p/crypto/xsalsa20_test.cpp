/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Known-answer tests for the vendored XSalsa20 cipher (decision D-03).
 *
 * All expected values are transcribed verbatim from upstream published
 * test-vector files (never computed by the code under test):
 *   - libsodium test/default/stream.c + stream.exp  (XSalsa20 golden pair
 *     firstkey/nonce shared with Go x/crypto/salsa20; the SHA-256 of the
 *     full 4 MiB keystream and the per-length keystream hex lines)
 *   - libsodium test/default/core2.c + core2.exp    (HSalsa20 subkey vector)
 */
#include <libp2p/crypto/xsalsa20/xsalsa20.hpp>

#include <gtest/gtest.h>
#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <vector>

using namespace libp2p::crypto::xsalsa20;

namespace {
  // libsodium test/default/stream.c + core2.c — firstkey[32] and nonce[24]
  // (the golden pair also carried by Go x/crypto/salsa20 salsa_test.go)
  const std::array<uint8_t, kKeySize> kFirstkey = {
      0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51, 0x19,
      0x7a, 0x9a, 0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
      0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89};

  const std::array<uint8_t, kNonceSize> kNonce = {
      0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73, 0xcd, 0x62, 0xbd, 0xa8,
      0x75, 0xfc, 0x73, 0xd6, 0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37};

  // libsodium test/default/core2.exp — HSalsa20 subkey:
  // crypto_core_hsalsa20(secondkey, nonceprefix, firstkey, sigma)
  const std::array<uint8_t, kKeySize> kSecondkey = {
      0xdc, 0x90, 0x8d, 0xda, 0x0b, 0x93, 0x44, 0xa9, 0x53, 0x62, 0x9b, 0x73,
      0x38, 0x20, 0x77, 0x88, 0x80, 0xf3, 0xce, 0xb4, 0x21, 0xbb, 0x61, 0xb9,
      0x1c, 0xbd, 0x4c, 0x3e, 0x66, 0x25, 0x6c, 0xe4};

  // libsodium test/default/stream.exp — first 63 keystream bytes: the common
  // prefix of the per-length hex lines (the i-length lines carry exactly i
  // keystream bytes; their final byte is the memset fill value i, not
  // keystream — so the longest usable line, i=63, yields bytes 0..62).
  // Byte 63 onward is proven by the 4 MiB SHA-256 KAT below. Exercising this
  // prefix = encrypting 63 zero bytes, i.e. the head of Salsa20 block 0 keyed
  // with the HSalsa20 subkey.
  const std::vector<uint8_t> kKeystreamFirst63 = {
      0xee, 0xa6, 0xa7, 0x25, 0x1c, 0x1e, 0x72, 0x91,
      0x6d, 0x11, 0xc2, 0xcb, 0x21, 0x4d, 0x3c, 0x25,
      0x25, 0x39, 0x12, 0x1d, 0x8e, 0x23, 0x4e, 0x65,
      0x2d, 0x65, 0x1f, 0xa4, 0xc8, 0xcf, 0xf8, 0x80,
      0x30, 0x9e, 0x64, 0x5a, 0x74, 0xe9, 0xe0, 0xa6,
      0x0d, 0x82, 0x43, 0xac, 0xd9, 0x17, 0x7a, 0xb5,
      0x1a, 0x1b, 0xeb, 0x8d, 0x5a, 0x2f, 0x5d, 0x70,
      0x0c, 0x09, 0x3c, 0x5e, 0x55, 0x85, 0x57};

  // libsodium test/default/stream.exp first line — SHA-256 of the full
  // 4 MiB XSalsa20 keystream (crypto_stream of 4194304 bytes then SHA-256)
  const std::array<uint8_t, 32> kKeystream4MiBSha256 = {
      0x66, 0x2b, 0x9d, 0x0e, 0x34, 0x63, 0x02, 0x91, 0x56, 0x06, 0x9b, 0x12,
      0xf9, 0x18, 0x69, 0x1a, 0x98, 0xf7, 0xdf, 0xb2, 0xca, 0x03, 0x93, 0xc9,
      0x6b, 0xbf, 0xc6, 0xb1, 0xfb, 0xd6, 0x30, 0xa2};

  std::vector<uint8_t> makePattern(size_t n) {
    std::vector<uint8_t> v(n);
    for (size_t i = 0; i < n; ++i) {
      v[i] = static_cast<uint8_t>(i * 7 + 3);
    }
    return v;
  }
}  // namespace

/**
 * @given the published libsodium firstkey/nonce golden pair
 * @when the vendored cipher encrypts 63 zero bytes (keystream exposure)
 * @then the result matches the published keystream prefix byte-for-byte
 *        — which transitively validates the HSalsa20 subkey derivation,
 *        since block 0 is Salsa20(HSalsa20(key, nonce[0..16)), ...)
 */
TEST(XSalsa20Test, KnownAnswerFirstBlockAndSubkeyChain) {
  std::vector<uint8_t> zeros(63, 0);
  XSalsa20Stream stream(kFirstkey, kNonce);
  stream.crypt(zeros);
  ASSERT_EQ(zeros, kKeystreamFirst63);
}

/**
 * @given the stream.exp full-keystream SHA-256 line
 * @when a 4 MiB keystream is generated in uneven chunks and hashed
 * @then SHA-256 matches the published 662b9d0e... value — multi-block
 *        correctness past block 0, including the 64-bit counter layout and
 *        chunk-boundary positioning at scale
 */
TEST(XSalsa20Test, KnownAnswerFull4MiBKeystream) {
  constexpr size_t kSize = 4194304;
  std::vector<uint8_t> buf(kSize, 0);
  XSalsa20Stream stream(kFirstkey, kNonce);
  const size_t chunks[] = {1, 3, 64, 7, 1000, 100000};
  size_t done = 0;
  size_t ci = 0;
  while (done < kSize) {
    const size_t n = std::min(chunks[ci % 6], kSize - done);
    stream.crypt(gsl::span<uint8_t>(buf).subspan(done, n));
    done += n;
    ++ci;
  }
  std::array<uint8_t, 32> digest{};
  SHA256(buf.data(), buf.size(), digest.data());
  ASSERT_EQ(digest, kKeystream4MiBSha256);
}

/**
 * @given 200 bytes of plaintext and the golden key/nonce
 * @when encrypted one-shot vs through one stream in chunks (1,3,64,7,100,
 *        remainder) and decrypted through a different partition (5,60,135)
 * @then chunked results are byte-identical to the one-shot result and the
 *        differently-chunked decrypt reproduces the plaintext (the libsodium
 *        crypto_stream_xsalsa20_xor_ic incremental-equivalence guarantee)
 */
TEST(XSalsa20Test, IncrementalPositioningUnequalChunks) {
  const auto plain = makePattern(200);

  auto one_shot = xsalsa20(kFirstkey, kNonce, plain);
  ASSERT_TRUE(one_shot);

  std::vector<uint8_t> chunked(plain);
  XSalsa20Stream enc(kFirstkey, kNonce);
  const size_t enc_parts[] = {1, 3, 64, 7, 100, 25};
  size_t off = 0;
  for (size_t n : enc_parts) {
    enc.crypt(gsl::span<uint8_t>(chunked).subspan(off, n));
    off += n;
  }
  ASSERT_EQ(off, 200u);
  ASSERT_EQ(chunked, one_shot.value());

  // decrypt with a DIFFERENT partition than encryption used
  std::vector<uint8_t> decrypted = chunked;
  XSalsa20Stream dec(kFirstkey, kNonce);
  const size_t dec_parts[] = {5, 60, 135};
  off = 0;
  for (size_t n : dec_parts) {
    dec.crypt(gsl::span<uint8_t>(decrypted).subspan(off, n));
    off += n;
  }
  ASSERT_EQ(decrypted, plain);
}

/**
 * @given spans crossing multiple 64-byte blocks
 * @when a fresh stream encrypts a span, and another fresh stream decrypts it
 * @then the original bytes are reproduced (crypt is an involution across
 *        instances; a single instance XORs with the NEXT keystream by design)
 */
TEST(XSalsa20Test, DecryptIsEncryptVariousLengths) {
  for (size_t len : {1u, 63u, 64u, 65u, 200u}) {
    const auto data = makePattern(len);
    auto encrypted = data;
    XSalsa20Stream s1(kFirstkey, kNonce);
    s1.crypt(encrypted);
    ASSERT_NE(encrypted, data) << "len " << len;
    auto decrypted = encrypted;
    XSalsa20Stream s2(kFirstkey, kNonce);
    s2.crypt(decrypted);
    ASSERT_EQ(decrypted, data) << "len " << len;
  }
}

/**
 * @given a stream fed an empty span before real data
 * @when crypt(empty) runs, then a short crypt
 * @then the empty call is a no-op: position unchanged (matches a fresh
 *        stream at offset 0)
 */
TEST(XSalsa20Test, EmptyInputIsNoOp) {
  const auto plain = makePattern(40);

  XSalsa20Stream with_empty(kFirstkey, kNonce);
  with_empty.crypt(gsl::span<uint8_t>());
  std::vector<uint8_t> a(plain);
  with_empty.crypt(a);

  std::vector<uint8_t> b(plain);
  XSalsa20Stream fresh(kFirstkey, kNonce);
  fresh.crypt(b);

  ASSERT_EQ(a, b);
}

/**
 * @given the one-shot free function and a manually constructed stream
 * @when both process the same message
 * @then results are identical
 */
TEST(XSalsa20Test, OneShotFreeFunctionEqualsStream) {
  const auto msg = makePattern(150);
  auto one_shot = xsalsa20(kFirstkey, kNonce, msg);
  ASSERT_TRUE(one_shot);

  std::vector<uint8_t> stream_result(msg);
  XSalsa20Stream stream(kFirstkey, kNonce);
  stream.crypt(stream_result);
  ASSERT_EQ(stream_result, one_shot.value());
}

/** Wrong key/nonce sizes are rejected by the one-shot entry point */
TEST(XSalsa20Test, OneShotRejectsWrongSizes) {
  const auto msg = makePattern(10);
  ASSERT_FALSE(xsalsa20(gsl::span<const uint8_t>(kFirstkey).first(31), kNonce, msg));
  ASSERT_FALSE(xsalsa20(kFirstkey, gsl::span<const uint8_t>(kNonce).first(23), msg));
}

/**
 * @given generateNonce()
 * @when called twice
 * @then both succeed with exactly 24 bytes and the two nonces differ
 *        (CSPRNG sanity; OpenSSL RAND_bytes per D-04)
 */
TEST(XSalsa20Test, NonceGeneration) {
  auto n1 = generateNonce();
  ASSERT_TRUE(n1);
  ASSERT_EQ(n1.value().size(), kNonceSize);
  auto n2 = generateNonce();
  ASSERT_TRUE(n2);
  ASSERT_NE(n1.value(), n2.value());
}

