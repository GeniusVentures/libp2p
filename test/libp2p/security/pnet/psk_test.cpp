/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * D-05 parse-matrix tests for the pnet pre-shared key type.
 */
#include <libp2p/security/pnet/pnet_error.hpp>
#include <libp2p/security/pnet/psk.hpp>

#include <gtest/gtest.h>

#include <type_traits>
#include <vector>

using namespace libp2p::security::pnet;

namespace {
  // fixed 32-byte test key: 0x00..0x1f
  const std::vector<uint8_t> kKeyBytes = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

  // base16 of kKeyBytes (lowercase)
  constexpr std::string_view kKeyHex =
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

  // base64 of kKeyBytes
  constexpr std::string_view kKeyB64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

  std::vector<uint8_t> spanToVec(gsl::span<const uint8_t> s) {
    return {s.begin(), s.end()};
  }
}  // namespace

// compile-time hygiene: copy is deleted, move is allowed (D-06)
static_assert(!std::is_copy_constructible_v<Psk>);
static_assert(!std::is_copy_assignable_v<Psk>);
static_assert(std::is_move_constructible_v<Psk>);
static_assert(std::is_move_assignable_v<Psk>);

/**
 * @given a complete go-ipfs swarm.key text with /base16/ framing
 * @when parsed via fromSwarmKeyText
 * @then a 32-byte Psk is produced matching the decoded key bytes
 */
TEST(PskTest, SwarmKeyBase16Valid) {
  std::string text = "/key/swarm/psk/1.0.0/\n/base16/";
  text += kKeyHex;
  text += "\n";
  auto res = Psk::fromSwarmKeyText(text);
  ASSERT_TRUE(res);
  ASSERT_EQ(res.value().span().size(), 32u);
  ASSERT_EQ(spanToVec(res.value().span()), kKeyBytes);
}

/** Same as SwarmKeyBase16Valid but with /base64/ framing */
TEST(PskTest, SwarmKeyBase64Valid) {
  std::string text = "/key/swarm/psk/1.0.0/\n/base64/";
  text += kKeyB64;
  text += "\n";
  auto res = Psk::fromSwarmKeyText(text);
  ASSERT_TRUE(res);
  ASSERT_EQ(spanToVec(res.value().span()), kKeyBytes);
}

/** Uppercase hex payload is accepted (case-insensitive unhex) */
TEST(PskTest, SwarmKeyBase16UppercaseValid) {
  std::string text = "/key/swarm/psk/1.0.0/\n/base16/";
  std::string upper(kKeyHex);
  for (auto &c : upper) {
    c = static_cast<char>(::toupper(static_cast<unsigned char>(c)));
  }
  text += upper;
  auto res = Psk::fromSwarmKeyText(text);
  ASSERT_TRUE(res);
  ASSERT_EQ(spanToVec(res.value().span()), kKeyBytes);
}

/**
 * @given raw (unframed) key material in hex, base64, and byte form
 * @when parsed via the dedicated constructors
 * @then all three produce identical span() bytes
 */
TEST(PskTest, RawConstructorsAgree) {
  auto from_hex = Psk::fromBase16String(kKeyHex);
  auto from_b64 = Psk::fromBase64String(kKeyB64);
  auto from_raw = Psk::fromRawBytes(kKeyBytes);
  ASSERT_TRUE(from_hex);
  ASSERT_TRUE(from_b64);
  ASSERT_TRUE(from_raw);
  ASSERT_EQ(spanToVec(from_hex.value().span()), kKeyBytes);
  ASSERT_EQ(spanToVec(from_b64.value().span()), kKeyBytes);
  ASSERT_EQ(spanToVec(from_raw.value().span()), kKeyBytes);
}

/** 31-byte and 33-byte raw inputs are rejected with PNET_INVALID_PSK_LENGTH */
TEST(PskTest, RejectsWrongRawLength) {
  std::vector<uint8_t> short_key(kKeyBytes.begin(), kKeyBytes.begin() + 31);
  auto res31 = Psk::fromRawBytes(short_key);
  ASSERT_FALSE(res31);
  ASSERT_EQ(res31.error(), PnetError::PNET_INVALID_PSK_LENGTH);

  std::vector<uint8_t> long_key = kKeyBytes;
  long_key.push_back(0x20);
  auto res33 = Psk::fromRawBytes(long_key);
  ASSERT_FALSE(res33);
  ASSERT_EQ(res33.error(), PnetError::PNET_INVALID_PSK_LENGTH);
}

/** 62/66-char hex payloads (decoding to 31/33 bytes) are rejected too */
TEST(PskTest, RejectsWrongDecodedLength) {
  std::string hex31(kKeyHex.begin(), kKeyHex.begin() + 62);  // 31 bytes
  auto res = Psk::fromBase16String(hex31);
  ASSERT_FALSE(res);
  ASSERT_EQ(res.error(), PnetError::PNET_INVALID_PSK_LENGTH);

  std::string hex33(kKeyHex);
  hex33 += "20";  // 33 bytes
  res = Psk::fromBase16String(hex33);
  ASSERT_FALSE(res);
  ASSERT_EQ(res.error(), PnetError::PNET_INVALID_PSK_LENGTH);
}

/** 64-char non-hex payload is rejected with PNET_INVALID_PSK_FORMAT */
TEST(PskTest, RejectsNonHexPayload) {
  constexpr std::string_view bad =
      "zz0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e0f";
  static_assert(bad.size() == 64);
  auto res = Psk::fromBase16String(bad);
  ASSERT_FALSE(res);
  ASSERT_EQ(res.error(), PnetError::PNET_INVALID_PSK_FORMAT);
}

/** Missing header or wrong version → PNET_INVALID_PSK_FORMAT */
TEST(PskTest, RejectsMissingOrWrongHeader) {
  auto res = Psk::fromSwarmKeyText(kKeyHex);  // raw hex, no framing at all
  ASSERT_FALSE(res);
  ASSERT_EQ(res.error(), PnetError::PNET_INVALID_PSK_FORMAT);

  std::string wrong_version = "/key/swarm/psk/2.0.0/\n/base16/";
  wrong_version += kKeyHex;
  res = Psk::fromSwarmKeyText(wrong_version);
  ASSERT_FALSE(res);
  ASSERT_EQ(res.error(), PnetError::PNET_INVALID_PSK_FORMAT);
}

/** /bin/ codec framing is rejected (no reliable length framing) */
TEST(PskTest, RejectsBinCodec) {
  std::string text = "/key/swarm/psk/1.0.0/\n/bin/\x00\x01\x02";
  auto res = Psk::fromSwarmKeyText(text);
  ASSERT_FALSE(res);
  ASSERT_EQ(res.error(), PnetError::PNET_INVALID_PSK_FORMAT);
}

/**
 * @given a Psk
 * @when moved
 * @then the moved-to object yields the original 32 bytes and the type stays
 *        move-constructible/assignable (compile-time asserts above)
 */
TEST(PskTest, MoveOnlyHygiene) {
  auto res = Psk::fromRawBytes(kKeyBytes);
  ASSERT_TRUE(res);
  Psk moved{std::move(res.value())};
  ASSERT_EQ(spanToVec(moved.span()), kKeyBytes);

  auto res2 = Psk::fromRawBytes(kKeyBytes);
  ASSERT_TRUE(res2);
  auto assigned = Psk::fromRawBytes(kKeyBytes);  // factory-only construction
  ASSERT_TRUE(assigned);
  Psk target{std::move(assigned.value())};
  target = std::move(res2.value());  // move-assign between Psk objects
  ASSERT_EQ(spanToVec(target.span()), kKeyBytes);
}

/** Every PnetError enumerator formats a message containing "pnet:" */
TEST(PskTest, ErrorMessagesCarryAttribution) {
  for (auto e : {PnetError::PNET_INVALID_PSK_FORMAT,
                 PnetError::PNET_INVALID_PSK_LENGTH,
                 PnetError::PNET_NONCE_GENERATION_FAILED,
                 PnetError::PNET_NONCE_READ_FAILED,
                 PnetError::PNET_ENCRYPT_FAILED,
                 PnetError::PNET_PUBLIC_BOOTSTRAP_REFUSED}) {
    std::error_code ec = make_error_code(e);
    ASSERT_NE(ec.message().find("pnet:"), std::string::npos)
        << "message missing pnet: attribution: " << ec.message();
    ASSERT_FALSE(ec.message().empty());
  }
}
