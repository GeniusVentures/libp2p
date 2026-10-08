/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <libp2p/security/pnet/psk.hpp>

#include <openssl/crypto.h>

#include <algorithm>
#include <vector>

#include <libp2p/common/hexutil.hpp>
#include <libp2p/multi/multibase_codec/codecs/base64.hpp>
#include <libp2p/security/pnet/pnet_error.hpp>

namespace libp2p::security::pnet {

  namespace {

    /// Trim trailing CR/LF/space/tab (go-ipfs swarm.key files end with \n)
    std::string_view trimTrailingWhitespace(std::string_view s) {
      while (!s.empty()
             && (s.back() == '\n' || s.back() == '\r' || s.back() == ' '
                 || s.back() == '\t')) {
        s.remove_suffix(1);
      }
      return s;
    }

  }  // namespace

  Psk::Psk(Psk &&other) noexcept {
    std::copy(other.key_.begin(), other.key_.end(), key_.begin());
    OPENSSL_cleanse(other.key_.data(), other.key_.size());
  }

  Psk &Psk::operator=(Psk &&other) noexcept {
    if (this != &other) {
      std::copy(other.key_.begin(), other.key_.end(), key_.begin());
      OPENSSL_cleanse(other.key_.data(), other.key_.size());
    }
    return *this;
  }

  Psk::~Psk() {
    OPENSSL_cleanse(key_.data(), key_.size());
  }

  outcome::result<Psk> Psk::fromDecoded(std::vector<uint8_t> decoded) {
    if (decoded.size() != kPskSize) {
      return PnetError::PNET_INVALID_PSK_LENGTH;
    }
    Psk psk;
    std::copy(decoded.begin(), decoded.end(), psk.key_.begin());
    // creation from .value() requires move; both are fine because we return
    // by value through outcome::result's move construction
    return psk;
  }

  outcome::result<Psk> Psk::fromRawBytes(gsl::span<const uint8_t> bytes) {
    if (bytes.size() != kPskSize) {
      return PnetError::PNET_INVALID_PSK_LENGTH;
    }
    std::vector<uint8_t> decoded(bytes.begin(), bytes.end());
    return fromDecoded(std::move(decoded));
  }

  outcome::result<Psk> Psk::fromBase16String(std::string_view hex) {
    // decode-framework failure (non-hex chars, odd length) → FORMAT error
    auto decoded = common::unhex(trimTrailingWhitespace(hex));
    if (!decoded) {
      return PnetError::PNET_INVALID_PSK_FORMAT;
    }
    return fromDecoded(std::move(decoded.value()));
  }

  outcome::result<Psk> Psk::fromBase64String(std::string_view b64) {
    // NOTE: materialize into a std::string — decodeBase64's validator uses
    // the C-string regex overload and would read past a non-terminated view
    // (e.g. a payload sliced out of the middle of swarm.key text)
    std::string payload{trimTrailingWhitespace(b64)};
    auto decoded = multi::detail::decodeBase64(payload);
    if (!decoded) {
      return PnetError::PNET_INVALID_PSK_FORMAT;
    }
    return fromDecoded(std::move(decoded.value()));
  }

  outcome::result<Psk> Psk::fromSwarmKeyText(std::string_view text) {
    // Expected framing (go-ipfs swarm.key):
    //   line 1: /key/swarm/psk/1.0.0/
    //   line 2: /base16/ or /base64/
    //   line 3: payload
    constexpr std::string_view kHeader = "/key/swarm/psk/1.0.0/";
    constexpr std::string_view kBase16 = "/base16/";
    constexpr std::string_view kBase64 = "/base64/";

    const std::string_view trimmed = trimTrailingWhitespace(text);

    // header line
    if (trimmed.substr(0, kHeader.size()) != kHeader) {
      return PnetError::PNET_INVALID_PSK_FORMAT;
    }
    std::string_view rest = trimmed.substr(kHeader.size());

    // skip the newline(s) between header and codec line
    while (!rest.empty() && (rest.front() == '\n' || rest.front() == '\r')) {
      rest.remove_prefix(1);
    }

    if (rest.substr(0, kBase16.size()) == kBase16) {
      std::string_view payload = rest.substr(kBase16.size());
      while (!payload.empty()
             && (payload.front() == '\n' || payload.front() == '\r')) {
        payload.remove_prefix(1);
      }
      return fromBase16String(payload);
    }
    if (rest.substr(0, kBase64.size()) == kBase64) {
      std::string_view payload = rest.substr(kBase64.size());
      while (!payload.empty()
             && (payload.front() == '\n' || payload.front() == '\r')) {
        payload.remove_prefix(1);
      }
      return fromBase64String(payload);
    }
    // wrong version already caught by the exact header match above;
    // any other codec line (e.g. /bin/) or malformed framing lands here
    return PnetError::PNET_INVALID_PSK_FORMAT;
  }

  gsl::span<const uint8_t> Psk::span() const noexcept {
    return gsl::span<const uint8_t>(key_.data(), key_.size());
  }

}  // namespace libp2p::security::pnet
