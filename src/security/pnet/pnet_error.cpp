/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <libp2p/security/pnet/pnet_error.hpp>

#include <string>
#include <system_error>

OUTCOME_CPP_DEFINE_CATEGORY(libp2p::security::pnet, PnetError, e) {
  using E = libp2p::security::pnet::PnetError;
  switch (e) {
    case E::PNET_INVALID_PSK_FORMAT:
      return "pnet: invalid pre-shared key format";
    case E::PNET_INVALID_PSK_LENGTH:
      return "pnet: invalid pre-shared key length";
    case E::PNET_NONCE_GENERATION_FAILED:
      return "pnet: nonce generation failed";
    case E::PNET_NONCE_READ_FAILED:
      return "pnet: failed to read the peer's nonce";
    case E::PNET_ENCRYPT_FAILED:
      return "pnet: failed to encrypt/decrypt protected bytes";
    case E::PNET_PUBLIC_BOOTSTRAP_REFUSED:
      return "pnet: dialing public bootstrap addresses is refused in "
             "private-network mode";
  }
  return "pnet: unknown error";
}
