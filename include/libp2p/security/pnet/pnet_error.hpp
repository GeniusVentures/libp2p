/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LIBP2P_SECURITY_PNET_PNET_ERROR_HPP
#define LIBP2P_SECURITY_PNET_PNET_ERROR_HPP

#include <libp2p/outcome/outcome.hpp>

namespace libp2p::security::pnet {

  enum class PnetError {
    PNET_INVALID_PSK_FORMAT = 1,  ///< PSK string/file malformed (bad framing,
                                   ///< encoding, or version)
    PNET_INVALID_PSK_LENGTH,       ///< decoded PSK is not exactly 32 bytes
    PNET_NONCE_GENERATION_FAILED,  ///< failed to generate the 24-byte nonce
    PNET_NONCE_READ_FAILED,        ///< failed to read the peer's nonce
    PNET_ENCRYPT_FAILED,           ///< failed to encrypt/decrypt protection
                                   ///< layer bytes
    PNET_PUBLIC_BOOTSTRAP_REFUSED, ///< private network refuses dialing public
                                   ///< bootstrap addresses
  };

}  // namespace libp2p::security::pnet

OUTCOME_HPP_DECLARE_ERROR(libp2p::security::pnet, PnetError)

#endif  // LIBP2P_SECURITY_PNET_PNET_ERROR_HPP
