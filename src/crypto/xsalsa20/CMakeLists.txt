#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

libp2p_add_library(p2p_crypto_xsalsa20
    xsalsa20.cpp
    )
target_link_libraries(p2p_crypto_xsalsa20
    PUBLIC
    Boost::boost
    OpenSSL::Crypto
    )
