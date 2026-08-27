#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

libp2p_add_library(p2p_pnet
    pnet_error.cpp
    psk.cpp
    )
target_link_libraries(p2p_pnet
    PUBLIC
    Boost::boost
    OpenSSL::Crypto
    p2p_hexutil
    p2p_multibase_codec
    )
