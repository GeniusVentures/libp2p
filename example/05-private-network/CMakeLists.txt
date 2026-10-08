#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_executable(libp2p_private_network_example
    private_network_example.cpp
    )
target_link_libraries(libp2p_private_network_example
    Boost::Boost.DI
    p2p_basic_host
    p2p_default_network
    p2p_pnet
    p2p_pnet_upgrader
    p2p_peer_repository
    p2p_inmem_address_repository
    p2p_inmem_key_repository
    p2p_inmem_protocol_repository
    p2p_protocol_echo
    p2p_literals
    Boost::date_time
    Boost::regex
    ${WIN_CRYPT_LIBRARY}
    )
