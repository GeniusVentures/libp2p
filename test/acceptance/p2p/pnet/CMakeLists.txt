#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

addtest(pnet_two_node_test
    pnet_two_node_test.cpp
    )
target_link_libraries(pnet_two_node_test
    p2p_default_network
    p2p_basic_host
    p2p_pnet
    p2p_pnet_upgrader
    p2p_peer_repository
    p2p_inmem_address_repository
    p2p_inmem_key_repository
    p2p_inmem_protocol_repository
    p2p_protocol_echo
    p2p_multiaddress
    p2p_testutil
    p2p_literals
    )
