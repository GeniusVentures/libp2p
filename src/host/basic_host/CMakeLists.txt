# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

libp2p_add_library(p2p_basic_host
    basic_host.cpp
    )
target_link_libraries(p2p_basic_host
    Boost::boost
    p2p_multiaddress
    p2p_relay_addresses
	p2p_observed_addresses
    )
