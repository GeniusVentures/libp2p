#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_subdirectory(protobuf)

libp2p_add_library(p2p_relay_addresses
	relay_addresses.cpp
    )
libp2p_add_library(p2p_relay
    relay.cpp
	relay_msg_processor.cpp
    )
	
libp2p_add_library(p2p_relay_upgrader
    relay_conupgrader.cpp
	relay_conupgrader_msg_processor.cpp
    )
	
target_link_libraries(p2p_relay_addresses
    p2p
    p2p_logger
    )

target_link_libraries(p2p_relay
    p2p
    p2p_relay_proto
    p2p_protobuf_message_read_writer
	p2p_holepunch_server
	p2p_holepunch_proto
    p2p_logger
	p2p_relay_addresses
    )
	
target_link_libraries(p2p_relay_upgrader
    p2p
    p2p_relay_proto
    p2p_protobuf_message_read_writer
	p2p_holepunch_client
	p2p_holepunch_proto
	p2p_identify
    p2p_logger
    )
