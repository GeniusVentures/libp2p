#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_subdirectory(protobuf)

libp2p_add_library(p2p_holepunch_server
    holepunch_server.cpp
	holepunch_server_msg_processor.cpp
    )
target_link_libraries(p2p_holepunch_server
    p2p
    p2p_holepunch_proto
    p2p_protobuf_message_read_writer
    p2p_logger
    )

libp2p_add_library(p2p_holepunch_client
    holepunch_client.cpp
	holepunch_client_msg_processor.cpp
    )
target_link_libraries(p2p_holepunch_client
    p2p
    p2p_holepunch_proto
    p2p_protobuf_message_read_writer
    p2p_logger
    )