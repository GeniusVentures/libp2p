#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_subdirectory(protobuf)

libp2p_add_library(p2p_autonat
    autonat.cpp
	autonat_msg_processor.cpp
    )
target_link_libraries(p2p_autonat
    p2p
    p2p_autonat_proto
    p2p_protobuf_message_read_writer
    p2p_logger
    )
