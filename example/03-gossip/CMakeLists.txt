#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
find_package(Boost REQUIRED COMPONENTS date_time filesystem random program_options)

link_directories(${Boost_LIB_DIR_STR})

if(Boost_FOUND)
    message("Boost is found!")
endif()
libp2p_add_library(gossip_common
    utility.cpp
#    console_async_reader.cpp
    )

target_link_libraries(gossip_common
    p2p_basic_host
    p2p_default_network
    p2p_peer_repository
    p2p_inmem_address_repository
    p2p_inmem_key_repository
    p2p_inmem_protocol_repository
    p2p_gossip
    asio_scheduler
    Boost::program_options    
    )

add_executable(gossip_chat_example
    gossip_chat_example.cpp
    )

set_target_properties(gossip_chat_example PROPERTIES LINK_FLAGS "/FORCE:MULTIPLE")
target_link_libraries(gossip_chat_example
    gossip_common   
    )
