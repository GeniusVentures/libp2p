# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

addtest(tcp_integration_test
    tcp_integration_test.cpp
    )
target_link_libraries(tcp_integration_test
    p2p_tcp
    p2p_testutil
    p2p_literals
    p2p_basic_scheduler
    p2p_asio_scheduler_backend
    )


addtest(tcp_listener_test
    tcp_listener_test.cpp
    )
target_link_libraries(tcp_listener_test
    p2p_tcp_listener
    p2p_literals
    p2p_basic_scheduler
    p2p_manual_scheduler_backend
    p2p_connection_gater
    )
