#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

addtest(psk_test
    psk_test.cpp
    )
target_link_libraries(psk_test
    p2p_pnet
    )

addtest(pnet_protected_connection_test
    pnet_protected_connection_test.cpp
    )
target_link_libraries(pnet_protected_connection_test
    p2p_pnet
    p2p_crypto_xsalsa20
    p2p_manual_scheduler_backend
    p2p_testutil
    )

addtest(pnet_upgrader_decorator_test
    pnet_upgrader_decorator_test.cpp
    )
target_link_libraries(pnet_upgrader_decorator_test
    p2p_pnet_upgrader
    p2p_manual_scheduler_backend
    p2p_testutil
    p2p_literals
    )
