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
