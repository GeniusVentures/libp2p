#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
find_package(Protobuf REQUIRED)
add_proto_library(p2p_identify_proto
    identify.proto
    )
