/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <libp2p/protocol/kademlia/error.hpp>

OUTCOME_CPP_DEFINE_CATEGORY_3(libp2p::protocol::kademlia, Error, e) {
  using E = libp2p::protocol::kademlia::Error;
  switch (e) {
    case E::NO_PEERS:
      return "no peers found";
    case E::MESSAGE_PARSE_ERROR:
      return "message parse error";
    case E::MESSAGE_DESERIALIZE_ERROR:
      return "message deserialize error";
    case E::MESSAGE_SERIALIZE_ERROR:
      return "message serialize error";
    case E::MESSAGE_WRONG:
      return "invalid message data";
    case E::UNEXPECTED_MESSAGE_TYPE:
      return "unexpected_message_type";
    case E::STREAM_RESET:
      return "stream reset";
    case E::VALUE_NOT_FOUND:
      return "value not found";
    case E::CONTENT_VALIDATION_FAILED:
      return "content validation failed";
    case E::TIMEOUT:
      return "operation timed out";
    case E::IN_PROGRESS:
      return "operation in progress";
    case E::FULFILLED:
      return "operation already was done";
    case E::NOT_IMPLEMENTED:
      return "feature is not implemented";
    case E::INTERNAL_ERROR:
      return "internal error";
    case E::SESSION_CLOSED:
      return "session was closed";
  }
  return "unknown error (libp2p::protocol::kademlia::Error)";
}
