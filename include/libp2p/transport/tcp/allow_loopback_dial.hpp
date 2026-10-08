/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LIBP2P_TRANSPORT_TCP_ALLOW_LOOPBACK_DIAL_HPP
#define LIBP2P_TRANSPORT_TCP_ALLOW_LOOPBACK_DIAL_HPP

namespace libp2p::transport {

  /**
   * DI-bindable opt-in flag for TcpTransport::dial()'s loopback-destination
   * guard. Absence of an explicit injector::useAllowLoopbackDial() binding
   * means loopback (127.0.0.0/8, ::1) dial destinations are rejected --
   * secure by default, per this project's core value that access control is
   * enforced at the network layer rather than left to the application layer.
   *
   * User-declared constructors (even the defaulted one) are REQUIRED here so
   * this type is not a C++ aggregate -- the exact same rationale
   * security::pnet::PskHandle documents in psk.hpp: Boost.DI applies
   * aggregate-member auto-injection to plain-data aggregates, which would
   * otherwise attempt to auto-construct the `allow` member whenever an
   * AllowLoopbackDial is needed but not explicitly bound. A bare `bool` ctor
   * parameter on TcpTransport itself would be ambiguous/unbindable for the
   * same reason a raw shared_ptr<const Psk> parameter was before PskHandle
   * existed.
   */
  struct AllowLoopbackDial {
    AllowLoopbackDial() = default;
    explicit AllowLoopbackDial(bool allow) : allow(allow) {}

    bool allow = false;
  };

}  // namespace libp2p::transport

#endif  // LIBP2P_TRANSPORT_TCP_ALLOW_LOOPBACK_DIAL_HPP
