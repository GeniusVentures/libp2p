/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LIBP2P_HOST_INJECTOR_HPP
#define LIBP2P_HOST_INJECTOR_HPP

#include <libp2p/injector/network_injector.hpp>

// implementations
#include <libp2p/host/basic_host.hpp>
#include <libp2p/peer/address_repository/inmem_address_repository.hpp>
#include <libp2p/peer/impl/peer_repository_impl.hpp>
#include <libp2p/peer/key_repository/inmem_key_repository.hpp>
#include <libp2p/peer/protocol_repository/inmem_protocol_repository.hpp>
#include <libp2p/protocol/common/asio/asio_scheduler.hpp>

namespace libp2p::injector {

  template <typename InjectorConfig = BOOST_DI_CFG, typename... Ts>
  inline auto makeHostInjector(Ts &&... args) {
    using namespace boost;  // NOLINT

    // clang-format off
    return di::make_injector<InjectorConfig>(
        makeNetworkInjector<InjectorConfig>(),

        // repositories
        di::bind<peer::PeerRepository>.TEMPLATE_TO<peer::PeerRepositoryImpl>(),
        di::bind<peer::AddressRepository>.TEMPLATE_TO<peer::InmemAddressRepository>(),
        di::bind<peer::KeyRepository>.TEMPLATE_TO<peer::InmemKeyRepository>(),
        di::bind<peer::ProtocolRepository>.TEMPLATE_TO<peer::InmemProtocolRepository>(),

        di::bind<protocol::SchedulerConfig>.TEMPLATE_TO(protocol::SchedulerConfig {}),
        di::bind<protocol::Scheduler>.TEMPLATE_TO<protocol::AsioScheduler>(),

        di::bind<Host>.TEMPLATE_TO<host::BasicHost>(),

        // user-defined overrides...
        std::forward<decltype(args)>(args)...
    );
    // clang-format on
  }

}  // namespace libp2p::injector

#endif  // LIBP2P_HOST_INJECTOR_HPP
