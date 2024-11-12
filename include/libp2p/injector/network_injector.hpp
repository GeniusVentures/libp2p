/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LIBP2P_NETWORK_INJECTOR_HPP
#define LIBP2P_NETWORK_INJECTOR_HPP

#include "platform/platform.hpp"
#include <boost/di.hpp>

// implementations
#include <libp2p/crypto/aes_ctr/aes_ctr_impl.hpp>
#include <libp2p/crypto/crypto_provider/crypto_provider_impl.hpp>
#include <libp2p/crypto/ecdsa_provider/ecdsa_provider_impl.hpp>
#include <libp2p/crypto/ed25519_provider/ed25519_provider_impl.hpp>
#include <libp2p/crypto/hmac_provider/hmac_provider_impl.hpp>
#include <libp2p/crypto/key_marshaller/key_marshaller_impl.hpp>
#include <libp2p/crypto/key_validator/key_validator_impl.hpp>
#include <libp2p/crypto/random_generator/boost_generator.hpp>
#include <libp2p/crypto/rsa_provider/rsa_provider_impl.hpp>
#include <libp2p/crypto/secp256k1_provider/secp256k1_provider_impl.hpp>
#include <libp2p/muxer/mplex.hpp>
#include <libp2p/muxer/yamux.hpp>
#include <libp2p/basic/scheduler/asio_scheduler_backend.hpp>
#include <libp2p/basic/scheduler/scheduler_impl.hpp>
#include <libp2p/network/impl/connection_manager_impl.hpp>
#include <libp2p/network/impl/dialer_impl.hpp>
#include <libp2p/network/impl/dnsaddr_resolver_impl.hpp>
#include <libp2p/network/impl/listener_manager_impl.hpp>
#include <libp2p/network/impl/network_impl.hpp>
#include <libp2p/network/impl/router_impl.hpp>
#include <libp2p/network/impl/transport_manager_impl.hpp>
#include <libp2p/peer/impl/identity_manager_impl.hpp>
#include <libp2p/protocol_muxer/multiselect.hpp>
#include <libp2p/security/noise.hpp>
#include <libp2p/security/plaintext.hpp>
#include <libp2p/security/plaintext/exchange_message_marshaller_impl.hpp>
#include <libp2p/security/secio.hpp>
#include <libp2p/security/secio/exchange_message_marshaller_impl.hpp>
#include <libp2p/security/secio/propose_message_marshaller_impl.hpp>
#include <libp2p/security/tls.hpp>
#include <libp2p/transport/impl/upgrader_impl.hpp>
#include <libp2p/transport/tcp.hpp>

// clang-format off
/**
 * @file network_injector.hpp
 * @brief This header defines DI injector helpers, which can be used instead of
 * manual wiring.
 *
 * The main function in this header is
 * @code makeNetworkInjector() @endcode
 * Use it to create a Boost.DI container with default types.
 *
 * By default:
 * - TCP is used as transport
 * - Plaintext as security
 * - Yamux as muxer
 * - Random keypair is generated
 *
 * List of libraries that should be linked to your lib/exe:
 *  - libp2p_network
 *  - libp2p_tcp
 *  - libp2p_yamux
 *  - libp2p_plaintext
 *  - libp2p_connection_manager
 *  - libp2p_transport_manager
 *  - libp2p_listener_manager
 *  - libp2p_identity_manager
 *  - libp2p_dialer
 *  - libp2p_router
 *  - multiselect
 *  - random_generator
 *  - key_generator
 *  - marshaller
 *
 * <b>Example 1</b>: Make default network with Yamux as muxer, Plaintext as
 * security, TCP as transport.
 * @code
 * auto injector = makeNetworkInjector();
 * std::shared_ptr<Network> network = injector.create<std::shared_ptr<Network>>();
 * assert(network != nullptr);
 * @endcode
 *
 * <b>Example 2</b>: Make network with new transport, muxer and security.
 * @code
 * struct NewTransport : public TransportAdaptor {...};
 * struct NewMuxer : public MuxerAdaptor {...};
 * struct NewSecurity : public SecurityAdaptor {...};
 *
 * auto injector = makeNetworkInjector(
 *   useTransportAdaptors<NewTransport>(),
 *   useMuxerAdaptors<NewMuxer>(),
 *   useSecurityAdaptors<NewSecurity>()
 * );
 *
 * std::shared_ptr<Network> network = injector.create<std::shared_ptr<Network>>();
 * assert(network != nullptr);
 * @endcode
 *
 * <b>Example 3</b>: Use mocked router:
 * @code
 * struct RouterMock : public Router {...};
 *
 * auto injector = makeNetworkInjector(
 *   boost::di::bind<Router>.to<RouterMock>()
 * );
 *
 * // build network
 * std::shared_ptr<Network> network = injector.create<std::shared_ptr<Network>>();
 * assert(network != nullptr);
 *
 * // get mock
 * std::shared_ptr<RouterMock> routerMock = injector.create<std::shared_ptr<RouterMock>>();
 * assert(routerMock != nullptr);
 * @endcode
 *
 * <b>Example 4</b>: Use instance of mock.
 * @code
 * struct RouterMock : public Router {...};
 *
 * auto routerMock = std::make_shared<RouterMock>();
 *
 * auto injector = makeNetworkInjector(
 *   boost::di::bind<Router>.to(routerMock)
 * );
 *
 * // build network
 * std::shared_ptr<Network> network = injector.create<std::shared_ptr<Network>>();
 * assert(network != nullptr);
 * @endcode
 */

// clang-format on

namespace libp2p::injector {

  /**
   * @brief Instruct injector to use this keypair. Can be used once.
   *
   * @code
   * KeyPair keyPair = {...};
   * auto injector = makeNetworkInjector(
   *   useKeyPair(std::move(keyPair))
   * );
   * @endcode
   */
  inline auto useKeyPair(const crypto::KeyPair &key_pair) {
    return boost::di::bind<crypto::KeyPair>().TEMPLATE_TO(
        key_pair)[boost::di::override];
  }

  /**
   * @brief Instruct injector to use specific config type. Can be used many
   * times for different types.
   * @tparam C config type
   * @param c config instance
   * @return injector binding
   *
   * @code
   * // config definition
   * struct YamuxConfig {
   *   int a = 5;
   * }
   *
   * // config consumer definition
   * struct Yamux {
   *   Yamux(YamuxConfig config);
   * }
   *
   * // create injector
   * auto injector = makeNetworkInjector(
   *   // change default value a=5 to a=3
   *   useConfig<YamuxConfig>({.a = 3})
   * );
   * @endcode
   */
  template <typename C>
  inline auto useConfig(C &&c) {
    return boost::di::bind<std::decay<C>>().TEMPLATE_TO(
        std::forward<C>(c))[boost::di::override];
  }

  /**
   * @brief Bind security adaptors by type. Can be used once. Technically many
   * types can be specified, even the same type, but in the end only 1 instance
   * for each type is created.
   * @tparam SecImpl one or many types of security adaptors to be used
   * @return injector binding
   *
   * @code
   * struct SomeNewAdaptor : public SecurityAdaptor {...};
   *
   * auto injector = makeNetworkInjector(
   *   useSecurityAdaptors<Plaintext, SomeNewAdaptor, SecioAdaptor>()
   * );
   * @endcode
   */
  template <typename... SecImpl>
  inline auto useSecurityAdaptors() {
    return boost::di::bind<security::SecurityAdaptor *[]>()  // NOLINT
        .TEMPLATE_TO<SecImpl...>()[boost::di::override];
  }

  /**
   * @brief Bind muxer adaptors by types. Can be used once. Technically many
   * types can be specified, even the same type, but in the end only 1 instance
   * for each type is created.
   * @tparam MuxerImpl one or many types of muxer adaptors to be used
   * @return injector binding
   */
  template <typename... MuxerImpl>
  inline auto useMuxerAdaptors() {
    return boost::di::bind<muxer::MuxerAdaptor *[]>()  // NOLINT
        .TEMPLATE_TO<MuxerImpl...>()[boost::di::override];
  }

  /**
   * @brief Instruct injector to use these transports. Can be used once.
   * Technically many types can be specified, even the same type, but in the end
   * only 1 instance for each type is created.
   * @tparam TransportImpl one or many types of transport adaptors to be used
   * @return injector binding
   */
  template <typename... TransportImpl>
  inline auto useTransportAdaptors() {
    return boost::di::bind<transport::TransportAdaptor *[]>()  // NOLINT
        .TEMPLATE_TO<TransportImpl...>()[boost::di::override];
  }

  /**
   * @brief Main function that creates Network Injector.
   * @tparam Ts types of injector bindings
   * @param args injector bindings that override default bindings.
   * @return complete network injector
   */
  template <typename InjectorConfig = BOOST_DI_CFG, typename... Ts>
  inline auto makeNetworkInjector(Ts &&... args) {
    using namespace boost;  // NOLINT

    auto csprng = std::make_shared<crypto::random::BoostRandomGenerator>();
    auto ed25519_provider =
        std::make_shared<crypto::ed25519::Ed25519ProviderImpl>();
    auto rsa_provider = std::make_shared<crypto::rsa::RsaProviderImpl>();
    auto ecdsa_provider = std::make_shared<crypto::ecdsa::EcdsaProviderImpl>();
    auto secp256k1_provider =
        std::make_shared<crypto::secp256k1::Secp256k1ProviderImpl>();
    auto hmac_provider = std::make_shared<crypto::hmac::HmacProviderImpl>();
    std::shared_ptr<crypto::CryptoProvider> crypto_provider =
        std::make_shared<crypto::CryptoProviderImpl>(
            csprng, ed25519_provider, rsa_provider, ecdsa_provider,
            secp256k1_provider, hmac_provider);
    auto validator =
        std::make_shared<crypto::validator::KeyValidatorImpl>(crypto_provider);

    // assume no error here. otherwise... just blow up executable
    auto keypair =
        crypto_provider->generateKeys(crypto::Key::Type::Ed25519).value();

    // clang-format off
    return di::make_injector<InjectorConfig>(
        di::bind<crypto::KeyPair>().TEMPLATE_TO(std::move(keypair)),
        di::bind<crypto::random::CSPRNG>().TEMPLATE_TO(std::move(csprng)),
        di::bind<crypto::ed25519::Ed25519Provider>().TEMPLATE_TO(std::move(ed25519_provider)),
        di::bind<crypto::rsa::RsaProvider>().TEMPLATE_TO(std::move(rsa_provider)),
        di::bind<crypto::ecdsa::EcdsaProvider>().TEMPLATE_TO(std::move(ecdsa_provider)),
        di::bind<crypto::secp256k1::Secp256k1Provider>().TEMPLATE_TO(std::move(secp256k1_provider)),
        di::bind<crypto::aes::AesCtr>().TEMPLATE_TO<crypto::aes::AesCtrImpl>(),
        di::bind<crypto::hmac::HmacProvider>().TEMPLATE_TO<crypto::hmac::HmacProviderImpl>(),
        di::bind<crypto::CryptoProvider>().TEMPLATE_TO<crypto::CryptoProviderImpl>(),
        di::bind<crypto::marshaller::KeyMarshaller>().TEMPLATE_TO<crypto::marshaller::KeyMarshallerImpl>(),
        di::bind<peer::IdentityManager>().TEMPLATE_TO<peer::IdentityManagerImpl>(),
        di::bind<crypto::validator::KeyValidator>().TEMPLATE_TO<crypto::validator::KeyValidatorImpl>(),
        di::bind<security::plaintext::ExchangeMessageMarshaller>().TEMPLATE_TO<security::plaintext::ExchangeMessageMarshallerImpl>(),
        di::bind<security::secio::ProposeMessageMarshaller>().TEMPLATE_TO<security::secio::ProposeMessageMarshallerImpl>(),
        di::bind<security::secio::ExchangeMessageMarshaller>().TEMPLATE_TO<security::secio::ExchangeMessageMarshallerImpl>(),

        di::bind<basic::Scheduler::Config>.TEMPLATE_TO(basic::Scheduler::Config{}),
        di::bind<basic::SchedulerBackend>().TEMPLATE_TO<basic::AsioSchedulerBackend>(),
        di::bind<basic::Scheduler>().TEMPLATE_TO<basic::SchedulerImpl>(),

        // internal
        di::bind<network::DnsaddrResolver>().TEMPLATE_TO <network::DnsaddrResolverImpl>(),
        di::bind<network::Router>().TEMPLATE_TO<network::RouterImpl>(),
        di::bind<network::ConnectionManager>().TEMPLATE_TO<network::ConnectionManagerImpl>(),
        di::bind<network::ListenerManager>().TEMPLATE_TO<network::ListenerManagerImpl>(),
        di::bind<network::Dialer>().TEMPLATE_TO<network::DialerImpl>(),
        di::bind<network::Network>().TEMPLATE_TO<network::NetworkImpl>(),
        di::bind<network::TransportManager>().TEMPLATE_TO<network::TransportManagerImpl>(),
        di::bind<transport::Upgrader>().TEMPLATE_TO<transport::UpgraderImpl>(),
        di::bind<protocol_muxer::ProtocolMuxer>().TEMPLATE_TO<protocol_muxer::multiselect::Multiselect>(),

        // default adaptors
        di::bind<muxer::MuxedConnectionConfig>.TEMPLATE_TO(muxer::MuxedConnectionConfig{}),
        //di::bind<security::SecurityAdaptor *[]>().TEMPLATE_TO<security::Plaintext, security::Secio, security::Noise, security::TlsAdaptor>(),  // NOLINT
        di::bind<security::SecurityAdaptor* []>().TEMPLATE_TO<security::Noise>(),  // NOLINT
        di::bind<muxer::MuxerAdaptor *[]>().TEMPLATE_TO<muxer::Yamux>(),  // NOLINT
        di::bind<transport::TransportAdaptor *[]>().TEMPLATE_TO<transport::TcpTransport>(),  // NOLINT

        // user-defined overrides...
        std::forward<decltype(args)>(args)...
    );
    // clang-format on
  }

}  // namespace libp2p::injector

#endif  // LIBP2P_NETWORK_INJECTOR_HPP
