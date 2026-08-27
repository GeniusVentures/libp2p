/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <chrono>
#include <future>
#include <memory>
#include <string_view>
#include <thread>

#include <gtest/gtest.h>

#include <libp2p/common/literals.hpp>
#include <libp2p/host/host.hpp>
#include <libp2p/injector/host_injector.hpp>
#include <libp2p/protocol/echo.hpp>

#include "testutil/prepare_loggers.hpp"

using namespace libp2p;
using namespace libp2p::common;

using std::chrono_literals::operator""s;
using std::chrono_literals::operator""ms;

namespace {
  // Distinct per-node marker types, one per makeNode<...>() call site across
  // the WHOLE test binary (not just per TEST_F case -- see the Boost.DI
  // aliasing note on makeNode below). Each is bound as an unused, inert
  // extra DI binding purely to force makeHostInjector<...>'s own template
  // instantiation to differ per node.
  struct NodeTagServer {};
  struct NodeTagClient {};
  struct NodeTagServer2 {};
  struct NodeTagAttacker {};

  // Byte-identical to pnet_injector_test.cpp's kValidSwarmKey.
  constexpr std::string_view kSwarmKeyMatched =
      "/key/swarm/psk/1.0.0/\n/base16/"
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n";

  // Byte-identical key pattern to dialer_test.cpp's / pnet_protected_connection_test.cpp's
  // kPskBBytes (0xff..0xe0), reformatted as swarm-key hex text -- deliberately
  // different from kSwarmKeyMatched.
  constexpr std::string_view kSwarmKeyMismatched =
      "/key/swarm/psk/1.0.0/\n/base16/"
      "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0\n";
}  // namespace

/**
 * @class PnetTwoNodeTest
 * @brief Purpose-built, exactly-2-node fixture (D-02) proving the pnet PSK
 * boundary end-to-end over real TCP loopback, through the full DI-assembled
 * Host (makeHostInjector(usePrivateNetwork(...))) -- distinct from
 * HostIntegrationTest's parametrized N-peer echo fixture, which is built
 * around echo-ping-many-peers rather than accept/reject semantics.
 */
struct PnetTwoNodeTest : public ::testing::Test {
  /// One DI-assembled node: its own io_context + dedicated thread, mirroring
  /// test_peer.hpp's Peer lifecycle (Peer::wait()/~Peer()). Every node
  /// listens on its own loopback address (mirroring host_integration_test's
  /// convention of every peer being both a listener and a dialer) so
  /// Host::newStream's own-listen-address-derived source-address selection
  /// (see BasicHost::newStream / RouteHelper::getBestSourceAddresses) always
  /// has a real loopback source to choose from.
  struct Node {
    std::shared_ptr<boost::asio::io_context> io_context;
    std::shared_ptr<Host> host;
    std::shared_ptr<protocol::Echo> echo;
    std::thread thread;

    ~Node() {
      if (thread.joinable()) {
        thread.join();
      }
      if (host) {
        host->stop();
      }
    }
  };

  /// Builds one DI-assembled node bound to the given swarm-key text.
  ///
  /// IMPORTANT (Rule 1 bug, Phase 3 discovery -- see 03-01-SUMMARY.md
  /// deviations): calling `makeHostInjector(usePrivateNetwork(text))` twice
  /// with an IDENTICAL static call signature causes Boost.DI to alias BOTH
  /// resulting shared_ptr<Host>/shared_ptr<io_context> instances to the SAME
  /// underlying objects -- the two "separate" nodes silently become the same
  /// Host, and a "dial" between them is actually a self-dial. This is a
  /// Boost.DI scope-caching behavior keyed by the injector's STATIC C++ TYPE
  /// (not by call site or call count), not anything specific to pnet/gater.
  /// The `Marker` template parameter's ONLY purpose is to force each
  /// makeNode<...>() call site to instantiate a distinct
  /// makeHostInjector<...> template, which produces genuinely independent
  /// object graphs. Every makeNode<...>() call ACROSS THE WHOLE TEST BINARY
  /// (not just within one TEST_F) must use a distinct Marker type --
  /// verified empirically: reusing a Marker across two different TEST_F
  /// cases reproduces the same aliasing bug across tests.
  template <typename Marker>
  static std::shared_ptr<Node> makeNode(std::string_view swarm_key_text) {
    auto injector =
        injector::makeHostInjector(injector::usePrivateNetwork(swarm_key_text),
                                   injector::useAllowLoopbackDial(),
                                   boost::di::bind<Marker>().to(Marker{}));

    auto node = std::make_shared<Node>();
    node->host = injector.create<std::shared_ptr<Host>>();
    node->io_context =
        injector.create<std::shared_ptr<boost::asio::io_context>>();
    node->echo = std::make_shared<protocol::Echo>();

    auto handler = [echo = node->echo](StreamAndProtocol stream) {
      echo->handle(stream);
    };
    node->host->setProtocolHandler({node->echo->getProtocolId()}, handler);

    return node;
  }

  /// Schedules listen+start on node's own io_context, then starts its
  /// dedicated thread running that io_context for `run_for`. Mirrors
  /// test_peer.cpp's Peer::startServer two-phase structure exactly.
  static void startListening(
      std::shared_ptr<Node> node, const multi::Multiaddress &ma,
      std::shared_ptr<std::promise<peer::PeerInfo>> promise,
      std::chrono::milliseconds run_for) {
    node->io_context->post([node, ma, promise] {
      ASSERT_TRUE(node->host->listen(ma))
          << "failed to start listening on " << ma.getStringAddress();
      node->host->start();
      promise->set_value(node->host->getPeerInfo());
    });

    node->thread =
        std::thread([node, run_for] { node->io_context->run_for(run_for); });
  }
};

/**
 * @given two Host nodes, both configured with the same 256-bit PSK, each
 * listening on its own loopback port, one dialing the other
 * @when the dialing node opens a stream on the echo protocol to the
 * listening node
 * @then the stream opens successfully -- PNET-01/02/03 hold end-to-end for
 * matched PSKs (D-01/D-02)
 */
TEST_F(PnetTwoNodeTest, MatchedPskConnectsAndOpensEchoStream) {
  testutil::prepareLoggers();

  auto server = makeNode<NodeTagServer>(kSwarmKeyMatched);
  auto client = makeNode<NodeTagClient>(kSwarmKeyMatched);

  auto server_ma = "/ip4/127.0.0.1/tcp/40520"_multiaddr;
  auto client_ma = "/ip4/127.0.0.1/tcp/40522"_multiaddr;

  auto server_promise = std::make_shared<std::promise<peer::PeerInfo>>();
  auto server_future = server_promise->get_future();
  startListening(server, server_ma, server_promise, 3s);

  auto client_promise = std::make_shared<std::promise<peer::PeerInfo>>();
  auto client_future = client_promise->get_future();
  startListening(client, client_ma, client_promise, 3s);

  ASSERT_EQ(server_future.wait_for(2s), std::future_status::ready);
  auto server_info = server_future.get();
  ASSERT_EQ(client_future.wait_for(2s), std::future_status::ready);

  // Heap-allocated so it safely outlives this stack frame if the bounded
  // wait below ever times out while the client thread is still running.
  auto stream_opened = std::make_shared<std::promise<bool>>();
  auto stream_opened_future = stream_opened->get_future();

  client->io_context->post([client, server_info, stream_opened] {
    client->host->newStream(
        server_info, {client->echo->getProtocolId()},
        [stream_opened](StreamAndProtocolOrError r) {
          stream_opened->set_value(r.has_value());
        });
  });

  ASSERT_EQ(stream_opened_future.wait_for(2s), std::future_status::ready);
  ASSERT_TRUE(stream_opened_future.get());
}

/**
 * @given a listening node configured with PSK K and a fresh dialing node
 * (also listening on its own loopback port) configured with a different
 * PSK K'
 * @when the dialing node attempts to open a stream on the echo protocol to
 * the listening node
 * @then no usable stream is ever established, observed black-box within a
 * bounded timeout -- either the connect attempt fails, or it never
 * completes at all (both are passing outcomes per D-03); no specific
 * PnetError value is asserted
 */
TEST_F(PnetTwoNodeTest, MismatchedPskNeverEstablishesUsableStream) {
  testutil::prepareLoggers();

  // Fresh node pair, distinct from the previous test's server/client -- do
  // not reuse PSK state across positive/negative cases.
  auto server2 = makeNode<NodeTagServer2>(kSwarmKeyMatched);
  auto attacker = makeNode<NodeTagAttacker>(kSwarmKeyMismatched);

  // Different ports from the matched-PSK case above, avoiding TIME_WAIT
  // collisions across TEST_F cases in one binary run.
  auto server_ma = "/ip4/127.0.0.1/tcp/40521"_multiaddr;
  auto attacker_ma = "/ip4/127.0.0.1/tcp/40523"_multiaddr;

  auto server_promise = std::make_shared<std::promise<peer::PeerInfo>>();
  auto server_future = server_promise->get_future();
  startListening(server2, server_ma, server_promise, 3s);

  auto attacker_promise = std::make_shared<std::promise<peer::PeerInfo>>();
  auto attacker_future = attacker_promise->get_future();
  startListening(attacker, attacker_ma, attacker_promise, 3s);

  ASSERT_EQ(server_future.wait_for(2s), std::future_status::ready);
  auto server_info = server_future.get();
  ASSERT_EQ(attacker_future.wait_for(2s), std::future_status::ready);

  auto stream_opened = std::make_shared<std::promise<bool>>();
  auto stream_opened_future = stream_opened->get_future();

  attacker->io_context->post([attacker, server_info, stream_opened] {
    attacker->host->newStream(
        server_info, {attacker->echo->getProtocolId()},
        [stream_opened](StreamAndProtocolOrError r) {
          stream_opened->set_value(r.has_value());
        });
  });

  auto status = stream_opened_future.wait_for(2s);
  if (status == std::future_status::ready) {
    // The callback fired -- it MUST be a failure, never success.
    ASSERT_FALSE(stream_opened_future.get())
        << "mismatched-PSK dial must never yield a usable stream";
  }
  // A bounded timeout (status == std::future_status::timeout) is ALSO a
  // passing outcome per D-03: "the attempt fails at the pnet layer and
  // never reaches multiselect" covers a permanent hang just as validly as
  // an explicit callback error -- do NOT fail the test on timeout.
}
