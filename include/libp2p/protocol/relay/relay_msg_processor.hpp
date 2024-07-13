#ifndef LIBP2P_RELAY_MSG_PROCESSOR_HPP
#define LIBP2P_RELAY_MSG_PROCESSOR_HPP

#include <memory>
#include <optional>
#include <string>
#include <unordered_map>

#include <gsl/span>
#include <libp2p/connection/stream.hpp>
#include <libp2p/crypto/key_marshaller.hpp>
#include <libp2p/host/host.hpp>
#include <libp2p/log/logger.hpp>
#include <libp2p/multi/multiaddress.hpp>
#include <libp2p/network/connection_manager.hpp>
#include <libp2p/outcome/outcome.hpp>
#include <libp2p/peer/identity_manager.hpp>
#include <libp2p/peer/peer_id.hpp>
#include <libp2p/protocol/identify/observed_addresses.hpp>

namespace relay::pb {
  class HopMessage;
  class StopMessage;
}

namespace libp2p::protocol {
  /**
   * Processor of messages of Autonat protocol
   */
  class RelayMessageProcessor
      : public std::enable_shared_from_this<RelayMessageProcessor> {
    using StreamSPtr = std::shared_ptr<connection::Stream>;

   public:
    using RelayCallback = void(const bool &);

    RelayMessageProcessor(
        Host &host, network::ConnectionManager &conn_manager,
        peer::IdentityManager &identity_manager,
        std::shared_ptr<crypto::marshaller::KeyMarshaller> key_marshaller);

    boost::signals2::connection onRelayReceived(
        const std::function<RelayCallback> &cb);

    /**
     * Send an autonat message over the provided stream
     * @param stream to be identified over
     */
    void sendRelay(StreamSPtr stream, std::vector<libp2p::multi::Multiaddress> connaddrs, uint64_t time);

    /**
     * Receive an Autonat message from the provided stream
     * @param stream to be identified over
     */
    void receiveRelay(StreamSPtr stream);

    /**
     * Get a Host of this processor
     * @return Host
     */
    Host &getHost() const noexcept;

    /**
     * Get a ConnectionManager of this processor
     * @return ConnectionManager
     */
    network::ConnectionManager &getConnectionManager() const noexcept;

    /**
     * Get an ObservedAddresses of this processor
     * @return ObservedAddresses
     */
    const ObservedAddresses &getObservedAddresses() const noexcept;

   private:
    /**
     * Called, when an autonat message is written to the stream
     * @param written_bytes - how much bytes were written
     * @param stream with the other side
     */
    void relaySent(outcome::result<size_t> written_bytes,
                      const StreamSPtr &stream);

    /**
     * Called, when an autonat message is received from the other peer
     * @param msg, which was read
     * @param stream, over which it was received
     */
    void relayReceived(outcome::result<relay::pb::HopMessage> msg_res,
                          const StreamSPtr &stream);


    Host &host_;
    network::ConnectionManager &conn_manager_;
    peer::IdentityManager &identity_manager_;
    std::shared_ptr<crypto::marshaller::KeyMarshaller> key_marshaller_;
    ObservedAddresses observed_addresses_;
    boost::signals2::signal<RelayCallback> signal_relay_received_;
    int successful_addresses_;
    int unsuccessful_addresses_;


    log::Logger log_ = log::createLogger("RelayMsgProcessor");
  };
}

#endif