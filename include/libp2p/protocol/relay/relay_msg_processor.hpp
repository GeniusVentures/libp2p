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
#include <libp2p/transport/upgrader.hpp>
#include <libp2p/transport/impl/upgrader_session.hpp>

namespace relay::pb {
  class HopMessage;
  class StopMessage;
  class Reservation;
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
    using RelayStopCallback = void(const peer::PeerId);

    RelayMessageProcessor(
        Host &host, network::ConnectionManager &conn_manager, std::shared_ptr<libp2p::transport::Upgrader> upgrader);

    boost::signals2::connection onRelayReceived(
        const std::function<RelayCallback> &cb);

    /**
     * Send an relay message over the provided stream to make a reservation
     * @param stream to be identified over
     */
    void sendHopReservation(StreamSPtr stream);

    /**
     * Receive a stop Relay message from the provided stream which should inficate someone is trying to connect to us
     * @param stream to be identified over
     */
    void receiveStopRelay(StreamSPtr stream, RelayStopCallback cb);

    /**
     * Receive an Relay message from the provided stream
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
    //const RelayAddresses &getObservedAddresses() const noexcept;

   private:
    /**
     * Called when a reservation data has been sent to a circuit relay provider
     * @param written_bytes - how much bytes were written
     * @param stream with the other side
     */
    void relayReservationSent(outcome::result<size_t> written_bytes,
                      const StreamSPtr &stream);


    /**
     * Called when we get back a reservation message after attempting to make one
     * @param msg, which was read
     * @param stream, over which it was received
     */
    void relayReservationReceived(outcome::result<relay::pb::HopMessage> msg_res,
                          const StreamSPtr &stream);

    /**
     * Called when we get a Stop message indicating a connect should occur with a specific node. Stream should now be the one used for that.
     * @param msg, which was read
     * @param stream, over which it was received
     */
    void relayConnectReceived(outcome::result<relay::pb::StopMessage> msg_res,
        const StreamSPtr& stream, RelayStopCallback cb);

    /**
     * Called, when an relay message is received from the other peer
     * @param stream, over which it was received
     */
    void relayConnectResponse(const StreamSPtr& stream, peer::PeerId peer_id, RelayStopCallback cb);

    /**
     * After a relay is accepted we expect to receive encryption and muxing.
     * @param stream, over which it was received
     */
    void relayConnectUpgrade(const StreamSPtr& stream, peer::PeerId peer_id, RelayStopCallback cb);

    Host &host_;
    network::ConnectionManager &conn_manager_;
    //RelayAddresses relay_addresses_;
    boost::signals2::signal<RelayCallback> signal_relay_received_;
    std::shared_ptr<libp2p::transport::Upgrader> upgrader_;


    log::Logger log_ = log::createLogger("RelayMsgProcessor");
  };
}

#endif