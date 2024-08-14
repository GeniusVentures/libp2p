#ifndef LIBP2P_HOLEPUNCH_MSG_PROCESSOR_HPP
#define LIBP2P_HOLEPUNCH_MSG_PROCESSOR_HPP

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

namespace holepunch::pb {
  class HolePunch;
}

namespace libp2p::protocol {
  /**
   * Processor of messages of Autonat protocol
   */
  class HolepunchMessageProcessor
      : public std::enable_shared_from_this<HolepunchMessageProcessor> {
    using StreamSPtr = std::shared_ptr<connection::Stream>;

   public:
    using HolepunchCallback = void(const bool &);

    HolepunchMessageProcessor(
        Host &host, network::ConnectionManager &conn_manager);

    boost::signals2::connection onHolepunchReceived(
        const std::function<HolepunchCallback> &cb);

    /**
     * Send an autonat message over the provided stream
     * @param stream to be identified over
     */
    void sendHolepunchConnect(StreamSPtr stream, peer::PeerId peer_id);

    /**
     * Receive an Autonat message from the provided stream
     * @param stream to be identified over
     */
    void receiveHolepunch(StreamSPtr stream);

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
    void holepunchSent(outcome::result<size_t> written_bytes,
                      const StreamSPtr &stream,
        peer::PeerId peer_id);

    /**
     * Called, when an autonat message is received from the other peer
     * @param msg, which was read
     * @param stream, over which it was received
     */
    void holepunchReceived(outcome::result<holepunch::pb::HolePunch> msg_res,
                          const StreamSPtr &stream);

    void holepunchConnectReturn(outcome::result<holepunch::pb::HolePunch> msg_res,
        const StreamSPtr& stream, std::chrono::steady_clock::time_point start_time,
        peer::PeerId peer_id);


    Host &host_;
    network::ConnectionManager &conn_manager_;
    ObservedAddresses observed_addresses_;
    boost::signals2::signal<HolepunchCallback> signal_holepunch_received_;


    log::Logger log_ = log::createLogger("HolepunchMsgProcessor");
  };
}

#endif