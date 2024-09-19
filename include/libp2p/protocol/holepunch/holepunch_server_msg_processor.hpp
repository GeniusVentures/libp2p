#ifndef LIBP2P_HOLEPUNCH_SERVER_MSG_PROCESSOR_HPP
#define LIBP2P_HOLEPUNCH_SERVER_MSG_PROCESSOR_HPP

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
  class HolepunchServerMsgProc
      : public std::enable_shared_from_this<HolepunchServerMsgProc> {
    using StreamSPtr = std::shared_ptr<connection::Stream>;

   public:
    using HolepunchCallback = void(const bool &);

    HolepunchServerMsgProc(
        Host &host, network::ConnectionManager &conn_manager);

    boost::signals2::connection onHolepunchReceived(
        const std::function<HolepunchCallback> &cb);

    /**
     * Send a holepunch request to a node
     * @param Stream over which to do the exchange provided by circuit relay
     * @param peer_id of other node
     */
    void sendHolepunchConnect(StreamSPtr stream, peer::PeerId peer_id, int retry_count = 0);

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
    //const ObservedAddresses &getObservedAddresses() const noexcept;

   private:
    /**
    Functions below happen when a holepunch connection is sent to another node
    */
    /**
     * Called when a holepunch CONNECT message is sent
     * @param written_bytes - how much bytes were written
     * @param stream with the other side
     * @param peer_id we are connecting to
     */
    void holepunchConnectSent(outcome::result<size_t> written_bytes,
                      const StreamSPtr &stream,
        peer::PeerId peer_id, int retry_count);

    /**
     * Called when we get a CONNECT message back, we will send a dcutr SYNC and connect to the other node
     * @param msg_res a protobuf message we expect to be a dcutr CONNECT
     * @param stream with the other side
     * @param timestamp indicating when we sent the original connect request
     * @param peer_id we are connecting to
     */
    void holepunchConnectReturn(outcome::result<holepunch::pb::HolePunch> msg_res,
        const StreamSPtr& stream, std::chrono::steady_clock::time_point start_time,
        peer::PeerId peer_id, int retry_count);

    Host &host_;
    network::ConnectionManager &conn_manager_;

    boost::signals2::signal<HolepunchCallback> signal_holepunch_received_;
    int kMaxRetries = 2;


    log::Logger log_ = log::createLogger("HolepunchServerMsgProcessor");
  };
}

#endif