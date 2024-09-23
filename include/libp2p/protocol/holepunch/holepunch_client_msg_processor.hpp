#ifndef LIBP2P_HOLEPUNCH_CLIENT_MSG_PROCESSOR_HPP
#define LIBP2P_HOLEPUNCH_CLIENT_MSG_PROCESSOR_HPP

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
  class HolepunchClientMsgProc
      : public std::enable_shared_from_this<HolepunchClientMsgProc> {
    using StreamSPtr = std::shared_ptr<connection::Stream>;

   public:
    using HolepunchCallback = void(const bool &);

    HolepunchClientMsgProc(
        Host &host, network::ConnectionManager &conn_manager);

    boost::signals2::connection onHolepunchReceived(
        const std::function<HolepunchCallback> &cb);


    /**
     * Receive a holepunch request over specified stream
     * @param stream to get a holepunch CONNECT
     */
    void receiveIncomingHolepunch(StreamSPtr stream);

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
    Functions below happen when a holepunch connection is initated with us
    */
    
    /**
     * Called, when an autonat message is received from the other peer
     * @param msg, which was read
     * @param stream, over which it was received
     */
    void holepunchIncomingReceived(outcome::result<holepunch::pb::HolePunch> msg_res,
        const StreamSPtr& stream);

    /**
     * Called, when a holepunch CONNECT is sent back to a node that initiated a holepunch
     * @param written_bytes - how much bytes were written
     * @param stream with the other side
     * @param Addresses we will connect to upon getting a sync
     */
    void holepunchConResponseSent(outcome::result<size_t> written_bytes,
        const StreamSPtr& stream,
        std::vector<libp2p::multi::Multiaddress> connaddrs);

    /**
     * Called, when a holepunch SYNC is received, we should connect to this node immediately. 
     * @param Protobuf message containing an assumed SYNC message
     * @param stream with the other side
     * @param Addresses we will connect to upon getting a sync
     */
    void holepunchSyncResponseReturn(outcome::result<holepunch::pb::HolePunch> msg_res,
        const StreamSPtr& stream,
        std::vector<libp2p::multi::Multiaddress> connaddrs);


    Host &host_;
    network::ConnectionManager &conn_manager_;

    boost::signals2::signal<HolepunchCallback> signal_holepunch_received_;
    //std::vector<std::shared_ptr<connection::CapableConnection>> connections_;
    std::unordered_map<peer::PeerId, std::unordered_set<std::shared_ptr<connection::RawConnection>>> connections_;
    int kMaxRetries = 2;


    log::Logger log_ = log::createLogger("HolepunchClientMsgProcessor");
  };
}

#endif