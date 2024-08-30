#ifndef LIBP2P_RELAY_CONUPGRADE_MSG_PROCESSOR_HPP
#define LIBP2P_RELAY_CONUPGRADE_MSG_PROCESSOR_HPP

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
	class Reservation;
}
namespace libp2p::protocol {
    /**
     * Processor of messages of Relay protocol
     */
    class RelayUpgraderMessageProcessor
        : public std::enable_shared_from_this<RelayUpgraderMessageProcessor> {
        using StreamSPtr = std::shared_ptr<connection::Stream>;
        using CompletionCallback = std::function<void(const bool&)>;
    public:
        RelayUpgraderMessageProcessor();

        void initiateRelayCon(StreamSPtr& stream_res, peer::PeerInfo peer_info, CompletionCallback cb);

        /**
         * Called when data was sent to make a connection
         * @param written_bytes - how much bytes were written
         * @param stream with the other side
         */
        void relayConnectSent(outcome::result<size_t> written_bytes,
            const StreamSPtr& stream, CompletionCallback cb);
        
        /**
          * Called when a response is sent from an attempted relay connection initiation
          * @param msg, which was read
          * @param stream, over which it was received
          */
        void relayConnectStatus(outcome::result<relay::pb::HopMessage> msg_res,
            const StreamSPtr& stream, CompletionCallback cb);
    private:


        //Host& host_;
        //network::ConnectionManager& conn_manager_;
        log::Logger log_ = log::createLogger("RelayUpgraderMsgProcessor");
    };
}
#endif 