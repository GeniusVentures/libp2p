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

    public:
        using RelayCallback = void(const bool&);
        using RelayStopCallback = void(const bool&);

        RelayUpgraderMessageProcessor(
            Host& host, network::ConnectionManager& conn_manager);

        

    private:


        Host& host_;
        network::ConnectionManager& conn_manager_;
        log::Logger log_ = log::createLogger("RelayUpgraderMsgProcessor");
    };
}
#endif 