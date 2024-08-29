#ifndef LIBP2P_RELAY_CONUPGRADE_HPP
#define LIBP2P_RELAY_CONUPGRADE_HPP
#include <iostream>
#include <libp2p/event/bus.hpp>
#include <libp2p/protocol/base_protocol.hpp>
#include <libp2p/protocol/relay/relay_conupgrader_msg_processor.hpp>
namespace libp2p::protocol {
    class RelayUpgrader : public BaseProtocol,
        public std::enable_shared_from_this<RelayUpgrader> {
    public:
        using CompletionCallback = std::function<void()>;
        RelayUpgrader(Host& host,
            std::shared_ptr<RelayUpgraderMessageProcessor> msg_processor,
            event::Bus& event_bus,
            CompletionCallback callback);

        /**
         * Stub in case we want to enable acting as a relay
         */
        void handle(StreamResult stream_res) override;

        void start();

    private:
    };
}
#endif