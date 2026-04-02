#include <libp2p/connection/stream_and_protocol.hpp>
#include <libp2p/protocol/relay/relay_conupgrader.hpp>

#include <string>
#include <tuple>

#include <boost/assert.hpp>
#include <iostream>

namespace {
    const std::string kRelayProto = "/libp2p/circuit/relay/0.2.0/hop";
    const std::string kRelayStopProto = "/libp2p/circuit/relay/0.2.0/stop";
}  // namespace

namespace libp2p::protocol {
    RelayUpgrader::RelayUpgrader()
        : msg_processor_(std::make_shared<libp2p::protocol::RelayUpgraderMessageProcessor>())
    {
        BOOST_ASSERT(msg_processor_);
    }


    void RelayUpgrader::handle(StreamAndProtocol stream_res)
    {

    }

    peer::Protocol RelayUpgrader::getProtocolId() const {
        return kRelayProto;
    }

    void RelayUpgrader::start(StreamAndProtocol stream_res, peer::PeerInfo peer_info, CompletionCallback cb)
    {
        log_->info("Creating a peer relay upgrade to {} ", peer_info.id.toBase58());
        msg_processor_->initiateRelayCon(stream_res.stream, std::move(peer_info), std::move(cb));
    }
}