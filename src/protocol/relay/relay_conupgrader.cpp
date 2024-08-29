#include <libp2p/protocol/relay/relay_conupgrader.hpp>

#include <string>
#include <tuple>

#include <boost/assert.hpp>
#include <iostream>


namespace libp2p::protocol {
    RelayUpgrader::RelayUpgrader()
        : msg_processor_(std::make_shared<libp2p::protocol::RelayUpgraderMessageProcessor>())
    {
        BOOST_ASSERT(msg_processor_);
    }


    void RelayUpgrader::handle(StreamResult stream_res)
    {

    }

    void RelayUpgrader::start(StreamResult stream_res, peer::PeerInfo peer_info, CompletionCallback cb)
    {
        msg_processor_->initiateRelayCon(stream_res.value(), peer_info, cb);
    }
}