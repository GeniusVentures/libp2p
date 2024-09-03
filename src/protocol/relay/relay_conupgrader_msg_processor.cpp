
#include "libp2p/protocol/relay/relay_conupgrader_msg_processor.hpp"

#include <tuple>

#include <generated/protocol/relay/protobuf/relay.pb.h>
#include <boost/assert.hpp>
#include <libp2p/basic/protobuf_message_read_writer.hpp>
#include <libp2p/network/network.hpp>
#include <libp2p/peer/address_repository.hpp>
#include <libp2p/protocol/identify/utils.hpp>
#include "libp2p/injector/host_injector.hpp"
#include <iostream>


namespace {
    inline std::string fromMultiaddrToString(
        const libp2p::multi::Multiaddress& ma) {
        auto const& addr = ma.getBytesAddress();
        return std::string(addr.begin(), addr.end());
    }

    inline libp2p::outcome::result<libp2p::multi::Multiaddress>
        fromStringToMultiaddr(const std::string& addr) {
        return libp2p::multi::Multiaddress::create(gsl::span<const uint8_t>(
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            reinterpret_cast<const uint8_t*>(addr.data()), addr.size()));
    }
}  // namespace

namespace libp2p::protocol {

    RelayUpgraderMessageProcessor::RelayUpgraderMessageProcessor()
    {

    }
	void RelayUpgraderMessageProcessor::initiateRelayCon(StreamSPtr& stream_res, peer::PeerInfo peer_info, CompletionCallback cb)
	{
        log_->info("Creating and sending hop connect message to {}", peer_info.id.toBase58());
		relay::pb::HopMessage msg;
		msg.set_type(relay::pb::HopMessage_Type_CONNECT);
        //Create a new peer for connection
        auto peer = new relay::pb::Peer;
        peer->set_id(std::string(peer_info.id.toVector().begin(), peer_info.id.toVector().end()));
        for (auto& addr : peer_info.addresses)
        {
            peer->add_addrs(fromMultiaddrToString(addr));
        }
        msg.set_allocated_peer(peer);

        // write the resulting Protobuf message
        auto rw = std::make_shared<basic::ProtobufMessageReadWriter>(stream_res);
        rw->write<relay::pb::HopMessage>(
            msg,
            [self{ shared_from_this() },
            stream_res, cb](auto&& res) mutable {
                self->relayConnectSent(std::forward<decltype(res)>(res), stream_res, cb);
            });
	}

    void RelayUpgraderMessageProcessor::relayConnectSent(
        outcome::result<size_t> written_bytes, const StreamSPtr& stream, CompletionCallback cb) {
        
        auto [peer_id, peer_addr] = detail::getPeerIdentity(stream);
        if (!written_bytes) {
            log_->error("cannot write Relay message to stream to peer {}, {}: {}",
                peer_id, peer_addr, written_bytes.error().message());
            return cb(false);
        }

        log_->info("successfully written an Relay Connect message to peer {}, {}",
            peer_id, peer_addr);

        // Handle incoming responses
        auto rw = std::make_shared<basic::ProtobufMessageReadWriter>(stream);
        rw->read<relay::pb::HopMessage>(
            [self{ shared_from_this() }, stream, cb](auto&& res) {
                self->relayConnectStatus(std::forward<decltype(res)>(res), stream, cb);
            });
    }

    void RelayUpgraderMessageProcessor::relayConnectStatus(
        outcome::result<relay::pb::HopMessage> msg_res,
        const StreamSPtr& stream, CompletionCallback cb) {
        auto [peer_id_str, peer_addr_str] = detail::getPeerIdentity(stream);
        if (!msg_res) {
            log_->error("cannot read an relay message from peer {}, {}: {}",
                peer_id_str, peer_addr_str, msg_res.error());
            return cb(false);
        }
        log_->info("Got back status from Relay Connect attempt {}", peer_id_str);
        auto&& msg = std::move(msg_res.value());
        //Make sure we got a STATUS response
        if (msg.type() != relay::pb::HopMessage_Type_STATUS)
        {
            log_->error("Relay got a type other than STATUS when expecting status for a connection we initiated from: {}, {}", peer_id_str,
                peer_addr_str);
            return cb(false);
        }
        //Make sure connection is OK
        if (msg.status() != relay::pb::OK)
        {
            log_->error("Relay got status that indicates connections are unavailable from: {}, {}  : {}", peer_id_str,
                peer_addr_str, msg.status());
            return cb(false);
        }
        //Run Callback
        cb(true);
    }
}