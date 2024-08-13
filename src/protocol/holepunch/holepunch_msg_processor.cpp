
#include "libp2p/protocol/holepunch/holepunch_msg_processor.hpp"

#include <tuple>

#include <generated/protocol/holepunch/protobuf/holepunch.pb.h>
#include <boost/assert.hpp>
#include <libp2p/basic/protobuf_message_read_writer.hpp>
#include <libp2p/network/network.hpp>
#include <libp2p/peer/address_repository.hpp>
#include <libp2p/protocol/identify/utils.hpp>
#include "libp2p/injector/host_injector.hpp"
#include <iostream>

namespace {
  inline std::string fromMultiaddrToString(
      const libp2p::multi::Multiaddress &ma) {
    auto const &addr = ma.getBytesAddress();
    return std::string(addr.begin(), addr.end());
  }

  inline libp2p::outcome::result<libp2p::multi::Multiaddress>
  fromStringToMultiaddr(const std::string &addr) {
    return libp2p::multi::Multiaddress::create(gsl::span<const uint8_t>(
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        reinterpret_cast<const uint8_t *>(addr.data()), addr.size()));
  }
}  // namespace

namespace libp2p::protocol {
    HolepunchMessageProcessor::HolepunchMessageProcessor(
        Host& host, network::ConnectionManager& conn_manager)
        : host_{ host },
        conn_manager_{ conn_manager }
    {
    }

    boost::signals2::connection HolepunchMessageProcessor::onHolepunchReceived(
        const std::function<HolepunchCallback>& cb) {
        return signal_holepunch_received_.connect(cb);
    }

    void HolepunchMessageProcessor::sendHolepunchConnect(StreamSPtr stream, peer::PeerInfo peer_info) {
        holepunch::pb::HolePunch msg;
        msg.set_type(holepunch::pb::HolePunch_Type_CONNECT);
        auto obsaddr = host_.getObservedAddresses();
        for (auto& addr : obsaddr)
        {
            msg.add_obsaddrs(fromMultiaddrToString(addr));
        }

        // write the resulting Protobuf message
        auto rw = std::make_shared<basic::ProtobufMessageReadWriter>(stream);
        rw->write<holepunch::pb::HolePunch>(
            msg,
            [self{ shared_from_this() },
            stream = std::move(stream)](auto&& res) mutable {
                self->holepunchSent(std::forward<decltype(res)>(res), stream);
            });
    }

    void HolepunchMessageProcessor::holepunchSent(
        outcome::result<size_t> written_bytes, const StreamSPtr& stream) {
        auto [peer_id, peer_addr] = detail::getPeerIdentity(stream);
        if (!written_bytes) {
            log_->error("cannot write Autonat message to stream to peer {}, {}: {}",
                peer_id, peer_addr, written_bytes.error().message());
            return stream->reset();
        }

        log_->info("successfully written an Autonat message to peer {}, {}",
            peer_id, peer_addr);
        // Handle incoming responses
        auto rw = std::make_shared<basic::ProtobufMessageReadWriter>(stream);
        rw->read<holepunch::pb::HolePunch>(
            [self{ shared_from_this() }, stream = std::move(stream)](auto&& res) {
                self->holepunchConnectReturn(std::forward<decltype(res)>(res), stream);
            });
    }

    void HolepunchMessageProcessor::receiveHolepunch(StreamSPtr stream) {
        auto rw = std::make_shared<basic::ProtobufMessageReadWriter>(stream);

    }

    Host& HolepunchMessageProcessor::getHost() const noexcept {
        return host_;
    }

    network::ConnectionManager& HolepunchMessageProcessor::getConnectionManager()
        const noexcept {
        return conn_manager_;
    }

    const ObservedAddresses& HolepunchMessageProcessor::getObservedAddresses()
        const noexcept {
        return observed_addresses_;
    }

    void HolepunchMessageProcessor::holepunchReceived(
        outcome::result<holepunch::pb::HolePunch> msg_res,
        const StreamSPtr& stream) {
        auto [peer_id_str, peer_addr_str] = detail::getPeerIdentity(stream);
        if (!msg_res) {
            log_->error("cannot read an holepunch message from peer {}, {}: {}",
                peer_id_str, peer_addr_str, msg_res.error());
            return stream->reset();
        }

        log_->info("received an holepunch message from peer {}, {}", peer_id_str,
            peer_addr_str);

        auto&& msg = std::move(msg_res.value());
        //Connect message
        if (msg.type() == holepunch::pb::HolePunch::CONNECT)
        {
            std::vector<libp2p::multi::Multiaddress> connaddrs;
            for (auto& addr : msg.obsaddrs())
            {
                connaddrs.push_back(fromStringToMultiaddr(addr).value());
            }
            //Open connection with SYN Packets?
        }
        //If we get a sync, open a new connection to observed addresses previousl recorded
        if (msg.type() == holepunch::pb::HolePunch::SYNC)
        {

        }
    }

    void HolepunchMessageProcessor::holepunchConnectReturn(
        outcome::result<holepunch::pb::HolePunch> msg_res,
        const StreamSPtr& stream) {
        auto [peer_id_str, peer_addr_str] = detail::getPeerIdentity(stream);
        if (!msg_res) {
            log_->error("cannot read an holepunch message from peer {}, {}: {}",
                peer_id_str, peer_addr_str, msg_res.error());
            return stream->reset();
        }

        log_->info("received an holepunch message from peer {}, {}", peer_id_str,
            peer_addr_str);

        auto&& msg = std::move(msg_res.value());
        //Connect message
        if (msg.type() == holepunch::pb::HolePunch::CONNECT)
        {
            std::vector<libp2p::multi::Multiaddress> connaddrs;
            for (auto& addr : msg.obsaddrs())
            {
                connaddrs.push_back(fromStringToMultiaddr(addr).value());
            }
        }
        //We now need to send a SYNC message to the node, and then initiate a connect after round trip time / 2 

    }

}

  // namespace libp2p::protocol
