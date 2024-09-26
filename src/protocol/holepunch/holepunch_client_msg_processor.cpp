
#include "libp2p/protocol/holepunch/holepunch_client_msg_processor.hpp"

#include <tuple>

#include <generated/protocol/holepunch/protobuf/holepunch.pb.h>
#include <boost/assert.hpp>
#include <libp2p/basic/protobuf_message_read_writer.hpp>
#include <libp2p/network/network.hpp>
#include <libp2p/peer/address_repository.hpp>
#include <libp2p/protocol/identify/utils.hpp>
#include "libp2p/injector/host_injector.hpp"
#include <thread>
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
    HolepunchClientMsgProc::HolepunchClientMsgProc(
        Host& host, network::ConnectionManager& conn_manager)
        : host_{ host },
        conn_manager_{ conn_manager },
        connections_()
    {
        std::cout << "Initialized Holepunch Message Processor" << std::endl;
    }

    boost::signals2::connection HolepunchClientMsgProc::onHolepunchReceived(
        const std::function<HolepunchCallback>& cb) {
        return signal_holepunch_received_.connect(cb);
    }


    void HolepunchClientMsgProc::receiveIncomingHolepunch(StreamSPtr stream) {
        auto rw = std::make_shared<basic::ProtobufMessageReadWriter>(stream);
        rw->read<holepunch::pb::HolePunch>(
            [self{ shared_from_this() }, s = std::move(stream)](auto&& res) {
                self->holepunchIncomingReceived(std::forward<decltype(res)>(res), s);
            });
    }

    Host& HolepunchClientMsgProc::getHost() const noexcept {
        return host_;
    }

    network::ConnectionManager& HolepunchClientMsgProc::getConnectionManager()
        const noexcept {
        return conn_manager_;
    }

    //const ObservedAddresses& HolepunchClientMsgProc::getObservedAddresses()
    //    const noexcept {
    //    return observed_addresses_;
    //}

    void HolepunchClientMsgProc::holepunchIncomingReceived(
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
        std::vector<libp2p::multi::Multiaddress> connaddrs;
        if (msg.type() != holepunch::pb::HolePunch::CONNECT)
        {
            log_->error("We were expecting a holepunch CONNECT but got something else {}, {}",
                peer_id_str, peer_addr_str);
            return;
        }
        for (auto& addr : msg.obsaddrs())
        {
            auto resolvedaddr = fromStringToMultiaddr(addr);
            if (resolvedaddr)
            {
                connaddrs.push_back(fromStringToMultiaddr(addr).value());
            }
        }
        if (connaddrs.size() <= 0)
        {
            log_->error("There were no valid addresses from {}, {}",
                peer_id_str, peer_addr_str);
            return;
        }
        //Send a connect message back.
        holepunch::pb::HolePunch outmsg;
        outmsg.set_type(holepunch::pb::HolePunch_Type_CONNECT);
        auto obsaddr = host_.getObservedAddressesReal(false);
        for (auto& addr : obsaddr)
        {
            if (!addr.hasCircuitRelay())
            {
                outmsg.add_obsaddrs(fromMultiaddrToString(addr));
            }
        }

        //Write to stream
        auto rw = std::make_shared<basic::ProtobufMessageReadWriter>(stream);
        rw->write<holepunch::pb::HolePunch>(
            outmsg,
            [self{ shared_from_this() },
            stream, connaddrs](auto&& res) mutable {
                self->holepunchConResponseSent(std::forward<decltype(res)>(res), stream, connaddrs);
            });

    }

    void HolepunchClientMsgProc::holepunchConResponseSent(
        outcome::result<size_t> written_bytes, const StreamSPtr& stream,
        std::vector<libp2p::multi::Multiaddress> connaddrs) {
        auto [peer_id, peer_addr] = detail::getPeerIdentity(stream);
        if (!written_bytes) {
            log_->error("cannot write holepunch connect response message to stream to peer {}, {}: {}",
                peer_id, peer_addr, written_bytes.error().message());
            return stream->reset();
        }

        log_->info("successfully written an holepunch connect response message to peer {}, {}",
            peer_id, peer_addr);
        // Handle incoming responses
        auto rw = std::make_shared<basic::ProtobufMessageReadWriter>(stream);
        rw->read<holepunch::pb::HolePunch>(
            [self{ shared_from_this() }, stream, connaddrs](auto&& res) {
                self->holepunchSyncResponseReturn(std::forward<decltype(res)>(res), stream, connaddrs);
            });
    }

    void HolepunchClientMsgProc::holepunchSyncResponseReturn(
        outcome::result<holepunch::pb::HolePunch> msg_res,
        const StreamSPtr& stream,
        std::vector<libp2p::multi::Multiaddress> connaddrs)
    {
        auto [peer_id_str, peer_addr_str] = detail::getPeerIdentity(stream);
        if (!msg_res) {
            log_->error("cannot read an holepunch sync message from peer {}, {}: {}",
                peer_id_str, peer_addr_str, msg_res.error());
            return stream->reset();
        }
        log_->info("received an assumed holepunch SYNC message from peer {}, {}", peer_id_str,
            peer_addr_str);

        auto&& msg = std::move(msg_res.value());
        if (msg.type() != holepunch::pb::HolePunch::SYNC)
        {
            log_->error("We were expecting a sync message from {}, {} We got something else.", peer_id_str, peer_addr_str);
            return;
        }

        //Should probably chose a peer ID from any observed address
        auto peer_id = peer::PeerId::fromBase58(peer_id_str);
        if (peer_id.has_error())
        {
            log_->error("We were expecting peer id from observed address {}.", connaddrs[0].getStringAddress());
            return;
        }


        auto peer_info = peer::PeerInfo{ peer_id.value(), connaddrs };

        //Connect immediately since we got a SYNC message.
        host_.connect(peer_info, [self{ shared_from_this() }, stream, peer_info](auto&& result) {
            if (result)
            {
                self->log_->info("Successfully opened a connection to peer {}", peer_info.id.toBase58());
                //TODO 
            }
            else {
                self->log_->info("Failed to connect to peer in holepunch, this may re-try {}: {}", peer_info.id.toBase58(), result.error().message());
            }
            }, true, false);
        
    }

}

  // namespace libp2p::protocol
