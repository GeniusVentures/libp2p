
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

    void HolepunchMessageProcessor::sendHolepunchConnect(StreamSPtr stream, peer::PeerId peer_id) {
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
            stream = std::move(stream), peer_id](auto&& res) mutable {
                self->holepunchConnectSent(std::forward<decltype(res)>(res), stream, peer_id);
            });
    }

    void HolepunchMessageProcessor::receiveIncomingHolepunch(StreamSPtr stream) {
        auto rw = std::make_shared<basic::ProtobufMessageReadWriter>(stream);
        rw->read<holepunch::pb::HolePunch>(
            [self{ shared_from_this() }, s = std::move(stream)](auto&& res) {
                self->holepunchIncomingReceived(std::forward<decltype(res)>(res), s);
            });
    }

    void HolepunchMessageProcessor::holepunchConnectSent(
        outcome::result<size_t> written_bytes, const StreamSPtr& stream,
        peer::PeerId peer_id) {
        auto [peer_id, peer_addr] = detail::getPeerIdentity(stream);
        if (!written_bytes) {
            log_->error("cannot write Autonat message to stream to peer {}, {}: {}",
                peer_id, peer_addr, written_bytes.error().message());
            return stream->reset();
        }

        log_->info("successfully written an Autonat message to peer {}, {}",
            peer_id, peer_addr);
        //Create a timestamp
        auto start_time = std::chrono::steady_clock::now();
        // Handle incoming responses
        auto rw = std::make_shared<basic::ProtobufMessageReadWriter>(stream);
        rw->read<holepunch::pb::HolePunch>(
            [self{ shared_from_this() }, stream = std::move(stream), start_time, peer_id](auto&& res) {
                self->holepunchConnectReturn(std::forward<decltype(res)>(res), stream, start_time, peer_id);
            });
    }

    void HolepunchMessageProcessor::holepunchConnectReturn(
        outcome::result<holepunch::pb::HolePunch> msg_res,
        const StreamSPtr& stream,
        std::chrono::steady_clock::time_point start_time,
        peer::PeerId peer_id) {
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
        if (msg.type() == holepunch::pb::HolePunch::CONNECT)
        {
            for (auto& addr : msg.obsaddrs())
            {
                connaddrs.push_back(fromStringToMultiaddr(addr).value());
            }
        }

        auto peer_info = peer::PeerInfo{ peer_id, connaddrs };

        //Calculate RTT
        auto end_time = std::chrono::steady_clock::now();
        auto rtt = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();

        //We now need to send a SYNC message to the node, and then initiate a connect after round trip time / 2 
        holepunch::pb::HolePunch msg;
        msg.set_type(holepunch::pb::HolePunch_Type_SYNC);

        //Send SYNC - Change to use async version below once we can get the io context into this class.
        auto rw = std::make_shared<basic::ProtobufMessageReadWriter>(stream);
        rw->read<holepunch::pb::HolePunch>(
            [self{ shared_from_this() }, stream = std::move(stream), rtt, peer_info](auto&& res) {
                // Calculate the delay time (RTT / 2)
                auto delay_duration = std::chrono::milliseconds(rtt / 2);
                // Wait for RTT / 2
                std::this_thread::sleep_for(delay_duration);
                // Now attempt to connect to the peer
                self->host_.connect(peer_info);
            });

        //rw->read<holepunch::pb::HolePunch>(
        //    [self{ shared_from_this() }, stream = std::move(stream), rtt, peer_info](auto&& res) {
        //        if (!res) {
        //            self->log_->error("Failed to read HolePunch message: {}", res.error().message());
        //            return;
        //        }

        //        // Calculate the delay time (RTT / 2)
        //        auto delay_duration = std::chrono::milliseconds(rtt / 2);

        //        // Create an asynchronous timer
        //        auto timer = std::make_shared<boost::asio::steady_timer>(self->io_context_, delay_duration);

        //        // Set the timer to wait for RTT / 2 asynchronously
        //        timer->async_wait([self, timer, peer_info](const boost::system::error_code& ec) {
        //            if (!ec) {
        //                // Now attempt to connect to the peer
        //                self->host_.connect(peer_info);
        //            }
        //            else {
        //                self->log_->error("Error during RTT wait: {}", ec.message());
        //            }
        //            });
        //    });

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

    void HolepunchMessageProcessor::holepunchIncomingReceived(
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
        if (msg.type() == holepunch::pb::HolePunch::CONNECT)
        {
            
            for (auto& addr : msg.obsaddrs())
            {
                connaddrs.push_back(fromStringToMultiaddr(addr).value());
            }
        }
        //Send a connect message back.
        holepunch::pb::HolePunch msg;
        msg.set_type(holepunch::pb::HolePunch_Type_CONNECT);
        auto obsaddr = host_.getObservedAddresses();
        for (auto& addr : obsaddr)
        {
            msg.add_obsaddrs(fromMultiaddrToString(addr));
        }

        //Write to stream
        auto rw = std::make_shared<basic::ProtobufMessageReadWriter>(stream);
        rw->write<holepunch::pb::HolePunch>(
            msg,
            [self{ shared_from_this() },
            stream = std::move(stream), connaddrs](auto&& res) mutable {
                self->holepunchConResponseSent(std::forward<decltype(res)>(res), stream, connaddrs);
            });

    }

    void HolepunchMessageProcessor::holepunchConResponseSent(
        outcome::result<size_t> written_bytes, const StreamSPtr& stream,
        std::vector<libp2p::multi::Multiaddress> connaddrs) {
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
            [self{ shared_from_this() }, stream = std::move(stream), connaddrs](auto&& res) {
                self->holepunchSyncResponseReturn(std::forward<decltype(res)>(res), stream, connaddrs);
            });
    }

    void HolepunchMessageProcessor::holepunchSyncResponseReturn(
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
        auto peer_id = peer::PeerId::fromBase58(connaddrs[0].getPeerId().value());
        if (peer_id.has_error())
        {
            log_->error("We were expecting peer id from observed address {}.", connaddrs[0].getStringAddress());
            return;
        }
        auto peer_info = peer::PeerInfo{ peer_id.value(), connaddrs};
        
        //Connect immediately since we got a SYNC message.
        host_.connect(peer_info);
    }

}

  // namespace libp2p::protocol
