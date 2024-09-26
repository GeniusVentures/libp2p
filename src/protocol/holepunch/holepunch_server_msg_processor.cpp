
#include "libp2p/protocol/holepunch/holepunch_server_msg_processor.hpp"

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
    HolepunchServerMsgProc::HolepunchServerMsgProc(
        Host& host, network::ConnectionManager& conn_manager)
        : host_{ host },
        conn_manager_{ conn_manager }
    {
        std::cout << "Initialized Holepunch Message Processor" << std::endl;
    }

    boost::signals2::connection HolepunchServerMsgProc::onHolepunchReceived(
        const std::function<HolepunchCallback>& cb) {
        return signal_holepunch_received_.connect(cb);
    }

    void HolepunchServerMsgProc::sendHolepunchConnect(StreamSPtr stream, peer::PeerId peer_id, int retry_count) {
        if (retry_count > kMaxRetries)
        {
            log_->error("Attemps at holepunching with {}, have exceeded the maximum retry count of {}",
                peer_id.toBase58(), kMaxRetries);
            return;
        }

        log_->info("Sending a holepunch message with our addresses to {}", peer_id.toBase58());

        holepunch::pb::HolePunch msg;
        msg.set_type(holepunch::pb::HolePunch_Type_CONNECT);
        auto obsaddr = host_.getObservedAddresses();
        for (auto& addr : obsaddr)
        {
            if (!addr.hasCircuitRelay())
            {
                msg.add_obsaddrs(fromMultiaddrToString(addr));
            }
        }

        // write the resulting Protobuf message
        auto rw = std::make_shared<basic::ProtobufMessageReadWriter>(stream);
        rw->write<holepunch::pb::HolePunch>(
            msg,
            [self{ shared_from_this() },
            stream = std::move(stream), peer_id, retry_count](auto&& res) mutable {
                self->holepunchConnectSent(std::forward<decltype(res)>(res), stream, peer_id, retry_count);
            });
    }


    void HolepunchServerMsgProc::holepunchConnectSent(
        outcome::result<size_t> written_bytes, const StreamSPtr& stream,
        peer::PeerId peer_id, int retry_count) {
        auto [peer_id_str, peer_addr_str] = detail::getPeerIdentity(stream);
        if (!written_bytes) {
            log_->error("cannot write holepunch connect message to stream to peer {}, {} {}: {}",
                peer_id_str, peer_addr_str, peer_id.toBase58(), written_bytes.error().message());
            return stream->reset();
        }

        log_->info("successfully written a holepunch connect message to peer {}, {} {}",
            peer_id_str, peer_addr_str, peer_id.toBase58());
        //Create a timestamp
        auto start_time = std::chrono::steady_clock::now();
        // Handle incoming responses
        auto rw = std::make_shared<basic::ProtobufMessageReadWriter>(stream);
        rw->read<holepunch::pb::HolePunch>(
            [self{ shared_from_this() }, stream, start_time, peer_id, retry_count](auto&& res) {
                self->holepunchConnectReturn(std::forward<decltype(res)>(res), stream, start_time, peer_id, retry_count);
            });
    }

    void HolepunchServerMsgProc::holepunchConnectReturn(
        outcome::result<holepunch::pb::HolePunch> msg_res,
        const StreamSPtr& stream,
        std::chrono::steady_clock::time_point start_time,
        peer::PeerId peer_id, int retry_count) {
        auto [peer_id_str, peer_addr_str] = detail::getPeerIdentity(stream);

        if (!msg_res) {
            log_->error("cannot read an holepunch message from peer {}, {}: {}",
                peer_id_str, peer_addr_str, msg_res.error());
            return stream->reset();
        }

        log_->info("received an holepunch message from peer {}, {} {} ", peer_id_str,
            peer_addr_str, peer_id.toBase58());

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
            auto addaddr = fromStringToMultiaddr(addr);
            if (addaddr)
            {
                connaddrs.push_back(addaddr.value());
            }
        }
        

        auto peer_info = peer::PeerInfo{ peer_id, connaddrs };

        

        //Calculate RTT
        auto end_time = std::chrono::steady_clock::now();
        auto rtt = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();

        //We now need to send a SYNC message to the node, and then initiate a connect after round trip time / 2 
        holepunch::pb::HolePunch outmsg;
        outmsg.set_type(holepunch::pb::HolePunch_Type_SYNC);

        log_->info("Sending a sync message to {} ", peer_id.toBase58());
        //Send SYNC - Change to use async version below once we can get the io context into this class.
        auto rw = std::make_shared<basic::ProtobufMessageReadWriter>(stream);
        rw->write<holepunch::pb::HolePunch>(
            outmsg,
            [self{ shared_from_this() },
            stream, connaddrs, rtt, peer_info](auto&& res) mutable {
                self->log_->info("Waiting for sync response from {}",peer_info.id.toBase58());
                auto rw = std::make_shared<basic::ProtobufMessageReadWriter>(stream);
                rw->read<holepunch::pb::HolePunch>(
                    [self, stream, rtt, peer_info](auto&& res) {
                        // Calculate the delay time (RTT / 2)
                        auto delay_duration = std::chrono::milliseconds(rtt / 2);
                        // Wait for RTT / 2
                        std::this_thread::sleep_for(delay_duration);
                        self->log_->info("Initiating a connect with {} after waiting", peer_info.id.toBase58());
                        // Now attempt to connect to the peer
                        self->host_.connect(peer_info, [self, stream, peer_info](auto&& result) {
                            if (result)
                            {
                                self->log_->info("Successfully opened a hole punch to peer {}", peer_info.id.toBase58());
                                //TODO Save connection, destroy existing connection
                                self->host_.getNetwork().getListener().removeRelayedConnections(peer_info.id);
                            }
                            else {
                                self->log_->error("Failed to connect to peer {}: {}", peer_info.id.toBase58(), result.error().message());
                                self->sendHolepunchConnect(stream, peer_info.id);
                            }
                            }, true, true);
                    });
            });


        //rw->read<holepunch::pb::HolePunch>(
        //    [self{ shared_from_this() }, stream, rtt, peer_info](auto&& res) {
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

    Host& HolepunchServerMsgProc::getHost() const noexcept {
        return host_;
    }

    network::ConnectionManager& HolepunchServerMsgProc::getConnectionManager()
        const noexcept {
        return conn_manager_;
    }

    //const ObservedAddresses& HolepunchServerMsgProc::getObservedAddresses()
    //    const noexcept {
    //    return observed_addresses_;
    //}
}

  // namespace libp2p::protocol
