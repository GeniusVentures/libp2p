
#include "libp2p/protocol/relay/relay_msg_processor.hpp"

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
    RelayMessageProcessor::RelayMessageProcessor(
        Host& host, network::ConnectionManager& conn_manager)
        : host_{ host },
        conn_manager_{ conn_manager }
    {


    }

    boost::signals2::connection RelayMessageProcessor::onRelayReceived(
        const std::function<RelayCallback>& cb) {
        return signal_relay_received_.connect(cb);
    }

    void RelayMessageProcessor::sendHopReservation(StreamSPtr stream) {
        //Create a Hop Message
        relay::pb::HopMessage msg;
        msg.set_type(relay::pb::HopMessage_Type_RESERVE);

        // write the resulting Protobuf message
        auto rw = std::make_shared<basic::ProtobufMessageReadWriter>(stream);
        rw->write<relay::pb::HopMessage>(
            msg,
            [self{ shared_from_this() },
            stream = std::move(stream)](auto&& res) mutable {
                self->relayReservationSent(std::forward<decltype(res)>(res), stream);
            });
    }

    void RelayMessageProcessor::sendConnectRelay(const StreamSPtr& stream, std::vector<libp2p::multi::Multiaddress> connaddrs, libp2p::peer::PeerId mypeer_id)
    {
        relay::pb::StopMessage msg;
        msg.set_type(relay::pb::StopMessage_Type_CONNECT);

        //Create a new peer for connection
        auto peer = new relay::pb::Peer;
        peer->set_id(std::string(mypeer_id.toVector().begin(), mypeer_id.toVector().end()));
        for (auto& addr : connaddrs)
        {
            peer->add_addrs(fromMultiaddrToString(addr));
        }

        //Optional Set Limits - Duration in seconds and Data in bytes.
        auto limits = new relay::pb::Limit;
        //limits->set_duration(2345345346345);
        //limits->set_data(123452345235);

        //Set Peer and Limits
        msg.set_allocated_peer(peer);
        msg.set_allocated_limit(limits);

        // write the resulting Protobuf message
        auto rw = std::make_shared<basic::ProtobufMessageReadWriter>(stream);
        rw->write<relay::pb::StopMessage>(
            msg,
            [self{ shared_from_this() },
            stream, mypeer_id, connaddrs](auto&& res) mutable {
                self->relayConnectSent(std::forward<decltype(res)>(res), stream);
            });
    }

    void RelayMessageProcessor::relayReservationSent(
        outcome::result<size_t> written_bytes, const StreamSPtr& stream) {
        auto [peer_id, peer_addr] = detail::getPeerIdentity(stream);
        if (!written_bytes) {
            log_->error("cannot write Relay message to stream to peer {}, {}: {}",
                peer_id, peer_addr, written_bytes.error().message());
            return stream->reset();
        }

        log_->info("successfully written an Relay message to peer {}, {}",
            peer_id, peer_addr);

        // Handle incoming responses
        auto rw = std::make_shared<basic::ProtobufMessageReadWriter>(stream);
        rw->read<relay::pb::HopMessage>(
            [self{ shared_from_this() }, stream](auto&& res) {
                self->relayReservationReceived(std::forward<decltype(res)>(res), stream);
            });
    }

    void RelayMessageProcessor::relayConnectSent(
        outcome::result<size_t> written_bytes, const StreamSPtr& stream) {
        auto [peer_id, peer_addr] = detail::getPeerIdentity(stream);
        if (!written_bytes) {
            log_->error("cannot write Relay message to stream to peer {}, {}: {}",
                peer_id, peer_addr, written_bytes.error().message());
            return stream->reset();
        }

        log_->info("successfully written an Relay message to peer {}, {}",
            peer_id, peer_addr);

        // Handle incoming responses
        auto rw = std::make_shared<basic::ProtobufMessageReadWriter>(stream);
        rw->read<relay::pb::StopMessage>(
            [self{ shared_from_this() }, stream = std::move(stream)](auto&& res) {
                self->relayConnectReceived(std::forward<decltype(res)>(res), stream);
            });
    }

    void RelayMessageProcessor::receiveRelay(StreamSPtr stream) {
        auto rw = std::make_shared<basic::ProtobufMessageReadWriter>(stream);

    }

    Host& RelayMessageProcessor::getHost() const noexcept {
        return host_;
    }

    network::ConnectionManager& RelayMessageProcessor::getConnectionManager()
        const noexcept {
        return conn_manager_;
    }

    const ObservedAddresses& RelayMessageProcessor::getObservedAddresses()
        const noexcept {
        return observed_addresses_;
    }

    void RelayMessageProcessor::relayReservationReceived(
        outcome::result<relay::pb::HopMessage> msg_res,
        const StreamSPtr& stream) {
        auto [peer_id_str, peer_addr_str] = detail::getPeerIdentity(stream);
        if (!msg_res) {
            log_->error("cannot read an relay message from peer {}, {}: {}",
                peer_id_str, peer_addr_str, msg_res.error());
            return stream->reset();
        }
        // in order for observed addresses feature to work, all those parameters
        // must be gotten
        auto remote_addr_res = stream->remoteMultiaddr();
        auto local_addr_res = stream->localMultiaddr();
        auto is_initiator_res = stream->isInitiator();
        if (!remote_addr_res || !local_addr_res || !is_initiator_res) {
            return log_->error("We appear to be missing an address on the stream containing relay info");
        }

        log_->info("received an relay message from peer {}, {}", peer_id_str,
            peer_addr_str);

        auto&& msg = std::move(msg_res.value());

        //Make sure we got a STATUS response
        if (msg.type() != relay::pb::HopMessage_Type_STATUS)
        {
            log_->info("Relay got a type other than STATUS when expecting status from: {}, {}", peer_id_str,
                peer_addr_str);
            return stream->reset();
        }
        //Make sure reservation is OK
        if (msg.status() != relay::pb::OK)
        {
            log_->info("Relay got status that indicates reservations are unavailable from: {}, {}", peer_id_str,
                peer_addr_str);
            return stream->reset();
        }
        // if our local address is not one of our "official" listen addresses, we don't know how to map this.
        auto& listener = host_.getNetwork().getListener();
        auto i_listen_addresses = listener.getListenAddressesInterfaces();

        auto listen_addresses = listener.getListenAddresses();
        auto addr_in_addresses =
            std::find(i_listen_addresses.begin(), i_listen_addresses.end(),
                local_addr_res.value())
            != i_listen_addresses.end()
            || std::find(listen_addresses.begin(), listen_addresses.end(),
                local_addr_res.value())
            != listen_addresses.end();
        if (!addr_in_addresses) {
            return log_->error("Relay stream address does not contain a valid listening address:  {}",
                local_addr_res.value().getStringAddress());
            return;
        }

        //Get Reservation info
        auto reservation = msg.reservation();

        for (auto& addr : reservation.addrs())
        {
            auto addrma = fromStringToMultiaddr(addr);
            if (!addrma.has_error())
            {
                std::string circuitaddress = std::string(addrma.value().getStringAddress()) + "/p2p-circuit/p2p/" + host_.getId().toBase58();
                auto circuitma = libp2p::multi::Multiaddress::create(circuitaddress);
                host_.getRelayRepository().add(local_addr_res.value(), circuitma.value(), reservation.expire());
            }
        }
    }

    void RelayMessageProcessor::relayConnectReceived(
        outcome::result<relay::pb::StopMessage> msg_res,
        const StreamSPtr& stream) {
        auto [peer_id_str, peer_addr_str] = detail::getPeerIdentity(stream);
        if (!msg_res) {
            log_->error("cannot read an relay message from peer {}, {}: {}",
                peer_id_str, peer_addr_str, msg_res.error());
            return stream->reset();
        }

        log_->info("received an relay message from peer {}, {}", peer_id_str,
            peer_addr_str);

        auto&& msg = std::move(msg_res.value());

        //Make sure we got a STATUS response
        if (msg.type() != relay::pb::StopMessage_Type_CONNECT)
        {
            log_->info("Relay Connnect got a type other than CONNECT when expecting status from: {}, {}", peer_id_str,
                peer_addr_str);
            return stream->reset();
        }
        //Make sure reservation is OK
        //if (msg.status() != relay::pb::OK)
        //{
        //    log_->info("Relay Connect got status that indicates reservations are unavailable from: {}, {}", peer_id_str,
        //        peer_addr_str);
        //    return stream->reset();
        //}
        //Send a positive response
        relayConnectResponse(stream);
    }

    void RelayMessageProcessor::relayConnectResponse(const StreamSPtr& stream)
    {
        //Create a Stop Message
        relay::pb::StopMessage msg;
        msg.set_type(relay::pb::StopMessage_Type_STATUS);
        msg.set_status(relay::pb::OK);

        // write the resulting Protobuf message, this stream is now the connection with peer.
        auto rw = std::make_shared<basic::ProtobufMessageReadWriter>(stream);
        rw->write<relay::pb::StopMessage>(
            msg,
            [self{ shared_from_this() },
            stream = std::move(stream)](auto&& res) mutable {
                self->relayReservationSent(std::forward<decltype(res)>(res), stream);
            });
    }
}

  // namespace libp2p::protocol
