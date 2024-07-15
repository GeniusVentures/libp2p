#include <libp2p/protocol/relay/relay.hpp>

#include <string>
#include <tuple>

#include <boost/assert.hpp>
#include <iostream>


namespace {
  const std::string kRelayProto = "/libp2p/circuit/relay/0.2.0/hop";
  const std::string kRelayStopProto = "/libp2p/circuit/relay/0.2.0/stop";
}  // namespace

namespace libp2p::protocol {
  Relay::Relay(Host &host,
                     std::shared_ptr<RelayMessageProcessor> msg_processor,
                     event::Bus &event_bus)
      : host_{host}, msg_processor_{std::move(msg_processor)}, bus_{event_bus} {
    BOOST_ASSERT(msg_processor_);
    msg_processor_->onRelayReceived([this](const bool& status) {

        });
    holepunchmsg_proc_ = std::make_shared<libp2p::protocol::HolepunchMessageProcessor>(
        host_, host_.getNetwork().getConnectionManager());
    holepunch_ = std::make_shared<libp2p::protocol::Holepunch>(host_, holepunchmsg_proc_, host_.getBus());
  }

  boost::signals2::connection Relay::onRelayReceived(
      const std::function<RelayMessageProcessor::RelayCallback> &cb) {
    return msg_processor_->onRelayReceived(cb);
  }

  std::vector<multi::Multiaddress> Relay::getAllObservedAddresses() const {
    return msg_processor_->getObservedAddresses().getAllAddresses();
  }

  std::vector<multi::Multiaddress> Relay::getObservedAddressesFor(
      const multi::Multiaddress &address) const {
    return msg_processor_->getObservedAddresses().getAddressesFor(address);
  }

  peer::Protocol Relay::getProtocolId() const {
    return kRelayProto;
  }

  void Relay::handle(StreamResult stream_res) {
    if (!stream_res) {
      return;
    }
    msg_processor_->receiveRelay(std::move(stream_res.value()));
  }

  void Relay::start(std::vector<libp2p::multi::Multiaddress> connaddrs, 
      libp2p::peer::PeerId peer_id, uint64_t time) {
    // no double starts
    BOOST_ASSERT(!started_);
    started_ = true;

    host_.setProtocolHandler(
        kRelayProto,
        [wp = weak_from_this()](protocol::BaseProtocol::StreamResult rstream) {
          if (auto self = wp.lock()) {
            self->handle(std::move(rstream));
          }
        });

    sub_ = bus_.getChannel<event::network::OnNewConnectionChannel>().subscribe(
        [wp = weak_from_this(), connaddrs, time, peer_id](auto &&conn) {
          if (auto self = wp.lock()) {
            return self->onNewConnection(conn, connaddrs, peer_id, time);
          }
        });
  }

  void Relay::onNewConnection(
      const std::weak_ptr<connection::CapableConnection> &conn,
      std::vector<libp2p::multi::Multiaddress> connaddrs, 
      libp2p::peer::PeerId peer_id, uint64_t time) {
    if (conn.expired()) {
      return;
    }

    auto remote_peer_res = conn.lock()->remotePeer();
    if (!remote_peer_res) {
      return;
    }

    auto remote_peer_addr_res = conn.lock()->remoteMultiaddr();
    if (!remote_peer_addr_res) {
      return;
    }

    peer::PeerInfo peer_info{std::move(remote_peer_res.value()),
                             std::vector<multi::Multiaddress>{
                                 std::move(remote_peer_addr_res.value())}};

    msg_processor_->getHost().newStream(
        peer_info, kRelayProto,
        [self{shared_from_this()}, connaddrs, time, peer_id](auto &&stream_res) {
            if (!stream_res) {
                self->log_->error("Failed to create new stream: {}", stream_res.error().message());
                return;
            }
            self->log_->info("Sending Autonat request to peer");
            auto stream = stream_res.value();
            self->msg_processor_->sendHopRelay(stream, connaddrs, peer_id, time);
        });
  }
}