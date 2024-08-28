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
                     event::Bus &event_bus, CompletionCallback callback)
      : host_{host}, msg_processor_{std::move(msg_processor)}, bus_{event_bus}, callback_(callback)
  {
      holepunch_msg_proc_ = std::make_shared<libp2p::protocol::HolepunchMessageProcessor>(host, host.getNetwork().getConnectionManager());
      holepunch_ = std::make_shared<libp2p::protocol::Holepunch>(host, holepunch_msg_proc_, host.getBus());
    
      BOOST_ASSERT(msg_processor_);
    
      msg_processor_->onRelayReceived([this](const bool& status) {
        if (!status)
        {
            relayconnections--;
        }
        else {
            log_->info("Starting holepunch since we have an established relay now");
            holepunch_->start();
        }
        });
    
    
  }

  boost::signals2::connection Relay::onRelayReceived(
      const std::function<RelayMessageProcessor::RelayCallback> &cb) {
    return msg_processor_->onRelayReceived(cb);
  }

  //std::vector<multi::Multiaddress> Relay::getAllObservedAddresses() const {
  //  return msg_processor_->getObservedAddresses().getAllAddresses();
  //}

  //std::vector<multi::Multiaddress> Relay::getObservedAddressesFor(
  //    const multi::Multiaddress &address) const {
  //  return msg_processor_->getObservedAddresses().getAddressesFor(address);
  //}

  peer::Protocol Relay::getProtocolId() const {
    return kRelayProto;
  }

  void Relay::handle(StreamResult stream_res) {
    if (!stream_res) {
      return;
    }
    msg_processor_->receiveRelay(std::move(stream_res.value()));
  }

  void Relay::handleStopMessage(StreamResult stream_res) {
      if (!stream_res) {
          return;
      }
      msg_processor_->receiveRelay(std::move(stream_res.value()));
  }

  void Relay::start() {
      if (started_) return;
    // no double starts
    BOOST_ASSERT(!started_);
    started_ = true;
    log_->info("Started Relay Protocol");
    host_.setProtocolHandler(
        kRelayProto,
        [wp = weak_from_this()](protocol::BaseProtocol::StreamResult rstream) {
          if (auto self = wp.lock()) {
            //self->handle(std::move(rstream));
              self->log_->info("Handle hop protocol");
          }
        });

    host_.setProtocolHandler(
        kRelayStopProto,
        [wp = weak_from_this()](protocol::BaseProtocol::StreamResult rstream) {
            if (auto self = wp.lock()) {
                self->log_->info("Handle stop protocol");
                self->handleStopMessage(std::move(rstream));
            }
        });

    sub_ = bus_.getChannel<event::network::OnNewConnectionChannel>().subscribe(
        [wp = weak_from_this()](auto &&conn) {
          if (auto self = wp.lock()) {
            return self->onNewConnection(conn);
          }
        });
  }

  void Relay::onNewConnection(
      const std::weak_ptr<connection::CapableConnection> &conn) {
      log_->info("Relay got new connection");
    if (conn.expired()) {
      log_->error("Relay new connection was expired for some reason");
      return;
    }

    if (relayconnections >= maxrelays)
    {
        log_->error("We already have as many relay connections as we need");
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
        [self{shared_from_this()}](auto &&stream_res) {
            if (!stream_res) {
                self->log_->error("Failed to create new stream: {}", stream_res.error().message());
                return;
            }
            self->log_->info("Sending Autonat request to peer");
            self->relayconnections++;
            auto stream = stream_res.value();
            self->msg_processor_->sendHopReservation(stream);
        });
  }
}