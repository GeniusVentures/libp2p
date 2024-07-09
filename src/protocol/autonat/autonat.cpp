#include <libp2p/protocol/autonat/autonat.hpp>

#include <string>
#include <tuple>

#include <boost/assert.hpp>



namespace {
  const std::string kAutonatProto = "/libp2p/autonat/1.0.0";
}  // namespace

namespace libp2p::protocol {
  Autonat::Autonat(Host &host,
                     std::shared_ptr<AutonatMessageProcessor> msg_processor,
                     event::Bus &event_bus)
      : host_{host}, msg_processor_{std::move(msg_processor)}, bus_{event_bus} {
    BOOST_ASSERT(msg_processor_);
    //msg_processor_->onAutonatReceived([this](const bool& status) {
    //    natstatus_ = status;
    //    });
  }

  boost::signals2::connection Autonat::onAutonatReceived(
      const std::function<AutonatMessageProcessor::AutonatCallback> &cb) {
    return msg_processor_->onAutonatReceived(cb);
  }

  std::vector<multi::Multiaddress> Autonat::getAllObservedAddresses() const {
    return msg_processor_->getObservedAddresses().getAllAddresses();
  }

  std::vector<multi::Multiaddress> Autonat::getObservedAddressesFor(
      const multi::Multiaddress &address) const {
    return msg_processor_->getObservedAddresses().getAddressesFor(address);
  }

  peer::Protocol Autonat::getProtocolId() const {
    return kAutonatProto;
  }

  void Autonat::handle(StreamResult stream_res) {
    if (!stream_res) {
      return;
    }
    msg_processor_->sendAutonat(std::move(stream_res.value()));
  }

  void Autonat::start() {
    // no double starts
    BOOST_ASSERT(!started_);
    started_ = true;

    host_.setProtocolHandler(
        kAutonatProto,
        [wp = weak_from_this()](protocol::BaseProtocol::StreamResult rstream) {
          if (auto self = wp.lock()) {
            self->handle(std::move(rstream));
          }
        });

    sub_ = bus_.getChannel<event::network::OnNewConnectionChannel>().subscribe(
        [wp = weak_from_this()](auto &&conn) {
          if (auto self = wp.lock()) {
            return self->onNewConnection(conn);
          }
        });
  }

  void Autonat::onNewConnection(
      const std::weak_ptr<connection::CapableConnection> &conn) {
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
        peer_info, kAutonatProto,
        [self{shared_from_this()}](auto &&stream_res) {
          if (!stream_res) {
            return;
          }
          self->msg_processor_->receiveAutonat(std::move(stream_res.value()));
        });
  }
}