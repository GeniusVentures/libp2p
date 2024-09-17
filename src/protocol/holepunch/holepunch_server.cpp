#include <libp2p/protocol/holepunch/holepunch_server.hpp>

#include <string>
#include <tuple>

#include <boost/assert.hpp>
#include <iostream>


namespace {
  const std::string kHolepunchServerProto = "/libp2p/dcutr";
}  // namespace

namespace libp2p::protocol {
    HolepunchServer::HolepunchServer(Host &host,
                     std::shared_ptr<HolepunchServerMsgProc> msg_processor,
                     event::Bus &event_bus)
      : host_{host}, msg_processor_{std::move(msg_processor)}, bus_{event_bus} {
    BOOST_ASSERT(msg_processor_);
    msg_processor_->onHolepunchReceived([this](const bool& status) {
        natstatus_ = status;
        });
  }

  boost::signals2::connection HolepunchServer::onHolepunchServerReceived(
      const std::function<HolepunchServerMsgProc::HolepunchCallback> &cb) {
    return msg_processor_->onHolepunchReceived(cb);
  }

  //std::vector<multi::Multiaddress> HolepunchServer::getAllObservedAddresses() const {
  //  return msg_processor_->getObservedAddresses().getAllAddresses();
  //}

  //std::vector<multi::Multiaddress> HolepunchServer::getObservedAddressesFor(
  //    const multi::Multiaddress &address) const {
  //  return msg_processor_->getObservedAddresses().getAddressesFor(address);
  //}

  peer::Protocol HolepunchServer::getProtocolId() const {
    return kHolepunchServerProto;
  }

  void HolepunchServer::handle(StreamResult stream_res) {
    if (!stream_res) {
      return;
    }
    msg_processor_->receiveIncomingHolepunch(std::move(stream_res.value()));
  }

  void HolepunchServer::start(peer::PeerId peerid) {
      if (started_) return;
    // no double starts
    //BOOST_ASSERT(!started_);
    started_ = true;

    //host_.setProtocolHandler(
    //    kHolepunchServerProto,
    //    [wp = weak_from_this()](protocol::BaseProtocol::StreamResult rstream) {
    //      if (auto self = wp.lock()) {
    //        self->handle(std::move(rstream));
    //      }
    //    });
    //msg_processor_->sendHolepunchServerConnect(stream, peer_info);
    //sub_ = bus_.getChannel<event::network::OnNewConnectionChannel>().subscribe(
    //    [wp = weak_from_this(), obsaddr](auto &&conn) {
    //      if (auto self = wp.lock()) {
    //        return self->onNewConnection(conn, obsaddr);
    //      }
    //    });
        msg_processor_->getHost().newStream(
        peerid, kHolepunchServerProto,
        [self{shared_from_this()}, peerid](auto &&stream_res) {
            if (!stream_res) {
                self->log_->error("Failed to create new stream: {}", stream_res.error().message());
                return;
            }
            self->log_->info("Sending dcutr holepunch request to peer {} ", peerid.toBase58());
            auto stream = stream_res.value();
            self->msg_processor_->sendHolepunchConnect(stream, obsaddr);
        });
  }

  void HolepunchServer::initiateHolepunchServer(StreamSPtr stream, peer::PeerId peer_id) {
        //Send out connect message
      msg_processor_->sendHolepunchConnect(stream, peer_id);
  }

  void HolepunchServer::onNewConnection(
      const std::weak_ptr<connection::CapableConnection> &conn,
      std::vector<libp2p::multi::Multiaddress> obsaddr) {
    //if (conn.expired()) {
    //  return;
    //}

    //auto remote_peer_res = conn.lock()->remotePeer();
    //if (!remote_peer_res) {
    //  return;
    //}

    //auto remote_peer_addr_res = conn.lock()->remoteMultiaddr();
    //if (!remote_peer_addr_res) {
    //  return;
    //}

    //peer::PeerInfo peer_info{std::move(remote_peer_res.value()),
    //                         std::vector<multi::Multiaddress>{
    //                             std::move(remote_peer_addr_res.value())}};

    //msg_processor_->getHost().newStream(
    //    peer_info, kHolepunchServerProto,
    //    [self{shared_from_this()}, obsaddr](auto &&stream_res) {
    //        if (!stream_res) {
    //            self->log_->error("Failed to create new stream: {}", stream_res.error().message());
    //            return;
    //        }
    //        self->log_->info("Sending Autonat request to peer");
    //        auto stream = stream_res.value();
    //        self->msg_processor_->sendHolepunchServerConnect(stream, obsaddr);
    //    });
  }
}