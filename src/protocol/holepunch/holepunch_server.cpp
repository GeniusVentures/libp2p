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
  void HolepunchServer::handle(StreamResult stream_res)
  {
  }


  peer::Protocol HolepunchServer::getProtocolId() const {
    return kHolepunchServerProto;
  }


  void HolepunchServer::start(peer::PeerId peerid) {
    //  if (started_) return;
    //// no double starts
    ////BOOST_ASSERT(!started_);
    //started_ = true;
      log_->info("Initiate a holepunch with: {}", peerid.toBase58());
        msg_processor_->getHost().newStream(
        peerid, kHolepunchServerProto,
        [self{shared_from_this()}, peerid](auto &&stream_res) {
            if (!stream_res) {
                self->log_->error("Failed to create new stream: {}", stream_res.error().message());
                return;
            }
            self->log_->info("Sending dcutr holepunch request to peer {} ", peerid.toBase58());
            auto stream = stream_res.value();
            self->msg_processor_->sendHolepunchConnect(stream, peerid, 0);
        });
  }

  void HolepunchServer::initiateHolepunchServer(StreamSPtr stream, peer::PeerId peer_id) {
        //Send out connect message
      msg_processor_->sendHolepunchConnect(stream, peer_id);
  }

}