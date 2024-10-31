#include <libp2p/protocol/holepunch/holepunch_client.hpp>

#include <string>
#include <tuple>

#include <boost/assert.hpp>
#include <iostream>


namespace {
  const std::string kHolepunchClientProto = "/libp2p/dcutr";
}  // namespace

namespace libp2p::protocol {
    HolepunchClient::HolepunchClient(Host &host,
                     std::shared_ptr<HolepunchClientMsgProc> msg_processor,
                     event::Bus &event_bus)
      : host_{host}, msg_processor_{std::move(msg_processor)}, bus_{event_bus} {
    BOOST_ASSERT(msg_processor_);
    msg_processor_->onHolepunchReceived([this](const bool& status) {
        natstatus_ = status;
        });
  }

  boost::signals2::connection HolepunchClient::onHolepunchClientReceived(
      const std::function<HolepunchClientMsgProc::HolepunchCallback> &cb) {
    return msg_processor_->onHolepunchReceived(cb);
  }

  //std::vector<multi::Multiaddress> HolepunchClient::getAllObservedAddresses() const {
  //  return msg_processor_->getObservedAddresses().getAllAddresses();
  //}

  //std::vector<multi::Multiaddress> HolepunchClient::getObservedAddressesFor(
  //    const multi::Multiaddress &address) const {
  //  return msg_processor_->getObservedAddresses().getAddressesFor(address);
  //}

  peer::Protocol HolepunchClient::getProtocolId() const {
    return kHolepunchClientProto;
  }

  void HolepunchClient::handle(StreamResult stream_res) {
    if (!stream_res) {
      return;
    }
    msg_processor_->receiveIncomingHolepunch(std::move(stream_res.value()));
  }

  void HolepunchClient::start() {
      if (started_) return;
    // no double starts
    //BOOST_ASSERT(!started_);
    started_ = true;

    host_.setProtocolHandler(
        kHolepunchClientProto,
        [wp = weak_from_this()](protocol::BaseProtocol::StreamResult rstream) {
          if (auto self = wp.lock()) {
            self->handle(std::move(rstream));
          }
        });
    //msg_processor_->sendHolepunchClientConnect(stream, peer_info);
    //sub_ = bus_.getChannel<event::network::OnNewConnectionChannel>().subscribe(
    //    [wp = weak_from_this(), obsaddr](auto &&conn) {
    //      if (auto self = wp.lock()) {
    //        return self->onNewConnection(conn, obsaddr);
    //      }
    //    });
  }
}