
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
        Host& host, network::ConnectionManager& conn_manager,
        peer::IdentityManager& identity_manager,
        std::shared_ptr<crypto::marshaller::KeyMarshaller> key_marshaller)
        : host_{ host },
        conn_manager_{ conn_manager },
        identity_manager_{ identity_manager },
        key_marshaller_{ std::move(key_marshaller) },
        successful_addresses_(),
        unsuccessful_addresses_() {
        BOOST_ASSERT(key_marshaller_);
    }

    boost::signals2::connection HolepunchMessageProcessor::onHolepunchReceived(
        const std::function<HolepunchCallback>& cb) {
        return signal_holepunch_received_.connect(cb);
    }

    void HolepunchMessageProcessor::sendHolepunch(StreamSPtr stream) {

    }

    void HolepunchMessageProcessor::holepunchSent(
        outcome::result<size_t> written_bytes, const StreamSPtr& stream) {
        auto [peer_id, peer_addr] = detail::getPeerIdentity(stream);
        if (!written_bytes) {
            log_->error("cannot write Autonat message to stream to peer {}, {}: {}",
                peer_id, peer_addr, written_bytes.error().message());
            return stream->reset();
        }

        log_->info("successfully written an Autonat message to peer {}, {}",
            peer_id, peer_addr);
    }

    void HolepunchMessageProcessor::receiveHolepunch(StreamSPtr stream) {
        auto rw = std::make_shared<basic::ProtobufMessageReadWriter>(stream);

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

    void HolepunchMessageProcessor::holepunchReceived(
        outcome::result<holepunch::pb::HolePunch> msg_res,
        const StreamSPtr& stream) {
        auto [peer_id_str, peer_addr_str] = detail::getPeerIdentity(stream);
        if (!msg_res) {
            log_->error("cannot read an autonat message from peer {}, {}: {}",
                peer_id_str, peer_addr_str, msg_res.error());
            return stream->reset();
        }

    }

}

  // namespace libp2p::protocol
