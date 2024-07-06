
#include "libp2p/protocol/autonat/autonat_msg_processor.hpp"

#include <tuple>

#include <generated/protocol/autonat/protobuf/autonat.pb.h>
#include <boost/assert.hpp>
#include <libp2p/basic/protobuf_message_read_writer.hpp>
#include <libp2p/network/network.hpp>
#include <libp2p/peer/address_repository.hpp>
#include <libp2p/protocol/identify/utils.hpp>
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
  AutonatMessageProcessor::AutonatMessageProcessor(
      Host &host, network::ConnectionManager &conn_manager,
      peer::IdentityManager &identity_manager,
      std::shared_ptr<crypto::marshaller::KeyMarshaller> key_marshaller)
      : host_{host},
        conn_manager_{conn_manager},
        identity_manager_{identity_manager},
        key_marshaller_{std::move(key_marshaller)} {
    BOOST_ASSERT(key_marshaller_);
  }

  boost::signals2::connection AutonatMessageProcessor::onAutonatReceived(
      const std::function<AutonatCallback> &cb) {
      return signal_autonat_received_.connect(cb);
  }

  void AutonatMessageProcessor::sendAutonat(StreamSPtr stream) {
    autonat::pb::Message msg;

    //Set to DIAL to ask nodes to dial us
    msg.set_type(autonat::pb::Message::DIAL);

    //Create a Dial PB
    auto dialmsg = new autonat::pb::Message_Dial;
    //Create a Peer ID
    auto dialpeer = new autonat::pb::Message_PeerInfo;
    //Set our Peer ID
    dialpeer->set_id(host_.getPeerInfo().id.toBase58());

    //Set our Addresses we think we are available on
    for (const auto& addr : host_.getPeerInfo().addresses) {
        dialpeer->add_addrs(fromMultiaddrToString(addr));
    }
    dialmsg->set_allocated_peer(dialpeer);
    msg.set_allocated_dial(dialmsg);
    // write the resulting Protobuf message
    auto rw = std::make_shared<basic::ProtobufMessageReadWriter>(stream);
    rw->write<autonat::pb::Message>(
        msg,
        [self{shared_from_this()},
         stream = std::move(stream)](auto &&res) mutable {
          self->autonatSent(std::forward<decltype(res)>(res), stream);
        });
  }

  void AutonatMessageProcessor::autonatSent(
      outcome::result<size_t> written_bytes, const StreamSPtr &stream) {
    auto [peer_id, peer_addr] = detail::getPeerIdentity(stream);
    if (!written_bytes) {
      log_->error("cannot write Autonat message to stream to peer {}, {}: {}",
                  peer_id, peer_addr, written_bytes.error().message());
      return stream->reset();
    }

    log_->info("successfully written an Autonat message to peer {}, {}",
               peer_id, peer_addr);

    stream->close([self{shared_from_this()}, p = std::move(peer_id),
                   a = std::move(peer_addr)](auto &&res) {
      if (!res) {
        self->log_->error("cannot close the stream to peer {}, {}: {}", p, a,
                          res.error().message());
      }
    });
  }

  void AutonatMessageProcessor::receiveAutonat(StreamSPtr stream) {
    auto rw = std::make_shared<basic::ProtobufMessageReadWriter>(stream);
    rw->read<autonat::pb::Message>(
        [self{shared_from_this()}, s = std::move(stream)](auto &&res) {
          self->autonatReceived(std::forward<decltype(res)>(res), s);
        });
  }

  Host &AutonatMessageProcessor::getHost() const noexcept {
    return host_;
  }

  network::ConnectionManager &AutonatMessageProcessor::getConnectionManager()
      const noexcept {
    return conn_manager_;
  }

  const ObservedAddresses &AutonatMessageProcessor::getObservedAddresses()
      const noexcept {
    return observed_addresses_;
  }

  void AutonatMessageProcessor::autonatReceived(
      outcome::result<autonat::pb::Message> msg_res,
      const StreamSPtr &stream) {
    auto [peer_id_str, peer_addr_str] = detail::getPeerIdentity(stream);
    if (!msg_res) {
      log_->error("cannot read an autonat message from peer {}, {}: {}",
                  peer_id_str, peer_addr_str, msg_res.error());
      return stream->reset();
    }

    log_->info("received an autonat message from peer {}, {}", peer_id_str,
               peer_addr_str);
    stream->close([self{shared_from_this()}, p = std::move(peer_id_str),
                   a = std::move(peer_addr_str)](auto &&res) {
      if (!res) {
        self->log_->error("cannot close the stream to peer {}, {}: {}", p, a,
                          res.error().message());
      }
    });

    auto &&msg = std::move(msg_res.value());
    
    if (!msg.has_type())
    {
        log_->error("AUTONAT Message has no type");
        return;
    }
    if (msg.type() == autonat::pb::Message::DIAL)
    {
        if (!msg.dial().has_peer())
        {
            log_->error("AUTONAT DIAL Message has no peer");
            return;
        }
        //Get Peer Info
        const auto& peer_info = msg.dial().peer();

        //Get Remote IP from stream for comparisons
        auto remote_ip = stream->remoteMultiaddr().value().getStringAddress();

        //Get Peer ID
        auto peer_id_res = libp2p::peer::PeerId::fromBase58(peer_info.id());
        if (!peer_id_res.has_value())
        {
            log_->error("AUTONAT Peer has no ID {}", remote_ip);
            return;
        }
        auto peer_id = peer_id_res.value();

        // List to store matching addresses
        //We must avoid participating in a DDOS by filtering addresses that do not match the address we are connected to.
        std::vector<std::string> matching_addresses;

        // Verify if any address in PeerInfo matches the remote IP
        for (const auto& addr : peer_info.addrs()) {
            if (addr.find(remote_ip) != std::string::npos) {
                matching_addresses.push_back(addr);
            }
        }

        if (!matching_addresses.empty()) {
            // Proceed with dialing logic using matching_addresses
            for (const auto& addr : matching_addresses) {
                // Dial the address

            }
        }
        else {
              log_->error("Peer has no matching addresses for AUTONAT dial. {}", peer_id.toBase58());
              return;
        }

    }

    if (msg.type() == autonat::pb::Message::DIAL_RESPONSE) {
        if (!msg.dialresponse().has_status()) {
            log_->error("DIAL_RESPONSE missing status. {}", msg.dialresponse().statustext());
            return;
        }

        const auto& addr = msg.dialresponse().addr();

        if (addr.empty()) {
            log_->error("DIAL_RESPONSE address is empty.");
            return;
        }
        if (msg.dialresponse().status() != autonat::pb::Message::OK)
        {
            unsuccessful_addresses_[addr]++;
            if (unsuccessful_addresses_[addr] >= 3)
            {
                log_->info("Address {} reported NOT OK 3 or more times. Assumed behind NAT.", addr);
                // Handle logic when behind NAT
            }
        }
        else {
            successful_addresses_[addr]++;

            if (successful_addresses_[addr] >= 3) {
                log_->info("Address {} reported OK 3 or more times. Assumed not behind NAT.", addr);
                // Handle logic when not behind NAT
            }
        }
    }
  }

  // namespace libp2p::protocol
