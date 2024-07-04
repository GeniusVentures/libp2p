
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
        if (!msg.dialresponse().has_status() || msg.dialresponse().status() != autonat::pb::Message::OK) {
            log_->error("DIAL_RESPONSE not OK or missing status. {}", msg.dialresponse().statustext());
            return;
        }

        const auto& addr = msg.dialresponse().addr();

        if (addr.empty()) {
            log_->error("DIAL_RESPONSE address is empty.");
            return;
        }

        successful_addresses_[addr]++;

        if (successful_addresses_[addr] >= 3) {
            log_->info("Address {} reported OK 3 or more times. Not behind NAT.", addr);
            // Handle logic when not behind NAT
        }
    }
  }

  boost::optional<peer::PeerId> AutonatMessageProcessor::consumePublicKey(
      const StreamSPtr &stream, std::string_view pubkey_str) {
    auto stream_peer_id_res = stream->remotePeerId();

    // if we haven't received a key from the other peer, all we can do is to
    // return the already known peer id
    if (pubkey_str.empty()) {
      if (!stream_peer_id_res) {
        return boost::none;
      }
      return stream_peer_id_res.value();
    }

    // peer id can be set in stream, derived from the received public key or
    // both; handle all possible cases
    boost::optional<peer::PeerId> stream_peer_id;
    boost::optional<crypto::PublicKey> pubkey;

    // retrieve a peer id from the stream
    if (stream_peer_id_res) {
      stream_peer_id = std::move(stream_peer_id_res.value());
    }

    // unmarshal a received public key
    std::vector<uint8_t> pubkey_buf;
    pubkey_buf.insert(pubkey_buf.end(), pubkey_str.begin(), pubkey_str.end());
    auto pubkey_res =
        key_marshaller_->unmarshalPublicKey(crypto::ProtobufKey{pubkey_buf});
    if (!pubkey_res) {
      log_->info("cannot unmarshal public key for peer {}: {}",
                 stream_peer_id ? stream_peer_id->toBase58() : "",
                 pubkey_res.error().message());
      return stream_peer_id;
    }
    pubkey = std::move(pubkey_res.value());

    // derive a peer id from the received public key; PeerId is made from
    // Protobuf-marshalled key, so we use it here
    auto msg_peer_id_res =
        peer::PeerId::fromPublicKey(crypto::ProtobufKey{pubkey_buf});
    if (!msg_peer_id_res) {
      log_->info("cannot derive PeerId from the received key: {}",
                 msg_peer_id_res.error().message());
      return stream_peer_id;
    }
    auto msg_peer_id = std::move(msg_peer_id_res.value());

    auto &key_repo = host_.getPeerRepository().getKeyRepository();
    if (!stream_peer_id) {
      // didn't know the ID before; memorize the key, from which it can be
      // derived later
      auto add_res = key_repo.addPublicKey(msg_peer_id, *pubkey);
      if (!add_res) {
        log_->error("cannot add key to the repo of peer {}: {}",
                    msg_peer_id.toBase58(), add_res.error().message());
      }
      return msg_peer_id;
    }

    if (stream_peer_id && *stream_peer_id != msg_peer_id) {
      log_->error(
          "peer with id {} sent public key, which derives to id {}, but they "
          "must be equal",
          stream_peer_id->toBase58(), msg_peer_id.toBase58());
      return boost::none;
    }

    // insert the derived key into key repository
    auto add_res = key_repo.addPublicKey(*stream_peer_id, *pubkey);
    if (!add_res) {
      log_->error("cannot add key to the repo of peer {}: {}",
                  stream_peer_id->toBase58(), add_res.error().message());
    }
    return stream_peer_id;
  }

  void AutonatMessageProcessor::consumeObservedAddresses(
      const std::string &address_str, const peer::PeerId &peer_id,
      const StreamSPtr &stream) {
    // in order for observed addresses feature to work, all those parameters
    // must be gotten
    auto remote_addr_res = stream->remoteMultiaddr();
    auto local_addr_res = stream->localMultiaddr();
    auto is_initiator_res = stream->isInitiator();
    if (!remote_addr_res || !local_addr_res || !is_initiator_res) {
      return;
    }
    
    auto address_res = fromStringToMultiaddr(address_str);
    if (!address_res) {
      return log_->error("peer {} has send an invalid observed address",
                         peer_id.toBase58());
    }
    auto &&observed_address = address_res.value();
    std::cout << "Address we are avail:::::" << observed_address.getStringAddress() << std::endl;
    // if our local address is not one of our "official" listen addresses, we
    // are not going to save its mapping to the observed one
    auto &listener = host_.getNetwork().getListener();
    auto i_listen_addresses = listener.getListenAddressesInterfaces();

    auto listen_addresses = listener.getListenAddresses();
    std::cout << "Address Test: " << remote_addr_res.value().getStringAddress() << std::endl;
    std::cout << "Address Test: " << local_addr_res.value().getStringAddress() << std::endl;
    std::cout << "Address Test: " << i_listen_addresses[0].getStringAddress() << std::endl;
    auto addr_in_addresses =
        std::find(i_listen_addresses.begin(), i_listen_addresses.end(),
                  local_addr_res.value())
            != i_listen_addresses.end()
        || std::find(listen_addresses.begin(), listen_addresses.end(),
                     local_addr_res.value())
            != listen_addresses.end();
    if (!addr_in_addresses) {
      std::cout << "Stopped at not in addresses" << std::endl;
      return;
    }

    if (!hasConsistentTransport(observed_address, host_.getAddresses())) {
      std::cout << "Stopped at no consistent transport" << std::endl;
      return;
    }

    observed_addresses_.add(std::move(observed_address),
                            std::move(local_addr_res.value()),
                            remote_addr_res.value(), is_initiator_res.value());
  }

  bool AutonatMessageProcessor::hasConsistentTransport(
      const multi::Multiaddress &ma, gsl::span<const multi::Multiaddress> mas) {
    auto ma_protos = ma.getProtocols();
    return std::any_of(mas.begin(), mas.end(),
                       [&ma_protos](const auto &ma_from_mas) {
                         return ma_protos == ma_from_mas.getProtocols();
                       });
  }

  void AutonatMessageProcessor::consumeListenAddresses(
      gsl::span<const std::string> addresses_strings,
      const peer::PeerId &peer_id) {
    if (addresses_strings.empty()) {
      return;
    }

    std::vector<multi::Multiaddress> listen_addresses;
    for (const auto &addr_str : addresses_strings) {
      auto addr_res = fromStringToMultiaddr(addr_str);
      if (!addr_res) {
        log_->error("peer {} has sent an invalid listen address",
                    peer_id.toBase58());
        continue;
      }
      listen_addresses.push_back(std::move(addr_res.value()));
    }

    auto &addr_repo = host_.getPeerRepository().getAddressRepository();

    // invalidate previously known addresses of that peer
    auto update_res = addr_repo.updateAddresses(peer_id, peer::ttl::kTransient);
    if (!update_res) {
      SL_DEBUG(log_, "cannot update listen addresses of the peer {}: {}",
               peer_id.toBase58(), update_res.error().message());
    }

    // memorize the addresses
    auto addresses = addr_repo.getAddresses(peer_id);
    if (!addresses) {
      SL_DEBUG(log_, "can not get addresses for peer {}", peer_id.toBase58());
    }

    bool permanent_ttl =
        (addresses
         && (conn_manager_.getBestConnectionForPeer(peer_id) != nullptr));

    auto upsert_res = addr_repo.upsertAddresses(
        peer_id, listen_addresses,
        permanent_ttl ? peer::ttl::kPermanent : peer::ttl::kRecentlyConnected);

    if (!upsert_res) {
      log_->error("cannot add addresses to peer {}: {}", peer_id.toBase58(),
                  upsert_res.error().message());
    }
  }
}  // namespace libp2p::protocol
