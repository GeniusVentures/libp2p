
#include "libp2p/protocol/autonat/autonat_msg_processor.hpp"

#include <tuple>

#include <generated/protocol/autonat/protobuf/autonat.pb.h>
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
    AutonatMessageProcessor::AutonatMessageProcessor(
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

    boost::signals2::connection AutonatMessageProcessor::onAutonatReceived(
        const std::function<AutonatCallback>& cb) {
        return signal_autonat_received_.connect(cb);
    }

    void AutonatMessageProcessor::sendAutonat(StreamSPtr stream) {
        if (host_.getObservedAddresses().size() <= 0)
        {
            log_->info("We have no observed addresses to check for NAT.");
            return;
        }
        autonat::pb::Message msg;

        //Set to DIAL to ask nodes to dial us
        msg.set_type(autonat::pb::Message::DIAL);

        //Create a Dial PB
        auto dialmsg = new autonat::pb::Message_Dial;
        //Create a Peer ID
        auto dialpeer = new autonat::pb::Message_PeerInfo;
        //Set our Peer ID
        dialpeer->set_id(std::string(host_.getPeerInfo().id.toVector().begin(), host_.getPeerInfo().id.toVector().end()));

        //Set our Addresses we think we are available on
        for (const auto& addr : host_.getObservedAddresses()) {
            //std::cout << "Adding address to Autonat PB: " << addr.getStringAddress() << std::endl;
            dialpeer->add_addrs(fromMultiaddrToString(addr));
        }
        dialmsg->set_allocated_peer(dialpeer);
        msg.set_allocated_dial(dialmsg);
        // write the resulting Protobuf message
        auto rw = std::make_shared<basic::ProtobufMessageReadWriter>(stream);
        rw->write<autonat::pb::Message>(
            msg,
            [self{ shared_from_this() },
            stream = std::move(stream)](auto&& res) mutable {
                self->autonatSent(std::forward<decltype(res)>(res), stream);
            });

    }

    void AutonatMessageProcessor::autonatSent(
        outcome::result<size_t> written_bytes, const StreamSPtr& stream) {
        auto [peer_id, peer_addr] = detail::getPeerIdentity(stream);
        if (!written_bytes) {
            log_->error("cannot write Autonat message to stream to peer {}, {}: {}",
                peer_id, peer_addr, written_bytes.error().message());
            return stream->reset();
        }

        log_->info("successfully written an Autonat message to peer {}, {}",
            peer_id, peer_addr);

                // Handle incoming responses
        auto rw = std::make_shared<basic::ProtobufMessageReadWriter>(stream);
        rw->read<autonat::pb::Message>(
            [self{ shared_from_this() }, stream = std::move(stream)](auto&& res) {
                self->autonatReceived(std::forward<decltype(res)>(res), stream);
            });
    }

    void AutonatMessageProcessor::receiveAutonat(StreamSPtr stream) {
        auto rw = std::make_shared<basic::ProtobufMessageReadWriter>(stream);
        rw->read<autonat::pb::Message>(
            [self{ shared_from_this() }, s = std::move(stream)](auto&& res) {
                self->autonatReceived(std::forward<decltype(res)>(res), s);
            });
    }

    Host& AutonatMessageProcessor::getHost() const noexcept {
        return host_;
    }

    network::ConnectionManager& AutonatMessageProcessor::getConnectionManager()
        const noexcept {
        return conn_manager_;
    }

    const ObservedAddresses& AutonatMessageProcessor::getObservedAddresses()
        const noexcept {
        return observed_addresses_;
    }

    void AutonatMessageProcessor::autonatReceived(
        outcome::result<autonat::pb::Message> msg_res,
        const StreamSPtr& stream) {
        auto [peer_id_str, peer_addr_str] = detail::getPeerIdentity(stream);
        if (!msg_res) {
            log_->error("cannot read an autonat message from peer {}, {}: {}",
                peer_id_str, peer_addr_str, msg_res.error());
            return stream->reset();
        }

        log_->info("received an autonat message from peer {}, {}", peer_id_str,
            peer_addr_str);


        auto&& msg = std::move(msg_res.value());

        if (!msg.has_type())
        {
            log_->error("AUTONAT Message has no type");
            return;
        }

        //Determine the type of message and handle
        switch (msg.type())
        {
        case autonat::pb::Message::DIAL:
            autonatParseDIALREQUEST(stream, msg, peer_id_str, peer_addr_str);
            break;
        case autonat::pb::Message::DIAL_RESPONSE:
            autonatParseDIALRESPONSE(stream, msg, peer_id_str, peer_addr_str);
            break;
        }
    }
    void AutonatMessageProcessor::autonatParseDIALREQUEST(const StreamSPtr& stream, autonat::pb::Message& msg, std::string& peer_id_str, std::string& peer_addr_str)
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
        std::vector<multi::Multiaddress> matching_addresses;

        // Verify if any address in PeerInfo matches the remote IP
        for (const auto& addr : peer_info.addrs()) {
            auto ma_addr = fromStringToMultiaddr(addr);
            if (ma_addr.value().getStringAddress().find(remote_ip) != std::string::npos) {
                matching_addresses.push_back(ma_addr.value());
            }
        }

        if (!matching_addresses.empty()) {
            //Create a temporary libp2p host to dial out with
            auto injector = libp2p::injector::makeHostInjector();
            auto temphost = injector.create<std::shared_ptr<libp2p::Host>>();
            libp2p::multi::Multiaddress listen_address = libp2p::multi::Multiaddress::create("/ip4/127.0.0.1/tcp/32348").value();
            temphost->getNetwork().getListener().listen(listen_address);
            //Create a dial response



            for (const auto& addr : matching_addresses)
            {
                //Consider whether duplicate addresses could cause us to report twice a positive or negative result.
                std::vector<multi::Multiaddress> dialaddr;
                dialaddr.push_back(addr);
                libp2p::peer::PeerInfo target_peer_info{ peer_id, dialaddr };
                temphost->newStream(
                    target_peer_info,
                    "/libp2p/autonat/1.0.0",
                    [self{ shared_from_this() }, stream, addr](auto&& stream_res) {
                        autonat::pb::Message responsemsg;
                        responsemsg.set_type(autonat::pb::Message::DIAL_RESPONSE);
                        auto dialrmsg = new autonat::pb::Message_DialResponse;
                        auto rw = std::make_shared<basic::ProtobufMessageReadWriter>(stream);
                        if (!stream_res) {
                            std::cerr << "Failed to create new stream: " << stream_res.error().message() << std::endl;
                            dialrmsg->set_status(autonat::pb::Message::E_DIAL_ERROR);
                            dialrmsg->set_statustext("Error Dialing");
                            responsemsg.set_allocated_dialresponse(dialrmsg);
                            rw->write<autonat::pb::Message>(
                                responsemsg,
                                [self, stream = std::move(stream)](auto&& res) mutable {
                                    self->log_->info("Sent a negative DIAL_RESPONSE to autonat request");
                                });
                            return;
                        }
                        dialrmsg->set_addr(fromMultiaddrToString(addr));
                        dialrmsg->set_status(autonat::pb::Message::OK);
                        dialrmsg->set_statustext("Success");
                        responsemsg.set_allocated_dialresponse(dialrmsg);
                        auto newstream = std::move(stream_res.value());
                        //Send Dial response on original stream

                        rw->write<autonat::pb::Message>(
                            responsemsg,
                            [self, stream = std::move(stream)](auto&& res) mutable {
                                self->log_->info("Sent a positive DIAL_RESPONSE to autonat request");
                            });
                        //Close this stream.
                        newstream->close([self](auto&& res)
                            {
                                if (!res)
                                {
                                    self->log_->error("cannot close the stream to peer: {}", res.error().message());
                                }
                            });
                        std::cout << "Successfully created new stream to target." << std::endl;
                    });
            }
            stream->close([self{ shared_from_this() }, p = std::move(peer_id_str),
                a = std::move(peer_addr_str)](auto&& res) {
                    if (!res) {
                        self->log_->error("cannot close the stream to peer {}, {}: {}", p, a,
                            res.error().message());
                    }
                });

        }
        else {
            log_->error("Peer has no matching addresses for AUTONAT dial. {}", peer_id.toBase58());
            stream->close([self{ shared_from_this() }, p = std::move(peer_id_str),
                a = std::move(peer_addr_str)](auto&& res) {
                    if (!res) {
                        self->log_->error("cannot close the stream to peer {}, {}: {}", p, a,
                            res.error().message());
                    }
                });
            return;
        }
    }

    void AutonatMessageProcessor::autonatParseDIALRESPONSE(const StreamSPtr& stream, autonat::pb::Message& msg, std::string& peer_id_str, std::string& peer_addr_str)
    {
        auto local_addr_res = stream->localMultiaddr();
        stream->close([self{ shared_from_this() }, p = std::move(peer_id_str),
            a = std::move(peer_addr_str)](auto&& res) {
                if (!res) {
                    self->log_->error("cannot close the stream to peer {}, {}: {}", p, a,
                        res.error().message());
                }
            });
        if (local_addr_res.has_error())
        {
            log_->error("DIAL_RESPONSE missing local address from stream. {}", local_addr_res.error().message());
            return;
        }
        if (!msg.dialresponse().has_status()) {
            log_->error("DIAL_RESPONSE missing status. {}", msg.dialresponse().statustext());
            signal_autonat_received_(false);
            return;
        }
        auto response_address = msg.dialresponse().addr();
        auto response_ma = fromStringToMultiaddr(response_address);
        if (response_ma.has_error())
        {
            log_->error("DIAL_RESPONSE bad address. {}", response_ma.error().message());
            return;
        }

        if (msg.dialresponse().status() == autonat::pb::Message::E_DIAL_ERROR)
        {
            log_->info("Address {} has a dial error, this will tally up.", response_ma.value().getStringAddress());
            unsuccessful_addresses_[std::string(response_ma.value().getStringAddress())]++;
        }
        else if (msg.dialresponse().status() == autonat::pb::Message::OK)
        {
            log_->info("Address {} has an OK status, this will tally up.", response_ma.value().getStringAddress());
            successful_addresses_[std::string(response_ma.value().getStringAddress())]++;
        }
        else {
            log_->info("Autonat DIAL_RESPONSE has had an error that does not indicate NAT status: {}", msg.dialresponse().statustext());
            //signal_autonat_received_(false);
        }
        //Record confirmation
        if (successful_addresses_[std::string(response_ma.value().getStringAddress())] >= 4)
        {
            log_->info("Autonat confirming address: {}", response_ma.value().getStringAddress());
            observed_addresses_.confirm(local_addr_res.value(), response_ma.value());
        }
        //Take uncertainty as fact
        if (unsuccessful_addresses_[std::string(response_ma.value().getStringAddress())] >= 4)
        {
            log_->info("Autonat unconfirming address: {}", response_ma.value().getStringAddress());
            observed_addresses_.unconfirm(local_addr_res.value(), response_ma.value());
        }
    }
}

  // namespace libp2p::protocol
