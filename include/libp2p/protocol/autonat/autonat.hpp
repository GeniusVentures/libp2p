#ifndef LIBP2P_AUTONAT_HPP
#define LIBP2P_AUTONAT_HPP
#include <generated/protocol/autonat/protobuf/autonat.pb.h>
#include <boost/assert.hpp>
#include <libp2p/basic/protobuf_message_read_writer.hpp>
#include <libp2p/network/network.hpp>
#include <libp2p/peer/address_repository.hpp>
#include <libp2p/protocol/identify/utils.hpp>
#include <iostream>

namespace libp2p::multi {
  class Multiaddress;
}

namespace libp2p::protocol {
  /**
   * Implementation of an autonat protocol, which is a way to say
   * determine whether or not we are behind a nat, and get a valid address in return.
   * Read more: https://github.com/libp2p/specs/tree/master/autonat
   */
  class Autonat : public BaseProtocol,
                   public std::enable_shared_from_this<Autonat> {
   public:
    /**
     * Create an Auto instance; it will immediately start watching
     * connection events and react to them
     * @param msg_processor to work with Identify messages
     * @param event_bus - bus, over which the events arrive
     */
    Autonat(Host &host,
             std::shared_ptr<IdentifyMessageProcessor> msg_processor,
             event::Bus &event_bus);

    ~Autonat() override = default;

    boost::signals2::connection onAutonatReceived(
        const std::function<IdentifyMessageProcessor::IdentifyCallback> &cb);

    /**
     * Get addresses other peers reported we have dialed from
     * @return set of addresses
     */
    std::vector<multi::Multiaddress> getAllObservedAddresses() const;

    /**
     * Get addresses other peers reported we have dialed from, when they
     * provided a (\param address)
     * @param address, for which to retrieve observed addresses
     * @return set of addresses
     */
    std::vector<multi::Multiaddress> getObservedAddressesFor(
        const multi::Multiaddress &address) const;

    peer::Protocol getProtocolId() const override;

    /**
     * In Identify, handle means we are being identified by the other peer, so
     * we are expected to send the Identify message
     */
    void handle(StreamResult stream_res) override;

    /**
     * Start accepting NewConnectionEvent-s and asking each of them for Identify
     */
    void start();

   private:
    /**
     * Handler for new connections, established by or with our host
     * @param conn - new connection
     */
    void onNewConnection(
        const std::weak_ptr<connection::CapableConnection> &conn);

    Host &host_;
    std::shared_ptr<IdentifyMessageProcessor> msg_processor_;
    event::Bus &bus_;
    event::Handle sub_;  // will unsubscribe during destruction by itself

    bool started_ = false;
  };
}



#endif