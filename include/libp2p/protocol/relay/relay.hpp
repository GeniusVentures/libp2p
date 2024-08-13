#ifndef LIBP2P_RELAY_HPP
#define LIBP2P_RELAY_HPP
#include <iostream>
#include <libp2p/event/bus.hpp>
#include <libp2p/protocol/base_protocol.hpp>
#include <libp2p/protocol/relay/relay_msg_processor.hpp>
#include <libp2p/protocol/holepunch/holepunch.hpp>

namespace libp2p::multi {
  class Multiaddress;
}

namespace libp2p::protocol {
  /**
   * Implementation of an autonat protocol, which is a way to say
   * determine whether or not we are behind a nat, and get a valid address in return.
   * Read more: https://github.com/libp2p/specs/tree/master/autonat
   */
  class Relay : public BaseProtocol,
                   public std::enable_shared_from_this<Relay> {
   public:
    /**
     * Create an Auto instance; it will immediately start watching
     * connection events and react to them
     * @param msg_processor to work with Autonat messages
     * @param event_bus - bus, over which the events arrive
     */
    Relay(Host &host,
             std::shared_ptr<RelayMessageProcessor> msg_processor,
             event::Bus &event_bus);

    ~Relay() override = default;

    boost::signals2::connection onRelayReceived(
        const std::function<RelayMessageProcessor::RelayCallback> &cb);

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
     * In Relay we onl really expect a stop message, but I would expect a separate helper if we wanted to be a relay.
     */
    void handle(StreamResult stream_res) override;

    void handleStopMessage(StreamResult stream_res);
    
    
    /**
     * Start accepting NewConnectionEvent-s and asking each of them for Autonat
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
    std::shared_ptr<RelayMessageProcessor> msg_processor_;
    event::Bus &bus_;
    event::Handle sub_;  // will unsubscribe during destruction by itself
    std::shared_ptr<libp2p::protocol::Holepunch> holepunch_;
    std::shared_ptr<libp2p::protocol::HolepunchMessageProcessor> holepunchmsg_proc_;
    log::Logger log_ = log::createLogger("Relay");
    int maxrelays = 3;
    int relayconnections;

    bool started_ = false;
  };
}



#endif