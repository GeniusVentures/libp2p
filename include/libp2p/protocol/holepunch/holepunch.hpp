#ifndef LIBP2P_HOLEPUNCH_HPP
#define LIBP2P_HOLEPUNCH_HPP
#include <iostream>
#include <libp2p/event/bus.hpp>
#include <libp2p/protocol/base_protocol.hpp>
#include <libp2p/protocol/holepunch/holepunch_msg_processor.hpp>

namespace libp2p::multi {
  class Multiaddress;
}

namespace libp2p::protocol {
  /**
   * Implementation of an holepunch protocol, which is a way to 
   * Initiate a connection from behind a nat be connecting at the same time using an observed address.
   * Read more: https://github.com/libp2p/specs/blob/master/relay/DCUtR.md
   */
  class Holepunch : public BaseProtocol,
                   public std::enable_shared_from_this<Holepunch> {
      using StreamSPtr = std::shared_ptr<connection::Stream>;
   public:
    /**
     * Create an Auto instance; it will immediately start watching
     * connection events and react to them
     * @param msg_processor to work with Holepunch messages
     * @param event_bus - bus, over which the events arrive
     */
    Holepunch(Host &host,
             std::shared_ptr<HolepunchMessageProcessor> msg_processor,
             event::Bus &event_bus);

    ~Holepunch() override = default;

    boost::signals2::connection onHolepunchReceived(
        const std::function<HolepunchMessageProcessor::HolepunchCallback> &cb);

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
     * If we get a holepunch CONNECT message, someone is trying to initiate a holepunch with us via a circuit relay
     * This handler sends this to message processor
     */
    void handle(StreamResult stream_res) override;

    /**
     * We only create a protocol handler here accepting holepunch dcutr.
     */
    void start();

    /**
     * Initiate a holepunch connection to another node
     */
    void initiateHolePunch(StreamSPtr stream, peer::PeerId peer_id);

   private:
    /**
     * Handler for new connections, established by or with our host
     * @param conn - new connection
     */
    void onNewConnection(
        const std::weak_ptr<connection::CapableConnection> &conn,
        std::vector<libp2p::multi::Multiaddress> obsaddr);

    Host &host_;
    std::shared_ptr<HolepunchMessageProcessor> msg_processor_;
    event::Bus &bus_;
    event::Handle sub_;  // will unsubscribe during destruction by itself
    bool natstatus_ = false; //False if we are behind a NAT, true if not.
    log::Logger log_ = log::createLogger("Holepunch");

    bool started_ = false;
  };
}



#endif