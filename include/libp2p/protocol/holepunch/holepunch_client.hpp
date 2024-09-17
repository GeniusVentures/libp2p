#ifndef LIBP2P_HolepunchClient_CLIENT_HPP
#define LIBP2P_HolepunchClient_CLIENT_HPP
#include <iostream>
#include <libp2p/event/bus.hpp>
#include <libp2p/protocol/base_protocol.hpp>
#include <libp2p/protocol/holepunch/holepunch_client_msg_processor.hpp>

namespace libp2p::multi {
  class Multiaddress;
}

namespace libp2p::protocol {
  /**
   * Implementation of an HolepunchClient protocol, which is a way to 
   * Initiate a connection from behind a nat be connecting at the same time using an observed address.
   * Read more: https://github.com/libp2p/specs/blob/master/relay/DCUtR.md
   */
  class HolepunchClient : public BaseProtocol,
                   public std::enable_shared_from_this<HolepunchClient> {
      using StreamSPtr = std::shared_ptr<connection::Stream>;
   public:
    /**
     * Create an Auto instance; it will immediately start watching
     * connection events and react to them
     * @param msg_processor to work with HolepunchClient messages
     * @param event_bus - bus, over which the events arrive
     */
    HolepunchClient(Host &host,
             std::shared_ptr<HolepunchClientMsgProc> msg_processor,
             event::Bus &event_bus);

    ~HolepunchClient() override = default;

    boost::signals2::connection onHolepunchClientReceived(
        const std::function<HolepunchClientMsgProc::HolepunchCallback> &cb);

    /**
     * Get addresses other peers reported we have dialed from
     * @return set of addresses
     */
    //std::vector<multi::Multiaddress> getAllObservedAddresses() const;

    /**
     * Get addresses other peers reported we have dialed from, when they
     * provided a (\param address)
     * @param address, for which to retrieve observed addresses
     * @return set of addresses
     */
    //std::vector<multi::Multiaddress> getObservedAddressesFor(
    //    const multi::Multiaddress &address) const;

    peer::Protocol getProtocolId() const override;

    /**
     * If we get a HolepunchClient CONNECT message, someone is trying to initiate a HolepunchClient with us via a circuit relay
     * This handler sends this to message processor
     */
    void handle(StreamResult stream_res) override;

    /**
     * We only create a protocol handler here accepting HolepunchClient dcutr.
     */
    void start();


   private:
    /**
     * Handler for new connections, established by or with our host
     * @param conn - new connection
     */
    void onNewConnection(
        const std::weak_ptr<connection::CapableConnection> &conn,
        std::vector<libp2p::multi::Multiaddress> obsaddr);

    Host &host_;
    std::shared_ptr<HolepunchClientMsgProc> msg_processor_;
    event::Bus &bus_;
    event::Handle sub_;  // will unsubscribe during destruction by itself
    bool natstatus_ = false; //False if we are behind a NAT, true if not.
    log::Logger log_ = log::createLogger("HolepunchClient");

    bool started_ = false;
  };
}



#endif