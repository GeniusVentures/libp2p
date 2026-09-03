#include <libp2p/protocol/autonat/autonat.hpp>

#include <string>
#include <tuple>

#include <boost/assert.hpp>
#include <thread>

namespace {
  const std::string kAutonatProto = "/libp2p/autonat/1.0.0";
}  // namespace

namespace libp2p::protocol {
  Autonat::Autonat(std::shared_ptr<Host> host,
                   std::shared_ptr<AutonatMessageProcessor> msg_processor,
                   event::Bus &event_bus,
                   std::shared_ptr<libp2p::transport::Upgrader> upgrader,
                   CompletionCallback callback)
      : host_{std::move(host)},
        msg_processor_{std::move(msg_processor)},
        bus_{event_bus},
        upgrader_{std::move(upgrader)},
        callback_(std::move(callback)) {
    BOOST_ASSERT(msg_processor_);

    msg_processor_->onAutonatReceived([this](const bool &status) {
      natstatus_ = status;
      if (!status && relay_) {
        log_->info("Starting relay after deciding we are behind a nat");
        if (relay_) {
          relay_->start();
        }
      } else {
        callback_();
      }
      log_->error("Autonat result: {}", status);
      if (!requestautonat_){
        return;}
      log_->info("Starting autonat requests again");
      // Set requestautonat_ to false
      requestautonat_ = false;

      // Create a detached thread that resets requestautonat_ to true after 3
      // minutes
      // Detached thread: hold only a weak_ptr so it cannot touch a destroyed
      // Autonat (the host may be torn down while it sleeps).
      std::thread([wp = weak_from_this()]() {
        for (int i = 0; i < 180; ++i) {
          std::this_thread::sleep_for(std::chrono::seconds(1));
          auto self = wp.lock();
          if (!self || self->should_stop_)
            return;
        }

        auto self = wp.lock();
        if (!self || self->should_stop_)
          return;
        auto *this_ = self.get();

        // Check if we still have valid observed addresses
        if (!this_->hasValidObservedAddresses()) {
          this_->log_->warn(
              "All observed addresses have expired. AutoNAT cannot function "
              "without observed addresses. Stopping AutoNAT operations.");
          // Reset NAT status to unknown state
          this_->natstatus_ = false;
          // Don't restart requests until we get new observed addresses
          this_->requestautonat_ = false;
          return;
        }

        this_->requestautonat_ = true;
        this_->msg_processor_->clearAutoNatTrackers();
      }).detach();
    });
  }

  Autonat::~Autonat() {
    should_stop_ = true;
    started_ = false;
  }

  boost::signals2::connection Autonat::onAutonatReceived(
      const std::function<AutonatMessageProcessor::AutonatCallback> &cb) {
    return msg_processor_->onAutonatReceived(cb);
  }

  std::vector<multi::Multiaddress> Autonat::getAllObservedAddresses() const {
    return msg_processor_->getObservedAddresses().getAllAddresses();
  }

  std::vector<multi::Multiaddress> Autonat::getObservedAddressesFor(
      const multi::Multiaddress &address) const {
    return msg_processor_->getObservedAddresses().getAddressesFor(address);
  }

  bool Autonat::hasValidObservedAddresses() const {
    // Use the host's observed addresses method to get the most reliable
    // addresses
    auto addresses = host_->getObservedAddresses();  // Get observed addresses
    return !addresses.empty();
  }

  void Autonat::setRelay(std::shared_ptr<libp2p::protocol::Relay> relay) {
    relay_ = relay;
  }

  peer::Protocol Autonat::getProtocolId() const {
    return kAutonatProto;
  }

  void Autonat::handle(StreamAndProtocol stream_res) {
    if (!stream_res.stream) {
      return;
    }
    msg_processor_->receiveAutonat(std::move(stream_res.stream));
  }

  void Autonat::start() {
    if (started_)
      return;
    // no double starts
    // BOOST_ASSERT(!started_);
    started_ = true;

    // Start periodic observed address monitoring
    startObservedAddressMonitoring();

    // host_->setProtocolHandler(
    //     kAutonatProto,
    //     [wp =
    //     weak_from_this()](protocol::BaseProtocol::StreamAndProtocolOrError
    //     rstream)
    //     {
    //       if (auto self = wp.lock()) {
    //         self->handle(std::move(rstream));
    //       }
    //     });

    sub_ = bus_.getChannel<event::network::OnNewConnectionChannel>().subscribe(
        [wp = weak_from_this()](auto &&conn) {
          if (auto self = wp.lock()) {
            return self->onNewConnection(conn);
          }
        });
  }

  void Autonat::startObservedAddressMonitoring() {
    // Start a thread that periodically checks observed addresses
    // Detached thread: hold only a weak_ptr so it cannot touch a destroyed
    // Autonat (the host may be torn down while it sleeps).
    std::thread([wp = weak_from_this()]() {
      while (true) {
        for (int i = 0; i < 60; ++i) {
          std::this_thread::sleep_for(std::chrono::seconds(1));
          auto self = wp.lock();
          if (!self || !self->started_ || self->should_stop_)
            return;
        }

        auto self = wp.lock();
        if (!self || !self->started_ || self->should_stop_)
          return;
        // Note: We rely on the host's getObservedAddressesReal() method to
        // handle garbage collection since the message processor's
        // getObservedAddresses() returns a const reference

        // Check if we have any valid observed addresses left
        if (!self->hasValidObservedAddresses() && self->requestautonat_) {
          self->log_->warn(
              "No valid observed addresses available. Stopping AutoNAT "
              "requests until addresses are restored.");
          self->requestautonat_ = false;
          self->natstatus_ = false;
        }
      }
    }).detach();
  }

  void Autonat::onNewConnection(
      const std::weak_ptr<connection::CapableConnection> &conn) {
    // Check if we have any observed addresses to verify before proceeding
    if (!hasValidObservedAddresses()) {
      log_->warn(
          "No observed addresses available to verify. AutoNAT cannot function "
          "without observed addresses.");
      return;
    }

    if (!requestautonat_) {
      log_->info("Not asking for autonat for now");
      return;
    }

    if (conn.expired()) {
      log_->info("Connection expired before requesting autonat");
      return;
    }

    auto remote_peer_res = conn.lock()->remotePeer();
    if (!remote_peer_res) {
      log_->info("Autonat connection has no peer info");
      return;
    }

    auto remote_peer_addr_res = conn.lock()->remoteMultiaddr();
    if (!remote_peer_addr_res) {
      log_->info("Autonat connection has no address");
      return;
    }

    peer::PeerInfo peer_info{std::move(remote_peer_res.value()),
                             std::vector<multi::Multiaddress>{
                                 std::move(remote_peer_addr_res.value())}};

    msg_processor_->getHost().newStream(
        peer_info, {kAutonatProto},
        [self{shared_from_this()}](auto &&stream_res) {
          if (!stream_res) {
            self->log_->error("Failed to create new stream: {}",
                              stream_res.error().message());
            return;
          }
          self->log_->info("Sending Autonat request to peer");
          self->msg_processor_->sendAutonat(stream_res.value().stream);
        });
  }
}  // namespace libp2p::protocol
