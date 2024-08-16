/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LIBP2P_RELAY_ADDRESSES_HPP
#define LIBP2P_RELAY_ADDRESSES_HPP

#include <chrono>
#include <unordered_map>
#include <vector>
#include <iostream>

#include <libp2p/multi/multiaddress.hpp>
#include <libp2p/peer/address_repository.hpp>

namespace libp2p::protocol {

  /**
   * Smart storage of mappings of our relay addresses that expires if not updated.
   */
  class RelayAddresses {
    using Clock = std::chrono::steady_clock;
    using Milliseconds = std::chrono::milliseconds;

   public:
       RelayAddresses()
           : relay_addresses_()
       {
           std::cout << "Initialized relay addresses" << std::endl;
       }
    /**
     * Get a set of addresses, associated with a specific address for relays
     * @param address, for which the mapping is to be extracted
     * @return set of addresses
     */
    std::vector<multi::Multiaddress> getAddressesFor(
        const multi::Multiaddress &address) const;

    /**
     * Get all addresses we have relay through
     * @return the addresses
     */
    std::vector<multi::Multiaddress> getAllAddresses() const;

    /**
     * Add an address, which has been reserved
     * @param observed - the observed address itself
     * @param local - address, which the remote peer thought it connects to
     * @param observer - address of the remote peer, which observed the (\param
     * observed) address
     * @param is_initiator - was the remote peer an initiator of the connection?
     */
    void add(multi::Multiaddress observed, multi::Multiaddress local,
        uint64_t expiration);

    /**
     * Get rid of expired addresses; should be called from time to time
     */
    void collectGarbage();

   private:
    struct RelayAddress {
      multi::Multiaddress address;
      uint64_t expiration;
    };

    std::unordered_map<multi::Multiaddress, std::vector<RelayAddress>>
        relay_addresses_;
  };
}  // namespace libp2p::protocol

#endif  // LIBP2P_RELAY_ADDRESSES_HPP
