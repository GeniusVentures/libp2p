/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <libp2p/protocol/relay/relay_addresses.hpp>

#include <algorithm>

namespace libp2p::protocol {
  std::vector<multi::Multiaddress> RelayAddresses::getAddressesFor(
      const multi::Multiaddress &address) const {
    std::vector<multi::Multiaddress> result;

    auto addr_entry_it = relay_addresses_.find(address);
    if (addr_entry_it == relay_addresses_.end()) {
      return result;
    }

    auto now = Clock::now();
    for (const auto &addr : addr_entry_it->second) {
        result.push_back(addr.address);
    }

    return result;
  }

  std::vector<multi::Multiaddress> RelayAddresses::getAllAddresses() const {
    std::vector<multi::Multiaddress> result;

    for (const auto &it : relay_addresses_) {
      auto addresses = getAddressesFor(it.first);
      result.insert(result.end(), std::make_move_iterator(addresses.begin()),
                    std::make_move_iterator(addresses.end()));
    }

    return result;
  }

  void RelayAddresses::add(multi::Multiaddress address,
      multi::Multiaddress local,                       
      uint64_t expiration) {

      auto local_addr_entry = relay_addresses_.find(local);
      if (local_addr_entry == relay_addresses_.end()) {
          // this is the first time somebody was connecting to this local address
          local_addr_entry =
              relay_addresses_
              .emplace(std::make_pair(std::move(local),
                                      std::vector<RelayAddress>()))
              .first;
      }

      auto &addresses = local_addr_entry->second;
      auto observed_addr_it =
          std::find_if(addresses.begin(), addresses.end(),
                     [&address](const auto &observed_addr) {
                       return observed_addr.address == address;
                     });
    
      if (observed_addr_it == addresses.end()) {
          //This address has not been recorded
          addresses.push_back(
              RelayAddress{std::move(address), expiration});
          return;
      }

      // update the address observation
      observed_addr_it->expiration = expiration;
  }

  void RelayAddresses::collectGarbage() {
      uint64_t now = std::chrono::seconds(std::time(nullptr)).count();

      for (auto& addr_entry : relay_addresses_) {
          auto& relay_vec = addr_entry.second;

          // Remove expired addresses from the vector
          relay_vec.erase(
              std::remove_if(relay_vec.begin(), relay_vec.end(),
                  [now](const RelayAddress& relay_address) {
                      return relay_address.expiration < now;
                  }),
              relay_vec.end()
          );

          //Remove the Multiaddress from the map if the vector is empty
          if (relay_vec.empty()) {
              relay_addresses_.erase(addr_entry.first);
          }
      }
  }
}  // namespace libp2p::protocol
