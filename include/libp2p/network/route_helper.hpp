/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <libp2p/multi/multiaddress.hpp>
#include <libp2p/outcome/outcome.hpp>
#include <string>
#include <vector>

namespace libp2p::network {

  /**
   * RouteHelper provides OS routing table integration for intelligent 
   * source interface selection, similar to go-libp2p's netroute package.
   * 
   * This helps choose the best source interface for outbound connections,
   * automatically preferring WiFi over cellular based on OS routing priorities.
   */
  class RouteHelper {
   public:
    struct RouteInfo {
      std::string interface_name;     ///< Network interface name (e.g., "wlan0", "eth0")
      std::string source_address;     ///< Preferred source IP address
      std::string gateway_address;    ///< Gateway IP address
      int metric;                     ///< Route metric (lower = preferred)
    };

    struct SourceAddresses {
      multi::Multiaddress ipv4_source;  ///< IPv4 source address (may be empty)
      multi::Multiaddress ipv6_source;  ///< IPv6 source address (may be empty)
      bool has_ipv4 = false;
      bool has_ipv6 = false;
    };

    /**
     * Get the preferred source address for reaching a destination.
     * This queries the OS routing table to determine which interface
     * the OS would naturally use for this destination.
     * 
     * @param destination_ip Target IP address
     * @return RouteInfo with preferred source interface details
     */
    static outcome::result<RouteInfo> getPreferredRoute(const std::string &destination_ip);

    /**
     * Get both IPv4 and IPv6 source addresses for outbound connections.
     * Returns the best available source addresses for both IP versions,
     * allowing the connection layer to choose based on destination.
     * 
     * @param available_listeners List of addresses we're currently listening on
     * @return SourceAddresses with IPv4 and/or IPv6 source addresses
     */
    static SourceAddresses getBestSourceAddresses(const std::vector<multi::Multiaddress> &available_listeners);

    /**
     * Choose the best source address for dialing to a destination.
     * Implements go-libp2p's 3-tier selection strategy:
     * 1. Route-based: Use OS-preferred interface if we're listening on it
     * 2. Fallback: Use unspecified (0.0.0.0) listeners 
     * 3. System pick: Let OS choose completely
     * 
     * @param destination_multiaddr Target multiaddress to connect to
     * @param available_listeners List of addresses we're currently listening on
     * @return Best source multiaddress to use for the connection
     */
    static outcome::result<multi::Multiaddress> chooseBestSourceAddress(
        const multi::Multiaddress &destination_multiaddr,
        const std::vector<multi::Multiaddress> &available_listeners);

    /**
     * Extract IP address from multiaddress
     */
    static outcome::result<std::string> extractIPFromMultiaddress(
        const multi::Multiaddress &addr);

   private:
    /**
     * Platform-specific routing table query implementation
     */
#ifdef _WIN32
    static outcome::result<RouteInfo> getRouteWindows(const std::string &destination_ip);
#elif defined(__linux__)
    static outcome::result<RouteInfo> getRouteLinux(const std::string &destination_ip);
#elif defined(__APPLE__)
    static outcome::result<RouteInfo> getRouteMacOS(const std::string &destination_ip);
#else
    static outcome::result<RouteInfo> getRouteGeneric(const std::string &destination_ip);
#endif

    /**
     * Check if an IP address is loopback
     */
    static bool isLoopback(const std::string &ip);

    /**
     * Check if an IP address is unspecified (0.0.0.0 or ::)
     */
    static bool isUnspecified(const std::string &ip);
  };

}  // namespace libp2p::network