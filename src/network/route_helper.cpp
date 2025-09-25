/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <libp2p/network/route_helper.hpp>

#include <libp2p/common/logger.hpp>
#include <iostream>
#include <sstream>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#elif defined(__linux__)
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>
#elif defined(__APPLE__)
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <net/route.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#endif

namespace libp2p::network {

  namespace {
    auto &log() {
      static auto logger = log::createLogger("route-helper");
      return *logger;
    }
  }

  outcome::result<RouteHelper::RouteInfo> RouteHelper::getPreferredRoute(const std::string &destination_ip) {
    log().debug("Looking up preferred route for destination: {}", destination_ip);

#ifdef _WIN32
    return getRouteWindows(destination_ip);
#elif defined(__linux__)
    return getRouteLinux(destination_ip);
#elif defined(__APPLE__)
    return getRouteMacOS(destination_ip);
#else
    return getRouteGeneric(destination_ip);
#endif
  }

  outcome::result<multi::Multiaddress> RouteHelper::chooseBestSourceAddress(
      const multi::Multiaddress &destination_multiaddr,
      const std::vector<multi::Multiaddress> &available_listeners) {
    
    log().debug("Choosing best source address for destination: {}", destination_multiaddr.getStringAddress());
    
    // Extract destination IP
    auto destination_ip_result = extractIPFromMultiaddress(destination_multiaddr);
    if (!destination_ip_result) {
      return destination_ip_result.error();
    }
    const auto &destination_ip = destination_ip_result.value();

    // Categorize available listeners
    std::vector<multi::Multiaddress> specific_listeners;
    std::vector<multi::Multiaddress> loopback_listeners;
    std::vector<multi::Multiaddress> unspecified_listeners;

    for (const auto &listener : available_listeners) {
      auto ip_result = extractIPFromMultiaddress(listener);
      if (!ip_result) {
        continue;
      }
      const auto &ip = ip_result.value();

      if (isLoopback(ip)) {
        loopback_listeners.push_back(listener);
        log().debug("Categorized as loopback listener: {}", listener.getStringAddress());
      } else if (isUnspecified(ip)) {
        unspecified_listeners.push_back(listener);
        log().debug("Categorized as unspecified listener: {}", listener.getStringAddress());
      } else {
        specific_listeners.push_back(listener);
        log().debug("Categorized as specific listener: {}", listener.getStringAddress());
      }
    }

    // Strategy 1: Route-based selection (like go-libp2p)
    // If we have specific listeners and destination is not loopback,
    // check if we're listening on the OS-preferred source interface
    if (!specific_listeners.empty() && !isLoopback(destination_ip)) {
      auto route_result = getPreferredRoute(destination_ip);
      if (route_result) {
        const auto &route = route_result.value();
        log().debug("OS prefers source address {} for destination {}", route.source_address, destination_ip);
        
        // Check if we have a listener on the preferred source address
        for (const auto &listener : specific_listeners) {
          auto listener_ip_result = extractIPFromMultiaddress(listener);
          if (listener_ip_result && listener_ip_result.value() == route.source_address) {
            log().info("Selected route-based source address: {} -> {}", 
                      listener.getStringAddress(), destination_multiaddr.getStringAddress());
            return listener;
          }
        }
        log().debug("No listener found on OS-preferred interface {}", route.source_address);
      } else {
        log().debug("Failed to get route info: {}", route_result.error().message());
      }
    }

    // Strategy 2: Loopback matching
    // If destination is loopback and we have loopback listeners
    if (isLoopback(destination_ip) && !loopback_listeners.empty()) {
      const auto &selected = loopback_listeners[0]; // Could randomize like go-libp2p
      log().info("Selected loopback source address: {} -> {}", 
                selected.getStringAddress(), destination_multiaddr.getStringAddress());
      return selected;
    }

    // Strategy 3: Unspecified fallback
    // Use unspecified (0.0.0.0) listeners - let OS pick source interface
    if (!unspecified_listeners.empty()) {
      const auto &selected = unspecified_listeners[0]; // Could randomize like go-libp2p
      log().info("Selected unspecified source address: {} -> {}", 
                selected.getStringAddress(), destination_multiaddr.getStringAddress());
      return selected;
    }

    // Strategy 4: No suitable listener found
    log().warn("No suitable source address found for destination: {}", destination_multiaddr.getStringAddress());
    return std::error_code{static_cast<int>(std::errc::address_not_available), std::system_category()};
  }

#ifdef _WIN32
  outcome::result<RouteHelper::RouteInfo> RouteHelper::getRouteWindows(const std::string &destination_ip) {
    DWORD bestIfIndex = 0;
    DWORD result = GetBestInterface(inet_addr(destination_ip.c_str()), &bestIfIndex);
    
    if (result != NO_ERROR) {
      log().debug("GetBestInterface failed for {}: {}", destination_ip, result);
      return std::error_code{static_cast<int>(std::errc::network_unreachable), std::system_category()};
    }

    // Get interface info
    ULONG bufferSize = 0;
    GetAdaptersAddresses(AF_INET, 0, nullptr, nullptr, &bufferSize);
    
    auto buffer = std::make_unique<char[]>(bufferSize);
    auto addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.get());
    
    result = GetAdaptersAddresses(AF_INET, 0, nullptr, addresses, &bufferSize);
    if (result != NO_ERROR) {
      log().debug("GetAdaptersAddresses failed: {}", result);
      return std::error_code{static_cast<int>(std::errc::network_unreachable), std::system_category()};
    }

    // Find the interface
    for (auto addr = addresses; addr != nullptr; addr = addr->Next) {
      if (addr->IfIndex == bestIfIndex) {
        RouteInfo info;
        info.interface_name = addr->AdapterName;
        info.metric = static_cast<int>(addr->Ipv4Metric);
        
        // Get first unicast address as source
        if (addr->FirstUnicastAddress) {
          auto sockaddr = addr->FirstUnicastAddress->Address.lpSockaddr;
          if (sockaddr->sa_family == AF_INET) {
            auto sin = reinterpret_cast<sockaddr_in*>(sockaddr);
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &sin->sin_addr, ip_str, sizeof(ip_str));
            info.source_address = ip_str;
            
            log().debug("Windows route found: interface={}, source={}, metric={}", 
                       info.interface_name, info.source_address, info.metric);
            return info;
          }
        }
      }
    }
    
    return std::error_code{static_cast<int>(std::errc::network_unreachable), std::system_category()};
  }

#elif defined(__linux__)
  outcome::result<RouteHelper::RouteInfo> RouteHelper::getRouteLinux(const std::string &destination_ip) {
    // Simple implementation using /proc/net/route
    std::ifstream route_file("/proc/net/route");
    if (!route_file.is_open()) {
      log().debug("Failed to open /proc/net/route");
      return std::error_code{static_cast<int>(std::errc::no_such_file_or_directory), std::system_category()};
    }

    std::string line;
    std::getline(route_file, line); // skip header
    
    uint32_t dest_addr = inet_addr(destination_ip.c_str());
    uint32_t best_metric = UINT32_MAX;
    std::string best_interface;
    
    while (std::getline(route_file, line)) {
      std::istringstream iss(line);
      std::string iface, dest_str, gateway_str, flags_str, refcnt_str, use_str, metric_str;
      
      if (iss >> iface >> dest_str >> gateway_str >> flags_str >> refcnt_str >> use_str >> metric_str) {
        uint32_t dest = strtoul(dest_str.c_str(), nullptr, 16);
        uint32_t metric = strtoul(metric_str.c_str(), nullptr, 10);
        
        // Check if this route matches (simple check for default route)
        if ((dest == 0 || (dest_addr & dest) == dest) && metric < best_metric) {
          best_metric = metric;
          best_interface = iface;
        }
      }
    }

    if (best_interface.empty()) {
      return std::error_code{static_cast<int>(std::errc::network_unreachable), std::system_category()};
    }

    // Get interface IP address
    struct ifaddrs *ifaddrs_ptr;
    if (getifaddrs(&ifaddrs_ptr) == -1) {
      return std::error_code{errno, std::system_category()};
    }

    RouteInfo info;
    info.interface_name = best_interface;
    info.metric = static_cast<int>(best_metric);
    
    for (auto ifa = ifaddrs_ptr; ifa != nullptr; ifa = ifa->ifa_next) {
      if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET && 
          std::string(ifa->ifa_name) == best_interface) {
        auto sin = reinterpret_cast<sockaddr_in*>(ifa->ifa_addr);
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sin->sin_addr, ip_str, sizeof(ip_str));
        info.source_address = ip_str;
        break;
      }
    }
    
    freeifaddrs(ifaddrs_ptr);
    
    if (info.source_address.empty()) {
      return std::error_code{static_cast<int>(std::errc::network_unreachable), std::system_category()};
    }
    
    log().debug("Linux route found: interface={}, source={}, metric={}", 
               info.interface_name, info.source_address, info.metric);
    return info;
  }

#elif defined(__APPLE__)
  outcome::result<RouteHelper::RouteInfo> RouteHelper::getRouteMacOS(const std::string &destination_ip) {
    // Simplified implementation - in production, you'd want to use routing socket
    struct ifaddrs *ifaddrs_ptr;
    if (getifaddrs(&ifaddrs_ptr) == -1) {
      return std::error_code{errno, std::system_category()};
    }

    RouteInfo info;
    info.metric = 0;
    
    // Find first non-loopback interface as fallback
    for (auto ifa = ifaddrs_ptr; ifa != nullptr; ifa = ifa->ifa_next) {
      if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET && 
          !(ifa->ifa_flags & IFF_LOOPBACK) && (ifa->ifa_flags & IFF_UP)) {
        auto sin = reinterpret_cast<sockaddr_in*>(ifa->ifa_addr);
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sin->sin_addr, ip_str, sizeof(ip_str));
        info.source_address = ip_str;
        info.interface_name = ifa->ifa_name;
        break;
      }
    }
    
    freeifaddrs(ifaddrs_ptr);
    
    if (info.source_address.empty()) {
      return std::error_code{static_cast<int>(std::errc::network_unreachable), std::system_category()};
    }
    
    log().debug("macOS route found: interface={}, source={}", 
               info.interface_name, info.source_address);
    return info;
  }

#else
  outcome::result<RouteHelper::RouteInfo> RouteHelper::getRouteGeneric(const std::string &destination_ip) {
    log().debug("Generic route lookup not implemented for this platform");
    return std::error_code{static_cast<int>(std::errc::function_not_supported), std::system_category()};
  }
#endif

  outcome::result<std::string> RouteHelper::extractIPFromMultiaddress(const multi::Multiaddress &addr) {
    auto ip4_opt = addr.getFirstValueForProtocol(multi::Protocol::Code::IP4);
    if (ip4_opt) {
      return ip4_opt.value();
    }
    
    auto ip6_opt = addr.getFirstValueForProtocol(multi::Protocol::Code::IP6);
    if (ip6_opt) {
      return ip6_opt.value();
    }
    
    return std::error_code{static_cast<int>(std::errc::invalid_argument), std::system_category()};
  }

  bool RouteHelper::isLoopback(const std::string &ip) {
    return ip.substr(0, 4) == "127." || ip == "::1";
  }

  bool RouteHelper::isUnspecified(const std::string &ip) {
    return ip == "0.0.0.0" || ip == "::";
  }

}  // namespace libp2p::network