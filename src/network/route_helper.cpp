/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <libp2p/network/route_helper.hpp>

#include <libp2p/log/logger.hpp>
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

    // Strategy 3: Unspecified fallback with route-based IP selection
    // For unspecified (0.0.0.0) listeners, get the OS-preferred source IP 
    // and construct a specific address using the listener's port
    if (!unspecified_listeners.empty()) {
      // Check IP version compatibility first
      bool destination_is_ipv6 = destination_ip.find(':') != std::string::npos;
      bool have_ipv4_listeners = false;
      bool have_ipv6_listeners = false;
      
      for (const auto &listener : unspecified_listeners) {
        auto listener_ip = extractIPFromMultiaddress(listener);
        if (listener_ip) {
          if (listener_ip.value().find(':') != std::string::npos) {
            have_ipv6_listeners = true;
          } else {
            have_ipv4_listeners = true;
          }
        }
      }
      
      // If we have IPv6 destination but only IPv4 listeners, skip route lookup
      if (destination_is_ipv6 && !have_ipv6_listeners) {
        log().debug("IPv6 destination {} but only IPv4 listeners available, skipping route lookup", destination_ip);
        const auto &selected = unspecified_listeners[0];
        log().warn("IP version mismatch, falling back to unspecified source address: {} -> {}", 
                  selected.getStringAddress(), destination_multiaddr.getStringAddress());
        return selected;
      }
      
      // Get the OS-preferred route for this destination
      auto route_result = getPreferredRoute(destination_ip);
      if (route_result) {
        const auto &route = route_result.value();
        log().debug("OS prefers source address {} for destination {} (unspecified listener case)", 
                   route.source_address, destination_ip);
        
        // Find a compatible unspecified listener (matching IP version)
        for (const auto &unspecified_listener : unspecified_listeners) {
          auto port_opt = unspecified_listener.getFirstValueForProtocol(multi::Protocol::Code::TCP);
          if (!port_opt) continue;
          
          // Check if this listener is compatible with the route IP version
          bool route_is_ipv6 = route.source_address.find(':') != std::string::npos;
          auto listener_ip = extractIPFromMultiaddress(unspecified_listener);
          bool listener_is_ipv6 = listener_ip && listener_ip.value().find(':') != std::string::npos;
          
          if (route_is_ipv6 == listener_is_ipv6) {
            // Construct a specific multiaddress with the route-preferred IP and listener port
            std::string protocol = route_is_ipv6 ? "ip6" : "ip4";
            auto specific_addr_result = multi::Multiaddress::create(
                "/" + protocol + "/" + route.source_address + "/tcp/" + port_opt.value());
            if (specific_addr_result) {
              auto specific_addr = specific_addr_result.value();
              log().info("Selected route-based specific address: {} -> {} (derived from unspecified listener)", 
                        specific_addr.getStringAddress(), destination_multiaddr.getStringAddress());
              return specific_addr;
            } else {
              log().debug("Failed to create specific multiaddress from route IP");
            }
          }
        }
      } else {
        log().debug("Failed to get route info for unspecified listener: {}", route_result.error().message());
      }
      
      // Fallback to original unspecified behavior if route lookup fails
      const auto &selected = unspecified_listeners[0];
      log().warn("Route lookup failed, falling back to unspecified source address: {} -> {}", 
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
    // Determine if this is IPv4 or IPv6
    bool is_ipv6 = destination_ip.find(':') != std::string::npos;
    
    // First try to read routing table files (may fail on Android due to permissions)
    const char* route_file_path = is_ipv6 ? "/proc/net/ipv6_route" : "/proc/net/route";
    std::ifstream route_file(route_file_path);
    bool proc_accessible = route_file.is_open();
    
    if (proc_accessible && !is_ipv6) {
      // IPv4 routing table parsing (original method)
      log().debug("Using /proc/net/route for IPv4 route lookup");
      
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
      
      if (!best_interface.empty()) {
        // Get interface IP address
        struct ifaddrs *ifaddrs_ptr;
        if (getifaddrs(&ifaddrs_ptr) == 0) {
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
          
          if (!info.source_address.empty()) {
            log().debug("Linux IPv4 route found: interface={}, source={}, metric={}", 
                       info.interface_name, info.source_address, info.metric);
            return info;
          }
        }
      }
    }
    
    // Fallback method for Android or when proc files aren't accessible
    log().debug("Proc routing files not accessible (Android?), using interface fallback method");
    
    struct ifaddrs *ifaddrs_ptr;
    if (getifaddrs(&ifaddrs_ptr) == -1) {
      log().debug("getifaddrs failed: {}", strerror(errno));
      return std::error_code{errno, std::system_category()};
    }

    RouteInfo info;
    info.interface_name = "default";
    info.metric = 0;
    
    // Android/fallback strategy: Find best available interface
    // Priority: WiFi > cellular/mobile > ethernet > other
    std::string wifi_ip, cellular_ip, ethernet_ip, other_ip;
    std::string wifi_if, cellular_if, ethernet_if, other_if;
    
    for (auto ifa = ifaddrs_ptr; ifa != nullptr; ifa = ifa->ifa_next) {
      if (!ifa->ifa_addr || !(ifa->ifa_flags & IFF_UP) || (ifa->ifa_flags & IFF_LOOPBACK)) {
        continue;
      }
      
      bool addr_matches_version = (is_ipv6 && ifa->ifa_addr->sa_family == AF_INET6) ||
                                 (!is_ipv6 && ifa->ifa_addr->sa_family == AF_INET);
      
      if (!addr_matches_version) continue;
      
      char ip_str[INET6_ADDRSTRLEN];
      if (is_ipv6) {
        auto sin6 = reinterpret_cast<sockaddr_in6*>(ifa->ifa_addr);
        inet_ntop(AF_INET6, &sin6->sin6_addr, ip_str, sizeof(ip_str));
        // Skip link-local IPv6 addresses
        if (strncmp(ip_str, "fe80:", 5) == 0) continue;
      } else {
        auto sin = reinterpret_cast<sockaddr_in*>(ifa->ifa_addr);
        inet_ntop(AF_INET, &sin->sin_addr, ip_str, sizeof(ip_str));
      }
      
      std::string if_name = ifa->ifa_name;
      log().debug("Found interface: {} with IP: {}", if_name, ip_str);
      
      // Interface priority detection (Android naming patterns)
      if (if_name.find("wlan") == 0 || if_name.find("wifi") != std::string::npos) {
        // WiFi interface (highest priority)
        if (wifi_ip.empty()) {
          wifi_ip = ip_str;
          wifi_if = if_name;
        }
      } else if (if_name.find("rmnet") == 0 || if_name.find("ccmni") == 0 || 
                 if_name.find("pdp") == 0 || if_name.find("ppp") == 0 ||
                 if_name.find("mobile") != std::string::npos) {
        // Cellular interface (medium priority)
        if (cellular_ip.empty()) {
          cellular_ip = ip_str;
          cellular_if = if_name;
        }
      } else if (if_name.find("eth") == 0) {
        // Ethernet (low priority)
        if (ethernet_ip.empty()) {
          ethernet_ip = ip_str;
          ethernet_if = if_name;
        }
      } else {
        // Other interfaces (lowest priority)
        if (other_ip.empty()) {
          other_ip = ip_str;
          other_if = if_name;
        }
      }
    }
    
    freeifaddrs(ifaddrs_ptr);
    
    // Select interface by priority: WiFi > Cellular > Ethernet > Other
    if (!wifi_ip.empty()) {
      info.source_address = wifi_ip;
      info.interface_name = wifi_if;
      info.metric = 10; // WiFi gets best metric
    } else if (!cellular_ip.empty()) {
      info.source_address = cellular_ip;
      info.interface_name = cellular_if;
      info.metric = 20; // Cellular gets higher metric
    } else if (!ethernet_ip.empty()) {
      info.source_address = ethernet_ip;
      info.interface_name = ethernet_if;
      info.metric = 30;
    } else if (!other_ip.empty()) {
      info.source_address = other_ip;
      info.interface_name = other_if;
      info.metric = 40;
    }
    
    if (info.source_address.empty()) {
      log().debug("No suitable {} address found on any interface", is_ipv6 ? "IPv6" : "IPv4");
      return std::error_code{static_cast<int>(std::errc::network_unreachable), std::system_category()};
    }
    
    log().debug("Android fallback route found: interface={}, source={}, metric={} ({})", 
               info.interface_name, info.source_address, info.metric,
               info.metric == 10 ? "WiFi" : info.metric == 20 ? "Cellular" : "Other");
    return info;
  }
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