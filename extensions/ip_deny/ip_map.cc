#include "extensions/ip_deny/ip_map.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <cstdint>

#ifdef NULL_PLUGIN

namespace proxy_wasm {
namespace null_plugin {
namespace ip_deny {

#endif

bool IPv4Map::insert(const std::string& ip_str, uint8_t mask) {
  uint32_t ip_int, mask_int;
  struct in_addr addr_struct;
  bool insert_flag = false;

  if (mask == 0) {
    ip_map.clear();
    ip_map.emplace(0, UINT32_MAX);
    return false;
  }

  if (mask > 32) {
    return true;
  }
  mask_int = (1 << (32 - mask)) - 1;

  if (inet_aton(ip_str.c_str(), &addr_struct) == 0) {
    return true;
  }
  ip_int = ntohl(addr_struct.s_addr);
  ip_int = ip_int & (0xFFFFFFFFu << (32 - mask));

  while (true) {
    auto it = ip_map.lower_bound(ip_int);
    // try to merge the larger one
    if (it != ip_map.end()) {
      if (static_cast<uint64_t>(ip_int) + mask_int + 1 >= it->first) {
        if (ip_int < it->first || ip_int + mask_int > it->first + it->second) {
          // can merge the larger one
          // When ip_int equals to it->first, we can only update it->second.
          // But we still erase it, in case that the inserted one can merge
          // more.
          uint32_t new_ip_end =
              std::max(ip_int + mask_int, it->first + it->second);
          mask_int = new_ip_end - ip_int;
          ip_map.erase(it);
          continue;
        } else {
          // no need to insert
          break;
        }
      }
    }
    // try to merge the smaller one
    if (it != ip_map.begin()) {
      --it;
      if (static_cast<uint64_t>(it->first) + it->second + 1 >= ip_int) {
        if (ip_int + mask_int > it->first + it->second) {
          // can merge the smaller one
          mask_int = ip_int + mask_int - it->first;
          ip_int = it->first;
          ip_map.erase(it);
          continue;
        } else {
          // no need to insert
          break;
        }
      }
    }
    // can insert
    insert_flag = true;
    break;
  }

  if (insert_flag) {
    ip_map.emplace(ip_int, mask_int);
  }

  return false;
}

bool IPv4Map::lookup(const std::string& ip_str) const {
  uint32_t ip_int;
  struct in_addr addr_struct;

  if (inet_aton(ip_str.c_str(), &addr_struct) == 0) {
    return false;
  }
  ip_int = ntohl(addr_struct.s_addr);

  auto it = ip_map.lower_bound(ip_int);
  if (it != ip_map.end()) {
    if (ip_int >= it->first && ip_int <= it->first + it->second) {
      return true;
    }
  }
  if (it != ip_map.begin()) {
    --it;
    if (ip_int >= it->first && ip_int <= it->first + it->second) {
      return true;
    }
  }
  return false;
}

std::string IPv4Map::print() {
  std::string ret;
  for (auto it = ip_map.begin(); it != ip_map.end(); ++it) {
    uint32_t ip_int = it->first;
    uint32_t mask_int = it->second;
    struct in_addr addr_struct;
    std::string ip_start_str, ip_end_str;

    addr_struct.s_addr = htonl(ip_int);
    ip_start_str = inet_ntoa(addr_struct);
    addr_struct.s_addr = htonl(ip_int + mask_int);
    ip_end_str = inet_ntoa(addr_struct);

    ret += ip_start_str + " - " + ip_end_str + "\n";
  }
  return ret;
}

#ifdef NULL_PLUGIN

}  // namespace ip_deny
}  // namespace null_plugin
}  // namespace proxy_wasm

#endif