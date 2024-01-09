#ifndef EXTENSIONS_IP_DENY_IP_MAP_H
#define EXTENSIONS_IP_DENY_IP_MAP_H

#include <cstdint>
#include <map>
#include <string>

#include "absl/numeric/int128.h"

#ifdef NULL_PLUGIN

namespace proxy_wasm {
namespace null_plugin {
namespace ip_deny {

#endif

class IPv4Map {
 public:
  /// \return True if insertion failed. False if insertion succeeded.
  bool insert(const std::string& ip_str, uint8_t mask);

  /// \return True if ip is in map. False if ip is not in map, or ip is invalid.
  bool lookup(const std::string& ip_str) const;

  std::map<uint32_t, uint32_t>::size_type size() { return ip_map.size(); }

  std::string print();

  std::map<uint32_t, uint32_t> ip_map;
};

#ifdef NULL_PLUGIN

}  // namespace ip_deny
}  // namespace null_plugin
}  // namespace proxy_wasm

#endif

#endif  // EXTENSIONS_IP_DENY_IP_MAP_H