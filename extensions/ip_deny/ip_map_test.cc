#include "extensions/ip_deny/ip_map.h"

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <vector>

#ifdef NULL_PLUGIN

using namespace proxy_wasm::null_plugin::ip_deny;

#endif

std::vector<std::pair<std::string, uint8_t>> ipv4_input = {
    {"10.1.1.24", 24},     {"10.1.1.33", 25},     {"10.1.0.193", 26},
    {"192.168.3.192", 26}, {"192.168.3.255", 16}, {"127.0.0.1", 32}};

int main() {
  IPv4Map ipv4_map;

  std::cout << "Before insertion: \n";
  for (size_t i = 0; i < ipv4_input.size(); ++i) {
    ipv4_map.insert(ipv4_input[i].first, ipv4_input[i].second);
    std::cout << ipv4_input[i].first << "/"
              << static_cast<int>(ipv4_input[i].second) << '\n';
  }

  std::cout << "After insertion: \n";
  std::cout << ipv4_map.print() << std::endl;
  return 0;
}