#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>
#include <tuple>
#include <vector>

bool cidrMatch(const in_addr &addr, const in_addr &net, uint8_t bits) {
  if (bits == 0) {
    // C99 6.5.7 (3): u32 << 32 is undefined behaviour
    return true;
  }
  return !((addr.s_addr ^ net.s_addr) & htonl(0xFFFFFFFFu << (32 - bits)));
}

int main() {
  std::ifstream file("original_list.txt");  // open the file

  if (!file.is_open()) {  // check if the file was opened successfully
    std::cerr << "Error opening file" << std::endl;
    return 1;
  }

  std::vector<std::tuple<in_addr, uint8_t, std::string>> ip_blacklist;

  std::string line;
  while (std::getline(file, line)) {  // read the file line by line

    in_addr ip;
    size_t slash_pos = line.find('/');

    if (slash_pos == std::string::npos) {
      inet_aton(line.c_str(), &ip);
      ip_blacklist.emplace_back(ip, 32, line);
      continue;
    }

    std::string ip_address = line.substr(0, slash_pos);

    inet_aton(ip_address.c_str(), &ip);

    int subnet_prefix_length = std::stoi(line.substr(slash_pos + 1));
    // std::cout << "ip: " << std::string(inet_ntoa(ip)) << " ";
    // std::cout << "subnet before: " << subnet_prefix_length << " ";
    // std::cout << "subnet:" << static_cast<uint8_t>(subnet_prefix_length) << "
    // "; std::cout << "line: " << line << "\n";
    ip_blacklist.emplace_back(ip, static_cast<uint8_t>(subnet_prefix_length),
                              line);
  }

  std::ifstream file2("requests.txt");

  if (!file2.is_open()) {  // check if the file was opened successfully
    std::cerr << "Error opening file" << std::endl;
    return 1;
  }

  while (std::getline(file2, line)) {
    in_addr ip;
    inet_aton(line.c_str(), &ip);

    bool is_blacklisted = false;
    std::string block_net;
    in_addr block_ip;
    uint8_t block_mask;
    for (auto &blacklisted_ip : ip_blacklist) {
      if (cidrMatch(ip, std::get<0>(blacklisted_ip),
                    std::get<1>(blacklisted_ip))) {
        is_blacklisted = true;
        block_ip = std::get<0>(blacklisted_ip);
        block_mask = std::get<1>(blacklisted_ip);
        block_net = std::get<2>(blacklisted_ip);
        break;
      }
    }

    if (is_blacklisted) {
      // std::cout << line
      //           << " is blocked by ip: " << std::string(inet_ntoa(block_ip))
      //           << "  mask: " << static_cast<unsigned>(block_mask) <<
      //           std::endl;
      std::cout << line << " is blocked by " << block_net << std::endl;
    } else {
      std::cout << line << " is unblock" << std::endl;
    }
  }

  file.close();  // close the file
  file2.close();

  return 0;
}