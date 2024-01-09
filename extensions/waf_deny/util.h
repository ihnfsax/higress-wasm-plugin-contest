#ifndef EXTENSIONS_WAF_DENY_UTIL_H
#define EXTENSIONS_WAF_DENY_UTIL_H

#ifdef NULL_PLUGIN

namespace proxy_wasm {
namespace null_plugin {
namespace waf_deny {

#endif

#include <string>
#include <utility>
#include <vector>

std::pair<std::string, std::string> splitFirst(const std::string&, char);
std::pair<std::string, std::string> splitLast(const std::string&, char);
std::string standardize(const std::string&);

#ifdef NULL_PLUGIN

}  // namespace waf_deny
}  // namespace null_plugin
}  // namespace proxy_wasm

#endif

#endif  // EXTENSIONS_WAF_DENY_UTIL_H