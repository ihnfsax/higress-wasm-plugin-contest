#ifndef EXTENSIONS_WAF_DENY_MATCHERS_BASIC_MATCHER_H
#define EXTENSIONS_WAF_DENY_MATCHERS_BASIC_MATCHER_H

#include <string>

#ifdef NULL_PLUGIN

namespace proxy_wasm {
namespace null_plugin {
namespace waf_deny {

#endif

class BasicMatcher {
 public:
  virtual ~BasicMatcher() = default;
  virtual bool match(const std::string& pattern, const std::string& data) = 0;
  virtual bool checkPatternValidity(const std::string&) const = 0;
  virtual std::string getMatchType() const = 0;
};

#ifdef NULL_PLUGIN

}  // namespace waf_deny
}  // namespace null_plugin
}  // namespace proxy_wasm

#endif

#endif  // EXTENSIONS_WAF_DENY_MATCHERS_BASIC_MATCHER_H