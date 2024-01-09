#ifndef EXTENSIONS_WAF_DENY_MATCHERS_REGEX_MATCHER_H
#define EXTENSIONS_WAF_DENY_MATCHERS_REGEX_MATCHER_H

#include <memory>

#include "extensions/waf_deny/matchers/basic_matcher.h"

#ifndef NULL_PLUGIN

#include "common/regex.h"
#include "proxy_wasm_intrinsics.h"

#else

#include "include/proxy-wasm/null_plugin.h"

namespace proxy_wasm {
namespace null_plugin {
namespace waf_deny {

#endif

class RegexMatcher : public BasicMatcher {
 public:
  bool match(const std::string& regex_pattern,
             const std::string& data) override;
  bool checkPatternValidity(const std::string&) const override;
  std::string getMatchType() const override { return "regex"; }

 private:
  std::unordered_map<std::string, std::unique_ptr<re2::RE2>> regex_cache;
};

#ifdef NULL_PLUGIN

}  // namespace waf_deny
}  // namespace null_plugin
}  // namespace proxy_wasm

#endif

#endif  // EXTENSIONS_WAF_DENY_MATCHERS_REGEX_MATCHER_H