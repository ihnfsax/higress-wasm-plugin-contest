#ifndef EXTENSIONS_WAF_DENY_MATCHERS_MULTI_TEXT_MATCHER_H
#define EXTENSIONS_WAF_DENY_MATCHERS_MULTI_TEXT_MATCHER_H

#include "extensions/waf_deny/matchers/basic_matcher.h"

#ifndef NULL_PLUGIN

#include "proxy_wasm_intrinsics.h"

#else

#include "include/proxy-wasm/null_plugin.h"

namespace proxy_wasm {
namespace null_plugin {
namespace waf_deny {

#endif

class MultiTextMatcher : public BasicMatcher {
 public:
  bool match(const std::string& pattern, const std::string& data) override;
  bool checkPatternValidity(const std::string&) const override;
  std::string getMatchType() const override { return "multi-text"; }
};

#ifdef NULL_PLUGIN

}  // namespace waf_deny
}  // namespace null_plugin
}  // namespace proxy_wasm

#endif

#endif  // EXTENSIONS_WAF_DENY_MATCHERS_MULTI_TEXT_MATCHER_H