#include "extensions/waf_deny/matchers/text_matcher.h"

#include "absl/strings/match.h"

#ifdef NULL_PLUGIN

namespace proxy_wasm {
namespace null_plugin {
namespace waf_deny {

#endif

bool TextMatcher::match(const std::string& pattern, const std::string& data) {
  if (pattern.empty()) {
    return false;
  }
  if (absl::StrContains(data, pattern)) {
    return true;
  }
  return false;
}

bool TextMatcher::checkPatternValidity(const std::string& pattern) const {
  return !pattern.empty();
}

#ifdef NULL_PLUGIN

}  // namespace waf_deny
}  // namespace null_plugin
}  // namespace proxy_wasm

#endif
