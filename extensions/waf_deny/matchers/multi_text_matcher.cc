#include "extensions/waf_deny/matchers/multi_text_matcher.h"

#include "absl/strings/str_split.h"

#ifdef NULL_PLUGIN

namespace proxy_wasm {
namespace null_plugin {
namespace waf_deny {

#endif

bool MultiTextMatcher::match(const std::string& pattern,
                             const std::string& data) {
  if (pattern.empty()) {
    return false;
  }
  const auto& parts = absl::StrSplit(pattern, ' ');

  for (const auto& part : parts) {
    if (!part.empty() && absl::StrContains(data, part)) {
      return true;
    }
  }
  return false;
}

bool MultiTextMatcher::checkPatternValidity(const std::string& pattern) const {
  return !pattern.empty();
}

#ifdef NULL_PLUGIN

}  // namespace waf_deny
}  // namespace null_plugin
}  // namespace proxy_wasm

#endif
