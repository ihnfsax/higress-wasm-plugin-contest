#include "extensions/waf_deny/matchers/file_text_matcher.h"

#include <sstream>

#include "absl/strings/ascii.h"
#include "absl/strings/match.h"
#include "extensions/waf_deny/static_rules.h"

#ifdef NULL_PLUGIN

namespace proxy_wasm {
namespace null_plugin {
namespace waf_deny {

#endif

bool FileTextMatcher::match(const std::string& filename,
                            const std::string& data) {
  std::string std_filename(absl::StripAsciiWhitespace(filename));
  auto iter = rule_data.find(std_filename);
  if (iter == rule_data.end()) {
    LOG_WARN("file not found: " + std_filename);
    return false;
  }
  std::istringstream iss(iter->second);
  for (std::string line; std::getline(iss, line);) {
    if (line.empty()) {
      continue;
    }
    if (absl::StrContains(data, line)) {
      return true;
    }
  }
  return false;
}

bool FileTextMatcher::checkPatternValidity(const std::string& pattern) const {
  std::string std_filename(absl::StripAsciiWhitespace(pattern));
  if (rule_data.find(std_filename) == rule_data.end()) {
    LOG_WARN("file not found: " + std_filename);
    return false;
  }
  return true;
}

#ifdef NULL_PLUGIN

}  // namespace waf_deny
}  // namespace null_plugin
}  // namespace proxy_wasm

#endif
