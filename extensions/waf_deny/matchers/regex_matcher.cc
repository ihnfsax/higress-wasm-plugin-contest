#include "extensions/waf_deny/matchers/regex_matcher.h"

#include <memory>

// #include <regex>

#include "absl/strings/ascii.h"
#include "absl/strings/match.h"

#ifdef NULL_PLUGIN

namespace proxy_wasm {
namespace null_plugin {
namespace waf_deny {

#endif

bool RegexMatcher::match(const std::string& regex_pattern,
                         const std::string& data) {
  std::string std_regex_pattern(absl::StripAsciiWhitespace(regex_pattern));

  if (regex_cache.find(std_regex_pattern) == regex_cache.end()) {
    auto re2_matcher =
        std::make_unique<re2::RE2>(std_regex_pattern, re2::RE2::Quiet);
    if (!re2_matcher->ok()) {
      LOG_WARN(re2_matcher->error());
      return false;
    }
    regex_cache.emplace(std_regex_pattern, std::move(re2_matcher));
  }

  auto iter = regex_cache.find(std_regex_pattern);

  return re2::RE2::PartialMatch(re2::StringPiece(data.data(), data.size()),
                                *iter->second);
}

bool RegexMatcher::checkPatternValidity(const std::string& pattern) const {
  std::string std_regex_pattern(absl::StripAsciiWhitespace(pattern));

  if (regex_cache.find(std_regex_pattern) == regex_cache.end()) {
    auto re2_matcher =
        std::make_unique<re2::RE2>(std_regex_pattern, re2::RE2::Quiet);
    if (!re2_matcher->ok()) {
      LOG_WARN(re2_matcher->error());
      return false;
    }
  }

  return true;
}

#ifdef NULL_PLUGIN

}  // namespace waf_deny
}  // namespace null_plugin
}  // namespace proxy_wasm

#endif
