#include "extensions/waf_deny/matchers/matcher_engine.h"

#include <regex>

#include "extensions/waf_deny/util.h"

#ifdef NULL_PLUGIN

namespace proxy_wasm {
namespace null_plugin {
namespace waf_deny {

#endif

void MatcherEngine::registerMatcher(std::unique_ptr<BasicMatcher> matcher) {
  std::string match_type = standardize(matcher->getMatchType());
  if (matchers.find(match_type) != matchers.end()) {
    LOG_WARN("matcher already registered: " + match_type);
  }
  matchers.emplace(match_type, std::move(matcher));
}

bool MatcherEngine::match(const std::string& match_type,
                          const std::string& pattern, const std::string& data) {
  std::string std_match_type = standardize(match_type);
  if (matchers.find(std_match_type) == matchers.end()) {
    LOG_WARN("unknown matchType: " + std_match_type);
    return false;
  }
  return matchers[std_match_type]->match(pattern, data);
}

bool MatcherEngine::checkValidity(const std::string& match_type,
                                  const std::string& pattern) const {
  std::string std_match_type = standardize(match_type);
  auto iter = matchers.find(std_match_type);
  if (iter == matchers.end()) {
    LOG_WARN("unknown matchType: " + std_match_type);
    return false;
  } else {
    return iter->second->checkPatternValidity(pattern);
  }
}

#ifdef NULL_PLUGIN

}  // namespace waf_deny
}  // namespace null_plugin
}  // namespace proxy_wasm

#endif
