#ifndef EXTENSIONS_WAF_DENY_MATCHERS_MATCHER_ENGINE_H
#define EXTENSIONS_WAF_DENY_MATCHERS_MATCHER_ENGINE_H

#include "extensions/waf_deny/matchers/file_text_matcher.h"
#include "extensions/waf_deny/matchers/multi_text_matcher.h"
#include "extensions/waf_deny/matchers/regex_matcher.h"
#include "extensions/waf_deny/matchers/text_matcher.h"

#ifndef NULL_PLUGIN

#include "proxy_wasm_intrinsics.h"

#else

#include "include/proxy-wasm/null_plugin.h"

namespace proxy_wasm {
namespace null_plugin {
namespace waf_deny {

#endif

class MatcherEngine {
 public:
  MatcherEngine() {
    registerMatcher(std::make_unique<TextMatcher>());
    registerMatcher(std::make_unique<FileTextMatcher>());
    registerMatcher(std::make_unique<RegexMatcher>());
    registerMatcher(std::make_unique<MultiTextMatcher>());
  }

  MatcherEngine(const MatcherEngine&) = delete;

  // register a new matcher function to engine
  void registerMatcher(std::unique_ptr<BasicMatcher>);

  // check if data match pattern with a matcher function
  bool match(const std::string& match_type, const std::string& pattern,
             const std::string& data);

  // check if a matche type and a pattern is valid
  // return true if valid, false if not
  bool checkValidity(const std::string& match_type,
                     const std::string& pattern) const;

 private:
  std::unordered_map<std::string, std::unique_ptr<BasicMatcher>> matchers;
};

#ifdef NULL_PLUGIN

}  // namespace waf_deny
}  // namespace null_plugin
}  // namespace proxy_wasm

#endif

#endif  // EXTENSIONS_WAF_DENY_MATCHERS_MATCHER_ENGINE_H