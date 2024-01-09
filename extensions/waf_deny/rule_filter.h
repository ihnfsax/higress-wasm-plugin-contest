#ifndef EXTENSIONS_WAF_DENY_RULE_FILTER_H
#define EXTENSIONS_WAF_DENY_RULE_FILTER_H

#include <cstdint>

#include "common/json_util.h"
#include "extensions/waf_deny/static_rules.h"
#include "extensions/waf_deny/util.h"

using nlohmann::json;

#ifdef NULL_PLUGIN

#include "include/proxy-wasm/null_plugin.h"

namespace proxy_wasm {
namespace null_plugin {
namespace waf_deny {

#endif

class GlobFilenameMatcher {
 public:
  GlobFilenameMatcher() = default;
  // return true if success, false otherwise
  bool load(const std::string& glob_pattern);
  // return true if success, false otherwise
  bool load(const std::vector<std::string>& glob_patterns);
  // return turn if match, false otherwise
  bool match(const std::string&) const;
  size_t size() const { return regex_patterns.size(); }

 private:
  std::vector<std::string> regex_patterns;
};

// TODO(ihnfsax): should be implemented with pboettch/json-schema-validator
class RuleFilter {
 public:
  RuleFilter() = default;

  // return true if the config is valid, false otherwise
  bool loadConfiguration(const json& config);

  // return true if the rule is qualified, false otherwise
  bool checkAndModifyRule(WafStaticRule& rule) const;

 private:
  struct Filter {
    bool min_set;
    bool max_set;
    uint64_t id_min;
    uint64_t id_max;
    std::vector<uint64_t> ids;
    std::vector<std::string> match_types;
    std::vector<std::string> actions;
    std::vector<std::string> placeholders;
    std::vector<std::string> transformations;
    std::vector<std::string> tags;
    GlobFilenameMatcher glob_filename_matcher;
    Filter()
        : min_set(false),
          max_set(false),
          id_min(UINT64_MAX),
          id_max(UINT64_MAX) {}
  };

  bool checkFilter(const Filter&, WafStaticRule&, bool) const;

  bool loadFilter(const json&, Filter&);
  bool loadArrayOfInt(const json&, std::vector<uint64_t>&);
  bool loadArrayOfString(const json&, std::vector<std::string>&,
                         bool if_standardize = false);

  std::vector<Filter> positive_filters;
  std::vector<Filter> negative_filters;
};

#ifdef NULL_PLUGIN

}  // namespace waf_deny
}  // namespace null_plugin
}  // namespace proxy_wasm

#endif

#endif  // EXTENSIONS_WAF_DENY_RULE_FILTER_H