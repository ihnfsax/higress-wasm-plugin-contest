#ifndef EXTENSIONS_WAF_DENY_STATIC_RULES_H
#define EXTENSIONS_WAF_DENY_STATIC_RULES_H

#include <cstdint>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#ifdef NULL_PLUGIN

#include "include/proxy-wasm/null_plugin.h"

namespace proxy_wasm {
namespace null_plugin {
namespace waf_deny {

#endif

struct WafMetadata {
  std::string version;
  std::string kind;
};

using WafMetadataSet = std::unordered_map<std::string, WafMetadata>;

extern WafMetadataSet metadata;

struct WafStaticRule {
  uint64_t id;
  std::string payload;
  std::string match_type;
  std::string action;
  std::vector<std::string> placeholders;
  std::vector<std::string> transformations;
  std::vector<std::string> tags;
  std::string filename;
};

using WafStaticRuleSet = std::vector<WafStaticRule>;
using WafStaticIndex = WafStaticRuleSet::iterator;

extern WafStaticRuleSet static_rules;

using WafRuleDataSet = std::unordered_map<std::string, std::string>;

// This variable should not be cleared.
extern WafRuleDataSet rule_data;

#ifdef NULL_PLUGIN

}  // namespace waf_deny
}  // namespace null_plugin
}  // namespace proxy_wasm

#endif

#endif  // EXTENSIONS_WAF_DENY_STATIC_RULES_H