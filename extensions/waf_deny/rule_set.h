#ifndef EXTENSIONS_WAF_DENY_RULE_SET_H
#define EXTENSIONS_WAF_DENY_RULE_SET_H

#include <cstdint>
#include <unordered_map>

#include "extensions/waf_deny/matchers/matcher_engine.h"
#include "extensions/waf_deny/static_rules.h"
#include "extensions/waf_deny/transformations/transformation_engine.h"

#ifndef NULL_PLUGIN

#include "proxy_wasm_intrinsics.h"

#else

#include "include/proxy-wasm/null_plugin.h"

namespace proxy_wasm {
namespace null_plugin {
namespace waf_deny {

#endif

class WafRule {
 public:
  WafRule(const std::string& placeholder, const std::string& transformation,
          const WafStaticIndex index)
      : placeholder(placeholder),
        transformation(transformation),
        index(index) {}
  const std::string& getPlaceholder() const { return placeholder; }
  const std::string& getTransformation() const { return transformation; }
  const std::string& getAction() const { return index->action; }
  const std::string& getPayload() const { return index->payload; }
  const std::string& getMatchType() const { return index->match_type; }
  const std::string& getFilename() const { return index->filename; }
  uint64_t getId() const { return index->id; }

 private:
  std::string placeholder;
  std::string transformation;
  WafStaticIndex index;
};

class WafTransaction;

class WafRuleSet {
  friend class WafTransaction;

 public:
  WafRuleSet() = default;
  // Load one dynamic rule from static rule. The index might not point to 1st
  // arguement.
  // return true if success, false if failed.
  bool loadRule(const WafStaticRule& static_rule, WafStaticIndex index,
                const TransformationEngine& te, const MatcherEngine& me);

  // clear all rules
  void clear();

 private:
  std::vector<WafRule> request_url_path_rules;
  std::vector<WafRule> request_url_filename_rules;
  std::vector<WafRule> request_url_basename_rules;
  std::vector<WafRule> request_url_param_rules;
  std::vector<WafRule> request_header_rules;
  std::vector<WafRule> request_html_form_rules;
  std::vector<WafRule> request_raw_body_rules;
};

#ifdef NULL_PLUGIN

}  // namespace waf_deny
}  // namespace null_plugin
}  // namespace proxy_wasm

#endif

#endif  // EXTENSIONS_WAF_DENY_RULE_SET_H