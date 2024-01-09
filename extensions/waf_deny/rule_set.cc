
#include "extensions/waf_deny/rule_set.h"

#include <iostream>
#include <string>

#include "absl/strings/ascii.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"

#ifdef NULL_PLUGIN

namespace proxy_wasm {
namespace null_plugin {
namespace waf_deny {

PROXY_WASM_NULL_PLUGIN_REGISTRY

#endif

bool WafRuleSet::loadRule(const WafStaticRule& static_rule,
                          WafStaticIndex index, const TransformationEngine& te,
                          const MatcherEngine& me) {
  // check matcher validity
  if (!me.checkValidity(static_rule.match_type, static_rule.payload)) {
    LOG_WARN(absl::StrCat("invalid payload and matchType: [",
                          static_rule.payload, ", ", static_rule.match_type,
                          "]"));
    return false;
  }

  // check transformation validity
  for (const auto& t : static_rule.transformations) {
    if (!te.checkValidity(t)) {
      LOG_WARN(absl::StrCat("invalid transformation: ", t));
      return false;
    }
  }

  for (const auto& p : static_rule.placeholders) {
    if (p.empty()) {
      LOG_WARN("empty placeholder");
      return false;
    }

    // URL Param
    if (p == "urlparamname" || p == "urlparamvalue" ||
        absl::StartsWith(p, "urlparamvalue:") ||
        absl::StartsWith(p, "!urlparamvalue:")) {
      for (const auto& t : static_rule.transformations) {
        request_url_param_rules.emplace_back(p, t, index);
      }
      continue;
    }

    // URL Path
    if (p == "urlpath") {
      for (const auto& t : static_rule.transformations) {
        request_url_path_rules.emplace_back(p, t, index);
      }
      continue;
    }

    // URL Filename
    if (p == "urlfilename") {
      for (const auto& t : static_rule.transformations) {
        request_url_filename_rules.emplace_back(p, t, index);
      }
      continue;
    }

    // URL Basename
    if (p == "urlbasename") {
      for (const auto& t : static_rule.transformations) {
        request_url_basename_rules.emplace_back(p, t, index);
      }
      continue;
    }

    // Header
    if (p == "headername" || p == "headervalue" ||
        absl::StartsWith(p, "headervalue:") ||
        absl::StartsWith(p, "!headervalue:")) {
      for (const auto& t : static_rule.transformations) {
        request_header_rules.emplace_back(p, t, index);
      }
      continue;
    }

    // HTML Form
    if (p == "htmlformname" || p == "htmlformvalue" ||
        absl::StartsWith(p, "htmlformvalue:") ||
        absl::StartsWith(p, "!htmlformvalue:")) {
      for (const auto& t : static_rule.transformations) {
        request_html_form_rules.emplace_back(p, t, index);
      }
      continue;
    }

    // Raw Body
    if (p == "rawbody") {
      for (const auto& t : static_rule.transformations) {
        request_raw_body_rules.emplace_back(p, t, index);
      }
      continue;
    }

    LOG_WARN(absl::StrCat("unknown placeholder: ", p));
    return false;
  }
  return true;
}

void WafRuleSet::clear() {
  request_url_path_rules.clear();
  request_url_param_rules.clear();
  request_header_rules.clear();
  request_html_form_rules.clear();
  request_raw_body_rules.clear();
}

#ifdef NULL_PLUGIN

}  // namespace waf_deny
}  // namespace null_plugin
}  // namespace proxy_wasm

#endif
