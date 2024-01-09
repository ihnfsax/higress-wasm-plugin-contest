#ifndef EXTENSIONS_WAF_DENY_TRANSACTION_H
#define EXTENSIONS_WAF_DENY_TRANSACTION_H

#include <memory>

#include "extensions/waf_deny/matchers/matcher_engine.h"
#include "extensions/waf_deny/rule_set.h"
#include "extensions/waf_deny/transformations/transformation_engine.h"

#ifdef NULL_PLUGIN

#include "include/proxy-wasm/null_plugin.h"

namespace proxy_wasm {
namespace null_plugin {
namespace waf_deny {

#endif

class WafTransaction {
 public:
  WafTransaction()
      : if_log(true),
        is_blocked(false),
        rule_set(nullptr),
        te(std::make_unique<TransformationEngine>()),
        me(std::make_unique<MatcherEngine>()) {}

  void setRuleSet(WafRuleSet* rule_set) { this->rule_set = rule_set; }
  void processURL(std::string url);
  void processHeaders(
      const std::vector<std::pair<std::string_view, std::string_view>>&
          headers);
  void appendRequestBody(const std::string& body) { request_body.append(body); }
  void processBody();
  bool isBlocked() { return is_blocked; }
  void setLogStatus(bool if_log) { this->if_log = if_log; }
  std::string getRequestBody() { return request_body; }

 private:
  void logMatchInfo(const std::string&, const WafRule&);
  bool matchRule(std::string data, const WafRule& rule);

  bool if_log;
  bool is_blocked;
  WafRuleSet* rule_set;
  std::unique_ptr<TransformationEngine> te;
  std::unique_ptr<MatcherEngine> me;
  std::string request_body;
  std::string content_type;
};

#ifdef NULL_PLUGIN

}  // namespace waf_deny
}  // namespace null_plugin
}  // namespace proxy_wasm

#endif

#endif  // EXTENSIONS_WAF_DENY_TRANSACTION_H