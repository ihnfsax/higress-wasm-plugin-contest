#ifndef EXTENSIONS_WAF_DENY_PLUGIN_H
#define EXTENSIONS_WAF_DENY_PLUGIN_H

#include <memory>
#include <set>
#include <unordered_map>

#include "common/http_util.h"
#include "common/route_rule_matcher.h"
#include "extensions/waf_deny/rule_filter.h"
#include "extensions/waf_deny/rule_set.h"
#include "extensions/waf_deny/rules_message.pb.h"
#include "extensions/waf_deny/static_rules.h"
#include "extensions/waf_deny/transaction.h"

#ifndef NULL_PLUGIN

#include "proxy_wasm_intrinsics.h"

#else

#include "include/proxy-wasm/null_plugin.h"

namespace proxy_wasm {
namespace null_plugin {
namespace waf_deny {

#endif
struct WafDenyConfigRule {
  WafRuleSet dynamic_rules;
};

class WafPluginRootContext : public RootContext,
                             public RouteRuleMatcher<WafDenyConfigRule> {
 public:
  WafPluginRootContext(uint32_t id, std::string_view root_id)
      : RootContext(id, root_id), duration_time(10000), use_client(true) {}
  ~WafPluginRootContext() {}

  bool onConfigure(size_t) override;
  bool configure(size_t);
  size_t updateRules(const json &, WafDenyConfigRule &);
  void onTick() override;
  bool useClient() { return use_client; }
  void applyNewConfig(const std::string &);
  void applyNewRules(const std::string &);

 private:
  bool parsePluginConfig(const json &, WafDenyConfigRule &) override;
  // Saved config, for rule reloading in the future
  json saved_configuration;

  // For config and rule being reloaded by a remote server
  std::string rule_server;
  uint32_t duration_time;

  // if set true, get rules and config from http request.
  bool use_client;
};

// Per-stream context.
class WafPluginContext : public Context {
 public:
  explicit WafPluginContext(uint32_t id, RootContext *root)
      : Context(id, root),
        transaction(std::make_unique<WafTransaction>()),
        config_update(false),
        rule_update(false){};

  FilterHeadersStatus onRequestHeaders(uint32_t, bool) override;
  FilterDataStatus onRequestBody(size_t, bool) override;
  void onCreate() override;

 private:
  inline WafPluginRootContext *rootContext() {
    return static_cast<WafPluginRootContext *>(this->root());
  }

  std::unique_ptr<WafTransaction> transaction;
  bool config_update;
  bool rule_update;
};

#ifdef NULL_PLUGIN

}  // namespace waf_deny
}  // namespace null_plugin
}  // namespace proxy_wasm

#endif

#endif  // EXTENSIONS_WAF_DENY_PLUGIN_H