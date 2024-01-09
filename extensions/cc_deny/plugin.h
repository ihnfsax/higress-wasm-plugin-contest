#ifndef EXTENSIONS_CC_DENY_PLUGIN_H
#define EXTENSIONS_CC_DENY_PLUGIN_H

#include <cstdint>
#include <map>
#include <string>

#include "common/http_util.h"
#include "common/route_rule_matcher.h"
#include "extensions/cc_deny/blocker.h"

#define ASSERT(_X) assert(_X)

#ifndef NULL_PLUGIN

#include "proxy_wasm_intrinsics.h"

#else

#include "include/proxy-wasm/null_plugin.h"

namespace proxy_wasm {
namespace null_plugin {
namespace cc_deny {

#endif

class PluginRootContext : public RootContext,
                          public RouteRuleMatcher<CCDenyConfigRule> {
 public:
  PluginRootContext(uint32_t id, std::string_view root_id)
      : RootContext(id, root_id) {}
  ~PluginRootContext() {}

  bool onConfigure(size_t) override;
  bool configure(size_t);
  FilterHeadersStatus onRequest(const CCDenyConfigRule &);

 private:
  bool parsePluginConfig(const json &, CCDenyConfigRule &) override;
};

// Per-stream context.
class PluginContext : public Context {
 public:
  explicit PluginContext(uint32_t id, RootContext *root) : Context(id, root) {}
  FilterHeadersStatus onRequestHeaders(uint32_t, bool) override;

 private:
  inline PluginRootContext *rootContext() {
    return static_cast<PluginRootContext *>(this->root());
  }
};

#ifdef NULL_PLUGIN

}  // namespace cc_deny
}  // namespace null_plugin
}  // namespace proxy_wasm

#endif

#endif  // EXTENSIONS_CC_DENY_PLUGIN_H
