#ifndef EXTENSIONS_IP_DENY_PLUGIN_H
#define EXTENSIONS_IP_DENY_PLUGIN_H

#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <array>
#include <cstdint>
#include <map>
#include <string>

#include "common/http_util.h"
#include "common/route_rule_matcher.h"
#include "extensions/ip_deny/ip_map.h"
#define ASSERT(_X) assert(_X)

#ifndef NULL_PLUGIN

#include "proxy_wasm_intrinsics.h"

#else

#include "include/proxy-wasm/null_plugin.h"

namespace proxy_wasm {
namespace null_plugin {
namespace ip_deny {

#endif

struct IPDenyConfigRule {
  IPv4Map ipv4_map;
};

class PluginRootContext : public RootContext,
                          public RouteRuleMatcher<IPDenyConfigRule> {
 public:
  PluginRootContext(uint32_t id, std::string_view root_id)
      : RootContext(id, root_id) {}
  ~PluginRootContext() {}

  bool onConfigure(size_t) override;
  bool configure(size_t);
  FilterHeadersStatus onRequest(const IPDenyConfigRule &);

 private:
  bool parsePluginConfig(const json &, IPDenyConfigRule &) override;
};

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

}  // namespace ip_deny
}  // namespace null_plugin
}  // namespace proxy_wasm

#endif

#endif  // EXTENSIONS_IP_DENY_PLUGIN_H
