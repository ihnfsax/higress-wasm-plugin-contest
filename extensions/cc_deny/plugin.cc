#include "extensions/cc_deny/plugin.h"

#include <array>
#include <cstdint>
#include <string>

#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "common/json_util.h"
#include "proxy_wasm_api.h"

using ::nlohmann::json;

#ifdef NULL_PLUGIN

namespace proxy_wasm {
namespace null_plugin {
namespace cc_deny {

PROXY_WASM_NULL_PLUGIN_REGISTRY

#endif

static RegisterContextFactory register_cc_deny(CONTEXT_FACTORY(PluginContext),
                                               ROOT_FACTORY(PluginRootContext));

bool PluginRootContext::onConfigure(size_t size) {
  // Parse configuration JSON string.
  if (size > 0 && !configure(size)) {
    LOG_WARN("configuration has errors initialization will not continue.");
    return false;
  }
  return true;
}

bool PluginRootContext::configure(size_t configuration_size) {
  auto configuration_data = getBufferBytes(WasmBufferType::PluginConfiguration,
                                           0, configuration_size);
  // Parse configuration JSON string.
  auto result = ::Wasm::Common::JsonParse(configuration_data->view());
  if (!result.has_value()) {
    LOG_WARN(absl::StrCat("cannot parse plugin configuration JSON string: ",
                          configuration_data->view()));
    return false;
  }
  if (!parseRuleConfig(result.value())) {
    LOG_WARN(absl::StrCat("cannot parse plugin configuration JSON string: ",
                          configuration_data->view()));
    return false;
  }
  return true;
}

bool PluginRootContext::parsePluginConfig(const json &configuration,
                                          CCDenyConfigRule &rule) {
  auto it = configuration.find("cc_rules");
  if (it == configuration.end() || !it.value().is_array()) {
    LOG_WARN("no cc_rules found in config");
    return false;
  }

  for (auto &[_, json_rule] : it.value().items()) {
    MaxQuery *q_max = &rule.cookie_max;
    uint16_t *block_seconds = &rule.cookie_block_seconds;
    if (json_rule.find("header") != json_rule.end()) {
      q_max = &rule.header_max;
      block_seconds = &rule.header_block_seconds;
    }

    for (auto &[key, value] : json_rule.items()) {
      if (key == "header" && value.is_string()) {
        rule.header_type = value.get<std::string>();
      } else if (key == "cookie" && value.is_string()) {
        rule.cookie_type = value.get<std::string>();
      } else if (key == "qps" && value.is_number_unsigned()) {
        q_max->qps = value.get<uint16_t>();
      } else if (key == "qpm" && value.is_number_unsigned()) {
        q_max->qpm = value.get<uint16_t>();
      } else if (key == "qpd" && value.is_number_unsigned()) {
        q_max->qpd = value.get<uint16_t>();
      } else if (key == "block_seconds" && value.is_number_unsigned()) {
        *block_seconds = value.get<uint16_t>();
      } else {
        LOG_WARN("unknown config field: " + key);
        return false;
      }
    }
  }

  return true;
}

FilterHeadersStatus PluginRootContext::onRequest(const CCDenyConfigRule &rule) {
  std::string key;
  GET_HEADER_VIEW(rule.header_type, header_client);
  if (!header_client.empty()) {
    key = header_key + std::string(header_client);
    if (Blocker::isBlocked(rule, key)) {
      sendLocalResponse(403, "", "denied by cc", HeaderStringPairs());
      return FilterHeadersStatus::StopIteration;
    } else {
      return FilterHeadersStatus::Continue;
    }
  }

  const auto &cookie_client = Wasm::Common::Http::parseCookies(
      [&](absl::string_view k) -> bool { return k == rule.cookie_type; });

  if (cookie_client.size() == 1) {
    key = cookie_key + std::string(cookie_client.begin()->second);
    if (Blocker::isBlocked(rule, key)) {
      sendLocalResponse(403, "", "denied by cc", HeaderStringPairs());
      return FilterHeadersStatus::StopIteration;
    } else {
      return FilterHeadersStatus::Continue;
    }
  }

  LOG_INFO("no cookie or header");
  return FilterHeadersStatus::Continue;
}

FilterHeadersStatus PluginContext::onRequestHeaders(uint32_t, bool) {
  auto *root_ctx = rootContext();
  return root_ctx->onHeaders(
      [root_ctx](const auto &config) { return root_ctx->onRequest(config); });
}

#ifdef NULL_PLUGIN

}  // namespace cc_deny
}  // namespace null_plugin
}  // namespace proxy_wasm

#endif
