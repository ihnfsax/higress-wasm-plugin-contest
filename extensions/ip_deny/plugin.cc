// Copyright (c) 2022 Alibaba Group Holding Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "extensions/ip_deny/plugin.h"

#include <array>
#include <string>

#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "common/json_util.h"
#include "proxy_wasm_api.h"

using ::nlohmann::json;
using ::Wasm::Common::JsonArrayIterate;
using ::Wasm::Common::JsonValueAs;

#ifdef NULL_PLUGIN

namespace proxy_wasm {
namespace null_plugin {
namespace custom_response {

PROXY_WASM_NULL_PLUGIN_REGISTRY

#endif

static RegisterContextFactory register_custom_response(
    CONTEXT_FACTORY(PluginContext), ROOT_FACTORY(PluginRootContext));

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
                                          IPDenyConfigRule &rule) {
  if (!JsonArrayIterate(
          configuration, "ip_blacklist", [&](const json &item) -> bool {
            auto address = JsonValueAs<std::string>(item);
            if (address.second != Wasm::Common::JsonParserResultDetail::OK) {
              return false;
            }

            std::vector<std::string> pair =
                absl::StrSplit(address.first.value(), absl::MaxSplits('/', 1));
            if (pair.size() != 1 && pair.size() != 2) {
              return false;
            }

            if (pair.size() == 1) {
              rule.ipv4_map.insert(pair[0], 32);
            } else {
              int num;
              if (absl::SimpleAtoi(pair[1], &num) && num <= 32) {
                rule.ipv4_map.insert(pair[0], num);
              } else {
                LOG_WARN("invalid ip mask: " + pair[1]);
                return false;
              }
            }
            return true;
          })) {
    LOG_WARN("failed to parse configuration for ip_blacklist.");
    return false;
  }

  return true;
}

FilterHeadersStatus PluginRootContext::onRequest(const IPDenyConfigRule &rule) {
  GET_HEADER_VIEW("x-real-ip", x_real_ip);
  auto real_ip_str = std::string(x_real_ip);
  if (real_ip_str.empty()) {
    return FilterHeadersStatus::Continue;
  }

  if (rule.ipv4_map.lookup(real_ip_str)) {
    sendLocalResponse(403, "", "denied by ip", HeaderStringPairs());
  }

  return FilterHeadersStatus::Continue;
}

FilterHeadersStatus PluginContext::onRequestHeaders(uint32_t, bool) {
  auto *root_ctx = rootContext();
  return root_ctx->onHeaders(
      [root_ctx](const auto &config) { return root_ctx->onRequest(config); });
}

#ifdef NULL_PLUGIN

}  // namespace custom_response
}  // namespace null_plugin
}  // namespace proxy_wasm

#endif
