#include "extensions/waf_deny/plugin.h"

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>

#include "absl/strings/ascii.h"
#include "common/http_util.h"
#include "extensions/waf_deny/matchers/matcher_engine.h"
#include "extensions/waf_deny/rule_filter.h"
#include "extensions/waf_deny/rules_message.pb.h"
#include "extensions/waf_deny/static_rules.h"
#include "extensions/waf_deny/transformations/transformation_engine.h"
#include "extensions/waf_deny/util.h"

#ifdef NULL_PLUGIN

namespace proxy_wasm {
namespace null_plugin {
namespace waf_deny {

PROXY_WASM_NULL_PLUGIN_REGISTRY

#endif

static RegisterContextFactory register_print_waf(
    CONTEXT_FACTORY(WafPluginContext), ROOT_FACTORY(WafPluginRootContext));

bool WafPluginRootContext::onConfigure(size_t size) {
  // Parse configuration JSON string.
  if (size > 0 && !configure(size)) {
    LOG_WARN("configuration has errors initialization will not continue.");
    return false;
  }
  proxy_set_tick_period_milliseconds(duration_time);
  return true;
}

bool WafPluginRootContext::configure(size_t configuration_size) {
  auto configuration_data = getBufferBytes(WasmBufferType::PluginConfiguration,
                                           0, configuration_size);
  // Parse configuration JSON string.
  auto result = ::Wasm::Common::JsonParse(configuration_data->view());
  if (!result.has_value()) {
    LOG_WARN(absl::StrCat(
        "syntax error: cannot parse plugin configuration JSON string: ",
        configuration_data->view()));
    return false;
  }
  if (!parseRuleConfig(result.value())) {
    return false;
  }
  saved_configuration = result.value();
  return true;
}

bool WafPluginRootContext::parsePluginConfig(const json& configuration,
                                             WafDenyConfigRule& waf_rule) {
  LOG_INFO("parsePluginConfig...");

  auto iter = configuration.find("rule_server");
  if (iter != configuration.end() && iter->is_string()) {
    LOG_INFO("rule server address set to " + iter->get<std::string>());
    rule_server = iter->get<std::string>();
  }

  size_t success_count = updateRules(configuration, waf_rule);

  if (success_count == 0) {
    LOG_WARN("no rule is loaded");
    return false;
  } else {
    LOG_INFO(absl::StrCat("(", success_count, "/", static_rules.size(),
                          ") rules are loaded successfully"));
    return true;
  }
}

size_t WafPluginRootContext::updateRules(const json& filter_config,
                                         WafDenyConfigRule& waf_rule) {
  LOG_INFO("updateRules...");
  if (static_rules.empty()) {
    LOG_WARN("no static rules to load");
    return false;
  }

  RuleFilter rule_filter;
  if (!rule_filter.loadConfiguration(filter_config)) {
    LOG_WARN("failed to load rule filter configuration");
    return false;
  }

  TransformationEngine te;  // just used for check validity
  MatcherEngine me;

  waf_rule.dynamic_rules.clear();

  size_t success_count = 0;

  LOG_INFO(absl::StrCat("static_rules size: ", static_rules.size()));

  for (auto iter = static_rules.begin(); iter != static_rules.end(); iter++) {
    // copy rule so can be modified
    auto modified_rule = *iter;
    if (!rule_filter.checkAndModifyRule(modified_rule)) {
      // This rule is filtered out, skip it.
      continue;
    }

    if (!waf_rule.dynamic_rules.loadRule(modified_rule, iter, te, me)) {
      LOG_WARN(absl::StrCat("failed load rule ", iter->id));
      return success_count;
    } else {
      LOG_INFO(absl::StrCat("load rule ", iter->id, " successfully"));
      success_count++;
    }
  }

  LOG_INFO(absl::StrCat("static_rules size: ", static_rules.size()));

  return success_count;
}

void WafPluginRootContext::onTick() {
  if (rule_server.empty()) {
    return;
  }
  auto context_id = id();
  auto callback = [this, context_id](uint32_t, size_t body_size, uint32_t) {
    LOG_INFO("start rule requesting callback");
    if (body_size == 0) {
      LOG_WARN("async_call failed");
      return;
    }
    // Switch context after getting headers, but before getting body to
    // exercise both code paths.
    auto current_ctx = getContext(context_id);
    if (current_ctx == nullptr) {
      LOG_WARN("context for rule requesting does not exist");
      return;
    }
    current_ctx->setEffectiveContext();
    auto content_type_header = getHeaderMapValue(
        WasmHeaderMapType::HttpCallResponseHeaders, "Content-Type");
    auto body =
        getBufferBytes(WasmBufferType::HttpCallResponseBody, 0, body_size);

    auto header_value = content_type_header->toString();
    if (absl::StartsWith(header_value, "application/json")) {
      // new json plugin configuration
      applyNewConfig(body->toString());
      return;
    } else if (absl::StartsWith(header_value, "application/protobuf")) {
      // new static rules
      applyNewRules(body->toString());
    } else {
      LOG_INFO("unknown content from rule server");
    }
  };

  auto r = httpCall(rule_server,
                    {{":method", "GET"},
                     {":path", "/"},
                     {":authority", "rule_server"},
                     {"identity", "waf_deny_wasm"}},
                    "", {}, 1000, callback);

  if (r != WasmResult::Ok) {
    LOG_WARN("failed to make a rule fetching http request call");
  }
}

void WafPluginRootContext::applyNewConfig(const std::string& body) {
  LOG_INFO("try to apply new plugin config...");
  auto result = ::Wasm::Common::JsonParse(body);
  if (!result.has_value()) {
    LOG_WARN(absl::StrCat(
        "syntax error: cannot parse plugin configuration JSON string: ", body));
    return;
  }
  if (!this->parseRuleConfig(result.value())) {
    LOG_WARN("can't apply new json config from remote entity");
  } else {
    LOG_INFO("successfully apply new json config from remote entity");
    this->saved_configuration = result.value();
  }
  return;
}

void WafPluginRootContext::applyNewRules(const std::string& body) {
  LOG_INFO("try to apply new waf rules...");
  waf_deny::RulesMessage rules_message;
  WafMetadataSet new_metadata;
  WafStaticRuleSet new_static_rules;
  WafRuleDataSet new_rule_data;
  if (rules_message.ParseFromString(body)) {
    LOG_INFO("parse protobuf rules success");
    // Metadata
    for (auto& meta : rules_message.metadata()) {
      std::string kind, version;
      if (meta.has_kind()) {
        kind = meta.kind();
      }
      if (meta.has_version()) {
        version = meta.version();
      }
      new_metadata.emplace(meta.filename(),
                           WafMetadata{.version = version, .kind = kind});
    }
    // Rules
    for (auto& rule : rules_message.static_rules()) {
      WafStaticRule new_rule;
      new_rule.id = rule.id();
      new_rule.payload = rule.payload();
      new_rule.match_type = rule.match_type();
      new_rule.action = rule.action();
      for (auto& placeholder : rule.placeholders()) {
        new_rule.placeholders.emplace_back(placeholder);
      }
      for (auto& transformation : rule.transformations()) {
        new_rule.transformations.emplace_back(transformation);
      }
      for (auto& tag : rule.tags()) {
        new_rule.tags.emplace_back(tag);
      }
      new_rule.filename = rule.filename();
      new_static_rules.emplace_back(std::move(new_rule));
    }
    // Rule data
    for (auto& data_file : rules_message.rule_data()) {
      new_rule_data.emplace(data_file.filename(), data_file.data());
    }
    static_rules = std::move(new_static_rules);
    metadata = std::move(new_metadata);
    rule_data = std::move(new_rule_data);
    if (!this->parseRuleConfig(this->saved_configuration)) {
      LOG_WARN("can't apply new rules from remote entity");
    } else {
      LOG_INFO("successfully apply rules from remote entity");
    }
  }
}

// Per-stream context.

void WafPluginContext::onCreate() {
  auto config = rootContext()->getMatchConfig();
  if (!config.second) {
    return;
  }
  const auto& waf_rule = config.second.value();
  transaction->setRuleSet(&waf_rule.get().dynamic_rules);
}

FilterHeadersStatus WafPluginContext::onRequestHeaders(uint32_t,
                                                       bool end_of_stream) {
  LOG_INFO("Handle request headers...");

  WasmDataPtr headers_holder = getRequestHeaderPairs();
  auto header_pairs = headers_holder->pairs();

  if (rootContext()->useClient()) {
    std::string identity, content_type;
    for (auto& pair : header_pairs) {
      if (standardize(std::string(pair.first)) == "identity") {
        identity = standardize(std::string(pair.second));
      } else if (standardize(std::string(pair.first)) == "content-type") {
        content_type = standardize(std::string(pair.second));
      }
    }
    if (identity == "waf_deny_wasm") {
      if (content_type == "application/json") {
        config_update = true;
        return FilterHeadersStatus::Continue;
      } else if (content_type == "application/protobuf") {
        rule_update = true;
        return FilterHeadersStatus::Continue;
      }
    }
  }

  auto url_holder = getRequestHeader(":path");

  transaction->processURL(url_holder->toString());
  if (transaction->isBlocked()) {
    sendLocalResponse(403, "", "denied by waf", {});
    return FilterHeadersStatus::StopIteration;
  }

  // Must hold unique_ptr to avoid memory leak
  transaction->processHeaders(header_pairs);
  if (transaction->isBlocked()) {
    sendLocalResponse(403, "", "denied by waf", {});
    return FilterHeadersStatus::StopIteration;
  }

  return FilterHeadersStatus::Continue;
}

FilterDataStatus WafPluginContext::onRequestBody(size_t body_buffer_length,
                                                 bool end_of_stream) {
  LOG_INFO("Handle request body...");

  auto body_holder =
      getBufferBytes(WasmBufferType::HttpRequestBody, 0, body_buffer_length);

  std::string body = body_holder->toString();

  transaction->appendRequestBody(body);

  if (end_of_stream) {
    if (config_update) {
      config_update = false;
      rootContext()->applyNewConfig(transaction->getRequestBody());
      sendLocalResponse(200, "", "[waf_deny] set new config", {});
      return FilterDataStatus::StopIterationNoBuffer;
    }
    if (rule_update) {
      rule_update = false;
      rootContext()->applyNewRules(transaction->getRequestBody());
      sendLocalResponse(200, "", "[waf_deny] set new rules", {});
      return FilterDataStatus::StopIterationNoBuffer;
    }
    transaction->processBody();
    if (transaction->isBlocked()) {
      sendLocalResponse(403, "", "denied by waf", {});
      return FilterDataStatus::StopIterationNoBuffer;
    }
  }

  return FilterDataStatus::Continue;
}

#ifdef NULL_PLUGIN

}  // namespace waf_deny
}  // namespace null_plugin
}  // namespace proxy_wasm

#endif
