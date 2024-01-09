
#include "extensions/waf_deny/transaction.h"

#include <iostream>
#include <string>

#include "absl/strings/ascii.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "common/http_util.h"
#include "extensions/waf_deny/util.h"

#ifdef NULL_PLUGIN

namespace proxy_wasm {
namespace null_plugin {
namespace waf_deny {

PROXY_WASM_NULL_PLUGIN_REGISTRY

#endif

void WafTransaction::processURL(std::string url) {
  if (rule_set == nullptr) {
    return;
  }
  is_blocked = false;

  if (url.empty()) {
    return;
  } else if (url[0] == '/') {
    url = url.substr(1);
  }

  const auto& [path, param_str] = splitFirst(url, '?');

  if (!path.empty()) {
    for (auto& rule : rule_set->request_url_path_rules) {
      if (rule.getPlaceholder() == "urlpath" && matchRule(path, rule)) {
        return;
      }
    }

    auto [prefix, url_filename] = splitLast(path, '/');
    if (url_filename.empty()) {
      url_filename = prefix;
    }
    if (!url_filename.empty()) {
      for (auto& rule : rule_set->request_url_filename_rules) {
        if (rule.getPlaceholder() == "urlfilename" &&
            matchRule(url_filename, rule)) {
          return;
        }
      }
      auto [basename, suffix] = splitLast(url_filename, '.');
      if (!basename.empty()) {
        for (auto& rule : rule_set->request_url_basename_rules) {
          if (rule.getPlaceholder() == "urlbasename" &&
              matchRule(basename, rule)) {
            return;
          }
        }
      }
    }
  }

  if (!param_str.empty()) {
    // Need to add a '?' to trigger parsing
    const auto& params = Wasm::Common::Http::parseQueryString("?" + param_str);
    // For each param
    for (auto& [name, value] : params) {
      for (auto& rule : rule_set->request_url_param_rules) {
        // Param name
        if (rule.getPlaceholder() == "urlparamname" && matchRule(name, rule)) {
          return;
        }
        // Param value
        bool is_needed = false;
        if (rule.getPlaceholder() == "urlparamvalue") {
          is_needed = true;
        } else if (absl::StartsWith(rule.getPlaceholder(), "urlparamvalue:")) {
          std::string suffix =
              rule.getPlaceholder().substr(strlen("urlparamvalue:"));
          if (name == suffix) {
            is_needed = true;
          }
        } else if (absl::StartsWith(rule.getPlaceholder(), "!urlparamvalue:")) {
          std::string suffix =
              rule.getPlaceholder().substr(strlen("!urlparamvalue:"));
          if (name != suffix) {
            is_needed = true;
          }
        }
        if (is_needed && matchRule(value, rule)) {
          return;
        }
      }
    }
  }
}

void WafTransaction::processHeaders(
    const std::vector<std::pair<std::string_view, std::string_view>>& headers) {
  if (rule_set == nullptr) {
    return;
  }
  is_blocked = false;
  content_type.clear();
  if (headers.empty()) {
    return;
  }

  for (auto& [name, value] : headers) {
    for (auto& rule : rule_set->request_header_rules) {
      // Content-Type
      if (standardize(std::string(name)) == "content-type") {
        content_type = value;
      }

      // Header Name
      if (rule.getPlaceholder() == "headername" &&
          matchRule(std::string(name), rule)) {
        return;
      }
      // Header Value
      bool is_needed = false;
      if (rule.getPlaceholder() == "headervalue") {
        is_needed = true;
      } else if (absl::StartsWith(rule.getPlaceholder(), "headervalue:")) {
        std::string suffix =
            rule.getPlaceholder().substr(strlen("headervalue:"));
        if (name == suffix) {
          is_needed = true;
        }
      } else if (absl::StartsWith(rule.getPlaceholder(), "!headervalue:")) {
        std::string suffix =
            rule.getPlaceholder().substr(strlen("!headervalue:"));
        if (name != suffix) {
          is_needed = true;
        }
      }
      if (is_needed && matchRule(std::string(value), rule)) {
        return;
      }
    }
  }
}

void WafTransaction::processBody() {
  if (rule_set == nullptr) {
    return;
  }
  is_blocked = false;

  if (request_body.empty()) {
    return;
  }

  // Raw Body
  for (auto& rule : rule_set->request_raw_body_rules) {
    if (matchRule(request_body, rule)) {
      request_body.clear();
      return;
    }
  }

  // HTML Form
  const auto& params =
      Wasm::Common::Http::parseParameters(request_body, 0, false);

  for (auto& [name, value] : params) {
    for (auto& rule : rule_set->request_html_form_rules) {
      // Form Name
      if (rule.getPlaceholder() == "htmlformname" && matchRule(name, rule)) {
        request_body.clear();
        return;
      }
      // Form Value
      bool is_needed = false;
      if (rule.getPlaceholder() == "htmlformvalue") {
        is_needed = true;
      } else if (absl::StartsWith(rule.getPlaceholder(), "htmlformvalue:")) {
        std::string suffix =
            rule.getPlaceholder().substr(strlen("htmlformvalue:"));
        if (name == suffix) {
          is_needed = true;
        }
      } else if (absl::StartsWith(rule.getPlaceholder(), "!htmlformvalue:")) {
        std::string suffix =
            rule.getPlaceholder().substr(strlen("!htmlformvalue:"));
        if (name != suffix) {
          is_needed = true;
        }
      }
      if (is_needed && matchRule(value, rule)) {
        request_body.clear();
        return;
      }
    }
  }
  request_body.clear();
  return;
}

bool WafTransaction::matchRule(std::string data, const WafRule& rule) {
  data = te->transform(rule.getTransformation(), data);
  if (!data.empty() &&
      me->match(rule.getMatchType(), rule.getPayload(), data)) {
    logMatchInfo(data, rule);
    if (rule.getAction() == "deny") {
      is_blocked = true;
      return true;
    }
  }
  return false;
}

void WafTransaction::logMatchInfo(const std::string& matched_info,
                                  const WafRule& rule) {
  std::string log_str;
  log_str += "RULE MATCHED: ";
  log_str += "[id: " + std::to_string(rule.getId()) + "] ";
  log_str += "[filename: " + rule.getFilename() + "] ";
  log_str += "[action: " + rule.getAction() + "] ";
  log_str += "[matchType: " + rule.getMatchType() + "] ";
  log_str += "[placeholder: " + rule.getPlaceholder() + "] ";
  log_str += "[transformation: " + rule.getTransformation() + "] ";
  log_str += "[matchedInfo: " + matched_info + "]";
  LOG_INFO(log_str);
}

#ifdef NULL_PLUGIN

}  // namespace waf_deny
}  // namespace null_plugin
}  // namespace proxy_wasm

#endif
