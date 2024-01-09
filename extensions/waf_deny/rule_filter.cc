#include "extensions/waf_deny/rule_filter.h"

#include <fnmatch.h>

#include <regex>
#include <string>
#include <vector>

#include "extensions/waf_deny/util.h"

#ifndef NULL_PLUGIN

#include "proxy_wasm_intrinsics.h"

#else

#include "include/proxy-wasm/null_plugin.h"

namespace proxy_wasm {
namespace null_plugin {
namespace waf_deny {

PROXY_WASM_NULL_PLUGIN_REGISTRY

#endif

bool GlobFilenameMatcher::load(const std::string& glob_pattern) {
  std::string rx = "^";
  for (size_t i = 0; i < glob_pattern.size();) {
    switch (glob_pattern[i]) {
      case '.':
      case '\\':
      case '+':
      case '[':
      case '^':
      case ']':
      case '$':
      case '(':
      case ')':
      case '{':
      case '}':
      case '=':
      case '!':
      case '<':
      case '>':
      case '|':
      case ':':
      case '-':
      case '/':
        rx += '\\';
        rx += glob_pattern[i];
        i++;
        break;
      case '?':
        rx += '.';
        i++;
        break;
      case '*':
        if (glob_pattern[i + 1] == '*') {
          if (glob_pattern[i + 2] == '/') {
            rx += ".*";
            i += 3;
          } else {
            return false;  // only allow **/
          }
        } else {
          rx += R"([^\/]*)";
          i++;
        }
        break;
      default:
        rx += glob_pattern[i];
        i++;
        break;
    }
  }
  rx += "$";
  regex_patterns.push_back(rx);
  return true;
}

bool GlobFilenameMatcher::load(const std::vector<std::string>& glob_patterns) {
  for (const auto& p : glob_patterns) {
    if (!load(p)) {
      return false;
    }
  }
  return true;
}

bool GlobFilenameMatcher::match(const std::string& str) const {
  for (const auto& p : regex_patterns) {
    std::regex regex_pattern(p);
    if (std::regex_match(str, regex_pattern)) {
      return true;
    }
  }
  return false;
}

// A valid configuration example:
// {
//   "enabled_rules" : {
//     "filename" : "**/*.yml",
//     "id" : [
//       123213,
//       213123
//     ],
//     "placeholders" : [
//       "*urlpath*",
//       "header"
//     ],
//   },
//   "disabled_rules" : [
//     {
//       "filename" : "xss/*.yml"
//     },
//     {
//       "id" : 122134,
//       "matchType" : {
//         "hello",
//         "ehllo"
//       },
//     }
//   ]
// }
bool RuleFilter::loadConfiguration(const json& config) {
  for (auto& e : config.items()) {
    if (e.key() == "enabled_rules") {
      if (e.value().is_object()) {
        Filter filter;
        if (!loadFilter(e.value(), filter)) {
          return false;
        } else {
          positive_filters.push_back(filter);
        }
      } else if (e.value().is_array()) {
        for (auto& f : e.value()) {
          Filter filter;
          if (!loadFilter(f, filter)) {
            return false;
          } else {
            positive_filters.push_back(filter);
          }
        }
      } else {
        LOG_WARN(
            "[load configuration] enabled_rules should be a filter or an "
            "array of filters");
        return false;
      }
    } else if (e.key() == "disabled_rules") {
      if (e.value().is_object()) {
        Filter filter;
        if (!loadFilter(e.value(), filter)) {
          return false;
        } else {
          negative_filters.push_back(filter);
        }
      } else if (e.value().is_array()) {
        for (auto& f : e.value()) {
          Filter filter;
          if (!loadFilter(f, filter)) {
            return false;
          } else {
            negative_filters.push_back(filter);
          }
        }
      } else {
        LOG_WARN(
            "[load configuration] disabled_rules should be a filter or an "
            "array of filters");
        return false;
      }
    } else if (e.key() == "rule_server") {
      continue;
    } else {
      LOG_WARN("[load configuration] unknown key in configuration: " + e.key());
      return false;
    }
  }
  return true;
}

bool RuleFilter::loadFilter(const json& filter_json, Filter& filter) {
  if (!filter_json.is_object()) {
    LOG_WARN("[load configuration] filter should be an object");
    return false;
  }

  for (auto& e : filter_json.items()) {
    if (e.key() == "id_max") {
      if (e.value().is_number_unsigned()) {
        filter.max_set = true;
        filter.id_max = e.value().get<uint64_t>();
      } else {
        LOG_WARN("[load configuration] invalid id_max");
        return false;
      }
    } else if (e.key() == "id_min") {
      if (e.value().is_number_unsigned()) {
        filter.min_set = true;
        filter.id_min = e.value().get<uint64_t>();
      } else {
        LOG_WARN("[load configuration] invalid id_min");
        return false;
      }
    } else if (e.key() == "id") {
      if (!loadArrayOfInt(e.value(), filter.ids)) {
        LOG_WARN("[load configuration] invalid id");
        return false;
      }
    } else if (e.key() == "matchType") {
      if (!loadArrayOfString(e.value(), filter.match_types, true)) {
        LOG_WARN("[load configuration] invalid matchType");
        return false;
      }
    } else if (e.key() == "action") {
      if (!loadArrayOfString(e.value(), filter.actions, true)) {
        LOG_WARN("[load configuration] invalid action");
        return false;
      }
    } else if (e.key() == "placeholders") {
      if (!loadArrayOfString(e.value(), filter.placeholders, true)) {
        LOG_WARN("[load configuration] invalid placeholders");
        return false;
      }
    } else if (e.key() == "transformations") {
      if (!loadArrayOfString(e.value(), filter.transformations, true)) {
        LOG_WARN("[load configuration] invalid transformation");
        return false;
      }
    } else if (e.key() == "tags") {
      if (!loadArrayOfString(e.value(), filter.tags)) {
        LOG_WARN("[load configuration] invalid tag");
        return false;
      }
    } else if (e.key() == "filename") {
      std::vector<std::string> filenames;
      if (!loadArrayOfString(e.value(), filenames)) {
        LOG_WARN("[load configuration] invalid filename pattern");
        return false;
      }
      if (!filter.glob_filename_matcher.load(filenames)) {
        LOG_WARN("[load configuration] invalid filename pattern");
        return false;
      }
    } else if (e.key() == "payload") {
      LOG_WARN("[load configuration] payload is not supported to be filtered");
      return false;
    } else {
      LOG_WARN("[load configuration] unknown key in filter: " + e.key());
      return false;
    }
  }
  return true;
}

bool RuleFilter::loadArrayOfInt(const json& config,
                                std::vector<uint64_t>& vec) {
  vec.clear();
  if (config.is_number_unsigned()) {
    vec.push_back(config.get<uint64_t>());
  } else if (config.is_array()) {
    for (auto& e : config) {
      if (!e.is_number_unsigned()) {
        return false;
      }
      vec.push_back(e.get<uint64_t>());
    }
  } else {
    return false;
  }
  return true;
}

bool RuleFilter::loadArrayOfString(const json& config,
                                   std::vector<std::string>& vec,
                                   bool if_standardize) {
  vec.clear();
  if (config.is_string()) {
    if (if_standardize) {
      vec.push_back(standardize(config.get<std::string>()));
    } else {
      vec.push_back(config.get<std::string>());
    }
    return true;
  } else if (config.is_array()) {
    for (auto& e : config) {
      if (!e.is_string()) {
        return false;
      }
      if (if_standardize) {
        vec.push_back(standardize(e.get<std::string>()));
      } else {
        vec.push_back(e.get<std::string>());
      }
    }
  } else {
    return false;
  }
  return true;
}

bool RuleFilter::checkAndModifyRule(WafStaticRule& rule) const {
  // standardize
  rule.match_type = standardize(rule.match_type);
  rule.action = standardize(rule.action);
  for (auto& placeholder : rule.placeholders) {
    placeholder = standardize(placeholder);
  }
  for (auto& transformation : rule.transformations) {
    transformation = standardize(transformation);
  }
  // negative_filters
  for (const auto& nf : negative_filters) {
    if (checkFilter(nf, rule, true)) {
      return false;
    }
  }
  if (positive_filters.empty()) {
    return false;
  }
  // positive_filters
  bool is_valid = false;
  for (const auto& pf : positive_filters) {
    if (checkFilter(pf, rule, false)) {
      is_valid = true;
    }
  }
  if (rule.placeholders.empty() || rule.transformations.empty()) {
    return false;
  }
  return is_valid;
}

bool RuleFilter::checkFilter(const Filter& filter, WafStaticRule& rule,
                             bool is_negative) const {
  // id_min and id_max
  if (filter.min_set && filter.max_set) {
    if (filter.id_min > filter.id_max) {
      return false;
    }
    if (rule.id < filter.id_min || rule.id > filter.id_max) {
      return false;
    }
  } else if (filter.min_set && rule.id < filter.id_min) {
    return false;
  } else if (filter.max_set && rule.id > filter.id_max) {
    return false;
  }

  // id
  if (!filter.ids.empty() && std::find(filter.ids.begin(), filter.ids.end(),
                                       rule.id) == filter.ids.end()) {
    return false;
  }

  // matchType
  if (!filter.match_types.empty()) {
    bool is_valid = false;
    for (const auto& pattern : filter.match_types) {
      if (::fnmatch(pattern.c_str(), rule.match_type.c_str(), FNM_NOESCAPE) ==
          0) {
        is_valid = true;
      }
    }
    if (!is_valid) {
      return false;
    }
  }

  // Action
  if (!filter.actions.empty()) {
    bool is_valid = false;
    for (const auto& pattern : filter.actions) {
      if (::fnmatch(pattern.c_str(), rule.match_type.c_str(), FNM_NOESCAPE) ==
          0) {
        is_valid = true;
      }
    }
    if (!is_valid) {
      return false;
    }
  }

  // Placeholders
  if (!filter.placeholders.empty()) {
    for (auto iter = rule.placeholders.begin();
         iter != rule.placeholders.end();) {
      bool is_valid = false;
      for (const auto& pattern : filter.placeholders) {
        if (::fnmatch(pattern.c_str(), iter->c_str(), FNM_NOESCAPE) == 0) {
          is_valid = true;
          break;
        }
      }
      if ((is_valid && is_negative) || (!is_valid && !is_negative)) {
        iter = rule.placeholders.erase(iter);
      } else {
        iter++;
      }
    }
  }
  if (rule.placeholders.empty()) {
    return false;
  }

  // Transformations
  if (!filter.transformations.empty()) {
    for (auto iter = rule.transformations.begin();
         iter != rule.transformations.end();) {
      bool is_valid = false;
      for (const auto& pattern : filter.transformations) {
        if (::fnmatch(pattern.c_str(), iter->c_str(), FNM_NOESCAPE) == 0) {
          is_valid = true;
          break;
        }
      }
      if ((is_valid && is_negative) || (!is_valid && !is_negative)) {
        iter = rule.transformations.erase(iter);
      } else {
        iter++;
      }
    }
  }
  if (rule.transformations.empty()) {
    return false;
  }

  // Tags
  if (!filter.tags.empty()) {
    bool is_valid = false;
    for (const auto& pattern : filter.tags) {
      for (auto& tag : rule.tags) {
        if (::fnmatch(pattern.c_str(), tag.c_str(), FNM_NOESCAPE) == 0) {
          is_valid = true;
          break;
        }
      }
      if (is_valid) {
        break;
      }
    }
    if (!is_valid) {
      return false;
    }
  }

  // Filename
  if (filter.glob_filename_matcher.size() != 0 &&
      !filter.glob_filename_matcher.match(rule.filename)) {
    return false;
  }

  return true;
}

#ifdef NULL_PLUGIN

}  // namespace waf_deny
}  // namespace null_plugin
}  // namespace proxy_wasm

#endif
