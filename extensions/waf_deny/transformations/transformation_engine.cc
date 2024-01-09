#include "extensions/waf_deny/transformations/transformation_engine.h"

#include <cstddef>
#include <cstdint>
#include <vector>

#include "absl/strings/str_replace.h"
#include "absl/strings/str_split.h"
#include "extensions/waf_deny/util.h"

#ifdef NULL_PLUGIN

namespace proxy_wasm {
namespace null_plugin {
namespace waf_deny {

#endif

void TransformationEngine::registerTransformation(
    std::unique_ptr<BasicTransformation> transformation) {
  std::string transformation_type =
      standardize(transformation->getTransformationType());
  if (transformations.find(transformation_type) != transformations.end()) {
    LOG_WARN("transformation already registered: " + transformation_type);
  }
  transformations[transformation_type] = std::move(transformation);
}

std::vector<std::string> TransformationEngine::transform(
    const std::vector<std::string>& cmds, const std::string& data) {
  std::vector<std::string> ret;
  ret.reserve(cmds.size());
  for (auto& cmd : cmds) {
    ret.push_back(transform(cmd, data));
  }
  return ret;
}

std::string TransformationEngine::transform(std::string cmd,
                                            const std::string& data) {
  cmd = standardize(cmd);
  std::string temp = data;

  if (data != original_data) {
    original_data = data;
    transformed_data.clear();
  }

  if (transformed_data.find(cmd) != transformed_data.end()) {
    return transformed_data[cmd];
  }

  std::vector<std::string> parts = absl::StrSplit(cmd, '|');
  for (size_t i = 0; i < parts.size(); ++i) {
    if (i == 0) {
      temp = internalTransform(parts[i], true, temp);
    } else {
      temp = internalTransform(parts[i], false, temp);
    }
    if (temp.empty()) {
      return "";
    }
  }

  transformed_data[cmd] = temp;

  return temp;
}

std::string TransformationEngine::internalTransform(const std::string& name,
                                                    bool use_cache,
                                                    const std::string& data) {
  if (use_cache && transformed_data.find(name) != transformed_data.end()) {
    return transformed_data[name];
  }
  if (transformations.find(name) == transformations.end()) {
    return "";
  }
  std::string transformed_data = transformations[name]->transform(data);
  if (use_cache) {
    this->transformed_data[name] = transformed_data;
  }
  return transformed_data;
}

bool TransformationEngine::checkValidity(const std::string& cmd) const {
  std::string std_cmd = standardize(cmd);
  std::vector<std::string> parts = absl::StrSplit(std_cmd, '|');
  for (size_t i = 0; i < parts.size(); ++i) {
    if (transformations.find(parts[i]) == transformations.end()) {
      return false;
    }
  }
  return true;
}

#ifdef NULL_PLUGIN

}  // namespace waf_deny
}  // namespace null_plugin
}  // namespace proxy_wasm

#endif
