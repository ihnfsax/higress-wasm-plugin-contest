#ifndef EXTENSIONS_WAF_DENY_TRANSFORMATIONS_TRANSFORMATION_ENGINE_H
#define EXTENSIONS_WAF_DENY_TRANSFORMATIONS_TRANSFORMATION_ENGINE_H

#include <string>
#include <unordered_map>

#include "extensions/waf_deny/transformations/base64_transformation.h"
#include "extensions/waf_deny/transformations/plain_transformation.h"
#include "extensions/waf_deny/transformations/url_transformation.h"

#ifdef NULL_PLUGIN

#include "include/proxy-wasm/null_plugin.h"

namespace proxy_wasm {
namespace null_plugin {
namespace waf_deny {

#endif

class TransformationEngine {
 public:
  TransformationEngine() {
    registerTransformation(std::make_unique<Base64Transformation>());
    registerTransformation(std::make_unique<URLTransformation>());
    registerTransformation(std::make_unique<PlainTransformation>());
  }

  TransformationEngine(const TransformationEngine&) = delete;

  // register a new transformation function to engine
  void registerTransformation(std::unique_ptr<BasicTransformation>);

  // transform data with registered transformation functions
  std::vector<std::string> transform(const std::vector<std::string>& cmds,
                                     const std::string& data);

  // transform data with a specific transformation function
  std::string transform(std::string cmd, const std::string& data);

  // check if a transformation type is valid
  // return true if valid, false if not
  bool checkValidity(const std::string&) const;

 private:
  std::vector<std::string> split(const std::string&);
  std::string internalTransform(const std::string&, bool, const std::string&);

  std::unordered_map<std::string, std::unique_ptr<BasicTransformation>>
      transformations;
  std::string original_data;
  std::unordered_map<std::string, std::string> transformed_data;
};

#ifdef NULL_PLUGIN

}  // namespace waf_deny
}  // namespace null_plugin
}  // namespace proxy_wasm

#endif

#endif  // EXTENSIONS_WAF_DENY_TRANSFORMATION_ENGINE_H