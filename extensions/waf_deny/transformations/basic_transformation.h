#ifndef EXTENSIONS_WAF_DENY_TRANSFORMATIONS_BASIC_TRANSFORMATION_H
#define EXTENSIONS_WAF_DENY_TRANSFORMATIONS_BASIC_TRANSFORMATION_H

#include <string>

#ifdef NULL_PLUGIN

namespace proxy_wasm {
namespace null_plugin {
namespace waf_deny {

#endif

class BasicTransformation {
 public:
  virtual ~BasicTransformation() = default;
  virtual std::string transform(const std::string&) = 0;
  virtual std::string getTransformationType() const = 0;
};

#ifdef NULL_PLUGIN

}  // namespace waf_deny
}  // namespace null_plugin
}  // namespace proxy_wasm

#endif

#endif  // EXTENSIONS_WAF_DENY_TRANSFORMATIONS_BASIC_TRANSFORMATION_H