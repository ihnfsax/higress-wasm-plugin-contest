#ifndef EXTENSIONS_WAF_DENY_TRANSFORMATIONS_PLAIN_TRANSFORMATION_H
#define EXTENSIONS_WAF_DENY_TRANSFORMATIONS_PLAIN_TRANSFORMATION_H

#include "extensions/waf_deny/transformations/basic_transformation.h"

#ifndef NULL_PLUGIN

#include "proxy_wasm_intrinsics.h"

#else

#include "include/proxy-wasm/null_plugin.h"

namespace proxy_wasm {
namespace null_plugin {
namespace waf_deny {

#endif

class PlainTransformation : public BasicTransformation {
 public:
  std::string transform(const std::string&) override;
  std::string getTransformationType() const override { return "plain"; }
};

#ifdef NULL_PLUGIN

}  // namespace waf_deny
}  // namespace null_plugin
}  // namespace proxy_wasm

#endif

#endif  // EXTENSIONS_WAF_DENY_TRANSFORMATIONS_PLAIN_TRANSFORMATION_H