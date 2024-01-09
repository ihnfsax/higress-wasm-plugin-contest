#include "extensions/waf_deny/transformations/plain_transformation.h"

#include "absl/strings/str_replace.h"

#ifdef NULL_PLUGIN

namespace proxy_wasm {
namespace null_plugin {
namespace waf_deny {

#endif

std::string PlainTransformation::transform(const std::string& data) {
  return data;
}

#ifdef NULL_PLUGIN

}  // namespace waf_deny
}  // namespace null_plugin
}  // namespace proxy_wasm

#endif
