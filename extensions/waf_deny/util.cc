#include "extensions/waf_deny/util.h"

// #include <fnmatch.h>

#include "absl/strings/ascii.h"
#include "absl/strings/str_replace.h"

#ifdef NULL_PLUGIN

namespace proxy_wasm {
namespace null_plugin {
namespace waf_deny {

#endif

std::pair<std::string, std::string> splitFirst(const std::string& input,
                                               char delim) {
  size_t pos = input.find(delim);

  if (pos != std::string::npos) {
    return {input.substr(0, pos), input.substr(pos + 1)};
  } else {
    return {input, ""};
  }
}

std::pair<std::string, std::string> splitLast(const std::string& input,
                                              char delim) {
  size_t pos = input.rfind(delim);

  if (pos != std::string::npos) {
    return {input.substr(0, pos), input.substr(pos + 1)};
  } else {
    return {input, ""};
  }
}

std::string standardize(const std::string& str) {
  std::string ret = str;
  absl::StrReplaceAll({{" ", ""}}, &ret);
  absl::AsciiStrToLower(&ret);
  return ret;
}

#ifdef NULL_PLUGIN

}  // namespace waf_deny
}  // namespace null_plugin
}  // namespace proxy_wasm

#endif