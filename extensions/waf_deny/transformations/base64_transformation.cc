#include "extensions/waf_deny/transformations/base64_transformation.h"

#include "absl/strings/str_replace.h"

#ifdef NULL_PLUGIN

namespace proxy_wasm {
namespace null_plugin {
namespace waf_deny {

#endif

const std::vector<uint8_t> base64_decode_table = {
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 62,  255,
    255, 255, 63,  52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  255, 255,
    255, 255, 255, 255, 255, 0,   1,   2,   3,   4,   5,   6,   7,   8,   9,
    10,  11,  12,  13,  14,  15,  16,  17,  18,  19,  20,  21,  22,  23,  24,
    25,  255, 255, 255, 255, 255, 255, 26,  27,  28,  29,  30,  31,  32,  33,
    34,  35,  36,  37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,
    49,  50,  51,  255, 255, 255, 255, 255};

const std::string base64_encode_table =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string Base64Transformation::transform(const std::string& data) {
  return decode(data);
}

std::string Base64Transformation::encode(const std::string& data) {
  std::string ret;
  ret.resize((((data.size()) + 2) / 3) * 4 + 1);

  size_t j = 0;
  size_t state = 0;
  char l = 0;
  for (size_t i = 0; i <= data.size(); i++) {
    char c = 0;
    if (i != data.size()) {
      c = data[i];
    }

    switch (state) {
      case 0:
        state = 1;
        ret[j++] = base64_encode_table[(c >> 2) & 0x3F];
        break;
      case 1:
        state = 2;
        ret[j++] = base64_encode_table[((l & 0x3) << 4) | ((c >> 4) & 0xF)];
        break;
      case 2:
        state = 0;
        ret[j++] = base64_encode_table[((l & 0xF) << 2) | ((c >> 6) & 0x3)];
        ret[j++] = base64_encode_table[c & 0x3F];
        break;
    }
    l = c;
  }

  // Truncate the string to the actual length
  if (data.size() % 3 != 1) {
    ret.resize(j - 1);
  } else {
    ret.resize(j);
  }

  switch (ret.size() % 4) {
    case 2:
      ret += "==";
      break;
    case 3:
      ret += "=";
      break;
  }

  return ret;
}

std::string Base64Transformation::decode(const std::string& data) {
  std::string copy = data;
  switch (copy.size() % 4) {
    case 2:
      copy += "==";
      break;
    case 3:
      copy += "=";
      break;
  }

  std::string ret;
  ret.resize(copy.length() / 4 * 3);

  for (size_t i = 0, j = 0; i < copy.size(); i++) {
    if (copy[i] == '=') {
      break;
    }
    if (copy[i] < '+' || copy[i] > 'z') {
      return "";
    }
    uint8_t c = base64_decode_table[static_cast<size_t>(copy[i])];
    if (c == 255) {
      return "";
    }
    switch (i & 0x3) {
      case 0:
        ret[j] = static_cast<char>((c << 2) & 0xFF);
        break;
      case 1:
        ret[j] = static_cast<char>(ret[j] | ((c >> 4) & 0x3));
        ++j;
        ret[j] = static_cast<char>((c & 0xF) << 4);
        break;
      case 2:
        ret[j] = static_cast<char>(ret[j] | ((c >> 2) & 0xF));
        ++j;
        ret[j] = static_cast<char>((c & 0x3) << 6);
        break;
      case 3:
        ret[j] = static_cast<char>(ret[j] | c);
        ++j;
        break;
    }
  }

  return ret;
}

#ifdef NULL_PLUGIN

}  // namespace waf_deny
}  // namespace null_plugin
}  // namespace proxy_wasm

#endif
