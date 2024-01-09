#include "extensions/waf_deny/transformations/url_transformation.h"

#ifdef NULL_PLUGIN

namespace proxy_wasm {
namespace null_plugin {
namespace waf_deny {

#endif

std::string URLTransformation::transform(const std::string& data) {
  return decode(data);
}

const std::string upperhex = "0123456789ABCDEF";

bool URLTransformation::shouldEscape(char c) {
  if (('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') ||
      ('0' <= c && c <= '9')) {
    return false;
  }

  switch (c) {
    case '-':
    case '_':
    case '.':
    case '~':
      return false;

    case '$':
    case '&':
    case '+':
    case ',':
    case '/':
    case ':':
    case ';':
    case '=':
    case '?':
    case '@':
      return true;
  }

  return true;
}

std::string URLTransformation::encode(const std::string& data) {
  size_t space_count = 0, hex_count = 0;
  for (size_t i = 0; i < data.length(); i++) {
    char c = data[i];
    if (shouldEscape(c)) {
      if (c == ' ') {
        space_count++;
      } else {
        hex_count++;
      }
    }
  }

  if (space_count == 0 && hex_count == 0) {
    return data;
  }

  std::string ret;

  if (hex_count == 0) {
    ret = data;
    for (size_t i = 0; i < ret.size(); i++) {
      if (data[i] == ' ') {
        ret[i] = '+';
      }
    }
    return ret;
  }

  ret.resize(data.size() + 2 * hex_count);

  size_t j = 0;
  for (size_t i = 0; i < data.size(); i++) {
    char c = data[i];

    if (c == ' ') {
      ret[j++] = '+';
    } else if (shouldEscape(c)) {
      ret[j] = '%';
      ret[j + 1] = upperhex[c >> 4];
      ret[j + 2] = upperhex[c & 15];
      j += 3;
    } else {
      ret[j++] = c;
    }
  }
  return ret;
}

int URLTransformation::unhex(char c) {
  if ('0' <= c && c <= '9') {
    return c - '0';
  } else if ('a' <= c && c <= 'f') {
    return c - 'a' + 10;
  } else if ('A' <= c && c <= 'F') {
    return c - 'A' + 10;
  }
  return 0;
}

std::string URLTransformation::decode(const std::string& data) {
  size_t n = 0;
  std::string s = data;
  bool has_plus = false;
  for (size_t i = 0; i < s.size();) {
    switch (s[i]) {
      case '%':
        n++;
        if (i + 2 >= s.size() || !isxdigit(s[i + 1]) || !isxdigit(s[i + 2])) {
          return "";
        }
        i += 3;
        break;
      case '+':
        has_plus = true;  // no break
      default:
        i++;
        break;
    }
  }

  if (n == 0 && !has_plus) {
    return data;
  }

  std::string ret;

  for (size_t i = 0; i < s.size(); i++) {
    switch (s[i]) {
      case '%':
        ret += static_cast<char>(unhex(s[i + 1]) << 4 | unhex(s[i + 2]));
        i += 2;
        break;
      case '+':
        ret += " ";
        break;
      default:
        ret += s[i];
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
