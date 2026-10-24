#include "core/util.h"

namespace agent::util {

int countRwxMappings(const std::string& maps) {
  int n = 0;
  size_t pos = 0;
  while (pos < maps.size()) {
    size_t eol = maps.find('\n', pos);
    if (eol == std::string::npos) eol = maps.size();
    const size_t sp = maps.find(' ', pos);
    if (sp != std::string::npos && sp < eol && maps.compare(sp + 1, 3, "rwx") == 0) ++n;
    pos = eol + 1;
  }
  return n;
}

std::string toValidUtf8(const std::string& s) {
  std::string out;
  out.reserve(s.size());
  size_t i = 0;
  while (i < s.size()) {
    const auto c = static_cast<unsigned char>(s[i]);
    size_t len = 0;
    if (c < 0x80) len = 1;
    else if (c >= 0xC2 && c <= 0xDF) len = 2;
    else if (c >= 0xE0 && c <= 0xEF) len = 3;
    else if (c >= 0xF0 && c <= 0xF4) len = 4;
    bool ok = len > 0 && i + len <= s.size();
    for (size_t k = 1; ok && k < len; ++k) ok = (static_cast<unsigned char>(s[i + k]) & 0xC0) == 0x80;
    if (ok) {
      out.append(s, i, len);
      i += len;
    } else {
      out += '?';
      ++i;
    }
  }
  return out;
}

}  // namespace agent::util
