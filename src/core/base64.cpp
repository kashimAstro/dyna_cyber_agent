#include "core/base64.h"

#include <cstdint>

namespace agent {

std::string base64Encode(const std::string& in, size_t line_len) {
  static const char* t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out, line;
  auto push = [&](char c) {
    line += c;
    if (line_len && line.size() == line_len) {
      out += line + "\r\n";
      line.clear();
    }
  };
  size_t i = 0;
  while (i + 2 < in.size()) {
    const uint32_t v = (static_cast<uint8_t>(in[i]) << 16) | (static_cast<uint8_t>(in[i + 1]) << 8) | static_cast<uint8_t>(in[i + 2]);
    push(t[v >> 18]); push(t[(v >> 12) & 63]); push(t[(v >> 6) & 63]); push(t[v & 63]);
    i += 3;
  }
  if (i + 1 == in.size()) {
    const uint32_t v = static_cast<uint8_t>(in[i]) << 16;
    push(t[v >> 18]); push(t[(v >> 12) & 63]); push('='); push('=');
  } else if (i + 2 == in.size()) {
    const uint32_t v = (static_cast<uint8_t>(in[i]) << 16) | (static_cast<uint8_t>(in[i + 1]) << 8);
    push(t[v >> 18]); push(t[(v >> 12) & 63]); push(t[(v >> 6) & 63]); push('=');
  }
  if (!line.empty()) out += line_len ? line + "\r\n" : line;  // unwrapped output has no line ends
  return out;
}

std::optional<std::string> base64Decode(const std::string& in) {
  std::string out;
  out.reserve(in.size() / 4 * 3);
  uint32_t val = 0;
  int bits = -8;
  for (unsigned char c : in) {
    int d;
    if (c >= 'A' && c <= 'Z') d = c - 'A';
    else if (c >= 'a' && c <= 'z') d = c - 'a' + 26;
    else if (c >= '0' && c <= '9') d = c - '0' + 52;
    else if (c == '+') d = 62;
    else if (c == '/') d = 63;
    else if (c == '=' || c == '\r' || c == '\n' || c == ' ') continue;
    else return std::nullopt;
    val = (val << 6) | static_cast<uint32_t>(d);
    bits += 6;
    if (bits >= 0) {
      out += static_cast<char>((val >> bits) & 0xFF);
      bits -= 8;
    }
  }
  return out;
}

}  // namespace agent
