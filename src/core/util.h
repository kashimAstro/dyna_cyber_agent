#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace agent::util {

inline bool startsWith(std::string_view s, std::string_view p) { return s.substr(0, p.size()) == p; }
inline bool endsWith(std::string_view s, std::string_view p) {
  return s.size() >= p.size() && s.substr(s.size() - p.size()) == p;
}

inline std::string_view trim(std::string_view s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\n' || s.front() == '\r')) s.remove_prefix(1);
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\n' || s.back() == '\r')) s.remove_suffix(1);
  return s;
}

// Splits on a single delimiter, keeping empty fields.
inline std::vector<std::string> split(std::string_view s, char d) {
  std::vector<std::string> out;
  size_t i = 0;
  while (true) {
    const size_t j = s.find(d, i);
    if (j == std::string_view::npos) {
      out.emplace_back(s.substr(i));
      return out;
    }
    out.emplace_back(s.substr(i, j - i));
    i = j + 1;
  }
}

// Splits on runs of spaces/tabs, dropping empty fields.
inline std::vector<std::string> splitWs(std::string_view s) {
  std::vector<std::string> out;
  size_t i = 0;
  while (i < s.size()) {
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
    size_t j = i;
    while (j < s.size() && s[j] != ' ' && s[j] != '\t') ++j;
    if (j > i) out.emplace_back(s.substr(i, j - i));
    i = j;
  }
  return out;
}

inline std::optional<uint64_t> parseUint(std::string_view s, int base = 10) {
  if (s.empty() || s.size() > 20) return std::nullopt;
  uint64_t v = 0;
  for (char c : s) {
    int d;
    if (c >= '0' && c <= '9') d = c - '0';
    else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
    else return std::nullopt;
    if (d >= base) return std::nullopt;
    if (v > (UINT64_MAX - static_cast<uint64_t>(d)) / static_cast<uint64_t>(base)) return std::nullopt;
    v = v * static_cast<uint64_t>(base) + static_cast<uint64_t>(d);
  }
  return v;
}

inline bool allDigits(std::string_view s) {
  if (s.empty()) return false;
  for (char c : s) if (c < '0' || c > '9') return false;
  return true;
}

inline std::string baseName(const std::string& p) {
  const size_t i = p.rfind('/');
  return i == std::string::npos ? p : p.substr(i + 1);
}

// Number of rwx mappings in the text of a /proc/<pid>/maps file.
int countRwxMappings(const std::string& maps);

// Lossy UTF-8 sanitiser: replaces invalid bytes so the string can go into JSON.
std::string toValidUtf8(const std::string& s);

}  // namespace agent::util
