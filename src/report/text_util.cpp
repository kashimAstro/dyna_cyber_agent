#include "report/text_util.h"

#include <algorithm>
#include <cctype>
#include <ctime>

#include "core/util.h"

namespace agent::report {
namespace {

std::string replaceCi(std::string s, const std::string& from, const std::string& to) {
  std::string lower = s;
  std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  size_t pos = 0;
  while ((pos = lower.find(from, pos)) != std::string::npos) {
    s.replace(pos, from.size(), to);
    lower.replace(pos, from.size(), to);
    pos += to.size();
  }
  return s;
}

void flatten(const nlohmann::json& j, const std::string& path, size_t max_rows, size_t max_val,
             std::vector<std::pair<std::string, std::string>>& out) {
  if (out.size() >= max_rows) return;
  if (j.is_null()) return;
  if (j.is_object()) {
    for (const auto& [k, v] : j.items()) flatten(v, path.empty() ? k : path + "." + k, max_rows, max_val, out);
    return;
  }
  std::string val;
  if (j.is_array()) {
    for (const auto& e : j) {
      if (!val.empty()) val += ", ";
      val += e.is_string() ? e.get<std::string>() : e.dump();
      if (val.size() > max_val) break;
    }
    if (val.empty()) return;
  } else if (j.is_string()) {
    val = j.get<std::string>();
  } else {
    val = j.dump();
  }
  out.emplace_back(sanitize(path, 80), sanitize(val, max_val));
}

}  // namespace

std::string sanitize(const std::string& in, size_t max_len) {
  const std::string valid = util::toValidUtf8(in);
  std::string s;
  s.reserve(valid.size());
  for (size_t i = 0; i < valid.size(); ++i) {
    const auto c = static_cast<unsigned char>(valid[i]);
    if (c < 0x20 || c == 0x7F) {
      s += ' ';
      continue;
    }
    if (c == 0xE2 && i + 2 < valid.size()) {  // U+200B-200F, U+202A-202E, U+2066-2069: zero-width and bidi controls
      const auto c1 = static_cast<unsigned char>(valid[i + 1]), c2 = static_cast<unsigned char>(valid[i + 2]);
      const bool zw = c1 == 0x80 && ((c2 >= 0x8B && c2 <= 0x8F) || (c2 >= 0xAA && c2 <= 0xAE));
      const bool iso = c1 == 0x81 && c2 >= 0xA6 && c2 <= 0xA9;
      if (zw || iso) {
        i += 2;
        continue;
      }
    }
    s += static_cast<char>(c);
  }
  s = replaceCi(s, "https://", "hxxps://");
  s = replaceCi(s, "http://", "hxxp://");
  s = replaceCi(s, "ftp://", "fxp://");
  if (s.size() > max_len) {
    s.resize(max_len);
    s = util::toValidUtf8(s) + "...";
  }
  return s;
}

std::string htmlEscape(const std::string& s) {
  std::string o;
  o.reserve(s.size() + s.size() / 8);
  for (char c : s) {
    switch (c) {
      case '&': o += "&amp;"; break;
      case '<': o += "&lt;"; break;
      case '>': o += "&gt;"; break;
      case '"': o += "&quot;"; break;
      case '\'': o += "&#39;"; break;
      default: o += c;
    }
  }
  return o;
}

std::string wrap(const std::string& text, size_t width, size_t indent) {
  const size_t room = width > indent + 10 ? width - indent : 20;
  std::vector<std::string> lines;
  for (const auto& para : util::split(text, '\n')) {
    std::string line;
    for (std::string w : util::splitWs(para)) {
      while (w.size() > room) {  // unbreakable token (path, hash): cut it
        if (!line.empty()) {
          lines.push_back(line);
          line.clear();
        }
        lines.push_back(w.substr(0, room));
        w = w.substr(room);
      }
      if (!line.empty() && line.size() + 1 + w.size() > room) {
        lines.push_back(line);
        line.clear();
      }
      line += (line.empty() ? "" : " ") + w;
    }
    lines.push_back(line);  // keeps blank lines between paragraphs
  }
  std::string out;
  for (size_t i = 0; i < lines.size(); ++i) {
    if (i) out += "\n" + (lines[i].empty() ? std::string() : std::string(indent, ' '));
    out += lines[i];
  }
  return out;
}

std::string fmtTime(int64_t ts) {
  const std::time_t t = static_cast<std::time_t>(ts);
  std::tm tm{};
  gmtime_r(&t, &tm);
  char b[40];
  std::strftime(b, sizeof(b), "%Y-%m-%d %H:%M:%S UTC", &tm);
  return b;
}

std::string fmtDate(int64_t ts) {
  const std::time_t t = static_cast<std::time_t>(ts);
  std::tm tm{};
  gmtime_r(&t, &tm);
  char b[16];
  std::strftime(b, sizeof(b), "%Y-%m-%d", &tm);
  return b;
}

std::string fmtAge(int64_t s) {
  if (s < 0) s = 0;
  if (s < 90) return std::to_string(s) + " s";
  if (s < 5400) return std::to_string(s / 60) + " min";
  if (s < 172800) return std::to_string(s / 3600) + " h";
  return std::to_string(s / 86400) + " d";
}

std::vector<std::pair<std::string, std::string>> flattenEvidence(const nlohmann::json& j, size_t max_rows, size_t max_val) {
  std::vector<std::pair<std::string, std::string>> out;
  flatten(j, "", max_rows, max_val, out);
  return out;
}

}  // namespace agent::report
