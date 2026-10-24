#include "collectors/log_templates.h"

#include <algorithm>
#include <cctype>
#include <cstring>

#include "core/sha256.h"
#include "core/util.h"

namespace agent {
namespace {

constexpr size_t kMaxTokens = 14;

bool hasDigit(const std::string& s) { return std::any_of(s.begin(), s.end(), [](unsigned char c) { return std::isdigit(c) != 0; }); }
bool allHex(const std::string& s) { return !s.empty() && std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::isxdigit(c) != 0; }); }
bool hasLetter(const std::string& s) { return std::any_of(s.begin(), s.end(), [](unsigned char c) { return std::isalpha(c) != 0; }); }

std::string lower(std::string s) {
  for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

// One token -> itself or a placeholder. Surrounding punctuation is kept so "(pid=123)," keeps its shape.
std::string maskToken(const std::string& tok) {
  size_t b = 0, e = tok.size();
  while (b < e && std::strchr("([{<\"'", tok[b])) ++b;
  while (e > b && std::strchr(")]}>,;:.\"'", tok[e - 1])) --e;
  if (b >= e) return tok;
  const std::string core = tok.substr(b, e - b);
  const std::string pre = tok.substr(0, b), post = tok.substr(e);
  std::string m;
  const size_t eq = core.find('=');
  if (eq != std::string::npos && eq > 0 && eq + 1 < core.size()) {
    m = core.substr(0, eq + 1) + "<*>";                       // key=value: the key is the shape, the value varies
  } else if (core[0] == '/' || core.find('/') != std::string::npos) {
    m = "<path>";
  } else if (hasDigit(core)) {
    m = "<*>";
  } else if (allHex(core) && core.size() >= 6) {
    m = "<*>";
  } else if (core.find('.') != std::string::npos && hasLetter(core) && core.size() >= 6) {
    m = "<host>";                                             // host.example.com, file.name.ext
  } else {
    m = core;
  }
  return pre + m + post;
}

}  // namespace

std::string logTemplate(const std::string& message) {
  std::string out;
  size_t count = 0;
  std::string prev;
  for (const auto& raw : util::splitWs(message)) {
    if (++count > kMaxTokens) {
      out += " ...";
      break;
    }
    const std::string t = maskToken(raw);
    if (t == prev && (t == "<*>" || t == "<path>" || t == "<host>")) continue;  // runs of the same placeholder collapse
    prev = t;
    out += (out.empty() ? "" : " ") + t;
  }
  return out;
}

std::string logTemplateId(const std::string& program, const std::string& tmpl) { return Sha256::hex(program + "|" + tmpl).substr(0, 12); }

bool logAlarming(const std::string& tmpl) {
  static const char* words[] = {"error",   "out of memory", "oom", "killed process", "protection fault", "fail",     "denied",   "refused",  "invalid", "unauthorized", "violation", "attack",  "exploit", "overflow",
                                "segfault", "panic",    "fatal",    "corrupt",  "forbidden", "backdoor",   "rootkit",   "malware", "illegal", "intrusion",
                                "suspicious", "tamper", "not permitted", "permission", "authentication", "unexpected", "crash", "abort", "blocked"};
  const std::string l = lower(tmpl);
  return std::any_of(std::begin(words), std::end(words), [&](const char* w) { return l.find(w) != std::string::npos; });
}

bool logNoise(const std::string& program, const std::string& message) {
  (void)program;
  return util::startsWith(message, "-- MARK --") || util::startsWith(message, "last message repeated") || message.empty();
}

}  // namespace agent
