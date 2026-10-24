#include "vuln/cvss.h"

#include <algorithm>
#include <cmath>
#include <map>

#include "core/util.h"

namespace agent {
namespace {

// CVSS 3.1 "Roundup": smallest number, to one decimal, that is >= the input (robust against float noise).
double roundUp(double x) {
  const long long i = std::llround(x * 100000.0);
  if (i % 10000 == 0) return static_cast<double>(i) / 100000.0;
  return (static_cast<double>(i / 10000) + 1.0) / 10.0;
}

}  // namespace

std::optional<double> cvssV3Score(const std::string& vector) {
  if (!util::startsWith(vector, "CVSS:3.")) return std::nullopt;
  std::map<std::string, std::string> m;
  for (const auto& part : util::split(vector, '/')) {
    const size_t c = part.find(':');
    if (c != std::string::npos) m[part.substr(0, c)] = part.substr(c + 1);
  }
  auto pick = [&](const char* k, std::initializer_list<std::pair<const char*, double>> table) -> std::optional<double> {
    const auto it = m.find(k);
    if (it == m.end()) return std::nullopt;
    for (const auto& [name, v] : table) if (it->second == name) return v;
    return std::nullopt;
  };
  const auto scope = m.find("S");
  if (scope == m.end() || (scope->second != "U" && scope->second != "C")) return std::nullopt;
  const bool changed = scope->second == "C";
  const auto av = pick("AV", {{"N", 0.85}, {"A", 0.62}, {"L", 0.55}, {"P", 0.2}});
  const auto ac = pick("AC", {{"L", 0.77}, {"H", 0.44}});
  const auto pr = pick("PR", {{"N", 0.85}, {"L", changed ? 0.68 : 0.62}, {"H", changed ? 0.5 : 0.27}});
  const auto ui = pick("UI", {{"N", 0.85}, {"R", 0.62}});
  const auto c = pick("C", {{"H", 0.56}, {"L", 0.22}, {"N", 0.0}});
  const auto i = pick("I", {{"H", 0.56}, {"L", 0.22}, {"N", 0.0}});
  const auto a = pick("A", {{"H", 0.56}, {"L", 0.22}, {"N", 0.0}});
  if (!av || !ac || !pr || !ui || !c || !i || !a) return std::nullopt;

  const double iss = 1.0 - (1.0 - *c) * (1.0 - *i) * (1.0 - *a);
  const double impact = changed ? 7.52 * (iss - 0.029) - 3.25 * std::pow(iss - 0.02, 15) : 6.42 * iss;
  const double exploitability = 8.22 * *av * *ac * *pr * *ui;
  if (impact <= 0) return 0.0;
  return changed ? roundUp(std::min(1.08 * (impact + exploitability), 10.0)) : roundUp(std::min(impact + exploitability, 10.0));
}

std::string cvssSeverity(double s) {
  if (s <= 0.0) return "none";
  if (s < 4.0) return "low";
  if (s < 7.0) return "medium";
  if (s < 9.0) return "high";
  return "critical";
}

}  // namespace agent
