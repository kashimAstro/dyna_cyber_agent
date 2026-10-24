#pragma once
#include <optional>
#include <string>

namespace agent {

enum class Severity { Info = 0, Low = 1, Medium = 2, High = 3, Critical = 4 };

inline const char* toString(Severity s) {
  switch (s) {
    case Severity::Info: return "info";
    case Severity::Low: return "low";
    case Severity::Medium: return "medium";
    case Severity::High: return "high";
    case Severity::Critical: return "critical";
  }
  return "info";
}

inline std::optional<Severity> parseSeverity(const std::string& s) {
  for (int i = 0; i <= 4; ++i) {
    if (s == toString(static_cast<Severity>(i))) return static_cast<Severity>(i);
  }
  return std::nullopt;
}

}  // namespace agent
