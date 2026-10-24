#pragma once
#include <memory>
#include <regex>
#include <string>
#include <vector>

#include "analysis/finding.h"
#include "collectors/collector.h"
#include "core/result.h"

namespace agent {

// Condition tree over an observation's data: leaf (field/op/value) or all/any/not.
struct Condition {
  enum class Kind { Leaf, All, Any, Not };
  Kind kind = Kind::Leaf;
  std::string field;  // dotted path, e.g. "owners.0.comm"; arrays without an index fan out
  std::string op;
  nlohmann::json value;
  std::shared_ptr<std::regex> regex;  // compiled once at load time
  std::vector<Condition> children;

  bool eval(const nlohmann::json& data) const;
};

struct Rule {
  std::string id, title, description, remediation, source;
  Severity severity = Severity::Info;
  std::vector<std::string> mitre;
  std::vector<std::string> cwe;

  std::string type;
  std::vector<std::string> tags_any, tags_all;
  std::string drift;                     // "" = not required, "any", or a facet
  std::vector<std::string> drift_absent;  // facets that must NOT be drifting
  std::vector<Condition> where;          // all must hold

  bool matches(const Observation& o, const std::vector<Identity>& drift_set) const;
};

// Loading validates everything (ops, regexes, severities, facets, duplicate ids) so a typo
// in a rule fails at startup instead of silently never matching.
Result<std::vector<Rule>> parseRules(const std::string& yaml_text, const std::string& source);
Result<std::vector<Rule>> loadRulesDir(const std::string& dir);

}  // namespace agent
