#pragma once
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "core/result.h"

namespace agent {

// "Do not analyse this": a filter the administrator sets from the console. An excluded observation produces no finding
// (the collectors still read it, the baseline still learns it). Filters can be limited to one machine and can expire.
struct Exclusion {
  int64_t id = 0;
  std::string kind;     // rule | package | cve | port | user | ip | path | process
  std::string pattern;  // shell-style wildcards (* ?); for ip an address or an IPv4 CIDR; for port "22", "tcp/22", "8000-8100"
  std::string target;   // "" = every machine
  std::string note;
  int64_t created_at = 0, expires_at = 0;  // 0 = never expires
};

const std::vector<std::string>& exclusionKinds();

// Checks the pattern for the kind and returns it in its canonical form. Refuses what would blind the agent: a pattern made only
// of wildcards, the root account, a whole disk, a network wider than /8.
Result<std::string> normalizeExclusionPattern(const std::string& kind, const std::string& pattern);

// True when the filter excludes this observation. `rule_id` is the rule that matched it; `data` is the observation data
// (for a stored finding that is its evidence, which is the same thing).
bool exclusionMatches(const Exclusion& x, const std::string& target, const std::string& rule_id, const std::string& obs_type, const nlohmann::json& data);

class ExclusionSet {
 public:
  ExclusionSet() = default;
  explicit ExclusionSet(std::vector<Exclusion> rows) : rows_(std::move(rows)) {}
  bool empty() const { return rows_.empty(); }
  // The first filter that excludes it, or nullptr.
  const Exclusion* find(const std::string& target, const std::string& rule_id, const std::string& obs_type, const nlohmann::json& data) const;
  // For addresses seen outside an observation (the attack map).
  bool excludesAddress(const std::string& target, const std::string& ip) const;

 private:
  std::vector<Exclusion> rows_;
};

}  // namespace agent
