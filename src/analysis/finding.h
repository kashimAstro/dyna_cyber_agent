#pragma once
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "core/severity.h"

namespace agent {

// A baselined facet of an observation, e.g. {"net.listen", "tcp|0.0.0.0:22"}.
struct Identity {
  std::string facet;
  std::string key;
  bool operator==(const Identity& o) const { return facet == o.facet && key == o.key; }
};

struct Finding {
  int64_t id = 0;  // set once stored
  std::string fingerprint;
  std::string rule_id;
  std::string title;
  Severity severity = Severity::Info;
  std::string description;
  std::string remediation;
  std::vector<std::string> mitre;
  std::vector<std::string> cwe;  // weakness classes ("CWE-732"): from the rule, or from the CVE for vulnerability matches

  std::string target;
  std::string collector;
  std::string obs_type;
  std::string obs_key;
  std::string stable_key;
  std::vector<std::string> tags;
  std::vector<Identity> drift;  // facets that were not in the baseline
  nlohmann::json evidence;      // the observation's data

  int64_t first_seen = 0;
  int64_t last_seen = 0;
  int64_t occurrences = 1;
  std::string status = "open";  // open | accepted
};

}  // namespace agent
