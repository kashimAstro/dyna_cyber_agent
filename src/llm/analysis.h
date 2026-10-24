#pragma once
#include <string>
#include <unordered_set>
#include <vector>

#include "core/result.h"
#include "core/severity.h"

namespace agent {

struct Assessment {
  int64_t finding_id = 0;
  std::string verdict;  // likely_malicious | suspicious | likely_benign | needs_more_data
  Severity risk = Severity::Info;
  int confidence = 0;   // 0..100
  std::string explanation;
  std::vector<std::string> recommended_actions;
  std::vector<std::string> additional_checks;
  std::vector<std::string> flags;  // set by the agent, never by the model (e.g. prompt_injection_suspected)
  int64_t created_at = 0;
};

struct Correlation {
  std::string title;
  std::string narrative;
  Severity risk = Severity::Info;
  std::vector<int64_t> finding_ids;
  std::vector<std::string> mitre;
};

struct Analysis {
  int64_t id = 0;
  std::string target;
  int64_t created_at = 0;
  std::string model;
  std::string summary;
  Severity overall_risk = Severity::Info;
  std::vector<Assessment> assessments;
  std::vector<Correlation> correlations;
  std::vector<int64_t> finding_ids;  // everything that was submitted in this call
  int prompt_tokens = 0;
  int completion_tokens = 0;
};

// Validates the model's JSON. The model output is untrusted: ids not in `allowed_ids` are dropped,
// enums are checked, strings are sanitised and length-capped. `dropped` counts discarded entries.
Result<Analysis> parseAnalysis(const std::string& json_text, const std::unordered_set<int64_t>& allowed_ids, size_t* dropped = nullptr);

}  // namespace agent
