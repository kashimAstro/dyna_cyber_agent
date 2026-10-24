#pragma once
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

#include <nlohmann/json.hpp>

#include "analysis/finding.h"
#include "llm/analysis.h"
#include "llm/prompt.h"

namespace agent {

// ONE summary per mail, written by the model after seeing everything the mail will contain.
struct Synthesis {
  struct Priority {
    std::string text;
    std::vector<int64_t> finding_ids;
  };
  std::string headline;  // one line: what the administrator must know
  std::string summary;   // a short paragraph
  std::vector<Priority> priorities;
  std::vector<Correlation> correlations;
  std::string model;
};

struct SynthesisItem {
  Finding finding;
  std::optional<Assessment> assessment;
  Severity effective = Severity::Info;
  bool is_new = false;
};

struct SynthesisInput {
  std::string kind = "alert";                 // alert | digest
  std::string host;
  std::vector<SynthesisItem> items;           // security findings featured in the mail (most severe first)
  nlohmann::json incidents = nlohmann::json::array();  // chains of related findings (title, stages, entities, finding ids, timeline)
  size_t items_omitted = 0;
  size_t carry_over = 0;                      // open findings already reported earlier
  nlohmann::json vulnerabilities;             // aggregate view of the vulnerability section (never the full list)
  std::vector<std::string> previous;          // headlines/summaries of the last mails: do not repeat them
};

nlohmann::json synthesisSchema();

PromptParts buildSynthesisPrompt(const SynthesisInput& in, const std::string& language, const std::string& admin_focus);

// The model output is untrusted: finding ids outside `allowed_ids` are dropped, strings sanitised and capped.
Result<Synthesis> parseSynthesis(const std::string& json_text, const std::unordered_set<int64_t>& allowed_ids);

}  // namespace agent
