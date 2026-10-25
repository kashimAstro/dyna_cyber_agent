#pragma once
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

#include <nlohmann/json.hpp>

#include "llm/analysis.h"
#include "llm/prompt.h"

namespace agent {

// A free question from the administrator, answered from facts the agent collected (see app/ask.h).
struct AskInput {
  std::string question;
  nlohmann::json facts;
  std::vector<int64_t> finding_ids;  // the findings present in `facts`
};

struct AskAnswer {
  std::string answer;
  std::string data_gaps;             // what the data does not allow to say
  std::vector<int64_t> finding_ids;  // findings the answer relies on
  std::string model;
};

nlohmann::json askSchema();

// `language` is the model-facing name ("italiano" / "english").
PromptParts buildAskPrompt(const AskInput& in, const std::string& language, const std::string& admin_focus);

// The reply is untrusted: ids outside `allowed_ids` are dropped, strings sanitised, a cut answer ends at a full sentence.
Result<AskAnswer> parseAskAnswer(const std::string& json_text, const std::unordered_set<int64_t>& allowed_ids);

}  // namespace agent
