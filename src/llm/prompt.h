#pragma once
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "analysis/finding.h"

namespace agent {

// True when text looks like instructions aimed at an LLM ("ignore previous instructions", fake roles...).
bool looksLikePromptInjection(const std::string& text);

// Compact, sanitised view of a finding for the model. `strict` trims harder (used when a finding is huge).
nlohmann::json findingForPrompt(const Finding& f, bool strict = false);

// JSON Schema of the reply (`max_findings` bounds the arrays).
nlohmann::json analysisSchema(size_t max_findings);

std::string systemPrompt(const std::string& language, const std::string& admin_focus);

struct PromptParts {
  std::string system;
  std::string user;
  std::vector<int64_t> finding_ids;
  size_t estimated_tokens = 0;
};

PromptParts buildPrompt(const std::string& target, const std::vector<Finding>& findings, const nlohmann::json& host_context,
                        const std::string& language, const std::string& admin_focus, bool strict = false);

// Rough token estimate for JSON-heavy text (deliberately pessimistic).
size_t estimateTokens(const std::string& s);

}  // namespace agent
