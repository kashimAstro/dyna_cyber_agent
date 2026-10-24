#pragma once
#include <chrono>
#include <string>
#include <vector>

#include "analysis/finding.h"
#include "llm/analysis.h"
#include "llm/llm_client.h"
#include "llm/synthesis.h"

namespace agent {

struct ReasonerOptions {
  std::string language = "italiano";
  std::string admin_focus;
  size_t max_findings_per_call = 8;
  size_t context_tokens = 32768;
  int max_tokens = 4096;
  int max_retries = 2;                              // on transport / server errors
  std::chrono::milliseconds retry_delay{2000};
  int breaker_threshold = 3;                        // consecutive failed calls before backing off
  std::chrono::seconds breaker_pause{300};
  int synthesis_max_tokens = 1800;
  std::chrono::seconds synthesis_timeout{180};
};

// Asks the model to assess findings. Never invents results: whatever it cannot assess stays unassessed.
class Reasoner {
 public:
  Reasoner(LlmClient& client, ReasonerOptions opts) : client_(client), opts_(std::move(opts)) {}

  // Findings of ONE target. Returns one Analysis per successful model call; may be partial.
  Result<std::vector<Analysis>> analyze(const std::string& target, std::vector<Finding> findings, const nlohmann::json& host_context);

  // One report for a whole mail (see Synthesis). Fails when the model is unreachable or its reply is unusable.
  Result<Synthesis> synthesize(const SynthesisInput& in);

  // False while the circuit breaker is open (model unreachable): callers should not even try.
  bool available() const;

  const ReasonerOptions& options() const { return opts_; }

 private:
  Result<std::vector<Analysis>> runBatch(const std::string& target, const std::vector<Finding>& batch, const nlohmann::json& ctx, int depth);

  LlmClient& client_;
  ReasonerOptions opts_;
  int consecutive_failures_ = 0;
  std::chrono::steady_clock::time_point paused_until_{};
};

}  // namespace agent
