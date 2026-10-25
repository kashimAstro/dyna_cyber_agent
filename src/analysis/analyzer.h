#pragma once
#include <chrono>
#include <memory>
#include <mutex>
#include <vector>

#include "analysis/finding.h"
#include "analysis/rule.h"
#include "store/store.h"

namespace agent {

struct AnalysisResult {
  std::vector<Finding> fresh;    // findings seen for the first time (to alert on)
  std::vector<Finding> repeats;  // already known and open
  size_t suppressed = 0;         // matched but accepted by the admin
  size_t excluded = 0;           // matched but covered by an exclusion filter (settings page)
  bool learning = false;
  size_t learned = 0;            // identities added to the baseline in this pass
  size_t resolved = 0;           // open findings whose condition is gone from this (complete) snapshot
};

struct AnalyzerOptions {
  bool explain_updates = false;                         // tag findings that a recent package upgrade explains
  std::chrono::seconds explain_window{7 * 86400};
};

// Turns a snapshot into findings: baseline drift detection + rule evaluation.
class Analyzer {
 public:
  Analyzer(Store& store, std::vector<Rule> rules, std::chrono::seconds learning, AnalyzerOptions opts = {})
      : store_(store), rules_(std::make_shared<const std::vector<Rule>>(std::move(rules))), learning_(learning), opts_(opts) {}

  Result<AnalysisResult> analyze(const Snapshot& snap);

  // Rules can be replaced while the agent runs (SIGHUP); analyses already in progress keep the set they started with.
  void replaceRules(std::vector<Rule> rules) {
    auto fresh = std::make_shared<const std::vector<Rule>>(std::move(rules));
    std::lock_guard<std::mutex> lock(mu_);
    rules_ = std::move(fresh);
  }
  size_t ruleCount() const {
    std::lock_guard<std::mutex> lock(mu_);
    return rules_->size();
  }

 private:
  Store& store_;
  mutable std::mutex mu_;
  std::shared_ptr<const std::vector<Rule>> rules_;
  std::chrono::seconds learning_;
  AnalyzerOptions opts_;
};

}  // namespace agent
