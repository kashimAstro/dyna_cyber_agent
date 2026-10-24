#include "llm/assess.h"

#include <spdlog/spdlog.h>

#include <map>
#include <unordered_set>

#include "llm/context.h"

namespace agent {

Result<AssessStats> assessPending(Store& store, Reasoner& reasoner, size_t limit) {
  auto pending = store.listUnassessed(limit);
  if (!pending) return err(pending.error());
  AssessStats stats;
  if (pending.value().empty()) return stats;

  std::map<std::string, std::vector<Finding>> by_target;
  for (auto& f : pending.value()) by_target[f.target].push_back(std::move(f));

  std::string last_error;
  size_t attempted = 0;
  for (auto& [target, findings] : by_target) {
    attempted += findings.size();
    auto r = reasoner.analyze(target, std::move(findings), buildHostContext(store, target));
    if (!r) {
      last_error = r.error();
      spdlog::warn("LLM analysis for {} failed: {}", target, last_error);
      continue;
    }
    for (auto& a : r.value()) {
      auto id = store.saveAnalysis(a);
      if (!id) {
        spdlog::error("cannot store analysis: {}", id.error());
        continue;
      }
      ++stats.analyses;
      stats.assessed += a.assessments.size();
      spdlog::info("LLM [{}] overall risk {}: {}", target, toString(a.overall_risk), a.summary);
      for (const auto& c : a.correlations) spdlog::warn("LLM [{}] correlation ({}): {}", target, toString(c.risk), c.title);
    }
  }
  stats.missing = attempted > stats.assessed ? attempted - stats.assessed : 0;
  if (stats.analyses == 0) return err(last_error.empty() ? "no analysis produced" : last_error);
  return stats;
}

}  // namespace agent
