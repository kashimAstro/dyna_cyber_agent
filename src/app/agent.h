#pragma once
#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

#include "analysis/analyzer.h"
#include "analysis/incident.h"
#include "collectors/collector.h"
#include "core/config.h"
#include "enrich/conn_tracker.h"
#include "enrich/enrich.h"
#include "llm/reasoner.h"
#include "report/notifier.h"
#include "store/store.h"
#include "transport/transport.h"
#include "vuln/vuln_context.h"

namespace agent {

inline AnalyzerOptions analyzerOptions(const Config& c) {
  AnalyzerOptions o;
  o.explain_updates = c.analysis.explain_updates;
  o.explain_window = c.analysis.explain_window;
  return o;
}

class Agent {
 public:
  Agent(Config cfg, std::unique_ptr<Store> store, std::vector<Rule> rules)
      : cfg_(std::move(cfg)),
        store_(std::move(store)),
        analyzer_(*store_, std::move(rules), cfg_.baseline_learning, analyzerOptions(cfg_)),
        incidents_(*store_, IncidentOptions{cfg_.analysis.incident_window, cfg_.analysis.incident_min_findings}),
        enricher_(*store_, cfg_.analysis) {}

  // Builds transports and collectors for every target. Targets that cannot be set up are skipped
  // with an error; fails only if nothing is runnable.
  Result<size_t> setup();

  // Runs every collector once on every target (targets in parallel); returns the snapshots taken.
  std::vector<Snapshot> runOnce();

  // Runs until `stop` becomes true: one worker thread per target (a slow or unreachable host never delays
  // the others) while this thread handles pruning, LLM assessment and mail.
  void run(const std::atomic<bool>& stop);

  // Rules are reloaded (without restarting) whenever `flag` is set; the flag is cleared afterwards.
  void setRuleReloader(std::atomic<bool>* flag, std::function<Result<std::vector<Rule>>()> loader) {
    reload_flag_ = flag;
    reload_rules_ = std::move(loader);
  }

  // Optional: enables LLM assessment of new findings (the Reasoner must outlive the Agent).
  void setReasoner(Reasoner* r) { reasoner_ = r; }
  // Optional: lets the `vulns` collector match inventories against the CVE database (must outlive the Agent).
  void setVulnContext(const VulnContext* v) { vuln_ctx_ = v; }

  // Optional: mails alerts and digests (must outlive the Agent).
  void setNotifier(Notifier* n) { notifier_ = n; }
  Notifier* notifier() { return notifier_; }

  // Optional local databases that enrich observations (countries, coordinates, threat lists). Must outlive the Agent.
  void setGeo(GeoDb* g) { enricher_.setGeo(g); }
  void setThreatIntel(ThreatIntel* t) { enricher_.setThreatIntel(t); }

  // Chains the open findings into incidents (no-op when analysis.incidents is off). Cheap; called every few seconds.
  void updateIncidents();

  // Assess every open finding that has no assessment yet. No-op without a Reasoner.
  void assessNow();

  // Findings first seen since the last call (oldest first).
  std::vector<Finding> takeNewFindings() {
    std::lock_guard<std::mutex> lock(mu_);
    return std::exchange(new_findings_, {});
  }

 private:
  struct Job {
    std::unique_ptr<ICollector> collector;
    std::chrono::seconds interval;
    std::chrono::steady_clock::time_point next;
  };
  struct TargetRuntime {
    std::string name;
    std::unique_ptr<ITransport> transport;
    std::vector<Job> jobs;
    ConnTracker conn;  // new outbound connections, from the `network` snapshots (beaconing)
  };

  Snapshot execute(TargetRuntime& t, Job& j);
  void targetLoop(TargetRuntime& t, const std::atomic<bool>& stop);
  void scheduleLlm(std::optional<std::chrono::steady_clock::time_point> when);

  std::unique_ptr<IStateStore> state_;  // persistent memory for collectors (log offsets, journal cursors)
  Config cfg_;
  std::unique_ptr<Store> store_;
  Analyzer analyzer_;
  IncidentEngine incidents_;
  Enricher enricher_;
  std::mutex mu_;  // guards new_findings_ and llm_due_ (touched by the target threads and the main thread)
  std::vector<Finding> new_findings_;
  const VulnContext* vuln_ctx_ = nullptr;
  std::atomic<bool>* reload_flag_ = nullptr;
  std::function<Result<std::vector<Rule>>()> reload_rules_;
  Reasoner* reasoner_ = nullptr;
  Notifier* notifier_ = nullptr;
  std::optional<std::chrono::steady_clock::time_point> llm_due_;  // when the next LLM pass is allowed to run
  std::vector<TargetRuntime> targets_;
};

}  // namespace agent
