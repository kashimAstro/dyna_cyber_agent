#include "analysis/analyzer.h"

#include <algorithm>
#include <map>
#include <set>

#include "analysis/explain.h"
#include "analysis/identity.h"

namespace agent {
namespace {

// Facets that belong to analyses which can be switched on (or become possible, like a geolocation database that
// arrives later) AFTER the baseline was locked. Their first day is a learning period of its own: otherwise turning
// the analysis on would report every country, beacon, eBPF program and log message shape the machine always had.
constexpr int64_t kLateFacetLearning = 24 * 3600;

bool lateFacet(const std::string& f) {
  return f == "net.country" || f == "auth.country" || f == "auth.hour" || f == "net.beacon" || f == "bpf.program" || f == "bpf.pinned" || f == "log.template";
}

}  // namespace

Result<AnalysisResult> Analyzer::analyze(const Snapshot& snap) {
  AnalysisResult res;
  if (!snap.error.empty()) return res;  // nothing trustworthy to analyse

  auto meta = store_.baselineMeta(snap.target, snap.ts);
  if (!meta) return err(meta.error());
  res.learning = !meta.value().locked && snap.ts < meta.value().started_at + learning_.count();

  std::shared_ptr<const std::vector<Rule>> rules;
  {
    std::lock_guard<std::mutex> lock(mu_);
    rules = rules_;
  }
  std::vector<Identity> to_learn;
  std::map<std::string, bool> late_learning;  // facet -> still inside its own first day (computed once per snapshot)
  std::set<std::string> seen;  // fingerprints present in this snapshot
  for (const auto& obs : snap.observations) {
    const auto ids = identitiesOf(obs);
    std::vector<Identity> drift;
    if (res.learning) {
      to_learn.insert(to_learn.end(), ids.begin(), ids.end());
    } else {
      for (const auto& id : ids) {
        auto known = store_.inBaseline(snap.target, id);
        if (!known) return err(known.error());
        if (known.value()) continue;
        if (lateFacet(id.facet)) {
          auto it = late_learning.find(id.facet);
          if (it == late_learning.end()) {
            auto first = store_.facetFirstSeen(snap.target, id.facet);
            if (!first) return err(first.error());
            it = late_learning.emplace(id.facet, !first.value() || snap.ts < *first.value() + kLateFacetLearning).first;
          }
          if (it->second) {
            to_learn.push_back(id);  // silently, like in the learning phase
            continue;
          }
        }
        drift.push_back(id);
      }
    }

    for (const auto& rule : *rules) {
      if (!rule.matches(obs, drift)) continue;
      Finding f;
      f.rule_id = rule.id;
      f.title = rule.title;
      f.severity = rule.severity;
      f.description = rule.description;
      f.remediation = rule.remediation;
      f.mitre = rule.mitre;
      f.cwe = rule.cwe;
      if (obs.type == "vuln.match" && obs.data.contains("cwes") && obs.data["cwes"].is_array()) {
        for (const auto& c : obs.data["cwes"]) if (c.is_object() && c.contains("id") && c["id"].is_string()) f.cwe.push_back(c["id"].get<std::string>());
      }
      f.target = snap.target;
      f.collector = snap.collector;
      f.obs_type = obs.type;
      f.obs_key = obs.key;
      f.stable_key = stableKey(obs);
      f.tags = obs.tags;
      f.drift = drift;
      f.evidence = obs.data;
      f.first_seen = f.last_seen = snap.ts;
      f.fingerprint = rule.id + "|" + snap.target + "|" + f.stable_key;

      // A new program / restarted service right after a package upgrade: say so (log events and vulnerabilities are not "things that appear").
      if (opts_.explain_updates && snap.collector != "logs" && snap.collector != "vulns" && snap.collector != "integrity" && snap.collector != "packages") {
        const auto first = store_.firstSeenOf(f.fingerprint);
        const int64_t first_seen = first && first.value() ? *first.value() : snap.ts;
        if (auto e = explainByUpdate(store_, snap.target, f.evidence, first_seen, opts_.explain_window)) applyExplanation(f, *e);
      }

      auto up = store_.upsertFinding(f);
      if (!up) return err(up.error());
      seen.insert(f.fingerprint);
      f.id = up.value().id;
      f.status = up.value().status;
      if (up.value().is_new) res.fresh.push_back(std::move(f));
      else if (f.status == "accepted") ++res.suppressed;
      else res.repeats.push_back(std::move(f));
    }
  }

  // State collectors describe the machine as it is now: a finding they no longer reproduce is resolved.
  // Event collectors (logs) describe history, so their findings stay until someone closes them.
  if (snap.collector != "logs") {
    auto open = store_.openFingerprints(snap.target, snap.collector);
    if (!open) return err(open.error());
    std::vector<int64_t> gone;
    for (const auto& [id, fp] : open.value()) if (!seen.count(fp)) gone.push_back(id);
    if (!gone.empty()) {
      auto r = store_.resolveFindings(gone, snap.ts);
      if (!r) return err(r.error());
      res.resolved = r.value();
    }
  }

  if (res.learning || !to_learn.empty()) {
    // Deduplicate before the write: a busy host repeats the same identities many times.
    std::sort(to_learn.begin(), to_learn.end(), [](const Identity& a, const Identity& b) { return std::tie(a.facet, a.key) < std::tie(b.facet, b.key); });
    to_learn.erase(std::unique(to_learn.begin(), to_learn.end()), to_learn.end());
    res.learned = to_learn.size();
    if (auto r = store_.addToBaseline(snap.target, to_learn, snap.ts); !r) return err(r.error());
  }
  return res;
}

}  // namespace agent
