#include "app/agent.h"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <thread>
#include <future>

#include "llm/assess.h"
#include "transport/factory.h"

namespace agent {
namespace {

// Collector state lives in the agent's database, under its own key prefix.
class StoreState final : public IStateStore {
 public:
  explicit StoreState(Store& s) : s_(s) {}
  std::optional<std::string> get(const std::string& key) override {
    auto r = s_.getMeta("state|" + key);
    return r && r.value() ? r.value() : std::nullopt;
  }
  void set(const std::string& key, const std::string& value) override { s_.setMeta("state|" + key, value); }

 private:
  Store& s_;
};

}  // namespace

Result<size_t> Agent::setup() {
  if (!state_) state_ = std::make_unique<StoreState>(*store_);
  if (auto b = store_->backfillSources(); b && b.value()) spdlog::info("attack map: {} past event(s) recovered from earlier findings", b.value());
  for (const auto& tc : cfg_.targets) {
    auto transport = makeTransport(tc);
    if (!transport) {
      spdlog::error("target {} skipped: {}", tc.name, transport.error());
      continue;
    }
    TargetRuntime rt;
    rt.name = tc.name;
    rt.transport = std::move(transport.value());

    std::vector<std::string> wanted = tc.collectors.empty() ? collectorNames() : tc.collectors;
    for (const auto& cname : wanted) {
      auto c = makeCollector(cname);
      if (!c) {
        spdlog::warn("target {}: collector '{}' not available, ignored", tc.name, cname);
        continue;
      }
      if (cname == "vulns" && !vuln_ctx_) {
        spdlog::debug("target {}: collector 'vulns' skipped (vuln.enabled is false)", tc.name);
        continue;
      }
      if (cname == "peers") {
        // peer analysis needs a group of enough members; without one the collector has nothing to do
        std::vector<std::string> members;
        for (const auto& other : cfg_.targets) if (!tc.group.empty() && other.group == tc.group) members.push_back(other.name);
        if (!cfg_.analysis.peers || members.size() < cfg_.analysis.peer_min_group) {
          if (!tc.group.empty()) spdlog::info("target {}: group '{}' has {} member(s), peer analysis needs {}: off", tc.name, tc.group, members.size(), cfg_.analysis.peer_min_group);
          continue;
        }
      }
      if (cname == "netflow" && !cfg_.analysis.beaconing && !cfg_.analysis.traffic_spikes) continue;
      CollectorOptions co;
      co.store = store_.get();
      co.beaconing = cfg_.analysis.beaconing;
      co.traffic_spikes = cfg_.analysis.traffic_spikes;
      {
        const auto ni = tc.intervals.find("network");
        co.network_interval = static_cast<int>(ni != tc.intervals.end() ? ni->second.count() : 15);
      }
      co.group = tc.group;
      for (const auto& other : cfg_.targets) if (!tc.group.empty() && other.group == tc.group) co.group_members.push_back(other.name);
      co.peer_min_group = cfg_.analysis.peer_min_group;
      co.peer_min_share = cfg_.analysis.peer_min_share;
      co.vuln = vuln_ctx_;
      co.target = tc.name;
      co.log_paths = tc.log_paths;
      co.log_backfill_kb = tc.log_backfill_kb;
      co.log_templates = cfg_.analysis.log_templates;
      co.log_templates_per_cycle = cfg_.analysis.log_templates_per_cycle;
      co.state = state_.get();
      c->configure(co);
      const auto it = tc.intervals.find(cname);
      const auto interval = it != tc.intervals.end() ? it->second : c->defaultInterval();
      rt.jobs.push_back({std::move(c), interval, std::chrono::steady_clock::now()});
    }
    if (rt.jobs.empty()) {
      spdlog::error("target {} skipped: no usable collectors", tc.name);
      continue;
    }
    targets_.push_back(std::move(rt));
  }
  if (targets_.empty()) return err("no runnable target");
  return targets_.size();
}

Snapshot Agent::execute(TargetRuntime& t, Job& j) {
  Snapshot s = runCollector(*j.collector, *t.transport, t.name);
  if (!s.error.empty()) spdlog::error("{}/{}: collection failed: {}", t.name, s.collector, s.error);
  else spdlog::debug("{}/{}: {} observation(s) in {} ms", t.name, s.collector, s.observations.size(), s.duration_ms);
  // Per-address activity goes to its own long-lived table, not into the (pruned) snapshot.
  if (s.collector == "logs") {
    std::vector<Store::SourceDelta> deltas;
    std::vector<Observation> rest;
    for (auto& o : s.observations) {
      if (o.type != "log.source") { rest.push_back(std::move(o)); continue; }
      Store::SourceDelta d;
      d.ip = o.data.value("src_ip", std::string());
      d.ssh_fail = o.data.value("ssh_fail", int64_t(0));
      d.ssh_ok = o.data.value("ssh_ok", int64_t(0));
      d.scans = o.data.value("scans", int64_t(0));
      d.web_hits = o.data.value("web_hits", int64_t(0));
      d.web_4xx = o.data.value("web_4xx", int64_t(0));
      if (o.data.contains("users")) d.users_json = o.data["users"].dump();
      if (!d.ip.empty()) deltas.push_back(std::move(d));
    }
    s.observations = std::move(rest);
    if (auto r = store_->recordSources(t.name, deltas, s.ts); !r) spdlog::error("{}/logs: cannot record attack sources: {}", t.name, r.error());
  }
  // Package installs/upgrades and the files each package owns go to their own tables (they would bloat the snapshot).
  if (s.collector == "packages") {
    std::vector<Store::PackageEvent> events;
    std::vector<Store::PackageFiles> files;
    std::vector<Observation> rest;
    for (auto& o : s.observations) {
      if (o.type != "pkg.change") { rest.push_back(std::move(o)); continue; }
      const auto& d = o.data;
      const std::string kind = d.value("kind", std::string());
      const std::string pkg = d.value("package", std::string());
      const int64_t ts = d.value("ts", int64_t(0));
      if (kind != "inventory") events.push_back({ts ? ts : s.ts, pkg, kind, d.value("old_version", std::string()), d.value("new_version", std::string())});
      if (d.contains("files") && d["files"].is_array() && kind != "removed") {
        Store::PackageFiles pf;
        pf.package = pkg;
        pf.ts = kind == "inventory" ? 0 : (ts ? ts : s.ts);
        for (const auto& f : d["files"]) if (f.is_string()) pf.paths.push_back(f.get<std::string>());
        files.push_back(std::move(pf));
      }
    }
    s.observations = std::move(rest);
    if (auto r = store_->recordPackageData(t.name, events, files); !r) spdlog::error("{}/packages: cannot record package changes: {}", t.name, r.error());
    else if (!events.empty()) spdlog::info("{}/packages: {} package change(s) recorded", t.name, events.size());
  }
  enricher_.apply(s);  // countries, coordinates, threat lists: before the rules and the stored copy see the observations
  if (auto r = store_->save(s); !r) spdlog::error("{}/{}: cannot store snapshot: {}", t.name, s.collector, r.error());
  if (s.collector == "network" && s.error.empty() && cfg_.analysis.beaconing) {
    const auto events = t.conn.update(s);
    if (auto r = store_->recordConnections(t.name, events); !r) spdlog::error("{}/network: cannot record connections: {}", t.name, r.error());
  }

  auto a = analyzer_.analyze(s);
  if (!a) {
    spdlog::error("{}/{}: analysis failed: {}", t.name, s.collector, a.error());
  } else {
    if (a.value().resolved) spdlog::info("{}/{}: {} finding(s) resolved (no longer present)", t.name, s.collector, a.value().resolved);
    if (a.value().learning) spdlog::debug("{}/{}: learning baseline ({} identities)", t.name, s.collector, a.value().learned);
    for (auto& f : a.value().fresh) {
      spdlog::warn("FINDING #{} [{}] {} {} on {} ({})", f.id, toString(f.severity), f.rule_id, f.title, f.target, f.stable_key);
      std::lock_guard<std::mutex> lock(mu_);
      new_findings_.push_back(std::move(f));
      // Group findings that arrive close together into one model call.
      if (reasoner_ && !llm_due_) llm_due_ = std::chrono::steady_clock::now() + cfg_.llm.batch_window;
    }
  }
  return s;
}

void Agent::updateIncidents() {
  if (!cfg_.analysis.incidents) return;
  const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
  auto r = incidents_.update(now);
  if (!r) spdlog::error("incidents: {}", r.error());
}

void Agent::scheduleLlm(std::optional<std::chrono::steady_clock::time_point> when) {
  std::lock_guard<std::mutex> lock(mu_);
  llm_due_ = when;
}

void Agent::assessNow() {
  if (!reasoner_) return;
  auto r = assessPending(*store_, *reasoner_, 50);
  if (!r) {
    spdlog::warn("LLM assessment skipped: {}", r.error());
    scheduleLlm(std::chrono::steady_clock::now() + std::chrono::minutes(10));  // try again later, findings stay stored
    return;
  }
  spdlog::info("LLM assessed {} finding(s) in {} call(s){}", r.value().assessed, r.value().analyses,
               r.value().missing ? ", " + std::to_string(r.value().missing) + " left unassessed" : "");
  scheduleLlm(r.value().missing ? std::optional(std::chrono::steady_clock::now() + std::chrono::minutes(10)) : std::nullopt);
}

std::vector<Snapshot> Agent::runOnce() {
  // One task per target: collectors of the same target stay sequential (a transport is not thread safe).
  std::vector<std::future<std::vector<Snapshot>>> futures;
  for (auto& t : targets_) {
    futures.push_back(std::async(std::launch::async, [this, &t] {
      std::vector<Snapshot> snaps;
      for (auto& j : t.jobs) snaps.push_back(execute(t, j));
      return snaps;
    }));
  }
  std::vector<Snapshot> out;
  for (auto& f : futures) {
    for (auto& s : f.get()) out.push_back(std::move(s));
  }
  return out;
}

void Agent::targetLoop(TargetRuntime& t, const std::atomic<bool>& stop) {
  using clock = std::chrono::steady_clock;
  while (!stop) {
    const auto now = clock::now();
    for (auto& j : t.jobs) {
      if (stop) return;
      if (j.next > now) continue;
      try {
        execute(t, j);
      } catch (const std::exception& e) {  // a bug in one collector must not take the whole target down
        spdlog::error("{}/{}: unexpected error: {}", t.name, j.collector->name(), e.what());
      }
      j.next = clock::now() + j.interval;
    }
    auto wake = clock::now() + std::chrono::seconds(60);
    for (const auto& j : t.jobs) wake = std::min(wake, j.next);
    while (!stop && clock::now() < wake) std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }
}

void Agent::run(const std::atomic<bool>& stop) {
  using clock = std::chrono::steady_clock;
  std::vector<std::thread> workers;
  for (auto& t : targets_) workers.emplace_back([this, &t, &stop] { targetLoop(t, stop); });
  spdlog::info("{} target worker(s) started", workers.size());

  auto next_prune = clock::now();
  auto next_mail = clock::now();
  auto next_incidents = clock::now();
  while (!stop) {
    if (reload_flag_ && reload_flag_->exchange(false) && reload_rules_) {
      auto r = reload_rules_();
      if (r) {
        analyzer_.replaceRules(std::move(r.value()));
        spdlog::info("rules reloaded: {} rule(s) active", analyzer_.ruleCount());
      } else {
        spdlog::error("rules NOT reloaded, keeping the current ones: {}", r.error());  // a typo must not leave the agent blind
      }
    }
    std::optional<clock::time_point> due;
    {
      std::lock_guard<std::mutex> lock(mu_);
      due = llm_due_;
    }
    if (reasoner_ && due && clock::now() >= *due) assessNow();
    if (clock::now() >= next_incidents) {
      updateIncidents();
      next_incidents = clock::now() + std::chrono::seconds(20);
    }
    if (notifier_ && clock::now() >= next_mail) {
      notifier_->tick();
      next_mail = clock::now() + std::chrono::seconds(5);
    }
    if (clock::now() >= next_prune) {
      const auto cutoff = std::chrono::system_clock::now() - std::chrono::hours(24 * cfg_.retention_days);
      const auto ts = std::chrono::duration_cast<std::chrono::seconds>(cutoff.time_since_epoch()).count();
      if (auto r = store_->prune(ts)) spdlog::info("pruned {} old snapshot(s)", r.value());
      else spdlog::error("{}", r.error());
      next_prune = clock::now() + std::chrono::hours(1);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
  }
  for (auto& w : workers) w.join();
}

}  // namespace agent
