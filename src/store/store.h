#pragma once
#include <memory>
#include <mutex>
#include <optional>
#include <string>

#include "analysis/finding.h"
#include "collectors/collector.h"
#include "llm/analysis.h"

struct sqlite3;

namespace agent {

// Agent-side state (snapshots). Lives on the machine running the agent, never on the target.
class Store {
 public:
  static Result<std::unique_ptr<Store>> open(const std::string& path);  // ":memory:" allowed
  ~Store();
  Store(const Store&) = delete;
  Store& operator=(const Store&) = delete;

  Result<int64_t> save(const Snapshot& s);
  // Latest snapshot of a collector that did not fail.
  Result<std::optional<Snapshot>> latest(const std::string& target, const std::string& collector);
  Result<size_t> prune(int64_t older_than_ts);

  // --- baseline ---------------------------------------------------------
  struct BaselineMeta {
    int64_t started_at = 0;
    bool locked = false;
  };
  // Creates the record (started_at = now) the first time a target is seen.
  Result<BaselineMeta> baselineMeta(const std::string& target, int64_t now);
  Result<bool> lockBaseline(const std::string& target, int64_t now);
  Result<bool> inBaseline(const std::string& target, const Identity& id);
  Result<bool> addToBaseline(const std::string& target, const std::vector<Identity>& ids, int64_t ts);
  Result<size_t> baselineSize(const std::string& target);
  // When the first item of this facet entered the baseline (nullopt: the facet was never learned on this target).
  Result<std::optional<int64_t>> facetFirstSeen(const std::string& target, const std::string& facet);

  // --- findings ---------------------------------------------------------
  struct UpsertResult {
    int64_t id = 0;
    bool is_new = false;
    std::string status;
  };
  // When a finding with this fingerprint first appeared (nullopt: never seen).
  Result<std::optional<int64_t>> firstSeenOf(const std::string& fingerprint);
  // True when an open package-integrity finding of the target names this path (the package does not vouch for it).
  Result<bool> integrityFlagged(const std::string& target, const std::string& path);
  // Findings are deduplicated by fingerprint: a repeat only bumps last_seen/occurrences.
  Result<UpsertResult> upsertFinding(const Finding& f);
  Result<std::optional<Finding>> getFinding(int64_t id);
  Result<std::vector<Finding>> listFindings(const std::string& status, size_t limit);  // status "" = any
  // Open findings that no model analysis has covered yet, most severe first.
  Result<std::vector<Finding>> listUnassessed(size_t limit);

  // --- LLM analyses -----------------------------------------------------
  Result<int64_t> saveAnalysis(const Analysis& a);
  Result<std::optional<Assessment>> latestAssessment(int64_t finding_id);
  Result<std::vector<Analysis>> listAnalysesSince(int64_t ts);  // with assessments and correlations

  // --- notifications ----------------------------------------------------
  // Open findings never included in an alert mail, most severe first.
  Result<std::vector<Finding>> listUnalerted(size_t limit);
  Result<bool> markAlerted(const std::vector<int64_t>& finding_ids, int64_t notification_id, int64_t ts);
  struct Notification {
    int64_t id = 0;
    std::string kind;    // alert | digest | test
    int64_t created_at = 0;
    std::string subject;
    std::string recipients;
    std::string status;  // sent | failed
    std::string error;
    std::vector<int64_t> finding_ids;
    std::string summary;  // the AI headline/summary the mail carried: the next mail is told not to repeat it
  };
  // Summaries of the most recent mails that were really sent (newest first), for the "do not repeat" context.
  Result<std::vector<std::pair<int64_t, std::string>>> recentSummaries(int64_t since, size_t limit);
  Result<int64_t> recordNotification(const Notification& n);
  Result<std::optional<int64_t>> lastNotificationTime(const std::string& kind, const std::string& status);
  Result<size_t> countNotifications(const std::string& kind, const std::string& status, int64_t since);
  Result<std::vector<Notification>> listNotifications(size_t limit);

  // --- attack sources: every address that touched a target (login attempts, scans, web probes) -----------------
  struct SourceDelta {
    std::string ip, users_json = "[]";
    int64_t ssh_fail = 0, ssh_ok = 0, scans = 0, web_hits = 0, web_4xx = 0;
  };
  struct SourceRow {
    std::string ip;
    int64_t first_ts = 0, last_ts = 0, ssh_fail = 0, ssh_ok = 0, scans = 0, web_hits = 0, web_4xx = 0;
    std::vector<std::string> targets, users;
  };
  // Adds counters (not replaces): the collector reports what happened since its previous report.
  Result<size_t> recordSources(const std::string& target, const std::vector<SourceDelta>& deltas, int64_t ts);
  // Totals per address since `since` (0 = everything), busiest first; `target` empty = all targets.
  Result<std::vector<SourceRow>> listSources(int64_t since, const std::string& target, size_t limit);
  // One-off: rebuilds history from findings recorded before sources were tracked (idempotent).
  Result<size_t> backfillSources();

  // --- package changes and file ownership (what the packages collector saw; explains "new" things after an upgrade) ---
  struct PackageEvent {
    int64_t ts = 0;
    std::string package, kind, old_version, new_version;  // kind: installed | upgraded | removed
  };
  struct PackageFiles {
    std::string package;
    int64_t ts = 0;  // when this version was installed (0 = it was already there when monitoring started)
    std::vector<std::string> paths;
  };
  struct PackageOwner {
    std::string package;
    int64_t changed_at = 0;
  };
  // Events are appended; the file list of every package named in `files` replaces its previous one.
  Result<bool> recordPackageData(const std::string& target, const std::vector<PackageEvent>& events, const std::vector<PackageFiles>& files);
  Result<std::optional<PackageOwner>> packageOwning(const std::string& target, const std::string& path);
  Result<std::optional<PackageEvent>> lastPackageEvent(const std::string& target, const std::string& package);
  Result<std::vector<PackageEvent>> packageEvents(const std::string& target, int64_t since, size_t limit);
  Result<size_t> packageFileCount(const std::string& target);

  // --- baseline contents (peer comparison) ---
  Result<std::vector<Identity>> baselineOf(const std::string& target, const std::vector<std::string>& facets);

  // --- incidents: findings chained by what they share (address, account, binary...) ---
  struct IncidentRow {
    int64_t id = 0;
    int64_t created_at = 0, updated_at = 0, first_ts = 0, last_ts = 0;
    Severity severity = Severity::Info;
    std::string title, status = "open";  // open | resolved
    nlohmann::json targets = nlohmann::json::array(), entities = nlohmann::json::array(), stages = nlohmann::json::array();
    std::vector<int64_t> finding_ids;
  };
  // Inserts (id == 0) or updates the row and makes `finding_ids` its exact membership.
  Result<int64_t> saveIncident(const IncidentRow& row);
  Result<std::optional<IncidentRow>> getIncident(int64_t id);
  Result<std::vector<IncidentRow>> listIncidents(const std::string& status, size_t limit);  // status "" = any; newest activity first
  Result<std::optional<int64_t>> incidentOfFinding(int64_t finding_id);
  Result<bool> deleteIncident(int64_t id);

  // --- logins (impossible travel, new countries) ---
  struct LoginRecord {
    int64_t ts = 0;
    std::string target, user, ip, cc;
    double lat = 0, lon = 0;
    bool located = false;
  };
  Result<bool> recordLogin(const LoginRecord& r);
  Result<std::optional<LoginRecord>> lastLocatedLogin(const std::string& user, int64_t before_ts);

  // --- outbound connections: one row per new connection seen (beaconing) ---
  struct ConnEvent {
    std::string dest, comm;
    int port = 0;
    int64_t ts = 0;
  };
  Result<bool> recordConnections(const std::string& target, const std::vector<ConnEvent>& events);
  struct ConnSeries {
    std::string dest, comm;
    int port = 0;
    std::vector<int64_t> times;  // ascending
  };
  // Destinations with at least `min_events` new connections since `since`.
  Result<std::vector<ConnSeries>> connectionSeries(const std::string& target, int64_t since, size_t min_events);

  Result<std::optional<std::string>> getMeta(const std::string& key);
  Result<bool> setMeta(const std::string& key, const std::string& value);

  // Per target/collector: how often collection worked since `since` (a silent collector is a signal too).
  struct CollectorHealth {
    std::string target, collector;
    int64_t last_ok = 0, last_error_ts = 0;
    std::string last_error;
    int64_t ok_count = 0, error_count = 0;
  };
  Result<std::vector<CollectorHealth>> collectorHealth(int64_t since);

  // --- lifecycle: open -> resolved (the condition disappeared) -> open again if it comes back ---
  Result<std::vector<std::pair<int64_t, std::string>>> openFingerprints(const std::string& target, const std::string& collector);  // (id, fingerprint)
  Result<size_t> resolveFindings(const std::vector<int64_t>& ids, int64_t ts);
  Result<size_t> countResolvedSince(int64_t ts);

  // Marks a finding accepted and adds its drift identities to the target's baseline.
  Result<bool> acceptFinding(int64_t id, int64_t now);

 private:
  explicit Store(sqlite3* db) : db_(db) {}
  Result<bool> exec(const char* sql);

  sqlite3* db_;
  mutable std::recursive_mutex mu_;  // one connection shared by the target threads: every public call is serialised
};

}  // namespace agent
