#pragma once
#include <deque>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "collectors/collector.h"
#include "collectors/log_parsers.h"

namespace agent {

struct LogAnalyzerOptions {
  int bruteforce_threshold = 8;       // failed logins from one address inside the window
  int64_t window_seconds = 600;
  int web_scan_threshold = 40;        // 4xx answers to one address inside the window
  size_t max_observations = 300;      // per drain; the rest is dropped with a warning
  size_t max_sources = 1500;          // per drain: distinct source addresses reported (busiest first)
  bool templates = false;             // learn the shape of every message no parser understood, report shapes never seen before
  size_t max_templates = 25;          // new shapes reported per drain (the rest wait for the next one)
};

// Turns log lines into observations. It owns the sliding windows that make "N failures in 10 minutes" possible,
// and knows nothing about files or transports. Event time is the collection time: the target's timezone and the
// missing year of syslog timestamps never matter.
class LogAnalyzer {
 public:
  explicit LogAnalyzer(LogAnalyzerOptions o = {}) : o_(o) {}

  void feedAuth(const std::string& file, const std::vector<std::string>& lines, int64_t now);
  void feedKernel(const std::string& file, const std::vector<std::string>& lines, int64_t now);
  void feedWeb(const std::string& file, const std::vector<std::string>& lines, int64_t now);
  // Lines of a general log (syslog, messages, journal) that no dedicated parser covers: only the templates are learned.
  void feedGeneric(const std::string& file, const std::vector<std::string>& lines, int64_t now);

  void setTemplates(bool enabled, size_t per_drain) {
    o_.templates = enabled;
    o_.max_templates = per_drain;
  }
  // Remembers which templates were already reported across restarts (otherwise every start would report them all again).
  void attachState(class IStateStore* st, std::string key) {
    state_ = st;
    state_key_ = std::move(key);
  }

  // Observations accumulated since the previous call.
  std::vector<Observation> drain(int64_t now, std::vector<std::string>* warnings = nullptr);

 private:
  struct Fail { int64_t ts; std::string user; bool invalid; };
  struct WebAgg {
    int64_t count = 0, success = 0;
    std::map<int, int64_t> statuses;
    std::string sample_uri, ua, file, ip, category;
  };
  struct Counted { Observation obs; int64_t count = 0; };
  // Every address that touched the machine since the last drain, however few the attempts: this is the raw
  // material of the attack map (the rules above only fire above their thresholds).
  struct SourceAgg {
    int64_t ssh_fail = 0, ssh_ok = 0, scans = 0, web_hits = 0, web_4xx = 0;
    std::set<std::string> users;
  };
  SourceAgg& source(const std::string& ip) { return sources_[ip]; }

  struct Tmpl { std::string program, tmpl, sample, file; int64_t count = 0; bool alarming = false; };
  void noteLine(const SyslogLine& sl, const std::string& file);
  void loadTemplateState();
  void addCounted(Observation o);
  void prune(int64_t now);

  LogAnalyzerOptions o_;
  std::map<std::string, std::deque<Fail>> failures_;      // ip -> failures inside the window
  std::map<std::string, std::deque<int64_t>> web_errors_;  // ip -> 4xx timestamps inside the window
  std::set<std::string> new_failure_ips_, new_web_error_ips_;
  std::map<std::string, std::string> success_after_;      // ip -> user that logged in after failures
  std::map<std::string, int64_t> auth_scans_;
  std::map<std::string, std::string> auth_scan_detail_;
  std::map<std::string, SourceAgg> sources_;
  std::map<std::string, Counted> events_;                  // key -> observation (+ repeat count)
  std::map<std::string, WebAgg> web_;
  std::map<std::string, std::set<std::string>> web_paths_;  // ip -> distinct paths in this batch (capped)
  std::map<std::string, Tmpl> pending_templates_;            // id -> template seen but not reported yet
  std::set<std::string> reported_templates_;                  // ids already reported (persisted)
  bool templates_loaded_ = false, templates_dirty_ = false;
  IStateStore* state_ = nullptr;
  std::string state_key_;
};

}  // namespace agent
