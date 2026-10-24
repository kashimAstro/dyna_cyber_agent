#pragma once
#include <chrono>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

#include "core/config.h"
#include "llm/http_client.h"
#include "vuln/vuln_db.h"

namespace agent {

struct SyncReport {
  std::string feed;      // kev | nvd | cwe | epss
  bool ok = false;
  bool partial = false;  // interrupted or rate-limited: the next run resumes where this one stopped
  std::string message;
  int64_t items = 0;
  std::vector<std::string> new_kev;  // CVEs that entered the CISA KEV catalog since the previous sync
};

struct SyncHooks {
  std::string nvd_api_key;
  std::function<void(std::chrono::milliseconds)> sleep;  // default: really sleeps
  std::function<bool()> cancelled;                       // checked between requests
  std::function<int64_t()> now;                          // epoch seconds
};

// Downloads the public feeds into the local vulnerability database. Everything is resumable: an interrupted
// or rate-limited NVD run continues from the same page next time, so a cold start (hundreds of requests at
// the NVD's polite rate) can be spread over several runs without losing work.
class FeedSync {
 public:
  FeedSync(VulnDb& db, IHttpClient& http, VulnConfig cfg, SyncHooks hooks = {});

  SyncReport syncKev();
  SyncReport syncNvd();
  SyncReport syncCwe();
  SyncReport syncEpss();  // one file a day; skipped when today's scores are already stored
  std::vector<SyncReport> syncAll();  // the enabled feeds, in a sensible order

  // One CVE straight from the NVD (to enrich a match the incremental feed has not delivered). Respects the rate limit.
  Result<bool> fetchCve(const std::string& id);

 private:
  Result<std::string> get(const std::string& url, bool nvd);
  void throttleNvd();
  int64_t nowSec() const { return hooks_.now(); }

  VulnDb& db_;
  IHttpClient& http_;
  VulnConfig cfg_;
  SyncHooks hooks_;
  int64_t last_nvd_ms_ = 0;
  std::mutex nvd_mu_;  // the NVD rate limit is per client: serialise requests from the sync thread and the matchers
};

}  // namespace agent
