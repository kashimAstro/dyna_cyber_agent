#pragma once
#include <memory>
#include <mutex>
#include <optional>
#include <string>

#include "core/result.h"
#include "vuln/vuln_types.h"

struct sqlite3;

namespace agent {

// Local copy of the vulnerability intelligence (CVE, CISA KEV, CWE, OSV answers). It lives in its own file
// (vuln.db): it is large, entirely rebuildable from the feeds, and its heavy writes must never block the
// agent's own database. Safe to share between threads.
class VulnDb {
 public:
  static Result<std::unique_ptr<VulnDb>> open(const std::string& path);  // ":memory:" allowed
  ~VulnDb();
  VulnDb(const VulnDb&) = delete;
  VulnDb& operator=(const VulnDb&) = delete;

  // --- CVE / KEV / CWE ---
  Result<bool> upsertCves(const std::vector<CveRecord>& cves);  // replaces the CPE rows of each CVE, keeps KEV data
  Result<bool> applyKev(const std::vector<KevEntry>& entries);  // flags CVEs as exploited (creates stub rows)
  Result<bool> upsertCwes(const std::vector<CweRecord>& cwes, int64_t fetched_at = 0);  // 0 = now
  Result<std::optional<CveRow>> getCve(const std::string& id);
  Result<std::vector<CveRow>> searchCves(const std::string& text, size_t limit);
  Result<std::vector<CpeRow>> cpeByProduct(const std::string& product);
  Result<std::optional<CweRecord>> getCwe(const std::string& id);
  // CWE ids referenced by stored CVEs / KEV entries that we have no (fresh) description for.
  Result<std::vector<std::string>> cweIdsToFetch(int64_t now, int64_t max_age_seconds, size_t limit);
  Result<std::vector<std::string>> kevAddedSince(int64_t ts);

  // --- OSV answers (cached: asking again for an unchanged package is pointless for a few hours) ---
  struct OsvCache {
    int64_t queried = 0;
    std::vector<std::string> vuln_ids;
  };
  Result<std::optional<OsvCache>> getOsvCache(const std::string& eco, const std::string& name, const std::string& version);
  Result<bool> putOsvCache(const std::string& eco, const std::string& name, const std::string& version, int64_t queried, const std::vector<std::string>& ids);
  Result<std::optional<OsvVuln>> getOsvVuln(const std::string& id);
  Result<bool> putOsvVuln(const OsvVuln& v, int64_t fetched);

  // --- EPSS: probability that a CVE is exploited in the next 30 days (FIRST.org) ---
  Result<bool> replaceEpss(const std::vector<EpssRow>& rows);  // the daily file is the whole truth: older rows go away
  Result<std::optional<EpssRow>> getEpss(const std::string& cve);

  // --- bookkeeping ---
  Result<std::optional<std::string>> getMeta(const std::string& key);
  Result<bool> setMeta(const std::string& key, const std::string& value);
  struct Stats {
    int64_t cves = 0, kev = 0, cwes = 0, cpe_rows = 0, osv_vulns = 0, epss = 0;
  };
  Result<Stats> stats();

 private:
  explicit VulnDb(sqlite3* db) : db_(db) {}
  Result<bool> exec(const char* sql);

  sqlite3* db_;
  std::recursive_mutex mu_;
};

}  // namespace agent
