#pragma once
#include <functional>
#include <optional>

#include "collectors/collector.h"
#include "collectors/packages_collector.h"
#include "core/config.h"
#include "llm/http_client.h"
#include "vuln/feed_sync.h"
#include "vuln/vuln_db.h"

namespace agent {

struct Inventory {
  OsRelease os;
  std::string kernel_release;
  std::vector<InstalledPackage> packages;
};

// Rebuilds the inventory from a `packages` snapshot (null when the snapshot has no packages).
std::optional<Inventory> inventoryFromSnapshot(const Snapshot& s);

// OSV ecosystem for an operating system ("Debian:12", "Ubuntu:22.04:LTS", ...), if OSV covers it.
std::optional<std::string> osvEcosystem(const OsRelease& os);

// Decides whether the installed software is affected by known vulnerabilities.
//
//  * OSV (when the distribution is covered): the distribution's own advisories, so a package that carries the
//    backported fix is not reported. This is the accurate path.
//  * NVD CPE ranges (otherwise, or on request): upstream version against the affected ranges. Distributions
//    backport fixes without changing the upstream version, so this over-reports on them; every such match is
//    tagged `upstream_version_match` and rated by the rules below the accurate kind.
//
// Output is a snapshot's worth of observations: one `vuln.match` per (CVE, source package) worth reading, and one
// `vuln.summary` with the totals (lower-scored matches are counted, not listed).
class VulnMatcher {
 public:
  VulnMatcher(VulnDb& db, IHttpClient* http, VulnConfig cfg, FeedSync* fetcher = nullptr, std::function<int64_t()> now = nullptr);

  Result<CollectOutput> match(const Inventory& inv);

 private:
  struct Unit {
    std::string source, version;
    std::vector<std::string> binaries;
  };
  struct Hit {
    std::string cve, source, version, fixed, origin;  // origin: osv | cpe
    std::vector<std::string> advisories;
    std::optional<double> osv_score;
    std::string osv_priority;
    int64_t osv_published = 0;
  };

  void matchOsv(const std::vector<Unit>& units, const std::string& eco, std::vector<Hit>& hits, std::vector<std::string>& warnings, bool& failed);
  void matchCpe(const Inventory& inv, const std::vector<Unit>& units, std::vector<Hit>& hits);

  VulnDb& db_;
  IHttpClient* http_;
  VulnConfig cfg_;
  FeedSync* fetcher_;
  std::function<int64_t()> now_;
};

}  // namespace agent
