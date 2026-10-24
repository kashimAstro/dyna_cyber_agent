#pragma once
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "core/config.h"
#include "core/result.h"
#include "llm/http_client.h"

namespace agent {

struct ThreatHit {
  std::string list, category;  // category: c2 | compromised | attacker | scanner
};

// Public IP blocklists (botnet C2 servers, hijacked networks, known attackers) downloaded to THIS machine and matched
// locally. Nothing about the monitored machines is ever sent anywhere: the lists come in, nothing goes out.
// IPv4 only. Thread-safe: the lookups run on the target threads while a refresh replaces a list.
class ThreatIntel {
 public:
  struct Range {
    uint32_t lo = 0, hi = 0;
    bool operator<(const Range& o) const { return lo < o.lo; }
  };

  ThreatIntel(std::string dir, std::vector<ThreatIntelConfig::List> lists) : dir_(std::move(dir)), configured_(std::move(lists)) {}

  // Reads the lists already on disk (a restart must not wait for a download).
  size_t load();
  std::optional<ThreatHit> lookup(const std::string& ip) const;

  struct ListInfo {
    std::string name, category;
    size_t ranges = 0;
    int64_t fetched = 0;
  };
  std::vector<ListInfo> info() const;
  bool empty() const;

  struct Report {
    std::string list;
    bool ok = false;
    size_t ranges = 0;
    std::string message;
  };
  // Downloads every configured list whose copy is older than `max_age` seconds (0 = all). A failed download keeps the old copy.
  std::vector<Report> refresh(IHttpClient& http, int64_t now, int64_t max_age, std::chrono::seconds timeout);

  // Plain text, one address or CIDR range per line, `#` or `;` comments (Spamhaus: "1.2.3.0/24 ; SBL123"). IPv6 and junk are skipped.
  static std::vector<Range> parseList(const std::string& text);
  static std::optional<uint32_t> parseIpv4(const std::string& s);

 private:
  struct Loaded {
    ThreatIntelConfig::List cfg;
    std::vector<Range> ranges;  // sorted, merged
    int64_t fetched = 0;
  };
  static std::vector<Range> merge(std::vector<Range> r);
  bool loadOne(Loaded& l);
  std::string pathOf(const std::string& name) const { return dir_ + "/" + name + ".list"; }

  std::string dir_;
  std::vector<ThreatIntelConfig::List> configured_;
  mutable std::mutex mu_;
  std::vector<Loaded> lists_;
};

}  // namespace agent
