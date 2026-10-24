#include "vuln/matcher.h"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cmath>
#include <chrono>
#include <map>
#include <set>

#include <nlohmann/json.hpp>

#include "core/util.h"
#include "vuln/cvss.h"
#include "vuln/cwe_names.h"
#include "vuln/feed_parsers.h"
#include "vuln/version.h"

namespace agent {
namespace {

using nlohmann::json;

constexpr size_t kBatch = 1000;
constexpr size_t kMaxDetailFetches = 300;  // advisory details per run; the rest follows on the next runs
constexpr size_t kMaxEnrich = 25;
constexpr double kEpssHigh = 0.1;            // 10% chance of exploitation in the next 30 days: rare among thousands of CVEs          // CVEs asked from the NVD one by one per run
constexpr size_t kMaxListed = 300;

int64_t systemSeconds() {
  return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string family(const std::string& eco) { return eco.substr(0, eco.find(':')); }

std::string lower(std::string s) {
  for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

bool isCveId(const std::string& s) {
  if (!util::startsWith(s, "CVE-")) return false;
  const auto p = util::split(s.substr(4), '-');
  return p.size() == 2 && util::allDigits(p[0]) && util::allDigits(p[1]);
}

// "UBUNTU-CVE-2023-5678" / "DEBIAN-CVE-2023-5678" -> "CVE-2023-5678"
std::string cveInside(const std::string& id) {
  const size_t p = id.find("CVE-");
  if (p == std::string::npos) return {};
  std::string c = id.substr(p);
  return isCveId(c) ? c : std::string();
}

bool validOsvId(const std::string& id) {
  if (id.empty() || id.size() > 100) return false;
  for (unsigned char c : id) if (!(std::isalnum(c) || c == ':' || c == '-' || c == '_' || c == '.')) return false;
  return true;
}

// Candidate NVD product names for a source package ("python3.10" -> python, "linux" -> linux_kernel).
std::vector<std::string> productCandidates(const std::string& source) {
  static const std::map<std::string, std::string> alias = {
      {"linux", "linux_kernel"}, {"linux-signed", "linux_kernel"}, {"linux-hwe", "linux_kernel"}, {"apache2", "http_server"}, {"isc-dhcp", "dhcp"},
      {"bind9", "bind"}, {"glibc", "glibc"}, {"eglibc", "glibc"}, {"openssh", "openssh"}, {"openldap", "openldap"}, {"mysql-8.0", "mysql"},
      {"postgresql-14", "postgresql"}, {"postgresql-15", "postgresql"}, {"postgresql-16", "postgresql"}, {"libxml2", "libxml2"}, {"zlib", "zlib"}};
  std::vector<std::string> out;
  auto add = [&](const std::string& p) {
    if (!p.empty() && std::find(out.begin(), out.end(), p) == out.end()) out.push_back(p);
  };
  const std::string s = lower(source);
  if (const auto it = alias.find(s); it != alias.end()) add(it->second);
  add(s);
  std::string stripped = s;
  while (stripped.size() > 3 && (std::isdigit(static_cast<unsigned char>(stripped.back())) || stripped.back() == '.')) stripped.pop_back();
  add(stripped);
  std::string underscored = s;
  std::replace(underscored.begin(), underscored.end(), '-', '_');
  add(underscored);
  return out;
}

bool cpeAffects(const CpeRow& r, const std::string& upstream) {
  if (r.version == "-") return false;
  if (r.version != "*") return compareUpstream(r.version, upstream) == 0;
  if (!r.start_incl.empty() && compareUpstream(upstream, r.start_incl) < 0) return false;
  if (!r.start_excl.empty() && compareUpstream(upstream, r.start_excl) <= 0) return false;
  if (!r.end_incl.empty() && compareUpstream(upstream, r.end_incl) > 0) return false;
  if (!r.end_excl.empty() && compareUpstream(upstream, r.end_excl) >= 0) return false;
  return true;
}

// Vendor priority words (Ubuntu) -> an estimated score, used only when nothing better exists.
std::optional<double> priorityScore(const std::string& p) {
  if (p == "critical") return 9.5;
  if (p == "high") return 8.0;
  if (p == "medium") return 5.5;
  if (p == "low") return 3.0;
  if (p == "negligible") return 1.0;
  return std::nullopt;
}

std::string isoDate(int64_t t) {
  if (t <= 0) return "";
  const std::time_t tt = static_cast<std::time_t>(t);
  std::tm tm{};
  gmtime_r(&tt, &tm);
  char b[16];
  std::strftime(b, sizeof(b), "%Y-%m-%d", &tm);
  return b;
}

}  // namespace

std::optional<Inventory> inventoryFromSnapshot(const Snapshot& s) {
  Inventory inv;
  for (const auto& o : s.observations) {
    const auto& d = o.data;
    if (o.type == "os.release") {
      inv.os.id = d.value("id", "");
      inv.os.version_id = d.value("version_id", "");
      inv.os.codename = d.value("codename", "");
      inv.os.pretty_name = d.value("pretty_name", "");
      inv.os.id_like = d.value("id_like", "");
    } else if (o.type == "os.kernel") {
      inv.kernel_release = d.value("release", "");
    } else if (o.type == "pkg.installed") {
      InstalledPackage p;
      p.name = d.value("name", "");
      p.version = d.value("version", "");
      p.arch = d.value("arch", "");
      p.source = d.value("source", p.name);
      p.source_version = d.value("source_version", p.version);
      p.manager = d.value("manager", "");
      inv.packages.push_back(std::move(p));
    }
  }
  if (inv.packages.empty()) return std::nullopt;
  return inv;
}

std::optional<std::string> osvEcosystem(const OsRelease& os) {
  const std::string major = os.version_id.substr(0, os.version_id.find('.'));
  if (os.id == "debian" && !major.empty()) return "Debian:" + major;
  if (os.id == "ubuntu" && os.version_id.size() >= 5) {
    const auto parts = util::split(os.version_id, '.');
    const auto year = util::parseUint(parts[0]);
    const bool lts = parts.size() >= 2 && parts[1] == "04" && year && *year % 2 == 0;  // 20.04, 22.04, 24.04...
    return "Ubuntu:" + os.version_id + (lts ? ":LTS" : "");
  }
  if (os.id == "rocky" && !major.empty()) return "Rocky Linux:" + major;
  if (os.id == "almalinux" && !major.empty()) return "AlmaLinux:" + major;
  return std::nullopt;
}

VulnMatcher::VulnMatcher(VulnDb& db, IHttpClient* http, VulnConfig cfg, FeedSync* fetcher, std::function<int64_t()> now)
    : db_(db), http_(http), cfg_(std::move(cfg)), fetcher_(fetcher), now_(now ? std::move(now) : std::function<int64_t()>(systemSeconds)) {}

void VulnMatcher::matchOsv(const std::vector<Unit>& units, const std::string& eco, std::vector<Hit>& hits, std::vector<std::string>& warnings, bool& failed) {
  const int64_t now = now_();
  const std::vector<std::string> headers = {"Content-Type: application/json", "Accept: application/json", "User-Agent: dyna_cyber_agent (security monitor; read-only)"};

  std::vector<std::vector<std::string>> ids(units.size());
  std::map<std::string, std::string> modified_seen;  // advisory id -> modified, from fresh answers
  std::vector<size_t> to_query;
  for (size_t i = 0; i < units.size(); ++i) {
    auto c = db_.getOsvCache(eco, units[i].source, units[i].version);
    if (c && c.value() && c.value()->queried + cfg_.refresh_every.count() > now) ids[i] = c.value()->vuln_ids;
    else to_query.push_back(i);
  }

  for (size_t start = 0; start < to_query.size() && !failed; start += kBatch) {
    const size_t end = std::min(to_query.size(), start + kBatch);
    std::vector<size_t> idx(to_query.begin() + static_cast<std::ptrdiff_t>(start), to_query.begin() + static_cast<std::ptrdiff_t>(end));
    std::vector<std::vector<std::string>> got(idx.size());
    std::vector<std::string> tokens(idx.size());
    for (int page = 0; page < 10; ++page) {
      json queries = json::array();
      std::vector<size_t> pos;  // position in idx of each query sent
      for (size_t k = 0; k < idx.size(); ++k) {
        if (page > 0 && tokens[k].empty()) continue;
        json q = {{"package", {{"name", units[idx[k]].source}, {"ecosystem", eco}}}, {"version", units[idx[k]].version}};
        if (page > 0) q["page_token"] = tokens[k];
        queries.push_back(std::move(q));
        pos.push_back(k);
      }
      if (queries.empty()) break;
      auto r = http_->postJson(cfg_.osv_url + "/v1/querybatch", json({{"queries", queries}}).dump(), headers, cfg_.timeout);
      if (!r || r.value().status != 200) {
        warnings.push_back("OSV query failed: " + (r ? "HTTP " + std::to_string(r.value().status) : r.error()) + "; using cached answers where available");
        failed = true;
        break;
      }
      auto parsed = parseOsvBatch(r.value().body);
      if (!parsed || parsed.value().size() != pos.size()) {
        warnings.push_back("OSV answer not understood; using cached answers where available");
        failed = true;
        break;
      }
      for (size_t n = 0; n < pos.size(); ++n) {
        const size_t k = pos[n];
        for (const auto& [id, modified] : parsed.value()[n].vulns) {
          got[k].push_back(id);
          modified_seen[id] = modified;
        }
        tokens[k] = parsed.value()[n].next_page_token;
      }
    }
    if (failed) break;
    for (size_t k = 0; k < idx.size(); ++k) {
      ids[idx[k]] = got[k];
      db_.putOsvCache(eco, units[idx[k]].source, units[idx[k]].version, now, got[k]);
    }
  }
  if (failed) {  // stale answers are better than none: a vulnerability does not vanish because a server did
    for (size_t i : to_query) {
      auto c = db_.getOsvCache(eco, units[i].source, units[i].version);
      if (c && c.value()) ids[i] = c.value()->vuln_ids;
    }
  }

  // Advisory details (aliases, fixed version, severity): fetched once, refreshed when OSV says they changed.
  std::set<std::string> wanted;
  for (const auto& v : ids) wanted.insert(v.begin(), v.end());
  size_t fetched = 0, pending = 0;
  for (const auto& id : wanted) {
    if (!validOsvId(id)) continue;
    auto have = db_.getOsvVuln(id);
    const auto m = modified_seen.find(id);
    const bool stale = have && have.value() && m != modified_seen.end() && have.value()->modified != m->second;
    if (have && have.value() && !stale) continue;
    if (failed || fetched >= kMaxDetailFetches) {
      ++pending;
      continue;
    }
    auto r = http_->get(cfg_.osv_url + "/v1/vulns/" + id, headers, cfg_.timeout);
    ++fetched;
    if (!r || r.value().status != 200) {
      ++pending;
      continue;
    }
    auto v = parseOsvVuln(r.value().body, family(eco));
    if (!v) {
      ++pending;
      continue;
    }
    db_.putOsvVuln(v.value(), now);
  }
  if (pending) warnings.push_back(std::to_string(pending) + " advisory detail(s) not fetched yet (they will be on the next runs)");

  for (size_t i = 0; i < units.size(); ++i) {
    for (const auto& id : ids[i]) {
      auto d = db_.getOsvVuln(id);
      if (!d || !d.value() || d.value()->withdrawn) continue;
      const OsvVuln& v = *d.value();
      std::set<std::string> cves;
      for (const auto& a : v.aliases) if (isCveId(a)) cves.insert(a);
      if (const std::string c = cveInside(v.id); !c.empty()) cves.insert(c);
      if (cves.empty()) cves.insert(v.id);  // an advisory without a CVE: keep it under its own id
      const auto fx = v.fixed.find(units[i].source);
      std::optional<double> score;
      if (!v.cvss_vector.empty()) score = cvssV3Score(v.cvss_vector);
      for (const auto& cve : cves) {
        Hit h;
        h.cve = cve;
        h.source = units[i].source;
        h.version = units[i].version;
        h.fixed = fx == v.fixed.end() ? "" : fx->second;
        h.origin = "osv";
        h.advisories.push_back(v.id);
        h.osv_score = score;
        h.osv_priority = v.severity_text;
        h.osv_published = v.published;
        hits.push_back(std::move(h));
      }
    }
  }
}

void VulnMatcher::matchCpe(const Inventory& inv, const std::vector<Unit>& units, std::vector<Hit>& hits) {
  std::vector<Unit> all = units;
  if (!inv.kernel_release.empty()) all.push_back({"linux", kernelUpstreamVersion(inv.kernel_release), {"kernel"}});
  std::set<std::string> done;
  for (const auto& u : all) {
    const std::string upstream = upstreamVersion(u.version);
    if (upstream.empty()) continue;
    for (const auto& product : productCandidates(u.source)) {
      auto rows = db_.cpeByProduct(product);
      if (!rows) continue;
      for (const auto& r : rows.value()) {
        if (!cpeAffects(r, upstream)) continue;
        if (!done.insert(r.cve_id + "|" + u.source).second) continue;
        Hit h;
        h.cve = r.cve_id;
        h.source = u.source;
        h.version = u.version;
        h.origin = "cpe";
        hits.push_back(std::move(h));
      }
    }
  }
}

Result<CollectOutput> VulnMatcher::match(const Inventory& inv) {
  CollectOutput out;
  const int64_t now = now_();

  // binary packages grouped by the source they were built from (that is what advisories talk about)
  std::map<std::string, Unit> by_source;
  for (const auto& p : inv.packages) {
    Unit& u = by_source[p.source + "|" + p.source_version];
    u.source = p.source;
    u.version = p.source_version;
    u.binaries.push_back(p.name);
  }
  std::vector<Unit> units;
  for (auto& [k, u] : by_source) units.push_back(std::move(u));

  const auto eco = cfg_.osv && http_ ? osvEcosystem(inv.os) : std::nullopt;
  std::vector<Hit> hits;
  bool osv_failed = false;
  if (eco) matchOsv(units, *eco, hits, out.warnings, osv_failed);
  const bool osv_used = eco.has_value() && !osv_failed;

  bool cpe_used = false;
  if (cfg_.cpe_match == "always" || (cfg_.cpe_match == "auto" && !osv_used)) {
    matchCpe(inv, units, hits);
    cpe_used = true;
    if (!osv_used) {
      out.warnings.push_back(std::string(eco ? "OSV unavailable" : "no OSV coverage for this operating system") +
                             ": using upstream-version matching against NVD data. Distributions backport fixes without changing versions, so expect false positives (and misses).");
    }
  }

  // one match per (CVE, source package); an accurate OSV answer wins over a CPE guess
  std::map<std::string, Hit> unique;
  for (auto& h : hits) {
    const std::string key = h.cve + "|" + h.source;
    auto it = unique.find(key);
    if (it == unique.end()) {
      unique.emplace(key, std::move(h));
    } else {
      if (it->second.origin == "cpe" && h.origin == "osv") {
        h.advisories.insert(h.advisories.end(), it->second.advisories.begin(), it->second.advisories.end());
        it->second = std::move(h);
      } else {
        for (const auto& a : h.advisories) if (std::find(it->second.advisories.begin(), it->second.advisories.end(), a) == it->second.advisories.end()) it->second.advisories.push_back(a);
      }
    }
  }

  struct Item {
    Observation obs;
    double score = -1;
    bool kev = false;
  };
  std::vector<Item> listed;
  std::map<std::string, int64_t> by_sev = {{"critical", 0}, {"high", 0}, {"medium", 0}, {"low", 0}, {"unscored", 0}};
  int64_t kev_matches = 0, total = 0, enriched = 0;
  std::set<std::string> sources_hit;
  const int64_t recent_window = static_cast<int64_t>(cfg_.new_within_days) * 86400;

  for (auto& [key, h] : unique) {
    std::optional<CveRow> row;
    if (isCveId(h.cve)) {
      auto r = db_.getCve(h.cve);
      if (r) row = r.value();
      if ((!row || !row->cvss) && fetcher_ && static_cast<size_t>(enriched) < kMaxEnrich) {
        ++enriched;
        if (fetcher_->fetchCve(h.cve)) {
          auto again = db_.getCve(h.cve);
          if (again) row = again.value();
        }
      }
    }
    if (row && row->status == "Rejected") continue;
    ++total;
    sources_hit.insert(h.source);

    std::optional<double> score;
    std::string score_source = "none";
    if (row && row->cvss) {
      score = row->cvss;
      score_source = "nvd";
    } else if (h.osv_score) {
      score = h.osv_score;
      score_source = "osv-vector";
    } else if (auto p = priorityScore(h.osv_priority)) {
      score = p;
      score_source = "osv-priority";
    }
    const bool kev = row && row->kev;
    const int64_t published = row && row->published ? row->published : h.osv_published;
    const bool recent = (published > 0 && now - published <= recent_window) || (kev && row->kev_added > 0 && now - row->kev_added <= recent_window);
    std::optional<EpssRow> epss;
    if (cfg_.epss) {
      auto e = db_.getEpss(h.cve);
      if (e && e.value()) epss = e.value();
    }
    const std::string sev = score ? cvssSeverity(*score) : "unscored";
    ++by_sev[sev == "none" ? "low" : sev];
    if (kev) ++kev_matches;
    const bool epss_high = epss && epss->score >= kEpssHigh;
    const bool list = kev || (score && *score >= cfg_.min_cvss) || (!score && recent) || epss_high;
    if (!list) continue;

    Observation o;
    o.type = "vuln.match";
    o.key = "vuln|" + h.cve + "|" + h.source;
    if (kev) o.tags.push_back("kev");
    if (row && row->kev_ransomware) o.tags.push_back("ransomware");
    o.tags.push_back(recent ? "recent" : "established");  // exactly one of the two: rules key on it
    o.tags.push_back(h.fixed.empty() ? "no_fix_known" : "fix_available");
    if (h.origin == "cpe") o.tags.push_back("upstream_version_match");
    if (!score) o.tags.push_back("unscored");
    if (util::startsWith(h.source, "linux")) o.tags.push_back("kernel");
    if (epss_high) o.tags.push_back("epss_high");

    json cwes = json::array();
    if (row) {
      for (const auto& id : row->cwes) {
        std::string name;
        if (auto c = db_.getCwe(id); c && c.value() && !c.value()->name.empty()) name = c.value()->name;
        else name = builtinCweName(id);
        cwes.push_back({{"id", id}, {"name", name}});
      }
    }
    std::string summary = row && !row->summary.empty() ? row->summary : std::string();
    std::vector<std::string> bins;
    for (const auto& u : units) if (u.source == h.source && u.version == h.version) bins = u.binaries;
    if (bins.size() > 8) bins.resize(8);
    std::vector<std::string> adv = h.advisories;
    if (adv.size() > 5) adv.resize(5);

    o.data = {{"cve", h.cve},
              {"package", h.source},
              {"binaries", bins},
              {"installed_version", h.version},
              {"fixed_version", h.fixed},
              {"cvss", score ? json(*score) : json(nullptr)},
              {"severity", sev},
              {"score_source", score_source},
              {"kev", kev},
              {"kev_due", row && row->kev ? isoDate(row->kev_due) : ""},
              {"cwes", cwes},
              {"summary", util::toValidUtf8(summary.substr(0, 400))},
              {"published", isoDate(published)},
              {"source", h.origin == "osv" ? "osv" : "nvd-cpe"},
              {"advisories", adv},
              {"confidence", h.origin == "osv" ? "high" : "low"},
              {"exposed_likely_exploited", false}};  // the vulns collector refines this once it knows what listens on the target
    if (epss) {
      o.data["epss"] = std::round(epss->score * 10000) / 10000;
      o.data["epss_percentile"] = std::round(epss->percentile * 10000) / 10000;
    }
    if (row && row->kev) o.data["kev_action"] = util::toValidUtf8(row->kev_action.substr(0, 200));
    listed.push_back({std::move(o), score.value_or(-1), kev});
  }

  std::sort(listed.begin(), listed.end(), [](const Item& a, const Item& b) { return a.kev != b.kev ? a.kev : a.score > b.score; });
  if (listed.size() > kMaxListed) {
    out.warnings.push_back(std::to_string(listed.size() - kMaxListed) + " more vulnerabilities not listed (lowest scores)");
    listed.resize(kMaxListed);
  }
  const size_t n_listed = listed.size();
  for (auto& it : listed) out.observations.push_back(std::move(it.obs));

  Observation s;
  s.type = "vuln.summary";
  s.key = "summary";
  auto stats = db_.stats();
  s.data = {{"packages", inv.packages.size()},
            {"source_packages", units.size()},
            {"matches", total},
            {"listed", n_listed},
            {"kev_matches", kev_matches},
            {"affected_sources", sources_hit.size()},
            {"by_severity", by_sev},
            {"osv_ecosystem", eco ? json(*eco) : json(nullptr)},
            {"osv_used", osv_used},
            {"cpe_used", cpe_used},
            {"db_cves", stats ? stats.value().cves : 0},
            {"min_cvss", cfg_.min_cvss}};
  out.observations.push_back(std::move(s));
  return out;
}

}  // namespace agent
