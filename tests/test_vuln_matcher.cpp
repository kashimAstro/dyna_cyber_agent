#include <catch2/catch.hpp>

#include <nlohmann/json.hpp>

#include "collectors/packages_collector.h"
#include "fake_transport.h"
#include "scripted_http.h"
#include "vuln/feed_parsers.h"
#include "vuln/matcher.h"

using namespace agent;
using nlohmann::json;

namespace {

constexpr int64_t kNow = 1792000000;  // 2026-10-14

InstalledPackage pkg(const std::string& name, const std::string& version, const std::string& source = "", const std::string& source_version = "") {
  InstalledPackage p;
  p.name = name;
  p.version = version;
  p.arch = "amd64";
  p.manager = "dpkg";
  p.source = source.empty() ? name : source;
  p.source_version = source_version.empty() ? version : source_version;
  return p;
}

Inventory ubuntu() {
  Inventory inv;
  inv.os.id = "ubuntu";
  inv.os.version_id = "22.04";
  inv.os.codename = "jammy";
  inv.kernel_release = "5.15.0-91-generic";
  inv.packages = {pkg("openssl", "3.0.2-0ubuntu1.12"), pkg("libssl3", "3.0.2-0ubuntu1.12+b1", "openssl", "3.0.2-0ubuntu1.12"), pkg("curl", "7.81.0-1ubuntu1.15"),
                  pkg("bash", "5.1-6ubuntu1")};
  return inv;
}

CveRecord cve(const std::string& id, double cvss, int64_t published, std::vector<std::string> cwes = {}) {
  CveRecord c;
  c.id = id;
  c.cvss = cvss;
  c.severity = cvss >= 9 ? "critical" : cvss >= 7 ? "high" : cvss >= 4 ? "medium" : "low";
  c.published = published;
  c.modified = published;
  c.summary = "Summary of " + id;
  c.cwes = std::move(cwes);
  c.status = "Analyzed";
  return c;
}

json osvVuln(const std::string& id, std::vector<std::string> aliases, const std::string& eco, const std::string& pkg_name, const std::string& fixed,
             const std::string& ubuntu_priority = "", const std::string& cvss_vector = "") {
  json v = {{"id", id}, {"modified", "2026-10-01T00:00:00Z"}, {"published", "2026-10-10T00:00:00Z"}, {"aliases", aliases}, {"summary", "Advisory " + id},
            {"affected", {{{"package", {{"ecosystem", eco}, {"name", pkg_name}}}, {"ranges", {{{"type", "ECOSYSTEM"}, {"events", fixed.empty() ? json::array({{{"introduced", "0"}}}) : json::array({{{"introduced", "0"}}, {{"fixed", fixed}}})}}}}}}}};
  json sev = json::array();
  if (!ubuntu_priority.empty()) sev.push_back({{"type", "Ubuntu"}, {"score", ubuntu_priority}});
  if (!cvss_vector.empty()) sev.push_back({{"type", "CVSS_V3"}, {"score", cvss_vector}});
  if (!sev.empty()) v["severity"] = sev;
  return v;
}

struct Lab {
  std::unique_ptr<VulnDb> db = std::move(VulnDb::open(":memory:").value());
  ScriptedHttp http;
  VulnConfig cfg;
  Lab() { cfg.osv_url = "https://osv.test"; }
  VulnMatcher matcher(FeedSync* f = nullptr) { return VulnMatcher(*db, &http, cfg, f, [] { return kNow; }); }

  // OSV: bash -> nothing, curl -> one advisory, openssl -> two (units come in alphabetical order)
  void scriptUbuntu() {
    http.ok("v1/querybatch", json({{"results", {json::object(), {{"vulns", {{{"id", "UBUNTU-CVE-2024-0001"}, {"modified", "2026-10-01T00:00:00Z"}}}}},
                                                 {{"vulns", {{{"id", "UBUNTU-CVE-2023-5678"}, {"modified", "2026-10-01T00:00:00Z"}}, {{"id", "USN-6000-1"}, {"modified", "2026-10-01T00:00:00Z"}}}}}}}}).dump());
    http.ok("v1/vulns/UBUNTU-CVE-2024-0001", osvVuln("UBUNTU-CVE-2024-0001", {"CVE-2024-0001"}, "Ubuntu:22.04:LTS", "curl", "7.81.0-1ubuntu1.16", "high").dump());
    http.ok("v1/vulns/UBUNTU-CVE-2023-5678", osvVuln("UBUNTU-CVE-2023-5678", {"CVE-2023-5678"}, "Ubuntu:22.04:LTS", "openssl", "3.0.2-0ubuntu1.13", "medium").dump());
    http.ok("v1/vulns/USN-6000-1", osvVuln("USN-6000-1", {"CVE-2023-5678", "CVE-2023-9999"}, "Ubuntu:22.04:LTS", "openssl", "3.0.2-0ubuntu1.14", "",
                                          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").dump());
  }
};

const Observation* find(const CollectOutput& o, const std::string& key_part) {
  for (const auto& ob : o.observations) if (ob.type == "vuln.match" && ob.key.find(key_part) != std::string::npos) return &ob;
  return nullptr;
}
const Observation* summary(const CollectOutput& o) {
  for (const auto& ob : o.observations) if (ob.type == "vuln.summary") return &ob;
  return nullptr;
}
bool tagged(const Observation* o, const std::string& t) { return o && std::find(o->tags.begin(), o->tags.end(), t) != o->tags.end(); }

}  // namespace

TEST_CASE("OSV ecosystems per distribution") {
  auto eco = [](const char* id, const char* ver) {
    OsRelease o;
    o.id = id;
    o.version_id = ver;
    return osvEcosystem(o);
  };
  REQUIRE(eco("debian", "12") == "Debian:12");
  REQUIRE(eco("debian", "11.7") == "Debian:11");
  REQUIRE(eco("ubuntu", "22.04") == "Ubuntu:22.04:LTS");
  REQUIRE(eco("ubuntu", "24.04") == "Ubuntu:24.04:LTS");
  REQUIRE(eco("ubuntu", "23.10") == "Ubuntu:23.10");  // not an LTS
  REQUIRE(eco("ubuntu", "21.04") == "Ubuntu:21.04");  // .04 but an odd year
  REQUIRE(eco("rocky", "9.3") == "Rocky Linux:9");
  REQUIRE(eco("almalinux", "8.9") == "AlmaLinux:8");
  REQUIRE_FALSE(eco("fedora", "39"));
  REQUIRE_FALSE(eco("debian", ""));
  REQUIRE_FALSE(eco("", ""));
}

TEST_CASE("inventory from a packages snapshot") {
  FakeTransport t;
  t.files["/etc/os-release"] = "ID=ubuntu\nVERSION_ID=\"22.04\"\n";
  t.files["/proc/sys/kernel/osrelease"] = "5.15.0-91-generic\n";
  t.files["/var/lib/dpkg/status"] = "Package: libssl3\nStatus: install ok installed\nArchitecture: amd64\nSource: openssl (3.0.2-0ubuntu1.12)\nVersion: 3.0.2-0ubuntu1.12+b1\n\n";
  auto c = PackagesCollector().collect(t);
  REQUIRE(c.ok());
  Snapshot s;
  s.observations = c.value().observations;
  auto inv = inventoryFromSnapshot(s);
  REQUIRE(inv);
  REQUIRE(inv->os.id == "ubuntu");
  REQUIRE(inv->kernel_release == "5.15.0-91-generic");
  REQUIRE(inv->packages.size() == 1);
  REQUIRE(inv->packages[0].source == "openssl");
  REQUIRE(inv->packages[0].source_version == "3.0.2-0ubuntu1.12");
  REQUIRE_FALSE(inventoryFromSnapshot(Snapshot{}));
}

TEST_CASE("matcher: distribution-aware matching through OSV") {
  Lab lab;
  lab.scriptUbuntu();
  REQUIRE(lab.db->upsertCves({cve("CVE-2023-9999", 9.8, kNow - 3 * 86400, {"CWE-787"}), cve("CVE-2023-5678", 5.3, kNow - 400 * 86400, {"CWE-79"})}).ok());
  KevEntry k;
  k.cve = "CVE-2024-0001";
  k.name = "curl heap overflow";
  k.added = kNow - 2 * 86400;
  k.due = kNow + 19 * 86400;
  k.action = "Apply updates.";
  k.ransomware = true;
  REQUIRE(lab.db->applyKev({k}).ok());

  auto r = lab.matcher().match(ubuntu());
  REQUIRE(r.ok());
  const auto& o = r.value();

  // the query asked about source packages, with the ecosystem and the source version
  REQUIRE(lab.http.count("v1/querybatch") == 1);
  const std::string body = lab.http.requested[0];
  REQUIRE(body.find("\"ecosystem\":\"Ubuntu:22.04:LTS\"") != std::string::npos);
  REQUIRE(body.find("\"name\":\"openssl\"") != std::string::npos);
  REQUIRE(body.find("3.0.2-0ubuntu1.12") != std::string::npos);
  REQUIRE(body.find("\"name\":\"libssl3\"") == std::string::npos);  // binaries are folded into their source

  const auto* crit = find(o, "CVE-2023-9999|openssl");
  REQUIRE(crit);
  REQUIRE(crit->data["cvss"] == 9.8);
  REQUIRE(crit->data["score_source"] == "nvd");
  REQUIRE(crit->data["fixed_version"] == "3.0.2-0ubuntu1.14");
  REQUIRE(crit->data["source"] == "osv");
  REQUIRE(crit->data["confidence"] == "high");
  REQUIRE(tagged(crit, "recent"));
  REQUIRE(tagged(crit, "fix_available"));
  REQUIRE_FALSE(tagged(crit, "kev"));
  REQUIRE(crit->data["cwes"][0]["id"] == "CWE-787");
  REQUIRE(crit->data["cwes"][0]["name"] == "Out-of-bounds Write");  // built-in name, no CWE download needed
  const auto bins = crit->data["binaries"];
  REQUIRE(std::find(bins.begin(), bins.end(), "libssl3") != bins.end());
  REQUIRE(std::find(bins.begin(), bins.end(), "openssl") != bins.end());

  const auto* exploited = find(o, "CVE-2024-0001|curl");
  REQUIRE(exploited);
  REQUIRE(tagged(exploited, "kev"));
  REQUIRE(tagged(exploited, "ransomware"));
  REQUIRE(tagged(exploited, "recent"));
  REQUIRE(exploited->data["kev_due"] == "2026-11-02");
  REQUIRE(exploited->data["score_source"] == "osv-priority");  // not in the NVD database: Ubuntu "high" estimated
  REQUIRE(exploited->data["cvss"] == 8.0);

  REQUIRE_FALSE(find(o, "CVE-2023-5678"));                      // 5.3: counted, not listed
  REQUIRE_FALSE(find(o, "|bash"));                              // nothing for bash

  const auto* sum = summary(o);
  REQUIRE(sum);
  REQUIRE(sum->data["matches"] == 3);
  REQUIRE(sum->data["listed"] == 2);
  REQUIRE(sum->data["kev_matches"] == 1);
  REQUIRE(sum->data["by_severity"]["critical"] == 1);
  REQUIRE(sum->data["by_severity"]["medium"] == 1);
  REQUIRE(sum->data["osv_used"] == true);
  REQUIRE(sum->data["cpe_used"] == false);
  REQUIRE(sum->data["osv_ecosystem"] == "Ubuntu:22.04:LTS");
  REQUIRE(sum->data["packages"] == 4);
  REQUIRE(sum->data["source_packages"] == 3);

  // asked again soon: nothing goes over the network, the answers come from the cache
  const size_t calls = lab.http.requested.size();
  auto again = lab.matcher().match(ubuntu());
  REQUIRE(again.ok());
  REQUIRE(lab.http.requested.size() == calls);
  REQUIRE(find(again.value(), "CVE-2023-9999|openssl"));
}

TEST_CASE("matcher: scores come from the best source available") {
  Lab lab;
  lab.scriptUbuntu();
  // CVE-2023-9999: no NVD record, but the advisory has a CVSS vector (9.8); CVE-2024-0001: unknown to NVD, enriched on demand
  lab.cfg.nvd_url = "https://nvd.test/cves";
  json nvd = {{"resultsPerPage", 1}, {"startIndex", 0}, {"totalResults", 1},
              {"vulnerabilities", {{{"cve", {{"id", "CVE-2024-0001"}, {"vulnStatus", "Analyzed"}, {"published", "2026-10-10T00:00:00.000"}, {"lastModified", "2026-10-12T00:00:00.000"},
                                             {"descriptions", {{{"lang", "en"}, {"value", "curl overflow"}}}},
                                             {"metrics", {{"cvssMetricV31", {{{"type", "Primary"}, {"cvssData", {{"baseScore", 7.5}, {"vectorString", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}}}}}}}},
                                             {"weaknesses", {{{"description", {{{"lang", "en"}, {"value", "CWE-122"}}}}}}}}}}}}};
  lab.http.ok("nvd.test", nvd.dump());
  SyncHooks hooks;
  hooks.now = [] { return kNow; };
  hooks.sleep = [](std::chrono::milliseconds) {};
  FeedSync fetcher(*lab.db, lab.http, lab.cfg, hooks);

  auto r = lab.matcher(&fetcher).match(ubuntu());
  REQUIRE(r.ok());
  const auto* a = find(r.value(), "CVE-2023-9999|openssl");
  REQUIRE(a);
  REQUIRE(a->data["score_source"] == "osv-vector");
  REQUIRE(a->data["cvss"] == 9.8);
  const auto* b = find(r.value(), "CVE-2024-0001|curl");
  REQUIRE(b);
  REQUIRE(b->data["score_source"] == "nvd");  // fetched from the NVD and stored
  REQUIRE(b->data["cvss"] == 7.5);
  REQUIRE(b->data["cwes"][0]["name"] == "Heap-based Buffer Overflow");
  REQUIRE(lab.db->getCve("CVE-2024-0001").value().has_value());
}

TEST_CASE("matcher: unscored, rejected and failure cases") {
  {  // unscored: listed only when recent
    Lab lab;
    lab.http.ok("v1/querybatch", json({{"results", {{{"vulns", {{{"id", "DEBIAN-CVE-2026-1111"}, {"modified", "x"}}, {{"id", "DEBIAN-CVE-2010-2222"}, {"modified", "x"}}}}}}}}).dump());
    json fresh = osvVuln("DEBIAN-CVE-2026-1111", {}, "Debian:12", "foo", "");
    json old = osvVuln("DEBIAN-CVE-2010-2222", {}, "Debian:12", "foo", "");
    old["published"] = "2010-05-05T00:00:00Z";
    fresh["published"] = "2026-10-12T00:00:00Z";
    lab.http.ok("v1/vulns/DEBIAN-CVE-2026-1111", fresh.dump());
    lab.http.ok("v1/vulns/DEBIAN-CVE-2010-2222", old.dump());
    Inventory inv;
    inv.os.id = "debian";
    inv.os.version_id = "12";
    inv.packages = {pkg("foo", "1.0-1")};
    auto r = lab.matcher().match(inv);
    REQUIRE(r.ok());
    const auto* n = find(r.value(), "CVE-2026-1111|foo");
    REQUIRE(n);
    REQUIRE(tagged(n, "unscored"));
    REQUIRE(tagged(n, "no_fix_known"));
    REQUIRE(n->data["cvss"].is_null());
    REQUIRE_FALSE(find(r.value(), "CVE-2010-2222"));
    REQUIRE(summary(r.value())->data["by_severity"]["unscored"] == 2);
  }
  {  // rejected CVEs are ignored
    Lab lab;
    lab.http.ok("v1/querybatch", json({{"results", {{{"vulns", {{{"id", "DEBIAN-CVE-2026-3333"}, {"modified", "x"}}}}}}}}).dump());
    lab.http.ok("v1/vulns/DEBIAN-CVE-2026-3333", osvVuln("DEBIAN-CVE-2026-3333", {}, "Debian:12", "foo", "1.1-1", "", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").dump());
    CveRecord rej = cve("CVE-2026-3333", 9.8, kNow);
    rej.status = "Rejected";
    REQUIRE(lab.db->upsertCves({rej}).ok());
    Inventory inv;
    inv.os.id = "debian";
    inv.os.version_id = "12";
    inv.packages = {pkg("foo", "1.0-1")};
    auto r = lab.matcher().match(inv);
    REQUIRE_FALSE(find(r.value(), "CVE-2026-3333"));
    REQUIRE(summary(r.value())->data["matches"] == 0);
  }
  {  // OSV unreachable, nothing cached: falls back to upstream matching and says so
    Lab lab;
    lab.http.status("v1/querybatch", 503);
    REQUIRE(lab.db->upsertCves({[] { auto c = cve("CVE-2021-44228", 10.0, kNow - 5 * 86400); c.cpes = {{"apache", "log4j", "*", "2.13.0", "", "", "2.15.0"}}; return c; }()}).ok());
    Inventory inv = ubuntu();
    inv.packages.push_back(pkg("log4j", "2.14.1-1"));
    auto r = lab.matcher().match(inv);
    REQUIRE(r.ok());
    bool warned_osv = false, warned_cpe = false;
    for (const auto& w : r.value().warnings) {
      warned_osv |= w.find("OSV query failed") != std::string::npos;
      warned_cpe |= w.find("upstream-version matching") != std::string::npos;
    }
    REQUIRE(warned_osv);
    REQUIRE(warned_cpe);
    const auto* m = find(r.value(), "CVE-2021-44228|log4j");
    REQUIRE(m);
    REQUIRE(tagged(m, "upstream_version_match"));
    REQUIRE(m->data["confidence"] == "low");
    REQUIRE(summary(r.value())->data["osv_used"] == false);
  }
  {  // OSV unreachable but answers were cached before: they are still used
    Lab lab;
    lab.scriptUbuntu();
    REQUIRE(lab.db->upsertCves({cve("CVE-2023-9999", 9.8, kNow - 3 * 86400)}).ok());
    REQUIRE(lab.matcher().match(ubuntu()).ok());
    lab.cfg.refresh_every = std::chrono::seconds(1800);
    VulnMatcher later(*lab.db, &lab.http, lab.cfg, nullptr, [] { return kNow + 86400; });  // cache now older than the refresh interval
    lab.http.routes.clear();
    lab.http.status("v1/querybatch", 500);
    auto r = later.match(ubuntu());
    REQUIRE(r.ok());
    REQUIRE(find(r.value(), "CVE-2023-9999|openssl"));  // stale answers beat silence
    REQUIRE(summary(r.value())->data["osv_used"] == false);
  }
}

TEST_CASE("matcher: upstream-version matching (no distribution data)") {
  Lab lab;
  lab.cfg.osv = false;
  CveRecord log4j = cve("CVE-2021-44228", 10.0, kNow - 5 * 86400, {"CWE-917"});
  log4j.cpes = {{"apache", "log4j", "*", "2.0.1", "", "", "2.3.1"}, {"apache", "log4j", "*", "2.13.0", "", "", "2.15.0"}, {"apache", "log4j", "2.0", "", "", "", ""}};  // several ranges, as in the real record
  CveRecord kernel = cve("CVE-2026-4444", 7.8, kNow - 20 * 86400);
  kernel.cpes = {{"linux", "linux_kernel", "*", "", "", "", "5.15.5"}};
  CveRecord other = cve("CVE-2026-5555", 9.0, kNow - 20 * 86400);
  other.cpes = {{"vendor", "unrelated", "*", "", "", "", "99"}};
  REQUIRE(lab.db->upsertCves({log4j, kernel, other}).ok());

  Inventory inv;
  inv.os.id = "fedora";
  inv.os.version_id = "39";
  inv.kernel_release = "5.15.0-91-generic";
  inv.packages = {pkg("log4j", "2.14.1-1"), pkg("python3.10", "3.10.12-1"), pkg("safe-lib", "1.0")};
  auto r = VulnMatcher(*lab.db, &lab.http, lab.cfg, nullptr, [] { return kNow; }).match(inv);
  REQUIRE(r.ok());
  const auto* l = find(r.value(), "CVE-2021-44228|log4j");
  REQUIRE(l);
  REQUIRE(tagged(l, "upstream_version_match"));
  REQUIRE(tagged(l, "recent"));
  REQUIRE(l->data["source"] == "nvd-cpe");
  const auto* kn = find(r.value(), "CVE-2026-4444|linux");
  REQUIRE(kn);
  REQUIRE(tagged(kn, "kernel"));  // matched against the running kernel version
  REQUIRE_FALSE(find(r.value(), "CVE-2026-5555"));
  REQUIRE(summary(r.value())->data["cpe_used"] == true);
  REQUIRE(lab.http.requested.empty());  // no network involved at all

  // version edges: just outside the affected range, and the range start
  inv.packages = {pkg("log4j", "2.3.1-1")};
  REQUIRE_FALSE(find(VulnMatcher(*lab.db, nullptr, lab.cfg, nullptr, [] { return kNow; }).match(inv).value(), "CVE-2021-44228"));  // fixed version
  inv.packages = {pkg("log4j", "2.0.0-1")};
  REQUIRE_FALSE(find(VulnMatcher(*lab.db, nullptr, lab.cfg, nullptr, [] { return kNow; }).match(inv).value(), "CVE-2021-44228"));  // before the range
  inv.packages = {pkg("log4j", "2.0.1-1")};
  REQUIRE(find(VulnMatcher(*lab.db, nullptr, lab.cfg, nullptr, [] { return kNow; }).match(inv).value(), "CVE-2021-44228"));
  inv.packages = {pkg("log4j", "2.0-1")};                                                                                         // the exact-version entry
  REQUIRE(find(VulnMatcher(*lab.db, nullptr, lab.cfg, nullptr, [] { return kNow; }).match(inv).value(), "CVE-2021-44228"));

  // cpe_match: never
  lab.cfg.cpe_match = "never";
  inv.packages = {pkg("log4j", "2.14.1-1")};
  auto none = VulnMatcher(*lab.db, nullptr, lab.cfg, nullptr, [] { return kNow; }).match(inv);
  REQUIRE_FALSE(find(none.value(), "CVE-2021-44228"));
  REQUIRE(summary(none.value())->data["cpe_used"] == false);
}

TEST_CASE("matcher: OSV wins over a CPE guess when both are enabled") {
  Lab lab;
  lab.cfg.cpe_match = "always";
  lab.scriptUbuntu();
  CveRecord c = cve("CVE-2023-9999", 9.8, kNow - 3 * 86400);
  c.cpes = {{"openssl", "openssl", "*", "", "", "", "3.0.20"}};
  REQUIRE(lab.db->upsertCves({c, cve("CVE-2024-0001", 7.5, kNow - 3 * 86400)}).ok());
  auto r = lab.matcher().match(ubuntu());
  REQUIRE(r.ok());
  size_t n = 0;
  for (const auto& o : r.value().observations) n += o.type == "vuln.match" && o.key.find("CVE-2023-9999|openssl") != std::string::npos;
  REQUIRE(n == 1);  // one match, not two
  const auto* m = find(r.value(), "CVE-2023-9999|openssl");
  REQUIRE(m->data["source"] == "osv");
  REQUIRE(m->data["confidence"] == "high");
  REQUIRE(m->data["fixed_version"] == "3.0.2-0ubuntu1.14");
}
