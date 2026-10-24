#include <catch2/catch.hpp>

#include <zlib.h>

#include <nlohmann/json.hpp>

#include "analysis/analyzer.h"
#include "analysis/rule.h"
#include "core/gzip.h"
#include "scripted_http.h"
#include "vuln/exposure.h"
#include "vuln/feed_parsers.h"
#include "vuln/feed_sync.h"
#include "vuln/matcher.h"

using namespace agent;
using nlohmann::json;

namespace {

constexpr int64_t kNow = 1792000000;  // 2026-10-14

std::string gz(const std::string& in) {
  z_stream z{};
  deflateInit2(&z, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);
  std::string out(in.size() + 256, '\0');
  z.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in.data()));
  z.avail_in = static_cast<uInt>(in.size());
  z.next_out = reinterpret_cast<Bytef*>(out.data());
  z.avail_out = static_cast<uInt>(out.size());
  deflate(&z, Z_FINISH);
  out.resize(z.total_out);
  deflateEnd(&z);
  return out;
}

const char* kEpss =
    "#model_version:v2026.06.15,score_date:2026-10-13T12:00:28Z\n"
    "cve,epss,percentile\n"
    "CVE-2024-0001,0.62000,0.98500\n"
    "CVE-2023-9999,0.00120,0.40000\n"
    "CVE-2023-1111,0.15000,0.95000\n"
    "garbage line\n";

}  // namespace

TEST_CASE("EPSS file parsing") {
  auto f = parseEpssCsv(kEpss);
  REQUIRE(f.ok());
  REQUIRE(f.value().score_date == "2026-10-13");
  REQUIRE(f.value().rows.size() == 3);
  REQUIRE(f.value().rows[0].cve == "CVE-2024-0001");
  REQUIRE(f.value().rows[0].score == Approx(0.62));
  REQUIRE(f.value().rows[0].percentile == Approx(0.985));
  REQUIRE_FALSE(parseEpssCsv("hello\nworld\n").ok());
  REQUIRE_FALSE(parseEpssCsv("cve,epss,percentile\n").ok());
}

TEST_CASE("gunzip: round trip, and a bomb is refused") {
  const std::string text = std::string(10000, 'a') + "end";
  auto back = gunzip(gz(text));
  REQUIRE(back.ok());
  REQUIRE(back.value() == text);
  REQUIRE_FALSE(gunzip("not gzip at all").ok());
  auto bomb = gunzip(gz(std::string(5u << 20, 'x')), 1u << 20);
  REQUIRE_FALSE(bomb.ok());
  REQUIRE(bomb.error().find("too large") != std::string::npos);
}

TEST_CASE("EPSS sync: looks back for the latest published day, stores it and then waits a day") {
  auto db = std::move(VulnDb::open(":memory:").value());
  ScriptedHttp http;
  VulnConfig cfg;
  cfg.epss_url = "https://epss.test/epss_scores-{date}.csv.gz";
  SyncHooks hooks;
  hooks.now = [] { return kNow; };  // 2026-10-14
  http.status("epss_scores-2026-10-14", 403);
  http.ok("epss_scores-2026-10-13", gz(kEpss));
  FeedSync sync(*db, http, cfg, hooks);

  auto rep = sync.syncEpss();
  REQUIRE(rep.ok);
  REQUIRE(rep.items == 3);
  REQUIRE(rep.message.find("2026-10-13") != std::string::npos);
  REQUIRE(http.requested.size() == 2);  // today's file does not exist yet
  auto row = db->getEpss("CVE-2024-0001");
  REQUIRE(row.value());
  REQUIRE(row.value()->score == Approx(0.62));
  REQUIRE_FALSE(db->getEpss("CVE-0000-0000").value());
  REQUIRE(db->stats().value().epss == 3);

  auto again = sync.syncEpss();
  REQUIRE(again.ok);
  REQUIRE(http.requested.size() == 2);  // refreshed once a day

  // nothing published for days: a clear failure, not a crash
  auto db2 = std::move(VulnDb::open(":memory:").value());
  ScriptedHttp none;
  none.status("epss_scores", 404);
  FeedSync sync2(*db2, none, cfg, hooks);
  auto bad = sync2.syncEpss();
  REQUIRE_FALSE(bad.ok);
  REQUIRE(bad.message.find("EPSS") != std::string::npos);
}

namespace {

InstalledPackage pkg(const std::string& name, const std::string& version, const std::string& source = "") {
  InstalledPackage p;
  p.name = name;
  p.version = version;
  p.arch = "amd64";
  p.manager = "dpkg";
  p.source = source.empty() ? name : source;
  p.source_version = version;
  return p;
}

json osvVuln(const std::string& id, std::vector<std::string> aliases, const std::string& pkg_name, const std::string& fixed) {
  return {{"id", id}, {"modified", "2026-10-01T00:00:00Z"}, {"published", "2026-10-10T00:00:00Z"}, {"aliases", aliases}, {"summary", "Advisory " + id},
          {"affected", {{{"package", {{"ecosystem", "Ubuntu:22.04:LTS"}, {"name", pkg_name}}},
                         {"ranges", {{{"type", "ECOSYSTEM"}, {"events", json::array({{{"introduced", "0"}}, {{"fixed", fixed}}})}}}}}}}};
}

CveRecord cve(const std::string& id, double cvss) {
  CveRecord c;
  c.id = id;
  c.cvss = cvss;
  c.severity = cvss >= 9 ? "critical" : cvss >= 7 ? "high" : cvss >= 4 ? "medium" : "low";
  c.published = kNow - 400 * 86400;
  c.modified = c.published;
  c.summary = "Summary of " + id;
  c.status = "Analyzed";
  return c;
}

}  // namespace

TEST_CASE("matches carry the EPSS score, and a high one makes a low-scored CVE worth listing") {
  auto db = std::move(VulnDb::open(":memory:").value());
  ScriptedHttp http;
  VulnConfig cfg;
  cfg.osv_url = "https://osv.test";
  cfg.min_cvss = 7.0;
  REQUIRE(db->upsertCves({cve("CVE-2024-0001", 5.0), cve("CVE-2023-9999", 5.0)}).ok());  // both below the listing threshold
  REQUIRE(db->replaceEpss(parseEpssCsv(kEpss).value().rows).ok());
  http.ok("v1/querybatch", json({{"results", {{{"vulns", {{{"id", "UBUNTU-CVE-2024-0001"}, {"modified", "x"}}, {{"id", "UBUNTU-CVE-2023-9999"}, {"modified", "x"}}}}}}}}).dump());
  http.ok("v1/vulns/UBUNTU-CVE-2024-0001", osvVuln("UBUNTU-CVE-2024-0001", {"CVE-2024-0001"}, "curl", "7.81.0-1ubuntu1.16").dump());
  http.ok("v1/vulns/UBUNTU-CVE-2023-9999", osvVuln("UBUNTU-CVE-2023-9999", {"CVE-2023-9999"}, "curl", "7.81.0-1ubuntu1.16").dump());
  Inventory inv;
  inv.os.id = "ubuntu";
  inv.os.version_id = "22.04";
  inv.packages = {pkg("curl", "7.81.0-1ubuntu1.15")};

  VulnMatcher m(*db, &http, cfg, nullptr, [] { return kNow; });
  auto r = m.match(inv);
  REQUIRE(r.ok());
  const Observation *high = nullptr, *low = nullptr;
  for (const auto& o : r.value().observations) {
    if (o.type != "vuln.match") continue;
    if (o.data["cve"] == "CVE-2024-0001") high = &o;
    if (o.data["cve"] == "CVE-2023-9999") low = &o;
  }
  REQUIRE(high);
  REQUIRE(high->data["epss"] == Approx(0.62));
  REQUIRE(std::find(high->tags.begin(), high->tags.end(), "epss_high") != high->tags.end());
  REQUIRE(high->data["exposed_likely_exploited"] == false);
  REQUIRE_FALSE(low);  // 0.12% and a score of 5: counted, not listed
}

TEST_CASE("exposure: which package listens, which one only runs") {
  auto st = Store::open(":memory:");
  REQUIRE(st.ok());
  Store& store = *st.value();
  REQUIRE(store.recordPackageData("web01", {}, {{"nginx", 0, {"/usr/sbin/nginx"}}, {"openssh-server", 0, {"/usr/sbin/sshd"}}, {"cron", 0, {"/usr/sbin/cron"}}, {"redis-server", 0, {"/usr/bin/redis-server"}}}).ok());

  Snapshot net;
  net.target = "web01";
  net.collector = "network";
  net.ts = 100;
  net.observations.push_back({"socket.inet", "a", {{"proto", "tcp"}, {"local_addr", "0.0.0.0"}, {"local_port", 80}, {"owners", {{{"pid", 5}, {"comm", "nginx"}, {"exe", "/usr/sbin/nginx"}}}}}, {"listening"}});
  net.observations.push_back({"socket.inet", "b", {{"proto", "tcp"}, {"local_addr", "127.0.0.1"}, {"local_port", 6379}, {"owners", {{{"pid", 6}, {"comm", "redis"}, {"exe", "/usr/bin/redis-server"}}}}}, {"listening"}});
  net.observations.push_back({"socket.inet", "c", {{"proto", "tcp"}, {"local_addr", "10.0.0.5"}, {"local_port", 50000}, {"owners", json::array()}}, {}});
  REQUIRE(store.save(net).ok());
  Snapshot procs;
  procs.target = "web01";
  procs.collector = "processes";
  procs.ts = 100;
  procs.observations.push_back({"process", "1", {{"pid", 9}, {"exe", "/usr/sbin/cron"}, {"kernel_thread", false}}, {}});
  procs.observations.push_back({"process", "2", {{"pid", 10}, {"exe", "/usr/sbin/sshd (deleted)"}, {"kernel_thread", false}}, {"exe_deleted"}});
  REQUIRE(store.save(procs).ok());

  const Exposure ex = computeExposure(store, "web01");
  REQUIRE(ex.ownership_known);
  REQUIRE(ex.listening_external.count("nginx"));
  REQUIRE(ex.listening_external.at("nginx")[0] == "tcp/0.0.0.0:80");
  REQUIRE(ex.listening_local.count("redis-server"));
  REQUIRE(ex.running.count("cron"));
  REQUIRE(ex.running.count("openssh-server"));  // the deleted-binary suffix does not hide it
  REQUIRE_FALSE(computeExposure(store, "other").ownership_known);

  auto match = [](const std::string& cve, const std::string& package, std::vector<std::string> tags, double cvss, double epss) {
    Observation o;
    o.type = "vuln.match";
    o.key = "vuln|" + cve + "|" + package;
    o.tags = std::move(tags);
    o.data = {{"cve", cve}, {"package", package}, {"binaries", {package}}, {"cvss", cvss}, {"epss", epss}, {"confidence", "high"}, {"exposed_likely_exploited", false}};
    return o;
  };
  std::vector<Observation> obs = {match("CVE-1", "nginx", {"epss_high", "established"}, 6.0, 0.4), match("CVE-2", "redis-server", {"established"}, 6.0, 0.0),
                                  match("CVE-3", "cron", {"established"}, 6.0, 0.0), match("CVE-4", "libfoo", {"established"}, 6.0, 0.0)};
  annotateMatches(obs, ex);
  REQUIRE(obs[0].data["exposure"] == "listening");
  REQUIRE(obs[0].data["ports"][0] == "tcp/0.0.0.0:80");
  REQUIRE(obs[0].data["exposed_likely_exploited"] == true);
  REQUIRE(obs[1].data["exposure"] == "listening_local");
  REQUIRE(obs[2].data["exposure"] == "running");
  REQUIRE(obs[3].data["exposure"] == "unknown");  // a library: its users cannot be told apart, so nothing is claimed
  // the same score ranks very differently depending on reach
  const int pa = obs[0].data["priority"], pb = obs[1].data["priority"], pc = obs[2].data["priority"], pd = obs[3].data["priority"];
  REQUIRE(pa > pb);
  REQUIRE(pb > pc);
  REQUIRE(pc > pd);
  REQUIRE(pa <= 100);

  // without file lists nothing is known about reach
  std::vector<Observation> blind = {match("CVE-1", "nginx", {"established"}, 6.0, 0.0)};
  annotateMatches(blind, Exposure{});
  REQUIRE(blind[0].data["exposure"] == "unknown");
}

TEST_CASE("priority: exploitation and reach outweigh the raw score") {
  json d = {{"cvss", 9.8}};
  const int plain = vulnPriority(d, {"established"});
  const int kev = vulnPriority(d, {"kev"});
  const int low_but_hot = vulnPriority({{"cvss", 5.0}, {"epss", 0.7}}, {"listening", "epss_high"});
  REQUIRE(kev > plain);
  REQUIRE(low_but_hot > vulnPriority({{"cvss", 5.0}}, {"established"}));
  REQUIRE(vulnPriority({{"cvss", 5.0}}, {"upstream_version_match"}) < vulnPriority({{"cvss", 5.0}}, {}));
  REQUIRE(vulnPriority({{"cvss", 10.0}, {"epss", 0.9}}, {"kev", "listening", "recent"}) == 100);
}

TEST_CASE("rules: a likely-exploited flaw in a network service is its own finding, not a duplicate") {
  auto rules = loadRulesDir(DEFAULT_RULES_DIR);
  REQUIRE(rules.ok());
  auto st = Store::open(":memory:");
  Store& store = *st.value();
  store.lockBaseline("web01", 0);
  Analyzer an(store, rules.value(), std::chrono::seconds(0));
  Snapshot s;
  s.target = "web01";
  s.collector = "vulns";
  s.ts = 500;
  auto m = [](const std::string& cve, double cvss, double epss, bool exposed, std::vector<std::string> tags) {
    Observation o;
    o.type = "vuln.match";
    o.key = "vuln|" + cve + "|pkg";
    o.tags = std::move(tags);
    o.data = {{"cve", cve}, {"package", "pkg"}, {"cvss", cvss}, {"epss", epss}, {"confidence", "high"}, {"kev", false}, {"exposed_likely_exploited", exposed}};
    return o;
  };
  s.observations.push_back(m("CVE-A", 9.8, 0.5, true, {"epss_high", "listening", "established", "fix_available"}));    // VULN-007 only
  s.observations.push_back(m("CVE-B", 9.8, 0.0, false, {"established", "fix_available"}));                            // VULN-004 as before
  s.observations.push_back(m("CVE-C", 5.0, 0.3, false, {"epss_high", "established", "fix_available"}));                // VULN-008
  auto r = an.analyze(s);
  REQUIRE(r.ok());
  std::map<std::string, std::vector<std::string>> by_cve;
  for (const auto& f : r.value().fresh) by_cve[f.evidence["cve"]].push_back(f.rule_id);
  REQUIRE(by_cve["CVE-A"] == std::vector<std::string>{"VULN-007"});
  REQUIRE(by_cve["CVE-B"] == std::vector<std::string>{"VULN-004"});
  REQUIRE(by_cve["CVE-C"] == std::vector<std::string>{"VULN-008"});
}
