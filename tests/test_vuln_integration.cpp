#include <catch2/catch.hpp>

#include <nlohmann/json.hpp>

#include "analysis/analyzer.h"
#include "collectors/vuln_collector.h"
#include "fake_transport.h"
#include "report/report.h"
#include "scripted_http.h"
#include "vuln/intel.h"
#include "vuln/vuln_context.h"

using namespace agent;
using nlohmann::json;

#ifndef DEFAULT_RULES_DIR
#error "DEFAULT_RULES_DIR must be defined by the build"
#endif

namespace {

Observation match(const std::string& cve, const std::string& pkg, double cvss, std::vector<std::string> tags, const std::string& confidence = "high",
                  bool kev = false, std::vector<std::string> cwes = {}) {
  Observation o;
  o.type = "vuln.match";
  o.key = "vuln|" + cve + "|" + pkg;
  o.tags = std::move(tags);
  json c = json::array();
  for (const auto& id : cwes) c.push_back({{"id", id}, {"name", "n"}});
  o.data = {{"cve", cve}, {"package", pkg}, {"installed_version", "1.0"}, {"fixed_version", "1.1"}, {"cvss", cvss >= 0 ? json(cvss) : json(nullptr)}, {"kev", kev},
            {"confidence", confidence}, {"cwes", c}, {"summary", "s"}};
  return o;
}

struct Lab {
  std::unique_ptr<Store> store = std::move(Store::open(":memory:").value());
  std::unique_ptr<Analyzer> analyzer;
  Lab() {
    analyzer = std::make_unique<Analyzer>(*store, std::move(loadRulesDir(DEFAULT_RULES_DIR).value()), std::chrono::seconds(0));
    REQUIRE(store->lockBaseline("t", 1).ok());
  }
  Snapshot snap(std::vector<Observation> obs, int64_t ts) {
    Snapshot s;
    s.target = "t";
    s.collector = "vulns";
    s.ts = ts;
    s.observations = std::move(obs);
    return s;
  }
  std::vector<std::pair<std::string, Severity>> fire(std::vector<Observation> obs, int64_t ts = 5000) {
    auto r = analyzer->analyze(snap(std::move(obs), ts));
    REQUIRE(r.ok());
    std::vector<std::pair<std::string, Severity>> out;
    for (const auto& f : r.value().fresh) out.emplace_back(f.rule_id, f.severity);
    return out;
  }
};

}  // namespace

TEST_CASE("vulnerability rules: every match triggers exactly one rule") {
  Lab lab;
  auto one = [&](Observation o, const char* rule, Severity sev) {
    Lab l;
    const auto fired = l.fire({std::move(o)});
    INFO("expected " << rule);
    REQUIRE(fired.size() == 1);
    REQUIRE(fired[0].first == rule);
    REQUIRE(fired[0].second == sev);
  };
  one(match("CVE-1", "curl", 7.5, {"kev", "recent"}, "high", true), "VULN-001", Severity::Critical);
  one(match("CVE-2", "openssl", 9.8, {"recent"}), "VULN-002", Severity::High);
  one(match("CVE-3", "openssl", 7.5, {"recent"}), "VULN-003", Severity::Medium);
  one(match("CVE-4", "openssl", 9.8, {"established"}), "VULN-004", Severity::Medium);
  one(match("CVE-5", "openssl", 7.2, {"established"}), "VULN-005", Severity::Low);
  one(match("CVE-6", "foo", -1, {"unscored", "recent"}), "VULN-006", Severity::Low);
  one(match("CVE-7", "foo", 9.0, {"kev", "upstream_version_match"}, "low", true), "VULN-010", Severity::Medium);  // a guess is not "critical"
  one(match("CVE-8", "foo", 8.0, {"upstream_version_match", "established"}, "low"), "VULN-011", Severity::Low);

  // boundaries
  one(match("CVE-9", "x", 9.0, {"recent"}), "VULN-002", Severity::High);
  one(match("CVE-10", "x", 8.9, {"recent"}), "VULN-003", Severity::Medium);
  one(match("CVE-11", "x", 7.0, {"established"}), "VULN-005", Severity::Low);

  // below the listing threshold nothing fires (the matcher would not even emit it)
  Lab quiet;
  REQUIRE(quiet.fire({match("CVE-12", "x", 5.0, {"recent"})}).empty());
}

TEST_CASE("vulnerability findings: CWE, dedup, resolution when the package is updated") {
  Lab lab;
  auto first = lab.analyzer->analyze(lab.snap({match("CVE-2026-1", "openssl", 9.8, {"recent"}, "high", false, {"CWE-787", "CWE-125"})}, 5000));
  REQUIRE(first.ok());
  REQUIRE(first.value().fresh.size() == 1);
  const auto& f = first.value().fresh[0];
  REQUIRE(f.cwe == std::vector<std::string>{"CWE-787", "CWE-125"});  // taken from the CVE
  REQUIRE(f.stable_key == "vuln|CVE-2026-1|openssl");
  auto stored = lab.store->getFinding(f.id);
  REQUIRE(stored.value()->cwe == std::vector<std::string>{"CWE-787", "CWE-125"});  // survives the database

  // the same match next hour: a repeat, not a new finding (so no second mail)
  auto again = lab.analyzer->analyze(lab.snap({match("CVE-2026-1", "openssl", 9.8, {"recent"}, "high", false, {"CWE-787"})}, 9000));
  REQUIRE(again.value().fresh.empty());
  REQUIRE(again.value().repeats.size() == 1);

  // a second CVE on the same package is a new finding; the first one still stands
  auto second = lab.analyzer->analyze(lab.snap({match("CVE-2026-1", "openssl", 9.8, {"recent"}), match("CVE-2026-2", "openssl", 9.1, {"recent"})}, 13000));
  REQUIRE(second.value().fresh.size() == 1);
  REQUIRE(second.value().fresh[0].stable_key == "vuln|CVE-2026-2|openssl");

  // the package gets updated: the matches disappear and the findings resolve by themselves
  auto fixed = lab.analyzer->analyze(lab.snap({}, 17000));
  REQUIRE(fixed.value().resolved == 2);
  REQUIRE(lab.store->listFindings("open", 10).value().empty());
  REQUIRE(lab.store->countResolvedSince(16000).value() == 2);
}

TEST_CASE("rule files may carry CWE ids, and they are validated") {
  auto ok = parseRules("- id: T\n  title: t\n  severity: low\n  cwe: [CWE-732, CWE-250]\n  match: {type: process, tags_any: [x]}\n", "mem");
  REQUIRE(ok.ok());
  REQUIRE(ok.value()[0].cwe == std::vector<std::string>{"CWE-732", "CWE-250"});
  for (const char* bad : {"[XSS]", "[CWE-]", "[CWE-12a]", "[cwe-79]", "[79]"}) {
    INFO(bad);
    REQUIRE_FALSE(parseRules(std::string("- id: T\n  title: t\n  severity: low\n  cwe: ") + bad + "\n  match: {type: process, tags_any: [x]}\n", "mem").ok());
  }
  auto defaults = loadRulesDir(DEFAULT_RULES_DIR);
  REQUIRE(defaults.ok());
  size_t with_cwe = 0;
  for (const auto& r : defaults.value()) with_cwe += !r.cwe.empty();
  REQUIRE(with_cwe >= 25);
}

TEST_CASE("reports show the weakness class with its name") {
  Lab lab;
  auto r = lab.analyzer->analyze(lab.snap({match("CVE-2026-1", "openssl", 9.8, {"recent"}, "high", false, {"CWE-787"})}, 5000));
  REQUIRE(r.ok());
  ReportContext ctx;
  ctx.host_label = "h";
  auto alert = buildAlertReport(*lab.store, lab.store->listFindings("open", 10).value(), ctx, 6000);
  REQUIRE(alert.ok());
  const std::string txt = renderText(alert.value()), html = renderHtml(alert.value());
  REQUIRE(txt.find("CWE-787  Out-of-bounds Write") != std::string::npos);  // in the references at the bottom
  REQUIRE(html.find("Out-of-bounds Write") != std::string::npos);
  REQUIRE(html.find("CWE-787") != std::string::npos);

  ctx.cwe_name = [](const std::string& id) { return id == "CWE-787" ? std::string("Catalog name wins") : std::string(); };
  auto custom = buildAlertReport(*lab.store, lab.store->listFindings("open", 10).value(), ctx, 6000);
  REQUIRE(renderText(custom.value()).find("Catalog name wins") != std::string::npos);

  // and a digest carries the intelligence section
  auto db = VulnDb::open(":memory:");
  KevEntry k;
  k.cve = "CVE-2026-9";
  k.added = 5500;
  REQUIRE(db.value()->applyKev({k}).ok());
  ReportContext dctx;
  dctx.lang = "en";
  dctx.intel = makeIntelProvider(*db.value(), *lab.store, "en");
  auto dg = buildDigestReport(*lab.store, 4000, 7000, Severity::Low, dctx);
  REQUIRE(dg.ok());
  REQUIRE_FALSE(dg.value().intel_lines.empty());
  const std::string dtxt = renderText(dg.value()), dhtml = renderHtml(dg.value());
  REQUIRE(dtxt.find("VULNERABILITY INTELLIGENCE") != std::string::npos);
  REQUIRE(dtxt.find("CVE-2026-9") != std::string::npos);                  // new KEV entry of the period
  REQUIRE(dtxt.find("CWE-787 Out-of-bounds Write (1)") != std::string::npos);  // weakness trend
  REQUIRE(dhtml.find("Vulnerability intelligence") != std::string::npos);
}

TEST_CASE("VulnCollector works from the stored inventory") {
  auto store = std::move(Store::open(":memory:").value());
  auto db = std::move(VulnDb::open(":memory:").value());
  ScriptedHttp http;
  http.ok("v1/querybatch", json({{"results", {{{"vulns", {{{"id", "UBUNTU-CVE-2099-1"}, {"modified", "x"}}}}}}}}).dump());
  json vuln = json::object();
  vuln["id"] = "UBUNTU-CVE-2099-1";
  vuln["modified"] = "x";
  vuln["aliases"] = json::array({"CVE-2099-1"});
  vuln["summary"] = "s";
  vuln["severity"] = json::array({json{{"type", "CVSS_V3"}, {"score", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}});
  json events = json::array({json{{"introduced", "0"}}, json{{"fixed", "9.9"}}});
  json range = json{{"type", "ECOSYSTEM"}, {"events", events}};
  json affected = json{{"package", json{{"ecosystem", "Ubuntu:22.04:LTS"}, {"name", "openssl"}}}, {"ranges", json::array({range})}};
  vuln["affected"] = json::array({affected});
  http.ok("v1/vulns/UBUNTU-CVE-2099-1", vuln.dump());
  VulnContext ctx;
  ctx.db = db.get();
  ctx.http = &http;
  ctx.store = store.get();
  ctx.cfg.osv_url = "https://osv.test";
  ctx.cfg.match_every = std::chrono::seconds(900);

  CollectorOptions opts;
  opts.target = "web01";
  opts.vuln = &ctx;
  auto c = makeCollector("vulns");
  REQUIRE(c);
  c->configure(opts);
  REQUIRE(c->defaultInterval().count() == 900);  // follows vuln.match_every

  FakeTransport unused;
  Snapshot none = runCollector(*c, unused, "web01");
  REQUIRE_FALSE(none.error.empty());  // no inventory yet: a clear error, not an empty "all clear"
  REQUIRE(none.error.find("inventory") != std::string::npos);

  Snapshot inv;
  inv.target = "web01";
  inv.collector = "packages";
  inv.ts = static_cast<int64_t>(std::time(nullptr));
  inv.observations.push_back({"os.release", "os", {{"id", "ubuntu"}, {"version_id", "22.04"}}, {}});
  inv.observations.push_back({"pkg.installed", "openssl:amd64", {{"name", "openssl"}, {"version", "3.0.2-1"}, {"arch", "amd64"}, {"source", "openssl"}, {"source_version", "3.0.2-1"}, {"manager", "dpkg"}}, {}});
  REQUIRE(store->save(inv).ok());

  Snapshot s = runCollector(*c, unused, "web01");
  REQUIRE(s.error.empty());
  bool match_found = false, empty_db_warning = false;
  for (const auto& o : s.observations) match_found |= o.type == "vuln.match" && o.data["cve"] == "CVE-2099-1" && o.data["cvss"] == 9.8;
  for (const auto& w : s.warnings) empty_db_warning |= w.find("database is empty") != std::string::npos;
  REQUIRE(match_found);
  REQUIRE(empty_db_warning);  // matching worked through OSV, but the feeds have not been downloaded yet: say so

  // without a context the collector explains itself instead of crashing
  auto lonely = makeCollector("vulns");
  Snapshot bad = runCollector(*lonely, unused, "web01");
  REQUIRE_FALSE(bad.error.empty());
}
