#include <catch2/catch.hpp>

#include <nlohmann/json.hpp>

#include "scripted_http.h"
#include "vuln/feed_parsers.h"
#include "vuln/feed_sync.h"

using namespace agent;

namespace {

constexpr int64_t kNow = 1800000000;  // fixed "current time" of the tests

std::string kevJson(std::initializer_list<const char*> ids) {
  nlohmann::json j = {{"catalogVersion", "x"}, {"count", ids.size()}, {"vulnerabilities", nlohmann::json::array()}};
  for (const char* id : ids) {
    j["vulnerabilities"].push_back({{"cveID", id}, {"vendorProject", "V"}, {"product", "P"}, {"vulnerabilityName", std::string("Name ") + id},
                                    {"dateAdded", "2026-10-19"}, {"shortDescription", "d"}, {"requiredAction", "patch"}, {"dueDate", "2026-11-09"}});
  }
  return j.dump();
}

// An NVD page with `n` CVEs numbered from `first`, out of `total`.
std::string nvdJson(int first, int n, int total, int start_index) {
  nlohmann::json j = {{"resultsPerPage", n}, {"startIndex", start_index}, {"totalResults", total}, {"vulnerabilities", nlohmann::json::array()}};
  for (int i = 0; i < n; ++i) {
    j["vulnerabilities"].push_back({{"cve", {{"id", "CVE-2026-" + std::to_string(1000 + first + i)},
                                             {"vulnStatus", "Analyzed"},
                                             {"published", "2026-10-01T00:00:00.000"},
                                             {"lastModified", "2026-10-02T00:00:00.000"},
                                             {"descriptions", {{{"lang", "en"}, {"value", "desc"}}}},
                                             {"weaknesses", {{{"description", {{{"lang", "en"}, {"value", i % 2 ? "CWE-79" : "CWE-787"}}}}}}}}}});
  }
  return j.dump();
}

struct Env {
  std::unique_ptr<VulnDb> db = std::move(VulnDb::open(":memory:").value());
  ScriptedHttp http;
  VulnConfig cfg;
  std::vector<std::chrono::milliseconds> sleeps;
  bool cancel = false;
  SyncHooks hooks;
  Env() {
    cfg.nvd_initial_days = 10;
    hooks.now = [] { return kNow; };
    hooks.sleep = [this](std::chrono::milliseconds ms) { sleeps.push_back(ms); };
    hooks.cancelled = [this] { return cancel; };
  }
  FeedSync sync() { return FeedSync(*db, http, cfg, hooks); }
};

size_t indexOf(const std::string& url) {
  const size_t p = url.find("startIndex=");
  return p == std::string::npos ? 0 : static_cast<size_t>(std::stoul(url.substr(p + 11)));
}

}  // namespace

TEST_CASE("sync: KEV catalog and what is new in it") {
  Env e;
  e.http.ok("known_exploited", kevJson({"CVE-2021-44228", "CVE-2026-0001"}));
  auto first = e.sync().syncKev();
  REQUIRE(first.ok);
  REQUIRE(first.items == 2);
  REQUIRE(first.new_kev.empty());  // the initial load is not news
  REQUIRE(e.db->getCve("CVE-2026-0001").value()->kev);
  REQUIRE(e.db->getMeta("kev_count").value() == "2");

  e.http = ScriptedHttp();
  e.http.ok("known_exploited", kevJson({"CVE-2021-44228", "CVE-2026-0001", "CVE-2026-7777"}));
  auto second = e.sync().syncKev();
  REQUIRE(second.ok);
  REQUIRE(second.new_kev == std::vector<std::string>{"CVE-2026-7777"});

  Env bad;
  bad.http.status("known_exploited", 503);
  auto down = bad.sync().syncKev();
  REQUIRE_FALSE(down.ok);
  REQUIRE(down.message.find("503") != std::string::npos);
  Env junk;
  junk.http.ok("known_exploited", "<html>maintenance</html>");
  REQUIRE_FALSE(junk.sync().syncKev().ok);
  REQUIRE(junk.db->stats().value().kev == 0);  // garbage never reaches the database
}

TEST_CASE("sync: NVD pages, windows and the polite rate") {
  Env e;
  // 3 CVEs served as a page of 2 plus a page of 1
  e.http.on("nvd.test", [](const std::string& url) -> Result<HttpResponse> {
    return HttpResponse{200, indexOf(url) == 0 ? nvdJson(0, 2, 3, 0) : nvdJson(2, 1, 3, 2)};
  });
  e.cfg.nvd_url = "https://nvd.test/cves";
  auto r = e.sync().syncNvd();
  REQUIRE(r.ok);
  REQUIRE_FALSE(r.partial);
  REQUIRE(r.items == 3);
  REQUIRE(e.http.requested.size() == 2);
  REQUIRE(e.http.requested[0].find("lastModStartDate=" + formatNvdTime(kNow - 10 * 86400) + "Z") != std::string::npos);
  REQUIRE(e.http.requested[0].find("lastModEndDate=" + formatNvdTime(kNow) + "Z") != std::string::npos);
  REQUIRE(e.http.requested[0].find("resultsPerPage=1000") != std::string::npos);
  REQUIRE(e.http.requested[1].find("startIndex=2") != std::string::npos);
  REQUIRE(e.db->stats().value().cves == 3);
  REQUIRE(e.db->getCve("CVE-2026-1002").value().has_value());
  REQUIRE(e.db->getMeta("nvd_last_sync").value() == std::to_string(kNow));

  // the second request waited for the NVD's rate limit (no API key: ~6.5 s)
  REQUIRE(e.sleeps.size() == 1);
  REQUIRE(e.sleeps[0] >= std::chrono::milliseconds(6000));
  for (const auto& h : e.http.request_headers) for (const auto& line : h) REQUIRE(line.rfind("apiKey", 0) != 0);

  // next run starts where the last one ended (minus a small overlap), not from the beginning
  e.http = ScriptedHttp();
  e.http.ok("nvd.test", nvdJson(0, 0, 0, 0));
  Env* keep = &e;
  FeedSync again = e.sync();
  (void)keep;
  auto r2 = again.syncNvd();
  REQUIRE(r2.ok);
  REQUIRE(r2.items == 0);
  REQUIRE(e.http.requested[0].find("lastModStartDate=" + formatNvdTime(kNow - 600) + "Z") != std::string::npos);
}

TEST_CASE("sync: NVD long look-back is split in windows of at most 120 days") {
  Env e;
  e.cfg.nvd_initial_days = 300;
  e.cfg.nvd_url = "https://nvd.test/cves";
  e.http.ok("nvd.test", nvdJson(0, 0, 0, 0));
  auto r = e.sync().syncNvd();
  REQUIRE(r.ok);
  REQUIRE(e.http.requested.size() == 3);  // 300 days = 119 + 119 + 62
  int64_t prev_end = 0;
  for (const auto& url : e.http.requested) {
    const size_t s = url.find("lastModStartDate=") + 17, en = url.find("lastModEndDate=") + 15;
    const int64_t start = parseIsoTime(url.substr(s, 23)), end = parseIsoTime(url.substr(en, 23));
    REQUIRE(end - start <= 119 * 86400);
    if (prev_end) REQUIRE(start == prev_end);  // windows are contiguous
    prev_end = end;
  }
  REQUIRE(prev_end == kNow);
}

TEST_CASE("sync: NVD resumes after an interruption or a rate limit") {
  Env e;
  e.cfg.nvd_url = "https://nvd.test/cves";
  int served = 0;
  e.http.on("nvd.test", [&](const std::string& url) -> Result<HttpResponse> {
    ++served;
    const size_t idx = indexOf(url);
    if (idx == 0) return HttpResponse{200, nvdJson(0, 2, 5, 0)};
    if (idx == 2) return HttpResponse{200, nvdJson(2, 2, 5, 2)};
    return HttpResponse{200, nvdJson(4, 1, 5, 4)};
  });
  // stop after the first page
  FeedSync s1(*e.db, e.http, e.cfg, e.hooks);
  e.hooks.cancelled = [&] { return served >= 1; };
  FeedSync interrupted(*e.db, e.http, e.cfg, e.hooks);
  auto r1 = interrupted.syncNvd();
  REQUIRE(r1.ok);
  REQUIRE(r1.partial);
  REQUIRE(r1.items == 2);
  REQUIRE(e.db->getMeta("nvd_last_sync").value().value_or("").empty());  // not finished: no "synced" mark

  // next run continues at index 2, not 0
  e.http.requested.clear();
  e.hooks.cancelled = [] { return false; };
  FeedSync resumed(*e.db, e.http, e.cfg, e.hooks);
  auto r2 = resumed.syncNvd();
  REQUIRE(r2.ok);
  REQUIRE_FALSE(r2.partial);
  REQUIRE(indexOf(e.http.requested[0]) == 2);
  REQUIRE(e.db->stats().value().cves == 5);

  // a 429 in the middle keeps what was stored and resumes later
  Env limited;
  limited.cfg.nvd_url = "https://nvd.test/cves";
  int calls = 0;
  limited.http.on("nvd.test", [&](const std::string& url) -> Result<HttpResponse> {
    if (++calls == 2) return HttpResponse{429, "slow down"};
    return HttpResponse{200, indexOf(url) == 0 ? nvdJson(0, 2, 4, 0) : nvdJson(2, 2, 4, 2)};
  });
  auto rl = limited.sync().syncNvd();
  REQUIRE_FALSE(rl.ok);
  REQUIRE(rl.partial);
  REQUIRE(rl.message.find("rate limited") != std::string::npos);
  REQUIRE(limited.db->stats().value().cves == 2);
  auto rl2 = limited.sync().syncNvd();
  REQUIRE(rl2.ok);
  REQUIRE(limited.db->stats().value().cves == 4);
}

TEST_CASE("sync: an NVD API key raises the rate and is sent as a header") {
  Env e;
  e.cfg.nvd_url = "https://nvd.test/cves";
  e.hooks.nvd_api_key = "secret-key";
  e.http.on("nvd.test", [](const std::string& url) -> Result<HttpResponse> {
    return HttpResponse{200, indexOf(url) == 0 ? nvdJson(0, 2, 3, 0) : nvdJson(2, 1, 3, 2)};
  });
  REQUIRE(e.sync().syncNvd().ok);
  bool sent = false;
  for (const auto& h : e.http.request_headers) for (const auto& line : h) sent |= line == "apiKey: secret-key";
  REQUIRE(sent);
  REQUIRE(e.sleeps.size() == 1);
  REQUIRE(e.sleeps[0] < std::chrono::milliseconds(1000));  // 0.7 s instead of 6.5 s
}

TEST_CASE("sync: CWE descriptions are fetched for what the CVEs reference") {
  Env e;
  e.cfg.cwe_url = "https://cwe.test/api/v1";
  CveRecord a, b;
  a.id = "CVE-2026-1";
  a.cwes = {"CWE-79", "CWE-787"};
  b.id = "CVE-2026-2";
  b.cwes = {"CWE-16", "CWE-79"};  // CWE-16 is a category: the API answers nothing for it
  REQUIRE(e.db->upsertCves({a, b}).ok());
  e.http.on("cwe.test", [](const std::string& url) -> Result<HttpResponse> {
    nlohmann::json j = {{"Weaknesses", nlohmann::json::array()}};
    for (const char* id : {"79", "787"}) {
      if (url.find(std::string("/") + id) == std::string::npos && url.find(std::string(",") + id) == std::string::npos && url.find(std::string("weakness/") + id) == std::string::npos) continue;
      j["Weaknesses"].push_back({{"ID", id}, {"Name", std::string("Name of ") + id}, {"Status", "Stable"}, {"Description", "d"}});
    }
    return HttpResponse{200, j.dump()};
  });
  auto r = e.sync().syncCwe();
  REQUIRE(r.ok);
  REQUIRE(e.http.requested.size() == 1);
  REQUIRE(e.http.requested[0].rfind("https://cwe.test/api/v1/cwe/weakness/", 0) == 0);  // one batched request...
  for (const char* id : {"16", "79", "787"}) REQUIRE(e.http.requested[0].find(id) != std::string::npos);  // ...for the three ids
  REQUIRE(e.db->getCwe("CWE-79").value()->name == "Name of 79");
  REQUIRE(e.db->getCwe("CWE-787").value()->name == "Name of 787");
  REQUIRE(e.db->getCwe("CWE-16").value()->status == "unavailable");  // remembered: not asked again right away
  REQUIRE(e.sync().syncCwe().message == "nothing to fetch");

  // a failing batch falls back to single requests (one unknown id must not hide the others)
  Env f;
  f.cfg.cwe_url = "https://cwe.test/api/v1";
  CveRecord c;
  c.id = "CVE-2026-3";
  c.cwes = {"CWE-79", "CWE-99999"};
  REQUIRE(f.db->upsertCves({c}).ok());
  f.http.on("cwe.test", [](const std::string& url) -> Result<HttpResponse> {
    if (url.find(',') != std::string::npos) return HttpResponse{404, "{}"};
    if (url.find("99999") != std::string::npos) return HttpResponse{404, "{}"};
    return HttpResponse{200, R"J({"Weaknesses":[{"ID":"79","Name":"XSS"}]})J"};
  });
  auto rf = f.sync().syncCwe();
  REQUIRE(rf.ok);
  REQUIRE(f.db->getCwe("CWE-79").value()->name == "XSS");
  REQUIRE(f.db->getCwe("CWE-99999").value()->status == "unavailable");
}

TEST_CASE("sync: single CVE lookup and syncAll order") {
  Env e;
  e.cfg.nvd_url = "https://nvd.test/cves";
  e.http.on("cveId=CVE-2026-1000", [](const std::string&) -> Result<HttpResponse> { return HttpResponse{200, nvdJson(0, 1, 1, 0)}; });
  e.http.on("cveId=CVE-2026-9999", [](const std::string&) -> Result<HttpResponse> { return HttpResponse{200, nvdJson(0, 0, 0, 0)}; });
  REQUIRE(e.sync().fetchCve("CVE-2026-1000").ok());
  REQUIRE(e.db->getCve("CVE-2026-1000").value().has_value());
  auto missing = e.sync().fetchCve("CVE-2026-9999");
  REQUIRE_FALSE(missing.ok());
  REQUIRE(missing.error().find("no record") != std::string::npos);
  REQUIRE_FALSE(e.sync().fetchCve("CVE-1; rm -rf /").ok());  // never concatenated into a URL unchecked
  REQUIRE_FALSE(e.sync().fetchCve("../etc/passwd").ok());

  Env all;
  all.cfg.kev_url = "https://kev.test/k.json";
  all.cfg.nvd_url = "https://nvd.test/cves";
  all.cfg.cwe_url = "https://cwe.test/api";
  all.http.ok("kev.test", kevJson({"CVE-2026-0001"}));
  all.http.ok("nvd.test", nvdJson(0, 1, 1, 0));
  all.http.ok("cwe.test", R"J({"Weaknesses":[{"ID":"787","Name":"OOB"},{"ID":"79","Name":"XSS"}]})J");
  all.cfg.epss_url = "https://epss.test/{date}.csv";
  all.http.status("epss.test", 404);  // not published: the feed reports a failure and the others carry on
  auto reports = all.sync().syncAll();
  REQUIRE(reports.size() == 4);
  REQUIRE(reports[0].feed == "kev");
  REQUIRE(reports[1].feed == "nvd");
  REQUIRE(reports[2].feed == "epss");
  REQUIRE_FALSE(reports[2].ok);
  REQUIRE(reports[3].feed == "cwe");
  REQUIRE(reports[3].items == 2);  // CWE runs last: it needed the ids the NVD feed delivered

  Env some;
  some.cfg.nvd = false;
  some.cfg.cwe = false;
  some.cfg.epss = false;
  some.cfg.kev_url = "https://kev.test/k.json";
  some.http.ok("kev.test", kevJson({"CVE-2026-0001"}));
  auto only = some.sync().syncAll();
  REQUIRE(only.size() == 1);
  REQUIRE(only[0].feed == "kev");
}

TEST_CASE("config: vuln section") {
  auto cfg = [](const std::string& body) { return parseConfig("vuln:\n" + body + "targets: [{name: a, transport: local}]\n"); };
  auto ok = cfg("  refresh_every: 12h\n  match_every: 30m\n  osv: false\n  cpe_match: always\n  nvd_initial_days: 30\n  min_cvss: 8.5\n  new_within_days: 7\n  nvd_url: http://mirror.local/nvd\n");
  REQUIRE(ok.ok());
  REQUIRE(ok.value().vuln.refresh_every.count() == 43200);
  REQUIRE_FALSE(ok.value().vuln.osv);
  REQUIRE(ok.value().vuln.cpe_match == "always");
  REQUIRE(ok.value().vuln.nvd_url == "http://mirror.local/nvd");
  REQUIRE(parseConfig("targets: [{name: a, transport: local}]\n").value().vuln.enabled);  // on by default
  REQUIRE_FALSE(cfg("  refresh_every: 5m\n").ok());                 // be polite with public services
  REQUIRE_FALSE(cfg("  cpe_match: sometimes\n").ok());
  REQUIRE_FALSE(cfg("  min_cvss: 11\n").ok());
  REQUIRE_FALSE(cfg("  nvd_initial_days: 0\n").ok());
  REQUIRE_FALSE(cfg("  kev_url: ftp://x\n").ok());
  REQUIRE_FALSE(cfg("  match_every: soon\n").ok());
}
