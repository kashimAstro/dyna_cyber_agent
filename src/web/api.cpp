#include "analysis/incident.h"
#include "web/api.h"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <numeric>
#include <set>

#include "app/synthesis.h"
#include "llm/context.h"
#include "report/mitre_names.h"
#include "report/text_util.h"

namespace agent {
namespace {

using nlohmann::json;

constexpr size_t kMaxAnalysisFindings = 24;
constexpr int kMaxRunningJobs = 3;

HttpReply jsonReply(const json& j, int status = 200) { return {status, "application/json; charset=utf-8", j.dump(-1, ' ', false, json::error_handler_t::replace)}; }
HttpReply error(int status, const std::string& msg) { return jsonReply({{"error", msg}}, status); }

bool sameToken(const std::string& a, const std::string& b) {
  if (a.size() != b.size()) return false;
  unsigned char diff = 0;
  for (size_t i = 0; i < a.size(); ++i) diff |= static_cast<unsigned char>(a[i] ^ b[i]);
  return diff == 0;
}

std::string lower(std::string s) {
  for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

int toInt(const std::map<std::string, std::string>& q, const char* key, int def, int lo, int hi) {
  const auto it = q.find(key);
  if (it == q.end()) return def;
  try { return std::max(lo, std::min(hi, std::stoi(it->second))); } catch (...) { return def; }
}

std::string qget(const std::map<std::string, std::string>& q, const char* key) {
  const auto it = q.find(key);
  return it == q.end() ? std::string() : it->second;
}

json assessmentJson(const Assessment& a) {
  return {{"verdict", a.verdict}, {"risk", toString(a.risk)}, {"confidence", a.confidence}, {"explanation", a.explanation},
          {"recommended_actions", a.recommended_actions}, {"additional_checks", a.additional_checks}, {"flags", a.flags}, {"created_at", a.created_at}};
}

json correlationJson(const Correlation& c) {
  return {{"title", c.title}, {"narrative", c.narrative}, {"risk", toString(c.risk)}, {"finding_ids", c.finding_ids}, {"mitre", c.mitre}};
}

json bySeverity(const std::array<size_t, 5>& a) {
  return {{"critical", a[4]}, {"high", a[3]}, {"medium", a[2]}, {"low", a[1]}, {"info", a[0]}};
}

}  // namespace

WebApi::WebApi(Deps d) : d_(std::move(d)) {
  if (!d_.clock) {
    d_.clock = [] { return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count(); };
  }
}

WebApi::~WebApi() {
  std::vector<std::thread> threads;
  {
    std::lock_guard<std::mutex> lock(mu_);
    threads.swap(threads_);
  }
  for (auto& t : threads) if (t.joinable()) t.join();
}

int64_t WebApi::now() const { return d_.clock(); }

json WebApi::findingSummary(const Finding& f, const std::optional<Assessment>& a) const {
  json j = {{"id", f.id}, {"rule_id", f.rule_id}, {"title", f.title}, {"severity", toString(f.severity)},
            {"effective", toString(effectiveSeverity(f, a))}, {"target", f.target}, {"collector", f.collector},
            {"subject", f.stable_key}, {"status", f.status}, {"first_seen", f.first_seen}, {"last_seen", f.last_seen},
            {"occurrences", f.occurrences}, {"tags", f.tags}, {"mitre", f.mitre}, {"cwe", f.cwe}, {"assessed", a.has_value()}};
  if (a) {
    j["verdict"] = a->verdict;
    j["ai_risk"] = toString(a->risk);
  }
  return j;
}

HttpReply WebApi::handle(const HttpRequest& req) {
  if (req.path == "/" || req.path == "/index.html") {
    if (req.method != "GET") return error(405, "method not allowed");
    std::string page = kConsoleHtml;  // the page is Italian; lang="en" switches its string table
    const auto at = page.find("@LANG@");
    if (at != std::string::npos) page.replace(at, 6, d_.cfg.language == "en" ? "en" : "it");
    return {200, "text/html; charset=utf-8", std::move(page)};
  }
  if (req.path.rfind("/api/", 0) != 0) return error(404, "not found");

  const auto auth = req.headers.find("authorization");
  if (auth == req.headers.end() || auth->second.rfind("Bearer ", 0) != 0 || !sameToken(auth->second.substr(7), d_.token)) {
    return error(401, "token missing or wrong");
  }

  const std::string& p = req.path;
  if (req.method == "GET") {
    if (p == "/api/overview") return overview();
    if (p == "/api/findings") return findings(req);
    if (p.rfind("/api/findings/", 0) == 0) {
      try { return findingDetail(std::stoll(p.substr(14))); } catch (...) { return error(400, "bad id"); }
    }
    if (p == "/api/vulns") return vulns(req);
    if (p == "/api/notifications") return notifications();
    if (p == "/api/incidents") return incidents();
    if (p.rfind("/api/incidents/", 0) == 0) {
      try { return incidentDetail(std::stoll(p.substr(15))); } catch (...) { return error(400, "bad id"); }
    }
    if (p == "/api/sources") return sources(req);
    if (p.rfind("/api/jobs/", 0) == 0) return jobStatus(p.substr(10));
    return error(404, "not found");
  }
  if (req.method == "POST") {
    const json body = req.body.empty() ? json::object() : json::parse(req.body, nullptr, false);
    if (body.is_discarded() || !body.is_object()) return error(400, "body must be a JSON object");
    if (p == "/api/analyze") return startAnalysis(body);
    if (p == "/api/report") return startReport(body);
    return error(404, "not found");
  }
  return error(405, "method not allowed");
}

HttpReply WebApi::overview() {
  Store& st = *d_.store;
  const int64_t t = now();
  json o = {{"generated_at", t}, {"version", d_.version}, {"host", d_.report_ctx.host_label},
            {"llm", {{"enabled", d_.cfg.llm.enabled}, {"usable", d_.llm != nullptr}}}};

  std::array<size_t, 5> sev{};
  std::array<size_t, 5> vband{};
  size_t security_open = 0, vuln_total = 0, kev = 0, with_fix = 0, new_24h = 0;
  std::set<std::string> packages;
  json top = json::array();
  if (auto open = st.listFindings("open", 100000)) {
    std::vector<std::pair<Severity, Finding>> sec;
    for (auto& f : open.value()) {
      auto a = st.latestAssessment(f.id);
      const std::optional<Assessment> as = a && a.value() ? a.value() : std::nullopt;
      const Severity eff = effectiveSeverity(f, as);
      ++sev[static_cast<size_t>(eff)];
      if (f.first_seen >= t - 86400) ++new_24h;
      if (isVulnFinding(f)) {
        ++vuln_total;
        const double cvss = f.evidence.contains("cvss") && f.evidence["cvss"].is_number() ? f.evidence["cvss"].get<double>() : -1;
        const bool k = hasTag(f, "kev");
        ++vband[k || cvss >= 9.0 ? 4 : cvss >= 7.0 ? 3 : cvss >= 4.0 ? 2 : 1];
        kev += k;
        with_fix += hasTag(f, "fix_available");
        packages.insert(f.target + "|" + f.evidence.value("package", std::string()));
      } else {
        ++security_open;
        sec.emplace_back(eff, std::move(f));
      }
    }
    std::stable_sort(sec.begin(), sec.end(), [](const auto& a, const auto& b) {
      return a.first != b.first ? a.first > b.first : a.second.last_seen > b.second.last_seen;
    });
    for (size_t i = 0; i < sec.size() && i < 8; ++i) {
      auto a = st.latestAssessment(sec[i].second.id);
      top.push_back(findingSummary(sec[i].second, a && a.value() ? a.value() : std::nullopt));
    }
  }
  o["open"] = {{"total", std::accumulate(sev.begin(), sev.end(), size_t(0))}, {"by_severity", bySeverity(sev)}, {"security", security_open}};
  o["vulns"] = {{"total", vuln_total}, {"kev", kev}, {"with_fix", with_fix}, {"packages", packages.size()}, {"by_band", bySeverity(vband)}};
  o["new_24h"] = new_24h;
  if (auto incs = st.listIncidents("open", 500)) {
    size_t serious = 0;
    for (const auto& i : incs.value()) serious += i.severity >= Severity::High;
    o["incidents"] = {{"open", incs.value().size()}, {"high_or_critical", serious}};
  }
  if (auto n = st.countResolvedSince(t - 86400)) o["resolved_24h"] = n.value();
  o["top"] = top;

  json targets = json::array();
  for (const auto& tc : d_.cfg.targets) {
    json x = {{"name", tc.name}, {"transport", tc.transport}};
    if (auto m = st.baselineMeta(tc.name, t)) {
      const int64_t ends = m.value().started_at + d_.cfg.baseline_learning.count();
      const bool learning = !m.value().locked && t < ends;
      x["baseline"] = {{"state", learning ? "learning" : "enforcing"}, {"locked", m.value().locked}, {"started_at", m.value().started_at}, {"ends_at", ends}};
      if (auto n = st.baselineSize(tc.name)) x["baseline"]["identities"] = n.value();
    }
    targets.push_back(std::move(x));
  }
  o["targets"] = targets;

  json health = json::array();
  if (auto h = st.collectorHealth(t - 86400)) {
    for (const auto& r : h.value()) {
      const auto it = d_.report_ctx.intervals.find(r.target + "|" + r.collector);
      const bool stale = it != d_.report_ctx.intervals.end() && (r.last_ok == 0 || t - r.last_ok > it->second * 3 + 120);
      health.push_back({{"target", r.target}, {"collector", r.collector}, {"last_ok", r.last_ok}, {"last_error_ts", r.last_error_ts},
                        {"last_error", r.last_error}, {"ok", r.ok_count}, {"errors", r.error_count}, {"stale", stale}});
    }
  }
  o["health"] = health;
  return jsonReply(o);
}

HttpReply WebApi::findings(const HttpRequest& req) {
  Store& st = *d_.store;
  const std::string status = qget(req.query, "status").empty() ? "open" : qget(req.query, "status");
  const auto all = st.listFindings(status == "all" ? "" : status, 100000);
  if (!all) return error(500, all.error());
  const Severity min = parseSeverity(qget(req.query, "severity")).value_or(Severity::Info);
  const std::string collector = qget(req.query, "collector"), target = qget(req.query, "target"), q = lower(qget(req.query, "q"));
  const bool hide_vulns = qget(req.query, "vulns") == "no";
  const int limit = toInt(req.query, "limit", 200, 1, 1000), offset = toInt(req.query, "offset", 0, 0, 1000000);

  std::vector<std::pair<Severity, json>> rows;
  size_t total = 0;
  for (const auto& f : all.value()) {
    if (!collector.empty() && f.collector != collector) continue;
    if (!target.empty() && f.target != target) continue;
    if (hide_vulns && isVulnFinding(f)) continue;
    auto a = st.latestAssessment(f.id);
    const std::optional<Assessment> as = a && a.value() ? a.value() : std::nullopt;
    const Severity eff = effectiveSeverity(f, as);
    if (eff < min) continue;
    if (!q.empty()) {
      std::string hay = lower(f.rule_id + " " + f.title + " " + f.target + " " + f.stable_key + " " + f.collector);
      for (const auto& t : f.tags) hay += " " + lower(t);
      for (const auto& m : f.mitre) hay += " " + lower(m);
      if (hay.find(q) == std::string::npos) continue;
    }
    ++total;
    rows.emplace_back(eff, findingSummary(f, as));
  }
  std::stable_sort(rows.begin(), rows.end(), [](const auto& a, const auto& b) {
    if (a.first != b.first) return a.first > b.first;
    return a.second["last_seen"].template get<int64_t>() > b.second["last_seen"].template get<int64_t>();
  });
  json items = json::array();
  for (size_t i = static_cast<size_t>(offset); i < rows.size() && items.size() < static_cast<size_t>(limit); ++i) items.push_back(rows[i].second);
  return jsonReply({{"total", total}, {"offset", offset}, {"items", items}});
}

HttpReply WebApi::findingDetail(int64_t id) {
  Store& st = *d_.store;
  auto f = st.getFinding(id);
  if (!f) return error(500, f.error());
  if (!f.value()) return error(404, "no such finding");
  auto a = st.latestAssessment(id);
  const std::optional<Assessment> as = a && a.value() ? a.value() : std::nullopt;
  json j = findingSummary(*f.value(), as);
  j["description"] = f.value()->description;
  j["remediation"] = f.value()->remediation;
  j["evidence"] = f.value()->evidence;
  json drift = json::array();
  for (const auto& d : f.value()->drift) drift.push_back({{"facet", d.facet}, {"key", d.key}});
  j["drift"] = drift;
  json mitre = json::array();
  for (const auto& m : f.value()->mitre) mitre.push_back({{"id", m}, {"name", mitreName(m)}});
  j["mitre_names"] = mitre;
  if (as) j["assessment"] = assessmentJson(*as);
  if (auto inc = st.incidentOfFinding(id); inc && inc.value()) j["incident_id"] = *inc.value();
  return jsonReply(j);
}

HttpReply WebApi::vulns(const HttpRequest& req) {
  Store& st = *d_.store;
  const auto all = st.listFindings("open", 100000);
  if (!all) return error(500, all.error());
  const std::string q = lower(qget(req.query, "q")), target = qget(req.query, "target"), only = qget(req.query, "only");
  const int limit = toInt(req.query, "limit", 500, 1, 3000);
  json rows = json::array();
  size_t total = 0;
  std::vector<json> list;
  for (const auto& f : all.value()) {
    if (!isVulnFinding(f)) continue;
    if (!target.empty() && f.target != target) continue;
    const bool kev = hasTag(f, "kev"), recent = hasTag(f, "recent");
    if (only == "kev" && !kev) continue;
    if (only == "recent" && !recent) continue;
    if (only == "fix" && !hasTag(f, "fix_available")) continue;
    if (only == "exposed" && f.evidence.value("exposure", std::string()) != "listening") continue;
    const auto& e = f.evidence;
    const std::string cve = e.value("cve", std::string()), pkg = e.value("package", std::string());
    if (!q.empty() && lower(cve + " " + pkg + " " + e.value("summary", std::string())).find(q) == std::string::npos) continue;
    ++total;
    json cwes = json::array();
    if (e.contains("cwes") && e["cwes"].is_array()) cwes = e["cwes"];
    list.push_back({{"id", f.id}, {"cve", cve}, {"package", pkg}, {"target", f.target}, {"installed", e.value("installed_version", std::string())},
                    {"fixed", e.value("fixed_version", std::string())}, {"cvss", e.value("cvss", json())}, {"kev", kev}, {"recent", recent},
                    {"low_confidence", hasTag(f, "upstream_version_match")}, {"published", e.value("published", std::string())},
                    {"summary", e.value("summary", std::string())}, {"cwes", cwes}, {"rule_id", f.rule_id}, {"severity", toString(f.severity)},
                    {"epss", e.value("epss", json())}, {"priority", e.value("priority", json())}, {"exposure", e.value("exposure", std::string("unknown"))},
                    {"ports", e.value("ports", json::array())}, {"reboot_pending", hasTag(f, "reboot_pending")}});
  }
  std::stable_sort(list.begin(), list.end(), [](const json& a, const json& b) {
    const int pa = a["priority"].is_number() ? a["priority"].get<int>() : -1, pb = b["priority"].is_number() ? b["priority"].get<int>() : -1;
    if (pa != pb) return pa > pb;
    if (a["kev"] != b["kev"]) return a["kev"].get<bool>();
    const double ca = a["cvss"].is_number() ? a["cvss"].get<double>() : -1, cb = b["cvss"].is_number() ? b["cvss"].get<double>() : -1;
    return ca > cb;
  });
  for (size_t i = 0; i < list.size() && i < static_cast<size_t>(limit); ++i) rows.push_back(std::move(list[i]));
  return jsonReply({{"total", total}, {"items", rows}});
}

namespace {
json incidentJson(const Store::IncidentRow& i, const std::string& lang) {
  return {{"id", i.id}, {"severity", toString(i.severity)}, {"status", i.status}, {"title", incidentTitle(i.stages, i.targets, lang)}, {"first_ts", i.first_ts},
          {"last_ts", i.last_ts}, {"created_at", i.created_at}, {"targets", i.targets}, {"entities", i.entities}, {"stages", i.stages},
          {"stage_names", [&] {
             json n = json::array();
             for (const auto& s : i.stages) n.push_back(tacticName(s.get<std::string>(), lang));
             return n;
           }()},
          {"finding_ids", i.finding_ids}};
}
}  // namespace

HttpReply WebApi::incidents() {
  auto list = d_.store->listIncidents("", 100);
  if (!list) return error(500, list.error());
  json items = json::array();
  for (const auto& i : list.value()) items.push_back(incidentJson(i, d_.cfg.language));
  return jsonReply({{"items", items}, {"enabled", d_.cfg.analysis.incidents}});
}

HttpReply WebApi::incidentDetail(int64_t id) {
  auto i = d_.store->getIncident(id);
  if (!i) return error(500, i.error());
  if (!i.value()) return error(404, "no such incident");
  json j = incidentJson(*i.value(), d_.cfg.language);
  json tl = json::array();
  for (int64_t fid : i.value()->finding_ids) {
    auto f = d_.store->getFinding(fid);
    if (!f || !f.value()) continue;
    auto a = d_.store->latestAssessment(fid);
    tl.push_back(findingSummary(*f.value(), a && a.value() ? a.value() : std::nullopt));
  }
  std::stable_sort(tl.begin(), tl.end(), [](const json& a, const json& b) { return a["first_seen"].get<int64_t>() < b["first_seen"].get<int64_t>(); });
  j["timeline"] = tl;
  return jsonReply(j);
}

HttpReply WebApi::notifications() {
  auto ns = d_.store->listNotifications(60);
  if (!ns) return error(500, ns.error());
  json items = json::array();
  for (const auto& n : ns.value()) {
    items.push_back({{"id", n.id}, {"kind", n.kind}, {"created_at", n.created_at}, {"subject", n.subject}, {"recipients", n.recipients},
                     {"status", n.status}, {"error", n.error}, {"findings", n.finding_ids.size()}, {"summary", n.summary}});
  }
  return jsonReply({{"items", items}});
}

HttpReply WebApi::sources(const HttpRequest& req) {
  const int days = toInt(req.query, "days", 7, 0, 3650);  // 0 = everything
  const std::string target = qget(req.query, "target");
  const int64_t t = now();
  auto rows = d_.store->listSources(days == 0 ? 0 : t - days * 86400LL, target, 3000);
  if (!rows) return error(500, rows.error());

  json items = json::array();
  std::map<std::string, std::pair<size_t, int64_t>> countries;  // cc -> (addresses, attempts)
  size_t located = 0, local = 0;
  int64_t attempts_total = 0;
  for (const auto& r : rows.value()) {
    const int64_t attempts = r.ssh_fail + r.ssh_ok + r.scans + r.web_hits + r.web_4xx;
    attempts_total += attempts;
    const bool is_local = GeoDb::isLocalAddress(r.ip);
    std::optional<GeoPoint> g;
    if (!is_local && d_.geo) g = d_.geo->lookup(r.ip);
    // Success after repeated failures is the dangerous pattern; the others are noise of different loudness.
    const char* risk = (r.ssh_ok > 0 && r.ssh_fail >= 3) ? "critical" : r.ssh_fail >= 8 ? "high" : (r.ssh_fail > 0 || r.scans > 0 || r.web_hits > 0) ? "medium" : "low";
    json x = {{"ip", r.ip}, {"local", is_local}, {"ssh_fail", r.ssh_fail}, {"ssh_ok", r.ssh_ok}, {"scans", r.scans}, {"web_hits", r.web_hits}, {"web_4xx", r.web_4xx},
              {"attempts", attempts}, {"first_seen", r.first_ts}, {"last_seen", r.last_ts}, {"targets", r.targets}, {"users", r.users}, {"risk", risk}};
    if (g) {
      x["cc"] = g->cc;
      x["region"] = g->region;
      x["city"] = g->city;
      x["lat"] = g->lat;
      x["lon"] = g->lon;
      ++located;
      auto& c = countries[g->cc];
      ++c.first;
      c.second += attempts;
    }
    if (is_local) ++local;
    items.push_back(std::move(x));
  }
  json by_country = json::array();
  std::vector<std::pair<std::string, std::pair<size_t, int64_t>>> cs(countries.begin(), countries.end());
  std::sort(cs.begin(), cs.end(), [](const auto& a, const auto& b) { return a.second.second > b.second.second; });
  for (size_t i = 0; i < cs.size() && i < 15; ++i) by_country.push_back({{"cc", cs[i].first}, {"addresses", cs[i].second.first}, {"attempts", cs[i].second.second}});

  json geo = {{"available", d_.geo && !d_.geo->empty()}};
  if (d_.geo && !d_.geo->empty()) {
    if (const auto b = d_.geo->meta("built_at")) geo["built_at"] = std::stoll(*b);
    geo["source"] = d_.geo->meta("source").value_or("");
  }
  return jsonReply({{"days", days}, {"geo", geo}, {"addresses", items.size()}, {"located", located}, {"local", local}, {"attempts", attempts_total},
                    {"by_country", by_country}, {"items", items}});
}

// ---- jobs -----------------------------------------------------------------------------------

std::string WebApi::newJob(const std::string& kind) {
  std::lock_guard<std::mutex> lock(mu_);
  Job j;
  j.id = std::to_string(now()) + "-" + std::to_string(++counter_);
  j.kind = kind;
  j.started = now();
  job_order_.push_back(j.id);
  jobs_[j.id] = j;
  while (job_order_.size() > 30) {
    jobs_.erase(job_order_.front());
    job_order_.pop_front();
  }
  ++running_;
  return j.id;
}

void WebApi::finishJob(const std::string& id, json result, const std::string& error_text) {
  std::lock_guard<std::mutex> lock(mu_);
  --running_;
  const auto it = jobs_.find(id);
  if (it == jobs_.end()) return;
  it->second.finished = now();
  it->second.state = error_text.empty() ? "done" : "error";
  it->second.result = std::move(result);
  it->second.error = error_text;
}

HttpReply WebApi::jobStatus(const std::string& id) {
  std::lock_guard<std::mutex> lock(mu_);
  const auto it = jobs_.find(id);
  if (it == jobs_.end()) return error(404, "no such job");
  const Job& j = it->second;
  json o = {{"id", j.id}, {"kind", j.kind}, {"state", j.state}, {"started", j.started}, {"finished", j.finished}};
  if (j.state == "done") o["result"] = j.result;
  if (j.state == "error") o["error"] = j.error;
  return jsonReply(o);
}

HttpReply WebApi::startAnalysis(const json& body) {
  if (!d_.llm) return error(503, "the language model is not configured (llm.enabled: false)");
  Store& st = *d_.store;
  std::vector<Finding> fs;
  std::set<int64_t> seen;
  if (body.contains("ids") && body["ids"].is_array()) {
    for (const auto& id : body["ids"]) {
      if (!id.is_number_integer() || fs.size() >= kMaxAnalysisFindings || !seen.insert(id.get<int64_t>()).second) continue;
      auto f = st.getFinding(id.get<int64_t>());
      if (f && f.value()) fs.push_back(*f.value());
    }
  } else if (body.contains("filter") && body["filter"].is_object()) {
    const json& fl = body["filter"];
    const Severity min = parseSeverity(fl.value("min_severity", std::string("low"))).value_or(Severity::Low);
    auto all = st.listFindings("open", 100000);
    if (!all) return error(500, all.error());
    std::vector<Finding> pick;
    for (auto& f : all.value()) {
      if (fl.contains("target") && fl["target"].is_string() && !fl["target"].get<std::string>().empty() && f.target != fl["target"].get<std::string>()) continue;
      if (fl.contains("collector") && fl["collector"].is_string() && !fl["collector"].get<std::string>().empty() && f.collector != fl["collector"].get<std::string>()) continue;
      if (f.severity < min) continue;
      pick.push_back(std::move(f));
    }
    std::stable_sort(pick.begin(), pick.end(), [](const Finding& a, const Finding& b) { return a.severity != b.severity ? a.severity > b.severity : a.last_seen > b.last_seen; });
    for (auto& f : pick) if (fs.size() < kMaxAnalysisFindings) fs.push_back(std::move(f));
  }
  if (fs.empty()) return error(400, "no finding selected (send \"ids\": [...] or a \"filter\")");
  std::string question = body.value("question", std::string());
  if (question.size() > 1500) question.resize(1500);

  {
    std::lock_guard<std::mutex> lock(mu_);
    if (running_ >= kMaxRunningJobs) return error(429, "too many analyses running: wait for one to finish");
  }
  const std::string id = newJob("analysis");
  std::lock_guard<std::mutex> lock(mu_);
  threads_.emplace_back([this, id, fs = std::move(fs), question = std::move(question)]() mutable { runAnalysis(id, std::move(fs), std::move(question)); });
  return jsonReply({{"job", id}}, 202);
}

void WebApi::runAnalysis(const std::string& id, std::vector<Finding> findings, std::string question) {
  std::lock_guard<std::mutex> llm_lock(llm_mu_);
  ReasonerOptions opts = d_.llm_options;
  if (!question.empty()) {
    if (!opts.admin_focus.empty()) opts.admin_focus += "\n";
    opts.admin_focus += "The administrator asks a specific question about these findings. Answer it in the summary field, based only on the "
                        "evidence, and keep assessing every finding as usual. Question: " + question;
  }
  Reasoner reasoner(*d_.llm, opts);
  std::map<std::string, std::vector<Finding>> by_target;
  for (auto& f : findings) by_target[f.target].push_back(std::move(f));

  json out = json::array();
  std::string last_error;
  for (auto& [target, fs] : by_target) {
    auto r = reasoner.analyze(target, std::move(fs), buildHostContext(*d_.store, target));
    if (!r) { last_error = r.error(); continue; }
    for (auto& a : r.value()) {
      d_.store->saveAnalysis(a);
      json assessments = json::array();
      for (const auto& as : a.assessments) {
        json x = assessmentJson(as);
        x["finding_id"] = as.finding_id;
        assessments.push_back(std::move(x));
      }
      json corr = json::array();
      for (const auto& c : a.correlations) corr.push_back(correlationJson(c));
      out.push_back({{"target", a.target}, {"summary", a.summary}, {"overall_risk", toString(a.overall_risk)}, {"model", a.model},
                     {"assessments", assessments}, {"correlations", corr}});
    }
  }
  if (out.empty()) finishJob(id, {}, last_error.empty() ? "no analysis produced" : last_error);
  else finishJob(id, {{"analyses", out}}, "");
}

HttpReply WebApi::startReport(const json& body) {
  const std::string kind = body.value("kind", std::string("digest"));
  if (kind != "digest" && kind != "alert") return error(400, "kind must be digest or alert");
  const int hours = std::max(1, std::min(24 * 30, body.value("hours", 24)));
  const bool synth = body.value("synthesize", false);
  if (synth && !d_.llm) return error(503, "the language model is not configured (llm.enabled: false)");
  {
    std::lock_guard<std::mutex> lock(mu_);
    if (running_ >= kMaxRunningJobs) return error(429, "too many jobs running: wait for one to finish");
  }
  const std::string id = newJob("report");
  std::lock_guard<std::mutex> lock(mu_);
  threads_.emplace_back([this, id, kind, hours, synth] { runReport(id, kind, hours, synth); });
  return jsonReply({{"job", id}}, 202);
}

void WebApi::runReport(const std::string& id, std::string kind, int hours, bool synthesize) {
  Store& st = *d_.store;
  const int64_t t = now();
  Result<Report> rep = err("unreachable");
  if (kind == "digest") {
    rep = buildDigestReport(st, t - hours * 3600LL, t, *parseSeverity(d_.cfg.alerting.digest_min_severity), d_.report_ctx);
  } else {
    const Severity thr = *parseSeverity(d_.cfg.alerting.min_severity);
    auto open = st.listFindings("open", 100000);
    if (!open) { finishJob(id, {}, open.error()); return; }
    std::vector<Finding> pick;
    for (auto& f : open.value()) {
      auto a = st.latestAssessment(f.id);
      if (isVulnFinding(f) && hasTag(f, "established")) continue;
      if (effectiveSeverity(f, a && a.value() ? a.value() : std::nullopt) >= thr) pick.push_back(std::move(f));
    }
    rep = buildAlertReport(st, pick, d_.report_ctx, t);
  }
  if (!rep) { finishJob(id, {}, rep.error()); return; }
  Report r = std::move(rep.value());
  if (synthesize && (!r.items.empty() || !r.vuln_items.empty() || !r.carry_over.empty())) {
    std::lock_guard<std::mutex> llm_lock(llm_mu_);
    Reasoner reasoner(*d_.llm, d_.llm_options);
    r.synthesis = makeSynthesizer(reasoner, st)(r);
    if (!r.synthesis) {
      finishJob(id, {}, "the model did not produce the AI report (unreachable or unusable reply); see the agent log");
      return;
    }
  }
  finishJob(id, {{"subject", reportSubject(r)}, {"html", renderHtml(r)}, {"text", renderText(r)}, {"with_ai", r.synthesis.has_value()},
                 {"items", r.items.size()}, {"vulns", r.vuln_items.size() + r.omitted_vulns}}, "");
}

}  // namespace agent
