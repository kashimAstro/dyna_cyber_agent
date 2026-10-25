#include <catch2/catch.hpp>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <thread>

#include "scripted_http.h"
#include "web/api.h"

using namespace agent;
using nlohmann::json;

namespace {

Finding mkFinding(const std::string& rule, Severity sev, const std::string& key, const std::string& collector = "processes") {
  Finding f;
  f.fingerprint = rule + "|web01|" + key;
  f.rule_id = rule;
  f.title = "Titolo " + rule;
  f.severity = sev;
  f.description = "Descrizione";
  f.remediation = "Rimedio";
  f.mitre = {"T1190"};
  f.target = "web01";
  f.collector = collector;
  f.obs_type = "process";
  f.stable_key = key;
  f.first_seen = f.last_seen = 1000;
  f.evidence = {{"pid", 42}, {"note", "<script>alert(1)</script>"}};
  return f;
}

struct Lab {
  std::unique_ptr<Store> store = std::move(Store::open(":memory:").value());
  ScriptedHttp http;
  std::unique_ptr<LlmClient> llm;
  std::unique_ptr<WebApi> api;
  int64_t ssh_id = 0, vuln_id = 0;

  explicit Lab(bool with_llm, const std::string& language = "it") {
    ssh_id = store->upsertFinding(mkFinding("LOG-002", Severity::Critical, "ssh")).value().id;
    Finding v = mkFinding("VULN-001", Severity::Critical, "vuln|CVE-2026-1|openssl", "vulns");
    v.tags = {"kev", "recent", "fix_available"};
    v.evidence = {{"cve", "CVE-2026-1"}, {"package", "openssl"}, {"installed_version", "1.0"}, {"fixed_version", "1.1"}, {"cvss", 9.8}};
    vuln_id = store->upsertFinding(v).value().id;
    WebApi::Deps d;
    d.store = store.get();
    d.token = "0123456789abcdef-secret";
    d.version = "test";
    d.report_ctx.host_label = "monitor01";
    d.cfg.language = language;
    d.cfg.targets.push_back({});
    d.cfg.targets[0].name = "web01";
    d.cfg.targets[0].transport = "local";
    d.clock = [] { return int64_t(2000); };
    if (with_llm) {
      LlmConfig lc;
      lc.url = "http://llm.invalid:8080";
      llm = std::make_unique<LlmClient>(lc, http);
      d.llm = llm.get();
      d.llm_options.retry_delay = std::chrono::milliseconds(0);
    }
    api = std::make_unique<WebApi>(std::move(d));
  }

  HttpReply call(const std::string& method, const std::string& path, const std::string& body = "", bool auth = true) {
    HttpRequest r;
    r.method = method;
    const size_t q = path.find('?');
    r.path = path.substr(0, q);
    if (q != std::string::npos) r.query["q"] = path.substr(q + 1);  // tests use only the free-text filter
    if (auth) r.headers["authorization"] = "Bearer 0123456789abcdef-secret";
    r.body = body;
    return api->handle(r);
  }

  json waitJob(const std::string& id) {
    for (int i = 0; i < 200; ++i) {
      const json j = json::parse(call("GET", "/api/jobs/" + id).body);
      if (j["state"] != "running") return j;
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    FAIL("job did not finish");
    return {};
  }
};

}  // namespace

TEST_CASE("web: token is required for the API, not for the page") {
  Lab lab(false);
  REQUIRE(lab.call("GET", "/", "", false).status == 200);
  REQUIRE(lab.call("GET", "/", "", false).body.find("dyna_cyber_agent") != std::string::npos);
  // the page language follows the global `language` setting
  const std::string it = lab.call("GET", "/", "", false).body;
  REQUIRE(it.find("<html lang=\"it\">") != std::string::npos);
  REQUIRE(it.find("@LANG@") == std::string::npos);
  Lab en(false, "en");
  REQUIRE(en.call("GET", "/", "", false).body.find("<html lang=\"en\">") != std::string::npos);
  REQUIRE(lab.call("GET", "/api/overview", "", false).status == 401);
  HttpRequest bad;
  bad.method = "GET";
  bad.path = "/api/overview";
  bad.headers["authorization"] = "Bearer wrong";
  REQUIRE(lab.api->handle(bad).status == 401);
  REQUIRE(lab.call("GET", "/api/overview").status == 200);
  REQUIRE(lab.call("DELETE", "/api/overview").status == 405);
  REQUIRE(lab.call("GET", "/api/nothing").status == 404);
}

TEST_CASE("web: overview, findings, detail and vulnerabilities") {
  Lab lab(false);
  const json o = json::parse(lab.call("GET", "/api/overview").body);
  REQUIRE(o["open"]["security"] == 1);
  REQUIRE(o["vulns"]["total"] == 1);
  REQUIRE(o["vulns"]["kev"] == 1);
  REQUIRE(o["targets"][0]["baseline"]["state"] == "learning");
  REQUIRE(o["llm"]["usable"] == false);

  const json fs = json::parse(lab.call("GET", "/api/findings").body);
  REQUIRE(fs["total"] == 2);
  REQUIRE(fs["items"][0]["effective"] == "critical");

  const json d = json::parse(lab.call("GET", "/api/findings/" + std::to_string(lab.ssh_id)).body);
  REQUIRE(d["mitre_names"][0]["name"] == "Exploit Public-Facing Application");
  REQUIRE(d["evidence"]["note"] == "<script>alert(1)</script>");  // data stays data: the page builds DOM with textContent
  REQUIRE(lab.call("GET", "/api/findings/99999").status == 404);
  REQUIRE(lab.call("GET", "/api/findings/abc").status == 400);

  const json v = json::parse(lab.call("GET", "/api/vulns").body);
  REQUIRE(v["total"] == 1);
  REQUIRE(v["items"][0]["cve"] == "CVE-2026-1");
  REQUIRE(v["items"][0]["kev"] == true);
  REQUIRE(json::parse(lab.call("GET", "/api/vulns?nomatch").body)["total"] == 0);
  REQUIRE(json::parse(lab.call("GET", "/api/notifications").body)["items"].empty());
}

TEST_CASE("web: AI actions need the model; a targeted analysis runs as a job and is stored") {
  Lab none(false);
  REQUIRE(none.call("POST", "/api/analyze", R"({"ids":[1]})").status == 503);
  REQUIRE(none.call("POST", "/api/report", R"({"kind":"digest","synthesize":true})").status == 503);
  REQUIRE(none.call("POST", "/api/analyze", "not json").status == 400);

  Lab lab(true);
  const std::string content = json({{"summary", "Sintesi della domanda"}, {"overall_risk", "high"},
                                    {"assessments", json::array({{{"finding_id", lab.ssh_id}, {"verdict", "suspicious"}, {"risk", "high"}, {"confidence", 80},
                                                                   {"explanation", "Perche'"}, {"recommended_actions", json::array({"Isola"})},
                                                                   {"additional_checks", json::array()}}})},
                                    {"correlations", json::array()}}).dump();
  lab.http.ok("/v1/chat/completions", json({{"choices", json::array({{{"message", {{"content", content}}}, {"finish_reason", "stop"}}})},
                                             {"usage", {{"prompt_tokens", 10}, {"completion_tokens", 5}}}}).dump());
  REQUIRE(lab.call("POST", "/api/analyze", R"({"ids":[]})").status == 400);
  const auto start = lab.call("POST", "/api/analyze", "{\"ids\":[" + std::to_string(lab.ssh_id) + "],\"question\":\"e' benigno?\"}");
  REQUIRE(start.status == 202);
  const json job = lab.waitJob(json::parse(start.body)["job"]);
  REQUIRE(job["state"] == "done");
  REQUIRE(job["result"]["analyses"][0]["summary"] == "Sintesi della domanda");
  REQUIRE(lab.http.requested.back().find("e' benigno?") != std::string::npos);  // the question reaches the model
  auto stored = lab.store->latestAssessment(lab.ssh_id);
  REQUIRE(stored.ok());
  REQUIRE(stored.value().has_value());
  REQUIRE(json::parse(lab.call("GET", "/api/findings/" + std::to_string(lab.ssh_id)).body)["assessment"]["verdict"] == "suspicious");
}

TEST_CASE("web: report preview is rendered without sending anything") {
  Lab lab(false);
  const auto start = lab.call("POST", "/api/report", R"({"kind":"digest","hours":24})");
  REQUIRE(start.status == 202);
  const json job = lab.waitJob(json::parse(start.body)["job"]);
  REQUIRE(job["state"] == "done");
  REQUIRE(job["result"]["html"].get<std::string>().find("CVE-2026-1") != std::string::npos);
  REQUIRE(job["result"]["text"].get<std::string>().find("LOG-002") != std::string::npos);
  REQUIRE(job["result"]["with_ai"] == false);
  REQUIRE(lab.call("POST", "/api/report", R"({"kind":"weekly"})").status == 400);
}

TEST_CASE("web: http server answers over a real loopback socket and enforces limits") {
  Lab lab(false);
  HttpServer server;
  WebApi* api = lab.api.get();
  REQUIRE(server.start("127.0.0.1", 0, [api](const HttpRequest& r) { return api->handle(r); }).ok());
  const auto request = [&](const std::string& raw) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(static_cast<uint16_t>(server.port()));
    ::inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    REQUIRE(::connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0);
    ::send(fd, raw.data(), raw.size(), 0);
    std::string out;
    char buf[4096];
    ssize_t n;
    while ((n = ::recv(fd, buf, sizeof(buf), 0)) > 0) out.append(buf, static_cast<size_t>(n));
    ::close(fd);
    return out;
  };
  const std::string page = request("GET / HTTP/1.1\r\nHost: x\r\n\r\n");
  REQUIRE(page.rfind("HTTP/1.1 200", 0) == 0);
  REQUIRE(page.find("Content-Security-Policy") != std::string::npos);
  REQUIRE(page.find("frame-ancestors 'none'") != std::string::npos);
  REQUIRE(request("GET /api/overview HTTP/1.1\r\nHost: x\r\n\r\n").rfind("HTTP/1.1 401", 0) == 0);
  const std::string ok = request("GET /api/overview HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer 0123456789abcdef-secret\r\n\r\n");
  REQUIRE(ok.rfind("HTTP/1.1 200", 0) == 0);
  REQUIRE(ok.find("\"open\"") != std::string::npos);
  REQUIRE(request("POST /api/report HTTP/1.1\r\nContent-Length: 99999999\r\n\r\n").rfind("HTTP/1.1 413", 0) == 0);
  REQUIRE(request("garbage\r\n\r\n").rfind("HTTP/1.1 400", 0) == 0);
  server.stop();
}

TEST_CASE("web: the attack map lists addresses with risk and counts, placed when the geo database knows them") {
  Lab lab(false);
  Store::SourceDelta a;
  a.ip = "198.51.100.5";
  a.ssh_fail = 12;
  a.ssh_ok = 1;
  a.users_json = "[\"root\"]";
  Store::SourceDelta b;
  b.ip = "192.168.1.19";
  b.ssh_ok = 2;
  Store::SourceDelta c;
  c.ip = "203.0.113.9";
  c.scans = 3;
  REQUIRE(lab.store->recordSources("web01", {a, b, c}, 1990).ok());
  const json j = json::parse(lab.call("GET", "/api/sources").body);
  REQUIRE(j["addresses"] == 3);
  REQUIRE(j["geo"]["available"] == false);
  REQUIRE(j["items"][0]["ip"] == "198.51.100.5");
  REQUIRE(j["items"][0]["risk"] == "critical");  // a login after repeated failures
  bool saw_local = false;
  for (const auto& it : j["items"]) {
    if (it["ip"] == "192.168.1.19") { saw_local = true; REQUIRE(it["local"] == true); REQUIRE(it["risk"] == "low"); }
    if (it["ip"] == "203.0.113.9") REQUIRE(it["risk"] == "medium");
  }
  REQUIRE(saw_local);
  REQUIRE(lab.call("GET", "/api/sources", "", false).status == 401);
}

TEST_CASE("web: incidents and the priority fields of the vulnerability list") {
  Lab lab(false, "en");
  Store::IncidentRow row;
  row.created_at = 1000;
  row.updated_at = 1500;
  row.first_ts = 900;
  row.last_ts = 1400;
  row.severity = Severity::Critical;
  row.title = "x";
  row.targets = json::array({"web01"});
  row.stages = json::array({"credential-access", "persistence"});
  row.entities = json::array({{{"kind", "ip"}, {"value", "203.0.113.7"}, {"findings", 2}}});
  row.finding_ids = {lab.ssh_id, lab.vuln_id};
  const int64_t id = lab.store->saveIncident(row).value();

  const json list = json::parse(lab.call("GET", "/api/incidents").body);
  REQUIRE(list["enabled"] == true);
  REQUIRE(list["items"].size() == 1);
  REQUIRE(list["items"][0]["title"] == "Credential access -> Persistence on web01");  // rendered in the configured language
  REQUIRE(list["items"][0]["stage_names"][1] == "Persistence");

  const json d = json::parse(lab.call("GET", "/api/incidents/" + std::to_string(id)).body);
  REQUIRE(d["timeline"].size() == 2);
  REQUIRE(d["severity"] == "critical");
  REQUIRE(lab.call("GET", "/api/incidents/999").status == 404);
  REQUIRE(lab.call("GET", "/api/incidents/abc").status == 400);

  const json o = json::parse(lab.call("GET", "/api/overview").body);
  REQUIRE(o["incidents"]["open"] == 1);
  REQUIRE(o["incidents"]["high_or_critical"] == 1);
  const json f = json::parse(lab.call("GET", "/api/findings/" + std::to_string(lab.ssh_id)).body);
  REQUIRE(f["incident_id"] == id);

  const json v = json::parse(lab.call("GET", "/api/vulns").body);
  REQUIRE(v["items"][0].contains("priority"));
  REQUIRE(v["items"][0]["exposure"] == "unknown");  // nothing was recorded about what listens
}

TEST_CASE("web: a finding is accepted as normal with a note and an expiry, and taken back") {
  Lab lab(false);
  const std::string id = std::to_string(lab.ssh_id);
  REQUIRE(lab.call("POST", "/api/findings/accept", R"({"ids":[]})").status == 400);
  REQUIRE(lab.call("POST", "/api/findings/accept", "{\"ids\":[" + id + "],\"days\":99999}").status == 400);
  REQUIRE(lab.call("POST", "/api/findings/accept", "{\"ids\":[" + id + "]}", false).status == 401);

  const auto ok = lab.call("POST", "/api/findings/accept", "{\"ids\":[" + id + ",424242],\"note\":\"backup notturno\",\"days\":7}");
  REQUIRE(ok.status == 200);
  const json r = json::parse(ok.body);
  REQUIRE(r["accepted"].size() == 1);
  REQUIRE(r["failed"].size() == 1);  // the unknown id is reported, not hidden
  REQUIRE(r["expires_at"] == 2000 + 7 * 86400);

  const json d = json::parse(lab.call("GET", "/api/findings/" + id).body);
  REQUIRE(d["status"] == "accepted");
  REQUIRE(d["acceptance"]["note"] == "backup notturno");
  REQUIRE(d["acceptance"]["expires_at"] == 2000 + 7 * 86400);

  const auto back = json::parse(lab.call("POST", "/api/findings/reopen", "{\"ids\":[" + id + "]}").body);
  REQUIRE(back["reopened"].size() == 1);
  REQUIRE(json::parse(lab.call("GET", "/api/findings/" + id).body)["status"] == "open");
  const auto again = json::parse(lab.call("POST", "/api/findings/reopen", "{\"ids\":[" + id + "]}").body);
  REQUIRE(again["reopened"].empty());
  REQUIRE(again["failed"].size() == 1);
}

TEST_CASE("web: a question is answered from the agent's own data, cites real findings and shows its period") {
  Lab none(false);
  REQUIRE(none.call("POST", "/api/ask", R"({"question":"cosa e' cambiato?"})").status == 503);

  Lab lab(true);
  REQUIRE(lab.call("POST", "/api/ask", R"({"question":"   "})").status == 400);
  REQUIRE(lab.call("POST", "/api/ask", json({{"question", std::string(601, 'x')}}).dump()).status == 400);
  REQUIRE(lab.call("POST", "/api/ask", R"({"question":"ciao","target":"nope"})").status == 400);
  REQUIRE(lab.call("POST", "/api/ask", R"({"question":"ciao"})", false).status == 401);

  const std::string content = json({{"answer", "Su web01 c'e' un accesso SSH sospetto (#" + std::to_string(lab.ssh_id) + ")."},
                                    {"finding_ids", json::array({lab.ssh_id, 424242})},
                                    {"data_gaps", ""}}).dump();
  lab.http.ok("/v1/chat/completions", json({{"choices", json::array({{{"message", {{"content", content}}}, {"finish_reason", "stop"}}})},
                                             {"usage", {{"prompt_tokens", 10}, {"completion_tokens", 5}}}}).dump());
  const auto start = lab.call("POST", "/api/ask", R"({"question":"cosa e' cambiato su web01 nelle ultime 48 ore?"})");
  REQUIRE(start.status == 202);
  const json job = lab.waitJob(json::parse(start.body)["job"]);
  REQUIRE(job["state"] == "done");
  const json& r = job["result"];
  REQUIRE(r["answer"].get<std::string>().find("accesso SSH") != std::string::npos);
  REQUIRE(r["findings"].size() == 1);                                   // the invented id is dropped, the real one is described
  REQUIRE(r["findings"][0]["id"] == lab.ssh_id);
  REQUIRE(r["machines"] == json::array({"web01"}));
  REQUIRE(r["period"]["detected"] == true);
  REQUIRE(r["period"]["to"].get<int64_t>() - r["period"]["from"].get<int64_t>() == 48 * 3600);
  REQUIRE(r["counts"]["findings_active_in_period"].get<int>() >= 1);
  const std::string sent = lab.http.requested.back();
  REQUIRE(sent.find("cosa e' cambiato su web01") != std::string::npos);  // the question and
  REQUIRE(sent.find("Titolo LOG-002") != std::string::npos);             // the agent's own findings reach the model, nothing else

  // the console can fix the period and the machine explicitly
  const auto fixed = lab.call("POST", "/api/ask", R"({"question":"riassumi","target":"web01","hours":6})");
  REQUIRE(fixed.status == 202);
  const json job2 = lab.waitJob(json::parse(fixed.body)["job"]);
  REQUIRE(job2["result"]["period"]["to"].get<int64_t>() - job2["result"]["period"]["from"].get<int64_t>() == 6 * 3600);
}

TEST_CASE("web: settings - filters are validated and close what they cover, pauses, and the reset needs its word") {
  Lab lab(false);
  const json s0 = json::parse(lab.call("GET", "/api/settings").body);
  REQUIRE(s0["exclusions"].empty());
  REQUIRE(s0["kinds"].size() == 8);
  REQUIRE(s0["targets"][0]["name"] == "web01");
  REQUIRE(s0["info"]["db"]["tables"].size() > 5);
  REQUIRE(s0["pause"]["mail_until"] == 0);
  REQUIRE(lab.call("GET", "/api/settings", "", false).status == 401);

  // refused: unknown kind, root, a machine that does not exist, a silly duration, wildcards only
  REQUIRE(lab.call("POST", "/api/settings/exclusions", R"({"kind":"colour","pattern":"red"})").status == 400);
  REQUIRE(lab.call("POST", "/api/settings/exclusions", R"({"kind":"user","pattern":"root"})").status == 400);
  REQUIRE(lab.call("POST", "/api/settings/exclusions", R"({"kind":"user","pattern":"backup","target":"nope"})").status == 400);
  REQUIRE(lab.call("POST", "/api/settings/exclusions", R"({"kind":"user","pattern":"backup","days":99999})").status == 400);
  REQUIRE(lab.call("POST", "/api/settings/exclusions", R"({"kind":"package","pattern":"*"})").status == 400);

  // a filter closes the open findings it covers at once
  const std::string id = std::to_string(lab.ssh_id);
  const auto add = lab.call("POST", "/api/settings/exclusions", R"({"kind":"rule","pattern":"log-002","note":"rumore","days":30})");
  REQUIRE(add.status == 200);
  const json a = json::parse(add.body);
  REQUIRE(a["pattern"] == "LOG-002");
  REQUIRE(a["closed"] == 1);
  REQUIRE(json::parse(lab.call("GET", "/api/findings/" + id).body)["status"] == "resolved");
  const json s1 = json::parse(lab.call("GET", "/api/settings").body);
  REQUIRE(s1["exclusions"].size() == 1);
  REQUIRE(s1["exclusions"][0]["note"] == "rumore");
  REQUIRE(s1["exclusions"][0]["expires_at"] == 2000 + 30 * 86400);
  REQUIRE(s1["exclusions"][0]["active"] == true);

  // import (an export keeps what is valid and says what is not)
  const auto imp = lab.call("POST", "/api/settings/exclusions/import",
                            R"({"items":[{"kind":"port","pattern":"8080","target":"web01"},{"kind":"user","pattern":"root"},{"kind":"ip","pattern":"10.0.0.0/8","expires_at":5}]})");
  REQUIRE(imp.status == 200);
  const json ji = json::parse(imp.body);
  REQUIRE(ji["added"] == 1);
  REQUIRE(ji["rejected"].size() == 2);                                  // root, and an already expired one
  REQUIRE(lab.call("POST", "/api/settings/exclusions/import", R"({"items":"x"})").status == 400);

  REQUIRE(lab.call("POST", "/api/settings/exclusions/delete", "{\"id\":" + a["id"].dump() + "}").status == 200);
  REQUIRE(lab.call("POST", "/api/settings/exclusions/delete", "{\"id\":" + a["id"].dump() + "}").status == 404);

  // pauses
  REQUIRE(lab.call("POST", "/api/settings/pause", "{}").status == 400);
  REQUIRE(lab.call("POST", "/api/settings/pause", R"({"mail_hours":-1})").status == 400);
  REQUIRE(lab.call("POST", "/api/settings/pause", R"({"mail_hours":4,"llm_paused":true})").status == 200);
  const json s2 = json::parse(lab.call("GET", "/api/settings").body);
  REQUIRE(s2["pause"]["mail_until"] == 2000 + 4 * 3600);
  REQUIRE(s2["pause"]["llm_paused"] == true);
  REQUIRE(lab.call("POST", "/api/settings/pause", R"({"mail_hours":0,"llm_paused":false})").status == 200);
  const json s3 = json::parse(lab.call("GET", "/api/settings").body);
  REQUIRE(s3["pause"]["mail_until"] == 0);
  REQUIRE(s3["pause"]["llm_paused"] == false);

  // the reset: no word, no reset; the right word wipes the data and, on request, keeps the filters
  REQUIRE(lab.call("POST", "/api/settings/reset", "{}").status == 400);
  REQUIRE(lab.call("POST", "/api/settings/reset", R"({"confirm":"reset"})").status == 400);
  REQUIRE(json::parse(lab.call("GET", "/api/findings/" + id).body)["id"] == lab.ssh_id);   // still there
  const auto rs = lab.call("POST", "/api/settings/reset", R"({"confirm":"RESET","keep_exclusions":true})");
  REQUIRE(rs.status == 200);
  REQUIRE(json::parse(rs.body)["rows_deleted"].get<int>() > 0);
  REQUIRE(lab.call("GET", "/api/findings/" + id).status == 404);
  REQUIRE(json::parse(lab.call("GET", "/api/settings").body)["exclusions"].size() == 1);   // the imported port filter stayed
  REQUIRE(lab.call("POST", "/api/settings/reset", R"({"confirm":"RESET"})").status == 200);
  REQUIRE(json::parse(lab.call("GET", "/api/settings").body)["exclusions"].empty());
}
