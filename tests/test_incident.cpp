#include <catch2/catch.hpp>

#include "analysis/incident.h"
#include "core/config.h"
#include "report/mailer.h"
#include "report/mitre_names.h"
#include "report/notifier.h"
#include "report/report.h"

using namespace agent;

namespace {

class FakeMailer final : public IMailer {
 public:
  std::vector<MailMessage> sent;
  Result<bool> send(const MailMessage& m) override {
    sent.push_back(m);
    return true;
  }
};

struct Fx {
  std::unique_ptr<Store> store = std::move(Store::open(":memory:").value());
  int n = 0;

  int64_t add(const std::string& rule, Severity sev, const std::string& collector, const std::string& obs_type, const nlohmann::json& evidence,
              std::vector<std::string> mitre, int64_t seen, const std::string& target = "web01") {
    Finding f;
    f.rule_id = rule;
    f.title = "Title of " + rule;
    f.severity = sev;
    f.mitre = std::move(mitre);
    f.target = target;
    f.collector = collector;
    f.obs_type = obs_type;
    f.stable_key = "k" + std::to_string(++n);
    f.fingerprint = rule + "|" + target + "|" + f.stable_key;
    f.first_seen = f.last_seen = seen;
    f.evidence = evidence;
    auto r = store->upsertFinding(f);
    REQUIRE(r.ok());
    return r.value().id;
  }
};

}  // namespace

TEST_CASE("entities: who and what a finding is about, without the generic noise") {
  Finding f;
  f.evidence = {{"src_ip", "203.0.113.7"}, {"user", "alice"}, {"exe", "/tmp/.x/payload"}, {"cmdline", {"/usr/bin/python3", "/tmp/.x/payload"}},
                {"owners", {{{"pid", 4}, {"comm", "x"}, {"exe", "/opt/app/bin/app"}}}}};
  auto e = entitiesOf(f);
  auto has = [&](const std::string& k, const std::string& v) { return std::find(e.begin(), e.end(), Entity{k, v}) != e.end(); };
  REQUIRE(has("ip", "203.0.113.7"));
  REQUIRE(has("user", "alice"));
  REQUIRE(has("path", "/tmp/.x/payload"));
  REQUIRE(has("path", "/opt/app/bin/app"));
  REQUIRE_FALSE(has("path", "/usr/bin/python3"));  // every script on the machine names it

  Finding g;
  g.evidence = {{"src_ip", "192.168.1.20"}, {"user", "root"}, {"remote_addr", "127.0.0.1"}, {"name", "www-data"}};
  REQUIRE(entitiesOf(g).empty());  // private/loopback addresses and generic accounts would chain unrelated findings
}

TEST_CASE("stage of a finding in the attack") {
  Finding brute;
  brute.mitre = {"T1110.001"};
  REQUIRE(stageOf(brute) == "credential-access");
  Finding win;
  win.mitre = {"T1110", "T1078"};
  REQUIRE(stageOf(win) == "initial-access");  // the login that worked is the entry, not the guessing
  Finding key;
  key.mitre = {"T1098.004"};
  REQUIRE(stageOf(key) == "persistence");
  Finding none;
  none.collector = "network";
  REQUIRE(stageOf(none) == "command-and-control");
  REQUIRE(mitreTactic("T1059.004") == "execution");
  REQUIRE(tacticName("persistence", "en") == "Persistence");
  REQUIRE(tacticName("persistence", "it") == "Persistenza");
}

TEST_CASE("findings sharing an address and an account become one incident") {
  Fx fx;
  const auto brute = fx.add("LOG-001", Severity::Medium, "logs", "log.auth.bruteforce", {{"src_ip", "203.0.113.7"}, {"failures", 30}}, {"T1110.001"}, 1000);
  const auto win = fx.add("LOG-002", Severity::Critical, "logs", "log.auth.bruteforce", {{"src_ip", "203.0.113.7"}, {"success_user", "alice"}}, {"T1110", "T1078"}, 1100);
  const auto key = fx.add("PERS-004", Severity::High, "persistence", "authorized_key", {{"user", "alice"}, {"path", "/home/alice/.ssh/authorized_keys"}}, {"T1098.004"}, 1200);
  const auto proc = fx.add("PROC-001", Severity::High, "processes", "process", {{"exe", "/home/alice/.cache/x"}, {"user", "alice"}}, {"T1059"}, 1300);
  const auto other = fx.add("SYS-001", Severity::Low, "system", "sysctl.value", {{"key", "kernel.x"}}, {}, 1250);
  const auto lan = fx.add("NET-005", Severity::Medium, "network", "socket.inet", {{"remote_addr", "192.168.1.1"}}, {"T1071"}, 1260);
  (void)other;
  (void)lan;

  IncidentEngine eng(*fx.store, IncidentOptions{});
  auto n = eng.update(2000);
  REQUIRE(n.ok());
  REQUIRE(n.value() == 1);
  auto list = fx.store->listIncidents("open", 10);
  REQUIRE(list.value().size() == 1);
  const auto& inc = list.value()[0];
  REQUIRE(inc.finding_ids == std::vector<int64_t>{brute, win, key, proc});
  REQUIRE(inc.stages == nlohmann::json::array({"credential-access", "initial-access", "persistence", "execution"}));
  REQUIRE(inc.severity == Severity::Critical);
  REQUIRE(inc.first_ts == 1000);
  REQUIRE(inc.last_ts == 1300);
  REQUIRE(inc.targets == nlohmann::json::array({"web01"}));
  REQUIRE(inc.title == "Credential access -> Initial access -> Persistence -> Execution on web01");
  REQUIRE(incidentTitle(inc.stages, inc.targets, "it").find("su web01") != std::string::npos);
  REQUIRE(fx.store->incidentOfFinding(win).value() == inc.id);

  // the engine is idempotent: same incident, same id
  REQUIRE(eng.update(2100).value() == 1);
  REQUIRE(fx.store->listIncidents("open", 10).value()[0].id == inc.id);

  // a member that goes away shrinks the chain; below two findings the incident is closed
  fx.store->resolveFindings({key, proc}, 2200);
  REQUIRE(eng.update(2300).value() == 1);  // brute + win still share the address
  fx.store->resolveFindings({win}, 2400);
  REQUIRE(eng.update(2500).value() == 0);
  REQUIRE(fx.store->listIncidents("open", 10).value().empty());
  REQUIRE(fx.store->getIncident(inc.id).value()->status == "resolved");
}

TEST_CASE("the same rule repeating, or findings far apart in time, are not an incident") {
  Fx fx;
  fx.add("LOG-001", Severity::Medium, "logs", "log.auth.bruteforce", {{"src_ip", "203.0.113.7"}}, {"T1110.001"}, 1000);
  fx.add("LOG-001", Severity::Medium, "logs", "log.auth.bruteforce", {{"src_ip", "203.0.113.7"}}, {"T1110.001"}, 1500);  // next day's counter of the same attack
  IncidentEngine eng(*fx.store, IncidentOptions{});
  REQUIRE(eng.update(2000).value() == 0);

  fx.add("PERS-004", Severity::High, "persistence", "authorized_key", {{"src_ip", "203.0.113.7"}}, {"T1098.004"}, 1000 + 3 * 86400);
  REQUIRE(eng.update(2000 + 3 * 86400).value() == 0);  // three days later: outside the 24 h window
  IncidentOptions wide;
  wide.window = std::chrono::hours(24 * 5);
  IncidentEngine eng2(*fx.store, wide);
  REQUIRE(eng2.update(2000 + 3 * 86400).value() == 1);
}

TEST_CASE("a new finding that bridges two incidents merges them into the older one") {
  Fx fx;
  fx.add("LOG-001", Severity::Medium, "logs", "log.auth.bruteforce", {{"src_ip", "203.0.113.7"}}, {"T1110.001"}, 1000);
  fx.add("LOG-002", Severity::Critical, "logs", "log.auth.bruteforce", {{"src_ip", "203.0.113.7"}}, {"T1078"}, 1010);
  fx.add("PERS-004", Severity::High, "persistence", "authorized_key", {{"user", "bob"}}, {"T1098.004"}, 1020);
  fx.add("PROC-001", Severity::High, "processes", "process", {{"user", "bob"}}, {"T1059"}, 1030);
  IncidentEngine eng(*fx.store, IncidentOptions{});
  REQUIRE(eng.update(2000).value() == 2);
  auto before = fx.store->listIncidents("open", 10).value();
  const int64_t oldest = std::min(before[0].id, before[1].id);

  fx.add("LOG-010", Severity::Medium, "logs", "log.auth.login", {{"src_ip", "203.0.113.7"}, {"user", "bob"}}, {"T1078"}, 1040);  // links the address and the account
  REQUIRE(eng.update(2100).value() == 1);
  auto after = fx.store->listIncidents("open", 10).value();
  REQUIRE(after.size() == 1);
  REQUIRE(after[0].id == oldest);
  REQUIRE(after[0].finding_ids.size() == 5);
  REQUIRE_FALSE(fx.store->getIncident(std::max(before[0].id, before[1].id)).value());
}

TEST_CASE("a mail shows an incident as one story and keeps three cards") {
  Fx fx;
  std::vector<int64_t> ids;
  ids.push_back(fx.add("LOG-001", Severity::Medium, "logs", "log.auth.bruteforce", {{"src_ip", "203.0.113.7"}}, {"T1110.001"}, 1000));
  ids.push_back(fx.add("LOG-002", Severity::Critical, "logs", "log.auth.bruteforce", {{"src_ip", "203.0.113.7"}, {"success_user", "alice"}}, {"T1078"}, 1010));
  ids.push_back(fx.add("PERS-004", Severity::High, "persistence", "authorized_key", {{"user", "alice"}}, {"T1098.004"}, 1020));
  ids.push_back(fx.add("PROC-001", Severity::High, "processes", "process", {{"user", "alice"}}, {"T1059"}, 1030));
  ids.push_back(fx.add("PROC-002", Severity::Low, "processes", "process", {{"user", "alice"}}, {"T1059"}, 1040));
  IncidentEngine eng(*fx.store, IncidentOptions{});
  REQUIRE(eng.update(2000).value() == 1);

  std::vector<Finding> all;
  for (int64_t id : ids) all.push_back(*fx.store->getFinding(id).value());
  ReportContext ctx;
  ctx.lang = "en";
  auto rep = buildAlertReport(*fx.store, all, ctx, 3000);
  REQUIRE(rep.ok());
  REQUIRE(rep.value().incidents.size() == 1);
  REQUIRE(rep.value().incidents[0].timeline.size() == 5);
  REQUIRE(rep.value().items.size() == 3);  // the three most severe keep a card
  REQUIRE(rep.value().top == Severity::Critical);
  for (const auto& it : rep.value().items) REQUIRE(it.incident_id == rep.value().incidents[0].row.id);

  const std::string txt = renderText(rep.value());
  CHECK(txt.find("INCIDENT #") != std::string::npos);
  CHECK(txt.find("Timeline:") != std::string::npos);
  CHECK(txt.find("PROC-002") != std::string::npos);  // a minor member still appears, as a timeline line
  const std::string html = renderHtml(rep.value());
  CHECK(html.find("incident #") != std::string::npos);
  CHECK(html.find("Credential access") != std::string::npos);
}

TEST_CASE("an incident that reaches the threshold alerts even when its pieces do not") {
  Fx fx;
  // two medium findings: alone below `high`; together (3 stages -> bumped) they are an incident of severity high
  fx.add("LOG-001", Severity::Medium, "logs", "log.auth.bruteforce", {{"src_ip", "203.0.113.7"}}, {"T1110.001"}, 1000);
  fx.add("NET-009", Severity::Medium, "network", "socket.inet", {{"remote_addr", "203.0.113.7"}}, {"T1071"}, 1010);
  fx.add("PERS-009", Severity::Medium, "persistence", "cron.entry", {{"remote_addr", "203.0.113.7"}}, {"T1053.003"}, 1020);
  IncidentEngine eng(*fx.store, IncidentOptions{});
  REQUIRE(eng.update(1100).value() == 1);
  REQUIRE(fx.store->listIncidents("open", 1).value()[0].severity == Severity::High);

  AlertingConfig cfg;
  cfg.min_severity = "high";
  cfg.recipients = {"admin@example.com"};
  cfg.smtp.host = "smtp.example.com";
  cfg.smtp.from = "agent@example.com";
  FakeMailer mailer;
  Notifier n(*fx.store, mailer, cfg, ReportContext{}, [] { return int64_t(5000); });
  auto o = n.tick(true);
  REQUIRE(o.alert_sent);
  REQUIRE(mailer.sent.size() == 1);
  CHECK(mailer.sent[0].text.find("INCIDENTE #") != std::string::npos);
}
