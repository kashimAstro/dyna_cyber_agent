#include <catch2/catch.hpp>

#include "analysis/analyzer.h"
#include "analysis/rule.h"
#include "collectors/log_analyzer.h"
#include "collectors/log_collector.h"
#include "collectors/log_templates.h"
#include "fake_transport.h"

using namespace agent;

namespace {

class MemState final : public IStateStore {
 public:
  std::map<std::string, std::string> kv;
  std::optional<std::string> get(const std::string& k) override {
    auto it = kv.find(k);
    return it == kv.end() ? std::nullopt : std::optional<std::string>(it->second);
  }
  void set(const std::string& k, const std::string& v) override { kv[k] = v; }
};

std::string line(const std::string& program, const std::string& msg) { return "Oct 24 10:00:00 web01 " + program + "[123]: " + msg; }

std::vector<const Observation*> templates(const std::vector<Observation>& obs) {
  std::vector<const Observation*> v;
  for (const auto& o : obs) if (o.type == "log.template") v.push_back(&o);
  return v;
}

}  // namespace

TEST_CASE("a log message becomes its shape") {
  REQUIRE(logTemplate("Accepted publickey for alice from 10.0.0.5 port 4211 ssh2: RSA SHA256:abc123") == "Accepted publickey for alice from <*> port <*> <*>: RSA <*>");
  REQUIRE(logTemplate("Connection closed by 203.0.113.9 port 51234") == logTemplate("Connection closed by 198.51.100.4 port 22"));
  REQUIRE(logTemplate("loaded /usr/lib/foo/bar.so from cache") == "loaded <path> from cache");
  REQUIRE(logTemplate("uid=1000 gid=1000 euid=0") == "uid=<*> gid=<*> euid=<*>");
  REQUIRE(logTemplate("connect to db.internal.example.com failed") == "connect to <host> failed");
  REQUIRE(logTemplate("a 1 2 3 4 5 b") == "a <*> b");                        // runs of placeholders collapse
  REQUIRE(logTemplate("one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen").find(" ...") != std::string::npos);
  REQUIRE(logTemplate("") == "");

  // different behaviour has a different shape, even when the same program writes it
  REQUIRE(logTemplate("session opened for user root") != logTemplate("session closed for user root"));
  REQUIRE(logTemplateId("cron", "x") == logTemplateId("cron", "x"));
  REQUIRE(logTemplateId("cron", "x") != logTemplateId("sshd", "x"));
  REQUIRE(logTemplateId("cron", "x").size() == 12);

  REQUIRE(logAlarming("Permission denied for <*>"));
  REQUIRE(logAlarming("kernel: general protection fault"));
  REQUIRE_FALSE(logAlarming("session opened for user alice"));
  REQUIRE(logNoise("rsyslogd", "-- MARK --"));
  REQUIRE(logNoise("systemd", "last message repeated 3 times"));
  REQUIRE_FALSE(logNoise("systemd", "Started Daily apt download activities."));
}

TEST_CASE("the log analyzer reports each message shape once, alarming ones first") {
  MemState st;
  LogAnalyzerOptions o;
  o.templates = true;
  o.max_templates = 2;
  LogAnalyzer a(o);
  a.attachState(&st, "logtpl|web01");
  a.feedGeneric("/var/log/syslog",
                {line("cron", "(root) CMD (run-parts /etc/cron.hourly)"), line("cron", "(root) CMD (run-parts /etc/cron.hourly)"),
                 line("kernel", "[ 12.5] Out of memory: killed process 77 (java)"), line("app", "Started worker 4"), line("app", "Started worker 9"),
                 line("app", "-- MARK --"), line("systemd", "denied access to /run/secret")},
                100);
  const auto first = a.drain(100);
  const auto t1 = templates(first);
  REQUIRE(t1.size() == 2);                                   // capped, the rest waits
  REQUIRE(t1[0]->data["alarming"] == true);
  REQUIRE(t1[1]->data["alarming"] == true);
  REQUIRE(std::find(t1[0]->tags.begin(), t1[0]->tags.end(), "alarming_words") != t1[0]->tags.end());

  const auto second = a.drain(130);
  const auto t2 = templates(second);
  REQUIRE(t2.size() == 2);                                   // the remaining shapes (the MARK line is noise)
  REQUIRE(t2[0]->data["template"] == "(root) CMD (run-parts <path>)");  // the more frequent first
  REQUIRE(t2[0]->data["count"] == 2);
  const auto third = a.drain(160);
  REQUIRE(templates(third).empty());                         // each shape is reported once

  // a restart does not report them all again
  LogAnalyzer b(o);
  b.attachState(&st, "logtpl|web01");
  b.feedGeneric("/var/log/syslog", {line("cron", "(root) CMD (run-parts /etc/cron.hourly)"), line("app", "Started worker 12"), line("brand", "new behaviour appeared")}, 200);
  const auto fourth = b.drain(200);
  const auto t3 = templates(fourth);
  REQUIRE(t3.size() == 1);
  REQUIRE(t3[0]->data["template"] == "new behaviour appeared");
}

TEST_CASE("lines that a dedicated parser understands are not templates, the others are") {
  LogAnalyzerOptions o;
  o.templates = true;
  LogAnalyzer a(o);
  a.feedAuth("/var/log/auth.log",
             {line("sshd", "Failed password for root from 203.0.113.9 port 22 ssh2"), line("sshd", "pam_unix(sshd:session): session opened for user alice"),
              line("CRON", "pam_unix(cron:session): session opened for user root")},
             100);
  const auto drained = a.drain(100);
  const auto t = templates(drained);
  INFO(drained.size());
  for (const auto* x : t) INFO(x->data.dump());
  REQUIRE(t.size() == 2);
  for (const auto* x : t) REQUIRE(x->data.value("template", std::string()).find("Failed password") == std::string::npos);

  LogAnalyzer off;  // disabled by default
  off.feedGeneric("/var/log/syslog", {line("x", "something new")}, 100);
  const auto none = off.drain(100);
  REQUIRE(templates(none).empty());
}

TEST_CASE("the log collector learns shapes of syslog even when auth and kernel logs exist") {
  FakeTransport t;
  t.files["/var/log/auth.log"] = "";
  t.files["/var/log/kern.log"] = "";
  t.files["/var/log/syslog"] = "";
  MemState st;
  LogCollector c;
  CollectorOptions o;
  o.target = "web01";
  o.state = &st;
  o.log_templates = true;
  c.configure(o);
  c.setClock([] { return 1000; });
  REQUIRE(c.collect(t).ok());  // first run: positions at the end of each log
  t.files["/var/log/syslog"] += line("myapp", "listening on 0.0.0.0:9000") + "\n";
  auto r = c.collect(t);
  REQUIRE(r.ok());
  const auto& robs = r.value().observations;
  const auto ts = templates(robs);
  REQUIRE(ts.size() == 1);
  REQUIRE(ts[0]->data["program"] == "myapp");
  REQUIRE(ts[0]->data["sample"] == "listening on 0.0.0.0:9000");

  LogCollector plain;  // without the option the combined syslog stays ignored
  CollectorOptions po;
  po.target = "web02";
  po.state = &st;
  plain.configure(po);
  plain.setClock([] { return 1000; });
  plain.collect(t);
  t.files["/var/log/syslog"] += line("myapp", "another one") + "\n";
  auto pr = plain.collect(t);
  REQUIRE(pr.ok());
  REQUIRE(templates(pr.value().observations).empty());
}

TEST_CASE("a new message shape is drift after the baseline, and nothing before it") {
  auto rules = loadRulesDir(DEFAULT_RULES_DIR);
  REQUIRE(rules.ok());
  auto st = Store::open(":memory:");
  Store& store = *st.value();
  Analyzer an(store, rules.value(), std::chrono::seconds(1000));
  auto snap = [](int64_t ts, const std::string& tmpl, bool alarming) {
    Snapshot s;
    s.target = "web01";
    s.collector = "logs";
    s.ts = ts;
    Observation o;
    o.type = "log.template";
    o.key = "tmpl|" + logTemplateId("app", tmpl);
    if (alarming) o.tags.push_back("alarming_words");
    o.data = {{"program", "app"}, {"template", tmpl}, {"hash", logTemplateId("app", tmpl)}, {"sample", tmpl}, {"count", 1}, {"alarming", alarming}};
    s.observations.push_back(o);
    return s;
  };
  store.baselineMeta("web01", 0);
  auto learning = an.analyze(snap(10, "worker started", false));
  REQUIRE(learning.ok());
  REQUIRE(learning.value().learning);
  REQUIRE(learning.value().fresh.empty());

  auto known = an.analyze(snap(100000, "worker started", false));
  REQUIRE(known.value().fresh.empty());  // already in the baseline
  auto fresh = an.analyze(snap(100100, "worker crashed unexpectedly", true));
  REQUIRE(fresh.value().fresh.size() == 1);
  REQUIRE(fresh.value().fresh[0].rule_id == "LOG-051");
  auto quiet = an.analyze(snap(100200, "worker stopped gracefully", false));
  REQUIRE(quiet.value().fresh.size() == 1);
  REQUIRE(quiet.value().fresh[0].rule_id == "LOG-050");
  REQUIRE(quiet.value().fresh[0].severity == Severity::Info);  // recorded and visible, but it does not fill the mails
}

TEST_CASE("an analysis switched on after the baseline learns silently for its first day") {
  auto rules = loadRulesDir(DEFAULT_RULES_DIR);
  REQUIRE(rules.ok());
  auto st = Store::open(":memory:");
  Store& store = *st.value();
  store.lockBaseline("web01", 0);  // the baseline is long locked: log shapes were never learned here
  Analyzer an(store, rules.value(), std::chrono::seconds(0));
  auto snap = [](int64_t ts, const std::string& tmpl) {
    Snapshot s;
    s.target = "web01";
    s.collector = "logs";
    s.ts = ts;
    Observation o;
    o.type = "log.template";
    o.key = "tmpl|" + logTemplateId("app", tmpl);
    o.data = {{"program", "app"}, {"template", tmpl}, {"hash", logTemplateId("app", tmpl)}, {"sample", tmpl}, {"count", 1}, {"alarming", false}};
    s.observations.push_back(o);
    return s;
  };
  const int64_t t0 = 1'800'000'000;
  REQUIRE(an.analyze(snap(t0, "worker started")).value().fresh.empty());               // enabling the analysis does not flood the mail
  REQUIRE(an.analyze(snap(t0 + 2 * 3600, "worker reloaded")).value().fresh.empty());   // still its first day
  REQUIRE(an.analyze(snap(t0 + 2 * 3600, "worker started")).value().fresh.empty());
  auto later = an.analyze(snap(t0 + 25 * 3600, "worker crashed"));                      // after that, a new shape is drift
  REQUIRE(later.value().fresh.size() == 1);
  REQUIRE(later.value().fresh[0].rule_id == "LOG-050");
  REQUIRE(an.analyze(snap(t0 + 26 * 3600, "worker reloaded")).value().fresh.empty());  // learned on the first day

  // ordinary facets are not affected: a new process on a locked baseline is still drift right away
  Snapshot ps;
  ps.target = "web01";
  ps.collector = "processes";
  ps.ts = t0;
  Observation p;
  p.type = "process";
  p.key = "1:1";
  p.data = {{"pid", 1}, {"ppid", 1}, {"comm", "x"}, {"uid", 0}, {"exe", "/opt/new/x"}, {"exe_sha256", "ab"}, {"parent_exe", "/sbin/init"}, {"kernel_thread", false}};
  ps.observations.push_back(p);
  bool drift = false;
  for (const auto& f : an.analyze(ps).value().fresh) drift |= !f.drift.empty();
  REQUIRE(drift);
}
