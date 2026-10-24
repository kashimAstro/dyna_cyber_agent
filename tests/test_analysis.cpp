#include <catch2/catch.hpp>

#include <fstream>

#include "analysis/analyzer.h"
#include "analysis/identity.h"
#include "analysis/rule.h"
#include "collectors/process_collector.h"
#include "core/sha256.h"
#include "fake_transport.h"
#include "transport/local_transport.h"

using namespace agent;

#ifndef DEFAULT_RULES_DIR
#error "DEFAULT_RULES_DIR must be defined by the build"
#endif

namespace {

Observation proc(int pid, const std::string& exe, const std::string& sha, const std::string& parent, int uid = 0,
                 std::vector<std::string> tags = {}) {
  Observation o;
  o.type = "process";
  o.key = std::to_string(pid) + ":1";
  o.tags = std::move(tags);
  o.data = {{"pid", pid},      {"ppid", 1},        {"comm", exe.substr(exe.rfind('/') + 1)}, {"uid", uid},
            {"exe", exe},      {"exe_sha256", sha}, {"parent_exe", parent},                   {"kernel_thread", false},
            {"cmdline", nlohmann::json::array()}};
  return o;
}

Snapshot snap(int64_t ts, std::vector<Observation> obs, const std::string& collector = "processes") {
  Snapshot s;
  s.target = "t";
  s.collector = collector;
  s.ts = ts;
  s.observations = std::move(obs);
  return s;
}

std::vector<Rule> defaultRules() {
  auto r = loadRulesDir(DEFAULT_RULES_DIR);
  REQUIRE(r.ok());
  return std::move(r.value());
}

bool fired(const AnalysisResult& r, const std::string& rule_id) {
  for (const auto& f : r.fresh) if (f.rule_id == rule_id) return true;
  return false;
}

}  // namespace

TEST_CASE("sha256 known vectors") {
  REQUIRE(Sha256::hex("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  REQUIRE(Sha256::hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  REQUIRE(Sha256::hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
  Sha256 h;  // streamed in odd chunks across block boundaries
  const std::string million(1000000, 'a');
  for (size_t i = 0; i < million.size(); i += 777) h.update(million.data() + i, std::min<size_t>(777, million.size() - i));
  REQUIRE(h.hexDigest() == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

TEST_CASE("LocalTransport::sha256File streams and enforces the size limit") {
  const std::string path = "/tmp/dyna_cyber_agent_test_sha.bin";
  { std::ofstream(path, std::ios::binary) << "abc"; }
  LocalTransport t;
  REQUIRE(t.sha256File(path, 1024).value() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  REQUIRE_FALSE(t.sha256File(path, 2).ok());
  REQUIRE_FALSE(t.sha256File("/etc", 1024).ok());
  REQUIRE_FALSE(t.sha256File("relative", 1024).ok());
  std::remove(path.c_str());
}

TEST_CASE("ProcessCollector hashes binaries once and resolves parents") {
  FakeTransport t;
  t.files["/proc/stat"] = "btime 1700000000\n";
  t.dirs["/proc"] = {"1", "50"};
  auto stat = [](const char* pid, const char* comm, int ppid) {
    return std::string(pid) + " (" + comm + ") S " + std::to_string(ppid) + " 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 500 0 0";
  };
  t.files["/proc/1/stat"] = stat("1", "init", 0);
  t.links["/proc/1/exe"] = "/sbin/init";
  t.files["/sbin/init"] = "";  // stat() works through files
  t.hashes["/sbin/init"] = "aa";
  t.files["/proc/50/stat"] = stat("50", "sh", 1);
  t.links["/proc/50/exe"] = "/bin/sh";
  t.files["/bin/sh"] = "";
  t.hashes["/bin/sh"] = "bb";
  ProcessCollector c;
  auto r1 = c.collect(t);
  REQUIRE(r1.ok());
  const int after_first = t.hash_calls;
  REQUIRE(after_first == 2);
  auto r2 = c.collect(t);
  REQUIRE(t.hash_calls == after_first);  // cached, files unchanged
  for (const auto& o : r1.value().observations) {
    if (o.data["pid"] == 50) {
      REQUIRE(o.data["exe_sha256"] == "bb");
      REQUIRE(o.data["parent_exe"] == "/sbin/init");
    }
  }
}

TEST_CASE("identities normalise unstable parts") {
  Observation listen;
  listen.type = "socket.inet";
  listen.tags = {"listening"};
  listen.data = {{"proto", "tcp"}, {"local_addr", "0.0.0.0"}, {"local_port", 41437}, {"owners", {{{"pid", 1}, {"comm", "rpc"}}}}};
  auto ids = identitiesOf(listen);
  REQUIRE(ids.size() == 1);
  REQUIRE(ids[0].facet == "net.listen");
  REQUIRE(ids[0].key == "tcp|0.0.0.0:eph|rpc");

  listen.data["local_port"] = 22;
  REQUIRE(identitiesOf(listen)[0].key == "tcp|0.0.0.0:22");

  Observation un;
  un.type = "socket.unix";
  un.data = {{"path", "/tmp/ssh-AbC123/agent.4521"}};
  REQUIRE(identitiesOf(un)[0].key == "/tmp/ssh-AbC#/agent.#");

  Observation kt = proc(2, "/x", "", "", 0);
  kt.data["kernel_thread"] = true;
  REQUIRE(identitiesOf(kt).empty());
}

TEST_CASE("rule parsing validates") {
  auto ok = parseRules(R"(
- id: T-1
  title: t
  severity: high
  match: {type: process, tags_any: [exe_deleted]}
)", "mem");
  REQUIRE(ok.ok());
  REQUIRE(ok.value().size() == 1);

  auto bad = [](const std::string& body) { return parseRules("- id: T\n  title: t\n  severity: high\n  match:\n" + body, "mem").ok(); };
  REQUIRE(bad("    type: process\n    tags_any: [x]\n"));
  REQUIRE_FALSE(bad("    type: nope\n    tags_any: [x]\n"));
  REQUIRE_FALSE(bad("    type: process\n"));  // would match everything
  REQUIRE_FALSE(bad("    type: process\n    drift: process.typo\n"));
  REQUIRE_FALSE(bad("    type: process\n    where:\n      - {field: exe, op: regex, value: '('}\n"));
  REQUIRE_FALSE(bad("    type: process\n    where:\n      - {field: exe, op: like, value: x}\n"));
  REQUIRE_FALSE(bad("    type: process\n    where:\n      - {field: uid, op: gt, value: abc}\n"));
  REQUIRE_FALSE(bad("    type: process\n    where:\n      - {field: uid, op: in, value: 3}\n"));
  REQUIRE_FALSE(parseRules("- id: T\n  title: t\n  severity: bogus\n  match: {type: process, tags_any: [x]}\n", "mem").ok());
  REQUIRE_FALSE(parseRules("- title: t\n  severity: low\n  match: {type: process, tags_any: [x]}\n", "mem").ok());
  REQUIRE_FALSE(parseRules("key: value", "mem").ok());
  REQUIRE_FALSE(parseRules("- [", "mem").ok());
}

TEST_CASE("condition operators") {
  auto rule = [](const std::string& where) {
    auto r = parseRules("- id: T\n  title: t\n  severity: low\n  match:\n    type: process\n    where:\n" + where, "mem");
    REQUIRE(r.ok());
    return r.value()[0];
  };
  Observation o = proc(7, "/usr/bin/python3", "h", "/usr/sbin/nginx", 33);
  o.data["owners"] = {{{"comm", "sshd"}}, {{"comm", "bash"}}};
  const std::vector<Identity> none;

  REQUIRE(rule("      - {field: uid, op: equals, value: 33}\n").matches(o, none));
  REQUIRE(rule("      - {field: uid, op: gt, value: 32}\n").matches(o, none));
  REQUIRE_FALSE(rule("      - {field: uid, op: lt, value: 33}\n").matches(o, none));
  REQUIRE(rule("      - {field: uid, op: in, value: [1, 33]}\n").matches(o, none));
  REQUIRE(rule("      - {field: exe, op: startswith, value: /usr/}\n").matches(o, none));
  REQUIRE(rule("      - {field: exe, op: endswith, value: [x, python3]}\n").matches(o, none));
  REQUIRE(rule("      - {field: exe, op: contains, value: bin}\n").matches(o, none));
  REQUIRE(rule("      - {field: exe, op: regex, value: 'py.*3$'}\n").matches(o, none));
  REQUIRE(rule("      - {field: owners.comm, op: equals, value: bash}\n").matches(o, none));  // fan-out over the array
  REQUIRE(rule("      - {field: owners.1.comm, op: equals, value: bash}\n").matches(o, none));
  REQUIRE_FALSE(rule("      - {field: owners.0.comm, op: equals, value: bash}\n").matches(o, none));
  REQUIRE(rule("      - {field: parent_exe, op: exists, value: true}\n").matches(o, none));
  REQUIRE(rule("      - {field: nothing, op: exists, value: false}\n").matches(o, none));
  REQUIRE(rule("      - {not: {field: uid, op: equals, value: 0}}\n").matches(o, none));
  REQUIRE(rule("      - any:\n          - {field: uid, op: equals, value: 1}\n          - {field: uid, op: equals, value: 33}\n").matches(o, none));
  REQUIRE_FALSE(rule("      - all:\n          - {field: uid, op: equals, value: 33}\n          - {field: exe, op: equals, value: x}\n").matches(o, none));
  // wrong types never match instead of throwing
  REQUIRE_FALSE(rule("      - {field: uid, op: startswith, value: '3'}\n").matches(o, none));
  REQUIRE_FALSE(rule("      - {field: exe, op: gt, value: 3}\n").matches(o, none));
}

TEST_CASE("default rules load and are consistent") {
  auto rules = defaultRules();
  REQUIRE(rules.size() >= 25);
  for (const auto& r : rules) {
    REQUIRE_FALSE(r.description.empty());
    REQUIRE_FALSE(r.remediation.empty());
  }
}

TEST_CASE("default rules: stateless detections") {
  auto rules = defaultRules();
  auto st = Store::open(":memory:");
  Analyzer an(*st.value(), rules, std::chrono::seconds(0));
  // learning is off (window 0) but the baseline is empty: non-drift rules must still fire.
  auto r = an.analyze(snap(1000, {
      proc(10, "/tmp/.x (deleted)", "h", "/bin/bash", 33, {"exe_deleted", "exe_in_volatile_dir"}),
      proc(11, "/bin/sh", "h", "/usr/sbin/nginx", 33),
      proc(12, "/usr/bin/xmrig", "h", "/bin/bash", 1000),
      proc(13, "/usr/sbin/sshd", "h", "/sbin/init", 0),
  }));
  REQUIRE(r.ok());
  REQUIRE(fired(r.value(), "PROC-001"));
  REQUIRE(fired(r.value(), "PROC-005"));
  REQUIRE(fired(r.value(), "PROC-012"));
  REQUIRE(fired(r.value(), "PROC-013"));
  REQUIRE_FALSE(fired(r.value(), "PROC-002"));
  // sshd triggers no stateless rule (drift rules do fire: the baseline is empty)
  for (const auto& f : r.value().fresh) {
    if (f.evidence["pid"] != 13) continue;
    REQUIRE(f.rule_id != "PROC-001");
    REQUIRE(f.rule_id != "PROC-005");
    REQUIRE(f.rule_id != "PROC-012");
    REQUIRE(f.rule_id != "PROC-013");
  }
}

TEST_CASE("analyzer: learning, drift, dedup, accept") {
  auto rules = defaultRules();
  auto st = Store::open(":memory:");
  Store& store = *st.value();
  Analyzer an(store, rules, std::chrono::seconds(100));

  // --- learning phase: the usual stuff is learned silently
  auto a = an.analyze(snap(1000, {proc(1, "/usr/sbin/sshd", "h1", "/sbin/init"), proc(2, "/usr/bin/cron", "h2", "/sbin/init")}));
  REQUIRE(a.ok());
  REQUIRE(a.value().learning);
  REQUIRE(a.value().fresh.empty());
  REQUIRE(a.value().learned > 0);
  REQUIRE(store.baselineSize("t").value() > 0);

  // --- still learning at t=1099, enforcing from t=1100
  REQUIRE(an.analyze(snap(1099, {proc(3, "/opt/new/tool", "h9", "/sbin/init")})).value().learning);
  auto b0 = an.analyze(snap(1100, {proc(1, "/usr/sbin/sshd", "h1", "/sbin/init")}));
  REQUIRE_FALSE(b0.value().learning);
  REQUIRE(b0.value().fresh.empty());  // known stuff stays quiet

  // --- drift: a new binary, a changed binary, a new parent
  auto b = an.analyze(snap(1200, {
      proc(20, "/srv/evil/backdoor", "h7", "/sbin/init"),
      proc(1, "/usr/sbin/sshd", "CHANGED", "/sbin/init"),
      proc(2, "/usr/bin/cron", "h2", "/usr/bin/python3"),
  }));
  REQUIRE(b.ok());
  REQUIRE(fired(b.value(), "PROC-007"));  // new executable
  REQUIRE(fired(b.value(), "PROC-008"));  // changed hash
  REQUIRE(fired(b.value(), "PROC-009"));  // new lineage
  REQUIRE_FALSE(fired(b.value(), "PROC-011"));

  // --- the same state again: dedup, nothing new, occurrences grow
  auto c = an.analyze(snap(1300, {proc(20, "/srv/evil/backdoor", "h7", "/sbin/init")}));
  REQUIRE(c.value().fresh.empty());
  REQUIRE_FALSE(c.value().repeats.empty());
  int64_t id = 0;
  for (const auto& f : c.value().repeats) if (f.rule_id == "PROC-007") id = f.id;
  REQUIRE(id > 0);
  auto stored = store.getFinding(id);
  REQUIRE(stored.value()->occurrences == 2);
  REQUIRE(stored.value()->first_seen == 1200);
  REQUIRE(stored.value()->last_seen == 1300);
  REQUIRE(stored.value()->drift.size() >= 1);

  // --- accepting makes it part of the baseline
  REQUIRE(store.acceptFinding(id, 1400).ok());
  REQUIRE(store.getFinding(id).value()->status == "accepted");
  auto d = an.analyze(snap(1500, {proc(20, "/srv/evil/backdoor", "h7", "/sbin/init")}));
  REQUIRE(d.value().fresh.empty());
  REQUIRE(d.value().repeats.empty());
  REQUIRE_FALSE(store.acceptFinding(99999, 1).ok());

  // --- listing
  auto open = store.listFindings("open", 100);
  REQUIRE(open.ok());
  for (const auto& f : open.value()) REQUIRE(f.status == "open");
  REQUIRE(store.listFindings("", 100).value().size() > open.value().size());
}

TEST_CASE("analyzer: lock ends learning, failed snapshots are ignored") {
  auto rules = defaultRules();
  auto st = Store::open(":memory:");
  Store& store = *st.value();
  Analyzer an(store, rules, std::chrono::hours(24 * 7));
  REQUIRE(an.analyze(snap(1000, {proc(1, "/usr/sbin/sshd", "h", "/sbin/init")})).value().learning);
  REQUIRE(store.lockBaseline("t", 1001).ok());
  auto r = an.analyze(snap(1002, {proc(9, "/opt/x", "h", "/sbin/init")}));
  REQUIRE_FALSE(r.value().learning);
  REQUIRE(fired(r.value(), "PROC-007"));

  Snapshot failed = snap(1003, {proc(9, "/opt/never-analysed", "h", "/sbin/init")});
  failed.error = "boom";
  auto f = an.analyze(failed);
  REQUIRE(f.ok());
  REQUIRE(f.value().fresh.empty());
}

TEST_CASE("default rules: network and users") {
  auto rules = defaultRules();
  auto st = Store::open(":memory:");
  Analyzer an(*st.value(), rules, std::chrono::seconds(0));

  auto sock = [](const std::string& proto, const std::string& laddr, int lport, const std::string& raddr, int rport,
                 const std::string& state, std::vector<std::string> tags, const std::string& comm) {
    Observation o;
    o.type = "socket.inet";
    o.key = proto + laddr + std::to_string(lport);
    o.tags = std::move(tags);
    o.data = {{"proto", proto}, {"local_addr", laddr}, {"local_port", lport},   {"remote_addr", raddr},
              {"remote_port", rport}, {"state", state}, {"owners", {{{"pid", 5}, {"comm", comm}}}}};
    return o;
  };
  auto r = an.analyze(snap(1000, {
      sock("tcp", "10.0.0.5", 40000, "203.0.113.9", 4444, "ESTABLISHED", {}, "bash"),
      sock("tcp", "0.0.0.0", 6379, "0.0.0.0", 0, "LISTEN", {"listening", "exposed"}, "redis-server"),
      sock("tcp", "127.0.0.1", 6379, "0.0.0.0", 0, "LISTEN", {"listening"}, "redis-server"),
      sock("tcp", "10.0.0.5", 40001, "127.0.0.1", 5432, "ESTABLISHED", {}, "bash"),
  }, "network"));
  REQUIRE(r.ok());
  REQUIRE(fired(r.value(), "NET-005"));  // reverse shell
  REQUIRE(fired(r.value(), "NET-006"));  // backdoor port
  REQUIRE(fired(r.value(), "NET-009"));  // exposed redis
  int net005 = 0, net009 = 0;
  for (const auto& f : r.value().fresh) {
    net005 += f.rule_id == "NET-005";
    net009 += f.rule_id == "NET-009";
  }
  REQUIRE(net005 == 1);  // loopback connection is not a reverse shell
  REQUIRE(net009 == 1);  // loopback-only redis is fine

  Observation u;
  u.type = "user";
  u.key = "toor";
  u.tags = {"uid0", "uid0_not_root", "empty_password", "login_shell"};
  u.data = {{"name", "toor"}, {"uid", 0}};
  auto ur = an.analyze(snap(1000, {u}, "users"));
  REQUIRE(fired(ur.value(), "USR-001"));
  REQUIRE(fired(ur.value(), "USR-002"));
}

TEST_CASE("rules_dir given as a glob gets an explicit error") {
  auto r = loadRulesDir("/home/user/dyna_cyber_agent/rules/default/*.yaml");
  REQUIRE_FALSE(r.ok());
  REQUIRE(r.error().find("not a pattern") != std::string::npos);
  REQUIRE(r.error().find("/home/user/dyna_cyber_agent/rules/default") != std::string::npos);
  auto missing = loadRulesDir("/nonexistent/rules");
  REQUIRE_FALSE(missing.ok());
  REQUIRE(missing.error().find("not found") != std::string::npos);
}
