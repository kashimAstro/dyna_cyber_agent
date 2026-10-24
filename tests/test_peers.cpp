#include <catch2/catch.hpp>

#include <chrono>

#include "analysis/analyzer.h"
#include "analysis/rule.h"
#include "collectors/peer_collector.h"
#include "fake_transport.h"

using namespace agent;

namespace {

int64_t nowTs() { return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count(); }

Observation user(const std::string& name, int uid) {
  return {"user", "u:" + name, {{"name", name}, {"uid", uid}, {"shell", "/bin/bash"}}, {}};
}
Observation listen(int port) {
  return {"socket.inet", "l" + std::to_string(port), {{"proto", "tcp"}, {"local_addr", "0.0.0.0"}, {"local_port", port}, {"owners", nlohmann::json::array()}}, {"listening"}};
}
Observation proc(const std::string& exe) {
  return {"process", exe, {{"pid", 1}, {"exe", exe}, {"exe_sha256", "ab"}, {"parent_exe", "/sbin/init"}, {"uid", 33}, {"kernel_thread", false}}, {}};
}

struct Fleet {
  std::unique_ptr<Store> store = std::move(Store::open(":memory:").value());
  std::vector<std::string> names;

  void member(const std::string& name, std::vector<Observation> users, std::vector<Observation> net, std::vector<Observation> procs, int64_t age = 0) {
    names.push_back(name);
    auto put = [&](const char* collector, std::vector<Observation> obs) {
      Snapshot s;
      s.target = name;
      s.collector = collector;
      s.ts = nowTs() - age;
      s.observations = std::move(obs);
      REQUIRE(store->save(s).ok());
    };
    put("users", std::move(users));
    put("network", std::move(net));
    put("processes", std::move(procs));
    put("persistence", {});
    put("system", {});
  }

  CollectOutput run(const std::string& target, size_t min_group = 3, double share = 0.8) {
    PeerCollector pc;
    CollectorOptions o;
    o.target = target;
    o.store = store.get();
    o.group = "web";
    o.group_members = names;
    o.peer_min_group = min_group;
    o.peer_min_share = share;
    pc.configure(o);
    FakeTransport t;
    auto r = pc.collect(t);
    REQUIRE(r.ok());
    return r.value();
  }
};

std::vector<std::string> keys(const CollectOutput& o) {
  std::vector<std::string> k;
  for (const auto& ob : o.observations) k.push_back(ob.data["kind"].get<std::string>() + ":" + ob.data["facet"].get<std::string>() + ":" + ob.data["item"].get<std::string>());
  std::sort(k.begin(), k.end());
  return k;
}

}  // namespace

TEST_CASE("peers: items are compared without the parts that differ for no reason") {
  Snapshot s;
  s.observations = {user("alice", 1001), proc("/usr/bin/apt-get"), proc("/opt/app/server"), listen(80),
                    {"socket.inet", "e", {{"proto", "tcp"}, {"local_addr", "0.0.0.0"}, {"local_port", 40000}, {"owners", {{{"pid", 1}, {"comm", "x"}}}}}, {"listening"}}};
  const auto items = PeerCollector::comparableItems(s);
  REQUIRE(items.count("user.account|alice"));                   // the uid is not part of the comparison
  REQUIRE(items.count("process.exe|/opt/app/server"));
  REQUIRE_FALSE(items.count("process.exe|/usr/bin/apt-get"));   // system tools come and go
  REQUIRE(items.count("net.listen|tcp|0.0.0.0:80"));
  REQUIRE(items.size() == 3);                                   // the ephemeral port is not a service
}

TEST_CASE("peers: what exists on one machine only, and what only one machine lacks") {
  Fleet f;
  const auto base_users = std::vector<Observation>{user("root", 0), user("deploy", 1000)};
  const auto base_net = std::vector<Observation>{listen(22), listen(80)};
  const auto base_proc = std::vector<Observation>{proc("/opt/app/server")};
  f.member("web01", {user("root", 0), user("deploy", 1000), user("backdoor", 1337)}, {listen(22), listen(80), listen(4444)}, {proc("/opt/app/server"), proc("/tmp/.x/miner")});
  f.member("web02", base_users, base_net, base_proc);
  f.member("web03", {user("root", 0), user("deploy", 1002)}, base_net, base_proc);  // the uid differs: not a difference
  f.member("web04", base_users, {listen(22)}, base_proc);                            // nginx is down here

  const auto web01 = f.run("web01");
  REQUIRE(keys(web01) == std::vector<std::string>{"unique:net.listen:tcp|0.0.0.0:4444", "unique:process.exe:/tmp/.x/miner", "unique:user.account:backdoor"});
  for (const auto& o : web01.observations) {
    REQUIRE(o.data["peers"] == 3);
    REQUIRE(o.data["peers_with_it"] == 0);
    if (o.data["facet"] == "user.account") REQUIRE(std::find(o.tags.begin(), o.tags.end(), "sensitive") != o.tags.end());
  }
  // sensitive differences are listed first
  REQUIRE(web01.observations[0].data["facet"] == "user.account");

  // web04 lacks the web server that all the others have (2 of 3 peers... web01 has it too: 3 of 3)
  REQUIRE(keys(f.run("web04")) == std::vector<std::string>{"missing:net.listen:tcp|0.0.0.0:80"});
  // a machine that is like the others reports nothing
  REQUIRE(f.run("web02").observations.empty());
}

TEST_CASE("peers: no verdict without enough comparable machines") {
  Fleet f;
  f.member("a", {user("x", 1)}, {listen(22)}, {proc("/opt/a")});
  f.member("b", {user("x", 1)}, {listen(22)}, {proc("/opt/a")});
  auto two = f.run("a");  // the group needs three members: with two there is no "majority"
  REQUIRE(two.observations.empty());
  REQUIRE_FALSE(two.warnings.empty());

  f.member("c", {user("x", 1)}, {listen(22)}, {proc("/opt/a")}, 5 * 86400);  // its data is days old: ignored
  auto stale = f.run("a");
  REQUIRE(stale.observations.empty());
  REQUIRE(stale.warnings[0].find("waits for data") != std::string::npos);
}

TEST_CASE("peers: the shipped rules turn a deviation into a finding") {
  auto rules = loadRulesDir(DEFAULT_RULES_DIR);
  REQUIRE(rules.ok());
  Fleet f;
  f.member("web01", {user("root", 0), user("backdoor", 1337)}, {listen(22), listen(4444)}, {proc("/opt/app/server")});
  f.member("web02", {user("root", 0)}, {listen(22), listen(80)}, {proc("/opt/app/server")});
  f.member("web03", {user("root", 0)}, {listen(22), listen(80)}, {proc("/opt/app/server")});
  f.member("web04", {user("root", 0)}, {listen(22), listen(80)}, {proc("/opt/app/server")});
  auto out = f.run("web01");
  Analyzer an(*f.store, rules.value(), std::chrono::seconds(0));
  f.store->lockBaseline("web01", 0);
  Snapshot s;
  s.target = "web01";
  s.collector = "peers";
  s.ts = nowTs();
  s.observations = out.observations;
  auto r = an.analyze(s);
  REQUIRE(r.ok());
  std::map<std::string, Severity> by_rule;
  for (const auto& fnd : r.value().fresh) by_rule[fnd.rule_id] = fnd.severity;
  REQUIRE(by_rule.count("PEER-001"));
  REQUIRE(by_rule["PEER-001"] == Severity::High);     // the account nobody else has
  REQUIRE(by_rule.count("PEER-002"));                  // the port nobody else has
  REQUIRE(by_rule.count("PEER-003"));                  // port 80 that three peers serve
}
