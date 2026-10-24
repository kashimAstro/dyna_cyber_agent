#include <catch2/catch.hpp>

#include "analysis/analyzer.h"
#include "analysis/rule.h"
#include "collectors/crossview_collector.h"
#include "fake_transport.h"

using namespace agent;

namespace {

FakeTransport machine() {
  FakeTransport t;
  t.dirs["/proc"] = {"1", "100", "200", "self"};
  t.dirs["/sys/fs/cgroup"] = {"system.slice", "cgroup.procs"};
  t.dirs["/sys/fs/cgroup/system.slice"] = {"ssh.service"};
  t.dirs["/sys/fs/cgroup/system.slice/ssh.service"] = {};
  t.files["/sys/fs/cgroup/cgroup.procs"] = "";
  t.files["/sys/fs/cgroup/system.slice/cgroup.procs"] = "";
  t.files["/sys/fs/cgroup/system.slice/ssh.service/cgroup.procs"] = "100\n200\n";
  t.files["/proc/modules"] = "ext4 1000 1 - Live 0x0\nvfat 10 0 - Live 0x0\n";
  t.dirs["/sys/module"] = {"ext4", "vfat", "printk"};
  t.dirs["/sys/module/ext4"] = {};
  t.dirs["/sys/module/vfat"] = {};
  t.dirs["/sys/module/printk"] = {};
  t.files["/sys/module/ext4/initstate"] = "live\n";
  t.files["/sys/module/vfat/initstate"] = "live\n";  // printk is built in: no initstate
  t.files["/proc/net/tcp"] = "  sl  local_address rem_address   st tx_queue rx_queue\n   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1\n"
                             "   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2\n"
                             "   2: 0100007F:D0A0 0100007F:1F90 01 00000000:00000000 00:00000000 00000000     0        0 3\n";
  t.files["/proc/net/tcp6"] = "  sl  local_address rem_address   st\n";
  CommandResult ss;
  ss.exit_code = 0;
  ss.out = "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\ntcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*\ntcp   LISTEN 0      5          127.0.0.1:8080      0.0.0.0:*\nudp   UNCONN 0      0            0.0.0.0:68        0.0.0.0:*\n";
  t.commands["ss -tulpn"] = ss;
  t.files["/proc/200/stat"] = "200 (sshd) S 1 200 200 0 -1 4194560 100 0 0 0 0 0 0 0 20 0 1 0 5000 1000 100 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n";
  t.files["/proc/777/stat"] = "777 (kworker-evil) S 1 777 777 0 -1 4194560 100 0 0 0 0 0 0 0 20 0 1 0 5000 1000 100 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n";
  return t;
}

std::vector<std::string> keys(const CollectOutput& o, const std::string& type) {
  std::vector<std::string> k;
  for (const auto& ob : o.observations) if (ob.type == type) k.push_back(ob.key);
  return k;
}

}  // namespace

TEST_CASE("crossview parsers") {
  REQUIRE(CrossViewCollector::parsePidList("1\n22\nx\n0\n300\n") == std::set<int>{1, 22, 300});
  REQUIRE(CrossViewCollector::listeningTcpPorts("hdr\n 0: 00000000:0016 00000000:0000 0A 0 0\n 1: 0100007F:D0A0 0100007F:1F90 01 0 0\n") == std::set<int>{22});
  REQUIRE(CrossViewCollector::ssListeningTcpPorts("Netid State Recv-Q Send-Q Local Address:Port Peer\ntcp LISTEN 0 1 [::]:443 [::]:*\nudp UNCONN 0 0 0.0.0.0:68 0.0.0.0:*\ntcp ESTAB 0 0 1.1.1.1:5 2.2.2.2:6\n") == std::set<int>{443});
  const auto bpf = CrossViewCollector::bpfPrograms("ffffffffc0a01234 t bpf_prog_7c1f3a9d0e2b4a55_sched_cls_x\t[bpf]\nffffffff81000000 T startup_64\nffffffffc0a01300 t bpf_prog_zzzz_bad\t[bpf]\n");
  REQUIRE(bpf.size() == 1);
  REQUIRE(bpf[0].tag == "7c1f3a9d0e2b4a55");
  REQUIRE(bpf[0].name == "sched_cls_x");
}

TEST_CASE("crossview: a consistent machine reports nothing") {
  auto t = machine();
  CrossViewCollector c;
  for (int i = 0; i < 3; ++i) {
    auto r = c.collect(t);
    REQUIRE(r.ok());
    for (const auto& o : r.value().observations) REQUIRE((o.type == "bpf.program" || o.type == "bpf.pinned"));
  }
}

TEST_CASE("crossview: a hidden process, module and port are reported on the second sighting") {
  auto t = machine();
  t.files["/sys/fs/cgroup/system.slice/ssh.service/cgroup.procs"] = "100\n200\n777\n";  // 777 is in a cgroup but not in the /proc listing
  t.dirs["/sys/module"].push_back("diamorphine");
  t.dirs["/sys/module/diamorphine"] = {};
  t.files["/sys/module/diamorphine/initstate"] = "live\n";                              // loaded, but missing from /proc/modules
  t.commands["ss -tulpn"].out += "tcp   LISTEN 0      128          0.0.0.0:31337     0.0.0.0:*\n";  // netlink shows a port /proc/net/tcp does not

  CrossViewCollector c;
  auto first = c.collect(t);
  REQUIRE(first.ok());
  REQUIRE(keys(first.value(), "crossview.hidden_pid").empty());  // one sighting could be a race
  auto second = c.collect(t);
  REQUIRE(second.ok());
  REQUIRE(keys(second.value(), "crossview.hidden_pid") == std::vector<std::string>{"pid|777"});
  REQUIRE(keys(second.value(), "crossview.hidden_module") == std::vector<std::string>{"module|diamorphine"});
  REQUIRE(keys(second.value(), "crossview.hidden_port") == std::vector<std::string>{"port|31337|proc"});
  for (const auto& o : second.value().observations) {
    if (o.type == "crossview.hidden_pid") REQUIRE(o.data["comm"] == "kworker-evil");
  }

  // a process that was only in the middle of exiting disappears from the report
  t.files.erase("/proc/777/stat");
  auto third = c.collect(t);
  REQUIRE(keys(third.value(), "crossview.hidden_pid").empty());

  // the shipped rules rate these as rootkit indicators
  auto rules = loadRulesDir(DEFAULT_RULES_DIR);
  REQUIRE(rules.ok());
  auto st = Store::open(":memory:");
  st.value()->lockBaseline("t", 0);
  Analyzer an(*st.value(), rules.value(), std::chrono::seconds(0));
  Snapshot s;
  s.target = "t";
  s.collector = "crossview";
  s.ts = 100;
  s.observations = second.value().observations;
  auto res = an.analyze(s);
  REQUIRE(res.ok());
  std::map<std::string, Severity> by;
  for (const auto& f : res.value().fresh) by[f.rule_id] = f.severity;
  REQUIRE(by["ROOT-001"] == Severity::Critical);
  REQUIRE(by["ROOT-002"] == Severity::Critical);
  REQUIRE(by["ROOT-003"] == Severity::High);
}

TEST_CASE("crossview: eBPF programs are read hourly and reported in between") {
  auto t = machine();
  t.files["/proc/kallsyms"] = "ffffffffc0a01234 t bpf_prog_7c1f3a9d0e2b4a55_xdp_main\t[bpf]\n";
  t.dirs["/sys/fs/bpf"] = {"tc"};
  CrossViewCollector c;
  auto r1 = c.collect(t);
  REQUIRE(keys(r1.value(), "bpf.program") == std::vector<std::string>{"bpf|7c1f3a9d0e2b4a55"});
  REQUIRE(keys(r1.value(), "bpf.pinned") == std::vector<std::string>{"bpffs|tc"});
  t.files.erase("/proc/kallsyms");  // not read again for a while
  auto r2 = c.collect(t);
  REQUIRE(keys(r2.value(), "bpf.program") == std::vector<std::string>{"bpf|7c1f3a9d0e2b4a55"});
}

TEST_CASE("crossview: missing interfaces are a warning, not an error") {
  FakeTransport t;  // nothing readable at all
  CrossViewCollector c;
  auto r = c.collect(t);
  REQUIRE(r.ok());
  REQUIRE(r.value().observations.empty());
  REQUIRE_FALSE(r.value().warnings.empty());
}
