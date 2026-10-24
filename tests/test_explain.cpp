#include <catch2/catch.hpp>

#include "analysis/analyzer.h"
#include "analysis/explain.h"
#include "analysis/rule.h"
#include "collectors/packages_collector.h"
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

std::string status(const std::string& name, const std::string& version, const std::string& extra = "") {
  return "Package: " + name + "\nStatus: install ok installed\nArchitecture: amd64\nVersion: " + version + "\n" + extra + "\n";
}

FakeTransport debian(const std::string& ssh_version) {
  FakeTransport t;
  t.files["/etc/os-release"] = "ID=debian\nVERSION_ID=\"12\"\n";
  t.files["/proc/sys/kernel/osrelease"] = "6.1.0-18-amd64\n";
  t.files["/var/lib/dpkg/status"] = status("openssh-server", ssh_version) + status("libc6", "2.36-9", "Multi-Arch: same\n") + status("curl", "7.88.1");
  t.files["/var/lib/dpkg/info/openssh-server.list"] = "/.\n/usr\n/usr/sbin/sshd\n/usr/share/doc/openssh-server/README\n/etc/ssh/sshd_config\n/lib/systemd/system/ssh.service\n/usr/lib/python3/dist-packages/x.py\n";
  t.files["/var/lib/dpkg/info/libc6:amd64.list"] = "/lib/x86_64-linux-gnu/libc.so.6\n/usr/bin/ldd\n";
  t.files["/var/lib/dpkg/info/curl.list"] = "/usr/bin/curl\n";
  return t;
}

const Observation* findChange(const CollectOutput& o, const std::string& package, const std::string& kind) {
  for (const auto& ob : o.observations) {
    if (ob.type == "pkg.change" && ob.data.value("package", "") == package && ob.data.value("kind", "") == kind) return &ob;
  }
  return nullptr;
}

}  // namespace

TEST_CASE("only files worth citing are kept from a package file list") {
  REQUIRE(interestingOwnedPath("/usr/sbin/sshd"));
  REQUIRE(interestingOwnedPath("/etc/ssh/sshd_config"));
  REQUIRE(interestingOwnedPath("/lib/systemd/system/ssh.service"));
  REQUIRE(interestingOwnedPath("/usr/lib/openssh/sftp-server"));
  REQUIRE(interestingOwnedPath("/lib/modules/6.1.0-18-amd64/kernel/fs/ext4/ext4.ko"));
  REQUIRE_FALSE(interestingOwnedPath("/usr/share/doc/x/README"));
  REQUIRE_FALSE(interestingOwnedPath("/usr/lib/x86_64-linux-gnu/libssl.so.3"));
  REQUIRE_FALSE(interestingOwnedPath("/usr/lib/python3/dist-packages/x.py"));
  REQUIRE_FALSE(interestingOwnedPath("/usr/bin/"));  // a directory entry
  REQUIRE_FALSE(interestingOwnedPath("relative/path"));
  const auto files = parseDpkgFileList("/.\n/usr\n/usr/sbin/sshd\n/usr/share/doc/a\n/etc/ssh/sshd_config\n");
  REQUIRE(files == std::vector<std::string>{"/usr/sbin/sshd", "/etc/ssh/sshd_config"});
}

TEST_CASE("the packages collector reports upgrades and the files each package owns") {
  MemState st;
  CollectorOptions o;
  o.target = "web01";
  o.state = &st;

  // first run: no history, so no events, but the file lists are collected ("inventory")
  auto t1 = debian("1:9.2p1-2");
  PackagesCollector c1;
  c1.configure(o);
  auto r1 = c1.collect(t1);
  REQUIRE(r1.ok());
  const auto* inv = findChange(r1.value(), "openssh-server", "inventory");
  REQUIRE(inv);
  REQUIRE(inv->data["ts"] == 0);
  REQUIRE(inv->data["files"] == nlohmann::json::array({"/usr/sbin/sshd", "/etc/ssh/sshd_config", "/lib/systemd/system/ssh.service"}));
  REQUIRE(findChange(r1.value(), "libc6", "inventory"));  // multi-arch list name

  // second run, nothing changed: nothing reported
  auto r2 = [&] {
    PackagesCollector c;
    c.configure(o);
    return c.collect(t1);
  }();
  REQUIRE(r2.ok());
  for (const auto& ob : r2.value().observations) REQUIRE(ob.type != "pkg.change");

  // an upgrade, an installation and a removal
  auto t3 = debian("1:9.2p1-2+deb12u3");
  t3.files["/var/lib/dpkg/status"] += status("nginx", "1.22.1");
  t3.files["/var/lib/dpkg/info/nginx.list"] = "/usr/sbin/nginx\n";
  t3.files["/var/lib/dpkg/status"].erase(t3.files["/var/lib/dpkg/status"].find("Package: curl"), status("curl", "7.88.1").size());
  FileInfo fi;
  fi.mtime = 5000;
  t3.infos["/var/lib/dpkg/info/openssh-server.list"] = fi;
  PackagesCollector c3;
  c3.configure(o);
  auto r3 = c3.collect(t3);
  REQUIRE(r3.ok());
  const auto* up = findChange(r3.value(), "openssh-server", "upgraded");
  REQUIRE(up);
  REQUIRE(up->data["old_version"] == "1:9.2p1-2");
  REQUIRE(up->data["new_version"] == "1:9.2p1-2+deb12u3");
  REQUIRE(up->data["ts"] == 5000);  // the time dpkg wrote the list, not the time of our run
  REQUIRE(up->data["files"].size() == 3);
  REQUIRE(findChange(r3.value(), "nginx", "installed"));
  REQUIRE(findChange(r3.value(), "curl", "removed"));
}

TEST_CASE("file lists are read in chunks on a large first inventory") {
  MemState st;
  FakeTransport t;
  t.files["/etc/os-release"] = "ID=debian\n";
  std::string db;
  const size_t n = PackagesCollector::kMaxListReadsPerRun + 50;
  for (size_t i = 0; i < n; ++i) {
    const std::string name = "pkg" + std::to_string(i);
    db += status(name, "1.0");
    t.files["/var/lib/dpkg/info/" + name + ".list"] = "/usr/bin/" + name + "\n";
  }
  t.files["/var/lib/dpkg/status"] = db;
  CollectorOptions o;
  o.target = "t";
  o.state = &st;
  auto count = [&] {
    PackagesCollector c;
    c.configure(o);
    auto r = c.collect(t);
    REQUIRE(r.ok());
    size_t k = 0;
    for (const auto& ob : r.value().observations) k += ob.type == "pkg.change";
    return k;
  };
  REQUIRE(count() == PackagesCollector::kMaxListReadsPerRun);
  REQUIRE(count() == 50);
  REQUIRE(count() == 0);
}

TEST_CASE("a reboot waiting for an update is reported") {
  auto t = debian("1:9.2p1-2");
  t.files["/var/run/reboot-required"] = "*** System restart required ***\n";
  t.files["/var/run/reboot-required.pkgs"] = "linux-image-6.1.0-20-amd64\nlibc6\n";
  auto r = PackagesCollector().collect(t);
  REQUIRE(r.ok());
  const Observation* rb = nullptr;
  for (const auto& ob : r.value().observations) if (ob.type == "os.reboot_required") rb = &ob;
  REQUIRE(rb);
  REQUIRE(rb->data["required"] == true);
  REQUIRE(rb->data["packages"][0] == "linux-image-6.1.0-20-amd64");
  REQUIRE(rb->tags == std::vector<std::string>{"reboot_pending"});
}

TEST_CASE("a finding is explained by a recent upgrade of the package that owns its file") {
  auto st = Store::open(":memory:");
  REQUIRE(st.ok());
  Store& store = *st.value();
  REQUIRE(store.recordPackageData("web01", {{10000, "openssh-server", "upgraded", "9.2", "9.3"}},
                                  {{"openssh-server", 10000, {"/usr/sbin/sshd", "/etc/ssh/sshd_config"}}, {"curl", 0, {"/usr/bin/curl"}}}).ok());
  const nlohmann::json ev = {{"exe", "/usr/sbin/sshd (deleted)"}, {"cmdline", {"/usr/sbin/sshd", "-D"}}, {"pid", 7}};
  const std::chrono::seconds week(7 * 86400);

  auto e = explainByUpdate(store, "web01", ev, 10600, week);
  REQUIRE(e);
  REQUIRE(e->package == "openssh-server");
  REQUIRE(e->kind == "upgraded");
  REQUIRE(e->new_version == "9.3");
  REQUIRE(e->changed_at == 10000);

  REQUIRE_FALSE(explainByUpdate(store, "web01", ev, 10000 + 8 * 86400, week));  // too long ago
  REQUIRE_FALSE(explainByUpdate(store, "web01", ev, 5000, week));               // the finding came BEFORE the upgrade
  REQUIRE(explainByUpdate(store, "web01", ev, 9800, week));                      // a few minutes of skew are fine
  REQUIRE_FALSE(explainByUpdate(store, "db01", ev, 10600, week));                // another machine
  REQUIRE_FALSE(explainByUpdate(store, "web01", {{"exe", "/usr/bin/curl"}}, 10600, week));  // already installed before monitoring (changed_at 0)
  REQUIRE_FALSE(explainByUpdate(store, "web01", {{"exe", "/tmp/evil"}}, 10600, week));

  // the package manager itself reports the file as modified: no excuse
  Finding pv;
  pv.fingerprint = "PKG-001|web01|x";
  pv.rule_id = "PKG-001";
  pv.target = "web01";
  pv.collector = "integrity";
  pv.obs_type = "pkg.verify";
  pv.stable_key = "x";
  pv.evidence = {{"path", "/usr/sbin/sshd"}, {"flags", "??5??????"}};
  REQUIRE(store.upsertFinding(pv).ok());
  REQUIRE_FALSE(explainByUpdate(store, "web01", ev, 10600, week));
}

TEST_CASE("the analyzer tags findings explained by an upgrade, and keeps the tag on repeats") {
  auto st = Store::open(":memory:");
  REQUIRE(st.ok());
  Store& store = *st.value();
  store.recordPackageData("t", {{1000, "openssh-server", "upgraded", "9.2", "9.3"}}, {{"openssh-server", 1000, {"/usr/sbin/sshd"}}});
  auto rules = parseRules(R"(
- id: T-1
  title: Process runs from a deleted binary
  severity: high
  match: {type: process, tags_any: [exe_deleted]}
)", "t");
  REQUIRE(rules.ok());
  AnalyzerOptions opt;
  opt.explain_updates = true;
  Analyzer an(store, rules.value(), std::chrono::seconds(0), opt);
  store.lockBaseline("t", 0);

  auto mk = [](int64_t ts, const std::string& exe) {
    Snapshot s;
    s.target = "t";
    s.collector = "processes";
    s.ts = ts;
    Observation o;
    o.type = "process";
    o.key = "7:1";
    o.tags = {"exe_deleted"};
    o.data = {{"pid", 7}, {"comm", "sshd"}, {"exe", exe}, {"uid", 0}, {"kernel_thread", false}};
    s.observations.push_back(o);
    return s;
  };
  auto r1 = an.analyze(mk(1100, "/usr/sbin/sshd (deleted)"));
  REQUIRE(r1.ok());
  REQUIRE(r1.value().fresh.size() == 1);
  CHECK(r1.value().fresh[0].tags.back() == "explained_by_update");
  CHECK(r1.value().fresh[0].evidence["explained_by"]["package"] == "openssh-server");

  auto r2 = an.analyze(mk(1200, "/usr/sbin/sshd (deleted)"));  // the next cycle re-saves the finding: the tag must survive
  REQUIRE(r2.ok());
  REQUIRE(r2.value().repeats.size() == 1);
  auto stored = store.getFinding(r2.value().repeats[0].id);
  REQUIRE(stored.value());
  CHECK(stored.value()->evidence.contains("explained_by"));
  CHECK(std::find(stored.value()->tags.begin(), stored.value()->tags.end(), "explained_by_update") != stored.value()->tags.end());

  // an unrelated binary is not explained
  auto r3 = an.analyze(mk(1300, "/opt/odd/agent (deleted)"));
  REQUIRE(r3.value().fresh.size() == 1);
  CHECK_FALSE(r3.value().fresh[0].evidence.contains("explained_by"));
}
