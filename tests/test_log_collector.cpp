#include <catch2/catch.hpp>

#include "collectors/log_collector.h"
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

std::string fail(const std::string& ip, int n, const std::string& user = "root") {
  std::string s;
  for (int i = 0; i < n; ++i) s += "Oct 22 20:15:" + std::string(i < 10 ? "0" : "") + std::to_string(i) + " h sshd[1]: Failed password for " + user + " from " + ip + " port 22 ssh2\n";
  return s;
}

std::unique_ptr<LogCollector> make(MemState& st, int backfill_kb = 0, std::vector<std::string> paths = {}) {
  auto c = std::make_unique<LogCollector>();
  CollectorOptions o;
  o.target = "web01";
  o.state = &st;
  o.log_backfill_kb = backfill_kb;
  o.log_paths = std::move(paths);
  c->configure(o);
  c->setClock([] { return 1000; });
  return c;
}

const Observation* find(const CollectOutput& o, const std::string& type, const std::string& key_part = "") {
  for (const auto& ob : o.observations) if (ob.type == type && ob.key.find(key_part) != std::string::npos) return &ob;
  return nullptr;
}

const char* kAuth = "/var/log/auth.log";

}  // namespace

TEST_CASE("logs: start at the end, then read only what is new") {
  FakeTransport t;
  MemState st;
  t.files[kAuth] = fail("203.0.113.1", 20);  // old history: must not be replayed
  auto c = make(st);
  auto r0 = c->collect(t);
  REQUIRE(r0.ok());
  REQUIRE(r0.value().observations.empty());
  REQUIRE(st.kv.count(std::string("log|web01|") + kAuth) == 1);

  REQUIRE(c->collect(t).value().observations.empty());  // nothing appended

  t.files[kAuth] += fail("203.0.113.2", 10);
  auto r1 = c->collect(t);
  REQUIRE(r1.ok());
  REQUIRE(find(r1.value(), "log.auth.bruteforce", "203.0.113.2"));
  REQUIRE_FALSE(find(r1.value(), "log.auth.bruteforce", "203.0.113.1"));  // history stays history
  REQUIRE(c->collect(t).value().observations.empty());                    // and it is consumed only once
}

TEST_CASE("logs: a partial last line waits for its end") {
  FakeTransport t;
  MemState st;
  t.files[kAuth] = "";
  auto c = make(st);
  c->collect(t);
  const std::string line = "Oct 22 20:16:00 h sudo:   alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/bash\n";
  t.files[kAuth] += line.substr(0, 40);  // half a line
  REQUIRE(c->collect(t).value().observations.empty());
  t.files[kAuth] += line.substr(40);
  auto r = c->collect(t);
  REQUIRE(find(r.value(), "log.auth.sudo", "alice"));
}

TEST_CASE("logs: rotation, including inode reuse") {
  FakeTransport t;
  MemState st;
  t.files[kAuth] = "Oct 22 20:00:00 h sshd[1]: Accepted publickey for old from 10.0.0.1 port 1 ssh2: RSA SHA256:x\n";
  t.inodes[kAuth] = 10;
  auto c = make(st);
  c->collect(t);

  // lines written just before logrotate renamed the file, and a fresh file afterwards
  const std::string last_gasp = "Oct 22 20:30:00 h sshd[2]: Accepted password for lastgasp from 10.0.0.2 port 2 ssh2\n";
  t.files[std::string(kAuth) + ".1"] = t.files[kAuth] + last_gasp;
  t.inodes[std::string(kAuth) + ".1"] = 10;
  t.files[kAuth] = "Oct 22 20:31:00 h sshd[3]: Accepted password for newlogin from 10.0.0.3 port 3 ssh2\n";
  t.inodes[kAuth] = 11;
  auto r = c->collect(t);
  REQUIRE(r.ok());
  REQUIRE(find(r.value(), "log.auth.login", "lastgasp"));   // recovered from the renamed file
  REQUIRE(find(r.value(), "log.auth.login", "newlogin"));   // and the new file from its start
  REQUIRE_FALSE(find(r.value(), "log.auth.login", "|old|"));
  REQUIRE(c->collect(t).value().observations.empty());

  // copytruncate / inode reuse: same inode, different (shorter) content
  t.files[kAuth] = "Oct 22 21:00:00 h sshd[4]: Accepted password for reused from 10.0.0.4 port 4 ssh2\n";
  auto r2 = c->collect(t);
  REQUIRE(find(r2.value(), "log.auth.login", "reused"));

  // same inode, same size or longer, but the beginning changed
  t.files[kAuth] = "Oct 22 22:00:00 h sshd[5]: Accepted password for rewritten from 10.0.0.5 port 5 ssh2\n" + std::string(300, ' ') + "\n";
  auto r3 = c->collect(t);
  REQUIRE(find(r3.value(), "log.auth.login", "rewritten"));
}

TEST_CASE("logs: a restart neither loses nor repeats lines") {
  FakeTransport t;
  MemState st;
  t.files[kAuth] = "";
  make(st)->collect(t);
  t.files[kAuth] += fail("203.0.113.7", 9);
  auto first = make(st);  // "the agent was restarted": a new instance with the same persisted state
  REQUIRE(find(first->collect(t).value(), "log.auth.bruteforce", "203.0.113.7"));
  auto second = make(st);
  REQUIRE(second->collect(t).value().observations.empty());
  t.files[kAuth] += fail("203.0.113.8", 9);
  REQUIRE(find(make(st)->collect(t).value(), "log.auth.bruteforce", "203.0.113.8"));
}

TEST_CASE("logs: backfill reads the tail of a log seen for the first time") {
  FakeTransport t;
  MemState st;
  const std::string history = std::string(3000, 'x') + "\n" + fail("203.0.113.9", 12);
  t.files[kAuth] = history;
  auto c = make(st, /*backfill_kb=*/1);  // last KiB only: starts mid-line, the partial line is dropped
  auto r = c->collect(t);
  REQUIRE(r.ok());
  REQUIRE(find(r.value(), "log.auth.bruteforce", "203.0.113.9"));
}

TEST_CASE("logs: no double counting when auth.log and syslog both exist") {
  FakeTransport t;
  MemState st;
  t.files[kAuth] = "";
  t.files["/var/log/syslog"] = "";
  t.files["/var/log/kern.log"] = "";
  auto c = make(st);
  c->collect(t);
  const std::string l = "Oct 22 20:16:00 h sudo:   alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls\n";
  t.files[kAuth] += l;
  t.files["/var/log/syslog"] += l;  // the same event, as rsyslog writes it to both files
  auto r = c->collect(t);
  const auto* s = find(r.value(), "log.auth.sudo", "alice");
  REQUIRE(s);
  REQUIRE(s->data["count"] == 1);

  // syslog alone is enough when the dedicated logs are missing
  FakeTransport t2;
  MemState st2;
  t2.files["/var/log/syslog"] = "";
  auto c2 = make(st2);
  c2->collect(t2);
  t2.files["/var/log/syslog"] += l + "Oct 22 20:17:00 h kernel: [1.0] device eth0 entered promiscuous mode\n";
  auto r2 = c2->collect(t2);
  REQUIRE(find(r2.value(), "log.auth.sudo", "alice"));
  REQUIRE(find(r2.value(), "log.kernel", "promisc"));
}

TEST_CASE("logs: web logs, globs and explicit types") {
  FakeTransport t;
  MemState st;
  t.dirs["/srv/logs"] = {"site-a.access.log", "site-b.access.log", "site-a.error.log", "old.access.log.1"};
  t.files["/srv/logs/site-a.access.log"] = "";
  t.files["/srv/logs/site-b.access.log"] = "";
  t.files["/srv/logs/site-a.error.log"] = "";
  auto c = make(st, 0, {"web:/srv/logs/*.access.log"});
  c->collect(t);
  t.files["/srv/logs/site-a.access.log"] += "203.0.113.9 - - [22/Oct/2026:20:15:01 +0000] \"GET /.env HTTP/1.1\" 404 5 \"-\" \"x\"\n";
  t.files["/srv/logs/site-b.access.log"] += "203.0.113.8 - - [22/Oct/2026:20:15:01 +0000] \"GET /?x=${jndi:ldap://e/a} HTTP/1.1\" 200 5 \"-\" \"x\"\n";
  t.files["/srv/logs/site-a.error.log"] += "garbage that must be ignored\n";
  auto r = c->collect(t);
  REQUIRE(r.ok());
  REQUIRE(find(r.value(), "log.web.attack", "203.0.113.9|sensitive_probe"));
  REQUIRE(find(r.value(), "log.web.attack", "203.0.113.8|log4shell"));
  REQUIRE(std::count_if(r.value().observations.begin(), r.value().observations.end(), [](const Observation& o) { return o.type != "log.source"; }) == 2);
}

TEST_CASE("logs: journal fallback keeps a cursor") {
  FakeTransport t;  // no log files at all
  MemState st;
  t.journal_cursor = "s=1;i=1";
  t.journal_text = "";
  auto c = make(st);
  auto r0 = c->collect(t);  // first run: only remembers where the journal is
  REQUIRE(r0.ok());
  REQUIRE(r0.value().observations.empty());
  REQUIRE(st.kv["journal|web01"] == "s=1;i=1");

  t.journal_cursor = "s=1;i=2";
  t.journal_text = "2026-10-22T20:16:00+0000 h sudo[9]:   alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/bash\n"
                   "2026-10-22T20:16:01+0000 h kernel: [1.0] device eth0 entered promiscuous mode\n";
  auto r = c->collect(t);
  REQUIRE(find(r.value(), "log.auth.sudo", "alice"));
  REQUIRE(find(r.value(), "log.kernel", "promisc"));
  REQUIRE(st.kv["journal|web01"] == "s=1;i=2");
}

TEST_CASE("logs: unreadable sources are reported, not hidden") {
  FakeTransport t;  // nothing readable, no journal
  t.journal_fails = true;
  MemState st;
  auto c = make(st, 0, {"auth:/var/log/auth.log"});
  auto r = c->collect(t);
  REQUIRE(r.ok());
  REQUIRE_FALSE(r.value().warnings.empty());
  bool mentions = false;
  for (const auto& w : r.value().warnings) mentions |= w.find("auth.log") != std::string::npos || w.find("no readable log source") != std::string::npos;
  REQUIRE(mentions);
}

#include "core/config.h"

TEST_CASE("config: log sources") {
  auto cfg = [](const std::string& extra) {
    return parseConfig("targets:\n  - {name: a, transport: local" + extra + "}\n");
  };
  auto ok = cfg(", log_paths: ['/var/log/auth.log', 'web:/var/log/nginx/*.log', 'kernel:/var/log/kern.log'], log_backfill_kb: 64, collectors: [logs, persistence, system, files, integrity]");
  REQUIRE(ok.ok());
  REQUIRE(ok.value().targets[0].log_paths.size() == 3);
  REQUIRE(ok.value().targets[0].log_backfill_kb == 64);
  REQUIRE(cfg("").ok());
  REQUIRE_FALSE(cfg(", log_paths: ['relative/auth.log']").ok());
  REQUIRE_FALSE(cfg(", log_paths: ['/var/log/../etc/shadow']").ok());
  REQUIRE_FALSE(cfg(", log_paths: ['/var/*/auth.log']").ok());   // wildcard only in the last component
  REQUIRE_FALSE(cfg(", log_paths: ['']").ok());
  REQUIRE_FALSE(cfg(", log_backfill_kb: -1").ok());
  REQUIRE_FALSE(cfg(", log_backfill_kb: 99999").ok());
  REQUIRE(cfg(", log_paths: '/var/log/auth.log'").ok());          // a single scalar is accepted too
}
