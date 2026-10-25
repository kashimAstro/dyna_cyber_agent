#include <catch2/catch.hpp>

#include <filesystem>

#include "analysis/analyzer.h"
#include "analysis/exclusions.h"
#include "analysis/rule.h"
#include "store/store.h"

using namespace agent;
using nlohmann::json;

#ifndef DEFAULT_RULES_DIR
#error "DEFAULT_RULES_DIR must be defined by the build"
#endif

namespace {

Exclusion ex(const std::string& kind, const std::string& pattern, const std::string& target = "") {
  Exclusion x;
  x.kind = kind;
  x.pattern = pattern;
  x.target = target;
  return x;
}

bool hits(const Exclusion& x, const std::string& obs_type, const json& data, const std::string& rule = "X-001", const std::string& target = "web01") {
  return exclusionMatches(x, target, rule, obs_type, data);
}

}  // namespace

TEST_CASE("exclusion patterns: what is accepted, and what would blind the agent is refused") {
  REQUIRE(normalizeExclusionPattern("rule", " log-050 ").value() == "LOG-050");
  REQUIRE(normalizeExclusionPattern("rule", "LOG-05*").ok());
  REQUIRE_FALSE(normalizeExclusionPattern("rule", "LOG").ok());
  REQUIRE_FALSE(normalizeExclusionPattern("rule", "*").ok());                       // everything
  REQUIRE_FALSE(normalizeExclusionPattern("rule", "**").ok());
  REQUIRE(normalizeExclusionPattern("package", "linux-*").ok());
  REQUIRE_FALSE(normalizeExclusionPattern("package", "bad/name").ok());
  REQUIRE(normalizeExclusionPattern("cve", "cve-2026-1234").value() == "CVE-2026-1234");
  REQUIRE_FALSE(normalizeExclusionPattern("cve", "2026-1234").ok());
  REQUIRE(normalizeExclusionPattern("port", "TCP/22").value() == "tcp/22");
  REQUIRE(normalizeExclusionPattern("port", "8000-8100").ok());
  REQUIRE_FALSE(normalizeExclusionPattern("port", "0").ok());
  REQUIRE_FALSE(normalizeExclusionPattern("port", "70000").ok());
  REQUIRE_FALSE(normalizeExclusionPattern("port", "9000-8000").ok());
  REQUIRE_FALSE(normalizeExclusionPattern("port", "icmp/1").ok());
  REQUIRE(normalizeExclusionPattern("user", "backup").ok());
  REQUIRE(normalizeExclusionPattern("user", "svc-*").ok());
  REQUIRE_FALSE(normalizeExclusionPattern("user", "root").ok());                    // the account an intruder wants
  REQUIRE_FALSE(normalizeExclusionPattern("user", "r*").ok());                      // ... also through a wildcard
  REQUIRE_FALSE(normalizeExclusionPattern("user", "ro?t").ok());
  REQUIRE(normalizeExclusionPattern("ip", "203.0.113.7").ok());
  REQUIRE(normalizeExclusionPattern("ip", "192.168.1.0/24").ok());
  REQUIRE(normalizeExclusionPattern("ip", "2001:db8::1").ok());
  REQUIRE_FALSE(normalizeExclusionPattern("ip", "0.0.0.0/0").ok());                 // too wide
  REQUIRE_FALSE(normalizeExclusionPattern("ip", "10.0.0.0/4").ok());
  REQUIRE_FALSE(normalizeExclusionPattern("ip", "not-an-ip").ok());
  REQUIRE(normalizeExclusionPattern("path", "/opt/app/").value() == "/opt/app/*");  // a directory means what is below it
  REQUIRE_FALSE(normalizeExclusionPattern("path", "opt/app").ok());
  REQUIRE_FALSE(normalizeExclusionPattern("path", "/opt/../etc").ok());
  REQUIRE_FALSE(normalizeExclusionPattern("path", "/*").ok());
  REQUIRE_FALSE(normalizeExclusionPattern("path", "/usr/*").ok());                  // a whole system directory
  REQUIRE(normalizeExclusionPattern("path", "/usr/local/legacy/tool").ok());
  REQUIRE(normalizeExclusionPattern("process", "/usr/bin/backup-agent").ok());
  REQUIRE_FALSE(normalizeExclusionPattern("process", "two words").ok());
  REQUIRE_FALSE(normalizeExclusionPattern("colour", "red").ok());
  REQUIRE_FALSE(normalizeExclusionPattern("rule", "").ok());
  REQUIRE_FALSE(normalizeExclusionPattern("rule", std::string(300, 'A')).ok());
}

TEST_CASE("exclusions: each kind looks at the right fields, and only there") {
  // rules
  REQUIRE(hits(ex("rule", "LOG-050"), "log.template", {}, "LOG-050"));
  REQUIRE_FALSE(hits(ex("rule", "LOG-050"), "log.template", {}, "LOG-051"));
  REQUIRE(hits(ex("rule", "LOG-05*"), "log.template", {}, "LOG-051"));

  // packages and CVEs (vulnerability matches carry both the source package and its binaries)
  const json vuln = {{"cve", "CVE-2026-1"}, {"package", "linux"}, {"binaries", json::array({"linux-image-6.8", "linux-headers-6.8"})}};
  REQUIRE(hits(ex("package", "linux"), "vuln.match", vuln));
  REQUIRE(hits(ex("package", "linux-image-*"), "vuln.match", vuln));
  REQUIRE_FALSE(hits(ex("package", "openssl"), "vuln.match", vuln));
  REQUIRE_FALSE(hits(ex("package", "linux"), "process", {{"package", "linux"}}));  // only package and vulnerability data
  REQUIRE(hits(ex("cve", "CVE-2026-1"), "vuln.match", vuln));
  REQUIRE(hits(ex("cve", "CVE-2026-*"), "vuln.match", vuln));
  REQUIRE_FALSE(hits(ex("cve", "CVE-2025-*"), "vuln.match", vuln));

  // ports: a service this machine offers, not a connection to someone else's port
  const json listen = {{"proto", "tcp"}, {"local_addr", "0.0.0.0"}, {"local_port", 8080}, {"remote_addr", "0.0.0.0"}, {"remote_port", 0}};
  const json outbound = {{"proto", "tcp"}, {"local_addr", "10.0.0.5"}, {"local_port", 51000}, {"remote_addr", "203.0.113.9"}, {"remote_port", 443}};
  REQUIRE(hits(ex("port", "8080"), "socket.inet", listen));
  REQUIRE(hits(ex("port", "tcp/8000-8100"), "socket.inet", listen));
  REQUIRE_FALSE(hits(ex("port", "udp/8080"), "socket.inet", listen));
  REQUIRE_FALSE(hits(ex("port", "443"), "socket.inet", outbound));                // excluding 443 must not hide connections out to it
  REQUIRE(hits(ex("port", "31337"), "crossview.hidden_port", {{"port", 31337}}));

  // accounts: logins, sudo, cron, ssh keys, the account itself; not file ownership or process uids
  REQUIRE(hits(ex("user", "backup"), "log.auth.login", {{"user", "backup"}, {"src_ip", "10.0.0.2"}}));
  REQUIRE(hits(ex("user", "backup"), "log.auth.sudo", {{"user", "alice"}, {"target_user", "backup"}}));
  REQUIRE(hits(ex("user", "svc-*"), "user", {{"name", "svc-ci"}}));
  REQUIRE(hits(ex("user", "backup"), "cron.entry", {{"user", "backup"}, {"command", "x"}}));
  REQUIRE_FALSE(hits(ex("user", "backup"), "file.entry", {{"user", "backup"}, {"path", "/usr/bin/su-like"}}));  // a SUID file owned by it is still news
  REQUIRE_FALSE(hits(ex("user", "backup"), "log.auth.login", {{"user", "mario"}}));

  // addresses
  REQUIRE(hits(ex("ip", "203.0.113.7"), "log.auth.bruteforce", {{"src_ip", "203.0.113.7"}}));
  REQUIRE(hits(ex("ip", "192.168.1.0/24"), "log.auth.login", {{"src_ip", "192.168.1.77"}}));
  REQUIRE_FALSE(hits(ex("ip", "192.168.1.0/24"), "log.auth.login", {{"src_ip", "192.168.2.77"}}));
  REQUIRE(hits(ex("ip", "198.51.100.1"), "socket.inet", json{{"remote_addr", "198.51.100.1"}, {"remote_port", 22}}));

  // paths and programs
  REQUIRE(hits(ex("path", "/opt/etcher/*"), "file.entry", {{"path", "/opt/etcher/chrome-sandbox"}}));
  REQUIRE_FALSE(hits(ex("path", "/opt/etcher/*"), "file.entry", {{"path", "/opt/other/x"}}));
  REQUIRE(hits(ex("path", "/etc/cron.d/backup"), "cron.entry", {{"file", "/etc/cron.d/backup"}}));
  REQUIRE(hits(ex("process", "/usr/bin/backup-agent"), "process", {{"exe", "/usr/bin/backup-agent"}, {"comm", "backup-agent"}}));
  REQUIRE(hits(ex("process", "backup-*"), "process", {{"exe", "/usr/bin/backup-agent"}, {"comm", "backup-agent"}}));
  REQUIRE_FALSE(hits(ex("process", "backup-*"), "file.entry", {{"exe", "backup-x"}}));  // processes only

  // one machine only
  REQUIRE(hits(ex("rule", "LOG-050", "web01"), "x", {}, "LOG-050", "web01"));
  REQUIRE_FALSE(hits(ex("rule", "LOG-050", "web01"), "x", {}, "LOG-050", "db01"));

  ExclusionSet set({ex("ip", "10.0.0.0/8"), ex("ip", "203.0.113.7", "db01")});
  REQUIRE(set.excludesAddress("web01", "10.1.2.3"));
  REQUIRE_FALSE(set.excludesAddress("web01", "203.0.113.7"));                         // that one is for db01 only
  REQUIRE(set.excludesAddress("db01", "203.0.113.7"));
}

TEST_CASE("exclusions in the store: one filter per kind+pattern+machine, expiry, deletion, closing what is open") {
  auto st = Store::open(":memory:");
  Store& s = *st.value();
  Exclusion a = ex("user", "backup");
  a.created_at = 100;
  a.note = "backup account";
  const int64_t id = s.addExclusion(a).value();
  a.note = "changed note";
  a.expires_at = 5000;
  REQUIRE(s.addExclusion(a).value() == id);                                          // the same filter again updates it
  auto all = s.listExclusions(false, 1000);
  REQUIRE(all.value().size() == 1);
  REQUIRE(all.value()[0].note == "changed note");
  REQUIRE(all.value()[0].expires_at == 5000);
  REQUIRE(s.listExclusions(true, 4999).value().size() == 1);
  REQUIRE(s.listExclusions(true, 5000).value().empty());                              // time is up
  REQUIRE(s.listExclusions(false, 5000).value().size() == 1);                         // still listed for the administrator

  Exclusion other = ex("user", "backup", "web01");                                   // another machine = another filter
  other.created_at = 100;
  REQUIRE(s.addExclusion(other).value() != id);

  // an open finding that a new filter covers is closed at once
  Finding f;
  f.fingerprint = "LOG-001|web01|k";
  f.rule_id = "LOG-001";
  f.title = "Login";
  f.severity = Severity::High;
  f.target = "web01";
  f.collector = "logs";
  f.obs_type = "log.auth.login";
  f.stable_key = "k";
  f.first_seen = f.last_seen = 200;
  f.evidence = {{"user", "backup"}, {"src_ip", "10.0.0.2"}};
  const int64_t fid = s.upsertFinding(f).value().id;
  Finding g = f;
  g.fingerprint = "LOG-001|web01|g";
  g.stable_key = "g";
  g.evidence = {{"user", "mario"}};
  const int64_t gid = s.upsertFinding(g).value().id;
  REQUIRE(s.resolveExcluded(ExclusionSet({a}), 300).value() == 1);
  REQUIRE(s.getFinding(fid).value()->status == "resolved");
  REQUIRE(s.getFinding(gid).value()->status == "open");

  REQUIRE(s.deleteExclusion(id).value());
  REQUIRE_FALSE(s.deleteExclusion(id).value());
}

TEST_CASE("analyzer: an excluded observation raises no finding and the old one resolves") {
  auto rules = loadRulesDir(DEFAULT_RULES_DIR);
  auto st = Store::open(":memory:");
  Store& store = *st.value();
  Analyzer an(store, rules.value(), std::chrono::seconds(100));
  const auto proc = [](const std::string& exe) {
    Observation o;
    o.type = "process";
    o.key = "20:1";
    o.data = {{"pid", 20}, {"ppid", 1}, {"comm", exe.substr(exe.rfind('/') + 1)}, {"uid", 0}, {"exe", exe}, {"exe_sha256", "h7"}, {"parent_exe", "/sbin/init"},
              {"kernel_thread", false}, {"cmdline", json::array()}};
    return o;
  };
  const auto snap = [&](int64_t ts, std::vector<Observation> obs) {
    Snapshot s;
    s.target = "t";
    s.collector = "processes";
    s.ts = ts;
    s.observations = std::move(obs);
    return s;
  };
  REQUIRE(an.analyze(snap(1000, {proc("/usr/sbin/sshd")})).value().learning);
  auto first = an.analyze(snap(1200, {proc("/srv/tools/backup-agent")}));
  REQUIRE_FALSE(first.value().fresh.empty());                                         // a new program: reported
  const int64_t id = first.value().fresh[0].id;

  Exclusion x = ex("process", "/srv/tools/backup-agent");
  x.created_at = 1250;
  REQUIRE(store.addExclusion(x).ok());
  auto again = an.analyze(snap(1300, {proc("/srv/tools/backup-agent")}));
  REQUIRE(again.ok());
  REQUIRE(again.value().fresh.empty());
  REQUIRE(again.value().repeats.empty());
  REQUIRE(again.value().excluded > 0);
  REQUIRE(again.value().resolved > 0);                                                // what was open is closed: it is not reproduced any more
  REQUIRE(store.getFinding(id).value()->status == "resolved");

  // an expired filter does not apply any more, and the finding comes back
  x.expires_at = 1301;
  REQUIRE(store.addExclusion(x).ok());
  auto late = an.analyze(snap(1400, {proc("/srv/tools/backup-agent")}));
  REQUIRE(late.value().excluded == 0);
  REQUIRE(store.getFinding(id).value()->status == "open");
}

TEST_CASE("total reset: everything goes, the filters can stay, a copy is saved first") {
  const std::string path = (std::filesystem::temp_directory_path() / "agent_reset_test.db").string();
  for (const auto& f : std::filesystem::directory_iterator(std::filesystem::temp_directory_path())) {
    if (f.path().filename().string().rfind("agent_reset_test.db", 0) == 0) std::filesystem::remove(f.path());
  }
  {
    auto st = Store::open(path);
    REQUIRE(st.ok());
    Store& s = *st.value();
    Finding f;
    f.fingerprint = "A-001|web01|k";
    f.rule_id = "A-001";
    f.title = "t";
    f.severity = Severity::High;
    f.target = "web01";
    f.collector = "processes";
    f.obs_type = "process";
    f.stable_key = "k";
    f.first_seen = f.last_seen = 10;
    REQUIRE(s.upsertFinding(f).ok());
    REQUIRE(s.addToBaseline("web01", {{"proc.exe", "/x"}}, 10).ok());
    REQUIRE(s.setMeta("digest_last", "5").ok());
    Exclusion x = ex("user", "backup");
    x.created_at = 10;
    REQUIRE(s.addExclusion(x).ok());

    const auto r = s.resetAll(true, 777);
    REQUIRE(r.ok());
    REQUIRE(r.value().rows_deleted >= 3);
    REQUIRE(r.value().backup_path == path + ".before-reset-777");
    REQUIRE(std::filesystem::exists(r.value().backup_path));
    REQUIRE(s.listFindings("", 10).value().empty());
    REQUIRE(s.baselineSize("web01").value() == 0);
    REQUIRE_FALSE(s.getMeta("digest_last").value().has_value());
    REQUIRE(s.listExclusions(false, 20).value().size() == 1);                        // kept on request

    // the copy still holds what was there
    auto copy = Store::open(r.value().backup_path);
    REQUIRE(copy.ok());
    REQUIRE(copy.value()->listFindings("", 10).value().size() == 1);

    REQUIRE(s.resetAll(false, 778).ok());
    REQUIRE(s.listExclusions(false, 20).value().empty());                            // and wiped when not
    // a clean database works as new
    REQUIRE(s.upsertFinding(f).value().is_new);
  }
  for (const auto& f : std::filesystem::directory_iterator(std::filesystem::temp_directory_path())) {
    if (f.path().filename().string().rfind("agent_reset_test.db", 0) == 0) std::filesystem::remove(f.path());
  }
}
