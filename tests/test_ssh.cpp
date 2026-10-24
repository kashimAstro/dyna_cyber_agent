#include <catch2/catch.hpp>

#include <sys/stat.h>
#include <unistd.h>

#include <chrono>
#include <cstdlib>
#include <fstream>

#include "core/base64.h"
#include "core/config.h"
#include "core/util.h"
#include "transport/command_policy.h"
#include "transport/gate.h"
#include "transport/ssh_transport.h"
#include "transport/ssh_validate.h"

using namespace agent;

// No test here opens a network connection. `ssh_binary` points to a script that behaves like ssh as far
// as the transport can tell (same argv, stdin/stdout streams) but runs the remote command locally.
namespace {

struct TmpDir {
  std::string path;
  TmpDir() {
    char tmpl[] = "/tmp/agent_ssh_test_XXXXXX";
    path = ::mkdtemp(tmpl);
  }
  ~TmpDir() { std::string cmd = "rm -rf '" + path + "'"; (void)!std::system(cmd.c_str()); }
  std::string file(const std::string& name) const { return path + "/" + name; }
  void write(const std::string& name, const std::string& content, bool exec = false) const {
    std::ofstream(file(name), std::ios::binary) << content;
    if (exec) ::chmod(file(name).c_str(), 0755);
  }
  std::string read(const std::string& name) const {
    std::ifstream f(file(name), std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(f), {});
  }
};

// Behaves like `ssh ... host command`: records its argv and executes the command locally.
const char* kFakeSsh = R"(#!/bin/sh
d=$(dirname "$0")
echo x >> "$d/invocations"
printf '%s\n' "$@" > "$d/args"
for last; do :; done
exec sh -c "$last"
)";

SshOptions opts(const TmpDir& t, const std::string& script = kFakeSsh) {
  t.write("ssh", script, true);
  SshOptions o;
  o.host = "target.example";
  o.user = "audit-ro";
  o.key_file = "/keys/id";
  o.ssh_binary = t.file("ssh");
  o.connect_timeout = std::chrono::seconds(2);
  o.op_timeout = std::chrono::seconds(20);
  return o;
}

size_t invocations(const TmpDir& t) { return util::split(t.read("invocations"), '\n').size() - 1; }

}  // namespace

TEST_CASE("ssh command line is locked down") {
  SshOptions o;
  o.host = "10.0.0.5";
  o.user = "audit-ro";
  o.key_file = "/etc/dyna_cyber_agent/keys/web01";
  o.known_hosts = "/etc/dyna_cyber_agent/known_hosts";
  o.proxy_jump = "ops@bastion:2222";
  o.port = 2200;
  const auto a = SshTransport::buildArgv(o);
  const std::string all = [&] { std::string s; for (const auto& x : a) s += x + "\n"; return s; }();
  for (const char* must : {"BatchMode=yes", "StrictHostKeyChecking=yes", "IdentitiesOnly=yes", "PasswordAuthentication=no", "ForwardAgent=no",
                           "ClearAllForwardings=yes", "ControlMaster=no", "UserKnownHostsFile=/etc/dyna_cyber_agent/known_hosts"}) {
    REQUIRE(all.find(must) != std::string::npos);
  }
  REQUIRE(a[0] == "/usr/bin/ssh");
  REQUIRE(a[1] == "-T");
  REQUIRE(a[a.size() - 3] == "--");            // host can never be parsed as an option
  REQUIRE(a[a.size() - 2] == "10.0.0.5");
  REQUIRE(all.find("-J\nops@bastion:2222") != std::string::npos);
  REQUIRE(all.find("-p\n2200") != std::string::npos);
  REQUIRE(all.find("-l\naudit-ro") != std::string::npos);
  REQUIRE(all.find("StrictHostKeyChecking=no") == std::string::npos);
  REQUIRE(all.find("accept-new") == std::string::npos);

  // stream mode: the gate script travels inside the command, base64 encoded
  const std::string cmd = SshTransport::remoteCommand(o);
  REQUIRE(cmd.rfind("exec sh -c \"$(printf %s '", 0) == 0);
  const size_t b = cmd.find("'") + 1, e = cmd.find("'", b);
  REQUIRE(base64Decode(cmd.substr(b, e - b)).value() == Gate::script());
  REQUIRE(cmd.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/= ,'\"$()%-", 0) != std::string::npos);  // sanity: it has spaces/quotes we added
  REQUIRE(cmd.substr(b, e - b).find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") == std::string::npos);

  o.gate_mode = "installed";
  o.gate_path = "/usr/local/bin/dyna_cyber_agent-gate";
  REQUIRE(SshTransport::remoteCommand(o) == "exec /usr/local/bin/dyna_cyber_agent-gate");
  o.sudo = true;
  REQUIRE(SshTransport::remoteCommand(o) == "exec sudo -n /usr/local/bin/dyna_cyber_agent-gate");
}

TEST_CASE("ssh values are validated, not just quoted") {
  REQUIRE(validSshHost("web01.example.com"));
  REQUIRE(validSshHost("10.0.0.5"));
  REQUIRE(validSshHost("fe80::1"));
  REQUIRE_FALSE(validSshHost("-oProxyCommand=evil"));
  REQUIRE_FALSE(validSshHost("host name"));
  REQUIRE_FALSE(validSshHost("host;reboot"));
  REQUIRE_FALSE(validSshHost("$(id)"));
  REQUIRE_FALSE(validSshHost(""));
  REQUIRE_FALSE(validSshUser("-l"));
  REQUIRE_FALSE(validSshUser("a b"));
  REQUIRE(validSshUser("audit-ro"));
  REQUIRE(validSshJump("ops@bastion:2222,ops@b2"));
  REQUIRE_FALSE(validSshJump("-oProxyCommand=x"));
  REQUIRE(validGatePath("/usr/local/bin/dyna_cyber_agent-gate"));
  REQUIRE_FALSE(validGatePath("relative/gate"));
  REQUIRE_FALSE(validGatePath("/usr/bin/../../tmp/x"));
  REQUIRE_FALSE(validGatePath("/tmp/x; rm -rf /"));
  REQUIRE_FALSE(validGatePath("/tmp/x y"));

  const std::string base = "targets:\n  - {name: a, transport: ssh, user: u, key: /k";
  auto cfg = [&](const std::string& extra) { return parseConfig(base + extra + "}\n").ok(); };
  REQUIRE(cfg(", host: h.example"));
  REQUIRE(cfg(", host: h.example, gate: installed, gate_path: /usr/local/bin/g, sudo: true, proxy_jump: 'o@b:22', connect_timeout: 5, op_timeout: 60"));
  REQUIRE_FALSE(cfg(", host: '-oProxyCommand=x'"));
  REQUIRE_FALSE(cfg(", host: 'h h'"));
  REQUIRE_FALSE(cfg(", host: h, gate: telepathy"));
  REQUIRE_FALSE(cfg(", host: h, gate: installed"));                          // needs gate_path
  REQUIRE_FALSE(cfg(", host: h, sudo: true"));                               // sudo needs the installed gate
  REQUIRE_FALSE(cfg(", host: h, gate: installed, gate_path: 'rel/g'"));
  REQUIRE_FALSE(cfg(", host: h, connect_timeout: 0"));
  REQUIRE_FALSE(cfg(", host: h, op_timeout: 1"));
  REQUIRE_FALSE(cfg(", host: h, ssh_binary: ssh"));                          // no PATH lookup
  REQUIRE_FALSE(cfg(", host: h, proxy_jump: '-J x'"));
  REQUIRE_FALSE(parseConfig("targets:\n  - {name: a, transport: ssh, host: h, user: u}\n").ok());  // key missing
}

TEST_CASE("the gate whitelist is consistent with the local policy") {
  const std::string script = Gate::script();
  REQUIRE(script.find("@@") == std::string::npos);
  for (const auto& c : Gate::commands()) {
    REQUIRE(c.find_first_of("\"'`$\\;&|<>(){}*?") == std::string::npos);  // safe to embed in a case pattern
    REQUIRE(script.find("\"" + c + "\"") != std::string::npos);
    REQUIRE(CommandPolicy::checkRules(util::splitWs(c)).ok());            // the gate never allows more than the agent
  }
}

TEST_CASE("gate protocol end to end (local fake ssh)") {
  TmpDir t;
  SshTransport tr(opts(t));
  auto host = tr.connect();
  REQUIRE(host.ok());
  REQUIRE_FALSE(host.value().empty());
  REQUIRE(t.read("args").find("StrictHostKeyChecking=yes") != std::string::npos);

  auto caps = tr.capabilities();
  REQUIRE(caps.ok());
  INFO(caps.value());
  REQUIRE(caps.value().find("base64=ok") != std::string::npos);
  REQUIRE(caps.value().find("find_printf=ok") != std::string::npos);
  REQUIRE(caps.value().find("stat_c=ok") != std::string::npos);
  REQUIRE(caps.value().find("MISSING") == std::string::npos);

  // reading
  auto st = tr.readFile("/proc/self/status", 1 << 20);
  REQUIRE(st.ok());
  REQUIRE(st.value().data.find("Name:") != std::string::npos);
  REQUIRE_FALSE(st.value().truncated);
  auto cut = tr.readFile("/proc/self/status", 10);
  REQUIRE(cut.ok());
  REQUIRE(cut.value().data.size() == 10);
  REQUIRE(cut.value().truncated);

  t.write("bin.dat", std::string("a\0b\xff\n\r", 6));
  auto bin = tr.readFile(t.file("bin.dat"), 100);
  REQUIRE(bin.ok());
  REQUIRE(bin.value().data == std::string("a\0b\xff\n\r", 6));  // binary safe

  REQUIRE_FALSE(tr.readFile("/nonexistent/file", 10).ok());
  REQUIRE_FALSE(tr.readFile("/etc", 10).ok());                   // directories are not files
  REQUIRE_FALSE(tr.readFile("relative", 10).ok());
  auto bad = tr.readFile("/etc/pass\nwd", 10);
  REQUIRE_FALSE(bad.ok());                                       // newline would break the line protocol

  // links, dirs, stat
  auto exe = tr.readLink("/proc/self/exe");
  REQUIRE(exe.ok());
  REQUIRE(exe.value().rfind("/", 0) == 0);  // an absolute path (the gate's own readlink binary)
  REQUIRE_FALSE(tr.readLink("/etc/passwd").ok());

  ::mkdir(t.file("d").c_str(), 0755);
  t.write("d/a b", "1");
  t.write("d/weird\nname", "2");
  REQUIRE(::symlink("/etc/passwd", t.file("d/link").c_str()) == 0);
  ::mkdir(t.file("d/sub").c_str(), 0755);
  auto ls = tr.listDir(t.file("d"));
  REQUIRE(ls.ok());
  REQUIRE(ls.value().size() == 4);
  for (const auto& e : ls.value()) {
    if (e.name == "sub") REQUIRE(e.is_dir);
    if (e.name == "link") REQUIRE(e.is_symlink);
  }
  bool weird = false, space = false;
  for (const auto& e : ls.value()) { weird |= e.name == "weird\nname"; space |= e.name == "a b"; }
  REQUIRE(weird);
  REQUIRE(space);
  REQUIRE_FALSE(tr.listDir("/nonexistent").ok());

  auto sl = tr.stat(t.file("d/link"));
  REQUIRE(sl.ok());
  REQUIRE(sl.value().is_symlink);
  auto sf = tr.stat("/etc/passwd");
  REQUIRE(sf.ok());
  REQUIRE_FALSE(sf.value().is_symlink);
  REQUIRE(sf.value().size > 0);
  REQUIRE(sf.value().mtime > 1000000000);
  REQUIRE_FALSE(tr.stat("/nonexistent").ok());

  // hashing
  t.write("abc", "abc");
  REQUIRE(tr.sha256File(t.file("abc"), 1024).value() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  auto too_big = tr.sha256File(t.file("abc"), 2);
  REQUIRE_FALSE(too_big.ok());
  REQUIRE(too_big.error().find("too large") != std::string::npos);

  // specialised ops
  const std::string me = "/proc/" + std::to_string(::getpid());
  auto res = tr.bulk({ReadOp::rwxMaps(me + "/maps"), ReadOp::rwxMaps("/etc/passwd"), ReadOp::socketInodes(me + "/fd"),
                      ReadOp::socketInodes("/etc"), ReadOp::rwxMaps("/proc/1/../self/maps"), ReadOp::rwxMaps("/proc/self/maps")});
  REQUIRE(res[0].ok);
  REQUIRE(res[0].count >= 0);
  REQUIRE_FALSE(res[1].ok);  // only /proc/<pid>/maps is accepted
  REQUIRE(res[2].ok);
  REQUIRE_FALSE(res[3].ok);
  REQUIRE_FALSE(res[4].ok);  // no path traversal tricks
  REQUIRE_FALSE(res[5].ok);  // only numeric pids

  REQUIRE(invocations(t) == 1);  // one ssh process served all of it
}

TEST_CASE("batches: many requests, one round trip, results in order") {
  TmpDir t;
  SshTransport tr(opts(t));
  std::vector<ReadOp> ops;
  for (int i = 0; i < 700; ++i) {  // > 2 frames of 256
    t.write("f" + std::to_string(i), "content-" + std::to_string(i));
    ops.push_back(i % 5 == 4 ? ReadOp::file("/nonexistent/" + std::to_string(i), 100) : ReadOp::file(t.file("f" + std::to_string(i)), 100));
  }
  const auto t0 = std::chrono::steady_clock::now();
  const auto res = tr.bulk(ops);
  const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
  REQUIRE(res.size() == 700);
  for (int i = 0; i < 700; ++i) {
    if (i % 5 == 4) REQUIRE_FALSE(res[static_cast<size_t>(i)].ok);
    else REQUIRE(res[static_cast<size_t>(i)].file.data == "content-" + std::to_string(i));
  }
  REQUIRE(ms < 15000);
  REQUIRE(invocations(t) == 1);

  // a full /proc scan like the collectors do
  auto dir = tr.listDir("/proc");
  REQUIRE(dir.ok());
  std::vector<ReadOp> scan;
  for (const auto& e : dir.value()) if (util::allDigits(e.name)) scan.push_back(ReadOp::file("/proc/" + e.name + "/stat", 4096));
  REQUIRE(scan.size() > 3);
  size_t good = 0;
  for (const auto& r : tr.bulk(scan)) good += r.ok;
  REQUIRE(good > 3);

  // large payloads cross the pipe buffers in both directions without blocking
  t.write("big", std::string(3u << 20, 'x'));
  auto big = tr.readFile(t.file("big"), 4u << 20);
  REQUIRE(big.ok());
  REQUIRE(big.value().data.size() == (3u << 20));
  std::vector<ReadOp> many;
  for (int i = 0; i < 40; ++i) many.push_back(ReadOp::file(t.file("big"), 1u << 20));
  for (const auto& r : tr.bulk(many)) REQUIRE(r.file.data.size() == (1u << 20));
}

TEST_CASE("run goes through the double whitelist") {
  TmpDir t;
  SshTransport tr(opts(t));
  auto r = tr.run({"uname", "-sr"});
  REQUIRE(r.ok());
  REQUIRE(r.value().exit_code == 0);
  REQUIRE(r.value().out.rfind("Linux", 0) == 0);

  auto idr = tr.run({"id"});
  REQUIRE(idr.ok());
  REQUIRE(idr.value().out.find("uid=") != std::string::npos);

  REQUIRE_FALSE(tr.run({"rm", "-rf", "/"}).ok());                   // not whitelisted at all
  REQUIRE_FALSE(tr.run({"ip", "addr", "add", "1.2.3.4/24", "dev", "lo"}).ok());  // refused by the local policy
  auto not_in_gate = tr.run({"ls", "/tmp"});                         // allowed locally, not by the gate
  REQUIRE_FALSE(not_in_gate.ok());
  REQUIRE(not_in_gate.error().find("not available over ssh") != std::string::npos);
  REQUIRE_FALSE(tr.run({"uname", "-a", ""}).ok());                   // empty argument

  // the gate itself refuses anything outside its list, even if a client skipped the local checks
  TmpDir t2;
  SshTransport raw(opts(t2));
  REQUIRE(raw.connect().ok());
  const auto script = Gate::script();
  REQUIRE(script.find("command not allowed by gate") != std::string::npos);
}

TEST_CASE("transport survives and reports a broken peer") {
  {  // wrong greeting
    TmpDir t;
    SshTransport tr(opts(t, "#!/bin/sh\necho x >> \"$(dirname \"$0\")/invocations\"\necho 'Welcome to a banner' \nsleep 5\n"));
    auto r = tr.connect();
    REQUIRE_FALSE(r.ok());
    REQUIRE(r.error().find("unexpected greeting") != std::string::npos);
  }
  {  // ssh itself fails (host key, auth...): its message reaches the log
    TmpDir t;
    SshTransport tr(opts(t, "#!/bin/sh\necho x >> \"$(dirname \"$0\")/invocations\"\necho 'Host key verification failed.' >&2\nexit 255\n"));
    auto r = tr.readFile("/etc/hostname", 10);
    REQUIRE_FALSE(r.ok());
    INFO(r.error());
    REQUIRE(r.error().find("Host key verification failed") != std::string::npos);
    // no reconnect storm: the next calls fail fast without spawning ssh again
    REQUIRE_FALSE(tr.readFile("/etc/hostname", 10).ok());
    REQUIRE_FALSE(tr.listDir("/proc").ok());
    REQUIRE(invocations(t) == 1);
  }
  {  // peer never answers
    TmpDir t;
    SshTransport tr(opts(t, "#!/bin/sh\nsleep 30\n"));
    const auto t0 = std::chrono::steady_clock::now();
    auto r = tr.connect();
    REQUIRE_FALSE(r.ok());
    REQUIRE(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(8));
    REQUIRE(r.error().find("timeout") != std::string::npos);
  }
  {  // peer dies mid-session: every op of the batch fails, none is invented
    TmpDir t;
    SshTransport tr(opts(t, "#!/bin/sh\necho 'AGENT-GATE 2 h'\nread l\nexit 0\n"));
    REQUIRE(tr.connect().ok());
    const auto res = tr.bulk({ReadOp::file("/etc/passwd", 10), ReadOp::stat("/etc")});
    REQUIRE(res.size() == 2);
    for (const auto& r : res) {
      REQUIRE_FALSE(r.ok);
      REQUIRE(r.error.find("closed") != std::string::npos);
    }
  }
  {  // a gate that returns garbage for a request
    TmpDir t;
    SshTransport tr(opts(t, "#!/bin/sh\necho 'AGENT-GATE 2 h'\nread l\necho 'OK !!!not-base64!!!'\nsleep 5\n"));
    const auto res = tr.bulk({ReadOp::file("/etc/passwd", 10)});
    REQUIRE_FALSE(res[0].ok);
  }
  {  // invalid options never reach exec
    TmpDir t;
    SshOptions o = opts(t);
    o.host = "-oProxyCommand=touch /tmp/pwned";
    SshTransport tr(o);
    REQUIRE_FALSE(tr.readFile("/etc/passwd", 10).ok());
    REQUIRE(::access(t.file("invocations").c_str(), F_OK) != 0);  // ssh was never started
  }
}

#include <set>

#include "collectors/collector.h"
#include "transport/local_transport.h"

TEST_CASE("collectors give the same picture over the gate as locally") {
  TmpDir t;
  SshTransport remote(opts(t));
  LocalTransport local;

  auto keys = [](const CollectOutput& o, const std::string& type) {
    std::set<std::string> s;
    for (const auto& ob : o.observations) if (ob.type == type) s.insert(ob.key);
    return s;
  };

  // users: fully deterministic, must be identical
  auto u_local = makeCollector("users")->collect(local);
  auto u_remote = makeCollector("users")->collect(remote);
  REQUIRE(u_local.ok());
  REQUIRE(u_remote.ok());
  for (const char* type : {"user", "group", "authorized_key", "sudoers_line"}) REQUIRE(keys(u_local.value(), type) == keys(u_remote.value(), type));

  // network: the same listening sockets
  auto n_local = makeCollector("network")->collect(local);
  auto n_remote = makeCollector("network")->collect(remote);
  REQUIRE(n_local.ok());
  REQUIRE(n_remote.ok());
  auto listening = [](const CollectOutput& o) {
    std::set<std::string> s;
    for (const auto& ob : o.observations) {
      if (ob.type != "socket.inet" || std::find(ob.tags.begin(), ob.tags.end(), "listening") == ob.tags.end()) continue;
      s.insert(ob.data["proto"].get<std::string>() + ob.data["local_addr"].get<std::string>() + ":" + std::to_string(ob.data["local_port"].get<int>()));
    }
    return s;
  };
  REQUIRE_FALSE(listening(n_local.value()).empty());
  REQUIRE(listening(n_local.value()) == listening(n_remote.value()));

  // processes: same set of running programs (short-lived helpers of the transport itself aside)
  auto p_local = makeCollector("processes")->collect(local);
  auto p_remote = makeCollector("processes")->collect(remote);
  REQUIRE(p_local.ok());
  REQUIRE(p_remote.ok());
  auto exes = [](const CollectOutput& o) {
    std::set<std::string> s;
    for (const auto& ob : o.observations) if (ob.data["exe"].is_string() && ob.data["exe_sha256"].is_string()) s.insert(ob.data["exe"].get<std::string>() + "|" + ob.data["exe_sha256"].get<std::string>());
    return s;
  };
  const auto el = exes(p_local.value()), er = exes(p_remote.value());
  REQUIRE(el.size() > 3);
  size_t common = 0;
  for (const auto& e : el) common += er.count(e);
  REQUIRE(common * 10 >= el.size() * 9);  // >= 90% identical (path AND hash)
  REQUIRE(invocations(t) == 1);
}

#include <sys/stat.h>

#include "transport/scan_presets.h"

TEST_CASE("scan output and journal output parsers") {
  const std::string nul(1, '\0');
  const std::string raw = "f\t4755\troot\troot\t1234\t1700000000.5\t/usr/bin/su" + nul + "l\t777\tbob\tbob\t4\t1700000001.0\t/tmp/a\tb c" + nul +
                          "garbage" + nul + "f\tzz\troot\troot\t1\t1.0\t/x" + nul;
  const auto e = parseScanOutput(raw);
  REQUIRE(e.size() == 2);
  REQUIRE(e[0].type == 'f');
  REQUIRE(e[0].mode == 04755);
  REQUIRE(e[0].user == "root");
  REQUIRE(e[0].size == 1234);
  REQUIRE(e[0].mtime == 1700000000);
  REQUIRE(e[0].path == "/usr/bin/su");
  REQUIRE(e[1].path == "/tmp/a\tb c");  // the path is the last field and may contain tabs

  const auto j = parseJournalOutput("2026-10-22T10:00:00+0000 h sshd[1]: hi\n2026-10-22T10:00:01+0000 h x: y\n-- cursor: s=abc;i=1;b=2\n");
  REQUIRE(j.cursor == "s=abc;i=1;b=2");
  REQUIRE(j.text == "2026-10-22T10:00:00+0000 h sshd[1]: hi\n2026-10-22T10:00:01+0000 h x: y\n");
  REQUIRE(parseJournalOutput("no cursor here\n").cursor.empty());

  REQUIRE(shellQuote("a b") == "'a b'");
  REQUIRE(shellQuote("it's") == "'it'\\''s'");
  REQUIRE(validJournalCursor("s=0123abc;i=12;b=ff;m=3;t=4;x=5"));
  REQUIRE_FALSE(validJournalCursor("x; rm -rf /"));
  REQUIRE_FALSE(validJournalCursor("$(id)"));
  REQUIRE_FALSE(validJournalCursor(std::string(400, 'a')));
  REQUIRE(findScanPreset("suid") != nullptr);
  REQUIRE(findScanPreset("evil") == nullptr);
}

TEST_CASE("tail, scan and journal: local and gate agree") {
  TmpDir t;
  SshTransport remote(opts(t));
  LocalTransport local;

  // ---- tail
  t.write("log", "line1\nline2\nline3\n");
  for (auto* tr : std::initializer_list<ITransport*>{&local, &remote}) {
    auto all = tr->tailFile(t.file("log"), 0, 1000);
    INFO(tr->name() << ": " << (all.ok() ? "" : all.error()));
    REQUIRE(all.ok());
    REQUIRE(all.value().data == "line1\nline2\nline3\n");
    REQUIRE(all.value().size == 18);
    REQUIRE(all.value().inode > 0);
    auto part = tr->tailFile(t.file("log"), 6, 5);
    REQUIRE(part.ok());
    REQUIRE(part.value().data == "line2");
    auto end = tr->tailFile(t.file("log"), 18, 100);
    REQUIRE(end.ok());
    REQUIRE(end.value().data.empty());
    REQUIRE(end.value().size == 18);
    auto past = tr->tailFile(t.file("log"), 999, 100);
    REQUIRE(past.ok());
    REQUIRE(past.value().data.empty());
    REQUIRE_FALSE(tr->tailFile("/nonexistent/log", 0, 10).ok());
    REQUIRE_FALSE(tr->tailFile("/etc", 0, 10).ok());
  }
  REQUIRE(local.tailFile(t.file("log"), 0, 10).value().inode == remote.tailFile(t.file("log"), 0, 10).value().inode);
  t.write("bin", std::string("a\0b\n\xff", 5));
  REQUIRE(remote.tailFile(t.file("bin"), 0, 100).value().data == std::string("a\0b\n\xff", 5));  // binary safe
  // rotation as logrotate does it (rename, then a new file): the inode changes
  const auto ino_before = remote.tailFile(t.file("log"), 0, 1).value().inode;
  REQUIRE(::rename(t.file("log").c_str(), t.file("log.1").c_str()) == 0);
  t.write("log", "fresh\n");
  REQUIRE(remote.tailFile(t.file("log"), 0, 100).value().inode != ino_before);

  // ---- scan 'volatile' sees what is lying around in /tmp
  t.write("run.sh", "#!/bin/sh\n", true);
  t.write(".hidden", "x");
  REQUIRE(::symlink("/etc/passwd", t.file("lnk").c_str()) == 0);
  REQUIRE(::mkfifo(t.file("fifo").c_str(), 0600) == 0);
  auto mine = [&](const std::vector<ScanEntry>& v) {
    std::map<std::string, ScanEntry> m;
    for (const auto& e : v) if (e.path.rfind(t.path, 0) == 0) m[e.path] = e;
    return m;
  };
  auto sl = local.scan("volatile");
  auto sr = remote.scan("volatile");
  REQUIRE(sl.ok());
  REQUIRE(sr.ok());
  const auto ml = mine(sl.value()), mr = mine(sr.value());
  REQUIRE(ml.size() >= 6);
  REQUIRE(ml.count(t.file("run.sh")) == 1);
  REQUIRE(ml.at(t.file("run.sh")).mode == 0755);
  REQUIRE(ml.at(t.file("lnk")).type == 'l');
  REQUIRE(ml.at(t.file("fifo")).type == 'p');
  REQUIRE(ml.count(t.file(".hidden")) == 1);
  REQUIRE(ml.size() == mr.size());
  for (const auto& [path, e] : ml) {
    REQUIRE(mr.count(path) == 1);
    REQUIRE(mr.at(path).type == e.type);
    REQUIRE(mr.at(path).mode == e.mode);
    REQUIRE(mr.at(path).size == e.size);
    REQUIRE(mr.at(path).user == e.user);
  }
  REQUIRE_FALSE(local.scan("nope").ok());
  REQUIRE_FALSE(remote.scan("nope").ok());
  // ---- journal (only when this machine lets us read it)
  REQUIRE_FALSE(local.journal("nope", "", 5).ok());
  REQUIRE_FALSE(local.journal("sys", "x; rm -rf /", 5).ok());
  REQUIRE_FALSE(remote.journal("sys", "$(id)", 5).ok());
  REQUIRE_FALSE(remote.journal("sys", "x y", 5).ok());
  auto jl = local.journal("sys", "", 5);
  if (jl.ok()) {
    auto jr = remote.journal("sys", "", 5);
    REQUIRE(jr.ok());
    REQUIRE_FALSE(jr.value().cursor.empty());
    REQUIRE(jr.value().text.find("-- cursor") == std::string::npos);
    auto again = remote.journal("sys", jr.value().cursor, 5);
    REQUIRE(again.ok());  // continuing from a cursor works (and may be empty)
    REQUIRE(remote.journal("kernel", "", 3).ok());
  } else {
    INFO("journal not readable here: " << jl.error());
  }
  REQUIRE(invocations(t) == 1);
}

// Walks the whole filesystem (slow): run with `agent_tests "[.slow]"`.
TEST_CASE("suid scan over the gate walks the real filesystem", "[.slow]") {
  TmpDir t;
  SshTransport remote(opts(t));
  auto suid = remote.scan("suid");
  REQUIRE(suid.ok());
  REQUIRE_FALSE(suid.value().empty());
  for (const auto& e : suid.value()) REQUIRE((e.mode & 06000) != 0);
}
