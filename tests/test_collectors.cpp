#include <catch2/catch.hpp>

#include "collectors/network_collector.h"
#include "collectors/process_collector.h"
#include "collectors/user_collector.h"
#include "fake_transport.h"

using namespace agent;

namespace {
const Observation* find(const CollectOutput& o, const std::string& type, const std::string& key_part) {
  for (const auto& ob : o.observations) if (ob.type == type && ob.key.find(key_part) != std::string::npos) return &ob;
  return nullptr;
}
bool has(const Observation* o, const std::string& tag) {
  return o && std::find(o->tags.begin(), o->tags.end(), tag) != o->tags.end();
}
}  // namespace

TEST_CASE("parseProcStat handles hostile comm names") {
  auto s = parseProcStat("42 (we) ird) (name) S 7 42 42 0 -1 4194304 1 0 0 0 1 2 0 0 20 0 1 0 12345 100 200 18446744073709551615");
  REQUIRE(s);
  REQUIRE(s->comm == "we) ird) (name");
  REQUIRE(s->state == 'S');
  REQUIRE(s->ppid == 7);
  REQUIRE(s->start_ticks == 12345);
  REQUIRE_FALSE(parseProcStat("garbage"));
  REQUIRE_FALSE(parseProcStat("1 (x) S 1"));
}

TEST_CASE("process helpers") {
  REQUIRE(parseProcStatus("Name:\tbash\nUid:\t1000\t1000\t1000\t1000\nGid:\t100\t100\t100\t100\n").uid == 1000);
  REQUIRE(splitCmdline(std::string("a\0b c\0", 6)) == std::vector<std::string>{"a", "b c"});
  REQUIRE(countRwxMappings("00400000-00401000 r-xp 0 0 0 /bin/x\n7f00-7f10 rwxp 0 0 0\n7f20-7f30 rw-p 0 0 0\n") == 1);
}

TEST_CASE("process tags") {
  using O = std::optional<std::string>;
  REQUIRE(processTags("sshd", O("/usr/sbin/sshd"), false, 0).empty());
  REQUIRE(processTags("x", O("/tmp/x"), false, 0) == std::vector<std::string>{"exe_in_volatile_dir"});
  auto t = processTags("nginx", O("/usr/sbin/nginx (deleted)"), false, 2);
  REQUIRE(t.size() == 2);
  REQUIRE(processTags("a", O("/memfd:a (deleted)"), false, 0).size() >= 2);
  REQUIRE(processTags("apache2", O("/usr/bin/python3"), false, 0) == std::vector<std::string>{"comm_mismatch"});
  REQUIRE(processTags("kworker/0:1", std::nullopt, true, 0).empty());
  // comm is cut at 15 chars by the kernel
  REQUIRE(processTags("systemd-resolve", O("/lib/systemd/systemd-resolved"), false, 0).empty());
}

TEST_CASE("ProcessCollector against a fake /proc") {
  FakeTransport t;
  t.files["/proc/stat"] = "cpu 1 2 3\nbtime 1700000000\n";
  t.dirs["/proc"] = {"1", "2", "666", "self", "net"};
  auto stat = [](const char* pid, const char* comm, int ppid) {
    return std::string(pid) + " (" + comm + ") S " + std::to_string(ppid) + " 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 500 0 0";
  };
  t.files["/proc/1/stat"] = stat("1", "systemd", 0);
  t.files["/proc/1/status"] = "Name:\tsystemd\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n";
  t.links["/proc/1/exe"] = "/usr/lib/systemd/systemd";
  t.files["/proc/1/cmdline"] = std::string("/sbin/init\0", 11);
  t.files["/proc/1/maps"] = "0-1 r-xp 0 0 0 x\n";
  t.files["/proc/2/stat"] = stat("2", "kthreadd", 0);
  t.files["/proc/666/stat"] = stat("666", "updater", 1);
  t.files["/proc/666/status"] = "Name:\tupdater\nUid:\t33\t33\t33\t33\n";
  t.links["/proc/666/exe"] = "/dev/shm/.x (deleted)";
  t.files["/proc/666/maps"] = "0-1 rwxp 0 0 0\n";

  ProcessCollector c;
  auto r = c.collect(t);
  REQUIRE(r.ok());
  REQUIRE(r.value().observations.size() == 3);
  const auto* sys = find(r.value(), "process", "1:500");
  REQUIRE(sys);
  REQUIRE(sys->tags.empty());
  REQUIRE(sys->data["start_time"] == 1700000005);
  const auto* bad = find(r.value(), "process", "666:");
  REQUIRE(has(bad, "exe_deleted"));
  REQUIRE(has(bad, "exe_in_volatile_dir"));
  REQUIRE(has(bad, "rwx_memory"));
  REQUIRE(bad->data["uid"] == 33);
  REQUIRE(find(r.value(), "process", "2:")->data["kernel_thread"] == true);
}

TEST_CASE("network address decoding") {
  REQUIRE(decodeAddr("0100007F", false) == "127.0.0.1");
  REQUIRE(decodeAddr("00000000", false) == "0.0.0.0");
  REQUIRE(decodeAddr("00000000000000000000000001000000", true) == "::1");
  REQUIRE(decodeAddr("0000000000000000FFFF00000100007F", true) == "::ffff:127.0.0.1");
  REQUIRE_FALSE(decodeAddr("zz", false));
  REQUIRE_FALSE(decodeAddr("0100007F", true));
}

TEST_CASE("inet/unix/packet table parsing") {
  const std::string tcp =
      "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
      "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1111 1 0 100 0 0 10 0\n"
      "   1: 0100007F:1F90 0100007F:D2A4 01 00000000:00000000 00:00000000 00000000  1000        0 2222 1 0 100 0 0 10 0\n"
      "   2: broken line\n";
  auto s = parseInetTable(tcp, false, true);
  REQUIRE(s.size() == 2);
  REQUIRE(s[0].state == "LISTEN");
  REQUIRE(s[0].local_port == 22);
  REQUIRE(s[1].local_port == 8080);
  REQUIRE(s[1].state == "ESTABLISHED");
  REQUIRE(s[1].uid == 1000);

  const std::string un =
      "Num       RefCount Protocol Flags    Type St Inode Path\n"
      "0000: 00000002 00000000 00010000 0001 01 3333 /run/x.sock\n"
      "0000: 00000003 00000000 00000000 0001 03 4444\n"
      "0000: 00000002 00000000 00010000 0001 01 5555 @abstract\n";
  size_t unnamed = 0;
  auto u = parseUnixTable(un, &unnamed);
  REQUIRE(u.size() == 2);
  REQUIRE(unnamed == 1);
  REQUIRE(u[0].listening);

  auto p = parsePacketTable("sk RefCnt Type Proto Iface R Rmem User Inode\nffff 3 3 0003 2 1 0 0 6666\n");
  REQUIRE(p.size() == 1);
  REQUIRE(p[0].inode == 6666);
}

TEST_CASE("NetworkCollector ties sockets to processes and tags exposure") {
  FakeTransport t;
  t.dirs["/proc"] = {"10"};
  t.dirs["/proc/10/fd"] = {"0", "3"};
  t.links["/proc/10/fd/0"] = "/dev/null";
  t.links["/proc/10/fd/3"] = "socket:[1111]";
  t.files["/proc/10/comm"] = "sshd\n";
  t.files["/proc/net/tcp"] =
      "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
      "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1111 1 0\n"
      "   1: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2222 1 0\n";
  t.files["/proc/net/packet"] = "sk RefCnt Type Proto Iface R Rmem User Inode\nffff 3 3 0003 2 1 0 0 7777\n";
  NetworkCollector c;
  auto r = c.collect(t);
  REQUIRE(r.ok());
  const auto* ssh = find(r.value(), "socket.inet", "|0.0.0.0:22|");
  REQUIRE(has(ssh, "listening"));
  REQUIRE(has(ssh, "exposed"));
  REQUIRE(ssh->data["owners"][0]["comm"] == "sshd");
  const auto* local = find(r.value(), "socket.inet", "|127.0.0.1:53|");
  REQUIRE(has(local, "listening"));
  REQUIRE_FALSE(has(local, "exposed"));
  REQUIRE(has(find(r.value(), "socket.packet", "7777"), "packet_socket"));

  FakeTransport empty;
  REQUIRE_FALSE(NetworkCollector().collect(empty).ok());
}

TEST_CASE("user parsing") {
  auto pw = parsePasswd("root:x:0:0:root:/root:/bin/bash\n# c\nbad\nwww:x:33:33::/var/www:/usr/sbin/nologin\n");
  REQUIRE(pw.size() == 2);
  REQUIRE(isLoginShell(pw[0].shell));
  REQUIRE_FALSE(isLoginShell(pw[1].shell));
  REQUIRE(passwordState("") == "empty");
  REQUIRE(passwordState("!") == "locked");
  REQUIRE(passwordState("*") == "locked");
  REQUIRE(passwordState("$6$abc") == "set");

  auto keys = parseAuthorizedKeys(
      "# comment\n"
      "ssh-ed25519 AAAAC3 alice@pc\n"
      "command=\"/bin/echo hi there\",no-pty ssh-rsa BBBB bob laptop\n"
      "garbage line\n");
  REQUIRE(keys.size() == 2);
  REQUIRE(keys[0].comment == "alice@pc");
  REQUIRE(keys[1].options == "command=\"/bin/echo hi there\",no-pty");
  REQUIRE(keys[1].type == "ssh-rsa");
  REQUIRE(keys[1].comment == "bob laptop");
}

TEST_CASE("UserCollector never stores password hashes") {
  FakeTransport t;
  t.files["/etc/passwd"] = "root:x:0:0::/root:/bin/bash\ntoor:x:0:0::/home/toor:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/bash\n";
  t.files["/etc/shadow"] = "root:$6$SECRETHASH:19000:0:99999:7:::\ntoor::19000::::::\nalice:!:19000::::::\n";
  t.files["/etc/group"] = "sudo:x:27:alice\nusers:x:100:\n";
  t.files["/home/alice/.ssh/authorized_keys"] = "ssh-ed25519 AAAA alice@pc\n";
  t.files["/etc/sudoers"] = "# x\nDefaults env_reset\nalice ALL=(ALL) NOPASSWD: ALL\n";
  t.dirs["/etc/sudoers.d"] = {};
  UserCollector c;
  auto r = c.collect(t);
  REQUIRE(r.ok());
  for (const auto& o : r.value().observations) REQUIRE(o.data.dump().find("SECRETHASH") == std::string::npos);
  REQUIRE(has(find(r.value(), "user", "toor"), "uid0_not_root"));
  REQUIRE(has(find(r.value(), "user", "toor"), "empty_password"));
  REQUIRE(find(r.value(), "user", "alice")->data["privileged_groups"][0] == "sudo");
  REQUIRE(find(r.value(), "authorized_key", "alice|ssh-ed25519"));
  REQUIRE(has(find(r.value(), "sudoers_line", "NOPASSWD"), "nopasswd"));
}
