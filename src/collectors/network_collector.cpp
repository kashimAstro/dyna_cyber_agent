#include "collectors/network_collector.h"

#include <arpa/inet.h>

#include <cstring>

#include "core/util.h"

namespace agent {
namespace {

const char* tcpState(unsigned s) {
  static const char* names[] = {"?",        "ESTABLISHED", "SYN_SENT",  "SYN_RECV", "FIN_WAIT1", "FIN_WAIT2",
                                "TIME_WAIT", "CLOSE",       "CLOSE_WAIT", "LAST_ACK", "LISTEN",    "CLOSING"};
  return s < sizeof(names) / sizeof(names[0]) ? names[s] : "?";
}

const char* unixType(unsigned t) {
  switch (t) {
    case 1: return "stream";
    case 2: return "dgram";
    case 5: return "seqpacket";
    default: return "other";
  }
}

bool isLoopback(const std::string& a) { return a == "127.0.0.1" || a == "::1" || util::startsWith(a, "127."); }

struct Owner {
  int64_t pid = 0;
  std::string comm, exe;
};
using Owners = std::map<uint64_t, std::vector<Owner>>;  // inode -> processes holding the socket

nlohmann::json ownersJson(const Owners& owners, uint64_t inode) {
  nlohmann::json arr = nlohmann::json::array();
  const auto it = owners.find(inode);
  if (it == owners.end()) return arr;
  for (size_t i = 0; i < it->second.size() && i < 4; ++i) {
    nlohmann::json o = {{"pid", it->second[i].pid}, {"comm", it->second[i].comm}};
    if (!it->second[i].exe.empty()) o["exe"] = it->second[i].exe;  // which package a listening service belongs to, and what a connection runs from
    arr.push_back(std::move(o));
  }
  return arr;
}

// Maps socket inodes to the processes holding them. Needs privileges for other users' fds.
// Two batches: socket inodes per pid, then the process name of those that hold sockets.
Owners buildOwners(ITransport& t, std::vector<std::string>& warnings) {
  Owners owners;
  auto dir = t.listDir("/proc");
  if (!dir) return owners;
  std::vector<std::string> pids;
  for (const auto& e : dir.value()) if (util::allDigits(e.name)) pids.push_back(e.name);

  std::vector<ReadOp> ops;
  for (const auto& pid : pids) ops.push_back(ReadOp::socketInodes("/proc/" + pid + "/fd"));
  const auto res = t.bulk(ops);

  int denied = 0;
  std::vector<size_t> with_sockets;
  for (size_t i = 0; i < pids.size(); ++i) {
    if (!res[i].ok) ++denied;
    else if (!res[i].inodes.empty()) with_sockets.push_back(i);
  }

  std::vector<ReadOp> comm_ops;
  for (size_t i : with_sockets) {
    comm_ops.push_back(ReadOp::file("/proc/" + pids[i] + "/comm", 64));
    comm_ops.push_back(ReadOp::link("/proc/" + pids[i] + "/exe"));
  }
  const auto comm_res = t.bulk(comm_ops);
  for (size_t k = 0; k < with_sockets.size(); ++k) {
    const size_t i = with_sockets[k];
    const int64_t pid = static_cast<int64_t>(util::parseUint(pids[i]).value_or(0));
    const std::string comm = comm_res[k * 2].ok ? util::toValidUtf8(std::string(util::trim(comm_res[k * 2].file.data))) : std::string();
    const std::string exe = comm_res[k * 2 + 1].ok ? util::toValidUtf8(comm_res[k * 2 + 1].text) : std::string();
    for (uint64_t inode : res[i].inodes) {
      auto& v = owners[inode];
      if (v.empty() || v.back().pid != pid) v.push_back({pid, comm, exe});
    }
  }
  if (denied) warnings.push_back(std::to_string(denied) + " process(es): fd table not readable, socket owners may be missing");
  return owners;
}

}  // namespace

std::optional<std::string> decodeAddr(const std::string& hex, bool v6) {
  if (!v6) {
    const auto v = hex.size() == 8 ? util::parseUint(hex, 16) : std::nullopt;
    if (!v) return std::nullopt;
    // The kernel prints the raw network-order bytes as a host-order u32.
    in_addr a;
    a.s_addr = static_cast<uint32_t>(*v);
    char buf[INET_ADDRSTRLEN];
    return inet_ntop(AF_INET, &a, buf, sizeof(buf)) ? std::optional<std::string>(buf) : std::nullopt;
  }
  if (hex.size() != 32) return std::nullopt;
  in6_addr a;
  for (size_t w = 0; w < 4; ++w) {
    const auto v = util::parseUint(hex.substr(w * 8, 8), 16);
    if (!v) return std::nullopt;
    const auto word = static_cast<uint32_t>(*v);
    std::memcpy(a.s6_addr + w * 4, &word, 4);
  }
  char buf[INET6_ADDRSTRLEN];
  return inet_ntop(AF_INET6, &a, buf, sizeof(buf)) ? std::optional<std::string>(buf) : std::nullopt;
}

std::vector<InetSocket> parseInetTable(const std::string& text, bool v6, bool tcp) {
  std::vector<InetSocket> out;
  bool header = true;
  for (const auto& line : util::split(text, '\n')) {
    if (header) {
      header = false;
      continue;
    }
    const auto f = util::splitWs(line);
    if (f.size() < 10) continue;
    const auto lp = util::split(f[1], ':'), rp = util::split(f[2], ':');
    if (lp.size() != 2 || rp.size() != 2) continue;
    const auto la = decodeAddr(lp[0], v6), ra = decodeAddr(rp[0], v6);
    const auto lport = util::parseUint(lp[1], 16), rport = util::parseUint(rp[1], 16);
    const auto st = util::parseUint(f[3], 16), uid = util::parseUint(f[7]), inode = util::parseUint(f[9]);
    if (!la || !ra || !lport || !rport || !st || !uid || !inode) continue;
    InetSocket s;
    s.local_addr = *la;
    s.remote_addr = *ra;
    s.local_port = static_cast<unsigned>(*lport);
    s.remote_port = static_cast<unsigned>(*rport);
    s.state = tcp ? tcpState(static_cast<unsigned>(*st)) : (*st == 1 ? "ESTABLISHED" : "UNCONN");
    s.uid = *uid;
    s.inode = *inode;
    out.push_back(std::move(s));
  }
  return out;
}

std::vector<UnixSocket> parseUnixTable(const std::string& text, size_t* unnamed) {
  std::vector<UnixSocket> out;
  if (unnamed) *unnamed = 0;
  bool header = true;
  for (const auto& line : util::split(text, '\n')) {
    if (header) {
      header = false;
      continue;
    }
    const auto f = util::splitWs(line);
    if (f.size() < 7) continue;
    const auto flags = util::parseUint(f[3], 16), type = util::parseUint(f[4], 16), inode = util::parseUint(f[6]);
    if (!flags || !type || !inode) continue;
    UnixSocket s;
    s.type = unixType(static_cast<unsigned>(*type));
    s.listening = (*flags & 0x10000) != 0;  // __SO_ACCEPTCON
    s.inode = *inode;
    if (f.size() >= 8) s.path = util::toValidUtf8(f[7]);
    if (s.path.empty() && !s.listening) {
      if (unnamed) ++*unnamed;  // anonymous connected pair: not interesting individually
      continue;
    }
    out.push_back(std::move(s));
  }
  return out;
}

std::vector<PacketSocket> parsePacketTable(const std::string& text) {
  std::vector<PacketSocket> out;
  bool header = true;
  for (const auto& line : util::split(text, '\n')) {
    if (header) {
      header = false;
      continue;
    }
    const auto f = util::splitWs(line);
    if (f.size() < 9) continue;
    const auto uid = util::parseUint(f[7]), inode = util::parseUint(f[8]);
    if (!uid || !inode) continue;
    PacketSocket s;
    s.type = f[2];
    s.proto = f[3];
    s.uid = *uid;
    s.inode = *inode;
    out.push_back(std::move(s));
  }
  return out;
}

Result<CollectOutput> NetworkCollector::collect(ITransport& t) {
  CollectOutput out;
  const Owners owners = buildOwners(t, out.warnings);
  bool any_table = false;

  struct Table { const char* file; const char* proto; bool v6; bool tcp; };
  static const Table tables[] = {{"/proc/net/tcp", "tcp", false, true},   {"/proc/net/tcp6", "tcp6", true, true},
                                 {"/proc/net/udp", "udp", false, false},  {"/proc/net/udp6", "udp6", true, false},
                                 {"/proc/net/raw", "raw", false, false},  {"/proc/net/raw6", "raw6", true, false}};
  constexpr size_t kTables = sizeof(tables) / sizeof(tables[0]);

  // One batch for every kernel table (inet, unix, packet).
  std::vector<ReadOp> ops;
  for (const auto& tb : tables) ops.push_back(ReadOp::file(tb.file, 16 << 20));
  ops.push_back(ReadOp::file("/proc/net/unix", 16 << 20));
  ops.push_back(ReadOp::file("/proc/net/packet", 4 << 20));
  const auto res = t.bulk(ops);

  for (size_t ti = 0; ti < kTables; ++ti) {
    const auto& tb = tables[ti];
    const OpResult& f = res[ti];
    if (!f.ok) {
      if (tb.proto == std::string("tcp")) return err("cannot read " + std::string(tb.file) + ": " + f.error);
      continue;  // ipv6 disabled, etc.
    }
    any_table = true;
    const bool is_raw = util::startsWith(tb.proto, "raw");
    for (const auto& s : parseInetTable(f.file.data, tb.v6, tb.tcp)) {
      Observation o;
      o.type = "socket.inet";
      o.key = std::string(tb.proto) + "|" + s.local_addr + ":" + std::to_string(s.local_port) + "|" + s.remote_addr + ":" +
              std::to_string(s.remote_port) + "|" + std::to_string(s.inode);
      const bool listening = tb.tcp ? s.state == "LISTEN" : (!is_raw && s.remote_port == 0);
      if (listening) {
        o.tags.push_back("listening");
        if (!isLoopback(s.local_addr)) o.tags.push_back("exposed");
      }
      if (is_raw) o.tags.push_back("raw_socket");
      o.data = {{"proto", tb.proto},       {"local_addr", s.local_addr}, {"local_port", s.local_port},
                {"remote_addr", s.remote_addr}, {"remote_port", s.remote_port}, {"state", s.state},
                {"uid", s.uid},            {"inode", s.inode},            {"owners", ownersJson(owners, s.inode)}};
      out.observations.push_back(std::move(o));
    }
  }

  const OpResult& unix_res = res[kTables];
  const OpResult& packet_res = res[kTables + 1];
  if (unix_res.ok) {
    any_table = true;
    size_t unnamed = 0;
    for (const auto& s : parseUnixTable(unix_res.file.data, &unnamed)) {
      Observation o;
      o.type = "socket.unix";
      o.key = "unix|" + s.path + "|" + std::to_string(s.inode);
      if (s.listening) o.tags.push_back("listening");
      if (util::startsWith(s.path, "@")) o.tags.push_back("abstract");
      if (util::startsWith(s.path, "/tmp/") || util::startsWith(s.path, "/var/tmp/") || util::startsWith(s.path, "/dev/shm/")) {
        o.tags.push_back("in_volatile_dir");
      }
      o.data = {{"path", s.path}, {"type", s.type}, {"listening", s.listening}, {"inode", s.inode}, {"owners", ownersJson(owners, s.inode)}};
      out.observations.push_back(std::move(o));
    }
    if (unnamed) out.warnings.push_back("info: " + std::to_string(unnamed) + " anonymous unix socket(s) not listed");
  }

  if (packet_res.ok) {
    for (const auto& s : parsePacketTable(packet_res.file.data)) {
      Observation o;
      o.type = "socket.packet";
      o.key = "packet|" + std::to_string(s.inode);
      o.tags = {"packet_socket"};  // sniffers / raw frame access
      o.data = {{"type", s.type}, {"proto", s.proto}, {"uid", s.uid}, {"inode", s.inode}, {"owners", ownersJson(owners, s.inode)}};
      out.observations.push_back(std::move(o));
    }
  }

  if (!any_table) return err("no network table readable");
  return out;
}

}  // namespace agent
