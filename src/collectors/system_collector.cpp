#include "collectors/system_collector.h"

#include <algorithm>
#include <set>

#include "core/util.h"

namespace agent {
namespace {

struct SysctlRule {
  const char* path;
  const char* key;
  enum Mode { Equals, AtLeast } mode;
  int64_t expected;
};

const SysctlRule kSysctl[] = {
    {"/proc/sys/kernel/randomize_va_space", "kernel.randomize_va_space", SysctlRule::Equals, 2},
    {"/proc/sys/kernel/kptr_restrict", "kernel.kptr_restrict", SysctlRule::AtLeast, 1},
    {"/proc/sys/kernel/dmesg_restrict", "kernel.dmesg_restrict", SysctlRule::Equals, 1},
    {"/proc/sys/kernel/yama/ptrace_scope", "kernel.yama.ptrace_scope", SysctlRule::AtLeast, 1},
    {"/proc/sys/kernel/unprivileged_bpf_disabled", "kernel.unprivileged_bpf_disabled", SysctlRule::AtLeast, 1},
    {"/proc/sys/kernel/modules_disabled", "kernel.modules_disabled", SysctlRule::AtLeast, -1},  // informational
    {"/proc/sys/fs/suid_dumpable", "fs.suid_dumpable", SysctlRule::Equals, 0},
    {"/proc/sys/fs/protected_symlinks", "fs.protected_symlinks", SysctlRule::Equals, 1},
    {"/proc/sys/fs/protected_hardlinks", "fs.protected_hardlinks", SysctlRule::Equals, 1},
    {"/proc/sys/net/ipv4/ip_forward", "net.ipv4.ip_forward", SysctlRule::Equals, 0},
    {"/proc/sys/net/ipv4/conf/all/accept_redirects", "net.ipv4.conf.all.accept_redirects", SysctlRule::Equals, 0},
    {"/proc/sys/net/ipv4/conf/all/send_redirects", "net.ipv4.conf.all.send_redirects", SysctlRule::Equals, 0},
    {"/proc/sys/net/ipv4/conf/all/accept_source_route", "net.ipv4.conf.all.accept_source_route", SysctlRule::Equals, 0},
    {"/proc/sys/net/ipv4/conf/all/rp_filter", "net.ipv4.conf.all.rp_filter", SysctlRule::AtLeast, 1},
    {"/proc/sys/net/ipv4/tcp_syncookies", "net.ipv4.tcp_syncookies", SysctlRule::Equals, 1},
    {"/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts", "net.ipv4.icmp_echo_ignore_broadcasts", SysctlRule::Equals, 1},
};

const std::set<std::string> kNoiseFs = {"proc", "sysfs", "devpts", "devtmpfs", "cgroup", "cgroup2", "mqueue", "tracefs", "bpf", "securityfs", "pstore", "debugfs",
                                        "configfs", "fusectl", "hugetlbfs", "autofs", "binfmt_misc", "nsfs", "rpc_pipefs", "overlay", "efivarfs", "squashfs",
                                        "fuse.portal", "fuse.gvfsd-fuse", "ramfs"};

const std::set<std::string> kSafeWorldWritableDevices = {"null", "zero", "full", "random", "urandom", "tty", "ptmx", "console_unused", "stdin", "stdout", "stderr", "fd"};

const char* typeName(uint32_t mode) {
  switch (mode & 0170000) {
    case 0060000: return "block";
    case 0020000: return "char";
    case 0100000: return "regular";
    case 0040000: return "dir";
    case 0120000: return "symlink";
    case 0010000: return "fifo";
    case 0140000: return "socket";
    default: return "other";
  }
}

std::string lower(std::string s) {
  for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

}  // namespace

std::vector<ModuleInfo> parseModules(const std::string& text) {
  std::vector<ModuleInfo> out;
  for (const auto& line : util::split(text, '\n')) {
    const auto f = util::splitWs(line);
    if (f.size() < 5) continue;
    ModuleInfo m;
    m.name = f[0];
    m.size = util::parseUint(f[1]).value_or(0);
    m.refcount = static_cast<int64_t>(util::parseUint(f[2]).value_or(0));
    if (f[3] != "-") for (const auto& u : util::split(f[3], ',')) if (!u.empty()) m.used_by.push_back(u);
    m.state = f[4];
    if (f.size() >= 7 && f[6].size() > 2 && f[6].front() == '(' && f[6].back() == ')') m.taint = f[6].substr(1, f[6].size() - 2);
    out.push_back(std::move(m));
  }
  return out;
}

std::string taintLetters(uint64_t v) {
  static const char* letters = "PFSRMBUDAWCIOELKXT";  // bit 0..17
  std::string s;
  for (int i = 0; i < 18; ++i) if (v & (1ull << i)) s += letters[i];
  return s;
}

std::vector<MountInfo> parseMounts(const std::string& text) {
  std::vector<MountInfo> out;
  for (const auto& line : util::split(text, '\n')) {
    const auto f = util::splitWs(line);
    if (f.size() < 4) continue;
    MountInfo m;
    m.device = f[0];
    m.mountpoint = f[1];
    for (size_t i = 0; i < m.mountpoint.size(); ++i) {  // "\040" style escapes
      if (m.mountpoint[i] == '\\' && i + 3 < m.mountpoint.size() && m.mountpoint.substr(i + 1, 3) == "040") m.mountpoint.replace(i, 4, " ");
    }
    m.fstype = f[2];
    m.options = util::split(f[3], ',');
    out.push_back(std::move(m));
  }
  return out;
}

std::vector<SshdOption> parseSshdConfig(const std::string& text) {
  std::vector<SshdOption> out;
  for (const auto& raw : util::split(text, '\n')) {
    const std::string l(util::trim(raw));
    if (l.empty() || l[0] == '#') continue;
    const size_t sp = l.find_first_of(" \t=");
    if (sp == std::string::npos) continue;
    SshdOption o;
    o.name = lower(l.substr(0, sp));
    o.value = std::string(util::trim(l.substr(l.find_first_not_of(" \t=", sp) == std::string::npos ? l.size() : l.find_first_not_of(" \t=", sp))));
    if (o.name == "match") {
      out.push_back({"match", o.value});
      break;  // everything after is conditional: not a global setting
    }
    out.push_back(std::move(o));
  }
  return out;
}

Result<CollectOutput> SystemCollector::collect(ITransport& t) {
  CollectOutput out;

  // ---- Batch 1
  std::vector<ReadOp> ops = {ReadOp::file("/proc/modules", 1 << 20),  ReadOp::file("/proc/sys/kernel/tainted", 64), ReadOp::file("/proc/mounts", 1 << 20),
                             ReadOp::file("/etc/resolv.conf", 64 * 1024), ReadOp::file("/etc/hosts", 256 * 1024), ReadOp::file("/etc/ssh/sshd_config", 256 * 1024),
                             ReadOp::list("/etc/ssh/sshd_config.d"),     ReadOp::list("/sys/class/net"),          ReadOp::list("/dev"),
                             ReadOp::list("/dev/shm")};
  const size_t n_fixed = ops.size();
  for (const auto& s : kSysctl) ops.push_back(ReadOp::file(s.path, 64));
  const auto r1 = t.bulk(ops);
  const OpResult &modules = r1[0], &taint = r1[1], &mounts = r1[2], &resolv = r1[3], &hosts = r1[4], &sshd = r1[5], &sshd_d = r1[6], &ifaces = r1[7], &dev = r1[8], &shm = r1[9];

  // ---- Batch 2: sshd drop-ins, interface flags, device node types
  std::vector<std::string> dropins;
  if (sshd_d.ok) for (const auto& e : sshd_d.entries) if (util::endsWith(e.name, ".conf")) dropins.push_back("/etc/ssh/sshd_config.d/" + e.name);
  std::sort(dropins.begin(), dropins.end());
  std::vector<std::string> iface_names;
  if (ifaces.ok) for (const auto& e : ifaces.entries) iface_names.push_back(e.name);
  std::vector<std::string> dev_paths;
  if (dev.ok) for (const auto& e : dev.entries) if (!e.is_dir) dev_paths.push_back("/dev/" + e.name);
  if (shm.ok) for (const auto& e : shm.entries) dev_paths.push_back("/dev/shm/" + e.name);

  std::vector<ReadOp> ops2;
  for (const auto& d : dropins) ops2.push_back(ReadOp::file(d, 256 * 1024));
  for (const auto& n : iface_names) ops2.push_back(ReadOp::file("/sys/class/net/" + n + "/flags", 32));
  for (const auto& p : dev_paths) ops2.push_back(ReadOp::stat(p));
  const auto r2 = t.bulk(ops2);
  size_t k = 0;

  // kernel modules + taint
  if (modules.ok) {
    for (const auto& m : parseModules(modules.file.data)) {
      Observation o;
      o.type = "kernel.module";
      o.key = m.name;
      if (m.taint.find('E') != std::string::npos) o.tags.push_back("module_unsigned");
      if (m.taint.find('O') != std::string::npos) o.tags.push_back("module_out_of_tree");
      o.data = {{"name", m.name}, {"size", m.size}, {"refcount", m.refcount}, {"used_by", m.used_by}, {"state", m.state}, {"taint", m.taint}};
      out.observations.push_back(std::move(o));
    }
  } else {
    out.warnings.push_back("/proc/modules not readable");
  }
  if (taint.ok) {
    const uint64_t v = util::parseUint(std::string(util::trim(taint.file.data))).value_or(0);
    Observation o;
    o.type = "kernel.taint";
    o.key = "taint";
    if (v & (1ull << 13)) o.tags.push_back("unsigned_module");
    if (v & (1ull << 12)) o.tags.push_back("out_of_tree_module");
    if (v & (1ull << 1)) o.tags.push_back("forced_module");
    o.data = {{"value", v}, {"flags", taintLetters(v)}};
    out.observations.push_back(std::move(o));
  }

  // sysctl
  for (size_t i = 0; i < sizeof(kSysctl) / sizeof(kSysctl[0]); ++i) {
    const OpResult& r = r1[n_fixed + i];
    if (!r.ok) continue;
    const std::string v(util::trim(r.file.data));
    const auto num = util::parseUint(v);
    const SysctlRule& s = kSysctl[i];
    Observation o;
    o.type = "sysctl.value";
    o.key = s.key;
    bool weak = false;
    if (num && s.expected >= 0) weak = s.mode == SysctlRule::Equals ? static_cast<int64_t>(*num) != s.expected : static_cast<int64_t>(*num) < s.expected;
    if (weak) o.tags.push_back("weak_setting");
    o.data = {{"key", s.key}, {"value", v}, {"expected", s.expected >= 0 ? std::string(s.mode == SysctlRule::AtLeast ? ">=" : "=") + std::to_string(s.expected) : std::string("n/a")}};
    out.observations.push_back(std::move(o));
  }

  // mounts
  if (mounts.ok) {
    for (const auto& m : parseMounts(mounts.file.data)) {
      const bool tmp_dir = m.mountpoint == "/tmp" || m.mountpoint == "/var/tmp" || m.mountpoint == "/dev/shm";
      if (kNoiseFs.count(m.fstype) && !tmp_dir) continue;
      if (m.fstype == "tmpfs" && !tmp_dir) continue;  // /run/user/*, /sys/fs/cgroup...: too many and uninteresting
      Observation o;
      o.type = "mount.entry";
      o.key = m.mountpoint + "|" + m.fstype;
      if (tmp_dir && std::find(m.options.begin(), m.options.end(), "noexec") == m.options.end()) o.tags.push_back("exec_allowed_in_tmp");
      if (util::startsWith(m.fstype, "fuse")) o.tags.push_back("fuse_mount");
      o.data = {{"device", util::toValidUtf8(m.device)}, {"mountpoint", util::toValidUtf8(m.mountpoint)}, {"fstype", m.fstype}, {"options", m.options}};
      out.observations.push_back(std::move(o));
    }
  }

  // resolver and hosts
  if (resolv.ok) {
    for (const auto& line : util::split(resolv.file.data, '\n')) {
      const auto f = util::splitWs(line);
      if (f.size() >= 2 && f[0] == "nameserver") {
        Observation o;
        o.type = "net.dns";
        o.key = "ns|" + f[1];
        o.data = {{"nameserver", f[1]}};
        out.observations.push_back(std::move(o));
      }
    }
  }
  if (hosts.ok) {
    for (const auto& line : util::split(hosts.file.data, '\n')) {
      std::string l(util::trim(line));
      if (const size_t h = l.find('#'); h != std::string::npos) l = std::string(util::trim(l.substr(0, h)));
      const auto f = util::splitWs(l);
      if (f.size() < 2) continue;
      Observation o;
      o.type = "net.hosts_entry";
      std::vector<std::string> names(f.begin() + 1, f.end());
      std::string joined;
      for (const auto& n : names) joined += (joined.empty() ? "" : " ") + n;
      o.key = f[0] + " " + joined;
      o.data = {{"ip", f[0]}, {"names", names}};
      out.observations.push_back(std::move(o));
    }
  }

  // sshd
  {
    std::string all;
    if (sshd.ok) all = sshd.file.data;
    std::vector<SshdOption> opts;
    // drop-ins are read first by sshd (first value wins), so they come before the main file
    std::string drop_text;
    for (size_t i = 0; i < dropins.size(); ++i) if (r2[k + i].ok) drop_text += r2[k + i].file.data + "\n";
    for (auto& o : parseSshdConfig(drop_text)) opts.push_back(std::move(o));
    for (auto& o : parseSshdConfig(all)) opts.push_back(std::move(o));
    std::set<std::string> seen_single;
    for (const auto& o : opts) {
      static const std::set<std::string> multi = {"port", "listenaddress", "hostkey", "allowusers", "allowgroups", "denyusers", "denygroups", "match", "subsystem", "acceptenv", "setenv"};
      if (!multi.count(o.name) && !seen_single.insert(o.name).second) continue;  // first value wins in sshd
      static const std::set<std::string> interesting = {"permitrootlogin", "passwordauthentication", "permitemptypasswords", "pubkeyauthentication", "kbdinteractiveauthentication",
                                                        "challengeresponseauthentication", "x11forwarding", "allowtcpforwarding", "gatewayports", "permittunnel", "authorizedkeysfile",
                                                        "authorizedkeyscommand", "authorizedkeyscommanduser", "forcecommand", "usepam", "port", "listenaddress", "permituserenvironment",
                                                        "hostbasedauthentication", "maxauthtries", "allowusers", "allowgroups", "denyusers", "match", "protocol", "loglevel", "rekeylimit"};
      if (!interesting.count(o.name)) continue;
      const std::string v = lower(o.value);
      Observation ob;
      ob.type = "sshd.option";
      ob.key = o.name + "=" + o.value;
      auto weak = [&](const char* tag) { ob.tags.push_back("weak_setting"); ob.tags.push_back(tag); };
      if (o.name == "permitrootlogin" && (v == "yes")) weak("permit_root_login");
      if (o.name == "passwordauthentication" && v == "yes") weak("password_authentication");
      if (o.name == "permitemptypasswords" && v == "yes") weak("permit_empty_passwords");
      if (o.name == "permituserenvironment" && v != "no") weak("permit_user_environment");
      if (o.name == "hostbasedauthentication" && v == "yes") weak("hostbased_authentication");
      if (o.name == "gatewayports" && v != "no") weak("gateway_ports");
      if (o.name == "permittunnel" && v != "no") weak("permit_tunnel");
      if (o.name == "authorizedkeyscommand") ob.tags.push_back("authorized_keys_command");
      if (o.name == "match") ob.tags.push_back("has_match_block");
      ob.data = {{"name", o.name}, {"value", util::toValidUtf8(o.value)}, {"value_lc", util::toValidUtf8(v)}};
      out.observations.push_back(std::move(ob));
    }
    k += dropins.size();
  }

  // interface modes
  for (size_t i = 0; i < iface_names.size(); ++i) {
    const OpResult& r = r2[k + i];
    if (!r.ok) continue;
    const std::string hex = std::string(util::trim(r.file.data));
    const auto flags = util::parseUint(util::startsWith(hex, "0x") ? hex.substr(2) : hex, 16);
    if (!flags) continue;
    Observation o;
    o.type = "net.iface";
    o.key = iface_names[i];
    const bool promisc = (*flags & 0x100) != 0, loopback = (*flags & 0x8) != 0;
    if (promisc && !loopback) o.tags.push_back("promiscuous");
    o.data = {{"name", iface_names[i]}, {"flags", hex}, {"up", (*flags & 0x1) != 0}, {"promisc", promisc}};
    out.observations.push_back(std::move(o));
  }
  k += iface_names.size();

  // device nodes
  for (size_t i = 0; i < dev_paths.size(); ++i) {
    const OpResult& r = r2[k + i];
    if (!r.ok) continue;
    const std::string type = typeName(r.info.mode);
    if (type == "dir") continue;
    const std::string& p = dev_paths[i];
    const std::string name = util::baseName(p);
    const bool in_shm = util::startsWith(p, "/dev/shm/");
    Observation o;
    o.type = "dev.node";
    o.key = p + "|" + type;
    if (!in_shm && type == "regular") o.tags.push_back("regular_file_in_dev");
    if (util::startsWith(name, ".")) o.tags.push_back("hidden_file");
    if (type == "regular" && (r.info.mode & 0111)) o.tags.push_back("executable");
    if ((type == "char" || type == "block") && (r.info.mode & 0002) && !kSafeWorldWritableDevices.count(name)) o.tags.push_back("world_writable_device");
    o.data = {{"path", p}, {"type", type}, {"mode", r.info.mode & 07777}, {"uid", r.info.uid}, {"size", r.info.size}};
    out.observations.push_back(std::move(o));
  }
  return out;
}

}  // namespace agent
