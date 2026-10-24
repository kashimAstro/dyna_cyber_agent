#include "collectors/crossview_collector.h"

#include <algorithm>

#include "collectors/process_collector.h"
#include "core/util.h"

namespace agent {
namespace {

constexpr size_t kMaxCgroupDirs = 3000;
constexpr int kMaxDepth = 8;
constexpr size_t kMaxBpf = 400;

}  // namespace

std::set<int> CrossViewCollector::parsePidList(const std::string& text) {
  std::set<int> out;
  for (const auto& line : util::split(text, '\n')) {
    const auto v = util::parseUint(std::string(util::trim(line)));
    if (v && *v > 0 && *v < (1u << 24)) out.insert(static_cast<int>(*v));
  }
  return out;
}

std::set<int> CrossViewCollector::listeningTcpPorts(const std::string& text) {
  std::set<int> out;
  bool first = true;
  for (const auto& line : util::split(text, '\n')) {
    if (first) { first = false; continue; }  // header
    const auto f = util::splitWs(line);
    if (f.size() < 4 || f[3] != "0A") continue;  // 0A = TCP_LISTEN
    const size_t colon = f[1].rfind(':');
    if (colon == std::string::npos) continue;
    try {
      out.insert(std::stoi(f[1].substr(colon + 1), nullptr, 16));
    } catch (...) {}
  }
  return out;
}

std::set<int> CrossViewCollector::ssListeningTcpPorts(const std::string& text) {
  std::set<int> out;
  for (const auto& line : util::split(text, '\n')) {
    const auto f = util::splitWs(line);
    if (f.size() < 5 || f[0] != "tcp" || f[1] != "LISTEN") continue;
    const size_t colon = f[4].rfind(':');
    if (colon == std::string::npos) continue;
    if (const auto p = util::parseUint(f[4].substr(colon + 1))) out.insert(static_cast<int>(*p));
  }
  return out;
}

std::vector<CrossViewCollector::BpfProgram> CrossViewCollector::bpfPrograms(const std::string& kallsyms) {
  // "ffffffffc0a01234 t bpf_prog_7c1f3a9d0e2b4a55_sched_cls_x\t[bpf]"
  std::vector<BpfProgram> out;
  for (const auto& line : util::split(kallsyms, '\n')) {
    const size_t p = line.find(" bpf_prog_");
    if (p == std::string::npos) continue;
    std::string sym = line.substr(p + 10);
    const size_t end = sym.find_first_of(" \t");
    if (end != std::string::npos) sym.resize(end);
    if (sym.size() < 17 || sym[16] != '_') continue;
    const std::string tag = sym.substr(0, 16);
    if (tag.find_first_not_of("0123456789abcdef") != std::string::npos) continue;
    out.push_back({tag, sym.substr(17)});
    if (out.size() >= kMaxBpf) break;
  }
  return out;
}

Result<CollectOutput> CrossViewCollector::collect(ITransport& t) {
  CollectOutput out;
  std::set<std::string> now_mismatch;
  struct Pending { Observation obs; };
  std::vector<Observation> candidates;

  // ---- processes: /proc listing against the cgroup lists ----------------------------------------------------------
  auto proc = t.listDir("/proc");
  if (proc) {
    std::set<int> listed;
    for (const auto& e : proc.value()) if (util::allDigits(e.name)) listed.insert(static_cast<int>(util::parseUint(e.name).value_or(0)));

    std::vector<std::string> dirs = {"/sys/fs/cgroup"}, all_dirs = dirs;
    for (int depth = 0; depth < kMaxDepth && !dirs.empty() && all_dirs.size() < kMaxCgroupDirs; ++depth) {
      std::vector<ReadOp> ops;
      for (const auto& d : dirs) ops.push_back(ReadOp::list(d));
      const auto res = t.bulk(ops);
      std::vector<std::string> next;
      for (size_t i = 0; i < dirs.size(); ++i) {
        if (!res[i].ok) continue;
        for (const auto& e : res[i].entries) {
          if (!e.is_dir || e.is_symlink || all_dirs.size() + next.size() >= kMaxCgroupDirs) continue;
          next.push_back(dirs[i] + "/" + e.name);
        }
      }
      all_dirs.insert(all_dirs.end(), next.begin(), next.end());
      dirs = std::move(next);
    }
    std::vector<ReadOp> reads;
    for (const auto& d : all_dirs) reads.push_back(ReadOp::file(d + "/cgroup.procs", 256 * 1024));
    const auto cg = t.bulk(reads);
    std::set<int> in_cgroup;
    size_t readable = 0;
    for (const auto& r : cg) {
      if (!r.ok) continue;
      ++readable;
      const auto p = parsePidList(r.file.data);
      in_cgroup.insert(p.begin(), p.end());
    }
    if (readable == 0) {
      out.warnings.push_back("cgroup membership lists not readable: hidden-process check skipped");
    } else {
      std::vector<int> missing;
      for (int pid : in_cgroup) if (!listed.count(pid)) missing.push_back(pid);
      std::vector<ReadOp> stat_ops;
      for (int pid : missing) stat_ops.push_back(ReadOp::file("/proc/" + std::to_string(pid) + "/stat", 4096));
      const auto stats = missing.empty() ? std::vector<OpResult>() : t.bulk(stat_ops);
      for (size_t i = 0; i < missing.size(); ++i) {
        if (!stats[i].ok) continue;  // gone by now: it only seemed to be hidden
        const auto ps = parseProcStat(stats[i].file.data);
        Observation o;
        o.type = "crossview.hidden_pid";
        o.key = "pid|" + std::to_string(missing[i]);
        o.tags = {"hidden_process"};
        o.data = {{"pid", missing[i]}, {"comm", ps ? util::toValidUtf8(ps->comm) : std::string("?")}, {"seen_in", "cgroup.procs"}, {"missing_from", "/proc listing"}};
        candidates.push_back(std::move(o));
      }
    }
  } else {
    out.warnings.push_back("/proc is not listable: hidden-process check skipped");
  }

  // ---- modules: /proc/modules against /sys/module ------------------------------------------------------------------
  {
    const auto r = t.bulk({ReadOp::file("/proc/modules", 1 << 20), ReadOp::list("/sys/module")});
    if (r[0].ok && r[1].ok) {
      std::set<std::string> listed;
      for (const auto& line : util::split(r[0].file.data, '\n')) {
        const auto f = util::splitWs(line);
        if (!f.empty()) listed.insert(f[0]);
      }
      std::vector<ReadOp> ops;
      std::vector<std::string> names;
      for (const auto& e : r[1].entries) if (e.is_dir) { names.push_back(e.name); ops.push_back(ReadOp::stat("/sys/module/" + e.name + "/initstate")); }
      const auto st = t.bulk(ops);
      for (size_t i = 0; i < names.size(); ++i) {
        if (!st[i].ok) continue;                 // built into the kernel: no initstate file
        if (listed.count(names[i])) continue;
        Observation o;
        o.type = "crossview.hidden_module";
        o.key = "module|" + names[i];
        o.tags = {"hidden_module"};
        o.data = {{"name", names[i]}, {"seen_in", "/sys/module"}, {"missing_from", "/proc/modules"}};
        candidates.push_back(std::move(o));
      }
    } else {
      out.warnings.push_back("module lists not readable: hidden-module check skipped");
    }
  }

  // ---- listening ports: /proc/net/tcp against netlink ---------------------------------------------------------------
  {
    const auto r = t.bulk({ReadOp::file("/proc/net/tcp", 4 << 20), ReadOp::file("/proc/net/tcp6", 4 << 20)});
    auto ss = t.run({"ss", "-tulpn"});
    if (r[0].ok && ss && ss.value().exit_code == 0) {
      std::set<int> proc_ports = listeningTcpPorts(r[0].file.data);
      if (r[1].ok) {
        const auto v6 = listeningTcpPorts(r[1].file.data);
        proc_ports.insert(v6.begin(), v6.end());
      }
      const auto ss_ports = ssListeningTcpPorts(ss.value().out);
      for (int p : ss_ports) {
        if (proc_ports.count(p)) continue;
        Observation o;
        o.type = "crossview.hidden_port";
        o.key = "port|" + std::to_string(p) + "|proc";
        o.tags = {"hidden_port"};
        o.data = {{"port", p}, {"seen_in", "ss (netlink)"}, {"missing_from", "/proc/net/tcp"}};
        candidates.push_back(std::move(o));
      }
      for (int p : proc_ports) {
        if (ss_ports.count(p)) continue;
        Observation o;
        o.type = "crossview.hidden_port";
        o.key = "port|" + std::to_string(p) + "|ss";
        o.tags = {"hidden_port"};
        o.data = {{"port", p}, {"seen_in", "/proc/net/tcp"}, {"missing_from", "ss (netlink)"}};
        candidates.push_back(std::move(o));
      }
    } else {
      out.warnings.push_back("port lists not comparable (/proc/net/tcp or `ss`): hidden-port check skipped");
    }
  }

  // a mismatch counts only when it persists
  std::set<std::string> seen_now;
  for (auto& c : candidates) {
    seen_now.insert(c.key);
    if (previous_.count(c.key)) out.observations.push_back(std::move(c));
  }
  previous_ = std::move(seen_now);

  // ---- eBPF ---------------------------------------------------------------------------------------------------------
  {
    const bool read_symbols = runs_ % 6 == 0;
    std::vector<ReadOp> ops = {ReadOp::list("/sys/fs/bpf")};
    if (read_symbols) ops.push_back(ReadOp::file("/proc/kallsyms", 24u << 20));
    const auto r = t.bulk(ops);
    if (read_symbols && r[1].ok) {
      bpf_cache_.clear();
      std::set<std::string> seen;
      for (const auto& p : bpfPrograms(r[1].file.data)) {
        if (!seen.insert(p.tag).second) continue;
        Observation o;
        o.type = "bpf.program";
        o.key = "bpf|" + p.tag;
        o.data = {{"tag", p.tag}, {"name", util::toValidUtf8(p.name)}};
        bpf_cache_.push_back(std::move(o));
      }
    }
    for (const auto& o : bpf_cache_) out.observations.push_back(o);
    if (r[0].ok) {
      for (const auto& e : r[0].entries) {
        Observation o;
        o.type = "bpf.pinned";
        o.key = "bpffs|" + e.name;
        o.data = {{"name", util::toValidUtf8(e.name)}, {"is_dir", e.is_dir}};
        out.observations.push_back(std::move(o));
      }
    }
  }
  ++runs_;
  return out;
}

}  // namespace agent
