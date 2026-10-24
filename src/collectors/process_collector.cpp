#include "collectors/process_collector.h"

#include <algorithm>
#include <map>

#include "core/util.h"

namespace agent {
namespace {
constexpr int64_t kClkTck = 100;  // USER_HZ is 100 on every mainstream Linux ABI
constexpr size_t kMaxCmdline = 4096;

bool inVolatileDir(const std::string& p) {
  return util::startsWith(p, "/tmp/") || util::startsWith(p, "/var/tmp/") || util::startsWith(p, "/dev/shm/");
}
}  // namespace

std::optional<ProcStat> parseProcStat(const std::string& text) {
  // comm may contain spaces and parentheses: it is delimited by the first '(' and the last ')'.
  const size_t lp = text.find('(');
  const size_t rp = text.rfind(')');
  if (lp == std::string::npos || rp == std::string::npos || rp < lp) return std::nullopt;
  ProcStat s;
  s.comm = text.substr(lp + 1, rp - lp - 1);
  const auto f = util::splitWs(text.substr(rp + 1));
  // f[0]=state(3) f[1]=ppid(4) ... f[19]=starttime(22)
  if (f.size() < 20 || f[0].empty()) return std::nullopt;
  s.state = f[0][0];
  const auto ppid = util::parseUint(f[1]);
  const auto start = util::parseUint(f[19]);
  if (!ppid || !start) return std::nullopt;
  s.ppid = static_cast<int64_t>(*ppid);
  s.start_ticks = *start;
  return s;
}

ProcStatus parseProcStatus(const std::string& text) {
  ProcStatus st;
  for (const auto& line : util::split(text, '\n')) {
    if (util::startsWith(line, "Name:")) {
      st.name = std::string(util::trim(std::string_view(line).substr(5)));
    } else if (util::startsWith(line, "Uid:") || util::startsWith(line, "Gid:")) {
      const auto f = util::splitWs(std::string_view(line).substr(4));
      if (const auto v = f.empty() ? std::nullopt : util::parseUint(f[0])) {
        (line[0] == 'U' ? st.uid : st.gid) = static_cast<int64_t>(*v);
      }
    }
  }
  return st;
}

std::vector<std::string> splitCmdline(const std::string& raw) {
  std::vector<std::string> out;
  std::string cur;
  for (char c : raw) {
    if (c == '\0') {
      out.push_back(util::toValidUtf8(cur));
      cur.clear();
    } else {
      cur += c;
    }
  }
  if (!cur.empty()) out.push_back(util::toValidUtf8(cur));
  return out;
}

int countRwxMappings(const std::string& maps) { return util::countRwxMappings(maps); }

std::vector<std::string> processTags(const std::string& comm, const std::optional<std::string>& exe, bool kernel_thread,
                                     int rwx_maps) {
  std::vector<std::string> tags;
  if (kernel_thread) return tags;
  if (rwx_maps > 0) tags.push_back("rwx_memory");
  if (!exe) return tags;
  std::string path = *exe;
  if (util::endsWith(path, " (deleted)")) {
    tags.push_back("exe_deleted");
    path.resize(path.size() - 10);
  }
  if (util::startsWith(path, "/memfd:")) tags.push_back("exe_memfd");
  if (inVolatileDir(path)) tags.push_back("exe_in_volatile_dir");
  const std::string base = util::baseName(path);
  // comm is truncated to 15 chars by the kernel.
  if (!base.empty() && !comm.empty() && !util::startsWith(base, comm) && !util::startsWith(comm, base.substr(0, 15))) {
    tags.push_back("comm_mismatch");
  }
  return tags;
}

Result<CollectOutput> ProcessCollector::collect(ITransport& t) {
  constexpr uint64_t kMaxHash = 512ull << 20;
  auto dir = t.listDir("/proc");
  if (!dir) return err(dir.error());

  int64_t btime = 0;
  if (auto st = t.readFile("/proc/stat", 1 << 20)) {
    for (const auto& line : util::split(st.value().data, '\n')) {
      if (util::startsWith(line, "btime ")) btime = static_cast<int64_t>(util::parseUint(line.substr(6)).value_or(0));
    }
  }

  std::vector<std::string> pids;
  for (const auto& e : dir.value()) if (util::allDigits(e.name)) pids.push_back(e.name);

  // Stage 1: everything about every process in one batch (6 requests per pid).
  constexpr size_t kPer = 6;
  std::vector<ReadOp> ops;
  ops.reserve(pids.size() * kPer);
  for (const auto& pid : pids) {
    const std::string base = "/proc/" + pid;
    ops.push_back(ReadOp::file(base + "/stat", 4096));
    ops.push_back(ReadOp::file(base + "/status", 16384));
    ops.push_back(ReadOp::file(base + "/cmdline", kMaxCmdline));
    ops.push_back(ReadOp::link(base + "/exe"));
    ops.push_back(ReadOp::link(base + "/cwd"));
    ops.push_back(ReadOp::rwxMaps(base + "/maps"));
  }
  const auto res = t.bulk(ops);

  struct Draft {
    std::string pid;
    ProcStat st;
    ProcStatus status;
    int64_t pid_n = 0;
    bool kernel_thread = false;
    std::optional<std::string> exe, cwd;
    std::vector<std::string> cmdline;
    int rwx = 0;
    std::optional<std::string> sha;
  };
  CollectOutput out;
  std::vector<Draft> drafts;
  int exe_denied = 0, maps_denied = 0;
  for (size_t i = 0; i < pids.size(); ++i) {
    const OpResult* r = &res[i * kPer];
    if (!r[0].ok) continue;  // process exited during the scan
    auto st = parseProcStat(r[0].file.data);
    if (!st) {
      out.warnings.push_back("unparsable /proc/" + pids[i] + "/stat");
      continue;
    }
    Draft d;
    d.pid = pids[i];
    d.st = *st;
    d.pid_n = static_cast<int64_t>(util::parseUint(pids[i]).value_or(0));
    d.kernel_thread = d.pid_n == 2 || st->ppid == 2;
    if (r[1].ok) d.status = parseProcStatus(r[1].file.data);
    if (r[2].ok) d.cmdline = splitCmdline(r[2].file.data);
    if (r[3].ok) d.exe = util::toValidUtf8(r[3].text);
    else if (!d.kernel_thread) ++exe_denied;
    if (r[4].ok) d.cwd = util::toValidUtf8(r[4].text);
    if (!d.kernel_thread) {
      if (r[5].ok) d.rwx = static_cast<int>(r[5].count);
      else ++maps_denied;
    }
    drafts.push_back(std::move(d));
  }

  // Stage 2: hash binaries, but only those that changed since the last run (stat is the cheap change detector).
  std::map<std::string, size_t> stat_idx;  // exe path -> index in stat batch
  std::vector<ReadOp> stat_ops;
  for (const auto& d : drafts) {
    if (!d.exe || d.kernel_thread) continue;
    const bool gone = util::endsWith(*d.exe, " (deleted)") || util::startsWith(*d.exe, "/memfd:");
    if (!gone && stat_idx.emplace(*d.exe, stat_ops.size()).second) stat_ops.push_back(ReadOp::stat(*d.exe));
  }
  const auto stat_res = t.bulk(stat_ops);

  struct HashJob { std::string cache_key, read_path; };
  std::vector<HashJob> jobs;
  std::map<std::string, size_t> job_idx;  // cache key -> index in jobs
  std::vector<std::string> key_of(drafts.size());
  for (size_t i = 0; i < drafts.size(); ++i) {
    const Draft& d = drafts[i];
    if (!d.exe || d.kernel_thread) continue;
    const bool gone = util::endsWith(*d.exe, " (deleted)") || util::startsWith(*d.exe, "/memfd:");
    std::string key, path;
    if (gone) {
      // No path any more: read through the process, once per process.
      key = "gone|" + d.pid + "|" + std::to_string(d.st.start_ticks);
      path = "/proc/" + d.pid + "/exe";
    } else {
      const OpResult& s = stat_res[stat_idx[*d.exe]];
      if (!s.ok) continue;
      key = *d.exe + "|" + std::to_string(s.info.size) + "|" + std::to_string(s.info.mtime);
      path = *d.exe;
    }
    key_of[i] = key;
    if (hash_cache_.count(key) == 0 && job_idx.emplace(key, jobs.size()).second) jobs.push_back({key, path});
  }
  if (!jobs.empty()) {
    if (hash_cache_.size() > 8192) hash_cache_.clear();
    std::vector<ReadOp> hash_ops;
    for (const auto& j : jobs) hash_ops.push_back(ReadOp::sha256(j.read_path, kMaxHash));
    const auto hash_res = t.bulk(hash_ops);
    for (size_t k = 0; k < jobs.size(); ++k) {
      hash_cache_[jobs[k].cache_key] = hash_res[k].ok ? hash_res[k].text : std::string();  // negative results are cached too
      if (!hash_res[k].ok && hash_res[k].error.find("too large") != std::string::npos && !warned_too_large_) {
        warned_too_large_ = true;
        out.warnings.push_back("some executables exceed the hash size limit and were not hashed");
      }
    }
  }
  for (size_t i = 0; i < drafts.size(); ++i) {
    if (key_of[i].empty()) continue;
    const auto it = hash_cache_.find(key_of[i]);
    if (it != hash_cache_.end() && !it->second.empty()) drafts[i].sha = it->second;
  }

  for (auto& d : drafts) {
    Observation o;
    o.type = "process";
    o.key = d.pid + ":" + std::to_string(d.st.start_ticks);
    o.tags = processTags(d.st.comm, d.exe, d.kernel_thread, d.rwx);
    o.data = {{"pid", d.pid_n},
              {"ppid", d.st.ppid},
              {"comm", util::toValidUtf8(d.st.comm)},
              {"state", std::string(1, d.st.state)},
              {"uid", d.status.uid},
              {"gid", d.status.gid},
              {"exe", d.exe ? nlohmann::json(*d.exe) : nlohmann::json(nullptr)},
              {"exe_sha256", d.sha ? nlohmann::json(*d.sha) : nlohmann::json(nullptr)},
              {"parent_exe", nullptr},
              {"cwd", d.cwd ? nlohmann::json(*d.cwd) : nlohmann::json(nullptr)},
              {"cmdline", d.cmdline},
              {"start_ticks", d.st.start_ticks},
              {"start_time", btime ? btime + static_cast<int64_t>(d.st.start_ticks) / kClkTck : 0},
              {"kernel_thread", d.kernel_thread},
              {"rwx_mappings", d.rwx}};
    out.observations.push_back(std::move(o));
  }

  // Resolve each process's parent executable (needed for lineage rules).
  std::map<int64_t, std::string> exe_by_pid;
  for (const auto& o : out.observations) {
    if (o.data["exe"].is_string()) exe_by_pid[o.data["pid"].get<int64_t>()] = o.data["exe"].get<std::string>();
  }
  for (auto& o : out.observations) {
    const auto it = exe_by_pid.find(o.data["ppid"].get<int64_t>());
    if (it != exe_by_pid.end()) o.data["parent_exe"] = it->second;
  }
  if (exe_denied) out.warnings.push_back(std::to_string(exe_denied) + " process(es): exe not readable (insufficient privileges?)");
  if (maps_denied) out.warnings.push_back(std::to_string(maps_denied) + " process(es): maps not readable (insufficient privileges?)");
  return out;
}

}  // namespace agent
